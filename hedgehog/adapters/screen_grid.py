"""Minimal text-only terminal screen emulator.

Tracks the visible grid of characters, the cursor position, and the
normal/alt screen toggle for reattach replay. Color and text attributes
(bold/italic/underline) are intentionally dropped — render() returns
plain text only. This is the experimental alternative to the dual ring
buffer in RingBuffer: it always renders the *current* frame, never stale
historical bytes, at the cost of losing color and ~150-250 LOC of state.

Supported escape sequences (rough xterm subset):
  CSI <r>;<c> H  / f      cursor position (1-indexed)
  CSI <n> A/B/C/D         cursor up / down / right / left
  CSI <n> J               erase display (0=to end, 1=from start, 2/3=all)
  CSI <n> K               erase line    (0=to end, 1=from start, 2=all)
  CSI <n> P               delete chars (DCH)
  CSI <n> X               erase chars  (ECH)
  CSI <n> @               insert blanks (ICH)
  CSI s / u               save / restore cursor
  CSI ? 1049 h/l          alt-screen toggle (also ?47, ?1047)
  CSI ? 25 h/l            cursor visibility — accepted, not tracked
  CSI <n> m               SGR — accepted and dropped (no color tracking)
  ESC c                   full reset (RIS)
  ESC 7 / 8               save / restore cursor (DECSC / DECRC)
  ESC [ ... <final>       any other CSI — final byte consumed, no-op
  ESC ] ... BEL/ST        OSC (window titles, hyperlinks) — consumed, no-op

Scrollback is kept for the *normal* screen only. When a line falls off
the top of the grid via scroll-up, it is pushed to self.scrollback (capped
by scrollback_max, in lines; 0 disables it). render() emits the scrollback
above the current grid, separated by CR/LF so the client terminal places
older content into its own scrollback buffer. Alt-screen scroll-up does
*not* feed scrollback — alt screens are full-screen UIs (htop, vim, Claude)
where scroll history is not meaningful.

Things deliberately NOT supported:
- Wide characters (CJK, emoji): each codepoint advances cursor by 1 cell.
  On render, the client terminal will reflow them — acceptable artifact.
- Combining characters / zero-width joiners: also advance by 1.
- Scroll regions (DECSTBM): we only do whole-screen scroll on bottom-row LF.
- Colors / SGR: dropped, render is plain text. This is the explicit tradeoff.
- Bracketed paste, mouse, focus events: consumed and ignored.
"""

from __future__ import annotations


class ScreenGrid:
    """Stateful character grid with a tiny ANSI parser.

    feed(bytes) updates the grid; render() emits a self-contained payload
    that paints the current state into a fresh client terminal.
    """

    # State machine: which kind of escape we're currently collecting.
    _IDLE = 0   # printing characters
    _ESC = 1    # just saw \033, waiting for the kind byte
    _CSI = 2    # collecting parameters until a final byte 0x40-0x7E
    _OSC = 3    # collecting until BEL (0x07) or ST (ESC \\)
    _OSC_ESC = 4  # inside OSC, just saw ESC, waiting for \\

    def __init__(self, rows: int = 24, cols: int = 80, scrollback_max: int = 1000):
        self.rows = max(1, rows)
        self.cols = max(1, cols)
        self.normal = self._blank_grid()
        self.alt = self._blank_grid()
        self.cursor_row = 0
        self.cursor_col = 0
        self.alt_mode = False
        # DECSC/DECRC save slot (one per screen). Two cursors so alt screen
        # has its own save register, matching xterm.
        self._saved = {"normal": None, "alt": None}
        # Parser state
        self._state = self._IDLE
        self._esc_buf = bytearray()
        # UTF-8 multibyte assembler: holds the partial leading bytes when a
        # codepoint straddles a feed boundary.
        self._utf_carry = bytearray()
        # Scrollback: lines that have scrolled off the top of the normal
        # screen. Each entry is a row (list of single-codepoint bytes), same
        # shape as a grid row. 0 disables (no scrollback kept).
        self.scrollback_max = max(0, scrollback_max)
        self.scrollback: list[list[bytes]] = []

    # ---------- grid helpers ----------

    def _blank_row(self) -> list[bytes]:
        return [b' '] * self.cols

    def _blank_grid(self) -> list[list[bytes]]:
        return [self._blank_row() for _ in range(self.rows)]

    @property
    def _grid(self) -> list[list[bytes]]:
        return self.alt if self.alt_mode else self.normal

    def resize(self, rows: int, cols: int):
        """Resize both screens. Content is preserved top-left, clipped or
        padded with blanks as needed."""
        rows = max(1, rows)
        cols = max(1, cols)
        if rows == self.rows and cols == self.cols:
            return

        def reshape(grid):
            new = [[b' '] * cols for _ in range(rows)]
            for r in range(min(rows, len(grid))):
                src = grid[r]
                for c in range(min(cols, len(src))):
                    new[r][c] = src[c]
            return new

        self.normal = reshape(self.normal)
        self.alt = reshape(self.alt)
        # Scrollback rows: clip or pad to new cols. Row count is preserved —
        # narrowing the screen does not shrink history.
        for i, row in enumerate(self.scrollback):
            if len(row) > cols:
                self.scrollback[i] = row[:cols]
            elif len(row) < cols:
                self.scrollback[i] = row + [b' '] * (cols - len(row))
        self.rows = rows
        self.cols = cols
        self.cursor_row = min(self.cursor_row, rows - 1)
        self.cursor_col = min(self.cursor_col, cols - 1)

    # ---------- cursor moves ----------

    def _clamp_cursor(self):
        if self.cursor_row < 0:
            self.cursor_row = 0
        elif self.cursor_row >= self.rows:
            self.cursor_row = self.rows - 1
        if self.cursor_col < 0:
            self.cursor_col = 0
        elif self.cursor_col >= self.cols:
            self.cursor_col = self.cols - 1

    def _scroll_up(self, n: int = 1):
        """Drop n top rows, append n blank rows at the bottom.

        In normal-screen mode, the dropped rows are appended to scrollback
        (capped by scrollback_max). Alt-screen never feeds scrollback —
        alt is for full-screen TUIs where scroll history is meaningless.

        Dedup: a row equal to any of the last `self.rows` scrollback entries
        is skipped. Claude Code (and similar TUIs that don't use alt-screen)
        redraws its whole UI on every status tick by clearing the screen
        and reprinting. Without dedup, each redraw appends a full screen's
        worth of identical lines to scrollback — reattach replay then shows
        the same chat block dozens of times.
        """
        if n <= 0:
            return

        # Capture the rows we're about to drop, for normal-mode scrollback.
        if not self.alt_mode and self.scrollback_max > 0:
            take = min(n, self.rows)
            dedup_window = max(1, self.rows)
            for r in range(take):
                # Copy the row — the grid will reuse list slots otherwise.
                new_row = list(self._grid[r])
                if self.scrollback:
                    recent = self.scrollback[-dedup_window:]
                    if any(new_row == old for old in recent):
                        continue
                self.scrollback.append(new_row)
            overflow = len(self.scrollback) - self.scrollback_max
            if overflow > 0:
                del self.scrollback[:overflow]

        if n >= self.rows:
            for r in range(self.rows):
                self._grid[r] = self._blank_row()
            return
        grid = self._grid
        del grid[:n]
        for _ in range(n):
            grid.append(self._blank_row())

    def _linefeed(self):
        if self.cursor_row + 1 >= self.rows:
            self._scroll_up(1)
        else:
            self.cursor_row += 1

    def _put_cell(self, cell: bytes):
        """Place one codepoint at the cursor and advance."""
        if self.cursor_col >= self.cols:
            self.cursor_col = 0
            self._linefeed()
        self._grid[self.cursor_row][self.cursor_col] = cell
        self.cursor_col += 1

    # ---------- feed ----------

    def feed(self, data: bytes):
        """Consume PTY output bytes and update grid state."""
        if not data:
            return

        if self._utf_carry:
            data = bytes(self._utf_carry) + data
            self._utf_carry.clear()

        i = 0
        n = len(data)
        while i < n:
            state = self._state
            if state == self._IDLE:
                b = data[i]
                if b == 0x1B:  # ESC
                    self._state = self._ESC
                    i += 1
                elif b < 0x20 or b == 0x7F:
                    self._control(b)
                    i += 1
                elif b < 0x80:
                    self._put_cell(bytes((b,)))
                    i += 1
                else:
                    # Start of a UTF-8 multibyte sequence.
                    if b >= 0xF0:
                        need = 4
                    elif b >= 0xE0:
                        need = 3
                    elif b >= 0xC0:
                        need = 2
                    else:
                        # Lone continuation byte — treat as opaque single byte
                        # rather than dropping, so e.g. Latin-1 streams still
                        # render something visible.
                        self._put_cell(bytes((b,)))
                        i += 1
                        continue
                    if i + need > n:
                        self._utf_carry.extend(data[i:n])
                        return
                    cell = data[i:i + need]
                    # Validate continuations to catch corrupted streams.
                    if all(0x80 <= cb < 0xC0 for cb in cell[1:]):
                        self._put_cell(bytes(cell))
                    else:
                        # Invalid sequence — fall back to putting the lead byte.
                        self._put_cell(bytes((b,)))
                        i += 1
                        continue
                    i += need
            elif state == self._ESC:
                b = data[i]
                i += 1
                if b == ord('['):
                    self._state = self._CSI
                    self._esc_buf.clear()
                elif b == ord(']'):
                    self._state = self._OSC
                    self._esc_buf.clear()
                elif b == ord('c'):  # RIS
                    self._reset()
                    self._state = self._IDLE
                elif b == ord('7'):  # DECSC
                    self._save_cursor()
                    self._state = self._IDLE
                elif b == ord('8'):  # DECRC
                    self._restore_cursor()
                    self._state = self._IDLE
                elif b == ord('D'):  # IND — line feed
                    self._linefeed()
                    self._state = self._IDLE
                elif b == ord('M'):  # RI — reverse index
                    if self.cursor_row == 0:
                        # scroll down by 1: append blank at top, drop bottom
                        grid = self._grid
                        grid.insert(0, self._blank_row())
                        grid.pop()
                    else:
                        self.cursor_row -= 1
                    self._state = self._IDLE
                elif b == ord('E'):  # NEL — next line
                    self.cursor_col = 0
                    self._linefeed()
                    self._state = self._IDLE
                else:
                    # Single-byte or 2-byte escape we don't model — drop.
                    self._state = self._IDLE
            elif state == self._CSI:
                b = data[i]
                i += 1
                if 0x40 <= b <= 0x7E:
                    self._dispatch_csi(bytes(self._esc_buf), b)
                    self._esc_buf.clear()
                    self._state = self._IDLE
                else:
                    self._esc_buf.append(b)
                    # Soft cap to avoid runaway state on malformed input.
                    if len(self._esc_buf) > 256:
                        self._esc_buf.clear()
                        self._state = self._IDLE
            elif state == self._OSC:
                b = data[i]
                i += 1
                if b == 0x07:  # BEL
                    self._esc_buf.clear()
                    self._state = self._IDLE
                elif b == 0x1B:
                    self._state = self._OSC_ESC
                else:
                    if len(self._esc_buf) < 4096:
                        self._esc_buf.append(b)
            elif state == self._OSC_ESC:
                b = data[i]
                i += 1
                # Any byte after ESC inside OSC ends it (canonical ST is ESC \\).
                self._esc_buf.clear()
                self._state = self._IDLE

    def _control(self, b: int):
        if b == 0x0A:  # LF
            self._linefeed()
        elif b == 0x0D:  # CR
            self.cursor_col = 0
        elif b == 0x08:  # BS
            if self.cursor_col > 0:
                self.cursor_col -= 1
        elif b == 0x09:  # TAB
            next_stop = ((self.cursor_col // 8) + 1) * 8
            self.cursor_col = min(next_stop, self.cols - 1)
        # BEL (0x07), other C0 controls: silently ignored.

    # ---------- CSI dispatch ----------

    def _parse_params(self, raw: bytes) -> tuple[list[int], bytes]:
        """Split a CSI parameter string into (numeric params, intermediates).

        Intermediates here is just the leading '?' / '>' / '!' marker, if any.
        """
        prefix = b''
        if raw and raw[:1] in (b'?', b'>', b'!'):
            prefix = raw[:1]
            raw = raw[1:]
        if not raw:
            return [], prefix
        parts = raw.split(b';')
        params = []
        for p in parts:
            if not p:
                params.append(0)
            else:
                try:
                    params.append(int(p))
                except ValueError:
                    params.append(0)
        return params, prefix

    def _dispatch_csi(self, raw: bytes, final: int):
        params, prefix = self._parse_params(raw)
        p1 = params[0] if params else 0

        # Private-mode SET/RESET — only care about alt-screen and a couple others.
        if prefix == b'?' and final in (ord('h'), ord('l')):
            on = final == ord('h')
            for p in params or [0]:
                if p in (1049, 47, 1047):
                    self._set_alt(on)
                # ?25 (cursor), ?2004 (bracketed paste), ?12 (blink), etc — ignore.
            return

        if prefix:
            # Other private/intermediate CSIs (DEC modes we don't model) — drop.
            return

        if final == ord('H') or final == ord('f'):  # CUP
            row = (params[0] - 1) if len(params) >= 1 and params[0] > 0 else 0
            col = (params[1] - 1) if len(params) >= 2 and params[1] > 0 else 0
            self.cursor_row = row
            self.cursor_col = col
            self._clamp_cursor()
        elif final == ord('A'):  # CUU
            self.cursor_row -= max(1, p1)
            self._clamp_cursor()
        elif final == ord('B'):  # CUD
            self.cursor_row += max(1, p1)
            self._clamp_cursor()
        elif final == ord('C'):  # CUF
            self.cursor_col += max(1, p1)
            self._clamp_cursor()
        elif final == ord('D'):  # CUB
            self.cursor_col -= max(1, p1)
            self._clamp_cursor()
        elif final == ord('G'):  # CHA — cursor to column
            self.cursor_col = max(0, (p1 - 1) if p1 > 0 else 0)
            self._clamp_cursor()
        elif final == ord('d'):  # VPA — cursor to row
            self.cursor_row = max(0, (p1 - 1) if p1 > 0 else 0)
            self._clamp_cursor()
        elif final == ord('J'):  # ED
            self._erase_display(p1)
        elif final == ord('K'):  # EL
            self._erase_line(p1)
        elif final == ord('P'):  # DCH — delete chars
            self._delete_chars(max(1, p1))
        elif final == ord('X'):  # ECH — erase chars
            self._erase_chars(max(1, p1))
        elif final == ord('@'):  # ICH — insert blanks
            self._insert_blanks(max(1, p1))
        elif final == ord('s'):  # save cursor
            self._save_cursor()
        elif final == ord('u'):  # restore cursor
            self._restore_cursor()
        elif final == ord('S'):  # SU — scroll up
            self._scroll_up(max(1, p1))
        elif final == ord('T'):  # SD — scroll down
            n = max(1, p1)
            for _ in range(min(n, self.rows)):
                grid = self._grid
                grid.insert(0, self._blank_row())
                grid.pop()
        # 'm' (SGR), 'r' (DECSTBM scroll region), 'n' (DSR), etc — silently ignored.

    # ---------- erase / insert / delete ----------

    def _erase_display(self, mode: int):
        grid = self._grid
        if mode == 0:
            # cursor → end of screen
            row = self._grid[self.cursor_row]
            for c in range(self.cursor_col, self.cols):
                row[c] = b' '
            for r in range(self.cursor_row + 1, self.rows):
                grid[r] = self._blank_row()
        elif mode == 1:
            # start → cursor
            for r in range(0, self.cursor_row):
                grid[r] = self._blank_row()
            row = grid[self.cursor_row]
            for c in range(0, min(self.cursor_col + 1, self.cols)):
                row[c] = b' '
        else:
            # mode 2 or 3 — whole screen (scrollback erase is no-op for us)
            for r in range(self.rows):
                grid[r] = self._blank_row()

    def _erase_line(self, mode: int):
        row = self._grid[self.cursor_row]
        if mode == 0:
            for c in range(self.cursor_col, self.cols):
                row[c] = b' '
        elif mode == 1:
            for c in range(0, min(self.cursor_col + 1, self.cols)):
                row[c] = b' '
        else:
            for c in range(self.cols):
                row[c] = b' '

    def _delete_chars(self, n: int):
        row = self._grid[self.cursor_row]
        del row[self.cursor_col:self.cursor_col + n]
        row.extend([b' '] * (self.cols - len(row)))

    def _erase_chars(self, n: int):
        row = self._grid[self.cursor_row]
        end = min(self.cols, self.cursor_col + n)
        for c in range(self.cursor_col, end):
            row[c] = b' '

    def _insert_blanks(self, n: int):
        row = self._grid[self.cursor_row]
        for _ in range(n):
            row.insert(self.cursor_col, b' ')
        del row[self.cols:]

    # ---------- cursor save/restore + alt screen ----------

    def _save_cursor(self):
        key = "alt" if self.alt_mode else "normal"
        self._saved[key] = (self.cursor_row, self.cursor_col)

    def _restore_cursor(self):
        key = "alt" if self.alt_mode else "normal"
        sv = self._saved[key]
        if sv is not None:
            self.cursor_row, self.cursor_col = sv
            self._clamp_cursor()

    def _set_alt(self, on: bool):
        if on == self.alt_mode:
            return
        if on:
            # Entering alt screen starts blank (xterm behavior).
            self.alt = self._blank_grid()
            self.alt_mode = True
            self.cursor_row = 0
            self.cursor_col = 0
        else:
            self.alt_mode = False
            # Leaving alt screen — return to whatever the normal grid was.

    def _reset(self):
        """RIS: full reset. Clear both screens + scrollback, home cursor."""
        self.normal = self._blank_grid()
        self.alt = self._blank_grid()
        self.alt_mode = False
        self.cursor_row = 0
        self.cursor_col = 0
        self._saved = {"normal": None, "alt": None}
        self.scrollback.clear()

    # ---------- render ----------

    def render(self) -> bytes:
        """Build a self-contained payload that paints current state on attach.

        In alt-screen mode we emit the alt grid positioned absolutely from
        (1,1) — there's no scrollback above it. In normal mode we first
        stream the scrollback rows (CR/LF separated, so the client terminal
        scrolls them into *its* scrollback), then the grid rows, then a
        relative cursor move so the cursor ends inside the grid regardless
        of how much of the scrollback the client terminal kept on-screen.
        """
        out = bytearray()
        out += b'\033c'         # full reset on the client terminal
        out += b'\033[0m'       # explicit attribute reset (defensive)

        if self.alt_mode:
            out += b'\033[?1049h'
            grid = self.alt
            for r in range(self.rows):
                line = b''.join(grid[r]).rstrip(b' ')
                out += f'\033[{r + 1};1H'.encode()
                if line:
                    out += line
            out += f'\033[{self.cursor_row + 1};{self.cursor_col + 1}H'.encode()
            return bytes(out)

        # Normal mode: scrollback then grid, then relative cursor placement.
        # Each row is trimmed of trailing spaces to save bandwidth (the \033c
        # cleared the client terminal to blanks already).
        for row in self.scrollback:
            line = b''.join(row).rstrip(b' ')
            out += line
            out += b'\r\n'

        grid = self.normal
        last_grid_idx = self.rows - 1
        for r in range(self.rows):
            line = b''.join(grid[r]).rstrip(b' ')
            if line:
                out += line
            if r != last_grid_idx:
                out += b'\r\n'

        # Position the cursor inside the grid relative to where the stream
        # left it (end of the last grid row, after any trim). CR brings the
        # cursor to col 0; CUU walks up to the cursor row; CUF walks right
        # to cursor_col. This works whether or not the client kept the
        # scrollback on its visible area.
        out += b'\r'
        up = last_grid_idx - self.cursor_row
        if up > 0:
            out += f'\033[{up}A'.encode()
        if self.cursor_col > 0:
            out += f'\033[{self.cursor_col}C'.encode()
        return bytes(out)

    def render_plain(self, include_scrollback: bool = False) -> str:
        """Current screen as plain multiline text — no ANSI at all.

        For WS `screen_snapshot` frames: the client renders the string in a
        monospace bubble as-is. Trailing spaces per row and trailing blank
        rows are trimmed. Cursor position is NOT embedded — the caller reads
        self.cursor_row / self.cursor_col into the frame payload.

        include_scrollback prepends normal-screen scrollback rows; alt mode
        never has scrollback (mirrors render()).
        """
        lines: list[str] = []
        if include_scrollback and not self.alt_mode:
            for row in self.scrollback:
                lines.append(b''.join(row).decode('utf-8', errors='replace').rstrip())
        grid = self.alt if self.alt_mode else self.normal
        for r in range(self.rows):
            lines.append(b''.join(grid[r]).decode('utf-8', errors='replace').rstrip())
        while lines and not lines[-1]:
            lines.pop()
        return '\n'.join(lines)
