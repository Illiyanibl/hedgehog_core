"""Plain-text transcript writer — ported from broker.py HistoryWriter.

Changes against the broker original (see docs/broker-audit.md):
- The caller passes an explicit file path (chat transcript lives at
  /data/chats/<chatId>/transcript.log) instead of the broker's
  HISTORY_DIR/<name>/<timestamp>.log convention.
- Size limits are constructor parameters instead of module constants.
Everything else — ANSI stripping, carry buffer for torn escapes, tail
truncation with hysteresis — is the broker code verbatim.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


class HistoryWriter:
    """Persistent plain-text transcript of a session's PTY output.

    The file is kept under max_bytes by truncating from the front (tail-mode)
    once it exceeds the limit by truncate_hysteresis — that hysteresis
    amortizes I/O so we don't rewrite the file on every byte over the limit.

    PTY output contains ANSI escape sequences (colors, cursor movement, alt
    screen). We strip them on write so the file is readable in any plain text
    editor / file manager. ESC sequences can straddle chunk boundaries, so a
    small carry buffer is held back when the tail of a chunk looks like the
    beginning of an unterminated escape.
    """

    # Match ANSI/VT escape sequences:
    #   CSI:  ESC [ params intermediates final         (final byte 0x40-0x7E)
    #   OSC:  ESC ] data (BEL | ESC \)                  (terminated by BEL or ST)
    #   single-char esc: ESC <0x40-0x5F>                (e.g. ESC c, ESC =, ESC D)
    _ANSI_RE = re.compile(
        rb'\x1b\[[0-?]*[ -/]*[@-~]'
        rb'|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)'
        rb'|\x1b[\x40-\x5F]'
    )
    # Strip remaining control bytes except \t \n \r.
    _CTRL_RE = re.compile(rb'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

    def __init__(self, path: Path, max_bytes: int = 10 * 1024 * 1024,
                 truncate_hysteresis: int = 512 * 1024):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._max_bytes = max_bytes
        self._hysteresis = truncate_hysteresis
        self._fh = self.path.open("ab", buffering=0)
        self._carry = b''
        try:
            self._size = self.path.stat().st_size
        except OSError:
            self._size = 0

    def write(self, data: bytes):
        """Strip ANSI/control bytes and append plain text to the transcript."""
        if not data:
            return
        buf = self._carry + data
        flush_part, self._carry = self._safe_split(buf)
        if not flush_part:
            return
        cleaned = self._ANSI_RE.sub(b'', flush_part)
        cleaned = self._CTRL_RE.sub(b'', cleaned)
        if not cleaned:
            return
        try:
            self._fh.write(cleaned)
        except OSError:
            return
        self._size += len(cleaned)
        if self._size >= self._max_bytes + self._hysteresis:
            self._truncate_tail()

    def close(self):
        """Flush any held-back carry as best-effort, then close the file."""
        if self._carry:
            cleaned = self._ANSI_RE.sub(b'', self._carry)
            cleaned = self._CTRL_RE.sub(b'', cleaned)
            if cleaned:
                try:
                    self._fh.write(cleaned)
                    self._size += len(cleaned)
                except OSError:
                    pass
            self._carry = b''
        try:
            self._fh.close()
        except OSError:
            pass

    @staticmethod
    def _safe_split(data: bytes) -> tuple[bytes, bytes]:
        """Find a split point that doesn't tear an unterminated ESC sequence.

        Returns (flushable_prefix, carry_to_keep).
        """
        idx = data.rfind(b'\x1b')
        if idx == -1:
            return data, b''
        tail = data[idx:]
        # OSC terminates on BEL (0x07) or ESC\; CSI/single-char terminate on
        # any byte in 0x40-0x7E after the intro. If we see one of those in
        # tail, the sequence is already complete.
        if b'\x07' in tail[1:]:
            return data, b''
        for byte in tail[2:]:  # skip ESC and its first byte
            if 0x40 <= byte <= 0x7E:
                return data, b''
        # Empirical safety valve: if carry would be huge, the ESC was probably
        # a stray literal — flush everything rather than let the carry grow.
        if len(tail) > 256:
            return data, b''
        return data[:idx], tail

    def _truncate_tail(self):
        """Atomically rewrite the file with only the last max_bytes bytes."""
        try:
            self._fh.flush()
            with self.path.open("rb") as src:
                src.seek(-self._max_bytes, os.SEEK_END)
                tail_bytes = src.read()
            tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
            with tmp_path.open("wb") as tmp:
                tmp.write(tail_bytes)
            os.replace(tmp_path, self.path)
            # Re-open in append mode: the previous fd now points at an unlinked
            # inode and would silently swallow further writes.
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = self.path.open("ab", buffering=0)
            self._size = len(tail_bytes)
        except OSError:
            # If truncation fails (disk full, permission issue), keep going —
            # write() will keep appending and we'll retry on next overshoot.
            pass
