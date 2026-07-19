"""Monotonic ULID generator.

Protocol frames are identified by ULIDs (protocol/messages.md §2): 26 chars
of Crockford base32, lexicographically sortable by creation time. The client
uses `last_seen_id` as a cursor, so IDs generated within the same millisecond
MUST still be strictly increasing — a plain random ULID breaks that. We keep
the classic monotonic scheme: same millisecond → increment the previous
randomness by one.

asyncio is single-threaded, so no lock is needed.
"""

from __future__ import annotations

import os
import time

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

_last_ms = -1
_last_rand = 0  # 80-bit randomness of the previous ULID


def new_ulid() -> str:
    global _last_ms, _last_rand
    ms = time.time_ns() // 1_000_000
    if ms <= _last_ms:
        # Same (or rewound) millisecond: bump randomness to stay monotonic.
        ms = _last_ms
        _last_rand = (_last_rand + 1) & ((1 << 80) - 1)
    else:
        _last_ms = ms
        _last_rand = int.from_bytes(os.urandom(10), "big")

    value = (ms << 80) | _last_rand
    chars = []
    for shift in range(125, -5, -5):
        chars.append(_CROCKFORD[(value >> shift) & 0x1F])
    return "".join(chars)
