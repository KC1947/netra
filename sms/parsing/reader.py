"""Length-bounded readers for captured binary fields."""

from __future__ import annotations

import struct


class Truncated(Exception):
    """The captured byte string ended before a declared field did."""


class Malformed(Exception):
    """A length or vector shape is invalid."""


class SafeReader:
    __slots__ = ("buf", "off", "end")

    def __init__(self, buf: bytes, off: int = 0, end: int | None = None):
        self.buf, self.off = buf, off
        self.end = len(buf) if end is None else min(end, len(buf))

    def remaining(self) -> int:
        return max(0, self.end - self.off)

    def need(self, n: int) -> None:
        if n < 0:
            raise Malformed("negative length")
        if self.remaining() < n:
            raise Truncated(f"need {n}, have {self.remaining()}")

    def u8(self) -> int:
        self.need(1)
        value = self.buf[self.off]
        self.off += 1
        return value

    def u16(self) -> int:
        self.need(2)
        value = struct.unpack_from("!H", self.buf, self.off)[0]
        self.off += 2
        return value

    def sub(self, n: int) -> SafeReader:
        self.need(n)
        result = SafeReader(self.buf, self.off, self.off + n)
        self.off += n
        return result

    def expect_end(self) -> None:
        if self.remaining():
            raise Malformed(f"{self.remaining()} trailing bytes")


def u16_vector(data: bytes, len_bytes: int, ceiling: int = 256) -> list[int]:
    """Read an exact-length uint16 vector, rejecting odd or trailing bytes."""
    reader = SafeReader(data)
    if len_bytes == 1:
        length = reader.u8()
    elif len_bytes == 2:
        length = reader.u16()
    else:
        raise Malformed("uint16 vector length prefix must be one or two bytes")
    if length % 2:
        raise Malformed("odd-length uint16 vector")
    body = reader.sub(length)
    reader.expect_end()
    result: list[int] = []
    while body.remaining():
        if len(result) >= ceiling:
            raise Malformed("vector exceeds ceiling")
        result.append(body.u16())
    return result
