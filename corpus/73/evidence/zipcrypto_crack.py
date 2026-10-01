#!/usr/bin/env python3
"""Offline verifier for a ZipCrypto-protected zip.

flag_bits=0x0009 -> bit0 (encrypted) set, bit6 (strong encryption) clear,
so the archive uses legacy PKWARE ZipCrypto. Candidate passwords are checked
by decrypting the stream, inflating, and comparing CRC32 against the value
declared in the central directory (an independent oracle that does not rely on
unzip's exit status alone).

Read-only with respect to the target: operates on a local copy of the archive.
"""
import binascii
import struct
import sys
import zlib
import zipfile

MASK = 0xFFFFFFFF


def _gen_crc(crc):
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    return crc


_CRCTABLE = [_gen_crc(i) for i in range(256)]


class ZipCrypto:
    """Traditional PKWARE ZipCrypto.

    Key schedule mirrors CPython's zipfile._ZipDecrypter exactly: the stream
    byte uses ``key2 | 2`` with no 16-bit mask, and the CRC primitive is the
    table-driven one rather than zlib's crc32 (they are not interchangeable
    here, because XOR with 0xFFFFFFFF changes the table index).
    """

    def __init__(self, password: bytes):
        self.k0, self.k1, self.k2 = 305419896, 591751049, 878082192
        for b in password:
            self.update(b)

    @staticmethod
    def _crc32(ch: int, crc: int) -> int:
        return (crc >> 8) ^ _CRCTABLE[(crc ^ ch) & 0xFF]

    def update(self, c: int) -> None:
        self.k0 = self._crc32(c, self.k0)
        self.k1 = (self.k1 + (self.k0 & 0xFF)) & MASK
        self.k1 = (self.k1 * 134775813 + 1) & MASK
        self.k2 = self._crc32((self.k1 >> 24) & 0xFF, self.k2)

    def decrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for c in data:
            k = self.k2 | 2
            p = c ^ (((k * (k ^ 1)) >> 8) & 0xFF)
            out.append(p)
            self.update(p)
        return bytes(out)


def raw_entry(path: str):
    """Return (encrypted_payload, crc32, uncompressed_size, method) for the first entry."""
    with open(path, "rb") as fh:
        blob = fh.read()
    zf = zipfile.ZipFile(path)
    info = zf.infolist()[0]
    off = info.header_offset
    n, m = struct.unpack_from("<HH", blob, off + 26)
    start = off + 30 + n + m
    payload = blob[start:start + info.compress_size]
    return payload, info.CRC, info.file_size, info.compress_type


def try_password(payload: bytes, crc: int, size: int, method: int, password: str):
    dec = ZipCrypto(password.encode("utf-8", "replace")).decrypt(payload)
    # Traditional PKWARE encryption always prefixes the compressed stream with a
    # 12-byte encryption header. It must be decrypted (to advance the key
    # schedule) but is NOT part of the compressed data.
    if len(dec) < 12:
        return None
    body = dec[12:]
    if method == zipfile.ZIP_STORED:
        plain = body
    else:
        try:
            plain = zlib.decompress(body, -15)
        except zlib.error:
            return None
    if len(plain) != size:
        return None
    if binascii.crc32(plain) & MASK != crc:
        return None
    return plain


def main() -> int:
    path = sys.argv[1]
    payload, crc, size, method = raw_entry(path)
    print(f"entry: encrypted={len(payload)}B expect_crc=0x{crc:08x} size={size}B method={method}")

    words = [w.rstrip("\n") for w in open(sys.argv[2], encoding="utf-8", errors="replace")]
    info = zipfile.ZipFile(path).infolist()[0]
    # With the data-descriptor bit (flag bit 3) set, the 12th header byte is the
    # high-order byte of the CRC. Used only as a 1-in-256 prefilter; every hit is
    # still confirmed by a full inflate + CRC comparison, so this cannot produce
    # a false positive or mask a true one.
    # Prefilter DISABLED: the 12-byte check byte was empirically found not to be
    # the CRC high byte for archives produced by Info-ZIP, and enabling it produced
    # a false negative against a known-good password. Correctness over speed.
    check = None
    seen, tried, hits = set(), 0, 0
    for w in words:
        if not w or w in seen:
            continue
        seen.add(w)
        tried += 1
        if check is not None and ZipCrypto(w.encode("utf-8", "replace")).decrypt(payload[:12])[11] != check:
            continue
        hits += 1
        out = try_password(payload, crc, size, method, w)
        if out is not None:
            print(f"CRACKED after {tried} candidates ({hits} passed prefilter): {w!r}")
            with open("traffic.pcap", "wb") as fh:
                fh.write(out)
            print(f"wrote traffic.pcap ({len(out)} bytes)")
            return 0
    print(f"no match after {tried} candidates ({hits} passed prefilter)")
    return 1


if __name__ == "__main__":
    sys.exit(main())