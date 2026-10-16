"""Minimal MaxMind DB (.mmdb) writer for tests.

Produces a valid IPv4 database with a one-node search tree, so every address resolves to the
same record. Enough to exercise maxminddb.open_database(), metadata checks and lookups.
"""

from __future__ import annotations

import struct

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"

_TYPES = {"utf8": 2, "double": 3, "uint16": 5, "uint32": 6, "map": 7, "uint64": 9,
          "array": 11, "bool": 14}


def _ctrl(type_num: int, size: int) -> bytes:
    if size < 29:
        size_bits, extra = size, b""
    elif size < 29 + 256:
        size_bits, extra = 29, bytes([size - 29])
    elif size < 285 + 65536:
        size_bits, extra = 30, struct.pack(">H", size - 285)
    else:
        size_bits, extra = 31, struct.pack(">I", size - 65821)[1:]
    if type_num <= 7:
        return bytes([(type_num << 5) | size_bits]) + extra
    return bytes([size_bits, type_num - 7]) + extra


def _uint(value: int, type_name: str) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    return _ctrl(_TYPES[type_name], len(raw)) + raw


def encode(value, hint: str | None = None) -> bytes:
    if isinstance(value, bool):
        return _ctrl(_TYPES["bool"], int(value))
    if isinstance(value, int):
        return _uint(value, hint or "uint32")
    if isinstance(value, float):
        return _ctrl(_TYPES["double"], 8) + struct.pack(">d", value)
    if isinstance(value, str):
        raw = value.encode()
        return _ctrl(_TYPES["utf8"], len(raw)) + raw
    if isinstance(value, dict):
        out = _ctrl(_TYPES["map"], len(value))
        for k, v in value.items():
            out += encode(str(k)) + encode(v)
        return out
    if isinstance(value, list):
        return _ctrl(_TYPES["array"], len(value)) + b"".join(encode(v) for v in value)
    raise TypeError(type(value))


def build_mmdb(record: dict, database_type: str = "GeoLite2-City",
               build_epoch: int = 1_760_000_000) -> bytes:
    node_count = 1
    pointer = node_count + 16  # first byte of the data section
    tree = pointer.to_bytes(3, "big") * 2  # 24-bit records, both branches -> data
    data = encode(record)
    meta = (
        _ctrl(_TYPES["map"], 9)
        + encode("node_count") + _uint(node_count, "uint32")
        + encode("record_size") + _uint(24, "uint16")
        + encode("ip_version") + _uint(4, "uint16")
        + encode("database_type") + encode(database_type)
        + encode("languages") + encode(["en"])
        + encode("binary_format_major_version") + _uint(2, "uint16")
        + encode("binary_format_minor_version") + _uint(0, "uint16")
        + encode("build_epoch") + _uint(build_epoch, "uint64")
        + encode("description") + encode({"en": "test database"})
    )
    return tree + b"\x00" * 16 + data + METADATA_MARKER + meta
