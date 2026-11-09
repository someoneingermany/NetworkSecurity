#!/usr/bin/env python3
"""Rahmenformat, CRC32, Logging."""

import binascii
import logging
import struct

MAGIC = b"DHBW"
VERSION = 1
ICMP_ID = 0x3107

PT_INIT, PT_DATA, PT_FIN, PT_ACK = 1, 2, 3, 4
ACK_OK, ACK_NACK = 0, 1

CHUNK_DATA_LEN = 36  # + 20 Byte Header = 56 Byte ICMP-Payload (wie Standard-Ping)

_HDR_FMT = ">4sBBIIHI"
HDR_LEN = struct.calcsize(_HDR_FMT)


def build_frame(ptype, seq, total, data):
    data = data or b""
    crc = binascii.crc32(data) & 0xFFFFFFFF
    header = struct.pack(_HDR_FMT, MAGIC, VERSION, ptype, seq, total, len(data), crc)
    return header + data


def parse_frame(raw):
    if raw is None or len(raw) < HDR_LEN:
        return None
    magic, version, ptype, seq, total, dlen, crc = struct.unpack(_HDR_FMT, raw[:HDR_LEN])
    if magic != MAGIC:
        return None
    data = raw[HDR_LEN:HDR_LEN + dlen]
    crc_ok = (binascii.crc32(data) & 0xFFFFFFFF) == crc and len(data) == dlen
    return {"ptype": ptype, "seq": seq, "total": total, "crc_ok": crc_ok, "data": data}


def get_logger(name, logfile):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False
    fmt = logging.Formatter("%(message)s")
    for handler in (logging.StreamHandler(), logging.FileHandler(logfile, mode="w", encoding="utf-8")):
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger
