#!/usr/bin/env python3
"""Programm B, Empfaenger: empfaengt via ICMP, prueft, decodiert, speichert, pcap."""

import base64
import binascii
import hashlib
import logging
import os
import struct
import sys
import threading
import time
from scapy.all import IP, ICMP, Raw, conf, send, AsyncSniffer, PcapWriter

IFACE = "lo0"
OUTDIR = "output"
LINGER = 3.0

MAGIC = b"DHBW"
VERSION = 1
ICMP_ID = 0x3107

PT_INIT, PT_DATA, PT_FIN, PT_ACK = 1, 2, 3, 4
ACK_OK, ACK_NACK = 0, 1

ICMP_PAYLOAD_LEN = 56
CHUNK_DATA_LEN = ICMP_PAYLOAD_LEN - 20

_HDR_FMT = ">4sBBIIHI"
HDR_LEN = struct.calcsize(_HDR_FMT)


def build_frame(ptype, seq, total, data):
    data = data or b""
    crc = binascii.crc32(data) & 0xFFFFFFFF
    header = struct.pack(_HDR_FMT, MAGIC, VERSION, ptype, seq, total, len(data), crc)
    frame = header + data
    if len(frame) > ICMP_PAYLOAD_LEN:
        raise ValueError(f"Frame ist zu gross: {len(frame)} statt maximal {ICMP_PAYLOAD_LEN} Byte")
    return frame.ljust(ICMP_PAYLOAD_LEN, b"\x00")


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


def self_test(log):
    # Kurzer Test, fuer die Pruefsumme CRC32
    frame = build_frame(PT_DATA, 1, 1, b"Testdaten")
    log.info("crc test normal: %s", parse_frame(frame)["crc_ok"])

    kaputt = bytearray(frame)
    kaputt[-1] ^= 0xFF  # 1 byte kippen
    log.info("crc test kaputt: %s", parse_frame(bytes(kaputt))["crc_ok"])

    # Gleiche Idee fuer den sha256 ueber die ganze Datei
    daten = b"Testdaten fuer den Selbsttest der Gesamtdatei-Pruefsumme"
    sha_soll = hashlib.sha256(daten).digest()
    log.info("sha256 test normal: %s", hashlib.sha256(daten).digest() == sha_soll)

    daten_kaputt = bytearray(daten)
    daten_kaputt[0] ^= 0xFF
    log.info("sha256 test kaputt: %s", hashlib.sha256(bytes(daten_kaputt)).digest() == sha_soll)


def main():
    conf.verb = 0
    os.makedirs(OUTDIR, exist_ok=True)
    log = get_logger("ProgrammB", os.path.join(OUTDIR, "programm_b.log"))
    self_test(log)
    pcap = PcapWriter(os.path.join(OUTDIR, "programm_b.pcap"), append=False, sync=True)
    out_path = os.path.join(OUTDIR, "empfangen_b.txt")

    state = {"total": None, "sha": None, "chunks": {}, "done": threading.Event()}

    def send_ack(dst, seq, status, icmp_id):
        frame = build_frame(PT_ACK, seq, 0, bytes([status]))
        pkt = IP(dst=dst) / ICMP(type=0, id=icmp_id, seq=seq & 0xFFFF) / Raw(load=frame)
        send(pkt, iface=IFACE, verbose=0)

    def assemble_and_save():
        # Sonst KeyError wenn FIN kommt bevor alle chunks da sind (zb bei nem
        # gefaketen FIN - die crc32 prueft nicht, wer das paket geschickt hat)
        missing = [i for i in range(1, state["total"] + 1) if i not in state["chunks"]]
        if missing:
            log.error("Es fehlen %d Frames: %s", len(missing), missing[:20])
            return

        #Decodierung der Daten (Base64 -> urspruengliche Bytes/Text)
        encoded = b"".join(state["chunks"][i] for i in range(1, state["total"] + 1))
        raw = base64.b64decode(encoded)
        if hashlib.sha256(raw).digest() != state["sha"]:
            log.error("SHA-256 stimmt nicht, Uebertragung fehlerhaft")
            return
        #  Ausgabe auf dem Bildschirm und Speicherung in einer Textdatei
        with open(out_path, "wb") as f:
            f.write(raw)
        print(raw.decode("utf-8", "replace"))
        log.info("SHA-256 korrekt, gespeichert in %s", out_path)

    def on_packet(pkt):
        # Packet Capture, beide Richtungen, ungefiltert, waehrend der Laufzeit
        pcap.write(pkt)
        # Empfang der von Programm A gesendeten Daten vom Netzwerkstack
        if not pkt.haslayer(ICMP) or not pkt.haslayer(Raw) or int(pkt[ICMP].type) != 8:
            return
        frame = parse_frame(bytes(pkt[Raw].load))
        if frame is None or frame["ptype"] == PT_ACK:
            return
        src, icmp_id, seq = pkt[IP].src, int(pkt[ICMP].id), frame["seq"]

        if not frame["crc_ok"]:
            log.warning("seq=%d CRC-Fehler -> NACK", seq)
            send_ack(src, seq, ACK_NACK, icmp_id)
            return

        if frame["ptype"] == PT_INIT:
            state["total"], state["sha"] = frame["total"], frame["data"]
            state["chunks"].clear()
        elif frame["ptype"] == PT_DATA:
            state["chunks"][seq] = frame["data"]
        elif frame["ptype"] == PT_FIN:
            assemble_and_save()
            state["done"].set()

        send_ack(src, seq, ACK_OK, icmp_id)

    sniffer = AsyncSniffer(filter="icmp", iface=IFACE, prn=on_packet, store=False)
    sniffer.start()
    try:
        while not state["done"].wait(0.5):
            pass
        time.sleep(LINGER)
    finally:
        sniffer.stop()
        pcap.close()

    return 0 if state["done"].is_set() else 1


if __name__ == "__main__":
    sys.exit(main())
