#!/usr/bin/env python3
"""Programm A, Sender: liest Datei, codiert (Base64), sendet via ICMP, schreibt pcap."""

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

FILE = "stgb_202c_202d.txt"
DST = "127.0.0.1"
IFACE = "lo0"
OUTDIR = "output"
ACK_TIMEOUT = 2.0
MAX_RETRIES = 5

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
    if len(data) > CHUNK_DATA_LEN:
        raise ValueError(f"Nutzdaten sind zu gross: {len(data)} statt maximal {CHUNK_DATA_LEN} Byte")
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


def main():
    conf.verb = 0
    os.makedirs(OUTDIR, exist_ok=True)
    log = get_logger("ProgrammA", os.path.join(OUTDIR, "programm_a.log"))
    pcap = PcapWriter(os.path.join(OUTDIR, "programm_a.pcap"), append=False, sync=True)

    lock = threading.Lock()
    ack_status, ack_events = {}, {}

    def on_packet(pkt):
        #Packet Capture, beide Richtungen, ungefiltert, waehrend der Laufzeit
        pcap.write(pkt)
        if not pkt.haslayer(ICMP) or not pkt.haslayer(Raw) or int(pkt[ICMP].type) != 0:
            return
        frame = parse_frame(bytes(pkt[Raw].load))
        if frame is None or frame["ptype"] != PT_ACK:
            return
        seq = frame["seq"]
        status = frame["data"][0] if frame["data"] else ACK_OK
        with lock:
            ack_status[seq] = status
            ev = ack_events.get(seq)
        log.info("<- %s seq=%d", "ACK" if status == ACK_OK else "NACK", seq)
        if ev:
            ev.set()

    def send_reliable(ptype, seq, total, data):
        # Senden ueber den Netzwerkstack via ICMP Echo-Request (Typ 8)
        frame = build_frame(ptype, seq, total, data)
        pkt = IP(dst=DST) / ICMP(type=8, id=ICMP_ID, seq=seq & 0xFFFF) / Raw(load=frame)
        for attempt in range(1, MAX_RETRIES + 1):
            ev = threading.Event()
            with lock:
                ack_events[seq] = ev
                ack_status[seq] = None
            send(pkt, iface=IFACE, verbose=0)
            log.info("-> ptype=%d seq=%d (Versuch %d/%d)", ptype, seq, attempt, MAX_RETRIES)
            #Stop-and-Wait ARQ fuer error control
            if ev.wait(ACK_TIMEOUT) and ack_status.get(seq) == ACK_OK:
                return True
        log.error("seq=%d nach %d Versuchen nicht bestaetigt, Abbruch", seq, MAX_RETRIES)
        return False

    if not os.path.isfile(FILE):
        log.error("Eingabedatei nicht gefunden: %s", FILE)
        return 2

    # Auslesen der Textdatei mit den zu extrahierenden Daten
    with open(FILE, "rb") as f:
        raw = f.read()
    sha = hashlib.sha256(raw).digest()

    # Codierung des Textinhaltes (Base64, kein Klartext auf dem Netz)
    encoded = base64.b64encode(raw)
    chunks = [encoded[i:i + CHUNK_DATA_LEN] for i in range(0, len(encoded), CHUNK_DATA_LEN)]
    total = len(chunks)

    sniffer = AsyncSniffer(filter="icmp", iface=IFACE, prn=on_packet, store=False)
    sniffer.start()
    time.sleep(0.3)

    ok = False
    try:
        ok = send_reliable(PT_INIT, 0, total, sha)
        for i, chunk in enumerate(chunks, start=1):
            if not ok:
                break
            ok = send_reliable(PT_DATA, i, total, chunk)
        if ok:
            ok = send_reliable(PT_FIN, total + 1, total, b"")
    finally:
        time.sleep(0.3)
        sniffer.stop()
        pcap.close()

    log.info("Ergebnis: %s", "ERFOLGREICH" if ok else "FEHLGESCHLAGEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
