#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Programm B, Empfaenger: empfaengt via ICMP, prueft, decodiert, speichert, pcap."""

import base64
import hashlib
import os
import sys
import threading
import time
from scapy.all import IP, ICMP, Raw, conf, send, AsyncSniffer, PcapWriter
import icmp_common as C

IFACE = "lo0"
OUTDIR = "output"
LINGER = 3.0


def main():
    conf.verb = 0
    os.makedirs(OUTDIR, exist_ok=True)
    log = C.get_logger("ProgrammB", os.path.join(OUTDIR, "programm_b.log"))
    pcap = PcapWriter(os.path.join(OUTDIR, "programm_b.pcap"), append=False, sync=True)
    out_path = os.path.join(OUTDIR, "empfangen_b.txt")

    state = {"total": None, "sha": None, "chunks": {}, "done": threading.Event()}

    def send_ack(dst, seq, status, icmp_id):
        frame = C.build_frame(C.PT_ACK, seq, 0, bytes([status]))
        pkt = IP(dst=dst) / ICMP(type=0, id=icmp_id, seq=seq & 0xFFFF) / Raw(load=frame)
        send(pkt, iface=IFACE, verbose=0)

    def assemble_and_save():
        # Aufgabe B3: Decodierung der Daten (Base64 -> urspruengliche Bytes/Text)
        encoded = b"".join(state["chunks"][i] for i in range(1, state["total"] + 1))
        raw = base64.b64decode(encoded)
        if hashlib.sha256(raw).digest() != state["sha"]:
            log.error("SHA-256 stimmt nicht, Uebertragung fehlerhaft")
            return
        # Aufgabe B4: Ausgabe auf dem Bildschirm und Speicherung in einer Textdatei
        with open(out_path, "wb") as f:
            f.write(raw)
        print(raw.decode("utf-8", "replace"))
        log.info("SHA-256 korrekt, gespeichert in %s", out_path)

    def on_packet(pkt):
        # Aufgabe B2: Packet Capture, beide Richtungen, ungefiltert, waehrend der Laufzeit
        pcap.write(pkt)
        # Aufgabe B1: Empfang der von Programm A gesendeten Daten vom Netzwerkstack
        if not pkt.haslayer(ICMP) or not pkt.haslayer(Raw) or int(pkt[ICMP].type) != 8:
            return
        frame = C.parse_frame(bytes(pkt[Raw].load))
        if frame is None or frame["ptype"] == C.PT_ACK:
            return
        src, icmp_id, seq = pkt[IP].src, int(pkt[ICMP].id), frame["seq"]

        if not frame["crc_ok"]:
            log.warning("seq=%d CRC-Fehler -> NACK", seq)
            send_ack(src, seq, C.ACK_NACK, icmp_id)
            return

        if frame["ptype"] == C.PT_INIT:
            state["total"], state["sha"] = frame["total"], frame["data"][:32]
            state["chunks"].clear()
        elif frame["ptype"] == C.PT_DATA:
            state["chunks"][seq] = frame["data"]
        elif frame["ptype"] == C.PT_FIN:
            assemble_and_save()
            state["done"].set()

        send_ack(src, seq, C.ACK_OK, icmp_id)

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
