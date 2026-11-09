#!/usr/bin/env python3
"""Programm A, Sender: liest Datei, codiert (Base64), sendet via ICMP, schreibt pcap."""

import base64
import hashlib
import os
import sys
import threading
import time
from scapy.all import IP, ICMP, Raw, conf, send, AsyncSniffer, PcapWriter
import icmp_common as C

FILE = "stgb_202c_202d.txt"
DST = "127.0.0.1"
IFACE = "lo0"
OUTDIR = "output"
ACK_TIMEOUT = 2.0
MAX_RETRIES = 5


def main():
    conf.verb = 0
    os.makedirs(OUTDIR, exist_ok=True)
    log = C.get_logger("ProgrammA", os.path.join(OUTDIR, "programm_a.log"))
    pcap = PcapWriter(os.path.join(OUTDIR, "programm_a.pcap"), append=False, sync=True)

    lock = threading.Lock()
    ack_status, ack_events = {}, {}

    def on_packet(pkt):
        #Packet Capture, beide Richtungen, ungefiltert, waehrend der Laufzeit
        pcap.write(pkt)
        if not pkt.haslayer(ICMP) or not pkt.haslayer(Raw) or int(pkt[ICMP].type) != 0:
            return
        frame = C.parse_frame(bytes(pkt[Raw].load))
        if frame is None or frame["ptype"] != C.PT_ACK:
            return
        seq = frame["seq"]
        status = frame["data"][0] if frame["data"] else C.ACK_OK
        with lock:
            ack_status[seq] = status
            ev = ack_events.get(seq)
        log.info("<- %s seq=%d", "ACK" if status == C.ACK_OK else "NACK", seq)
        if ev:
            ev.set()

    def send_reliable(ptype, seq, total, data):
        # Senden ueber den Netzwerkstack via ICMP Echo-Request (Typ 8)
        frame = C.build_frame(ptype, seq, total, data)
        pkt = IP(dst=DST) / ICMP(type=8, id=C.ICMP_ID, seq=seq & 0xFFFF) / Raw(load=frame)
        for attempt in range(1, MAX_RETRIES + 1):
            ev = threading.Event()
            with lock:
                ack_events[seq] = ev
                ack_status[seq] = None
            send(pkt, iface=IFACE, verbose=0)
            log.info("-> ptype=%d seq=%d (Versuch %d/%d)", ptype, seq, attempt, MAX_RETRIES)
            #Stop-and-Wait ARQ fuer error control
            if ev.wait(ACK_TIMEOUT) and ack_status.get(seq) == C.ACK_OK:
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
    chunks = [encoded[i:i + C.CHUNK_DATA_LEN] for i in range(0, len(encoded), C.CHUNK_DATA_LEN)]
    total = len(chunks)

    sniffer = AsyncSniffer(filter="icmp", iface=IFACE, prn=on_packet, store=False)
    sniffer.start()
    time.sleep(0.3)

    ok = False
    try:
        ok = send_reliable(C.PT_INIT, 0, total, sha)
        for i, chunk in enumerate(chunks, start=1):
            if not ok:
                break
            ok = send_reliable(C.PT_DATA, i, total, chunk)
        if ok:
            ok = send_reliable(C.PT_FIN, total + 1, total, b"")
    finally:
        time.sleep(0.3)
        sniffer.stop()
        pcap.close()

    log.info("Ergebnis: %s", "ERFOLGREICH" if ok else "FEHLGESCHLAGEN")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
