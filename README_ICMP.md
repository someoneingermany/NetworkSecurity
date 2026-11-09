# Network Security, ICMP-Datenexfiltration (Programm A & B)

Pruefungsleistung TINF24CS2. Methode: **ICMP**. Sprache: **Python 3 + scapy**.
Der Code ist bewusst minimal gehalten: `main()` haelt pro Programm den kompletten
Ablauf in lokalen Variablen und Closures, keine Klassen, kein State-Objekt. Alle
Parameter (Ziel-IP, Interface, Timeouts) sind fest im Code eingestellt, keine
Kommandozeilenoptionen noetig.

## Dateien
| Datei | Zweck |
|---|---|
| `programm_a.py` | Sender ("Malware"): liest Datei, Base64, sendet via ICMP, schreibt pcap |
| `programm_b.py` | Empfaenger (Angreifer): empfaengt, prueft, decodiert, speichert, pcap |
| `icmp_common.py` | Gemeinsames Modul: Rahmenformat, CRC32, Logging |
| `stgb_202c_202d.txt` | Vorgegebener Quelltext fuer Programm A |
| `doc/documentation.typ` | Abgabe-Dokumentation (Typst) gemaess den Pruefungskriterien |
| `doc/code-erklaerung.typ` | Technische Erklaerung, wie der Code funktioniert (Typst) |

## Setup
Ein virtuelles Environment mit scapy wird benoetigt (liegt bereits als `.venv/` bereit):
```bash
python3 -m venv .venv
./.venv/bin/pip install scapy
```

## Ausfuehren (eine Maschine, Loopback)
Raw Sockets brauchen root, also `sudo`. Zwei Terminals, B zuerst:

Terminal 1:
```bash
sudo ./.venv/bin/python programm_b.py
```
Terminal 2:
```bash
sudo ./.venv/bin/python programm_a.py
```

Fuer zwei Hosts im selben Subnetz: `DST`, `IFACE` am Kopf von `programm_a.py`
und `IFACE` in `programm_b.py` anpassen (z. B. `eth0`, Ziel-IP von B).

## Ergebnisdateien (alle im Ordner `output/`)
- `output/programm_a.pcap`, `output/programm_b.pcap`, Mitschnitt **beider Richtungen, ungefiltert**, zur Laufzeit erzeugt
- `output/empfangen_b.txt`, von B decodierter Text (muss mit `stgb_202c_202d.txt` identisch sein)
- `output/programm_a.log`, `output/programm_b.log`, vollstaendiges Debug-Log
- Vergleich: `diff stgb_202c_202d.txt output/empfangen_b.txt` muss leer sein

## Zuordnung zu den Bewertungskriterien
- **Auslesen der Textdatei** -> `main()` in `programm_a.py` liest `FILE`
- **Codierung (kein Klartext)** -> Base64 (`base64.b64encode`), Decodierung in B (`assemble_and_save`)
- **Senden ueber Netzwerkstack (ICMP)** -> `send_reliable()`: ICMP Echo-Request Typ 8, Payload = eigener Rahmen
- **pcap, beide Richtungen ungefiltert** -> `AsyncSniffer(filter="icmp")` + `PcapWriter` live (in `on_packet`)
- **Integritaet** -> CRC32 pro Frame (`parse_frame` prueft `crc_ok`) **und** SHA-256 ueber die Gesamtdatei
- **Fehlerkorrektur** -> Stop-and-Wait ARQ: B sendet ACK/NACK (Echo-Reply), A sendet bei
  Timeout/NACK automatisch erneut (`send_reliable`, `MAX_RETRIES`, `ACK_TIMEOUT`)

## Protokoll / Rahmenformat (in der ICMP-Payload)
```
magic "NSEC"(4) | version(1) | ptype(1) | seq(4) | total(4) | data_len(2) | crc32(4) | data(...)
```
ptype: INIT(1) = SHA-256 + Dateiname, DATA(2) = Base64-Chunk, FIN(3) = Ende, ACK(4) = Bestaetigung.
Chunk = 36 Byte Base64 -> 56 Byte ICMP-Payload (wie Standard-Ping, unauffaellig).

## Dokumentation (Typst)
Die beiden `.typ`-Dateien in `doc/` mit typst zu PDF rendern:
```bash
typst compile doc/documentation.typ doc/documentation.pdf
typst compile doc/code-erklaerung.typ doc/code-erklaerung.pdf
```
