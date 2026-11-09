#set page(
  paper: "a4",
  margin: (x: 2.4cm, y: 2.4cm),
  numbering: "1 / 1",
)
#set text(font: "Helvetica Neue", size: 10.5pt, lang: "de")
#set par(justify: true, leading: 0.62em)
#show heading: set block(above: 1.2em, below: 0.6em)
#set heading(numbering: "1.")
#show raw.where(block: false): r => box(fill: luma(240), inset: (x: 3pt), outset: (y: 2pt), radius: 2pt, text(font: "Menlo", size: 9pt, r))
#show raw.where(block: true): r => block(fill: luma(244), inset: 8pt, radius: 3pt, width: 100%, text(font: "Menlo", size: 9pt, r))

#align(center)[
  #text(size: 17pt, weight: "bold")[Wie der Code funktioniert]
  #v(0.2em)
  #text(size: 11pt)[Technische Erläuterung der ICMP-Exfiltration · Programm A, B und `icmp_common`]
  #v(0.4em)
  #text(size: 9.5pt, fill: luma(90))[Network Security · TINF24CS2 · Python 3 / Scapy]
]
#v(0.6em)
#line(length: 100%, stroke: 0.5pt + luma(180))
#v(0.4em)

= Überblick

Das Projekt besteht aus drei Python-Dateien. `programm_a.py` ist der Sender, der die
Textdatei ausliest und verschickt; `programm_b.py` ist der Empfänger, der die Daten
wieder einsammelt, prüft und abspeichert; `icmp_common.py` enthält die Bausteine, die
beide brauchen: das Rahmenformat, die Prüfsummen und das Logging.

Der gesamte Code ist bewusst funktionsbasiert geschrieben – es gibt keine eigenen
Klassen. Zusammengehalten wird eine laufende Übertragung stattdessen durch ein einfaches
Wörterbuch, das überall `st` (für „state", also Zustand) heißt. Es wird einmal zu Beginn
mit `make_state()` angelegt und danach an jede Funktion weitergereicht. Jede Funktion
liest aus diesem Dict und schreibt ihre Ergebnisse (Zähler, empfangene Pakete,
Bestätigungen) wieder hinein. So ersetzt das `st`-Dict das, was sonst die Felder eines
Objekts wären.

#table(
  columns: (auto, 1fr),
  inset: 6pt,
  stroke: 0.4pt + luma(170),
  table.header([*Datei*], [*Aufgabe*]),
  [`icmp_common.py`], [Rahmenformat (`build_frame`/`parse_frame`), CRC32, Hexdump, Logging],
  [`programm_a.py`], [Datei lesen, Base64, senden, auf Bestätigung warten, pcap schreiben],
  [`programm_b.py`], [empfangen, prüfen, bestätigen, zusammensetzen, speichern, pcap schreiben],
)

= Das gemeinsame Modul `icmp_common.py`

== Konstanten und Rahmenformat

Ganz oben stehen die festen Werte, auf die sich beide Seiten einigen. `MAGIC = b"NSEC"`
ist die Kennung, an der ein Paket als „von uns" erkannt wird. Die Pakettypen `PT_INIT`,
`PT_DATA`, `PT_FIN` und `PT_ACK` unterscheiden, ob ein Paket die Übertragung eröffnet,
Nutzdaten trägt, sie abschließt oder nur eine Bestätigung ist. `CHUNK_DATA_LEN = 36`
legt fest, wie viele Base64-Zeichen in ein einzelnes Paket passen.

Der Kopf jedes Rahmens wird mit dem Format-String `">4sBBIIHI"` gepackt. Gelesen wird er
so: `>` bedeutet Network Byte Order (Big Endian), `4s` sind die vier Magic-Bytes, die
beiden `B` sind Version und Pakettyp (je ein Byte), die drei `I` sind Sequenznummer,
Gesamtzahl und CRC32 (je vier Byte), und `H` ist die Datenlänge (zwei Byte). Zusammen
ergibt das genau 20 Byte, die `HDR_LEN` festhält.

`build_frame()` setzt diesen Kopf zusammen und hängt die Daten an. Vorher berechnet es
die CRC32-Prüfsumme über den Datenteil und legt sie mit in den Kopf:

```python
def build_frame(ptype, seq, total, data):
    data = data or b""
    crc = binascii.crc32(data) & 0xFFFFFFFF
    header = struct.pack(_HDR_FMT, MAGIC, VERSION, ptype, seq, total, len(data), crc)
    return header + data
```

`parse_frame()` ist das Gegenstück. Es prüft zuerst, ob das Paket lang genug ist und das
richtige Magic trägt – andernfalls gibt es `None` zurück, und das Paket gilt als fremder
Verkehr. Danach zerlegt es den Kopf, schneidet den Datenteil heraus und rechnet die
CRC32 neu nach. Das Ergebnis dieses Vergleichs steht im Feld `crc_ok`; darüber erkennt
der Empfänger später, ob ein Paket unterwegs beschädigt wurde.

== Kleine Helfer

`hexdump()` formatiert Bytes in die bekannte zweispaltige Ansicht (links die Hex-Werte,
rechts die druckbaren Zeichen) – praktisch fürs Debug-Log. `human_bytes()` macht aus
einer Byte-Zahl eine lesbare Angabe wie `2.14 KB`.

== Logging

`setup_logging()` richtet zwei Ausgaben gleichzeitig ein: die Konsole und eine Logdatei.
Die Konsole zeigt ab Stufe INFO (mit `-v` auch DEBUG) und ist farbig, die Datei
protokolliert immer alles auf DEBUG-Ebene samt Datum und Logger-Namen. Die eigentliche
Formatierung übernehmen die beiden Funktionen `_format_console()` und `_format_file()`.
Da die `logging`-Bibliothek an einen Handler ein Formatter-Objekt mit einer
`format`-Methode erwartet, baut der Helfer `_make_formatter()` eine leere
Formatter-Instanz und hängt einfach unsere Funktion an deren `.format` – so bleibt alles
funktionsbasiert, ohne eine eigene Formatter-Klasse. `banner()` schließlich gibt einen
eingerahmten Kopfblock aus, wie man ihn am Anfang und Ende jedes Laufs sieht.

= Der Sender `programm_a.py`

== Zustand anlegen

`make_state()` legt den Ausgabeordner an, öffnet die pcap-Datei zum Schreiben, startet
das Logging und sammelt alles in einem Dict: Zieladresse, Interface, Timeout, die
Wörterbücher für die Bestätigungen (`ack_status`, `ack_events`), ein `Lock` für den
sicheren Zugriff aus mehreren Threads und die Zähler für die Statistik.

== Senden und auf Bestätigung warten

`send_frame()` baut mit `build_frame()` den Rahmen, verpackt ihn in ein
`IP()/ICMP()/Raw()`-Paket und schickt ihn mit `send()` auf die Reise. Der ICMP-Typ 8
macht daraus einen Echo-Request (einen Ping).

Darüber liegt `send_reliable()` – hier steckt die Fehlerkorrektur. Die Funktion schickt
ein Paket und wartet dann mit einem `threading.Event` darauf, dass die Bestätigung
eintrifft:

```python
def send_reliable(st, ptype, seq, total, data):
    for attempt in range(1, st["max_retries"] + 1):
        ev = threading.Event()
        with st["lock"]:
            st["ack_events"][seq] = ev
            st["ack_status"][seq] = None
        send_frame(st, ptype, seq, total, data)
        if ev.wait(st["ack_timeout"]):          # auf ACK/NACK warten
            if st["ack_status"].get(seq) == C.ACK_OK:
                return True                      # bestätigt -> fertig
            # sonst war es ein NACK -> Schleife sendet erneut
        # sonst Timeout -> Schleife sendet erneut
    return False                                 # nach max. Versuchen aufgeben
```

Der Trick: Das `Event` wird nicht hier gesetzt, sondern vom Sniffer-Thread, sobald die
passende Bestätigung ankommt. Kommt sie mit Status „OK", ist das Paket durch; kommt ein
NACK oder gar nichts (Timeout), läuft die Schleife erneut und sendet dasselbe Paket noch
einmal – bis zu `max_retries` Mal.

== Den Rückkanal mithören

`on_packet()` ist die Funktion, die der Sniffer für jedes gesehene ICMP-Paket aufruft.
Sie hat zwei Jobs. Erstens schreibt sie jedes Paket sofort in die pcap-Datei – dadurch
landen beide Richtungen ungefiltert im Mitschnitt. Zweitens schaut sie, ob es sich um
einen Echo-Reply (Typ 0) mit einem gültigen ACK-Rahmen handelt. Wenn ja, trägt sie den
Status ein und löst das passende `Event` aus – genau darauf wartet `send_reliable()`.
Fremde Pings und die eigenen Requests werden hier ignoriert.

== Der Ablauf in `run()`

`run()` zieht alles zusammen: Datei einlesen, SHA-256 bilden, mit `base64.b64encode`
codieren und in 36-Zeichen-Stücke schneiden. Dann startet der Sniffer, und es geht in
drei Phasen los – erst das INIT-Paket (mit SHA-256 und Dateiname), dann die Datenpakete
in einer Schleife, zum Schluss das FIN-Paket. Jedes davon geht über `send_reliable()`,
wird also garantiert bestätigt oder nach mehreren Versuchen als Fehler gemeldet. Am Ende
wird der Sniffer gestoppt, die pcap geschlossen und `print_stats()` zieht Bilanz.

= Der Empfänger `programm_b.py`

== Zustand und Hilfsfunktionen

`make_state()` ist analog zum Sender aufgebaut, nur dass hier zusätzlich der Puffer für
die empfangenen Stücke (`chunks`), die erwarteten Metadaten und ein `done`-Event stehen,
das signalisiert, wann die Übertragung komplett ist. `send_ack()` baut einen ACK- oder
NACK-Rahmen und schickt ihn als Echo-Reply (Typ 0) zurück an den Sender.

== Pakete verarbeiten

`on_packet()` ist das Herzstück. Für jedes Paket schreibt es zuerst in die pcap, dann
filtert es auf eigene Echo-Requests (Typ 8) mit gültigem Rahmen. Als Erstes wird die
CRC32 geprüft: Ist sie falsch, geht sofort ein NACK zurück und das Paket wird verworfen.
Ist sie in Ordnung, entscheidet der Pakettyp, welche Handler-Funktion übernimmt:

```python
    if frame["ptype"] == C.PT_INIT:
        handle_init(st, frame)
    elif frame["ptype"] == C.PT_DATA:
        handle_data(st, frame)
    elif frame["ptype"] == C.PT_FIN:
        handle_fin(st)
    send_ack(st, src, seq, C.ACK_OK, icmp_id)     # jedes gute Paket bestätigen
```

`handle_init()` merkt sich, wie viele Pakete kommen und welchen SHA-256 das Ergebnis
haben muss. `handle_data()` legt das Datenstück unter seiner Sequenznummer ab; ein schon
bekanntes Stück wird als Duplikat erkannt und nur noch einmal bestätigt, ohne es doppelt
zu speichern. `handle_fin()` stößt das Zusammensetzen an und setzt das `done`-Event.

== Zusammensetzen und speichern

`assemble_and_save()` prüft zuerst, ob alle Stücke von 1 bis `total` da sind. Dann hängt
es sie der Reihe nach aneinander, decodiert mit `base64.b64decode` und vergleicht den
SHA-256 des Ergebnisses mit dem erwarteten Wert. Nur wenn der stimmt, gilt die
Übertragung als fehlerfrei. Anschließend wird der Text in die Datei geschrieben und auf
dem Bildschirm ausgegeben.

== Der Ablauf in `run()`

`run()` startet den Sniffer und wartet dann in einer Schleife auf das `done`-Event. Weil
die eigentliche Arbeit im Sniffer-Thread passiert (über `on_packet`), muss der
Hauptthread nur warten. Nach dem FIN läuft der Empfänger noch kurz weiter (`linger`),
um verspätete Wiederholungen des Senders bei Bedarf erneut zu bestätigen, dann wird
sauber abgeräumt und die Statistik ausgegeben.

= Das Zusammenspiel

Für jedes Datenpaket ergibt sich derselbe Takt: A schickt einen Echo-Request mit einem
Datenstück, B prüft die Prüfsumme und antwortet mit einem Echo-Reply – entweder ACK
(alles gut) oder NACK (kaputt, bitte nochmal). A wartet genau auf diese Antwort, bevor es
das nächste Paket schickt. Dieses einfache Hin und Her, in der Netzwerktechnik
Stop-and-Wait genannt, sorgt zusammen mit der CRC32 pro Paket und dem SHA-256 über das
Ganze dafür, dass am Ende Zeichen für Zeichen dasselbe ankommt, was losgeschickt wurde.

Wichtig für das Verständnis ist der eine Punkt mit den Threads: In beiden Programmen
läuft der Scapy-Sniffer in einem eigenen Hintergrund-Thread und ruft dort `on_packet`
auf. Der Hauptthread sendet (bei A) bzw. wartet (bei B). Die Verständigung zwischen
beiden läuft über das `st`-Dict und die `threading.Event`-Objekte – deshalb wird der
Zugriff auf die gemeinsamen Wörterbücher bei A mit einem `Lock` abgesichert.
