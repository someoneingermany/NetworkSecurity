#set page(
  paper: "a4",
  margin: (x: 2.4cm, y: 2.4cm),
  numbering: "1 / 1",
)
#set text(font: "Helvetica Neue", size: 10.5pt, lang: "de")
#set par(justify: true, leading: 0.62em)
#show heading: set block(above: 1.2em, below: 0.6em)
#set heading(numbering: "1.")

#align(center)[
  #text(size: 17pt, weight: "bold")[Datenexfiltration über ICMP]
  #v(0.2em)
  #text(size: 11pt)[Dokumentation zur Prüfungsleistung Network Security · TINF24CS2]
  #v(0.4em)
  #text(size: 9.5pt, fill: luma(90))[Devi Müller · Methode: ICMP · Python 3 / Scapy]
]
#v(0.6em)
#line(length: 100%, stroke: 0.5pt + luma(180))
#v(0.4em)

= Worum es geht

Die Aufgabe war, einen Datenabfluss über das Netzwerk nachzustellen: Ein Programm A
liest eine Textdatei aus (die Paragrafen 202c und 202d StGB) und schickt deren Inhalt
an ein Programm B, das die Daten wieder zusammensetzt, auf dem Bildschirm anzeigt und
abspeichert. Beide Programme schneiden ihren eigenen Netzwerkverkehr als pcap mit.

Als Transportweg wurde *ICMP* gewählt; beide Programme sind in Python mit der Bibliothek
Scapy umgesetzt. Die eigentlichen Nutzdaten wandern nicht im Klartext über die Leitung,
sondern Base64-codiert in der Nutzlast von ganz normalen Ping-Paketen. Dieses Dokument
erklärt, warum ICMP, wie der Transport funktioniert, wie codiert und decodiert wird und
wie sichergestellt wird, dass am Ende wirklich Zeichen für Zeichen dasselbe ankommt, was
losgeschickt wurde.

Konkret ist die Vorlage rund 1,6 Kilobyte groß. Nach der Base64-Codierung wird daraus
ein Strom von knapp 2,2 Kilobyte, der in Stücke von je 36 Zeichen geschnitten wird. Das
ergibt 61 Datenpakete, dazu je ein Paket für den Anfang und das Ende der Übertragung.
Das klingt nach wenig, reicht aber völlig, um alle Mechanismen an einem echten Beispiel
zu zeigen: Transport, Codierung, Prüfsummen und die automatische Wiederholung bei
Fehlern.

Die beiden Programme heißen schlicht `programm_a.py` (der Sender) und `programm_b.py`
(der Empfänger); gemeinsame Bausteine wie das Rahmenformat und die Prüfsummen liegen in
`icmp_common.py`.

= Warum ICMP und nicht ARP, SNMP oder DNS

Für die Wahl gab es ein paar handfeste Gründe. ICMP ist auf praktisch jedem Netz
erlaubt und unverdächtig: Ping-Verkehr sieht niemand als Angriff, und die meisten
Firewalls lassen Echo-Requests und -Replies durch. Genau das macht den Protokolltyp
für eine verdeckte Übertragung attraktiv: Man versteckt sich im Rauschen, das
sowieso ständig unterwegs ist.

Der zweite Grund ist technischer Natur: Ein ICMP-Echo-Request darf eine frei wählbare
Nutzlast tragen, und der Empfänger antwortet per Definition mit einem Echo-Reply. Damit
liefert das Protokoll gleich zwei Dinge, die ohnehin gebraucht werden: erstens einen
Platz für die Daten (die Payload), zweitens einen natürlichen Rückkanal für
Bestätigungen. Der Reply ist ohnehin vorgesehen und muss nur mit Inhalt gefüllt werden.
Request hin, Reply zurück, das ist genau der Ablauf, den ICMP vorsieht; der Entwurf hält
sich also an das Protokoll und zweckentfremdet nur die Nutzlast.

Die anderen drei Methoden wurden verworfen. ARP wäre auf die Broadcast-Domain
beschränkt und kennt keinen sauberen Rückweg für Quittungen. DNS hätte bedeutet, Daten
in Subdomains zu pressen, mit allen Längenbegrenzungen und Zeichenbeschränkungen, die
Hostnamen so mit sich bringen. SNMP wiederum setzt eine funktionierende Agenten-Manager-
Infrastruktur voraus und wirkt in einem kleinen Testnetz eher aufgesetzt. ICMP war für
das Szenario schlicht der direkteste und robusteste Weg.

= Wie die Daten übers Netz gehen

Programm A verschickt die Daten in vielen kleinen ICMP-Echo-Requests (Typ 8). In jede
Nutzlast wird ein eigener kleiner Rahmen (ein „Frame") gelegt, der aus einem Kopf und
dem eigentlichen Datenstück besteht. Programm B hört mit einem Raw-Socket auf
eingehende Echo-Requests, erkennt an einer Kennung, welche davon aus Programm A stammen,
und schickt für jedes korrekt empfangene Paket einen Echo-Reply (Typ 0) als Bestätigung
zurück. Fremder Ping-Verkehr wird dabei ignoriert.

Dabei wird der von ICMP vorgesehene Ablauf bewusst eingehalten, statt ihn zu brechen:
Jeder Request bekommt eine feste Identifier-Nummer und eine fortlaufende Sequenznummer
im ICMP-Kopf, genau wie ein echter Ping sie setzt, und B antwortet darauf mit einem
passenden Echo-Reply. Von außen betrachtet ist das also ein formal korrekter
Ping-Austausch, nur dass in der Nutzlast nicht die üblichen Füllbytes stehen, sondern
der codierte Rahmen. So bleibt der Verkehr protokollkonform und fällt nicht schon
dadurch auf, dass er sich seltsam verhält.

Damit der Verkehr unauffällig bleibt, ist die Paketgröße bewusst an einen normalen Ping
angelehnt. Ein Standard-Ping unter macOS oder Linux trägt 56 Byte Nutzlast; der Rahmen
ist mit 20 Byte Kopf plus 36 Byte Daten genauso groß. Wer nur auf die Paketgrößen
schaut, sieht also nichts Ungewöhnliches.

Der Rahmenkopf ist 20 Byte lang und immer gleich aufgebaut:

#figure(
  table(
    columns: (auto, auto, 1fr),
    inset: 6pt,
    align: (left, center, left),
    stroke: 0.4pt + luma(170),
    table.header([*Feld*], [*Größe*], [*Bedeutung*]),
    [magic], [4 B], [Kennung „NSEC", um eigene Pakete von fremdem Ping zu trennen],
    [version], [1 B], [Protokollversion (aktuell 1)],
    [ptype], [1 B], [Pakettyp: INIT, DATA, FIN oder ACK],
    [seq], [4 B], [laufende Nummer des Frames],
    [total], [4 B], [Gesamtzahl der Datenframes],
    [data#sub[len]], [2 B], [Länge des Datenteils],
    [crc32], [4 B], [Prüfsumme über den Datenteil],
    [data], [0–36 B], [das eigentliche (codierte) Datenstück],
  ),
  caption: [Aufbau eines Frames innerhalb der ICMP-Nutzlast.],
)

Eine Übertragung läuft in drei Phasen ab. Zuerst schickt A ein *INIT*-Paket mit den
Metadaten (dem SHA-256-Fingerabdruck der Originaldatei und dem Dateinamen) und sagt
damit auch, wie viele Datenpakete folgen werden. Danach kommen die *DATA*-Pakete, jedes
mit einem Stück der codierten Daten und seiner eigenen laufenden Nummer. Zum Schluss
markiert ein *FIN*-Paket das Ende, woraufhin B alles zusammensetzt und prüft. Die
*ACK*-Pakete sind die Bestätigungen, die B über den Echo-Reply zurückschickt.

Wichtig ist, dass die Daten tatsächlich durch den Netzwerkstack des Betriebssystems
gehen und nicht etwa über einen direkten Funktionsaufruf zwischen den Prozessen. Scapy
baut das IP/ICMP-Paket und übergibt es an einen Socket; der Kernel verschickt es, und
auf der Gegenseite liest ein Raw-Socket es wieder ein. In Wireshark ist jeder Schritt
sichtbar.

Für ein einzelnes Datenpaket sieht der Ablauf zwischen A und B immer gleich aus:

+ A baut den Frame zusammen: Kopf mit laufender Nummer und Prüfsumme, dahinter das
  36 Zeichen lange Datenstück.
+ A verpackt den Frame in einen ICMP-Echo-Request und schickt ihn an B. Parallel notiert
  A sich, dass es für diese Nummer noch auf eine Bestätigung wartet.
+ B empfängt den Request, erkennt an der Kennung das eigene Format und rechnet die
  Prüfsumme nach.
+ Stimmt sie, legt B das Datenstück unter seiner Nummer ab und schickt einen
  Echo-Reply mit der Bestätigung (ACK) zurück. Stimmt sie nicht, schickt B stattdessen
  ein NACK.
+ A bekommt die Antwort, hakt das Paket ab und geht zum nächsten über. Bleibt die
  Antwort aus oder kommt ein NACK, sendet A dasselbe Paket erneut.

Dieser kurze Hin-und-Her-Takt wiederholt sich für jedes der 61 Datenpakete, eingerahmt
vom INIT am Anfang und vom FIN am Ende.

= Codierung und Decodierung

Verschlüsselt wird laut Aufgabe nichts. Gefordert ist ein Codierungsverfahren, und die
Wahl fiel auf *Base64*. Der Grund ist praktischer Natur: Der Originaltext
enthält Umlaute, Paragrafenzeichen und Zeilenumbrüche, also Bytes, die man nicht ohne
Weiteres roh durch eine Paketnutzlast schieben möchte, ohne irgendwann über ein
Sonderzeichen zu stolpern. Base64 bildet beliebige Bytes auf einen handzahmen
Zeichenvorrat (A–Z, a–z, 0–9, `+`, `/`) ab und macht aus dem Text einen gleichförmigen
Strom, der sich sauber in gleich große Stücke schneiden lässt. Nebenbei ist der Inhalt
damit auch nicht mehr im Klartext lesbar: Wer den Mitschnitt öffnet, sieht erst einmal
nur eine Buchstabensuppe.

Ein kleines Beispiel macht das anschaulich: Aus dem Wort `§ 202c` (das wegen des
Paragrafenzeichens schon mehrere Bytes umfasst) wird nach der Codierung die harmlose
Zeichenfolge `wqcgMjAyYw==`. Genau solche Zeichenketten reihen sich in den
Datenpaketen aneinander, und kein Mensch erkennt ihnen auf den ersten Blick an, dass
dahinter Gesetzestext steckt.

Der Ablauf ist denkbar direkt. Programm A liest die Datei als Bytes ein, jagt sie durch
`base64.b64encode` und zerlegt das Ergebnis in Stücke von je 36 Zeichen. Jedes Stück
wandert in ein DATA-Paket. Programm B sammelt die Stücke, sortiert sie nach ihrer
laufenden Nummer, hängt sie wieder aneinander und ruft `base64.b64decode` auf. Heraus
kommen exakt die ursprünglichen Bytes, die dann als Text angezeigt und gespeichert
werden. Weil Base64 eine umkehrbare Eins-zu-eins-Abbildung ist, geht bei Codierung und
Decodierung grundsätzlich kein Zeichen verloren. Alle Verluste, die abgefangen werden
müssen, passieren auf dem Transportweg, nicht bei der Codierung.

Dass die Umlaute und das Paragrafenzeichen heil durchkommen, hängt übrigens auch daran,
dass die Datei konsequent als Bytes behandelt und erst ganz am Ende, bei der Anzeige,
wieder als UTF-8-Text interpretiert wird. So gibt es unterwegs keine Stelle, an der ein
Zeichensatz falsch geraten werden könnte.

= Integrität und Fehlerkorrektur

Dass alles ankommt, bleibt nicht dem Zufall überlassen. Geprüft wird auf zwei Ebenen,
und bei Fehlern wird aktiv nachkorrigiert.

*Pro Paket* trägt jeder Frame eine CRC32-Prüfsumme über seinen Datenteil im Kopf.
Programm B rechnet die Prüfsumme beim Empfang neu und vergleicht. Stimmt sie, gilt das
Paket als sauber; stimmt sie nicht, war das Paket unterwegs beschädigt und wird
verworfen. CRC32 ist kein kryptografischer Schutz, aber genau das richtige Werkzeug, um
Bitfehler bei der Übertragung zuverlässig zu erkennen. Schon ein einziges gekipptes Bit
im Datenteil führt zu einer völlig anderen Prüfsumme. B merkt den Fehler also sofort,
noch bevor das kaputte Stück überhaupt in den Gesamtpuffer wandert. Genau dieses
Verhalten wurde auch gezielt getestet: Dreht man in einem Frame ein Bit um, schlägt
die Prüfung erwartungsgemäß an und das Paket wird als fehlerhaft markiert.

*Für die Gesamtdatei* kommt zusätzlich SHA-256 ins Spiel. Den Fingerabdruck der
Originaldatei schickt A gleich zu Beginn im INIT-Paket mit. Wenn B am Ende alles
zusammengesetzt und decodiert hat, bildet es seinerseits den SHA-256 über das Ergebnis
und vergleicht. Nur wenn beide Werte identisch sind, ist garantiert, dass wirklich die
komplette Datei fehlerfrei angekommen ist und nicht etwa ein Stück vertauscht oder
verloren wurde.

Die eigentliche *Fehlerkorrektur* läuft über ein einfaches, aber wirksames Verfahren:
Stop-and-Wait mit Bestätigungen, in der Netzwerktechnik als ARQ bekannt. A schickt ein
Paket und wartet, bis B es bestätigt. Dabei gibt es zwei Fälle. Kam das Paket sauber an,
schickt B ein ACK mit dem Status „OK", und A geht zum nächsten Paket über. War die
Prüfsumme falsch, schickt B ein NACK zurück, und A sendet dasselbe Paket sofort noch
einmal. Bleibt die Bestätigung ganz aus (etwa weil ein Paket komplett verloren ging),
läuft bei A nach zwei Sekunden eine Zeitschranke ab, und auch dann wird erneut gesendet.
Bis zu fünf Versuche pro Paket sind vorgesehen; erst danach gilt die Übertragung als
gescheitert. Doppelt angekommene Pakete erkennt B an ihrer laufenden Nummer und
bestätigt sie einfach noch einmal, ohne sie ein zweites Mal zu verarbeiten.

Zusammengenommen greifen die drei Mechanismen ineinander: CRC32 erkennt kaputte Pakete,
das ARQ-Verfahren sorgt dafür, dass fehlende oder beschädigte Pakete automatisch
nachgeliefert werden, und SHA-256 ist am Ende der Beweis, dass das Ergebnis vollständig
und korrekt ist.

= Mitschnitt und Nachvollziehbarkeit

Beide Programme erzeugen während der Laufzeit selbst eine pcap-Datei. Dazu läuft in
jedem Programm ein Scapy-Sniffer mit, der jedes ICMP-Paket (in beide Richtungen und
ungefiltert) sofort in die Datei schreibt. So entstehen zwei Mitschnitte, die man
hinterher in Wireshark Paket für Paket nachvollziehen kann: die Echo-Requests mit den
Daten und die Echo-Replies mit den Bestätigungen.

Zusätzlich schreibt jedes Programm ein ausführliches Logbuch. Auf der Konsole sieht man
im Klartext, welches Paket gerade raus- oder reingeht, wie die Prüfsumme ausfällt und
wie weit die Übertragung fortgeschritten ist; in der Logdatei landet zusätzlich jede
Einzelheit inklusive Hexdump. Am Ende fasst eine kleine Statistik zusammen, wie viele
Pakete gesendet wurden, wie oft wiederholt werden musste und ob am Schluss alles passt.
Alle Ergebnisse (die beiden pcap-Dateien, die von B gespeicherte Textdatei und die
Logs) legen die Programme gesammelt in einem Ordner `output/` ab.

= Testaufbau

Für die Erprobung reicht ein einziger Rechner: Programm A und Programm B laufen in zwei
getrennten Prozessen und reden ausschließlich über die Loopback-Schnittstelle
miteinander. Die Daten gehen also trotzdem echt durch den Netzwerkstack und nicht am
Protokoll vorbei. Zuerst wird B gestartet, es wartet dann auf eingehende Pakete; danach
startet A und beginnt zu senden. Für zwei getrennte Maschinen oder virtuelle Gäste im
selben Subnetz ändert sich nur die Zieladresse und die Netzwerkschnittstelle, der Rest
bleibt gleich. Weil beide Programme mit Rohpaketen arbeiten, brauchen sie
Administratorrechte; unter macOS und Linux werden sie deshalb mit `sudo` gestartet.

Dass am Ende wirklich dasselbe herauskommt, lässt sich mit einem Handgriff bestätigen:
Ein Vergleich der Originaldatei mit der von B geschriebenen Datei darf keinen Unterschied
zeigen. Zusammen mit dem SHA-256-Abgleich im Programm selbst ist das der Nachweis, dass
die Übertragung zeichengenau war.

= Ein Durchlauf in der Praxis

Im Logbuch liest sich eine Übertragung ungefähr so: A meldet zu Beginn die Eckdaten
(Dateigröße, den SHA-256 des Originals und die Zahl der zu sendenden Pakete) und
schickt dann der Reihe nach INIT, die 61 Datenpakete und zum Schluss FIN. Für jedes
Paket erscheint eine Zeile mit Richtung, Pakettyp, laufender Nummer und dem Ergebnis der
Prüfsumme, etwa so:

#block(inset: (left: 0.5em), text(size: 9pt, font: "Menlo")[
```
-> DATA seq=12  len=36  crc-ok  (56 Byte Rahmen)
<- ACK  seq=12  (OK)
```
])

Auf der Gegenseite spiegelt sich das: B protokolliert jedes empfangene Paket, bestätigt
es und meldet den Fortschritt in Prozent. Sobald FIN eintrifft, setzt B die Stücke
zusammen, prüft den SHA-256, speichert die Datei und gibt den vollständigen Gesetzestext
auf dem Bildschirm aus. Zum Abschluss zieht jedes Programm eine kurze Bilanz: wie viele
Pakete gesendet bzw. empfangen wurden, wie oft wiederholt werden musste und ob die
Prüfung am Ende erfolgreich war. Muss einmal kein Paket wiederholt werden, steht dort
schlicht eine Null bei den Wiederholungen; läuft dagegen ein Paket verloren, sieht man
im Log genau, welche Nummer erneut geschickt wurde und dass sie beim zweiten Anlauf
ankam.

= Fazit

In einem kleinen, ruhigen Testnetz funktioniert der Weg über ICMP sehr zuverlässig. Die
Datei kommt vollständig und zeichengenau an, und durch das ARQ-Verfahren übersteht die
Übertragung auch einzelne verlorene oder beschädigte Pakete, ohne dass ein Mensch
eingreifen muss. Für den Rahmen dieser Prüfungsleistung ist die Methode damit gut
geeignet.

In der Praxis hätte der Ansatz allerdings auch Grenzen. Das Stop-and-Wait-Verfahren ist
bewusst einfach gehalten und nicht auf Geschwindigkeit optimiert. Für ein paar
Kilobyte ist das egal, für große Datenmengen würde es zäh. Und so unauffällig
Ping-Verkehr auf den ersten Blick ist, so auffällig wird er, wenn man genauer hinsieht:
Ein Dauerfeuer aus Echo-Requests mit immer gleicher Größe und einer Nutzlast voller
zufällig aussehender Zeichen ist für ein aufmerksames Überwachungssystem ein deutliches
Warnsignal.

Genau da setzt auch die Abwehr an. Erkennen lässt sich so ein Abfluss, indem man den
ICMP-Verkehr überwacht statt ihn blind durchzulassen: auf ungewöhnlich viele oder
regelmäßige Pings achten, die Nutzlast inspizieren und auf hohe Zufälligkeit (Entropie)
prüfen, und solche Muster mit einem IDS wie Snort oder Suricata melden lassen.
Verhindern kann man ihn, indem man ICMP an den Netzgrenzen einschränkt oder in der Rate
begrenzt und per Egress-Filter kontrolliert, was das Netz überhaupt nach außen verlassen
darf.

Was dafür nötig ist, lässt sich in drei Dinge fassen. Erstens *Sichtbarkeit*: Man
braucht einen Sensor an der richtigen Stelle (typischerweise am Gateway oder über einen
Mirror-Port am Switch), der den ICMP-Verkehr überhaupt mitbekommt, dazu Werkzeuge, die
nicht nur Pakettypen zählen, sondern auch in die Nutzlast schauen und per NetFlow oder
einem Monitoring die Mengen und Zeitabstände über längere Zeit auswerten. Zweitens
*Regeln und Technik*: eine Firewall mit Egress-Filterung, IDS/IPS-Signaturen, die auf
auffällige Payload-Größen und hohe Entropie ansprechen, und eine Rate-Begrenzung für
ICMP. Und drittens (fast der wichtigste Punkt) *Menschen und Prozesse*: Die beste
Meldung nützt nichts, wenn niemand die Alarme auswertet; es braucht also jemanden, der
die Baseline des normalen Ping-Verkehrs kennt, Abweichungen bewertet und im Ernstfall
reagiert. Allein mit Technik ist es also nicht getan; Erkennung und Abwehr stehen und
fallen damit, dass der Verkehr beobachtet *und* jemand zuständig ist.
