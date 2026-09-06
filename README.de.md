[English](README.md) · **Deutsch**

# StegoComm

**Ein Proof of Concept für einen verdeckten, verschlüsselten Nachrichtenkanal, der Chiffretext in unauffälligem Geplauder versteckt.**

Zwei zusammenspielende Implementierungen mit exakt demselben Wire-Format:

| Komponente | Was es ist | Abhängigkeiten |
|---|---|---|
| `cover_studio.html` | Browser-Tool (GUI): kodieren **und** dekodieren, komplett lokal | **keine** — Datei einfach öffnen |
| `stegocomms.py` | Python-CLI, byte-kompatibel zum Browser-Tool | `cryptography` |

Eine im Browser kodierte Nachricht lässt sich mit der Python-CLI dekodieren und umgekehrt.

> ⚠️ **Das ist ein Proof of Concept, keine auditierte Sicherheitssoftware.** Es zeigt die Architektur (echte AEAD-Verschlüsselung in einem steganographischen Text-Cover mit Vorwärtsfehlerkorrektur). Verlass dich damit nicht auf den Schutz gefährdeter Menschen ohne unabhängiges Sicherheitsreview.

---

## So funktioniert es

Fünf Schritte hin, dieselben fünf zurück. Nur der letzte ist ungewöhnlich — die
ersten vier sind gewöhnliche, gut verstandene Kryptographie.

```
        WAS DU EINGIBST
        "Treffen Sonntag 18 Uhr am alten Hafen"
                     │
                     │   1.  KLEINER MACHEN
                     │       deflate — weniger Bytes zu verstecken
                     ▼
        ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
                     │
                     │   2.  ABSCHLIESSEN
                     │       AES-256-GCM, Schlüssel aus deiner Passphrase
                     │       (PBKDF2, 200 000 Runden)
                     ▼
        ████████████████████████    ← unlesbares Rauschen.
                     │                 DAS ist, was dich schützt
                     │
                     │   3.  ZERTEILEN
                     │       in 8-Byte-Blöcke
                     ▼
        ██ ██ ██ ██ ██ ██
                     │
                     │   4.  ABSICHERN
                     │       Parity-Blöcke dazu (Reed-Solomon)
                     ▼
        ██ ██ ██ ██ ██ ██ ▓▓ ▓▓     ▓ = Parity: 2 verlorene Blöcke lassen
                     │                  sich ohne Nachfrage rekonstruieren
                     │
                     │   5.  TARNEN
                     │       jeder Block wird zu Sätzen —
                     ▼       die WORTWAHL trägt die Bits
        ┌──────────────────────────────────┐
        │  der markt ist ruhig heute       │   ← das verschickst du
        │  das dach ist fein drinnen       │
        │  die antenne ist stetig hier     │
        │  ...                             │
        └──────────────────────────────────┘

        Der Empfänger geht dieselben fünf Schritte rückwärts.
```

**Warum die Wortwahl die Daten sind.** Jeder Satz folgt einer Schablone, und jede
Lücke darin hat eine feste Liste möglicher Wörter. Bei 32 Nomen zur Auswahl ist
es 5 Bit wert, *welches* Nomen dasteht. Nomen, Adjektiv und Endung zusammen — und
ein kurzer Satz hat 10 bis 28 Bit transportiert. Der Empfänger schlägt jedes Wort
in denselben Listen nach und hat die Bits zurück.

**Wofür jede Schicht da ist**

| Schicht | Löst |
|---|---|
| deflate | weniger Bytes zu verstecken |
| AES-256-GCM | niemand kann es lesen, Manipulation fällt auf |
| Reed-Solomon | verlorene Blöcke ohne Nachforderung rekonstruiert |
| die Grammatik | es sieht nicht nach Nachricht aus |
| Zufalls-Padding | Füllbits wiederholen kein verräterisches Muster |

**Das Wichtigste:** Die Sicherheit kommt aus Schritt 2, nicht aus Schritt 5.
Selbst wer genau weiß, wie dieses Werkzeug arbeitet, und die Sätze sauber
zurückrechnet, landet beim Rauschen aus Schritt 2 — und ohne deine Passphrase ist
dort Schluss. Die Tarnung sorgt dafür, dass überhaupt niemand hinsieht.

---

## Was es im Detail macht

Du hast eine geheime Nachricht. StegoComm:

1. **komprimiert** sie (deflate),
2. **verschlüsselt** sie mit AES-256-GCM (Schlüssel aus einer gemeinsamen Passphrase via PBKDF2-HMAC-SHA256, 200 000 Iterationen),
3. zerlegt den Chiffretext in 8-Byte-**Blöcke** und ergänzt **Reed-Solomon-Parity-Blöcke** (GF(256), Cauchy-Matrix), damit verlorene oder beschädigte Blöcke ohne Nachforderung rekonstruiert werden,
4. **kodiert jeden Block als unauffällige Sätze** — Wetter und Smalltalk auf Deutsch oder Englisch — wobei die *Wortwahl* die Bits trägt,
5. füllt Restbits mit schlüsselabgeleitetem **Zufalls-Padding**, damit Füllsätze keine verräterischen Muster wiederholen.

Im Cover steht **nirgends ein Klartext-Header**. Blockindex und Block-CRC stecken
in den Satz-Bits; die pro Nachricht konstanten Felder (Blockzahl, Parity-Zahl,
Padlänge, Block-Nonce) liegen in einem **Manifest**, das selbst aus ganz normalen
Cover-Sätzen besteht und mit einem schlüsselabgeleiteten Keystream verschleiert
ist. Ohne Passphrase ist es von einem Nutzblock nicht zu unterscheiden. Das
Manifest wird zweimal gesendet — am Anfang und am Ende, mit verschiedenen Nonces
und daher völlig verschiedenem Wortlaut — damit der Verlust einer Stelle nicht
die ganze Nachricht kostet.

Das Cover besteht deshalb **ausschließlich aus Trägersätzen** — keinerlei
Rahmenzeile, und **nur Buchstaben und einfache Leerzeichen**: keine Satzzeichen,
keine Ziffern, auf keiner Stufe. Das ist Absicht, denn Satzzeichen sind genau
das, was eine Funk- oder Chat-Strecke stillschweigend verschluckt oder ersetzt.

Die beiden Profile unterscheiden sich nur in der Schreibweise: `plain` (Standard)
liefert Kleinbuchstaben, damit es wie eine normale Chat-Nachricht aussieht,
`js8call` liefert Großbuchstaben — den Zeichensatz, den JS8Call am effizientesten
überträgt. Die Schreibweise trägt keine Daten; der Decoder wandelt vor dem Parsen
ohnehin alles in Kleinbuchstaben.

Der Empfänger dreht alles zurück; eine Block-CRC erkennt beschädigte Blöcke und
behandelt sie als Erasure, was die Parity bis zu ihrer Grenze repariert — darüber
kommt ein **NACK**, der genau angibt, welche Blöcke nachzusenden sind
(Selective-Repeat-ARQ).

### Den Transportweg überleben

Das Cover muss unbeschadet ankommen, und echte Transportwege sind nicht
sorgfältig. Der Decoder liest deshalb gar keine Zeilen mehr — er liest **einen
durchgehenden Wortstrom**. Jede Satz-Schablone hat eine feste Wortzahl, die Sätze
lassen sich also allein aus der Wortfolge zurückgewinnen, und **Zeilenumbrüche
tragen keine Information**. Ein Weg, der den Text umbricht, zusammenzieht, neu
umbricht oder mit Leerzeilen durchsetzt, ändert nichts.

Davor bügelt er den Rest der üblichen Schäden aus: Groß-/Kleinschreibung, ein
vorangestelltes Rufzeichen oder Zitatzeichen (`KN4CRD: `, `> `), Satzzeichen an
beliebiger Stelle und Folgen von Leerzeichen. Cover-Sätze enthalten nie `:` oder
`>`, das Abschneiden eines solchen Präfixes kann also nie einen echten Satz
beschädigen.

Findet er trotzdem Zeichen, die die Grammatik nie erzeugt, sagt er das — statt
deiner Passphrase die Schuld zu geben. Diese Meldung ist das Nützlichste, was er
dir sagen kann, wenn ein Transportweg deinen Text verändert.

Tödlich bleibt ein Weg, der **Wörter verändert oder verschluckt**. Jeder
beschädigte Satz kostet einen Block; die Parity fängt ein paar davon ab, darüber
kommt ein NACK.

### Der Glaubhaftigkeits-Regler

**„Stufe" ist einfach die Stellung des Glaubhaftigkeits-Reglers** — eine von
vier, auf der Kommandozeile `--level 0` bis `--level 3`. Sie entscheidet, wie
viel jeder Satz zu tragen hat: eine niedrige Stufe nutzt nur die alltäglichsten
Wörter und braucht dafür viele Sätze; eine hohe Stufe greift auf viel breitere
Wortlisten zu, ein Satz trägt also mehr, und es werden weniger Sätze gebraucht.
Sonst ändert sich nichts — dieselbe Verschlüsselung, dieselbe Nachricht. Du
tauschst nur, wie natürlich der Text klingt, gegen seine Länge.

Der Empfänger muss nicht wissen, welche Stufe du benutzt hast.

Gemessen an `Treffen Sonntag 18 Uhr am alten Hafen` (deutsch, 2 Parity-Blöcke):

| Stufe | Wirkung | Bit/Satz | Sätze | Zeichen | Beispielsatz |
|---|---|---|---|---|---|
| 0 | sehr glaubhaft | 10 | 104 | 2657 | `das band ist stetig hier` |
| 1 | glaubhaft (Standard) | 13 | 89 | 2267 | `die antenne ist mild vorn` |
| 2 | knapp | 20 | 52 | 2104 | `das radio ist stetig und der zaun fertig` |
| 3 | sehr knapp | 28 | 39 | 1439 | `kaffee hart turm langsam gleich warm` |

Höhere Stufen hängen **keine** Nebensätze mehr an — das war der v3-Entwurf, und
er ging nach hinten los: ein angehängter Nebensatz brachte ~5 Bit, kostete aber
~20 Zeichen. Dadurch *sank* die Dichte pro Zeichen mit steigender Stufe, und
„sehr knapp" erzeugte einen **längeren** Cover als „sehr glaubhaft". In v4 bleibt
der Satz kurz und die **Wortlisten werden breiter** (8/16/32 Optionen je Slot =
3/4/5 Bit); Stufe 3 fällt zusätzlich in den Telegrammstil ohne Artikel und Verb.
Die Glaubhaftigkeit sinkt jetzt durch ungewöhnliche Wortwahl, nicht durch Länge
— und die Zeichenzahl fällt endlich mit der Stufe.

Wichtig zur Einordnung: Auf JS8Call hängt die Sendezeit an **Zeichen**, die Stufe
halbiert sie also tatsächlich. In einem Chat-Transport spart sie vor allem
Nachrichten zum Einfügen.

Weder Sprache noch Stufe stehen irgendwo im Cover — der Decoder probiert schlicht
alle 8 Kombinationen durch, die CRC16 des Manifests entscheidet.

---

## Installation

**Browser-Tool — nichts zu installieren.** Einfach `cover_studio.html` öffnen:

```bash
xdg-open cover_studio.html        # Linux
# oder doppelklicken, oder file:///pfad/zu/cover_studio.html als Lesezeichen
```

**Python-CLI** braucht Python 3.8+ und das Paket `cryptography`. Am robustesten (distro-unabhängig) über eine virtuelle Umgebung:

```bash
cd StegoComm
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Auf Fedora alternativ das Systempaket: `sudo dnf install python3-cryptography`.
(Ein einfaches `pip install --user cryptography` geht auch — außer die Distribution meldet `externally-managed-environment`, dann die venv oben nutzen.)

## Benutzung

**Browser:** Nachricht eintippen, Passphrase eingeben (beide Seiten dieselbe),
Sprache / Kanal / Glaubhaftigkeit wählen, dann **Copy all**. Die Gegenseite fügt
den Text im Panel *Receive & decrypt* ein und klickt **Decrypt**.
**Test with my own cover** ist ein Loopback-Test: der Knopf fügt den gerade
erzeugten Cover ins Empfangsfeld ein und entschlüsselt ihn, damit du ohne zweiten
Rechner prüfen kannst, dass Kodieren und Dekodieren zusammenpassen.

**CLI:**

```bash
# Selbsttest (Round-Trip + Parity + NACK + Transportschäden)
python3 stegocomms.py selftest

# Nachricht in Cover-Text kodieren (Kleinschreibung ist Standard)
python3 stegocomms.py encode --pass "gemeinsame-passphrase" --lang de --level 1 \
        "Treffen Sonntag 18 Uhr am alten Hafen"

# ... in Großschreibung für JS8Call
python3 stegocomms.py encode --pass "gemeinsame-passphrase" --profile js8call \
        --lang de --level 1 "Treffen Sonntag 18 Uhr am alten Hafen"

# Cover-Text von stdin dekodieren
python3 stegocomms.py decode --pass "gemeinsame-passphrase"    # einfügen, dann Strg-D
```

**Gegenprobe Browser ⇄ Python** (Interop-Beweis): in einem kodieren, im anderen
dekodieren, gleiche Passphrase. Kommt der Klartext zurück, stimmen die beiden
unabhängigen Implementierungen überein.

### Zur Passphrase

Alles ist erlaubt: ein Zeichen oder fünfhundert, Umlaute, Emoji,
Anführungszeichen, Backslashes, Tabs. PBKDF2 macht aus beliebigem UTF-8-Text
einen 32-Byte-Schlüssel. Drei Dinge solltest du wissen:

- **Nichts wird getrimmt.** `"geheim"` und `"geheim "` sind verschiedene
  Schlüssel. Ein beim Kopieren aufgeschnapptes Leerzeichen bricht die
  Entschlüsselung.
- **Das Feld ist nicht maskiert** (`type="text"`), die Passphrase steht sichtbar
  auf dem Schirm.
- **Länge ist egal, Ratbarkeit nicht.** `"hund"` funktioniert technisch
  einwandfrei und ist trotzdem wertlos — daran hängt die gesamte Sicherheit.

---

## Senden über JS8Call

**Nur die Cover-Sätze einfügen, sonst nichts.** JS8Call sendet dein Rufzeichen
selbst — du tippst dort Nachrichtentext, keinen Header. Also kein `DE <call>`
davorsetzen, und niemals ein fremdes Rufzeichen senden: das ist überall dort
illegal, wo Amateurfunk lizenziert ist. Frühere Fassungen dieses Werkzeugs haben
dekorative Rufzeichen-Zeilen ausgegeben (`DE W1ABC MSG 3/14`); genau deswegen
sind sie entfernt worden. Ein altes Cover mit solchen Zeilen lässt sich weiterhin
dekodieren — der Decoder überspringt, was er nicht parsen kann.

1. Mit `--profile js8call` kodieren (Großschreibung) oder im Browser-Tool den
   Kanal **JS8Call** wählen.
2. Den kompletten Cover kopieren.
3. In das Sendefeld von JS8Call einfügen und senden. Lange Cover passen nicht in
   einen Frame; JS8Call zerlegt sie, oder du sendest sie stückweise.
4. Der Empfänger kopiert den empfangenen Text aus JS8Call heraus und fügt ihn bei
   `decode` ein. Rufzeichen-Präfixe und Zeilenumbrüche werden automatisch
   behandelt.

---

## Wire-Format v4

Das aktuelle Wire-Format ist **v4**. Seine Grammatik enthält überhaupt keine
Satzzeichen, und der Decoder liest einen Wortstrom statt Zeilen und normalisiert
vor dem Parsen Groß-/Kleinschreibung, Rufzeichen-/Zitat-Präfixe, Satzzeichen und
Leerraum weg. Unterschiede zu v3: der Klartext-Header pro Block ist weg (die
Rahmung steckt jetzt im verdeckten Kanal plus einem verschleierten Manifest), die
Glaubhaftigkeitsstufen erkaufen Dichte über die *Wortwahl* statt über die
Satzlänge, und deutsche Nomen tragen ihren richtigen Artikel (`der Kaffee` statt
des pauschalen `das kaffee` aus v3). Das PBKDF2-Salt heißt jetzt
`stegocomm/v4/pbkdf2`, **v3-Cover lassen sich mit v4 also nicht entschlüsseln** —
das Format ist ohnehin inkompatibel.

### Schichtenaufbau

```
Klartext → deflate → AES-256-GCM(iv‖Chiffretext‖Tag)
         → 8-Byte-Datenblöcke (+ R Cauchy/Reed-Solomon-Parity-Blöcke)
         → je Block: idx‖Nutzlast‖CRC8 (80 Bit), mit Keystream verschleiert
         → Cover-Sätze (variable Dichte) + je ein Manifest an Anfang und Ende
         → Restbits mit schlüsselabgeleitetem Zufalls-Padding gefüllt
```

Weil es keine Header-Zeilen mehr gibt, an denen man sich neu ausrichten könnte,
schiebt der Decoder ein Fenster über den Wortstrom: er liest *n* Sätze, prüft die
Block-CRC und rückt bei Misserfolg nur um **ein Wort** weiter. Ein verlorener
oder verstümmelter Satz kostet damit einen Block, nicht den Rest der Nachricht.

### Bekannte Grenzen

- Nachrichten sind auf 254 Blöcke begrenzt, also rund 2 kB Chiffretext.
- Alle Sätze einer Stufe folgen einer Schablone, ein langer Cover wirkt daher
  strukturell repetitiv — das galt für v3 genauso und ist eine Grenze der
  Glaubhaftigkeit, kein Fehler.
- Die Blockerkennung hängt an einer 8-Bit-CRC; eine zufällige Satzfolge wird mit
  ~1/256 fälschlich als Block gelesen. Ein Fehltreffer verdirbt die Nutzlast, das
  GCM-Tag weist die Nachricht dann ab statt falschen Klartext zu liefern.

---

## Sicherheitshinweise

- **Punkt-zu-Punkt, für sich genommen nicht Ende-zu-Ende:** Die Passphrase schützt den Nachrichteninhalt zwischen den zwei Menschen, die sie teilen. Wähle eine starke, außerhalb dieses Kanals ausgetauschte Passphrase.
- **Alles hängt an dieser Passphrase.** Kein Schlüsselaustausch, keine Forward Secrecy: wer sie später bekommt, liest jede je abgefangene Nachricht.
- **Keine Absender-Authentifizierung.** Wer den Schlüssel hat, kann auch senden. Zwei Leute mit demselben Schlüssel sind füreinander nicht unterscheidbar.
- **Kein Replay-Schutz.** Ein abgefangener Cover lässt sich später erneut einspielen.
- **Der Cover verbirgt *Inhalt und die Tatsache, dass es Inhalt gibt*, aber nicht zwingend, *dass zwei Parteien kommunizieren*.** Metadaten (wer mit wem, wann, wie viel) sind ein eigenes Problem.
- **Die Tarnung hält keiner statistischen Prüfung stand.** Alle Sätze einer Stufe folgen einer Schablone, ein langer Cover ist auffällig repetitiv. Gegen flüchtiges Lesen wirkt das, gegen jemanden der gezielt sucht nicht.
- **Nicht auditiert.** Proof of Concept. Keine Gewähr.
