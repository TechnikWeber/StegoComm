[English](README.md) · **Deutsch**

# StegoComm

[![tests](https://github.com/TechnikWeber/StegoComm/actions/workflows/ci.yml/badge.svg)](https://github.com/TechnikWeber/StegoComm/actions/workflows/ci.yml)

**Ein Proof of Concept für einen verdeckten, verschlüsselten Nachrichtenkanal, der Chiffretext in unauffälligem Geplauder versteckt.**

Zwei zusammenspielende Implementierungen mit exakt demselben Wire-Format:

| Komponente | Was es ist | Abhängigkeiten |
|---|---|---|
| `cover_studio.html` | Browser-Tool (GUI): kodieren **und** dekodieren, komplett lokal | **keine** — Datei einfach öffnen |
| `stegocomms.py` | Python-CLI, byte-kompatibel zum Browser-Tool | `cryptography` |

Eine im Browser kodierte Nachricht lässt sich mit der Python-CLI dekodieren und umgekehrt.

![Das Browser-Tool: links die Nachricht, rechts der erzeugte Cover](docs/cover-studio.jpg)

*Links, was du eintippst und woraus der Cover gebaut wird. Rechts der Text zum
Senden, mit laufender Anzeige, wie stark er die Nachricht aufbläht.*

![Dieselbe Nachricht im kompakten Ziffernformat](docs/cover-studio-compact.jpg)

*Dieselbe Nachricht mit abgeschalteter Tarnung — 354 statt 1753 Zeichen, und ein
deutlicher Hinweis, dass hier nichts mehr versteckt wird.*

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
                     │       deflate, aber nur wenn es wirklich kleiner wird
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

| Schicht | Löst |
|---|---|
| deflate (wenn es hilft) | weniger Bytes zu verstecken |
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

Im Cover steht **nirgends ein Klartext-Header**. Blockindex und Block-CRC stecken
in den Satz-Bits; die pro Nachricht konstanten Felder liegen in einem
**Manifest**, das selbst aus normalen Cover-Sätzen besteht, mit einem
schlüsselabgeleiteten Keystream verschleiert und damit von einem Nutzblock nicht
zu unterscheiden ist. Es wird zweimal gesendet, am Anfang und am Ende, damit der
Verlust einer Stelle nicht die ganze Nachricht kostet.

Das Cover besteht **ausschließlich aus Trägersätzen**, aus **nur Buchstaben und
einfachen Leerzeichen** — keine Satzzeichen, keine Ziffern, auf keiner Stufe,
denn Satzzeichen sind genau das, was eine Funk- oder Chat-Strecke stillschweigend
verschluckt. `plain` (Standard) liefert Kleinbuchstaben, `js8call` Großbuchstaben
für JS8Calls effizientesten Zeichensatz; die Schreibweise trägt keine Daten.

Der Empfänger dreht alles zurück; eine Block-CRC erkennt beschädigte Blöcke und
behandelt sie als Erasure, was die Parity bis zu ihrer Grenze repariert — darüber
kommt ein **NACK**, der genau angibt, welche Blöcke nachzusenden sind
(Selective-Repeat-ARQ).

### Kompaktformate — wenn du keine Tarnung brauchst

Ist der Kanal ohnehin privat und zählt nur die Größe, sind die Sätze reine
Verschwendung: **`--format digits` und `--format base32` geben dasselbe
Wire-Format in einem kürzeren Alphabet aus.**

| Format | Gleiche Nachricht | Alphabet | Bit pro Zeichen |
|---|---|---|---|
| `sentences` (Standard) | 889 Zeichen | Wörter | 0,5 – 0,9 |
| `digits` | 263 Zeichen | `0`–`9` | 3,3 |
| `base32` | 175 Zeichen | Crockford, Großbuchstaben | 5 |

Vier- bis sechsmal kürzer, und verloren geht genau eine Sache: **die Tarnung.**
Alles andere bleibt unangetastet — dieselbe Verschlüsselung, dieselbe Parity,
dieselbe CRC, dasselbe Manifest, derselbe NACK. `digits` übersteht jeden
Transportweg und lässt sich über Funk vorlesen; `base32` nutzt Crockfords
Alphabet (ohne I, L, O, U) und ist das kürzeste. Der Decoder erkennt alle drei
Formate selbst — eine Seite kann Sätze senden und die andere Ziffern, ohne dass
mehr abgesprochen wäre als die Passphrase.

```
04037 82089 24965 64789 15437     ← digits
9S5EW 5K71F HD248                 ← base32
```

### Themen-Vokabulare

Die Sätze werden aus sechs Alltagsvokabularen gebaut — **Wetter & Himmel,
Haushalt & Küche, Garten & draußen, Arbeit & Erledigungen, Unterwegs & Straße,
Funk & Technik**, je 64 Nomen — und pro Satz wird ein Thema gezogen, damit ein
Cover zwischen Themen wandert wie echtes Geplauder. Alles außer *Funk & Technik*
ist standardmäßig an; **AFU mode** schaltet auf *Funk & Technik* allein um.

**Die Auswahl betrifft nur das Senden, beide Seiten müssen sie nicht abgleichen.**
Jedes Nomen kommt in genau einem Thema vor, das Nomen sagt dem Decoder also, aus
welchem Thema ein Satz stammt — die Testsuite beweist es, indem jede
Implementierung mit einer anderen Themenwahl kodiert. Auf der Kommandozeile:
`--topics weather,garden` oder `--afu`.

### Den Transportweg überleben

Der Decoder liest gar keine Zeilen — er liest **einen durchgehenden Wortstrom**.
Jede Satz-Schablone hat eine feste Wortzahl, **Zeilenumbrüche tragen also keine
Information**: ein Weg, der den Text umbricht, zusammenzieht oder neu umbricht,
ändert nichts. Davor bügelt er Groß-/Kleinschreibung, ein vorangestelltes
Rufzeichen oder Zitatzeichen (`KN4CRD: `, `> `), Satzzeichen und Folgen von
Leerzeichen weg — und findet er trotzdem Zeichen, die die Grammatik nie erzeugt,
sagt er das, statt deiner Passphrase die Schuld zu geben. Tödlich bleibt ein Weg,
der **Wörter verändert oder verschluckt**: jeder beschädigte Satz kostet einen
Block, die Parity fängt ein paar davon ab, darüber kommt ein NACK.

### Der Glaubhaftigkeits-Regler

**„Stufe" ist die Stellung des Glaubhaftigkeits-Reglers** — eine von vier, auf
der Kommandozeile `--level 0` bis `--level 3`. Eine niedrige Stufe nutzt nur die
alltäglichsten Wörter und braucht dafür viele Sätze; eine hohe greift auf viel
breitere Listen zu, ein Satz trägt also mehr. Sonst ändert sich nichts: du
tauschst nur, wie natürlich der Text klingt, gegen seine Länge. Der Empfänger
muss nicht wissen, welche Stufe du benutzt hast.

Gemessen an `Treffen Sonntag 18 Uhr am alten Hafen` (deutsch, 2 Parity-Blöcke):

| Stufe | Wirkung | Bit/Satz | Wörter aus | Sätze | Zeichen | Beispielsatz |
|---|---|---|---|---|---|---|
| 0 | sehr glaubhaft | 14 | 16 Nomen, 8+8 andere | 78 | 2186 | `jetzt war die karte laut` |
| 1 | glaubhaft (Standard) | 17 | 32 Nomen, 16+16 | 65 | 1920 | `oben blieb der drucker mau` |
| 2 | knapp | 23 | 64 Nomen, 32+16+16 | 52 | 1630 | `abends war regen hart hell` |
| 3 | sehr knapp | 26 | 64 Nomen, 64+32+32 | 50 | 1422 | `heil diesig prognose wiederholt` |

Die Natürlichkeit fällt hörbar Stufe für Stufe: 0 und 1 sind vollständige Sätze
mit Artikel und Verb, Stufe 2 lässt den Artikel weg, Stufe 3 zusätzlich das Verb.
Diese Leiter ist **gemessen, nicht geraten** — über die Cover-Länge entscheidet
`ceil(80 / Bits) × mittlere Satzlänge`, deshalb werfen die knappen Stufen
Funktionswörter raus und machen die **Wortlisten breiter** (8/16/32 Optionen je
Slot), statt Nebensätze anzuhängen. Die Glaubhaftigkeit sinkt also durch
ungewöhnliche Wortwahl, und die Zeichenzahl fällt mit — auf JS8Call, wo die
Sendezeit an Zeichen hängt, halbiert die Stufe sie tatsächlich.

Jede Stufe bietet **sechzehn Satzformen** mit identischer Wortzahl und Bitbreite;
welche benutzt wird, ist selbst Teil der Nutzlast, die Vielfalt ist also gratis.
Weder Sprache noch Stufe stehen irgendwo im Cover — der Decoder probiert alle 8
Kombinationen durch, die CRC16 des Manifests entscheidet.

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

**Browser:** Nachricht eintippen, Schlüssel eingeben (beide Seiten denselben),
Sprache / Kanal / Glaubhaftigkeit wählen, dann **Copy all**. Die Gegenseite fügt
den Text im Panel *Receive & decrypt* ein und klickt **Decrypt**. **Test with my
own cover** ist ein Loopback-Test: der Knopf dekodiert den gerade erzeugten
Cover, damit du ohne zweiten Rechner prüfen kannst, dass beide Richtungen
zusammenpassen.

Über dem Schlüsselfeld sitzen vier Knöpfe:

- **🎲 Random** ersetzt den Schlüssel durch 25 Zeichen aus
  `crypto.getRandomValues` — 125 Bit, aus einem Alphabet ohne die Verwechsler
  `l/1` und `o/0`, damit er es übersteht, über Funk durchgegeben zu werden.
- **👁 Show** zeigt den Schlüssel an; **standardmäßig ist er maskiert**, damit ihn
  ein Screenshot oder ein Blick über die Schulter nicht mitnimmt.
- **⧉ Copy** legt ihn in die Zwischenablage, maskiert oder nicht.
- **🔒 Das Schloss** schaltet das Feld auf schreibgeschützt und graut den Würfel
  aus, damit ein versehentlicher Tastendruck nicht unbemerkt den Schlüssel
  ändert, auf den sich beide Seiten geeinigt haben.

Gespeichert wird nichts — Tab zu, Schlüssel weg. Also aufschreiben, bevor du
etwas sendest.

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

# ... nur aus gewählten Vokabularen, oder allein aus Funk & Technik
python3 stegocomms.py encode --pass "..." --topics weather,garden "..."
python3 stegocomms.py encode --pass "..." --afu --profile js8call "..."

# ... oder ganz ohne Tarnung, 4- bis 6-mal kürzer
python3 stegocomms.py encode --pass "..." --format digits "..."
python3 stegocomms.py encode --pass "..." --format base32 "..."

# Cover-Text von stdin dekodieren
python3 stegocomms.py decode --pass "gemeinsame-passphrase"    # einfügen, dann Strg-D
```

**Gegenprobe Browser ⇄ Python** (Interop-Beweis): in einem kodieren, im anderen
dekodieren, gleiche Passphrase. Kommt der Klartext zurück, stimmen die beiden
unabhängigen Implementierungen überein.

### Zur Passphrase

Jeder UTF-8-Text funktioniert — PBKDF2 macht aus allem einen 32-Byte-Schlüssel.
Weil aber die gesamte Sicherheit an dieser einen Zeichenkette hängt, **verweigern
beide Seiten das Kodieren unter 12 Zeichen** und sagen dir, wenn das Eingegebene
schwächer ist als es aussieht. (`--allow-weak-pass` hebelt die CLI-Prüfung aus;
Dekodieren ist nie eingeschränkt, sonst kämst du an deine alten Nachrichten nicht
mehr heran.)

**Wie eine gute Passphrase aussieht:** vier oder fünf zusammenhanglose Wörter,
z. B. `hafen-laterne-still-sieben`, oder der 🎲-Zufallsschlüssel aus dem
Browser-Tool. Länge darüber hinaus zählt weniger als Unvorhersagbarkeit —
`aaaaaaaaaaaaaaaaaaaa` hat zwanzig Zeichen und ist wertlos. Die Prüfung meldet
nur, was tatsächlich prüfbar ist (Länge, Vielfalt, ob es ein einzelnes Wort ist);
kein Messwerkzeug kann wissen, ob *du* zufällig gewählt hast, und sie sagt das
auch.

**Nichts wird getrimmt:** `"geheim"` und `"geheim "` sind verschiedene Schlüssel,
ein beim Kopieren aufgeschnapptes Leerzeichen bricht also die Entschlüsselung.

---

## Senden über JS8Call

> ⚠️ **Im Amateurfunk sind Verschlüsselung und verschleierte Aussendungen nicht
> zulässig.** Der Inhalt einer Aussendung muss offen und für jeden Mithörer
> nachvollziehbar sein — ihn zu verschlüsseln oder in harmlosem Geplauder zu
> verstecken ist genau das, was die Bestimmungen untersagen. Geregelt wird das
> von jeder Verwaltung selbst (in Deutschland die Amateurfunkverordnung, in den
> USA FCC Part 97, anderswo entsprechend), deshalb **vor dem Senden die für dich
> geltenden Vorschriften prüfen.** Auf den Amateurfunkbändern ist dieses Werkzeug
> eine Demonstration; über Chat, E-Mail oder andere Wege außerhalb des
> Amateurfunks gilt die Einschränkung nicht.

**Nur die Cover-Sätze einfügen, sonst nichts.** JS8Call sendet dein Rufzeichen
selbst — du tippst dort Nachrichtentext, keinen Header. Also kein `DE <call>`
davorsetzen, und niemals ein fremdes Rufzeichen senden: das ist überall dort
illegal, wo Amateurfunk lizenziert ist.

1. Mit `--profile js8call` kodieren (Großschreibung) oder im Browser-Tool den
   Kanal **JS8Call** wählen.
2. Den kompletten Cover kopieren.
3. In das Sendefeld von JS8Call einfügen und senden. Lange Cover passen nicht in
   einen Frame; JS8Call zerlegt sie, oder du sendest sie stückweise.
4. Der Empfänger kopiert den empfangenen Text aus JS8Call heraus und fügt ihn bei
   `decode` ein. Rufzeichen-Präfixe und Zeilenumbrüche werden automatisch
   behandelt.

---

## Wire-Format v5

Die Grammatik enthält überhaupt keine Satzzeichen, und der Decoder liest einen
Wortstrom statt Zeilen. Jede Stufe hat sechzehn Satzformen, die Sätze stammen aus
sechs Themen-Vokabularen — beides muss der Empfänger nicht wissen. Deflate wird
nur angewandt, wenn es die Nachricht tatsächlich verkleinert, also hält das
Manifest fest, was benutzt wurde. Das Salt heißt `stegocomm/v5/pbkdf2`; **Cover
früherer Versionen lassen sich nicht mehr entschlüsseln.**

```
Klartext → deflate → AES-256-GCM(iv‖Chiffretext‖Tag)
         → 8-Byte-Datenblöcke (+ R Cauchy/Reed-Solomon-Parity-Blöcke)
         → je Block: idx‖Nutzlast‖CRC8 (80 Bit), mit Keystream verschleiert
         → Cover-Sätze (variable Dichte) + je ein Manifest an Anfang und Ende
         → Restbits mit schlüsselabgeleitetem Zufalls-Padding gefüllt
```

Weil es keine Header-Zeilen gibt, an denen man sich neu ausrichten könnte,
schiebt der Decoder ein Fenster über den Wortstrom: er liest *n* Sätze, prüft die
Block-CRC und rückt bei Misserfolg nur um **ein Wort** weiter. Ein verlorener
oder verstümmelter Satz kostet damit einen Block, nicht den Rest der Nachricht.

### Bekannte Grenzen

- Nachrichten sind auf 254 Blöcke begrenzt, also rund 2 kB Chiffretext.
- Ein Cover ist 40- bis 70-mal so lang wie die Nachricht. Das meiste davon ist
  systembedingt — die Grammatik trägt 0,4 bis 0,8 Bit pro Zeichen. Größere Blöcke
  wurden gemessen und verworfen: die Parity wächst mit der Blockgröße mit, 8 Byte
  ergaben bei jeder getesteten Länge den kürzesten Cover.
- Die Sätze sind schablonenerzeugt und paaren Wörter zufällig, es kommen also
  schiefe Kombinationen vor. Es liest sich wie Geplauder, nicht wie Prosa.
- Die Blockerkennung hängt an einer 8-Bit-CRC; eine zufällige Satzfolge wird mit
  ~1/256 fälschlich als Block gelesen. Das GCM-Tag weist die Nachricht dann ab,
  statt falschen Klartext zu liefern.

---

## Tests laufen lassen

Die beiden Implementierungen müssen byteweise übereinstimmen, deshalb ist die
Gegenprobe der entscheidende Teil — wer nur eine von beiden ändert, fällt hier
durch. Das läuft bei jedem Push über GitHub Actions, lokal mit:

```bash
./tests/run_all.sh
```

Geprüft werden der Selbsttest jeder Engine (Round-Trip, Parity-Rekonstruktion,
NACK, Manifest-Redundanz, Resynchronisation, Transportschäden,
Grammatik-Konsistenz), danach kodiert jede Implementierung und die andere
dekodiert — über alle Stufen, Sprachen und Profile, jeder Fall mit einer
*anderen* Themenwahl, damit ein ins Bit-Layout durchgeschlagenes Thema den Build
umwirft. Zuletzt, dass Wortlisten und Passphrasen-Regel auf beiden Seiten
identisch sind. `tests/engine.mjs` lädt die Browser-Engine direkt aus
`cover_studio.html`, getestet wird also der ausgelieferte Code.

---

## Lizenz

MIT — siehe [LICENSE](LICENSE).

---

## Sicherheitshinweise

- **Punkt-zu-Punkt, für sich genommen nicht Ende-zu-Ende:** Die Passphrase schützt den Nachrichteninhalt zwischen den zwei Menschen, die sie teilen. Wähle eine starke, außerhalb dieses Kanals ausgetauschte Passphrase.
- **Alles hängt an dieser Passphrase.** Kein Schlüsselaustausch, keine Forward Secrecy: wer sie später bekommt, liest jede je abgefangene Nachricht.
- **Keine Absender-Authentifizierung.** Wer den Schlüssel hat, kann auch senden. Zwei Leute mit demselben Schlüssel sind füreinander nicht unterscheidbar.
- **Kein Replay-Schutz.** Ein abgefangener Cover lässt sich später erneut einspielen.
- **Der Cover verbirgt *Inhalt und die Tatsache, dass es Inhalt gibt*, aber nicht zwingend, *dass zwei Parteien kommunizieren*.** Metadaten (wer mit wem, wann, wie viel) sind ein eigenes Problem.
- **Die Tarnung hält keiner statistischen Prüfung stand.** Alle Sätze einer Stufe folgen einer Schablone, ein langer Cover ist auffällig repetitiv. Gegen flüchtiges Lesen wirkt das, gegen jemanden der gezielt sucht nicht.
- **Nicht auditiert.** Proof of Concept. Keine Gewähr.
- **Rechtlich:** Im Amateurfunk sind verschlüsselte oder verschleierte
  Aussendungen nicht erlaubt. Was zulässig ist, richtet sich nach den
  Bestimmungen deines Landes — vor dem Senden prüfen. Siehe
  [Senden über JS8Call](#senden-über-js8call).
