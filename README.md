# StegoComm

**A proof-of-concept covert, encrypted messaging channel that hides ciphertext inside innocuous-looking chatter.**

*[English](#english) · [Deutsch](#deutsch)*

Two interoperable implementations that speak the exact same wire format:

| Component | What it is | Dependencies |
|---|---|---|
| `cover_studio.html` | Browser tool (GUI): encode **and** decode, entirely client-side | **none** — just open the file |
| `stegocomms.py` | Python CLI engine, byte-compatible with the browser tool | `cryptography` |

A message encoded in the browser can be decoded by the Python CLI and vice versa.

> ⚠️ **This is a proof of concept, not audited security software.** It demonstrates the architecture (real AEAD encryption inside a steganographic text cover with forward error correction). Do not rely on it for protecting people at risk without an independent security review.

---

## English

### What it does

You have a secret message. StegoComm:

1. **compresses** it (deflate),
2. **encrypts** it with AES-256-GCM (key derived from a shared passphrase via PBKDF2-HMAC-SHA256, 200 000 iterations),
3. splits the ciphertext into 8-byte **blocks** and adds **Reed-Solomon parity blocks** (GF(256), Cauchy matrix) so lost or corrupted blocks can be reconstructed without asking for a resend,
4. **encodes each block as ordinary-looking sentences** — e.g. weather/radio small-talk in German or English — where the *choice of words* carries the bits,
5. fills leftover bits with key-derived **random padding** so filler sentences don't repeat tell-tale patterns.

There is **no plaintext header anywhere in the cover**. The block index and its
CRC travel inside the sentence bits; the per-message constants (block count,
parity count, padding length, block nonce) live in a **manifest** that is itself
made of ordinary cover sentences and is masked with a key-derived keystream.
Without the passphrase it cannot be told apart from a payload block. The
manifest is sent twice — once at the start, once at the end, with different
nonces and therefore completely different wording — so losing one spot does not
cost you the message.

The cover is therefore **nothing but carrier sentences** — there is no framing
line of any kind. The two profiles differ only in casing: `js8call` emits upper
case (the character set JS8Call transmits most efficiently), `plain` emits lower
case so it reads like an ordinary chat message. Casing carries no data; the
decoder lower-cases everything before parsing.

The result looks like harmless chatter (or a ham-radio JS8Call exchange) but carries an encrypted payload. The receiver reverses everything; a per-block CRC detects damaged blocks and treats them as erasures, which parity repairs up to its limit — beyond that you get a **NACK** listing exactly which blocks to resend (selective-repeat ARQ).

### The believability slider

The browser tool has a **Glaubhaftigkeit** (believability) slider, mirrored by the CLI's `--level 0..3`:

Higher levels do **not** bolt extra clauses onto the sentence — that was the v3
design, and it backfired: a tacked-on clause bought ~5 bits but cost ~20
characters, so density per character *fell* as the level rose and "very terse"
produced a **longer** cover than "very believable". In v4 the sentence stays
short and the **word lists get wider** (8/16/32 options per slot = 3/4/5 bits);
level 3 additionally drops articles and verbs for a telegraphic style.
Believability now falls because the word choice gets odd, not because the text
gets longer — and the character count finally falls with the level.

Measured on `Treffen Sonntag 18 Uhr am alten Hafen` (German, `plain`, 2 parity blocks):

| Level | Feel | Bits/sentence | Sentences | Characters | Bits/char |
|---|---|---|---|---|---|
| 0 | very believable | 10 | 104 | 2649 | 0.39 |
| 1 | believable (default) | 13 | 89 | 2272 | 0.51 |
| 2 | terse | 20 | 52 | 1934 | 0.54 |
| 3 | very terse | 28 | 39 | 1507 | 0.72 |

Note what the slider actually buys you: on JS8Call, airtime tracks *characters*,
so the level genuinely halves transmission time. In a chat transport it mostly
buys you fewer messages to paste.

The receiver does **not** need to know the language or level in advance. Neither
is stored anywhere — the decoder simply tries all 8 (language, level)
combinations and lets the manifest's CRC16 decide.

### Install

**Browser tool — nothing to install.** Just open `cover_studio.html`:

```bash
xdg-open cover_studio.html        # Linux
# or double-click it, or bookmark file:///path/to/cover_studio.html
```

**Python CLI** needs Python 3.8+ and the `cryptography` package. The robust, cross-distro way is a virtual environment:

```bash
cd StegoComm
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

On Fedora you may instead use the system package: `sudo dnf install python3-cryptography`.
(A bare `pip install --user cryptography` also works unless your distro reports `externally-managed-environment` — then use the venv above.)

### Usage

**Browser:** type your message, enter a passphrase (both sides must use the same one), pick language / channel / believability, then **Vollständig kopieren** (copy the full cover). The other side pastes it into the *Empfangen & Entschlüsseln* panel and clicks **Entschlüsseln**.

**CLI:**

```bash
# self-test (round-trip + parity recovery + NACK)
python3 stegocomms.py selftest

# encode a message to cover text
python3 stegocomms.py encode --pass "your-shared-passphrase" --lang en --level 1 \
        "Meet Sunday 6pm at the old harbour"

# ... in lower case, so it reads like an ordinary chat message
python3 stegocomms.py encode --pass "your-shared-passphrase" --profile plain \
        --lang en --level 1 "Meet Sunday 6pm at the old harbour"

# decode cover text from stdin
python3 stegocomms.py decode --pass "your-shared-passphrase"    # paste, then Ctrl-D
```

**Cross-check browser ⇄ Python** (prove interop): encode in one, decode in the other, using the same passphrase. If the plaintext comes back, the two independent implementations agree.

```
encode:  python3 stegocomms.py encode --pass P --lang de --level 1 "text"   # paste output into the browser
decode:  python3 stegocomms.py decode --pass P                              # paste browser's "copy full cover" here
```

### How the layers stack

```
plaintext → deflate → AES-256-GCM(iv‖ciphertext‖tag)
          → 8-byte data blocks (+ R Cauchy/Reed-Solomon parity blocks)
          → per block: idx‖payload‖CRC8 (80 bits), masked with a keystream
          → cover sentences (variable density) + one manifest run at each end
          → spare bits filled with key-derived random padding
```

Each layer solves one problem: GCM = confidentiality + integrity; Reed-Solomon = loss/error recovery without a round-trip; the grammar = the disguise; random padding = removes statistical tells; the masked manifest = framing without a visible header.

Because there are no header lines to re-synchronise on, the decoder slides a
window over the text: it reads *n* sentences, checks the block CRC, and on
failure advances by a single sentence instead of a whole block. A dropped or
mangled sentence therefore costs one block, not the rest of the message.

---

## Deutsch

### Was es macht

Du hast eine geheime Nachricht. StegoComm:

1. **komprimiert** sie (deflate),
2. **verschlüsselt** sie mit AES-256-GCM (Schlüssel aus einer gemeinsamen Passphrase via PBKDF2-HMAC-SHA256, 200 000 Iterationen),
3. zerlegt den Chiffretext in 8-Byte-**Blöcke** und ergänzt **Reed-Solomon-Parity-Blöcke** (GF(256), Cauchy-Matrix), damit verlorene oder beschädigte Blöcke ohne Nachforderung rekonstruiert werden,
4. **kodiert jeden Block als unauffällige Sätze** — z.B. Wetter-/Funk-Smalltalk auf Deutsch oder Englisch — wobei die *Wortwahl* die Bits trägt,
5. füllt Restbits mit schlüsselabgeleitetem **Zufalls-Padding**, damit Füllsätze keine verräterischen Muster wiederholen.

Im Cover steht **nirgends ein Klartext-Header**. Blockindex und Block-CRC stecken
in den Satz-Bits; die pro Nachricht konstanten Felder (Blockzahl, Parity-Zahl,
Padlänge, Block-Nonce) liegen in einem **Manifest**, das selbst aus ganz normalen
Cover-Sätzen besteht und mit einem schlüsselabgeleiteten Keystream verschleiert
ist. Ohne Passphrase ist es von einem Nutzblock nicht zu unterscheiden. Das
Manifest wird zweimal gesendet — am Anfang und am Ende, mit verschiedenen Nonces
und daher völlig verschiedenem Wortlaut — damit der Verlust einer Stelle nicht
die ganze Nachricht kostet.

Das Cover besteht deshalb **ausschließlich aus Trägersätzen** — es gibt keinerlei
Rahmenzeile. Die beiden Profile unterscheiden sich nur in der Schreibweise:
`js8call` liefert Großbuchstaben (den Zeichensatz, den JS8Call am effizientesten
überträgt), `plain` Kleinbuchstaben, damit es wie eine normale Chat-Nachricht
aussieht. Die Schreibweise trägt keine Daten; der Decoder wandelt vor dem Parsen
ohnehin alles in Kleinbuchstaben.

Das Ergebnis sieht aus wie harmloses Geplauder (oder ein JS8Call-Funkspruch), transportiert aber eine verschlüsselte Nutzlast. Der Empfänger dreht alles zurück; eine Block-CRC erkennt beschädigte Blöcke und behandelt sie als Erasure, was die Parity bis zu ihrer Grenze repariert — darüber kommt ein **NACK**, der genau angibt, welche Blöcke nachzusenden sind (Selective-Repeat-ARQ).

### Der Glaubhaftigkeits-Regler

Das Browser-Tool hat einen **Glaubhaftigkeits**-Regler, gespiegelt durch `--level 0..3` in der CLI:

Höhere Stufen hängen **keine** Nebensätze mehr an — das war der v3-Entwurf, und
er ging nach hinten los: ein angehängter Nebensatz brachte ~5 Bit, kostete aber
~20 Zeichen. Dadurch *sank* die Dichte pro Zeichen mit steigender Stufe, und
„sehr knapp" erzeugte einen **längeren** Cover als „sehr glaubhaft". In v4 bleibt
der Satz kurz und die **Wortlisten werden breiter** (8/16/32 Optionen je Slot =
3/4/5 Bit); Stufe 3 fällt zusätzlich in den Telegrammstil ohne Artikel und Verb.
Die Glaubhaftigkeit sinkt jetzt durch ungewöhnliche Wortwahl, nicht durch Länge
— und die Zeichenzahl fällt endlich mit der Stufe.

Gemessen an `Treffen Sonntag 18 Uhr am alten Hafen` (deutsch, `plain`, 2 Parity-Blöcke):

| Stufe | Wirkung | Bit/Satz | Sätze | Zeichen | Bit/Zeichen |
|---|---|---|---|---|---|
| 0 | sehr glaubhaft | 10 | 104 | 2649 | 0,39 |
| 1 | glaubhaft (Standard) | 13 | 89 | 2272 | 0,51 |
| 2 | knapp | 20 | 52 | 1934 | 0,54 |
| 3 | sehr knapp | 28 | 39 | 1507 | 0,72 |

Wichtig zur Einordnung: Auf JS8Call hängt die Sendezeit an **Zeichen**, die Stufe
halbiert sie also tatsächlich. In einem Chat-Transport spart sie vor allem
Nachrichten zum Einfügen.

Der Empfänger muss Sprache und Stufe **nicht** vorher kennen. Beides steht
nirgends im Cover — der Decoder probiert schlicht alle 8 Kombinationen aus
Sprache und Stufe durch, die CRC16 des Manifests entscheidet.

### Installation

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

### Benutzung

**Browser:** Nachricht eintippen, Passphrase eingeben (beide Seiten dieselbe), Sprache / Kanal / Glaubhaftigkeit wählen, dann **Vollständig kopieren**. Die Gegenseite fügt den Text im Panel *Empfangen & Entschlüsseln* ein und klickt **Entschlüsseln**.

**CLI:**

```bash
# Selbsttest (Round-Trip + Parity-Rekonstruktion + NACK)
python3 stegocomms.py selftest

# Nachricht in Cover-Text kodieren
python3 stegocomms.py encode --pass "gemeinsame-passphrase" --lang de --level 1 \
        "Treffen Sonntag 18 Uhr am alten Hafen"

# ... in Kleinschreibung, damit es wie eine normale Chat-Nachricht aussieht
python3 stegocomms.py encode --pass "gemeinsame-passphrase" --profile plain \
        --lang de --level 1 "Treffen Sonntag 18 Uhr am alten Hafen"

# Cover-Text von stdin dekodieren
python3 stegocomms.py decode --pass "gemeinsame-passphrase"    # einfügen, dann Strg-D
```

**Gegenprobe Browser ⇄ Python** (Interop-Beweis): in einem kodieren, im anderen dekodieren, gleiche Passphrase. Kommt der Klartext zurück, stimmen die beiden unabhängigen Implementierungen überein.

### Schichtenaufbau

```
Klartext → deflate → AES-256-GCM(iv‖Chiffretext‖Tag)
         → 8-Byte-Datenblöcke (+ R Cauchy/Reed-Solomon-Parity-Blöcke)
         → je Block: idx‖Nutzlast‖CRC8 (80 Bit), mit Keystream verschleiert
         → Cover-Sätze (variable Dichte) + je ein Manifest an Anfang und Ende
         → Restbits mit schlüsselabgeleitetem Zufalls-Padding gefüllt
```

Jede Schicht löst ein Problem: GCM = Vertraulichkeit + Integrität; Reed-Solomon = Verlust-/Fehlerkorrektur ohne Rückfrage; die Grammatik = die Tarnung; Zufalls-Padding = entfernt statistische Verräter; das verschleierte Manifest = Rahmung ohne sichtbaren Header.

Weil es keine Header-Zeilen mehr gibt, an denen man sich neu ausrichten könnte,
schiebt der Decoder ein Fenster über den Text: er liest *n* Sätze, prüft die
Block-CRC und rückt bei Misserfolg nur um **einen** Satz weiter statt um einen
ganzen Block. Ein verlorener oder verstümmelter Satz kostet damit einen Block,
nicht den Rest der Nachricht.

---

## Sending over JS8Call / Senden über JS8Call

**Paste only the cover sentences. Nothing else.** JS8Call puts your own callsign
on the air itself — you type message text, not a header. Do not prepend `DE
<call>`, and never send a callsign that is not yours: that is illegal wherever
amateur radio is licensed. Earlier versions of this tool printed decorative
callsign lines (`DE W1ABC MSG 3/14`); they were removed for exactly this reason.
If you still have such a cover lying around it decodes fine — the decoder skips
lines it cannot parse.

1. Encode with `--profile js8call` (upper case) or the **JS8Call** channel in the
   browser tool.
2. Copy the whole cover.
3. Paste it into JS8Call's send box and transmit. Long covers exceed one frame;
   JS8Call splits them, or you send them in chunks.
4. The receiver copies the received text out of JS8Call — their own and your
   callsign prefixes included, those do no harm — and pastes it into `decode`.

Two things to check on your own installation before relying on this:

- **Punctuation.** Levels 2 and 3 put a comma inside each sentence. Confirm that
  a comma survives your JS8Call setup intact; if it is dropped or substituted,
  stay on level 0 or 1, which use no punctuation at all.
- **Line breaks.** The decoder needs one sentence per line. If your transport
  reflows or joins lines, the sentences run together and nothing decodes.

**Nur die Cover-Sätze einfügen, sonst nichts.** JS8Call sendet dein Rufzeichen
selbst — du tippst dort Nachrichtentext, keinen Header. Also kein `DE <call>`
davorsetzen, und niemals ein fremdes Rufzeichen senden: das ist überall dort
illegal, wo Amateurfunk lizenziert ist. Frühere Fassungen dieses Werkzeugs haben
dekorative Rufzeichen-Zeilen ausgegeben (`DE W1ABC MSG 3/14`); genau deswegen
sind sie entfernt worden. Ein altes Cover mit solchen Zeilen lässt sich weiterhin
dekodieren — der Decoder überspringt, was er nicht parsen kann.

Vorher prüfen: ob ein **Komma** deine JS8Call-Strecke unbeschadet übersteht (nur
Stufe 2 und 3 nutzen eins — Stufe 0 und 1 kommen ohne Satzzeichen aus), und ob
**Zeilenumbrüche** erhalten bleiben; der Decoder braucht einen Satz pro Zeile.

---

## Wire format v4 / Wire-Format v4

The current wire format is **v4**. It differs from v3 in three ways: the plaintext
per-block header is gone (framing now lives in the covert channel plus a masked
manifest), the believability levels trade density for *word choice* instead of
sentence length, and German nouns carry their correct article (`der Kaffee`
instead of v3's blanket `das kaffee`). The PBKDF2 salt changed to
`stegocomm/v4/pbkdf2`, so **v3 covers cannot be decoded by v4** — the format is
incompatible anyway. Both implementations were changed in lockstep and verified
against each other in both directions across all 4 levels × 2 languages ×
2 profiles.

Das aktuelle Wire-Format ist **v4**. Unterschiede zu v3: der Klartext-Header pro
Block ist weg (die Rahmung steckt jetzt im verdeckten Kanal plus einem
verschleierten Manifest), die Glaubhaftigkeitsstufen erkaufen Dichte über die
*Wortwahl* statt über die Satzlänge, und deutsche Nomen tragen ihren richtigen
Artikel (`der Kaffee` statt des pauschalen `das kaffee` aus v3). Das PBKDF2-Salt
heißt jetzt `stegocomm/v4/pbkdf2`, **v3-Cover lassen sich mit v4 also nicht
entschlüsseln** — das Format ist ohnehin inkompatibel.

### Known limits / Bekannte Grenzen

- A message is capped at 254 blocks, i.e. roughly 2 kB of ciphertext.
  Nachrichten sind auf 254 Blöcke begrenzt, also rund 2 kB Chiffretext.
- Every sentence at a given level follows one template, so a long cover is
  structurally repetitive. That was true in v3 as well and is a believability
  ceiling, not a correctness problem.
  Alle Sätze einer Stufe folgen einer Schablone, ein langer Cover wirkt daher
  strukturell repetitiv — das galt für v3 genauso und ist eine Grenze der
  Glaubhaftigkeit, kein Fehler.
- Block detection rests on an 8-bit CRC, so a random sentence run has a ~1/256
  chance of being mistaken for a block. A false hit corrupts the payload and the
  GCM tag then rejects the message rather than returning wrong plaintext.
  Die Blockerkennung hängt an einer 8-Bit-CRC; eine zufällige Satzfolge wird mit
  ~1/256 fälschlich als Block gelesen. Ein Fehltreffer verdirbt die Nutzlast, das
  GCM-Tag weist die Nachricht dann ab statt falschen Klartext zu liefern.

---

## Security notes / Sicherheitshinweise

- **Point-to-point, not end-to-end by itself:** the passphrase protects the message content between the two people who share it. Choose a strong, shared-out-of-band passphrase.
- **The cover hides *content and the fact that content exists*, but not necessarily *that two parties communicate*.** Metadata (who talks to whom, when, how much) is a separate problem.
- **Not audited.** Proof of concept. No warranty.
