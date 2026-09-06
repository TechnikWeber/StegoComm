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

The result looks like harmless chatter (or a ham-radio JS8Call exchange) but carries an encrypted payload. The receiver reverses everything; a per-block CRC detects damaged blocks and treats them as erasures, which parity repairs up to its limit — beyond that you get a **NACK** listing exactly which blocks to resend (selective-repeat ARQ).

### The believability slider

The browser tool has a **Glaubhaftigkeit** (believability) slider, mirrored by the CLI's `--level 0..3`:

| Level | Feel | Bits per sentence | Trade-off |
|---|---|---|---|
| 0 | very believable | 8 | most natural, longest cover |
| 1 | believable | 13 | good compromise (default) |
| 2 | terse | 17 | shorter, noticeably stilted |
| 3 | very terse | 22 | shortest, clearly artificial |

The receiver does **not** need to know the language or level in advance — both are written into the block header and detected automatically on decode.

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
          → per block: 64 payload bits → cover sentences (variable density)
          → spare bits filled with key-derived random padding
```

Each layer solves one problem: GCM = confidentiality + integrity; Reed-Solomon = loss/error recovery without a round-trip; the grammar = the disguise; random padding = removes statistical tells.

---

## Deutsch

### Was es macht

Du hast eine geheime Nachricht. StegoComm:

1. **komprimiert** sie (deflate),
2. **verschlüsselt** sie mit AES-256-GCM (Schlüssel aus einer gemeinsamen Passphrase via PBKDF2-HMAC-SHA256, 200 000 Iterationen),
3. zerlegt den Chiffretext in 8-Byte-**Blöcke** und ergänzt **Reed-Solomon-Parity-Blöcke** (GF(256), Cauchy-Matrix), damit verlorene oder beschädigte Blöcke ohne Nachforderung rekonstruiert werden,
4. **kodiert jeden Block als unauffällige Sätze** — z.B. Wetter-/Funk-Smalltalk auf Deutsch oder Englisch — wobei die *Wortwahl* die Bits trägt,
5. füllt Restbits mit schlüsselabgeleitetem **Zufalls-Padding**, damit Füllsätze keine verräterischen Muster wiederholen.

Das Ergebnis sieht aus wie harmloses Geplauder (oder ein JS8Call-Funkspruch), transportiert aber eine verschlüsselte Nutzlast. Der Empfänger dreht alles zurück; eine Block-CRC erkennt beschädigte Blöcke und behandelt sie als Erasure, was die Parity bis zu ihrer Grenze repariert — darüber kommt ein **NACK**, der genau angibt, welche Blöcke nachzusenden sind (Selective-Repeat-ARQ).

### Der Glaubhaftigkeits-Regler

Das Browser-Tool hat einen **Glaubhaftigkeits**-Regler, gespiegelt durch `--level 0..3` in der CLI:

| Stufe | Wirkung | Bits pro Satz | Kompromiss |
|---|---|---|---|
| 0 | sehr glaubhaft | 8 | am natürlichsten, längster Cover |
| 1 | glaubhaft | 13 | guter Kompromiss (Standard) |
| 2 | knapp | 17 | kürzer, merklich gestelzt |
| 3 | sehr knapp | 22 | kürzester, deutlich künstlich |

Der Empfänger muss Sprache und Stufe **nicht** vorher kennen — beides steht im Block-Header und wird beim Decode automatisch erkannt.

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

# Cover-Text von stdin dekodieren
python3 stegocomms.py decode --pass "gemeinsame-passphrase"    # einfügen, dann Strg-D
```

**Gegenprobe Browser ⇄ Python** (Interop-Beweis): in einem kodieren, im anderen dekodieren, gleiche Passphrase. Kommt der Klartext zurück, stimmen die beiden unabhängigen Implementierungen überein.

### Schichtenaufbau

```
Klartext → deflate → AES-256-GCM(iv‖Chiffretext‖Tag)
         → 8-Byte-Datenblöcke (+ R Cauchy/Reed-Solomon-Parity-Blöcke)
         → je Block: 64 Nutzbits → Cover-Sätze (variable Dichte)
         → Restbits mit schlüsselabgeleitetem Zufalls-Padding gefüllt
```

Jede Schicht löst ein Problem: GCM = Vertraulichkeit + Integrität; Reed-Solomon = Verlust-/Fehlerkorrektur ohne Rückfrage; die Grammatik = die Tarnung; Zufalls-Padding = entfernt statistische Verräter.

---

## Security notes / Sicherheitshinweise

- **Point-to-point, not end-to-end by itself:** the passphrase protects the message content between the two people who share it. Choose a strong, shared-out-of-band passphrase.
- **The cover hides *content and the fact that content exists*, but not necessarily *that two parties communicate*.** Metadata (who talks to whom, when, how much) is a separate problem.
- **Not audited.** Proof of concept. No warranty.
