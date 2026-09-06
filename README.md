**English** · [Deutsch](README.de.md)

# StegoComm

[![tests](https://github.com/TechnikWeber/StegoComm/actions/workflows/ci.yml/badge.svg)](https://github.com/TechnikWeber/StegoComm/actions/workflows/ci.yml)

**A proof-of-concept covert, encrypted messaging channel that hides ciphertext inside innocuous-looking chatter.**

Two interoperable implementations that speak the exact same wire format:

| Component | What it is | Dependencies |
|---|---|---|
| `cover_studio.html` | Browser tool (GUI): encode **and** decode, entirely client-side | **none** — just open the file |
| `stegocomms.py` | Python CLI engine, byte-compatible with the browser tool | `cryptography` |

A message encoded in the browser can be decoded by the Python CLI and vice versa.

> ⚠️ **This is a proof of concept, not audited security software.** It demonstrates the architecture (real AEAD encryption inside a steganographic text cover with forward error correction). Do not rely on it for protecting people at risk without an independent security review.

---

## How it works

Five steps down, the same five back up. Only the last one is unusual — the first
four are ordinary, well-understood cryptography.

```
        WHAT YOU TYPE
        "Meet Sunday 6pm at the old harbour"
                     │
                     │   1.  SQUEEZE
                     │       deflate, but only if it actually shrinks
                     ▼
        ▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒
                     │
                     │   2.  LOCK
                     │       AES-256-GCM, key from your passphrase
                     │       (PBKDF2, 200 000 rounds)
                     ▼
        ████████████████████████    ← unreadable noise.
                     │                 THIS is what protects you
                     │
                     │   3.  SLICE
                     │       into 8-byte blocks
                     ▼
        ██ ██ ██ ██ ██ ██
                     │
                     │   4.  INSURE
                     │       add parity blocks (Reed-Solomon)
                     ▼
        ██ ██ ██ ██ ██ ██ ▓▓ ▓▓     ▓ = parity: any 2 lost blocks
                     │                  can be rebuilt without a resend
                     │
                     │   5.  DISGUISE
                     │       each block becomes sentences —
                     ▼       the CHOICE OF WORDS carries the bits
        ┌──────────────────────────────────┐
        │  the market is quiet today       │   ← this is what you send
        │  the roof is fine inside         │
        │  the antenna is steady here      │
        │  ...                             │
        └──────────────────────────────────┘

        The receiver runs the same five steps backwards.
```

**Why the choice of words is the data.** Each sentence follows one pattern, and
every slot in it has a fixed list of possible words. With 32 nouns to choose
from, *which* noun appears is worth 5 bits. Pick a noun, an adjective and an
ending, and one short sentence has carried 10 to 28 bits. The receiver looks up
each word's position in the same lists and gets the bits straight back.

**What each layer is for**

| Layer | Solves |
|---|---|
| deflate (when it helps) | fewer bytes to hide |
| AES-256-GCM | nobody can read it, and tampering is detected |
| Reed-Solomon | lost blocks rebuilt without asking for a resend |
| the grammar | it does not look like a message |
| random padding | filler bits do not repeat a tell-tale pattern |

**The important bit:** your security comes from step 2, not step 5. Even someone
who knows exactly how this tool works and unpicks the sentences perfectly ends up
with the noise from step 2 — and without your passphrase that is where they stop.
The disguise buys you that nobody looks in the first place.

---

## What it does in detail

You have a secret message. StegoComm:

1. **compresses** it (deflate) — but only when that actually shrinks it; deflate costs six bytes of framing, which a short message never earns back,
2. **encrypts** it with AES-256-GCM (key derived from a shared passphrase via PBKDF2-HMAC-SHA256, 200 000 iterations),
3. splits the ciphertext into 8-byte **blocks** and adds **Reed-Solomon parity blocks** (GF(256), Cauchy matrix) so lost or corrupted blocks can be reconstructed without asking for a resend,
4. **encodes each block as ordinary-looking sentences** — weather and small-talk in German or English — where the *choice of words* carries the bits,
5. fills leftover bits with key-derived **random padding** so filler sentences don't repeat tell-tale patterns.

There is **no plaintext header anywhere in the cover**. The block index and its
CRC travel inside the sentence bits; the per-message constants (block count,
parity count, padding length, block nonce) live in a **manifest** that is itself
made of ordinary cover sentences and is masked with a key-derived keystream.
Without the passphrase it cannot be told apart from a payload block. The
manifest is sent twice — once at the start, once at the end, with different
nonces and therefore completely different wording — so losing one spot does not
cost you the message.

The cover is therefore **nothing but carrier sentences** — no framing line of any
kind, and **letters and single spaces only**: no punctuation, no digits, at any
level. That is deliberate, because punctuation is exactly what a radio or chat
path quietly drops or substitutes.

The two profiles differ only in casing: `plain` (the default) emits lower case so
it reads like an ordinary chat message, `js8call` emits upper case, the character
set JS8Call transmits most efficiently. Casing carries no data; the decoder
lower-cases everything before parsing.

The receiver reverses everything; a per-block CRC detects damaged blocks and
treats them as erasures, which parity repairs up to its limit — beyond that you
get a **NACK** listing exactly which blocks to resend (selective-repeat ARQ).

### Cover topics

The sentences are built from one of six everyday vocabularies — **weather & sky,
home & kitchen, garden & outdoors, work & errands, travel & road, radio & tech**,
64 nouns each — and a topic is drawn per sentence, so a cover wanders between
subjects the way real chatter does. Everything but *radio & tech* is on by default; the **AFU
mode** button switches to *radio & tech* alone for amateur-radio use, and every
box stays individually tickable either way.

**The selection is sender-side only, and the two sides never have to match it.**
The topic carries no data: only the nouns differ between topics, every noun is
unique across all of them, and the indices behind the words mean the same thing
everywhere. So the noun tells the decoder which topic a sentence came from, and
it knows all six regardless of what you ticked. One person can send with weather
and kitchen switched on while the other has only radio & tech ticked, and each
still reads the other perfectly — same passphrase is all that is shared. The
test suite checks exactly this, encoding with a different topic set in each
implementation and decoding with the other.

On the command line: `--topics weather,garden` or `--afu`.

### Surviving the transport

The cover has to arrive intact, and real transports are not careful. The decoder
therefore does not read lines at all — it reads **one continuous stream of
words**. Every sentence pattern has a fixed word count, so the sentences can be
recovered from the word sequence alone and **line breaks carry no information**.
A path that wraps, joins, reflows or blank-line-separates the text changes
nothing.

Before that it folds away the rest of the usual damage: casing, a leading
callsign or quote marker (`KN4CRD: `, `> `), punctuation anywhere, and runs of
whitespace. Cover sentences never contain `:` or `>`, so stripping such a prefix
can never damage a genuine sentence.

If it still finds characters the grammar never produces, it says so rather than
blaming your passphrase — that message is the single most useful thing it can
tell you when a path is mangling your text.

What remains fatal is a path that **changes or drops words**. Each damaged
sentence costs one block; parity absorbs a few, and beyond that you get a NACK.

### The believability slider

**"Level" is simply the position of the believability slider** — one of four
settings, `--level 0` to `--level 3` on the command line. It decides how hard
each sentence works: a low level uses only the most everyday words and needs many
sentences; a high level draws on much wider word lists, so one sentence carries
more, and fewer sentences are needed. Nothing else changes — same encryption,
same message. You are trading how natural the text reads against how long it is.

The receiver does not need to be told which level you used.

Measured on `Treffen Sonntag 18 Uhr am alten Hafen` (German, 2 parity blocks):

| Level | Feel | Bits/sentence | Words drawn from | Sentences | Characters | Example |
|---|---|---|---|---|---|---|
| 0 | very believable | 14 | 16 nouns, 8+8 others | 78 | 2186 | `jetzt war die karte laut` |
| 1 | believable (default) | 17 | 32 nouns, 16+16 | 65 | 1920 | `oben blieb der drucker mau` |
| 2 | terse | 23 | 64 nouns, 32+16+16 | 52 | 1630 | `abends war regen hart hell` |
| 3 | very terse | 26 | 64 nouns, 64+32+32 | 50 | 1422 | `heil diesig prognose wiederholt` |

Naturalness falls step by step in a way you can hear: levels 0 and 1 are complete
sentences with an article and a verb, level 2 drops the article, level 3 drops
the verb as well. This ladder was **measured, not guessed** — what decides cover
length is `ceil(80 / bits) × average sentence length`, and four short sentences
beat three long ones, which is why the terse levels shed function words rather
than adding clauses.

Higher levels do **not** bolt extra clauses onto the sentence — that was the v3
design, and it backfired: a tacked-on clause bought ~5 bits but cost ~20
characters, so density per character *fell* as the level rose and "very terse"
produced a **longer** cover than "very believable". In v4 the sentence stays
short and the **word lists get wider** (8/16/32 options per slot = 3/4/5 bits);
level 3 additionally drops articles and verbs for a telegraphic style.
Believability now falls because the word choice gets odd, not because the text
gets longer — and the character count finally falls with the level.

Note what the slider actually buys you: on JS8Call, airtime tracks *characters*,
so the level genuinely halves transmission time. In a chat transport it mostly
buys you fewer messages to paste.

Each level offers **sixteen sentence shapes** of identical word count and bit
width — eight copulas (`is/was/stays/stayed/seems/seemed/looks/looked`, mixing
tense the way real chatter does) times two word orders for levels 0 to 2, and
sixteen of the 24 orderings of the four words for level 3. Which one is used is
itself part of the payload, so the variety is free: it adds four bits per
sentence rather than costing anything, which is why level 0 needs six sentences
per block rather than seven.

The higher levels also reach deeper into the word lists. Each topic holds **64
nouns**, ordered by how everyday the word is, and the shared lists hold 64
adjectives plus 32 each of weather words, endings and time adverbs. Level 0 sees
only the first 16 nouns and the 8 commonest adjectives; level 3 sees everything,
which is part of why it sounds odd — and why it carries nearly twice the bits per
character.

Neither the language nor the level is stored anywhere — the decoder simply tries
all 8 (language, level) combinations and lets the manifest's CRC16 decide.

---

## Install

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

## Usage

**Browser:** type your message, enter a passphrase (both sides must use the same
one), pick language / channel / believability, then **Copy all**. The other side
pastes it into the *Receive & decrypt* panel and clicks **Decrypt**.
**Test with my own cover** is a loopback check: it pastes the cover you just
generated into the receive box and decrypts it, so you can confirm encode and
decode agree without a second machine.

**CLI:**

```bash
# self-test (round-trip + parity recovery + NACK + transport damage)
python3 stegocomms.py selftest

# encode a message to cover text (plain lower case is the default)
python3 stegocomms.py encode --pass "your-shared-passphrase" --lang en --level 1 \
        "Meet Sunday 6pm at the old harbour"

# ... in upper case for JS8Call
python3 stegocomms.py encode --pass "your-shared-passphrase" --profile js8call \
        --lang en --level 1 "Meet Sunday 6pm at the old harbour"

# ... drawing only on chosen vocabularies, or on radio & tech alone
python3 stegocomms.py encode --pass "..." --topics weather,garden "..."
python3 stegocomms.py encode --pass "..." --afu --profile js8call "..."

# decode cover text from stdin
python3 stegocomms.py decode --pass "your-shared-passphrase"    # paste, then Ctrl-D
```

**Cross-check browser ⇄ Python** (prove interop): encode in one, decode in the
other, using the same passphrase. If the plaintext comes back, the two
independent implementations agree.

### About the passphrase

Any UTF-8 text works — umlauts, emoji, quotes, backslashes, tabs — because
PBKDF2 turns whatever you type into a 32-byte key. But since the entire security
of the tool hangs on this one string, both the CLI and the browser tool now
**refuse to encode below 12 characters** and tell you when what you typed is
weaker than it looks. (`--allow-weak-pass` overrides the CLI check; decoding is
never restricted, or you could not read your own old messages.)

**What a good passphrase looks like:** four or five unrelated words, e.g.
`harbour-lantern-quiet-seven`. Length beyond that matters less than
unpredictability — `aaaaaaaaaaaaaaaaaaaa` is twenty characters and worthless.
The check reports what is actually checkable (length, variety, whether it is a
single word); no meter can tell whether *you* picked it at random, and it says so.

Two further things to know:

- **Nothing is trimmed.** `"secret"` and `"secret "` are different keys. A stray
  space picked up while copying will break decryption.
- **The field is not masked** (`type="text"`), so the passphrase is visible on screen.

---

## Sending over JS8Call

**Paste only the cover sentences. Nothing else.** JS8Call puts your own callsign
on the air itself — you type message text, not a header. Do not prepend `DE
<call>`, and never send a callsign that is not yours: that is illegal wherever
amateur radio is licensed. Earlier versions of this tool printed decorative
callsign lines (`DE W1ABC MSG 3/14`); they were removed for exactly this reason.
If you still have such a cover lying around it decodes fine — the decoder skips
what it cannot parse.

1. Encode with `--profile js8call` (upper case) or the **JS8Call** channel in the
   browser tool.
2. Copy the whole cover.
3. Paste it into JS8Call's send box and transmit. Long covers exceed one frame;
   JS8Call splits them, or you send them in chunks.
4. The receiver copies the received text out of JS8Call and pastes it into
   `decode`. Callsign prefixes and line breaks are handled automatically.

---

## Wire format v5

The current wire format is **v5**. Its grammar contains no punctuation at all,
and the decoder reads a stream of words rather than lines, normalising away
casing, callsign/quote prefixes, punctuation and whitespace before parsing.
Each level carries eight sentence shapes and the sentences are drawn from six
topic vocabularies (neither of which the receiver has to be told), and deflate is
applied only when it actually shrinks the message — it costs six bytes of framing, which a short
message never earns back, so the manifest records which was used. The salt is
`stegocomm/v5/pbkdf2`; **covers from earlier versions cannot be decoded**, and
the format is incompatible anyway.

Both implementations are changed in lockstep and verified against each other in
both directions on every push — see `tests/`.

### How the layers stack

```
plaintext → deflate → AES-256-GCM(iv‖ciphertext‖tag)
          → 8-byte data blocks (+ R Cauchy/Reed-Solomon parity blocks)
          → per block: idx‖payload‖CRC8 (80 bits), masked with a keystream
          → cover sentences (variable density) + one manifest run at each end
          → spare bits filled with key-derived random padding
```

Because there are no header lines to re-synchronise on, the decoder slides a
window over the word stream: it reads *n* sentences, checks the block CRC, and on
failure advances by a single **word**. A dropped or mangled sentence therefore
costs one block, not the rest of the message.

### Known limits

- A message is capped at 254 blocks, i.e. roughly 2 kB of ciphertext.
- A cover is 40× to 70× the length of the message. Most of that is inherent —
  the grammar carries 0.4 to 0.8 bits per character — and the browser tool now
  breaks the rest down for you field by field. Larger blocks would cut the
  per-block framing, but they were measured and rejected: the parity blocks grow
  with the block size, so 8 bytes turned out to be the smallest cover at every
  message length tried.
- With sixteen shapes and six vocabularies a long cover no longer repeats one
  pattern, but the sentences are still template-generated and pair words at
  random, so odd combinations occur. It reads as chatter, not as prose.
- Block detection rests on an 8-bit CRC, so a random sentence run has a ~1/256
  chance of being mistaken for a block. A false hit corrupts the payload and the
  GCM tag then rejects the message rather than returning wrong plaintext.

---

## Running the tests

The two implementations must agree byte for byte, so the cross-check is the part
that matters — a change to only one of them fails here. This runs on every push
via GitHub Actions, and locally with:

```bash
./tests/run_all.sh
```

It runs each engine's own selftest (round-trip, parity recovery, NACK, manifest
redundancy, resynchronisation, transport damage, grammar consistency), then
encodes with each implementation and decodes with the other across all levels,
languages and profiles — each case with a *different* topic selection, so a topic
leaking into the bit layout would fail the build. It then checks the word lists:
that nouns are unique across every topic, that slots which can share a position
never share a word, and that both implementations carry byte-identical lists.
Finally it checks that the passphrase rule is identical on both sides. `tests/engine.mjs` loads the browser engine straight out of
`cover_studio.html`, so the tested code is the shipped code.

---

## License

MIT — see [LICENSE](LICENSE).

---

## Security notes

- **Point-to-point, not end-to-end by itself:** the passphrase protects the message content between the two people who share it. Choose a strong, shared-out-of-band passphrase.
- **Everything hangs on that passphrase.** There is no key exchange and no forward secrecy: whoever obtains it later can read every message they ever intercepted.
- **No sender authentication.** Anyone holding the key can also send. Two people sharing a key are indistinguishable to each other.
- **No replay protection.** An intercepted cover can be replayed later.
- **The cover hides *content and the fact that content exists*, but not necessarily *that two parties communicate*.** Metadata (who talks to whom, when, how much) is a separate problem.
- **The disguise does not survive statistical scrutiny.** Every sentence at a level follows one template, so a long cover is conspicuously repetitive. It works against a casual reader, not against someone looking for it.
- **Not audited.** Proof of concept. No warranty.
