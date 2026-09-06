"""
stegocomms.py -- Proof of Concept v4

Covert, encrypted message channel over any text transport.
This version is BYTE-COMPATIBLE with the browser tool cover_studio.html:
a cover produced in the browser decodes here and vice versa.

Dependencies:  pip install cryptography      (zlib/hashlib = standard library)

Pipeline (sender):
  plaintext -> zlib(deflate) -> AES-256-GCM (iv||ciphertext||tag)
    -> pad to a multiple of CHUNK -> K data blocks
    -> +R cross-block parity (Reed-Solomon over GF(256), Cauchy matrix -> MDS)
    -> per block: idx || payload || CRC8, masked with a keystream
    -> bits rendered as cover sentences (density varies by "level")
    -> leftover bits filled with key-derived random padding
The receiver runs it backwards; a per-block CRC spots damaged blocks and treats
them as erasures -> reconstructed up to the parity limit WITHOUT asking for a
resend, beyond that a NACK naming the missing data blocks.

What changed in v4 compared to v3
---------------------------------
1. No plaintext header any more.  v3 prefixed every block with a line
   "DE W1ABC MSG 0/12 K 10 SZ 74 LV 0 CK 8" -- in a chat transport by far the
   most conspicuous element of the whole cover.  In v4 the block index and the
   block CRC live in the sentence bits, and the fields that are constant per
   message (K, R, ciphertext padding, block nonce) live in a MANIFEST which is
   itself made of ordinary cover sentences.  A cover therefore consists of
   nothing but chat sentences.
   The manifest is masked with a key-derived keystream; without the passphrase
   it cannot be told apart from a payload block.  It is sent twice (start and
   end, with different nonces and therefore completely different wording) so
   that losing one spot does not cost the whole message.
   Language and level are NOT stored -- the receiver tries all 8 combinations
   and lets the manifest CRC16 decide.

2. Density instead of length.  In v3 the higher levels bought their bits by
   appending clauses: a tacked-on clause carried ~5 bits but cost ~20
   characters -- a worse ratio than the base sentence.  Density per character
   therefore FELL as the level rose (0.31 -> 0.26 bits/char) and "very terse"
   produced MORE characters than "very believable".  In v4 the sentence stays
   short and the word lists get wider (8/16/32 options = 3/4/5 bits per slot);
   level 3 additionally drops articles and verbs for a telegraphic style.
   Believability now falls through unusual word choice rather than length --
   and the character count falls monotonically with the level.

3. Correct articles in German ("der Kaffee", "die Antenne") instead of v3's
   blanket "das".

v3 covers can NOT be decoded with v4 (different wire format and a different
PBKDF2 salt).

Key:  derived from the shared passphrase via PBKDF2-HMAC-SHA256
      (salt "stegocomm/v4/pbkdf2", 200_000 iterations, 32 bytes).
      Both sides must use the same passphrase.
"""

import sys, os, re, math, zlib, hashlib, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK = 8            # bytes per block
BLOCK_BITS = CHUNK * 8   # 64
PBKDF2_SALT = b"stegocomm/v5/pbkdf2"
PBKDF2_ITERS = 200_000

# Field sizes (bytes) of the two frame types
MNONCE_LEN = 2                     # manifest nonce, sent in the clear
BNONCE_LEN = 2                     # block nonce, masked inside the manifest
# K | R | pad length | bnonce | crc16 -- the ciphertext length is carried as a
# 3-bit pad length (ctlen = K*CHUNK - pad) rather than as a 16-bit number.
MANIFEST_PLAIN = 1 + 1 + 1 + BNONCE_LEN + 2                   # 7 bytes
MANIFEST_LEN = MNONCE_LEN + MANIFEST_PLAIN                    # 9 bytes
MANIFEST_BITS = MANIFEST_LEN * 8                              # 72
BLOCK_FRAME = 1 + CHUNK + 1        # idx | payload | crc8 = 10 bytes
FRAME_BITS = BLOCK_FRAME * 8       # 80

MAX_BLOCKS = 254                   # idx fits in one byte, 255 stays reserved

# --------------------------------------------------------- GF(256) arithmetic
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11d
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]

def gmul(a, b):
    return 0 if (a == 0 or b == 0) else _EXP[_LOG[a] + _LOG[b]]

def ginv(a):
    return _EXP[255 - _LOG[a]]

def cauchy(R, K):
    """Cauchy encoding matrix R x K -- every square submatrix is invertible (MDS)."""
    P = []
    for r in range(R):
        xr = 255 - r                       # xr != i guaranteed (see the encode limit)
        P.append([ginv(xr ^ i) for i in range(K)])
    return P

def _unit(i, n):
    row = [0] * n
    row[i] = 1
    return row

def mat_inv(M, n):
    """GF(256) matrix inverse via Gauss-Jordan; None if singular."""
    A = [list(row) for row in M]
    I = [[1 if i == j else 0 for j in range(n)] for i in range(n)]
    for c in range(n):
        p = c
        while p < n and A[p][c] == 0:
            p += 1
        if p == n:
            return None
        if p != c:
            A[p], A[c] = A[c], A[p]
            I[p], I[c] = I[c], I[p]
        inv = ginv(A[c][c])
        A[c] = [gmul(v, inv) for v in A[c]]
        I[c] = [gmul(v, inv) for v in I[c]]
        for r in range(n):
            if r == c:
                continue
            f = A[r][c]
            if f == 0:
                continue
            A[r] = [A[r][j] ^ gmul(f, A[c][j]) for j in range(n)]
            I[r] = [I[r][j] ^ gmul(f, I[c][j]) for j in range(n)]
    return I

# --------------------------------------------------------- bit helpers + CRC
def bytes_to_bits(bs):
    bits = []
    for b in bs:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits):
    out = bytearray(len(bits) // 8)
    for i in range(len(out)):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i * 8 + j]
        out[i] = v
    return bytes(out)

def crc16(bs):
    """CRC-16-CCITT (0x1021, init 0xFFFF, no reflection) -- exactly as in the GUI."""
    c = 0xffff
    for b in bs:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xffff if (c & 0x8000) else (c << 1) & 0xffff
    return c & 0xffff

# --------------------------------------------------------- grammars DE/EN
# Word lists are ordered by how ordinary the word is; a level uses the PREFIX of
# length 2^k (8/16/32 -> 3/4/5 bits).  Level 0 therefore only ever sees the most
# common, least remarkable words, level 3 the whole list.
# Nouns carry their article; the slots b1/b2 render the bare form (everything
# after the first space) for the telegraphic style.
# MUST stay identical to POOLS/TEMPLATES in cover_studio.html.
POOLS = {
    "de": {
        "N1": ["das wetter", "das signal", "das band", "der funk",
               "der kaffee", "der garten", "die antenne", "der verkehr",
               "das licht", "der himmel", "das radio", "das netz",
               "der wind", "das dach", "der markt", "der weg",
               "der zug", "der hof", "der ofen", "der keller",
               "der boden", "der strom", "der nebel", "der regen",
               "der frost", "der mond", "das feld", "das ufer",
               "das tal", "der teich", "die halle", "die kueche"],
        "N2": ["der plan", "der nachbar", "der kollege", "der empfang",
               "der turm", "der draht", "die huette", "die leitung",
               "der schuppen", "der zaun", "der schalter", "die kiste",
               "die lampe", "der schlauch", "der eimer", "der korb",
               "der stecker", "die kette", "der riegel", "der deckel",
               "die schaufel", "der hammer", "die leiter", "der pfosten",
               "der bogen", "die schiene", "der knoten", "der rahmen",
               "die klappe", "der spiegel", "die tuer", "der kasten"],
        "A1": ["gut", "fein", "mau", "stark", "ruhig", "laut", "stetig", "klar",
               "matt", "zaeh", "frisch", "flach", "dicht", "fest", "mild", "rau",
               "schwach", "hart", "weich", "glatt", "steil", "eng", "breit", "tief",
               "hoch", "kurz", "lang", "dumpf", "spitz", "grob", "zart", "schroff"],
        "A2": ["warm", "kuehl", "still", "windig", "hell", "trueb", "trocken", "feucht",
               "sonnig", "wolkig", "kalt", "lau", "diesig", "klamm", "schwuel", "frostig"],
        "A3": ["bereit", "spaet", "nah", "fertig", "offen", "langsam", "knapp", "leer",
               "voll", "frei", "sicher", "locker", "straff", "schief", "gerade", "sauber",
               "neu", "alt", "heil", "krumm", "rund", "eckig", "leicht", "schwer",
               "hohl", "massiv", "roh", "blank", "glatt", "stumpf", "warm", "kalt"],
        "END": ["hier", "jetzt", "wieder", "noch", "heute", "gleich", "spaeter", "morgen",
                "abends", "nachts", "drinnen", "draussen", "oben", "unten", "vorn", "hinten"],
        "ADV2": ["gleich", "spaeter", "heute", "morgen", "abends", "nachts", "frueh", "bald",
                 "jetzt", "dann", "kurz", "lange", "oft", "selten", "immer", "nie"],
    },
    "en": {
        "N1": ["the weather", "the signal", "the band", "the rig",
               "the coffee", "the garden", "the antenna", "the traffic",
               "the light", "the sky", "the radio", "the net",
               "the wind", "the roof", "the market", "the path",
               "the train", "the yard", "the stove", "the cellar",
               "the floor", "the power", "the fog", "the rain",
               "the frost", "the moon", "the field", "the shore",
               "the valley", "the pond", "the hall", "the kitchen"],
        "N2": ["the plan", "the neighbour", "the colleague", "the reception",
               "the tower", "the wire", "the shack", "the line",
               "the shed", "the fence", "the switch", "the crate",
               "the lamp", "the hose", "the bucket", "the basket",
               "the plug", "the chain", "the latch", "the lid",
               "the shovel", "the hammer", "the ladder", "the post",
               "the arch", "the rail", "the knot", "the frame",
               "the flap", "the mirror", "the door", "the box"],
        "A1": ["good", "fine", "poor", "strong", "quiet", "noisy", "steady", "clear",
               "dull", "tough", "fresh", "flat", "dense", "firm", "mild", "rough",
               "weak", "hard", "soft", "smooth", "steep", "narrow", "wide", "deep",
               "high", "short", "long", "muffled", "sharp", "coarse", "tender", "harsh"],
        "A2": ["warm", "cool", "calm", "windy", "bright", "cloudy", "dry", "damp",
               "sunny", "overcast", "cold", "mellow", "hazy", "clammy", "muggy", "frosty"],
        "A3": ["ready", "late", "close", "set", "open", "slow", "tight", "empty",
               "full", "free", "safe", "loose", "taut", "crooked", "straight", "clean",
               "new", "old", "whole", "bent", "round", "square", "light", "heavy",
               "hollow", "solid", "raw", "plain", "smooth", "blunt", "warm", "cold"],
        "END": ["here", "now", "again", "still", "today", "soon", "later", "tomorrow",
                "tonight", "outside", "inside", "upstairs", "downstairs", "ahead",
                "behind", "nearby"],
        "ADV2": ["soon", "later", "today", "tomorrow", "tonight", "overnight", "early",
                 "shortly", "now", "then", "briefly", "long", "often", "rarely",
                 "always", "never"],
    },
}

# Slot name -> word list.  A "b" prefix renders the form without its article.
SLOT_POOL = {"n1": "N1", "b1": "N1", "n2": "N2", "b2": "N2",
             "a1": "A1", "a2": "A2", "a3": "A3", "end": "END", "adv2": "ADV2"}

# {slot:count} -- count is the prefix length used and must be a power of two.
# Templates contain NO punctuation at all: every character has to survive the
# transport untouched, and a comma is exactly the kind of thing a radio or chat
# path quietly drops or substitutes.  Letters and single spaces only.
# Each level offers SEVERAL sentence shapes of identical word count and
# identical bit width.  Which one is used is itself part of the payload, so the
# variety is free -- it adds log2(count) bits per sentence rather than costing
# anything.  Without this every line of a long cover had the same shape, which
# is what gives a text cover away to a human reader faster than anything else.
# Shapes at one level must be mutually exclusive; the selftest checks that.
TEMPLATES = {
    "de": [
        ["{n1:16} ist {a1:8} {end:8}",                                   # 10+1 bits
         "{end:8} ist {n1:16} {a1:8}"],
        ["{n1:32} ist {a1:16} {end:16}",                                 # 13+1 bits
         "{end:16} ist {n1:32} {a1:16}"],
        ["{n1:32} ist {a1:32} und {n2:32} {a3:32}",                      # 20+1 bits
         "{n2:32} ist {a3:32} und {n1:32} {a1:32}"],
        ["{b1:32} {a1:32} {b2:32} {a3:32} {adv2:16} {a2:16}",            # 28+1 bits
         "{adv2:16} {a2:16} {b2:32} {a3:32} {b1:32} {a1:32}"],
    ],
    "en": [
        ["{n1:16} is {a1:8} {end:8}",
         "{end:8} {n1:16} is {a1:8}"],
        ["{n1:32} is {a1:16} {end:16}",
         "{end:16} {n1:32} is {a1:16}"],
        ["{n1:32} is {a1:32} and {n2:32} {a3:32}",
         "{n2:32} is {a3:32} and {n1:32} {a1:32}"],
        ["{b1:32} {a1:32} {b2:32} {a3:32} {adv2:16} {a2:16}",
         "{adv2:16} {a2:16} {b2:32} {a3:32} {b1:32} {a1:32}"],
    ],
}

_SLOT_RE = re.compile(r"\{(\w+):(\d+)\}")

def _build_shape(lang, tpl):
    pools = POOLS[lang]
    slots, bits = [], 0
    pat, last = "", 0
    for m in _SLOT_RE.finditer(tpl):
        name, cnt = m.group(1), int(m.group(2))
        opts = list(pools[SLOT_POOL[name]][:cnt])
        if len(opts) != cnt or cnt & (cnt - 1):
            raise ValueError(f"word list {name}:{cnt} ({lang}) unusable")
        if name.startswith("b"):
            opts = [w.split(" ", 1)[1] for w in opts]
        if len(set(opts)) != cnt:
            raise ValueError(f"word list {name}:{cnt} ({lang}) has duplicates")
        width = cnt.bit_length() - 1
        slots.append({"opts": opts, "width": width})
        bits += width
        pat += re.escape(tpl[last:m.start()])
        # longest alternative first -> no premature partial match
        alts = sorted(opts, key=len, reverse=True)
        pat += "(" + "|".join(re.escape(w) for w in alts) + ")"
        last = m.end()
    pat += re.escape(tpl[last:])
    return {"tpl": tpl, "slots": slots, "bits": bits,
            "re": re.compile("^" + pat + "$")}

def _build(lang):
    out = []
    for variants in TEMPLATES[lang]:
        n = len(variants)
        if n & (n - 1):
            raise ValueError(f"{lang}: sentence shapes per level must be a power of two")
        sel = n.bit_length() - 1
        shapes = [_build_shape(lang, v) for v in variants]
        base = {s["bits"] for s in shapes}
        if len(base) != 1:
            raise ValueError(f"{lang}: sentence shapes of one level must carry "
                             f"the same number of bits, got {sorted(base)}")
        # Every shape has a fixed word count, and all shapes of a level must
        # agree on it -- that is what lets the decoder work on a stream of words
        # instead of on lines.
        toks = {len(_render_shape(s, [0] * s["bits"]).split()) for s in shapes}
        if len(toks) != 1:
            raise ValueError(f"{lang}: sentence shapes of one level must have "
                             f"the same word count, got {sorted(toks)}")
        out.append({"shapes": shapes, "sel": sel, "bits": sel + base.pop(),
                    "tokens": toks.pop()})
    return out

def _render_shape(shape, bits):
    idx = 0
    words = []
    for s in shape["slots"]:
        v = 0
        for _ in range(s["width"]):
            v = (v << 1) | bits[idx]
            idx += 1
        words.append(s["opts"][v])
    it = iter(words)
    return _SLOT_RE.sub(lambda m: next(it), shape["tpl"])

def render_sentence(lv, bits):
    """The leading bits pick the sentence shape, the rest fill its slots."""
    sel = 0
    for i in range(lv["sel"]):
        sel = (sel << 1) | bits[i]
    return _render_shape(lv["shapes"][sel], bits[lv["sel"]:])

# A client may prefix a line with a callsign ("KN4CRD: ") or a quote marker
# ("> ").  Cover sentences never contain ":" or ">", so stripping such a prefix
# can never damage a genuine sentence.
_PREFIX_RE = re.compile(r"^[>\s]*(?:[a-z0-9/\-]{1,12}\s*[:>]\s*)?")
_PUNCT_RE = re.compile(r"[.!?,;:\"'()\[\]<>_*]+")

def clean_line(line):
    """Fold away what a transport typically changes: casing, a leading callsign
    or quote marker, punctuation of any kind, and runs of whitespace.  The
    grammar emits none of that, so removing it can never destroy information."""
    s = _PREFIX_RE.sub("", line.strip().lower())
    return re.sub(r"\s+", " ", _PUNCT_RE.sub(" ", s)).strip()

def _match(lv, s):
    """Which shape does this sentence have, and what bits does it carry?"""
    for k, shape in enumerate(lv["shapes"]):
        m = shape["re"].match(s)
        if not m:
            continue
        bits = [(k >> b) & 1 for b in range(lv["sel"] - 1, -1, -1)]
        for i, sl in enumerate(shape["slots"]):
            v = sl["opts"].index(m.group(i + 1))
            for b in range(sl["width"] - 1, -1, -1):
                bits.append((v >> b) & 1)
        return bits
    return None

def parse_sentence(lv, line):
    return _match(lv, clean_line(line))

def parse_at(lv, toks, pos):
    """Try to read one sentence out of the word stream starting at pos."""
    n = lv["tokens"]
    if pos + n > len(toks):
        return None
    return _match(lv, " ".join(toks[pos:pos + n]))

# _build needs render_sentence to measure each template's word count, so the
# grammars are built here rather than next to _build.
GRAMMARS = {"de": _build("de"), "en": _build("en")}
LEVELS = range(len(TEMPLATES["de"]))

# --------------------------------------------------------- crypto
MIN_PASS_LEN = 12          # refused outright below this
GOOD_PASS_LEN = 20         # what we actually recommend

def rate_passphrase(p):
    """A deliberately conservative judgement.  No meter can tell whether YOU
    chose a passphrase at random, so this only reports what is checkable:
    length, variety, and whether it looks like a single word.  Returns
    (verdict, note) with verdict in "reject" / "weak" / "ok" / "good"."""
    n = len(p)
    if n < MIN_PASS_LEN:
        return ("reject", f"Too short: {n} of at least {MIN_PASS_LEN} characters. "
                          f"Everything this tool protects rests on this one string.")
    words = [w for w in re.split(r"[^0-9A-Za-z\u00c0-\u024f]+", p) if w]
    uniq = len(set(p.lower()))
    if len(words) <= 1 and n < GOOD_PASS_LEN:
        return ("weak", "Looks like a single word. Four or five unrelated words "
                        "are far harder to guess than one long one.")
    if uniq < 6:
        return ("weak", f"Only {uniq} different characters -- repetition adds "
                        f"length but almost no guesswork.")
    if n < GOOD_PASS_LEN and len(words) < 4:
        return ("ok", f"Usable, but {GOOD_PASS_LEN}+ characters or four or more "
                      f"unrelated words would be markedly better.")
    return ("good", "")

def derive_key(passphrase):
    raw = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
                              PBKDF2_SALT, PBKDF2_ITERS, 32)
    return {"raw": raw, "aes": AESGCM(raw)}

def encrypt_msg(secret, key):
    """deflate costs 6 bytes of framing, which a short message never earns back
    -- so take whichever is smaller and record which in the manifest."""
    plain = secret.encode("utf-8")
    packed = zlib.compress(plain, 9)
    comp = len(packed) < len(plain)
    iv = os.urandom(12)
    body = key["aes"].encrypt(iv, packed if comp else plain, None)  # ct + 16-byte tag
    return iv + body, comp

def decrypt_msg(ct, key, comp):
    iv, body = ct[:12], ct[12:]
    plain = key["aes"].decrypt(iv, body, None)
    return (zlib.decompress(plain) if comp else plain).decode("utf-8")

def _ks(raw, tag, extra, nbytes):
    """SHA-256 keystream:  seed = raw || tag(2) || extra || counter."""
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(raw + tag + bytes(extra) + bytes([ctr & 0xff])).digest()
        ctr += 1
    return bytes(out[:nbytes])

def ks_manifest(raw, mnonce, n):
    return _ks(raw, b"SM", mnonce, n)

def ks_block(raw, bnonce, n):
    """Masks the 10-byte block frame.  Deliberately does NOT depend on the
    block index -- that sits inside the frame and is unknown while decoding."""
    return _ks(raw, b"SB", bnonce, n)

def ks_pad(raw, bnonce, idx, n):
    """Padding bits at the end of a sentence run; different per block and
    ignored while decoding."""
    return _ks(raw, b"SP", bytes(bnonce) + bytes([idx & 0xff]), n)

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# --------------------------------------------------------- frames
def build_manifest(raw, K, R, ctlen, bnonce, mnonce, comp):
    plain = bytes([K, R, ((K * CHUNK - ctlen) & 0x07) | (0x08 if comp else 0)]) + bytes(bnonce)
    c = crc16(plain)
    plain += bytes([(c >> 8) & 0xff, c & 0xff])
    return bytes(mnonce) + _xor(plain, ks_manifest(raw, mnonce, len(plain)))

def parse_manifest(raw, buf):
    if len(buf) < MANIFEST_LEN:
        return None
    mnonce = buf[:MNONCE_LEN]
    plain = _xor(buf[MNONCE_LEN:MANIFEST_LEN],
                 ks_manifest(raw, mnonce, MANIFEST_PLAIN))
    if crc16(plain[:-2]) != ((plain[-2] << 8) | plain[-1]):
        return None
    K, R, flags = plain[0], plain[1], plain[2]
    pad, comp = flags & 0x07, bool(flags & 0x08)
    bnonce = plain[3:3 + BNONCE_LEN]
    ctlen = K * CHUNK - pad
    if K == 0 or K + R > MAX_BLOCKS or (flags & 0xf0) or ctlen <= 0:
        return None
    return {"K": K, "R": R, "ctlen": ctlen, "bnonce": bnonce, "comp": comp}

def build_frame(raw, idx, payload, bnonce):
    ck = crc16(bytes([idx]) + payload) & 0xff
    plain = bytes([idx]) + payload + bytes([ck])
    return _xor(plain, ks_block(raw, bnonce, BLOCK_FRAME))

def parse_frame(raw, buf, bnonce):
    plain = _xor(buf[:BLOCK_FRAME], ks_block(raw, bnonce, BLOCK_FRAME))
    idx, payload, ck = plain[0], plain[1:1 + CHUNK], plain[-1]
    if (crc16(bytes([idx]) + payload) & 0xff) != ck:
        return None
    return idx, payload

def render_run(lv, frame, nbits, pad):
    """Bit field -> sentences; fill the last sentence's spare capacity from pad."""
    bits = bytes_to_bits(frame)[:nbits]
    n = math.ceil(nbits / lv["bits"])
    need = n * lv["bits"] - nbits
    if need > 0:
        bits = bits + bytes_to_bits(pad)[:need]
    return [render_sentence(lv, bits[i * lv["bits"]:(i + 1) * lv["bits"]])
            for i in range(n)]

def sentences_for(lv, nbits):
    return math.ceil(nbits / lv["bits"])

# --------------------------------------------------------- encode / decode
def apply_profile(txt, profile):
    """js8call = upper case (JS8Call's efficient character set), plain = lower
    case.  Casing carries no data; the decoder lower-cases everything anyway."""
    return txt.upper() if profile == "js8call" else txt.lower()

def encode(secret, key, lang="de", profile="plain", level=1, parity=2):
    raw = key["raw"]
    lv = GRAMMARS[lang][level]
    ct, comp = encrypt_msg(secret, key)
    ctlen = len(ct)
    padded = ct + b"\x00" * ((-ctlen) % CHUNK)
    K = len(padded) // CHUNK
    if K > MAX_BLOCKS:
        raise ValueError(f"Message too long -- {K} data blocks, the limit is "
                         f"{MAX_BLOCKS} (about {MAX_BLOCKS * CHUNK} bytes of ciphertext).")
    data = [padded[i * CHUNK:(i + 1) * CHUNK] for i in range(K)]
    R = min(parity, max(0, MAX_BLOCKS - K))
    parity_blocks = []
    if R > 0:
        P = cauchy(R, K)
        for r in range(R):
            pb = bytearray(CHUNK)
            for j in range(CHUNK):
                acc = 0
                for i in range(K):
                    acc ^= gmul(P[r][i], data[i][j])
                pb[j] = acc
            parity_blocks.append(bytes(pb))
    allb = data + parity_blocks
    tot = len(allb)

    bnonce = os.urandom(BNONCE_LEN)
    pad_bytes = math.ceil(lv["bits"] / 8) + 1

    def manifest_section():
        mnonce = os.urandom(MNONCE_LEN)
        buf = build_manifest(raw, K, R, ctlen, bnonce, mnonce, comp)
        pad = ks_pad(raw, bnonce, 0xff, pad_bytes)
        return {"lines": render_run(lv, buf, MANIFEST_BITS, pad)}

    sections = [manifest_section()]
    for i in range(tot):
        buf = build_frame(raw, i, allb[i], bnonce)
        pad = ks_pad(raw, bnonce, i, pad_bytes)
        sections.append({"lines": render_run(lv, buf, FRAME_BITS, pad), "block": i})
    sections.append(manifest_section())

    return {"sections": sections, "K": K, "R": R, "tot": tot,
            "ctlen": ctlen, "level": level, "lang": lang, "profile": profile}

def cover_to_text(enc, sections=None):
    """Cover as text -- nothing but carrier sentences, no framing lines of any
    kind.  The profile only decides the casing: js8call sends upper case (that
    is the character set JS8Call transmits most efficiently), plain sends lower
    case so it reads like an ordinary chat message.  Never put a callsign in
    here yourself: JS8Call prefixes your own callsign automatically, and
    transmitting one that is not yours is illegal."""
    parts = []
    for s in (sections if sections is not None else enc["sections"]):
        parts += [apply_profile(l, enc["profile"]) for l in s["lines"]]
    return "\n".join(parts)

def _tokens(cover_text):
    """The whole cover as one stream of words.  Line breaks carry no
    information, so a transport that reflows, wraps or joins lines cannot
    hurt -- the sentences are recovered from the word sequence alone."""
    toks = []
    for l in cover_text.splitlines():
        if not l.strip():
            continue
        s = clean_line(l)
        if s:
            toks.extend(s.split(" "))
    return toks

def _foreign_chars(cover_text):
    """Characters the grammar never produces.  Their presence means the text was
    altered on the way -- the most common reason decoding fails, and one that
    otherwise looks exactly like a wrong passphrase."""
    seen = set()
    for l in cover_text.splitlines():
        if not l.strip():
            continue
        s = _PREFIX_RE.sub("", l.strip().lower())
        seen.update(c for c in s if not (c == " " or ("a" <= c <= "z")))
    return sorted(seen)

def _read_run(lv, toks, pos, n_sent):
    """Read n_sent consecutive sentences from the word stream at pos."""
    bits = []
    step = lv["tokens"]
    for s in range(n_sent):
        pb = parse_at(lv, toks, pos + s * step)
        if pb is None:
            return None
        bits += pb
    return bits

def _find_manifest(raw, toks):
    """Tries every (language, level) and slides a window over the word stream;
    the manifest CRC16 decides.  Returns the manifest fields, the language, the
    level and the word ranges it occupies.  Sliding by a single word is what
    lets the decoder re-align after damage of any kind."""
    n = len(toks)
    for lang in ("de", "en"):
        for level in LEVELS:
            lv = GRAMMARS[lang][level]
            n_sent = sentences_for(lv, MANIFEST_BITS)
            span = n_sent * lv["tokens"]
            hit, spans = None, []
            i = 0
            while i + span <= n:
                bits = _read_run(lv, toks, i, n_sent)
                if bits is not None:
                    man = parse_manifest(raw, bits_to_bytes(bits[:MANIFEST_BITS]))
                    if man is not None:
                        if hit is None:
                            hit = man
                        spans.append((i, i + span))
                        i += span
                        continue
                i += 1
            if hit is not None:
                return hit, lang, level, spans
    return None, None, None, []

def decode(cover_text, key):
    raw = key["raw"]
    toks = _tokens(cover_text)
    foreign = _foreign_chars(cover_text)
    warning = None
    if foreign:
        warning = ("The text contains characters this tool never produces ("
                   + " ".join(foreign) + ") -- something on the transport path "
                   "altered it. Trailing punctuation is tolerated; anything else "
                   "costs the affected block.")
    man, lang, level, spans = _find_manifest(raw, toks)
    if man is None:
        if foreign:
            return {"ok": False, "warning": warning,
                    "error": "No valid manifest found. The text contains characters "
                             "this tool never produces (" + " ".join(foreign) + "), so "
                             "the transport path most likely altered it -- the "
                             "passphrase may well be fine."}
        return {"ok": False, "error": "No valid manifest found -- wrong passphrase, "
                                      "or this is not cover text."}
    K, R, ctlen, bnonce = man["K"], man["R"], man["ctlen"], man["bnonce"]
    comp = man["comp"]
    tot = K + R
    lv = GRAMMARS[lang][level]
    n_sent = sentences_for(lv, FRAME_BITS)
    span = n_sent * lv["tokens"]

    blocked = set()
    for a, b in spans:
        blocked.update(range(a, b))

    n = len(toks)
    found = {}
    i = 0
    while i + span <= n:
        if any(x in blocked for x in range(i, i + span)):
            i += 1
            continue
        bits = _read_run(lv, toks, i, n_sent)
        if bits is not None:
            fr = parse_frame(raw, bits_to_bytes(bits[:FRAME_BITS]), bnonce)
            if fr is not None and fr[0] < tot and fr[0] not in found:
                found[fr[0]] = fr[1]
                i += span
                continue
        i += 1

    data_missing = [d for d in range(K) if d not in found]
    present = sorted(found.keys())

    if not data_missing:
        data_blocks = [found[d] for d in range(K)]
        recovered = False
    elif len(present) >= K:
        P = cauchy(R, K)
        surv = present[:K]
        A = [_unit(idx, K) if idx < K else list(P[idx - K]) for idx in surv]
        Ainv = mat_inv(A, K)
        if Ainv is None:
            return {"ok": False, "missing": data_missing, "tot": tot, "K": K,
                    "recovered": False, "error": "Reconstruction failed."}
        data_blocks = [bytearray(CHUNK) for _ in range(K)]
        for j in range(CHUNK):
            rhs = [found[idx][j] for idx in surv]
            for d in range(K):
                acc = 0
                for m in range(K):
                    acc ^= gmul(Ainv[d][m], rhs[m])
                data_blocks[d][j] = acc
        data_blocks = [bytes(b) for b in data_blocks]
        recovered = True
    else:
        return {"ok": False, "missing": data_missing, "tot": tot, "K": K,
                "recovered": False, "warning": warning}

    ct = b"".join(data_blocks)[:ctlen]
    try:
        msg = decrypt_msg(ct, key, comp)
        return {"ok": True, "message": msg, "tot": tot, "K": K,
                "recovered": recovered, "R": R, "lang": lang, "level": level,
                "warning": warning}
    except Exception:
        return {"ok": False, "tot": tot, "K": K, "warning": warning,
                "error": "Decryption failed -- wrong passphrase, or too many "
                         "damaged blocks."}

def nack_string(res):
    if not res.get("missing"):
        return None
    return ", ".join(str(i) for i in res["missing"]) + f" of {res['tot']}"

# --------------------------------------------------------- selftest
def _selftest():
    key = derive_key("test-passphrase")
    ok_all = True
    for lang, level, par, profile in [("de", 1, 2, "js8call"), ("en", 0, 2, "plain"),
                                      ("de", 3, 1, "plain"), ("en", 2, 2, "js8call")]:
        secret = f"Meet Sunday 6pm at the old harbour -- {lang}/{level}"
        enc = encode(secret, key, lang=lang, profile=profile, level=level, parity=par)
        cover = cover_to_text(enc)
        r0 = decode(cover, key)
        clean = r0.get("ok") and r0.get("message") == secret
        det = (r0.get("lang") == lang and r0.get("level") == level)
        print(f"[{lang} L{level} P{par} {profile}] clean: {r0.get('ok')} "
              f"-> {'MATCH' if clean else 'MISMATCH'}"
              f"  detected: {r0.get('lang')}/L{r0.get('level')} {'OK' if det else 'WRONG'}")
        ok_all &= bool(clean and det)

        # drop par data blocks -> recovered via parity, no resend needed
        keep = [s for s in enc["sections"] if s.get("block") is None or s["block"] >= par]
        r1 = decode(cover_to_text(enc, keep), key)
        via = r1.get("ok") and r1.get("recovered") and r1.get("message") == secret
        print(f"   {par} blocks dropped -> ok: {r1.get('ok')} via_parity: {r1.get('recovered')} "
              f"msg: {'MATCH' if via else r1.get('error') or 'MISMATCH'}")
        ok_all &= bool(via)

        # drop par+1 -> NACK
        keep2 = [s for s in enc["sections"] if s.get("block") is None or s["block"] >= par + 1]
        r2 = decode(cover_to_text(enc, keep2), key)
        print(f"   {par+1} blocks dropped -> ok: {r2.get('ok')} nack: {nack_string(r2)}")
        ok_all &= (not r2.get("ok")) and bool(r2.get("missing"))

        # drop the leading manifest -> the trailing one must take over
        keep3 = enc["sections"][1:]
        r3 = decode(cover_to_text(enc, keep3), key)
        man_ok = r3.get("ok") and r3.get("message") == secret
        print(f"   leading manifest dropped -> ok: {r3.get('ok')} "
              f"msg: {'MATCH' if man_ok else r3.get('error') or 'MISMATCH'}")
        ok_all &= bool(man_ok)

        # delete a single sentence in the middle -> resync + erasure
        raw_lines = cover_to_text(enc).split("\n")
        cut = len(raw_lines) // 2
        del raw_lines[cut]
        r4 = decode("\n".join(raw_lines), key)
        print(f"   1 sentence deleted -> ok: {r4.get('ok')} "
              f"msg: {'MATCH' if r4.get('message') == secret else r4.get('error') or 'NACK'}")
        ok_all &= bool(r4.get("ok") and r4.get("message") == secret)

    # a mangled transport: callsign prefix, trailing punctuation, doubled spaces
    enc = encode("Meet at six", key, lang="en", level=2, parity=2)
    mangled = "\n".join("KN4CRD: " + l.replace(" ", "  ") + "!"
                        for l in cover_to_text(enc).split("\n"))
    r6 = decode(mangled, key)
    print(f"[mangled transport] ok: {r6.get('ok')} "
          f"msg: {'MATCH' if r6.get('message') == 'Meet at six' else 'MISMATCH'} "
          f"warned: {bool(r6.get('warning'))}")
    ok_all &= bool(r6.get("ok") and r6.get("message") == "Meet at six" and r6.get("warning"))

    # every sentence must match exactly one shape, or decoding is a coin flip
    import random
    amb = []
    for lang in ("de", "en"):
        for level, lv in enumerate(GRAMMARS[lang]):
            for _ in range(400):
                bits = [random.randint(0, 1) for _ in range(lv["bits"])]
                s = render_sentence(lv, bits)
                hits = sum(1 for sh in lv["shapes"] if sh["re"].match(s))
                if hits != 1 or _match(lv, s) != bits:
                    amb.append(f"{lang} L{level}: {s!r} matched {hits}")
                    break
    print(f"[sentence shapes] unambiguous and reversible: "
          f"{'yes' if not amb else 'NO -- ' + '; '.join(amb)}")
    ok_all &= not amb

    # deflate must never make the ciphertext bigger than the raw message
    for probe in ("hi", "Meet at six", "Treffen Sonntag 18 Uhr am alten Hafen",
                  "Treffen Sonntag 18 Uhr am alten Hafen. " * 20):
        e = encode(probe, key, lang="en", level=1, parity=2)
        r = decode(cover_to_text(e), key)
        if r.get("message") != probe:
            print(f"[compression] FAILED for {len(probe)} chars")
            ok_all = False
            break
    else:
        print("[compression] raw/deflate choice round-trips at every length")

    # a transport that reflows, joins or wraps lines must not matter at all
    import textwrap
    flat = " ".join(cover_to_text(enc).split("\n"))
    reflow = {"one line": flat,
              "wrapped at 40": textwrap.fill(flat, 40),
              "wrapped at 200": textwrap.fill(flat, 200),
              "blank lines": "\n\n".join(textwrap.wrap(flat, 120))}
    bad = [n for n, txt in reflow.items()
           if decode(txt, key).get("message") != "Meet at six"]
    print(f"[reflowed lines] {len(reflow) - len(bad)}/{len(reflow)} ok"
          + (f" -- FAILED: {bad}" if bad else ""))
    ok_all &= not bad

    # a clean cover must NOT be flagged
    r7 = decode(cover_to_text(enc), key)
    print(f"[clean cover] ok: {r7.get('ok')} warned: {bool(r7.get('warning'))} "
          f"-> {'OK' if r7.get('ok') and not r7.get('warning') else 'FAILURE'}")
    ok_all &= bool(r7.get("ok") and not r7.get("warning"))

    # a wrong passphrase must not get through
    enc = encode("secret", key, lang="de", level=1, parity=2)
    r5 = decode(cover_to_text(enc), derive_key("wrong"))
    print(f"[wrong passphrase] ok: {r5.get('ok')} -> {'correctly rejected' if not r5.get('ok') else 'FAILURE'}")
    ok_all &= (not r5.get("ok"))

    print("selftest done:", "ALL GREEN" if ok_all else "FAILURE")
    return ok_all

# --------------------------------------------------------- CLI
def _main():
    ap = argparse.ArgumentParser(description="StegoComm v4 -- byte-compatible with cover_studio.html")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encode", help="plaintext -> cover (stdout)")
    pe.add_argument("message", nargs="*", help="message (otherwise read from stdin)")
    pe.add_argument("--pass", dest="passphrase", required=True)
    pe.add_argument("--lang", choices=["de", "en"], default="de")
    pe.add_argument("--level", type=int, default=1, choices=[0, 1, 2, 3],
                    help="0=very believable ... 3=very terse")
    pe.add_argument("--parity", type=int, default=2)
    pe.add_argument("--allow-weak-pass", action="store_true",
                    help="encode even with a passphrase below the minimum length")
    pe.add_argument("--profile", choices=["js8call", "plain"], default="plain",
                    help="plain=lower case (default), js8call=upper case")

    pd = sub.add_parser("decode", help="cover (stdin) -> plaintext")
    pd.add_argument("--pass", dest="passphrase", required=True)

    sub.add_parser("selftest", help="check round-trip + parity + NACK")

    args = ap.parse_args()
    if args.cmd == "selftest":
        sys.exit(0 if _selftest() else 1)

    if args.cmd == "encode":
        verdict, note = rate_passphrase(args.passphrase)
        if verdict == "reject" and not args.allow_weak_pass:
            print("REFUSED: " + note, file=sys.stderr)
            print("A good passphrase is four or five unrelated words, e.g. "
                  "\"harbour-lantern-quiet-seven\". Pass --allow-weak-pass to "
                  "override.", file=sys.stderr)
            sys.exit(3)
        if note:
            print("WARNING: " + note, file=sys.stderr)

    key = derive_key(args.passphrase)
    if args.cmd == "encode":
        msg = " ".join(args.message) if args.message else sys.stdin.read().rstrip("\n")
        enc = encode(msg, key, lang=args.lang, profile=args.profile,
                     level=args.level, parity=args.parity)
        print(cover_to_text(enc))
    elif args.cmd == "decode":
        res = decode(sys.stdin.read(), key)
        if res.get("warning"):
            print("WARNING: " + res["warning"], file=sys.stderr)
        if res.get("ok"):
            tag = " [recovered via parity]" if res.get("recovered") else ""
            print(res["message"] + tag)
        elif res.get("missing"):
            print("NACK -- missing data blocks: " + (nack_string(res) or ""), file=sys.stderr)
            sys.exit(2)
        else:
            print("ERROR: " + res.get("error", "unknown"), file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    _main()
