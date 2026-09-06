"""
stegocomms.py -- Proof of Concept v4

Verdeckter, verschluesselter Nachrichtenkanal ueber beliebige Text-Transporte.
Diese Fassung ist BYTE-KOMPATIBEL zum Browser-Tool cover_studio.html:
im Browser erzeugter Cover laesst sich hier entschluesseln und umgekehrt.

Abhaengigkeiten:  pip install cryptography      (zlib/hashlib = Standardlib)

Pipeline (Sender):
  Klartext -> zlib(deflate) -> AES-256-GCM (iv||ciphertext||tag)
    -> auf CHUNK-Vielfaches (Null-)padden -> K Datenbloecke
    -> +R Cross-Block-Parity (Reed-Solomon ueber GF(256), Cauchy-Matrix -> MDS)
    -> je Block: idx || payload || CRC8, mit Keystream verschleiert
    -> Bits in Cover-Saetze (variable Dichte je "level")
    -> Rest-Bits mit schluesselabgeleitetem Zufalls-Padding gefuellt
Empfaenger geht rueckwaerts; per-Block-CRC erkennt beschaedigte Bloecke und
behandelt sie als Erasure -> bis zur Parity-Grenze OHNE Nachforderung
rekonstruiert, darueber ein NACK mit den fehlenden Datenbloecken.

NEU in v4 gegenueber v3
-----------------------
1. Kein Klartext-Header mehr.  v3 stellte jedem Block eine Zeile
   "DE W1ABC MSG 0/12 K 10 SZ 74 LV 0 CK 8" voran -- in einem Chat-Transport
   das mit Abstand auffaelligste Element des ganzen Covers.  In v4 stecken
   Blockindex und Block-CRC in den Satz-Bits, und die pro Nachricht
   konstanten Felder (K, R, Ciphertext-Laenge, Block-Nonce) liegen in einem
   MANIFEST, das selbst aus ganz normalen Cover-Saetzen besteht.  Ein Cover
   im Profil "plain" enthaelt damit ausschliesslich Chat-Saetze.
   Das Manifest ist mit einem schluesselabgeleiteten Keystream verschleiert;
   ohne Passphrase ist es von einem Nutzblock nicht zu unterscheiden.  Es
   wird zweimal gesendet (Anfang + Ende, mit verschiedenen Nonces und daher
   voellig verschiedenem Wortlaut), damit der Verlust einer Stelle nicht die
   ganze Nachricht unlesbar macht.
   Sprache und Stufe stehen NICHT im Manifest -- der Empfaenger probiert die
   8 Kombinationen durch, die CRC16 des Manifests entscheidet.

2. Dichte statt Laenge.  In v3 holten hoehere Stufen ihre Bits, indem sie
   Nebensaetze anhaengten: ein Nebensatz brachte ~5 Bit, kostete aber ~20
   Zeichen -- schlechter als der Grundsatz.  Dadurch sank die Dichte pro
   Zeichen mit steigender Stufe (0,31 -> 0,26 Bit/Zeichen) und "sehr knapp"
   erzeugte MEHR Zeichen als "sehr glaubhaft".  In v4 bleibt der Satz kurz
   und die Wortlisten werden breiter (8/16/32 Optionen = 3/4/5 Bit je Slot);
   Stufe 3 faellt zusaetzlich ins Telegrammstil ohne Artikel und Verb.
   Die Glaubhaftigkeit sinkt jetzt durch ungewoehnliche Wortwahl, nicht durch
   Laenge -- und die Zeichenzahl faellt monoton mit der Stufe.

3. Richtige Artikel im Deutschen ("der Kaffee", "die Antenne") statt des
   pauschalen "das" aus v3.

v3-Cover lassen sich mit v4 NICHT entschluesseln (anderes Wire-Format und
anderes PBKDF2-Salt).

Schluessel:  aus gemeinsamer Passphrase via PBKDF2-HMAC-SHA256
             (Salt "stegocomm/v4/pbkdf2", 200_000 Iterationen, 32 Byte).
             Beide Seiten muessen dieselbe Passphrase nutzen.
"""

import sys, os, re, math, zlib, hashlib, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK = 8            # Byte pro Block
BLOCK_BITS = CHUNK * 8   # 64
PBKDF2_SALT = b"stegocomm/v4/pbkdf2"
PBKDF2_ITERS = 200_000

# Feldgroessen (Byte) der beiden Rahmen-Typen
MNONCE_LEN = 2                     # Manifest-Nonce, im Klartext
BNONCE_LEN = 2                     # Block-Nonce, im Manifest verschleiert
# K | R | Padlaenge | bnonce | crc16 -- die Ciphertext-Laenge steckt als
# 3-Bit-Padlaenge drin (ctlen = K*CHUNK - pad) statt als 16-Bit-Zahl.
MANIFEST_PLAIN = 1 + 1 + 1 + BNONCE_LEN + 2                   # 7 Byte
MANIFEST_LEN = MNONCE_LEN + MANIFEST_PLAIN                    # 9 Byte
MANIFEST_BITS = MANIFEST_LEN * 8                              # 72
BLOCK_FRAME = 1 + CHUNK + 1        # idx | payload | crc8 = 10 Byte
FRAME_BITS = BLOCK_FRAME * 8       # 80

MAX_BLOCKS = 254                   # idx passt in 1 Byte, 255 bleibt frei

# --------------------------------------------------------- GF(256) Arithmetik
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
    """Cauchy-Kodiermatrix R x K -- jede quadratische Teilmatrix invertierbar (MDS)."""
    P = []
    for r in range(R):
        xr = 255 - r                       # xr != i garantiert (siehe encode-Grenze)
        P.append([ginv(xr ^ i) for i in range(K)])
    return P

def _unit(i, n):
    row = [0] * n
    row[i] = 1
    return row

def mat_inv(M, n):
    """GF(256)-Matrixinverse via Gauss-Jordan; None wenn singulaer."""
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

# --------------------------------------------------------- Bit-Helfer + CRC
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
    """CRC-16-CCITT (0x1021, init 0xFFFF, keine Reflection) -- exakt wie im GUI."""
    c = 0xffff
    for b in bs:
        c ^= b << 8
        for _ in range(8):
            c = ((c << 1) ^ 0x1021) & 0xffff if (c & 0x8000) else (c << 1) & 0xffff
    return c & 0xffff

# --------------------------------------------------------- Grammatiken DE/EN
# Wortlisten sind nach Gebraeuchlichkeit sortiert; eine Stufe nutzt jeweils das
# PRAEFIX der Laenge 2^k (8/16/32 -> 3/4/5 Bit).  Stufe 0 sieht also nur die
# haeufigsten, unauffaelligsten Woerter, Stufe 3 die ganze Liste.
# Nomen tragen ihren Artikel mit; die Slots b1/b2 rendern die blosse Form
# (alles nach dem ersten Leerzeichen) fuer den Telegrammstil.
# MUSS mit den POOLS/TEMPLATES in cover_studio.html identisch bleiben.
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

# Slot-Name -> Wortliste.  Ein "b"-Praefix rendert die artikellose Form.
SLOT_POOL = {"n1": "N1", "b1": "N1", "n2": "N2", "b2": "N2",
             "a1": "A1", "a2": "A2", "a3": "A3", "end": "END", "adv2": "ADV2"}

# {slot:anzahl} -- anzahl ist die genutzte Praefixlaenge und muss 2er-Potenz sein.
TEMPLATES = {
    "de": [
        "{n1:16} ist {a1:8} {end:8}",                                   # 10 Bit
        "{n1:32} ist {a1:16} {end:16}",                                 # 13 Bit
        "{n1:32} ist {a1:32}, {n2:32} {a3:32}",                         # 20 Bit
        "{b1:32} {a1:32}, {b2:32} {a3:32}, {adv2:16} {a2:16}",          # 28 Bit
    ],
    "en": [
        "{n1:16} is {a1:8} {end:8}",
        "{n1:32} is {a1:16} {end:16}",
        "{n1:32} is {a1:32}, {n2:32} {a3:32}",
        "{b1:32} {a1:32}, {b2:32} {a3:32}, {adv2:16} {a2:16}",
    ],
}

NAMES = ["W1ABC", "DL2XYZ", "OH5QQ", "VK3RT", "G0MNP"]

_SLOT_RE = re.compile(r"\{(\w+):(\d+)\}")

def _build(lang):
    pools = POOLS[lang]
    out = []
    for tpl in TEMPLATES[lang]:
        slots, bits = [], 0
        pat, last = "", 0
        for m in _SLOT_RE.finditer(tpl):
            name, cnt = m.group(1), int(m.group(2))
            opts = list(pools[SLOT_POOL[name]][:cnt])
            if len(opts) != cnt or cnt & (cnt - 1):
                raise ValueError(f"Wortliste {name}:{cnt} ({lang}) unbrauchbar")
            if name.startswith("b"):
                opts = [w.split(" ", 1)[1] for w in opts]
            if len(set(opts)) != cnt:
                raise ValueError(f"Wortliste {name}:{cnt} ({lang}) hat Duplikate")
            width = cnt.bit_length() - 1
            slots.append({"opts": opts, "width": width})
            bits += width
            pat += re.escape(tpl[last:m.start()])
            # laengste Alternative zuerst -> kein vorzeitiger Teiltreffer
            alts = sorted(opts, key=len, reverse=True)
            pat += "(" + "|".join(re.escape(w) for w in alts) + ")"
            last = m.end()
        pat += re.escape(tpl[last:])
        out.append({"tpl": tpl, "slots": slots, "bits": bits,
                    "re": re.compile("^" + pat + "$")})
    return out

GRAMMARS = {"de": _build("de"), "en": _build("en")}
LEVELS = range(len(TEMPLATES["de"]))

def render_sentence(lv, bits):
    idx = 0
    words = []
    for s in lv["slots"]:
        v = 0
        for _ in range(s["width"]):
            v = (v << 1) | bits[idx]
            idx += 1
        words.append(s["opts"][v])
    it = iter(words)
    return _SLOT_RE.sub(lambda m: next(it), lv["tpl"])

def parse_sentence(lv, line):
    s = re.sub(r"[.\s]+$", "", line.strip())
    m = lv["re"].match(s)
    if not m:
        return None
    bits = []
    for i, sl in enumerate(lv["slots"]):
        v = sl["opts"].index(m.group(i + 1))
        for b in range(sl["width"] - 1, -1, -1):
            bits.append((v >> b) & 1)
    return bits

# --------------------------------------------------------- Krypto
def derive_key(passphrase):
    raw = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"),
                              PBKDF2_SALT, PBKDF2_ITERS, 32)
    return {"raw": raw, "aes": AESGCM(raw)}

def encrypt_msg(secret, key):
    comp = zlib.compress(secret.encode("utf-8"), 9)
    iv = os.urandom(12)
    body = key["aes"].encrypt(iv, comp, None)     # ciphertext + 16-Byte-Tag
    return iv + body

def decrypt_msg(ct, key):
    iv, body = ct[:12], ct[12:]
    comp = key["aes"].decrypt(iv, body, None)
    return zlib.decompress(comp).decode("utf-8")

def _ks(raw, tag, extra, nbytes):
    """SHA-256-Keystream:  seed = raw || tag(2) || extra || counter."""
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        out += hashlib.sha256(raw + tag + bytes(extra) + bytes([ctr & 0xff])).digest()
        ctr += 1
    return bytes(out[:nbytes])

def ks_manifest(raw, mnonce, n):
    return _ks(raw, b"SM", mnonce, n)

def ks_block(raw, bnonce, n):
    """Verschleiert den 10-Byte-Blockrahmen.  Haengt bewusst NICHT vom
    Blockindex ab -- der steckt ja im Rahmen und ist beim Dekodieren
    zunaechst unbekannt."""
    return _ks(raw, b"SB", bnonce, n)

def ks_pad(raw, bnonce, idx, n):
    """Fuellbits am Satzende; pro Block verschieden, wird beim Dekodieren
    ignoriert."""
    return _ks(raw, b"SP", bytes(bnonce) + bytes([idx & 0xff]), n)

def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# --------------------------------------------------------- Rahmen
def build_manifest(raw, K, R, ctlen, bnonce, mnonce):
    plain = bytes([K, R, (K * CHUNK - ctlen) & 0x07]) + bytes(bnonce)
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
    K, R, pad = plain[0], plain[1], plain[2]
    bnonce = plain[3:3 + BNONCE_LEN]
    ctlen = K * CHUNK - pad
    if K == 0 or K + R > MAX_BLOCKS or pad > 7 or ctlen <= 0:
        return None
    return {"K": K, "R": R, "ctlen": ctlen, "bnonce": bnonce}

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
    """Bitfeld -> Saetze; Rest der letzten Satzkapazitaet mit pad auffuellen."""
    bits = bytes_to_bits(frame)[:nbits]
    n = math.ceil(nbits / lv["bits"])
    need = n * lv["bits"] - nbits
    if need > 0:
        bits = bits + bytes_to_bits(pad)[:need]
    return [render_sentence(lv, bits[i * lv["bits"]:(i + 1) * lv["bits"]])
            for i in range(n)]

def sentences_for(lv, nbits):
    return math.ceil(nbits / lv["bits"])

# --------------------------------------------------------- Encode / Decode
def apply_profile(txt, profile):
    return txt.upper() if profile == "js8call" else txt.lower()

def encode(secret, key, lang="de", profile="js8call", level=1, parity=2):
    raw = key["raw"]
    lv = GRAMMARS[lang][level]
    ct = encrypt_msg(secret, key)
    ctlen = len(ct)
    padded = ct + b"\x00" * ((-ctlen) % CHUNK)
    K = len(padded) // CHUNK
    if K > MAX_BLOCKS:
        raise ValueError(f"Nachricht zu lang -- {K} Datenbloecke, erlaubt sind "
                         f"{MAX_BLOCKS} (rund {MAX_BLOCKS * CHUNK} Byte Ciphertext).")
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
        buf = build_manifest(raw, K, R, ctlen, bnonce, mnonce)
        pad = ks_pad(raw, bnonce, 0xff, pad_bytes)
        return {"header": f"DE {NAMES[0]} CQ CQ",
                "lines": render_run(lv, buf, MANIFEST_BITS, pad)}

    sections = [manifest_section()]
    for i in range(tot):
        buf = build_frame(raw, i, allb[i], bnonce)
        pad = ks_pad(raw, bnonce, i, pad_bytes)
        sections.append({"header": f"DE {NAMES[i % len(NAMES)]} MSG {i}/{tot}",
                         "lines": render_run(lv, buf, FRAME_BITS, pad),
                         "block": i})
    sections.append(manifest_section())

    return {"sections": sections, "K": K, "R": R, "tot": tot,
            "ctlen": ctlen, "level": level, "lang": lang, "profile": profile}

def cover_to_text(enc, sections=None):
    """Cover als Text.  Im Profil js8call bekommt jeder Abschnitt eine
    dekorative Rufzeichen-Zeile -- sie traegt KEINE Daten und wird beim
    Dekodieren einfach uebersprungen.  Im Profil plain entfaellt sie, das
    Cover besteht dann ausschliesslich aus Chat-Saetzen."""
    parts = []
    for s in (sections if sections is not None else enc["sections"]):
        if enc["profile"] == "js8call" and s.get("header"):
            parts.append(apply_profile(s["header"], enc["profile"]))
        parts += [apply_profile(l, enc["profile"]) for l in s["lines"]]
    return "\n".join(parts)

def _norm_lines(cover_text):
    return [re.sub(r"[.\s]+$", "", l.strip().lower())
            for l in cover_text.splitlines() if l.strip()]

def _find_manifest(raw, lines):
    """Probiert alle (Sprache, Stufe) durch und schiebt ein Fenster ueber den
    Text; die CRC16 im Manifest entscheidet.  Liefert Manifest-Daten, Sprache,
    Stufe und die belegten Zeilenbereiche."""
    n = len(lines)
    for lang in ("de", "en"):
        for level in LEVELS:
            lv = GRAMMARS[lang][level]
            span = sentences_for(lv, MANIFEST_BITS)
            hit, spans = None, []
            i = 0
            while i + span <= n:
                bits, ok = [], True
                for s in range(span):
                    pb = parse_sentence(lv, lines[i + s])
                    if pb is None:
                        ok = False
                        break
                    bits += pb
                if ok:
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
    lines = _norm_lines(cover_text)
    man, lang, level, spans = _find_manifest(raw, lines)
    if man is None:
        return {"ok": False, "error": "Kein gueltiges Manifest gefunden -- "
                                      "falsche Passphrase oder kein Cover-Text."}
    K, R, ctlen, bnonce = man["K"], man["R"], man["ctlen"], man["bnonce"]
    tot = K + R
    lv = GRAMMARS[lang][level]
    span = sentences_for(lv, FRAME_BITS)

    blocked = set()
    for a, b in spans:
        blocked.update(range(a, b))

    n = len(lines)
    found = {}
    i = 0
    while i + span <= n:
        if i in blocked:
            i += 1
            continue
        bits, ok = [], True
        for s in range(span):
            if (i + s) in blocked:
                ok = False
                break
            pb = parse_sentence(lv, lines[i + s])
            if pb is None:
                ok = False
                break
            bits += pb
        if ok:
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
                    "recovered": False, "error": "Rekonstruktion fehlgeschlagen."}
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
                "recovered": False}

    ct = b"".join(data_blocks)[:ctlen]
    try:
        msg = decrypt_msg(ct, key)
        return {"ok": True, "message": msg, "tot": tot, "K": K,
                "recovered": recovered, "R": R, "lang": lang, "level": level}
    except Exception:
        return {"ok": False, "tot": tot, "K": K,
                "error": "Entschluesselung fehlgeschlagen -- falsche Passphrase "
                         "oder zu viele Datenfehler."}

def nack_string(res):
    if not res.get("missing"):
        return None
    return ", ".join(str(i) for i in res["missing"]) + f" von {res['tot']}"

# --------------------------------------------------------- Selbsttest
def _selftest():
    key = derive_key("test-passphrase")
    ok_all = True
    for lang, level, par, profile in [("de", 1, 2, "js8call"), ("en", 0, 2, "plain"),
                                      ("de", 3, 1, "plain"), ("en", 2, 2, "js8call")]:
        secret = f"Treffen Sonntag 18 Uhr am alten Hafen -- {lang}/{level}"
        enc = encode(secret, key, lang=lang, profile=profile, level=level, parity=par)
        cover = cover_to_text(enc)
        r0 = decode(cover, key)
        clean = r0.get("ok") and r0.get("message") == secret
        det = (r0.get("lang") == lang and r0.get("level") == level)
        print(f"[{lang} L{level} P{par} {profile}] sauber: {r0.get('ok')} "
              f"-> {'MATCH' if clean else 'MISMATCH'}"
              f"  erkannt: {r0.get('lang')}/L{r0.get('level')} {'OK' if det else 'FALSCH'}")
        ok_all &= bool(clean and det)

        # par Datenbloecke weg -> via Parity ohne Nachforderung
        keep = [s for s in enc["sections"] if s.get("block") is None or s["block"] >= par]
        r1 = decode(cover_to_text(enc, keep), key)
        via = r1.get("ok") and r1.get("recovered") and r1.get("message") == secret
        print(f"   {par} Bloecke weg -> ok: {r1.get('ok')} via_parity: {r1.get('recovered')} "
              f"msg: {'MATCH' if via else r1.get('error') or 'MISMATCH'}")
        ok_all &= bool(via)

        # par+1 weg -> NACK
        keep2 = [s for s in enc["sections"] if s.get("block") is None or s["block"] >= par + 1]
        r2 = decode(cover_to_text(enc, keep2), key)
        print(f"   {par+1} Bloecke weg -> ok: {r2.get('ok')} nack: {nack_string(r2)}")
        ok_all &= (not r2.get("ok")) and bool(r2.get("missing"))

        # vorderes Manifest weg -> hinteres muss uebernehmen
        keep3 = enc["sections"][1:]
        r3 = decode(cover_to_text(enc, keep3), key)
        man_ok = r3.get("ok") and r3.get("message") == secret
        print(f"   1. Manifest weg -> ok: {r3.get('ok')} "
              f"msg: {'MATCH' if man_ok else r3.get('error') or 'MISMATCH'}")
        ok_all &= bool(man_ok)

        # ein einzelner Satz mitten drin verstuemmelt -> Resync + Erasure
        raw_lines = cover_to_text(enc).split("\n")
        cut = len(raw_lines) // 2
        del raw_lines[cut]
        r4 = decode("\n".join(raw_lines), key)
        print(f"   1 Satz geloescht -> ok: {r4.get('ok')} "
              f"msg: {'MATCH' if r4.get('message') == secret else r4.get('error') or 'NACK'}")
        ok_all &= bool(r4.get("ok") and r4.get("message") == secret)

    # falsche Passphrase darf nicht durchgehen
    enc = encode("geheim", key, lang="de", level=1, parity=2)
    r5 = decode(cover_to_text(enc), derive_key("falsch"))
    print(f"[falsche Passphrase] ok: {r5.get('ok')} -> {'korrekt abgelehnt' if not r5.get('ok') else 'FEHLER'}")
    ok_all &= (not r5.get("ok"))

    print("selftest fertig:", "ALLES GRUEN" if ok_all else "FEHLER")
    return ok_all

# --------------------------------------------------------- CLI
def _main():
    ap = argparse.ArgumentParser(description="StegoComm v4 -- byte-kompatibel zu cover_studio.html")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pe = sub.add_parser("encode", help="Klartext -> Cover (stdout)")
    pe.add_argument("message", nargs="*", help="Nachricht (sonst von stdin)")
    pe.add_argument("--pass", dest="passphrase", required=True)
    pe.add_argument("--lang", choices=["de", "en"], default="de")
    pe.add_argument("--level", type=int, default=1, choices=[0, 1, 2, 3],
                    help="0=sehr glaubhaft ... 3=sehr knapp")
    pe.add_argument("--parity", type=int, default=2)
    pe.add_argument("--profile", choices=["js8call", "plain"], default="js8call")

    pd = sub.add_parser("decode", help="Cover (stdin) -> Klartext")
    pd.add_argument("--pass", dest="passphrase", required=True)

    sub.add_parser("selftest", help="Round-Trip + Parity + NACK pruefen")

    args = ap.parse_args()
    if args.cmd == "selftest":
        sys.exit(0 if _selftest() else 1)

    key = derive_key(args.passphrase)
    if args.cmd == "encode":
        msg = " ".join(args.message) if args.message else sys.stdin.read().rstrip("\n")
        enc = encode(msg, key, lang=args.lang, profile=args.profile,
                     level=args.level, parity=args.parity)
        print(cover_to_text(enc))
    elif args.cmd == "decode":
        res = decode(sys.stdin.read(), key)
        if res.get("ok"):
            tag = " [via Parity rekonstruiert]" if res.get("recovered") else ""
            print(res["message"] + tag)
        elif res.get("missing"):
            print("NACK -- fehlende Datenbloecke: " + (nack_string(res) or ""), file=sys.stderr)
            sys.exit(2)
        else:
            print("FEHLER: " + res.get("error", "unbekannt"), file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    _main()
