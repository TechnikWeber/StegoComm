"""
stegocomms.py -- Proof of Concept v3

Verdeckter, verschluesselter Nachrichtenkanal ueber beliebige Text-Transporte.
Diese Fassung ist BYTE-KOMPATIBEL zum Browser-Tool cover_studio.html:
im Browser erzeugter Cover laesst sich hier entschluesseln und umgekehrt.

Abhaengigkeiten:  pip install cryptography      (zlib/hashlib = Standardlib)

Pipeline (Sender):
  Klartext -> zlib(deflate) -> AES-256-GCM (iv||ciphertext||tag)
    -> auf CHUNK-Vielfaches (Null-)padden -> K Datenbloecke
    -> +R Cross-Block-Parity (Reed-Solomon ueber GF(256), Cauchy-Matrix -> MDS)
    -> Bits je Block in Cover-Saetze (variable Dichte je "level")
    -> Rest-Bits mit schluesselabgeleitetem Zufalls-Padding gefuellt
Empfaenger geht rueckwaerts; per-Block-CRC erkennt beschaedigte Bloecke und
behandelt sie als Erasure -> bis zur Parity-Grenze OHNE Nachforderung
rekonstruiert, darueber ein NACK mit den fehlenden Datenbloecken.

Schluessel:  aus gemeinsamer Passphrase via PBKDF2-HMAC-SHA256
             (Salt "stegocomm/v3/pbkdf2", 200_000 Iterationen, 32 Byte).
             Beide Seiten muessen dieselbe Passphrase nutzen.
"""

import sys, os, re, math, zlib, hashlib, argparse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK = 8            # Byte pro Block
BLOCK_BITS = CHUNK * 8   # 64
PBKDF2_SALT = b"stegocomm/v3/pbkdf2"
PBKDF2_ITERS = 200_000

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
# Jede Wortliste hat exakt 2/4/8 Eintraege -> 1/2/3 Bit, reversibel dekodierbar.
# MUSS mit den POOLS/TEMPLATES in cover_studio.html identisch bleiben.
POOLS = {
    "en": {
        "adv":  ["well", "so", "anyway", "also"],
        "noun": ["weather", "signal", "band", "rig", "coffee", "garden", "antenna", "traffic"],
        "adj":  ["good", "fine", "poor", "strong", "quiet", "noisy", "steady", "clear"],
        "adj2": ["warm", "cool", "calm", "windy", "bright", "cloudy", "dry", "damp"],
        "noun2":["news", "plan", "crew", "path", "gear", "tower", "wire", "shack"],
        "adj3": ["ready", "late", "close", "set", "open", "slow", "near", "short"],
        "adv2": ["today", "later", "soon", "yet"],
        "adj4": ["stable", "tough", "fresh", "flat", "light", "dense", "firm", "mild"],
        "end":  ["here", "now", "again", "still"],
    },
    "de": {
        "adv":  ["naja", "also", "tja", "ansonsten"],
        "noun": ["wetter", "signal", "band", "funk", "kaffee", "garten", "antenne", "verkehr"],
        "adj":  ["gut", "fein", "mau", "stark", "ruhig", "laut", "stetig", "klar"],
        "adj2": ["warm", "kuehl", "still", "windig", "hell", "trueb", "trocken", "feucht"],
        "noun2":["plan", "nachbar", "kollege", "weg", "empfang", "turm", "draht", "huette"],
        "adj3": ["bereit", "spaet", "nah", "fertig", "offen", "langsam", "knapp", "matt"],
        "adv2": ["heute", "spaeter", "gleich", "wohl"],
        "adj4": ["stabil", "zaeh", "frisch", "flach", "leicht", "dicht", "fest", "mild"],
        "end":  ["hier", "jetzt", "wieder", "noch"],
    },
}
TEMPLATES = {
    "en": [
        "the {noun} is {adj} {end}",
        "{adv} the {noun} is {adj} and {adj2} {end}",
        "{adv} the {noun} is {adj} and {adj2}, the {noun2} looks {adj3}",
        "{adv} the {noun} is {adj} and {adj2}, the {noun2} looks {adj3}, {adv2} it stays {adj4}",
    ],
    "de": [
        "das {noun} ist {adj} {end}",
        "{adv} das {noun} ist {adj} und {adj2} {end}",
        "{adv} das {noun} ist {adj} und {adj2}, der {noun2} wirkt {adj3}",
        "{adv} das {noun} ist {adj} und {adj2}, der {noun2} wirkt {adj3}, {adv2} bleibt es {adj4}",
    ],
}
NAMES = ["W1ABC", "DL2XYZ", "OH5QQ", "VK3RT", "G0MNP"]

_SLOT_RE = re.compile(r"\{(\w+)\}")

def _width(opts):
    return int(round(math.log2(len(opts))))

def _build(lang):
    pools = POOLS[lang]
    out = []
    for tpl in TEMPLATES[lang]:
        order = _SLOT_RE.findall(tpl)
        bits = sum(_width(pools[n]) for n in order)
        pat, last = "", 0
        for m in _SLOT_RE.finditer(tpl):
            pat += re.escape(tpl[last:m.start()])
            pat += "(" + "|".join(re.escape(w) for w in pools[m.group(1)]) + ")"
            last = m.end()
        pat += re.escape(tpl[last:])
        out.append({"tpl": tpl, "pools": pools, "order": order,
                    "bits": bits, "re": re.compile("^" + pat + "$")})
    return out

GRAMMARS = {"de": _build("de"), "en": _build("en")}

def render_sentence(lv, bits):
    idx = 0
    words = {}
    for name in lv["order"]:
        opts = lv["pools"][name]
        w = _width(opts)
        v = 0
        for _ in range(w):
            v = (v << 1) | bits[idx]
            idx += 1
        words[name] = opts[v]
    return _SLOT_RE.sub(lambda m: words[m.group(1)], lv["tpl"])

def parse_sentence(lv, line):
    s = re.sub(r"[.\s]+$", "", line.strip())
    m = lv["re"].match(s)
    if not m:
        return None
    bits = []
    for i, name in enumerate(lv["order"]):
        opts = lv["pools"][name]
        v = opts.index(m.group(i + 1))
        w = _width(opts)
        for b in range(w - 1, -1, -1):
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

def keystream(raw, idx, nbytes):
    out = bytearray()
    ctr = 0
    while len(out) < nbytes:
        seed = raw + bytes([0x50, 0x41, idx & 0xff, ctr & 0xff])   # "PA" + idx + ctr
        out += hashlib.sha256(seed).digest()
        ctr += 1
    return bytes(out[:nbytes])

# --------------------------------------------------------- Encode / Decode
def apply_profile(txt, profile):
    return txt.upper() if profile == "js8call" else txt.lower()

def render_block(idx, tot, K, ctlen, level, lang, data_bytes, raw):
    lv = GRAMMARS[lang][level]
    bits = bytes_to_bits(data_bytes)                       # 64
    s_per = math.ceil(BLOCK_BITS / lv["bits"])
    need = s_per * lv["bits"] - BLOCK_BITS
    if need > 0:
        ks = keystream(raw, idx, math.ceil(need / 8))
        bits += bytes_to_bits(ks)[:need]
    ck = crc16(data_bytes) & 0xff
    header = f"DE {NAMES[idx % len(NAMES)]} MSG {idx}/{tot} K {K} SZ {ctlen} LV {level} CK {ck}"
    lines = [render_sentence(lv, bits[i * lv["bits"]:(i + 1) * lv["bits"]]) for i in range(s_per)]
    return header, lines

def encode(secret, key, lang="de", profile="js8call", level=1, parity=2):
    ct = encrypt_msg(secret, key)
    ctlen = len(ct)
    padded = ct + b"\x00" * ((-ctlen) % CHUNK)
    K = len(padded) // CHUNK
    data = [padded[i * CHUNK:(i + 1) * CHUNK] for i in range(K)]
    R = min(parity, max(0, 255 - K))
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
    blocks = [render_block(i, tot, K, ctlen, level, lang, allb[i], key["raw"])
              for i in range(tot)]
    return {"blocks": blocks, "K": K, "R": R, "tot": tot,
            "ctlen": ctlen, "level": level, "lang": lang, "profile": profile}

def cover_to_text(enc):
    parts = []
    for header, lines in enc["blocks"]:
        parts.append(apply_profile(header, enc["profile"]))
        parts += [apply_profile(l, enc["profile"]) for l in lines]
    return "\n".join(parts)

HEADER_RE = re.compile(r"^de (\S+) msg (\d+)/(\d+) k (\d+) sz (\d+) lv (\d+) ck (\d+)$")

def decode(cover_text, key):
    lines = [re.sub(r"[.\s]+$", "", l.strip().lower())
             for l in cover_text.splitlines() if l.strip()]
    n = len(lines)
    i = 0
    tot = K = ctlen = None
    lang = None
    found = {}
    while i < n:
        mh = HEADER_RE.match(lines[i])
        if not mh:
            i += 1
            continue
        idx = int(mh.group(2)); tot = int(mh.group(3)); K = int(mh.group(4))
        ctlen = int(mh.group(5)); level = int(mh.group(6)); ck = int(mh.group(7))
        i += 1
        if lang is None:
            for L in ("de", "en"):
                lv = GRAMMARS[L][level] if level < len(GRAMMARS[L]) else None
                if lv and lv["re"].match(lines[i] if i < n else ""):
                    lang = L
                    break
        lv = GRAMMARS[lang][level] if lang is not None else None
        if lv is None:
            continue
        s_per = math.ceil(BLOCK_BITS / lv["bits"])
        bits, good = [], True
        for _ in range(s_per):
            pb = parse_sentence(lv, lines[i] if i < n else "")
            i += 1
            if pb is None:
                good = False
                break
            bits += pb
        if not good:
            continue
        bs = bits_to_bytes(bits[:BLOCK_BITS])
        if (crc16(bs) & 0xff) != ck:          # beschaedigt -> als Erasure behandeln
            continue
        found[idx] = bs
    if tot is None or K is None:
        return {"ok": False, "error": "Kein gueltiger Cover-Block erkannt."}

    R = tot - K
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
        return {"ok": False, "missing": data_missing, "tot": tot, "K": K, "recovered": False}

    ct = b"".join(data_blocks)[:ctlen]
    try:
        msg = decrypt_msg(ct, key)
        return {"ok": True, "message": msg, "tot": tot, "K": K, "recovered": recovered, "R": R}
    except Exception:
        return {"ok": False, "tot": tot, "K": K,
                "error": "Entschluesselung fehlgeschlagen -- falsche Passphrase oder zu viele Datenfehler."}

def nack_string(res):
    if not res.get("missing"):
        return None
    return ", ".join(str(i) for i in res["missing"]) + f" von {res['tot']}"

# --------------------------------------------------------- Selbsttest
def _selftest():
    key = derive_key("test-passphrase")
    ok_all = True
    for lang, level, par in [("de", 1, 2), ("en", 0, 2), ("de", 3, 1)]:
        secret = f"Treffen Sonntag 18 Uhr am alten Hafen -- {lang}/{level}"
        enc = encode(secret, key, lang=lang, profile="js8call", level=level, parity=par)
        cover = cover_to_text(enc)
        r0 = decode(cover, key)
        clean = r0.get("ok") and r0.get("message") == secret
        print(f"[{lang} L{level} P{par}] sauber: {r0.get('ok')} -> {'MATCH' if clean else 'MISMATCH'}")
        ok_all &= clean
        # Bloecke anhand Header gruppieren
        groups, cur = [], None
        for ln in cover.split("\n"):
            if re.match(r"^DE ", ln, re.I):
                if cur:
                    groups.append(cur)
                cur = [ln]
            elif cur:
                cur.append(ln)
        if cur:
            groups.append(cur)
        # par Bloecke weg -> via Parity
        lossy = "\n".join("\n".join(g) for gi, g in enumerate(groups) if gi >= par)
        r1 = decode(lossy, key)
        via = r1.get("ok") and r1.get("recovered") and r1.get("message") == secret
        print(f"   {par} Bloecke weg -> ok: {r1.get('ok')} via_parity: {r1.get('recovered')} "
              f"msg: {'MATCH' if via else r1.get('error') or 'MISMATCH'}")
        ok_all &= via
        # par+1 weg -> NACK
        lossy2 = "\n".join("\n".join(g) for gi, g in enumerate(groups) if gi >= par + 1)
        r2 = decode(lossy2, key)
        print(f"   {par+1} Bloecke weg -> ok: {r2.get('ok')} nack: {nack_string(r2)}")
        ok_all &= (not r2.get("ok"))
    print("selftest fertig:", "ALLES GRUEN" if ok_all else "FEHLER")
    return ok_all

# --------------------------------------------------------- CLI
def _main():
    ap = argparse.ArgumentParser(description="StegoComm v3 -- byte-kompatibel zu cover_studio.html")
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
