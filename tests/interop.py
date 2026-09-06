"""The other half of the cross-implementation check: writes covers produced by
the Python engine, and verifies the ones produced by the browser engine.

    python tests/interop.py write <dir>
    python tests/interop.py verify <dir>
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import stegocomms as sc                                    # noqa: E402

PASS = "harbour-lantern-quiet-seven"

# Must stay identical to CASES in tests/engine.mjs.
CASES = [
    ("de", 0, 2, "plain", "sentences"),
    ("de", 1, 2, "js8call", "sentences"),
    ("de", 2, 1, "plain", "digits"),
    ("de", 3, 2, "plain", "base32"),
    ("en", 0, 2, "js8call", "sentences"),
    ("en", 1, 1, "plain", "base32"),
    ("en", 2, 2, "js8call", "digits"),
    ("en", 3, 2, "plain", "sentences"),
]


def secret_for(lang, level, profile):
    """Deliberately awkward: umlauts, a non-BMP character and a quote, so an
    encoding bug on either side shows up rather than passing silently."""
    return f'interop {lang} L{level} {profile} — Umlaute äöü ß, Emoji 🛰, "quoted"'


# Each case uses a different topic selection, and the other implementation is
# never told which.  If the topic ever leaked into the bit layout, this fails.
TOPIC_SETS = [
    sc.TOPIC_ORDER,                     # everything
    sc.AFU_TOPICS,                      # amateur-radio mode
    ["garden"],                         # a single topic
    ["weather", "travel"],              # two
    ["home", "work", "garden"],         # three
    ["tech", "weather"],                # tech mixed in
    None,                               # the default set
    ["travel"],
]


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("write", "verify"):
        print("usage: python tests/interop.py write|verify <dir>", file=sys.stderr)
        return 2
    mode, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    key = sc.derive_key(PASS)

    failures = 0
    for i, (lang, level, par, profile, fmt) in enumerate(CASES):
        secret = secret_for(lang, level, profile)
        stem = f"{lang}_{level}_{profile}_{fmt}"
        if mode == "write":
            enc = sc.encode(secret, key, lang=lang, profile=profile,
                            level=level, parity=par,
                            topics=TOPIC_SETS[i % len(TOPIC_SETS)], fmt=fmt)
            with open(os.path.join(out, f"py_{stem}.txt"), "w", encoding="utf-8") as fh:
                fh.write(sc.cover_to_text(enc))
        else:
            path = os.path.join(out, f"js_{stem}.txt")
            if not os.path.exists(path):
                print(f"  FAIL {stem}: {path} missing")
                failures += 1
                continue
            with open(path, encoding="utf-8") as fh:
                res = sc.decode(fh.read(), key)
            ok = res.get("ok") and res.get("message") == secret
            failures += 0 if ok else 1
            note = "" if ok else f"  -- {res.get('error') or res.get('message')!r}"
            print(f"  {'ok  ' if ok else 'FAIL'} browser -> python: {stem}{note}")

    if mode == "write":
        print(f"  wrote {len(CASES)} python covers to {out}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
