"""The passphrase check exists twice -- once in Python, once in the browser
tool -- and the two must agree, or the CLI would accept what the GUI refuses.
This extracts the JavaScript version and compares both on the same inputs."""

import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import stegocomms as sc                                    # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PROBES = [
    "",
    "kurz",
    "hundhund",
    "trommelfeuerwerk",
    "aaaaaaaaaaaaaaaa",
    "correct-horse-battery-staple",
    "harbour lantern quiet seven",
    "Sonne7!Mond",
    "xK9#mQ2$vL4&pR7",
    "a" * 200,
    "Umlaute-äöü-und-mehr-Wörter",
]


def js_verdicts(probes):
    """Run ratePassphrase() from cover_studio.html on the same inputs."""
    with open(os.path.join(ROOT, "cover_studio.html"), encoding="utf-8") as fh:
        html = fh.read()
    m = re.search(r"(const MIN_PASS_LEN[\s\S]*?\n\})\n", html)
    if not m:
        raise SystemExit("could not find ratePassphrase() in cover_studio.html")
    src = m.group(1) + "\nconsole.log(JSON.stringify(" \
          + json.dumps(probes) + ".map(p => ratePassphrase(p)[0])));\n"
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(src)
        path = fh.name
    try:
        out = subprocess.run([os.environ.get("NODE", "node"), path],
                             capture_output=True, text=True, check=True)
        return json.loads(out.stdout.strip().splitlines()[-1])
    finally:
        os.unlink(path)


def main():
    js = js_verdicts(PROBES)
    failures = 0
    for probe, j in zip(PROBES, js):
        p = sc.rate_passphrase(probe)[0]
        ok = p == j
        failures += 0 if ok else 1
        label = probe if len(probe) <= 32 else probe[:29] + "..."
        print(f"  {'ok  ' if ok else 'FAIL'} {label!r:36} python={p:<6} browser={j}")

    # The minimum the CLI enforces must actually be enforced.
    if sc.rate_passphrase("x" * (sc.MIN_PASS_LEN - 1))[0] != "reject":
        print("  FAIL a passphrase below MIN_PASS_LEN is not rejected")
        failures += 1
    if sc.rate_passphrase("harbour lantern quiet seven")[0] == "reject":
        print("  FAIL a sensible passphrase is rejected")
        failures += 1

    print("  passphrase rating agrees" if not failures
          else f"  {failures} disagreement(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
