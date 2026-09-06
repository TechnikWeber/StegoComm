"""Checks the shipped word lists, not a copy of them.

Two things are verified. First, the invariants the design depends on: a noun
identifies its topic, so nouns must be unique across every topic, and any two
slots whose words can land in the same position in different sentence shapes must
not share a word. Break either and a sentence could be read two ways.

Second, that both implementations carry exactly the same lists. They are
generated from one definition, but nothing stops someone editing one by hand.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import stegocomms as sc                                    # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Slots whose words may appear in the same position in different shapes.
# END and ADV2 are exempt: no level uses both.
DISJOINT = [("N", "A1"), ("N", "A2"), ("N", "ADV2"), ("N", "END"),
            ("A1", "A2"), ("A1", "ADV2"), ("A1", "END"),
            ("A2", "ADV2"), ("A2", "END")]
SIZES = {"A1": 64, "A2": 32, "END": 32, "ADV2": 32}
NOUNS_PER_TOPIC = 64


def bare(word):
    return word.split(" ", 1)[1] if " " in word else word


def check_invariants():
    problems = []
    for lang in ("de", "en"):
        nouns = {}
        for topic in sc.TOPIC_ORDER:
            words = sc.TOPIC_WORDS[lang][topic]["N"]
            if len(words) != NOUNS_PER_TOPIC:
                problems.append(f"{lang}/{topic}: {len(words)} nouns, want {NOUNS_PER_TOPIC}")
            for w in words:
                b = bare(w)
                if b in nouns:
                    problems.append(f"{lang}: noun {b!r} appears in "
                                    f"{topic} and {nouns[b]} -- topics must not share nouns")
                nouns[b] = topic

        for key, want in SIZES.items():
            words = sc.SHARED_POOLS[lang][key]
            if len(words) != want:
                problems.append(f"{lang}/{key}: {len(words)} entries, want {want}")
            dupes = sorted({w for w in words if words.count(w) > 1})
            if dupes:
                problems.append(f"{lang}/{key}: duplicates {dupes}")

        pools = dict(sc.SHARED_POOLS[lang], N=sorted(nouns))
        for x, y in DISJOINT:
            shared = sorted(set(pools[x]) & set(pools[y]))
            if shared:
                problems.append(f"{lang}: {x} and {y} both contain {shared}")
    return problems


def browser_pools():
    """Ask the browser engine for its word lists, as JSON."""
    script = (
        'import {TOPIC_WORDS, SHARED_POOLS, TEMPLATES, TOPIC_ORDER, DEFAULT_TOPICS,'
        ' AFU_TOPICS} from "./tests/engine.mjs";\n'
        'console.log(JSON.stringify({TOPIC_WORDS, SHARED_POOLS, TEMPLATES,'
        ' TOPIC_ORDER, DEFAULT_TOPICS, AFU_TOPICS}));\n'
    )
    out = subprocess.run([os.environ.get("NODE", "node"), "--input-type=module", "-e", script],
                         cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("could not read the browser pools:\n" + out.stderr[-2000:])
    return json.loads(out.stdout.strip().splitlines()[-1])


def check_implementations_agree():
    js = browser_pools()
    problems = []
    for name, mine, theirs in [
        ("TOPIC_ORDER", sc.TOPIC_ORDER, js["TOPIC_ORDER"]),
        ("DEFAULT_TOPICS", sc.DEFAULT_TOPICS, js["DEFAULT_TOPICS"]),
        ("AFU_TOPICS", sc.AFU_TOPICS, js["AFU_TOPICS"]),
        ("TEMPLATES", sc.TEMPLATES, js["TEMPLATES"]),
        ("SHARED_POOLS", sc.SHARED_POOLS, js["SHARED_POOLS"]),
    ]:
        if mine != theirs:
            problems.append(f"{name} differs between the two implementations")
    for lang in ("de", "en"):
        for topic in sc.TOPIC_ORDER:
            mine = sc.TOPIC_WORDS[lang][topic]["N"]
            theirs = js["TOPIC_WORDS"][lang][topic]["N"]
            if mine != theirs:
                only_py = [w for w in mine if w not in theirs][:3]
                only_js = [w for w in theirs if w not in mine][:3]
                problems.append(f"{lang}/{topic} nouns differ -- "
                                f"python only: {only_py}, browser only: {only_js}")
    return problems


def main():
    problems = check_invariants()
    print(f"  {'ok  ' if not problems else 'FAIL'} word-list invariants"
          + ("" if not problems else ":"))
    for p in problems:
        print("       " + p)

    agree = check_implementations_agree()
    print(f"  {'ok  ' if not agree else 'FAIL'} both implementations carry the same lists"
          + ("" if not agree else ":"))
    for p in agree:
        print("       " + p)

    total = len(sc.TOPIC_ORDER) * NOUNS_PER_TOPIC
    print(f"       {total} nouns per language across {len(sc.TOPIC_ORDER)} topics, "
          f"plus {sum(SIZES.values())} shared words")
    return 1 if (problems or agree) else 0


if __name__ == "__main__":
    sys.exit(main())
