/* Exercises the browser engine on its own: round-trip, parity recovery, NACK,
   manifest redundancy, resynchronisation, transport damage, and the grammar's
   internal consistency. */
import { GRAMMARS, TOPIC_ORDER, DEFAULT_TOPICS, AFU_TOPICS, deriveKey, encode,
         decode, coverToText, renderSentence, parseSentence, PASS, CASES,
         rewrap, NOUN_TOPIC, seedRandom, SEED } from "./engine.mjs";

/* Pinned randomness: a red run must mean a real defect, not an unlucky draw.
   STEGO_SEED=0 draws real randomness, STEGO_SEED=<n> tries another corner. */
const seeded = seedRandom();
console.log(seeded ? `seeded with ${SEED} -- STEGO_SEED=0 draws real randomness instead`
                   : "unseeded -- drawing real randomness, results will vary");
const rndBit = (() => {
  let a = (SEED || Date.now()) >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) & 1;
  };
})();

let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "  ok  " : "  FAIL"} ${name}${detail ? "  -- " + detail : ""}`);
};

const key = await deriveKey(PASS);

console.log("grammar");
/* Every sentence must match exactly one (shape, topic) pair, or decoding is a
   coin flip. This is the rule the whole topic feature rests on. */
for (const lang of ["de", "en"]) {
  for (let level = 0; level < GRAMMARS[lang].length; level++) {
    const lv = GRAMMARS[lang][level];
    let bad = null;
    for (const topic of TOPIC_ORDER) {
      for (let i = 0; i < 120 && !bad; i++) {
        const bits = Array.from({ length: lv.bits }, rndBit);
        const s = renderSentence(lv, bits, topic);
        let hits = 0;
        for (const variant of lv.shapes)
          for (const tp of TOPIC_ORDER) if (variant[tp]._re.exec(s)) hits++;
        if (hits !== 1) bad = `${JSON.stringify(s)} matched ${hits} (shape, topic) pairs`;
        else if (JSON.stringify(parseSentence(lv, s, lang)) !== JSON.stringify(bits))
          bad = `${JSON.stringify(s)} did not round-trip its bits`;
      }
      if (bad) break;
    }
    check(`${lang} L${level}: shapes unambiguous across all topics`, !bad, bad || "");
  }
}

console.log("topic independence");
/* The point of the design: the topic selection is sender-side only. A receiver
   never learns or needs it, so two people with different boxes ticked still
   understand each other. */
{
  const k = await deriveKey(PASS);
  const secret = "Meet Sunday 6pm at the old harbour";
  for (const [name, topics] of [
    ["every topic", TOPIC_ORDER],
    ["default set", DEFAULT_TOPICS],
    ["AFU mode (tech only)", AFU_TOPICS],
    ["one topic", ["garden"]],
    ["two topics", ["weather", "home"]],
  ]) {
    const e = await encode(secret, k, "en", "plain", 1, 2, topics);
    const cover = coverToText(e);
    const r = await decode(cover, k);
    check(`a cover built from ${name} decodes without that setting`,
          r.ok && r.message === secret);
    // ...and the selection really did restrict the vocabulary
    const alien = [...new Set(cover.split(/\s+/).filter(Boolean))]
      .filter(w => NOUN_TOPIC.en[w] && !topics.includes(NOUN_TOPIC.en[w]));
    check(`...and drew only on ${topics.length} topic(s)`, !alien.length,
          alien.slice(0, 4).join(", "));
  }
}

console.log("round-trip, parity, NACK");
for (const [lang, level, par, profile] of CASES) {
  const secret = `Meet Sunday 6pm at the old harbour -- ${lang}/${level}`;
  const enc = await encode(secret, key, lang, profile, level, par);
  const tag = `${lang} L${level} P${par} ${profile}`;

  const clean = await decode(coverToText(enc), key);
  check(`${tag}: clean round-trip`, clean.ok && clean.message === secret && !clean.warning);
  check(`${tag}: language and level detected`, clean.lang === lang && clean.level === level,
        `got ${clean.lang}/L${clean.level}`);

  const keep = enc.sections.filter(s => s.block === undefined || s.block >= par);
  const viaParity = await decode(coverToText(enc, keep), key);
  check(`${tag}: ${par} blocks lost, rebuilt from parity`,
        viaParity.ok && viaParity.recovered && viaParity.message === secret);

  const keep2 = enc.sections.filter(s => s.block === undefined || s.block >= par + 1);
  const nack = await decode(coverToText(enc, keep2), key);
  check(`${tag}: ${par + 1} blocks lost, NACK instead of garbage`,
        !nack.ok && Array.isArray(nack.missing) && nack.missing.length > 0);

  const tail = await decode(coverToText(enc, enc.sections.slice(1)), key);
  check(`${tag}: leading manifest lost, trailing one takes over`,
        tail.ok && tail.message === secret);

  const lines = coverToText(enc).split("\n");
  lines.splice(Math.floor(lines.length / 2), 1);
  const resync = await decode(lines.join("\n"), key);
  check(`${tag}: one sentence deleted, decoder resynchronises`,
        resync.ok && resync.message === secret);
}

console.log("transport damage");
const msg = "Meet at six";
const enc = await encode(msg, key, "en", "plain", 2, 2);
const flat = coverToText(enc).split("\n").join(" ");
for (const [name, text] of [
  ["all on one line", flat],
  ["wrapped at 40", rewrap(flat, 40)],
  ["wrapped at 200", rewrap(flat, 200)],
  ["blank lines between", rewrap(flat, 120).split("\n").join("\n\n")],
  ["quote markers", coverToText(enc).split("\n").map(l => "> " + l).join("\n")],
]) {
  const r = await decode(text, key);
  check(`line breaks do not matter: ${name}`, r.ok && r.message === msg);
}

const mangled = coverToText(enc).split("\n")
  .map(l => "KN4CRD: " + l.replace(/ /g, "  ") + "!").join("\n");
const m = await decode(mangled, key);
check("callsign prefixes, double spaces and trailing '!' survive", m.ok && m.message === msg);
check("...and are reported rather than blamed on the passphrase", !!m.warning);

const cleanRun = await decode(coverToText(enc), key);
check("an undamaged cover raises no warning", cleanRun.ok && !cleanRun.warning);

console.log("compression and length");
for (const probe of ["hi", "Meet at six", "Meet Sunday 6pm at the old harbour",
                     "Meet Sunday 6pm at the old harbour. ".repeat(20)]) {
  const e = await encode(probe, key, "en", "plain", 1, 2);
  const r = await decode(coverToText(e), key);
  check(`round-trips at ${probe.length} characters (deflate: ${e.comp})`,
        r.ok && r.message === probe);
}

const emoji = "Umlaute äöü ß und ein Satellit 🛰";
const e2 = await encode(emoji, key, "de", "plain", 1, 2);
const r2 = await decode(coverToText(e2), key);
check("non-ASCII and non-BMP characters survive", r2.ok && r2.message === emoji);

console.log("rejection");
const wrong = await decode(coverToText(enc), await deriveKey("lantern-harbour-seven-quiet"));
check("a wrong passphrase is rejected", !wrong.ok);
const noise = await decode("this is not a cover text at all", key);
check("arbitrary text is rejected", !noise.ok);

console.log(failures ? `\nFAILED: ${failures} check(s)` : "\nall JS engine checks passed");
process.exit(failures ? 1 : 0);
