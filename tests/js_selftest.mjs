/* Exercises the browser engine on its own: round-trip, parity recovery, NACK,
   manifest redundancy, resynchronisation, transport damage, and the grammar's
   internal consistency. */
import { GRAMMARS, deriveKey, encode, decode, coverToText, renderSentence,
         matchSentence, PASS, CASES, rewrap } from "./engine.mjs";

let failures = 0;
const check = (name, ok, detail = "") => {
  if (!ok) failures++;
  console.log(`${ok ? "  ok  " : "  FAIL"} ${name}${detail ? "  -- " + detail : ""}`);
};

const key = await deriveKey(PASS);

console.log("grammar");
for (const lang of ["de", "en"]) {
  for (let level = 0; level < GRAMMARS[lang].length; level++) {
    const lv = GRAMMARS[lang][level];
    let bad = null;
    for (let i = 0; i < 500 && !bad; i++) {
      const bits = Array.from({ length: lv.bits }, () => Math.random() < 0.5 ? 0 : 1);
      const s = renderSentence(lv, bits);
      const hits = lv.shapes.filter(sh => sh._re.exec(s)).length;
      if (hits !== 1) bad = `${JSON.stringify(s)} matched ${hits} shapes`;
      else if (JSON.stringify(matchSentence(lv, s)) !== JSON.stringify(bits))
        bad = `${JSON.stringify(s)} did not round-trip its bits`;
    }
    check(`${lang} L${level}: shapes unambiguous and reversible`, !bad, bad || "");
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
