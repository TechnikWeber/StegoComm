/* One half of the cross-implementation check: writes covers produced by the
   browser engine, and verifies the ones produced by the Python CLI.
   Usage:  node tests/interop.mjs write <dir>
           node tests/interop.mjs verify <dir>                                */
import fs from "node:fs";
import path from "node:path";
import { deriveKey, encode, decode, coverToText, PASS, CASES,
         TOPIC_ORDER, AFU_TOPICS } from "./engine.mjs";

const [mode, dir] = process.argv.slice(2);
if (!["write", "verify"].includes(mode) || !dir) {
  console.error("usage: node tests/interop.mjs write|verify <dir>");
  process.exit(2);
}
fs.mkdirSync(dir, { recursive: true });
const key = await deriveKey(PASS);

/* Deliberately awkward: umlauts, a non-BMP character and a quote, so an
   encoding bug on either side shows up rather than passing silently. */
const secretFor = (lang, level, profile) =>
  `interop ${lang} L${level} ${profile} — Umlaute äöü ß, Emoji 🛰, "quoted"`;

let failures = 0;
/* Each case uses a different topic selection, and the other implementation is
   never told which. If the topic ever leaked into the bit layout, this fails. */
const topicsFor = (i) => [
  TOPIC_ORDER,                      // everything
  AFU_TOPICS,                       // amateur-radio mode
  ["garden"],                       // a single topic
  ["weather", "travel"],            // two
  ["home", "work", "garden"],       // three
  ["tech", "weather"],              // tech mixed in
  undefined,                        // the default set
  ["travel"],
][i % 8];

for (const [i, [lang, level, par, profile, fmt]] of CASES.entries()) {
  const secret = secretFor(lang, level, profile);
  const stem = `${lang}_${level}_${profile}_${fmt}`;
  if (mode === "write") {
    const enc = await encode(secret, key, lang, profile, level, par, topicsFor(i), fmt);
    fs.writeFileSync(path.join(dir, `js_${stem}.txt`), coverToText(enc));
  } else {
    const file = path.join(dir, `py_${stem}.txt`);
    if (!fs.existsSync(file)) {
      console.log(`  FAIL ${stem}: ${file} missing`);
      failures++;
      continue;
    }
    const r = await decode(fs.readFileSync(file, "utf8"), key);
    const ok = r.ok && r.message === secret;
    if (!ok) failures++;
    console.log(`  ${ok ? "ok  " : "FAIL"} python -> browser: ${stem}` +
                (ok ? "" : `  -- ${r.error || JSON.stringify(r.message)}`));
  }
}

if (mode === "write") console.log(`  wrote ${CASES.length} browser covers to ${dir}`);
process.exit(failures ? 1 : 0);
