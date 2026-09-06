/* Loads the encode/decode engine out of cover_studio.html so the browser
   implementation can be tested, and compared against the Python one.
   Everything below the UI marker touches the DOM and is left out. */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const html = fs.readFileSync(path.join(root, "cover_studio.html"), "utf8");

const script = html.match(/<script>([\s\S]*?)<\/script>/);
if (!script) throw new Error("no <script> block found in cover_studio.html");
const UI = "/* ==================================================================== UI */";
const cut = script[1].indexOf(UI);
if (cut < 0) throw new Error("UI marker not found in cover_studio.html");

const mod = await import("data:text/javascript;base64," + Buffer.from(
  script[1].slice(0, cut) +
  "\nexport {GRAMMARS, POOLS, TEMPLATES, deriveKey, encode, decode, coverToText," +
  " renderSentence, matchSentence};"
).toString("base64"));

export const {
  GRAMMARS, POOLS, TEMPLATES, deriveKey, encode, decode, coverToText,
  renderSentence, matchSentence,
} = mod;

/* The passphrase used across the tests. Long enough to pass the strength check
   the CLI enforces, so both sides can use the same one. */
export const PASS = "harbour-lantern-quiet-seven";

/* Re-wrap a text at a given width, to simulate a transport that reflows it. */
export function rewrap(text, width) {
  const out = [];
  let line = "";
  for (const word of text.split(/\s+/).filter(Boolean)) {
    if ((line + " " + word).trim().length > width) { out.push(line.trim()); line = word; }
    else line += " " + word;
  }
  if (line.trim()) out.push(line.trim());
  return out.join("\n");
}

export const CASES = [
  ["de", 0, 2, "plain"],
  ["de", 1, 2, "js8call"],
  ["de", 2, 1, "plain"],
  ["de", 3, 2, "plain"],
  ["en", 0, 2, "js8call"],
  ["en", 1, 1, "plain"],
  ["en", 2, 2, "js8call"],
  ["en", 3, 2, "plain"],
];
