// Print the scene/voiceover timeline for each version and flag voice lines that overlap.
// Usage: node scripts/check-timing.mjs [v1 ...]
import { readFileSync, readdirSync } from "node:fs";

const durations = JSON.parse(readFileSync("src/voiceover-durations.json", "utf-8"));
const src = readFileSync("src/timeline.ts", "utf-8");
const FPS = 30, T = Number(src.match(/export const T = (\d+)/)[1]), LEAD = Number(src.match(/export const LEAD = (\d+)/)[1]);
const only = process.argv.slice(2);
const variants = readdirSync("src/variants").filter((f) => f.endsWith(".json")).sort().map((f) => JSON.parse(readFileSync(`src/variants/${f}`, "utf-8")));

for (const v of variants.filter((v) => !only.length || only.includes(v.id))) {
  console.log(`== ${v.id} (${v.name}) ==`);
  let t = 0, lastVoiceEnd = -Infinity, ok = true;
  v.scenes.forEach((s, i) => {
    const d = durations[`${v.id}-${s.id}`];
    if (d === undefined) {
      console.log(`${s.id.padEnd(11)} MISSING CLIP`);
      ok = false;
      return;
    }
    const frames = LEAD + Math.ceil(d * FPS) + s.gap + (i === v.scenes.length - 1 ? 0 : T);
    const vs = t + LEAD, ve = vs + d * FPS;
    const gap = (vs - lastVoiceEnd) / FPS;
    if (gap < 0.3) ok = false;
    console.log(`${s.id.padEnd(11)} scene ${(t / FPS).toFixed(2).padStart(6)}–${((t + frames) / FPS).toFixed(2).padStart(6)}s  voice ${(vs / FPS).toFixed(2).padStart(6)}–${(ve / FPS).toFixed(2).padStart(6)}s  gap-before ${Number.isFinite(gap) ? gap.toFixed(2) : "  - "}s`);
    lastVoiceEnd = ve;
    t += frames - T;
  });
  console.log(`total ${((t + T) / FPS).toFixed(2)}s (${t + T} frames)  ${ok ? "no voice overlaps" : "PROBLEM DETECTED"}`);
}
