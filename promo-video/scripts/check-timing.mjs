// Print the scene/voiceover timeline and flag any voice line that overlaps the next one.
import { readFileSync } from "node:fs";

const durations = JSON.parse(readFileSync("src/voiceover-durations.json", "utf-8"));
const src = readFileSync("src/timeline.ts", "utf-8");
const FPS = 30, T = Number(src.match(/export const T = (\d+)/)[1]), LEAD = Number(src.match(/export const LEAD = (\d+)/)[1]);
const plan = [...src.matchAll(/\{ id: "(\w+)", gap: (\d+) \}/g)].map((m) => ({ id: m[1], gap: Number(m[2]) }));

let t = 0, lastVoiceEnd = -Infinity, ok = true;
plan.forEach((s, i) => {
  const vf = Math.ceil(durations[s.id] * FPS);
  const frames = LEAD + vf + s.gap + (i === plan.length - 1 ? 0 : T);
  const vs = t + LEAD, ve = vs + durations[s.id] * FPS;
  const gap = (vs - lastVoiceEnd) / FPS;
  if (gap < 0.3) ok = false;
  console.log(`${s.id.padEnd(11)} scene ${(t / FPS).toFixed(2).padStart(6)}–${((t + frames) / FPS).toFixed(2).padStart(6)}s  voice ${(vs / FPS).toFixed(2).padStart(6)}–${(ve / FPS).toFixed(2).padStart(6)}s  gap-before ${Number.isFinite(gap) ? gap.toFixed(2) : "  - "}s`);
  lastVoiceEnd = ve;
  t += frames - T;
});
console.log(`total ${(t + T) / FPS}s (${t + T} frames)  ${ok ? "no voice overlaps" : "OVERLAP DETECTED"}`);
