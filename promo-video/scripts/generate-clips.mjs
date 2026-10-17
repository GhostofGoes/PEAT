// Generate one ElevenLabs clip per voiceover section, loudness-normalize it,
// and write the measured durations to src/voiceover-durations.json.
// Usage: node scripts/generate-clips.mjs [--reprocess] [sectionId ...]
//   --reprocess  re-trim/normalize the existing raw clips without calling the API
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";

const reprocess = process.argv.includes("--reprocess");
const apiKey = process.env.ELEVENLABS_API_KEY;
if (!apiKey && !reprocess) throw new Error("ELEVENLABS_API_KEY is not set");

const config = JSON.parse(readFileSync("voiceover-config.json", "utf-8"));
const only = process.argv.slice(2).filter((a) => !a.startsWith("--"));
const outDir = "public/voice";
mkdirSync(outDir, { recursive: true });
mkdirSync("voice-tests", { recursive: true });

const durationsPath = "src/voiceover-durations.json";
const durations = existsSync(durationsPath) ? JSON.parse(readFileSync(durationsPath, "utf-8")) : {};

async function synthesize(section, rawPath) {
  const settings = { ...config.settings, ...(section.settings ?? {}) };
  const res = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${config.voiceId}`, {
    method: "POST",
    headers: { "xi-api-key": apiKey, "Content-Type": "application/json" },
    body: JSON.stringify({
      text: section.text,
      model_id: config.model,
      voice_settings: { ...settings, use_speaker_boost: true },
    }),
  });
  if (!res.ok) throw new Error(`${section.id}: ${res.status} ${(await res.text()).slice(0, 300)}`);
  writeFileSync(rawPath, Buffer.from(await res.arrayBuffer()));
}

for (const section of config.sections) {
  if (only.length && !only.includes(section.id)) continue;
  const raw = `voice-tests/${section.id}-raw.mp3`;
  if (!reprocess) await synthesize(section, raw);

  // Trim leading/trailing silence (keeping a short pad so soft onsets survive), then normalize loudness.
  const out = `${outDir}/${section.id}.mp3`;
  execFileSync("ffmpeg", [
    "-y", "-loglevel", "error", "-i", raw, "-af",
    "silenceremove=start_periods=1:start_threshold=-55dB:start_silence=0.08,areverse," +
      "silenceremove=start_periods=1:start_threshold=-55dB:start_silence=0.12,areverse," +
      "loudnorm=I=-16:TP=-1.5:LRA=11",
    "-ar", "44100", "-b:a", "192k", out,
  ]);
  const d = parseFloat(execFileSync("ffprobe", ["-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", out], { encoding: "utf-8" }));
  durations[section.id] = Math.round(d * 1000) / 1000;
  console.log(`${section.id.padEnd(12)} ${d.toFixed(2)}s  "${section.text}"`);
}

writeFileSync(durationsPath, JSON.stringify(durations, null, 2) + "\n");
