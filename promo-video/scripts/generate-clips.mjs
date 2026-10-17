// Generate one ElevenLabs clip per scene of every version in src/variants/, loudness-normalize
// it, and record its duration in src/voiceover-durations.json. Lines whose text hasn't changed
// since the last run (tracked in src/voice-manifest.json) are skipped.
// Usage: node scripts/generate-clips.mjs [--force] [--reprocess] [v1 | v1-threat ...]
//   --force      regenerate even if the text is unchanged
//   --reprocess  re-trim/normalize the existing raw clips without calling the API
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { execFileSync } from "node:child_process";

const args = process.argv.slice(2);
const force = args.includes("--force");
const reprocess = args.includes("--reprocess");
const only = args.filter((a) => !a.startsWith("--"));
const apiKey = process.env.ELEVENLABS_API_KEY;
if (!apiKey && !reprocess) throw new Error("ELEVENLABS_API_KEY is not set");

const voice = JSON.parse(readFileSync("voiceover-config.json", "utf-8"));
const variants = readdirSync("src/variants")
  .filter((f) => f.endsWith(".json"))
  .sort()
  .map((f) => JSON.parse(readFileSync(`src/variants/${f}`, "utf-8")));

mkdirSync("public/voice", { recursive: true });
mkdirSync("voice-tests", { recursive: true });
const load = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf-8")) : {});
const durations = load("src/voiceover-durations.json");
const manifest = load("src/voice-manifest.json");
const save = () => {
  const sorted = (o) => Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));
  writeFileSync("src/voiceover-durations.json", JSON.stringify(sorted(durations), null, 2) + "\n");
  writeFileSync("src/voice-manifest.json", JSON.stringify(sorted(manifest), null, 2) + "\n");
};

async function synthesize(text, rawPath) {
  for (let attempt = 1; ; attempt++) {
    const res = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${voice.voiceId}`, {
      method: "POST",
      headers: { "xi-api-key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ text, model_id: voice.model, voice_settings: { ...voice.settings, use_speaker_boost: true } }),
    });
    if (res.ok) return writeFileSync(rawPath, Buffer.from(await res.arrayBuffer()));
    const body = (await res.text()).slice(0, 300);
    if (attempt >= 4 || (res.status !== 429 && res.status < 500)) throw new Error(`${rawPath}: ${res.status} ${body}`);
    await new Promise((r) => setTimeout(r, 2000 * attempt));
  }
}

// Trim leading/trailing silence (keeping a short pad so soft onsets survive), then normalize loudness.
function processClip(key) {
  const out = `public/voice/${key}.mp3`;
  execFileSync("ffmpeg", [
    "-y", "-loglevel", "error", "-i", `voice-tests/${key}-raw.mp3`, "-af",
    "silenceremove=start_periods=1:start_threshold=-55dB:start_silence=0.08,areverse," +
      "silenceremove=start_periods=1:start_threshold=-55dB:start_silence=0.12,areverse," +
      "loudnorm=I=-16:TP=-1.5:LRA=11",
    "-ar", "44100", "-b:a", "192k", out,
  ]);
  const d = parseFloat(execFileSync("ffprobe", ["-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", out], { encoding: "utf-8" }));
  return Math.round(d * 1000) / 1000;
}

const jobs = variants.flatMap((v) =>
  v.scenes
    .map((s) => ({ key: `${v.id}-${s.id}`, text: s.vo, variant: v.id }))
    .filter((j) => !only.length || only.includes(j.key) || only.includes(j.variant)),
);
const todo = jobs.filter((j) => force || reprocess || manifest[j.key] !== j.text || !existsSync(`public/voice/${j.key}.mp3`));
console.log(`${todo.length} of ${jobs.length} clips to ${reprocess ? "reprocess" : "generate"}`);

// A few requests at a time keeps within ElevenLabs concurrency limits.
const queue = [...todo];
await Promise.all(
  Array.from({ length: 3 }, async () => {
    for (let job; (job = queue.shift()); ) {
      if (!reprocess) await synthesize(job.text, `voice-tests/${job.key}-raw.mp3`);
      durations[job.key] = processClip(job.key);
      manifest[job.key] = job.text;
      console.log(`${job.key.padEnd(16)} ${durations[job.key].toFixed(2)}s  "${job.text}"`);
      save();
    }
  }),
);
save();
