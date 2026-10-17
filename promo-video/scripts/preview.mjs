// Render one still per scene (late in the scene, after its animations land) for the given
// compositions, bundling once. Output: out/preview/<composition>/<nn>-<scene>.png
// Usage: node scripts/preview.mjs [composition-id-substring ...] [--at=0.8] [--browser=/path/to/headless_shell]
import { mkdirSync } from "node:fs";
import path from "node:path";
import { bundle } from "@remotion/bundler";
import { renderStill, selectComposition, getCompositions } from "@remotion/renderer";

const args = process.argv.slice(2);
const filters = args.filter((a) => !a.startsWith("--"));
const at = Number(args.find((a) => a.startsWith("--at="))?.slice(5) ?? 0.8);
const browserExecutable = args.find((a) => a.startsWith("--browser="))?.slice(10) ?? null;

const serveUrl = await bundle({ entryPoint: path.resolve("src/index.ts") });
const all = await getCompositions(serveUrl, { browserExecutable });
const targets = all.filter((c) => !filters.length || filters.some((f) => c.id.includes(f)));

for (const meta of targets) {
  const composition = await selectComposition({ serveUrl, id: meta.id, browserExecutable, inputProps: meta.defaultProps });
  const { timeline } = meta.defaultProps;
  const dir = `out/preview/${meta.id}`;
  mkdirSync(dir, { recursive: true });
  const scale = meta.width > 3000 ? 0.4 : 0.5;
  for (const [i, s] of timeline.scenes.entries()) {
    const start = timeline.start[s.id];
    const frame = Math.min(meta.durationInFrames - 1, Math.round(start + s.frames * at - (i < timeline.scenes.length - 1 ? 12 : 0)));
    await renderStill({ composition, serveUrl, frame, output: `${dir}/${String(i).padStart(2, "0")}-${s.id}.png`, scale, browserExecutable, inputProps: meta.defaultProps });
  }
  console.log(`${meta.id}: ${timeline.scenes.length} stills`);
}
