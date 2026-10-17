# PEAT promo video

Promo videos for PEAT, built with [Remotion](https://www.remotion.dev/). There are five versions, each with its own script and visual style. They all follow the same story ("Problem Stack"):

1. Four pain points about control-layer visibility.
2. A "what if" turn.
3. PEAT's Scan, Pull, Parse and Diff workflow.
4. Safety, then what PEAT collects from, where it runs, the Python API and the modular design.
5. The close: PEAT is free and open source (GPLv3).

Each version runs about 1:40–2:00.

| Version | Style | Script tone | Music |
|---|---|---|---|
| V1 Signal | Dark navy, PEAT cyan, perspective grid, Inter | Confident, direct | Inspired Ambient |
| V2 Blueprint | Engineering blueprint, outlined panels, IBM Plex | Precise, technical | Motivational Day |
| V3 Control Room | SCADA/HMI dark, phosphor green, scanlines, Space Grotesk | Short and punchy | Upbeat Corporate |
| V4 Daylight | Light mode, soft cards, Manrope | Plain language for managers and asset owners | Motivational Day |
| V5 Kinetic | Black with electric cyan, dot matrix, zoom transitions, Sora | Rhetorical, high-energy | Upbeat Corporate |

Every version renders in three formats:

| Composition | Size | Use |
|---|---|---|
| `Promo-V1-Landscape` … `Promo-V5-Landscape` | 1920x1080 (16:9) | Web, slides, YouTube |
| `Promo-V1-Portrait` … `Promo-V5-Portrait` | 1080x1920 (9:16) | Mobile, social, Shorts |
| `Promo-V1-Ultrawide` … `Promo-V5-Ultrawide` | 3440x1440 (21:9) | Ultrawide monitors |

The ultrawide format lays scenes out on a 1080px-tall virtual canvas and scales it up to 1440. That keeps type sizes consistent across formats while the layout uses the extra width (`src/layout.tsx`).

## How it's organized

| Path | What it holds |
|---|---|
| `src/variants/v1.json` … `v5.json` | One file per version: theme, music, and for each scene the voiceover line (`vo`), on-screen copy (`text`, with accent words in `*asterisks*`), pacing (`gap`) and `cues`. |
| `src/theme.ts` | The five visual themes: palette, fonts, panel and background style, transition style. |
| `src/scenes/` | Scene components. They read copy and cues from the current version, so one set of scenes serves all five. |
| `src/word-times.json` | Word timestamps for every clip. A cue such as `"kicker": "would"` starts that animation on the frame where "would" is spoken. |

The voiceover is the ElevenLabs library voice "Adam - American, Dark and Tough" (`IRHApOXLvnW57QJPQH2P`), `eleven_multilingual_v2`, with the Confident preset (stability 0.60, similarity 0.85, style 0.25) at speed 1.05 (`voiceover-config.json`).

Sources for the claims:

- `docs/introduction.rst`: use cases and vendor-tool limits.
- `docs/design_documents.rst`: the safety design. Scanning verifies devices before a pull, fingerprints them one at a time, and tries the most reliable, lowest-load methods first.
- `docs/configure.rst`: limiting what's pulled.
- `docs/system_requirements.rst`: macOS is best-effort.
- `docs/python_examples.rst` and `docs/module_developer_guide.rst`: the Python API and module design.
- `docs/supported_devices.csv` and `docs/tcp_ip_protocols_used_by_peat.csv`: supported devices and protocols.
- The October 2026 talk "Closing the Control-Layer Visibility Gap": the attack timeline and "10+ vendors, ~25 device families, 13 protocols".

The terminal, JSON, diff and hardware visuals are stylized mock-ups, not literal PEAT output.

## Build

Media files (`*.mp3`, `*.mp4`) are git-ignored, so recreate the audio before rendering.

```bash
npm install

# Voiceover: one clip per scene and version into public/voice/ (unchanged lines are skipped)
export ELEVENLABS_API_KEY=...
node scripts/generate-clips.mjs            # all versions
node scripts/generate-clips.mjs v3         # one version
node scripts/generate-clips.mjs v3-safety  # one line

# Word timings for animation cues (pip install faster-whisper)
python scripts/word-times.py

# Background music (Pixabay, royalty-free, from the promo-video skill), padded to cover 2 minutes
M=<path-to-skill>/music
mkdir -p public/music
ffmpeg -i $M/inspired-ambient-141686.mp3 -i $M/inspired-ambient-141686.mp3 -filter_complex "[0:a][1:a]acrossfade=d=4:c1=tri:c2=tri" public/music/ambient.mp3
ffmpeg -i $M/the-upbeat-inspiring-corporate-142313.mp3 -i $M/the-upbeat-inspiring-corporate-142313.mp3 -filter_complex "[0:a][1:a]acrossfade=d=4:c1=tri:c2=tri" public/music/corporate.mp3
cp $M/motivational-day-112790.mp3 public/music/motivational.mp3

# Check timelines (flags overlapping voice lines)
node scripts/check-timing.mjs

# Preview and render
npx remotion studio
npx remotion render Promo-V1-Landscape out/peat-promo-v1-landscape.mp4 --crf=16
npx remotion render Promo-V1-Portrait out/peat-promo-v1-portrait.mp4 --crf=16
npx remotion render Promo-V1-Ultrawide out/peat-promo-v1-ultrawide.mp4 --crf=18
```

Scene lengths come from the clip durations plus each scene's `gap`, so changing a line resizes its scene. After changing a line, rerun `generate-clips.mjs` and `word-times.py`. Then check the scene's `cues` still name words that are in the new line. A missing cue word falls back to a fixed fraction of the line.

If Remotion can't download its headless browser, pass a local one with `--browser-executable`.

Earlier cuts (the ~70s short cut and the first ~96s long cut) are in this folder's git history.
