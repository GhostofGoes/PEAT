# PEAT promo video

A ~71 second promo video for PEAT, built with [Remotion](https://www.remotion.dev/). It uses the "Problem Stack" story structure: four pain points about control-layer visibility, a "what if" turn, then PEAT's Scan, Pull, Parse and Diff workflow. It ends on the fact that PEAT is free and open source (GPLv3).

There are two compositions built from the same scenes:

| Composition | Size | Use |
|---|---|---|
| `Promo-Landscape` | 1920x1080 (16:9) | Web, slides, YouTube |
| `Promo-Portrait` | 1080x1920 (9:16) | Social, mobile |

## Script

The voiceover is the ElevenLabs library voice "Adam - American, Dark and Tough" (`IRHApOXLvnW57QJPQH2P`), `eleven_multilingual_v2`, with the Confident preset (stability 0.60, similarity 0.85, style 0.25) at speed 1.05. An earlier cut used "wayne" (`RV8OR7AC0uhWHZnVnmI5`). To switch voices, change `voiceId` in `voiceover-config.json`, regenerate the clips, and re-sync the cues (see below).

| Scene | Line |
|---|---|
| Threat | From Stuxnet to FrostyGoop, attacks now target the controllers themselves. |
| Question | So... are your controllers compromised? Right now? |
| Baseline | Most sites can't say. Configs are rarely checked against a golden baseline. |
| Tooling | Vendor tools work one device at a time, need a Windows VM per vendor, and can cost eleven thousand dollars a seat. |
| Turn | What if one tool could see them all? |
| Reveal | Meet PEAT. The Process Extraction and Analysis Tool, from Sandia National Laboratories. |
| Scan | Scan finds and fingerprints OT devices. |
| Pull | Pull grabs logic, configs, logs, and firmware, over Ethernet or serial. |
| Parse | Parse turns proprietary blobs into one data model. |
| Diff | Then diff it against your golden config, or stream it into Elastic or Splunk. |
| Proof | Ten-plus vendors. Linux, Windows, or Docker. |
| Free | And it's completely free. Open source, under GPL version three. |
| CTA | Close the visibility gap. Get PEAT on GitHub today. |

Sources for the claims: `docs/introduction.rst` (use cases, the $11,000 single-seat license, headless/VM limits), `docs/supported_devices.csv`, `docs/tcp_ip_protocols_used_by_peat.csv`, and the October 2026 talk "Closing the Control-Layer Visibility Gap" (attack timeline, "10+ vendors, ~25 device families, 13 protocols"). The terminal, JSON and diff panels are stylized mock-ups, not literal PEAT output.

## Build

Media files (`*.mp3`, `*.mp4`) are git-ignored, so you need to recreate the audio before rendering.

```bash
npm install

# Voiceover: one clip per scene into public/voice/, durations into src/voiceover-durations.json
export ELEVENLABS_API_KEY=...
node scripts/generate-clips.mjs            # all scenes
node scripts/generate-clips.mjs pull cta   # just some scenes

# Background music: "Inspired Ambient" (Pixabay, royalty-free), from the promo-video skill
cp <path-to>/inspired-ambient-141686.mp3 public/music.mp3

# Check the timeline (flags overlapping voice lines)
node scripts/check-timing.mjs

# Preview and render
npx remotion studio
npx remotion render Promo-Landscape out/peat-promo-landscape.mp4 --crf=16
npx remotion render Promo-Portrait out/peat-promo-portrait.mp4 --crf=16
```

Scene lengths come from the voice clip durations (`src/timeline.ts`), so regenerating a line resizes its scene. In-scene animation cues are frame numbers taken from word timestamps (`scripts/word-times.py`, uses `faster-whisper`). If you change a line's wording, re-check those cues in `src/scenes/`.

If Remotion can't download its headless browser, pass a local one with `--browser-executable`.
