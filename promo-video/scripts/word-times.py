"""Word-level timestamps for each voiceover clip (faster-whisper), saved to src/word-times.json.

Scenes use these to sync animations to the words they name (see `cues` in src/variants/*.json).
Only clips that are new or changed since the last run are transcribed, unless keys are given.

Usage: python scripts/word-times.py [v1 | v1-threat ...]
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
from faster_whisper import WhisperModel

OUT = Path("src/word-times.json")
STATE = Path("voice-tests/word-times-state.json")

words = json.loads(OUT.read_text()) if OUT.exists() else {}
state = json.loads(STATE.read_text()) if STATE.exists() else {}
manifest = json.loads(Path("src/voice-manifest.json").read_text())

wanted = sys.argv[1:]
todo = [
    k
    for k in sorted(manifest)
    if (k in wanted or k.split("-")[0] in wanted)
    or (not wanted and state.get(k) != manifest[k])
]
print(f"{len(todo)} clips to transcribe")

model = WhisperModel(os.environ.get("WHISPER_MODEL", "small.en"), device="cpu", compute_type="int8")
for key in todo:
    pcm = subprocess.run(
        ["ffmpeg", "-loglevel", "error", "-i", f"public/voice/{key}.mp3", "-f", "s16le", "-ac", "1", "-ar", "16000", "-"],
        capture_output=True,
        check=True,
    ).stdout
    audio = np.frombuffer(pcm, np.int16).astype(np.float32) / 32768
    segments, _ = model.transcribe(audio, word_timestamps=True)
    words[key] = [[w.word.strip(), round(w.start, 2)] for s in segments for w in s.words]
    state[key] = manifest[key]
    print(f"[{key}] " + " ".join(f"{w}@{t:.2f}" for w, t in words[key]))
    OUT.write_text(json.dumps(dict(sorted(words.items())), indent=1) + "\n")
    STATE.write_text(json.dumps(state, indent=1) + "\n")
