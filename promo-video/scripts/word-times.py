"""Print word-level timestamps for each voiceover clip (faster-whisper)."""
import json, os, subprocess, sys

import numpy as np
from faster_whisper import WhisperModel

model = WhisperModel(os.environ.get("WHISPER_MODEL", "base.en"), device="cpu", compute_type="int8")
ids = [s["id"] for s in json.load(open("voiceover-config.json"))["sections"]]
for i in sys.argv[1:] or ids:
    pcm = subprocess.run(["ffmpeg", "-loglevel", "error", "-i", f"public/voice/{i}.mp3", "-f", "s16le", "-ac", "1", "-ar", "16000", "-"], capture_output=True, check=True).stdout
    audio = np.frombuffer(pcm, np.int16).astype(np.float32) / 32768
    segs, _ = model.transcribe(audio, word_timestamps=True)
    words = [w for s in segs for w in s.words]
    print(f"[{i}] " + " ".join(f"{w.word.strip()}@{w.start:.2f}" for w in words) + f"  (end {words[-1].end:.2f})")
