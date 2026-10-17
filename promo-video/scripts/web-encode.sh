#!/usr/bin/env bash
# Re-encode rendered masters (out/*.mp4) into smaller, web-friendly copies in out/web/:
# H.264 High, yuv420p, AAC, moov atom up front (+faststart) so playback starts before download ends.
# Usage: scripts/web-encode.sh [out/peat-promo-v1-landscape.mp4 ...]   (default: all v* masters)
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p out/web
files=("$@")
[ ${#files[@]} -eq 0 ] && files=(out/peat-promo-v*.mp4)
for f in "${files[@]}"; do
  out="out/web/$(basename "$f")"
  ffmpeg -y -loglevel error -i "$f" -c:v libx264 -preset slow -crf 22 -profile:v high -pix_fmt yuv420p \
    -movflags +faststart -c:a aac -b:a 160k "$out"
  echo "$out $(du -h "$out" | cut -f1)"
done
