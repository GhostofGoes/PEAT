#!/usr/bin/env bash
# Render every version in every format to out/. Pass version ids (v1 v3 ...) to limit.
# Set BROWSER to a headless Chromium path if Remotion can't download its own.
set -euo pipefail
cd "$(dirname "$0")/.."
versions=("${@:-v1 v2 v3 v4 v5}")
for v in ${versions[@]}; do
  for f in Landscape Portrait Ultrawide; do
    crf=16; [ "$f" = Ultrawide ] && crf=18
    out="out/peat-promo-$v-$(echo "$f" | tr '[:upper:]' '[:lower:]').mp4"
    npx remotion render "Promo-${v^^}-$f" "$out" --codec=h264 --crf=$crf --jpeg-quality=95 \
      --audio-bitrate=192k --concurrency=4 --log=error ${BROWSER:+--browser-executable="$BROWSER"}
    echo "rendered $out"
  done
done
