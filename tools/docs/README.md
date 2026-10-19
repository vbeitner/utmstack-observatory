# Documentation media tools

Regenerates everything under `docs/media/`, the feature tour and the PDFs from a demo-mode instance.
Needs Node 18+, Google Chrome, ffmpeg, and Python 3.10+ with `pip install markdown==3.7`.

```bash
cd tools/docs && npm install
# 1. a demo instance (synthetic data)
(cd ../../app && DEMO=1 DASH_PASS=demo-password-1 BIND=127.0.0.1 PORT=8799 DATA_DIR=/tmp/obs-demo python3 server.py &)
# 2. screenshots (+ hotspot boxes in out/rects.json) and screencast frames
node capture.js http://127.0.0.1:8799 out all
# 3. encode clips (per clip: out/raw-video/<name>/frames.txt)
for n in out/raw-video/*/; do n=$(basename $n)
  ffmpeg -y -f concat -safe 0 -i out/raw-video/$n/frames.txt -vf "fps=30,scale=1600:-2,format=yuv420p" \
    -c:v libx264 -crf 25 -preset slow -movflags +faststart ../../docs/media/video/$n.mp4
  ffmpeg -y -i ../../docs/media/video/$n.mp4 -vf "fps=8,scale=800:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" ../../docs/media/gif/$n.gif
done
# screenshots: out/images/*.png -> docs/media/screens/*.jpg (1600 px wide, phone shots 780 px)
# 4. tour and PDFs
python3 build_tour.py tour-steps.json out/rects.json ../../docs/tour/index.html "$(cat ../../VERSION)"
python3 md2html.py ../../docs/manual/USER-MANUAL.md ../../docs/manual/.print.html "User Manual" "Version $(cat ../../VERSION)"
node pdf.js ../../docs/manual/.print.html ../../docs/manual/USER-MANUAL.pdf && rm ../../docs/manual/.print.html
```

The print HTML must sit next to the Markdown file so its relative image paths resolve. `pdf.js` puts the logo
(`docs/media/brand/logo.png`) in every page header and the copyright in the footer.

The *Apply fix* screenshot needs a yellow cluster: `python3 yellow_demo.py ../../app 8798` serves demo data with a fake
yellow OpenSearch that the button can repair (sign in with `DEMO_PASS`, default `demo-password-1`).

© 2026 Victor Beitner. All rights reserved.
