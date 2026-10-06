# Motion illustrations

Three short, silent French illustrations for the public repository. They follow
[DESIGN.md](../../DESIGN.md): graphite surfaces, mint signals, the open aperture
motif and Segoe UI / Consolas. They draw new vector diagrams; no dashboard
screenshot, customer data or product interface is modified.

Every frame visibly carries **ILLUSTRATION · DONNÉES FICTIVES**. The cards and
queue events are explanatory examples, not measured coverage, confidence
calibration or operational guarantees.

| Clip | Meaning | Important limit |
| --- | --- | --- |
| `footprint` | Available network, endpoint and identity sources feed an evidence-based view of AI categories. | Identity imports provide context. The picture does not establish complete network visibility. |
| `evidence` | A network contact, an installed tool and an explicitly instrumented event establish different facts. | Installation does not establish usage. Usage and model remain unknown without explicit evidence. Corroboration needs independent sources. |
| `resilience` | A collector stores events locally, queues during a simulated interruption, then retries delivery to a protected API. | This scenario uses a scoped collector key. Actual durability, delivery and capacity depend on configuration and local resources; legacy authentication can still be configured. |

The scoped credential assumption is documented in
[collector operations](../../docs/collector-operations.md). Confidence labels are
fictional examples for the stated fact, not product scoring rules.

## Reproduce

Use Python 3.11 or later with a separate environment. These are optional authoring
dependencies, not application runtime dependencies:

```sh
python -m venv tmp/motion-tools/venv
# Windows
tmp/motion-tools/venv/Scripts/python -m pip install -r tools/motion/requirements.txt
tmp/motion-tools/venv/Scripts/python tools/motion/render.py
tmp/motion-tools/venv/Scripts/python tools/motion/validate.py
tmp/motion-tools/venv/Scripts/python -m unittest discover -s tools/motion -p "test_*.py"
```

On Linux/macOS, use `tmp/motion-tools/venv/bin/python`. `imageio-ffmpeg` supplies
the encoder; an installed `ffmpeg` is also accepted. Pass `--ffmpeg /path/to/ffmpeg`
to select an exact executable. No binaries or fonts are committed.

Windows font discovery uses installed Segoe UI, Segoe UI Bold and Consolas.
Linux discovery falls back to installed DejaVu Sans / DejaVu Sans Bold / DejaVu
Sans Mono. On any platform, pass all three explicit local font files to match a
chosen toolchain:

```sh
python tools/motion/render.py --font-regular /path/to/regular.ttf --font-bold /path/to/bold.ttf --font-mono /path/to/mono.ttf
```

Fonts are not bundled or downloaded. Exact text layout and asset bytes depend
on the font files and encoder build. The manifest records font SHA-256 values,
Pillow and FFmpeg versions so the published toolchain can be identified. Within
that toolchain the renderer uses fixed times, no randomness, no live inputs and
a single encoder thread.

For a quick review without encoding, run:

```sh
python tools/motion/render.py --posters-only --contact-sheet tmp/motion-tools/posters.png --timeline-sheets tmp/motion-tools/previews
```

## Export contract and validation

Outputs are in [docs/assets/motion](../../docs/assets/motion):

- MP4: 1280 × 720, 24 fps, 9 seconds, H.264, `yuv420p`, no audio, `faststart`.
- GIF: 960 × 540, 12 fps, infinite loop. If the first encode exceeds 3 MB,
  the renderer uses 10 fps and a smaller palette. Each GIF is at most
  3,000,000 bytes; their sum is at most 8,000,000 bytes.
- WebP: lossless 1280 × 720 still, from a useful reading point in each story.
- `manifest.json`: duration, dimensions, codec settings, toolchain, font
  fingerprints, byte counts and SHA-256 values for all nine assets.

The renderer supersamples each frame at 2× and downsamples with Lanczos.
Signals reveal in sequence, settle into a reading hold, then return to the
opening pose while the canvas, headings and fictional-data label remain visible.

`validate.py` checks all asset hashes and byte counts, every GIF frame and its
timing/loop metadata, MP4 container ordering, full MP4 decoding and stream
properties. It samples decoded frames for continuity and the persistent label.
Pass `--sample-sheets tmp/motion-tools/decoded` to save temporary contact sheets
from the encoded videos, including their first and last frames.
`test_render.py` covers deterministic drawing, boundary times, source/usage
semantics, label stability, accents, font errors and loop reset. Animation
previews stay in ignored `tmp/` and are not part of the published assets.
