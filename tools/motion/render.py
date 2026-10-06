"""Draw reproducible, silent editorial illustrations; no product UI or live data."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from PIL import __version__ as pillow_version

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "assets" / "motion"
W, H, FPS, SECONDS, SCALE = 1280, 720, 24, 9, 2
STORIES = ("footprint", "evidence", "resilience")
POSTER_TIMES = {"footprint": 6.8, "evidence": 6.8, "resilience": 3.8}
COLORS = {
    "bg": "#0c1217",
    "panel": "#10191f",
    "raised": "#162129",
    "border": "#3c4d57",
    "mint": "#65dbc6",
    "white": "#eff5f5",
    "muted": "#a8b9c2",
    "dim": "#70848f",
    "amber": "#edc589",
}
FONT_CHOICES = {
    "regular": ("segoeui.ttf", "DejaVuSans.ttf"),
    "bold": ("segoeuib.ttf", "DejaVuSans-Bold.ttf"),
    "mono": ("consola.ttf", "DejaVuSansMono.ttf"),
}
FONTS: dict[str, str] = {}


def color(name: str, alpha: float = 1) -> tuple[int, int, int, int]:
    value = COLORS.get(name, name).lstrip("#")
    return (*tuple(int(value[i : i + 2], 16) for i in (0, 2, 4)), round(255 * alpha))


def resolve_font(role: str, explicit: str | None) -> str:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Missing {role} font: {path}")
        ImageFont.truetype(str(path), 20)
        return str(path)
    for name in FONT_CHOICES[role]:
        for candidate in (
            Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / name,
            Path("/usr/share/fonts/truetype/dejavu") / name,
        ):
            if candidate.is_file():
                return str(candidate.resolve())
        try:
            font = ImageFont.truetype(name, 20)
            return str(Path(font.path).resolve())
        except OSError:
            continue
    raise RuntimeError(f"No {role} font found. Pass --font-{role} with a local font file.")


@lru_cache(maxsize=64)
def font(size: int, role: str = "regular") -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(FONTS[role], size * SCALE)


def smooth(value: float) -> float:
    value = max(0.0, min(1.0, value))
    return value * value * (3 - 2 * value)


def reveal(t: float, start: float, span: float = 0.7) -> float:
    return smooth((t - start) / span) * (1 - smooth((t - 8.1) / 0.9))


def cubic(points: tuple[tuple[float, float], ...], u: float) -> tuple[float, float]:
    a, b, c, d = points
    return tuple(
        (1 - u) ** 3 * a[i] + 3 * (1 - u) ** 2 * u * b[i] + 3 * (1 - u) * u**2 * c[i] + u**3 * d[i] for i in (0, 1)
    )


class Canvas:
    def __init__(self, image: Image.Image | None = None):
        self.image = image.copy() if image else Image.new("RGB", (W * SCALE, H * SCALE), COLORS["bg"])
        self.draw = ImageDraw.Draw(self.image, "RGBA")

    def box(self, rect, fill="panel", stroke=None, radius=16, alpha=1, width=1):
        self.draw.rounded_rectangle(
            tuple(round(p * SCALE) for p in rect),
            radius=round(radius * SCALE),
            fill=color(fill, alpha),
            outline=color(stroke, alpha) if stroke else None,
            width=round(width * SCALE),
        )

    def line(self, points, fill="border", width=1, alpha=1):
        self.draw.line(
            [(round(x * SCALE), round(y * SCALE)) for x, y in points],
            fill=color(fill, alpha),
            width=round(width * SCALE),
            joint="curve",
        )

    def circle(self, x, y, r, fill="mint", alpha=1, stroke=None, width=1):
        self.draw.ellipse(
            tuple(round(p * SCALE) for p in (x - r, y - r, x + r, y + r)),
            fill=color(fill, alpha),
            outline=color(stroke, alpha) if stroke else None,
            width=round(width * SCALE),
        )

    def text(self, x, y, value, size=24, fill="white", role="regular", alpha=1, anchor="lt"):
        face = font(size, role)
        bbox = self.draw.textbbox((x * SCALE, y * SCALE), value, font=face, anchor=anchor)
        if not (0 <= bbox[0] and bbox[2] <= W * SCALE and 0 <= bbox[1] and bbox[3] <= H * SCALE):
            raise ValueError(f"Text outside canvas: {value!r}, {bbox}")
        if alpha < 1:
            # Pillow's RGB text path can discard fill alpha. Composite a small
            # RGBA glyph layer explicitly so fades remain continuous.
            left, top, right, bottom = bbox
            layer = Image.new("RGBA", (right - left + 4, bottom - top + 4), (0, 0, 0, 0))
            ImageDraw.Draw(layer).text(
                (x * SCALE - left + 2, y * SCALE - top + 2),
                value,
                font=face,
                fill=color(fill, alpha),
                anchor=anchor,
            )
            self.image.paste(layer, (left - 2, top - 2), layer)
        else:
            self.draw.text((x * SCALE, y * SCALE), value, font=face, fill=color(fill), anchor=anchor)

    def curve(self, points, fill="border", width=1, alpha=1):
        self.line([cubic(points, u / 60) for u in range(61)], fill, width, alpha)

    def aperture(self, x, y, r=24, alpha=1):
        # Open ring and signal dot mirror the geometry of docs/assets/brand-mark.svg.
        for fraction, weight, opacity in ((1, 0.118, 1), (0.43, 0.09, 0.45)):
            rr = r * fraction
            rect = tuple(round(v * SCALE) for v in (x - rr, y - rr, x + rr, y + rr))
            self.draw.arc(rect, 35, 325, color("mint", opacity * alpha), round(r * weight * SCALE))
        self.circle(x + r * 1.07, y, r * 0.13, "mint", alpha)

    def finish(self) -> Image.Image:
        return self.image.resize((W, H), Image.Resampling.LANCZOS)


def common(story: str) -> Canvas:
    c = Canvas()
    c.box((40, 34, 88, 82), "panel", radius=13)
    c.aperture(62, 58, 16)
    c.text(104, 43, "OPEN SHADOW AI", 21, role="bold")
    c.text(104, 68, "ÉCLAIRER LES DÉCISIONS", 12, "muted", "mono")
    c.box((806, 42, 1220, 78), "raised", radius=9)
    c.circle(825, 60, 3, "mint")
    c.text(839, 51, "ILLUSTRATION · DONNÉES FICTIVES", 17, "muted", "mono")
    titles = {
        "footprint": (
            "L’empreinte IA, mise en lumière.",
            "Relier les signaux disponibles aux grandes catégories d’IA.",
        ),
        "evidence": ("Savoir ce que la preuve établit.", "Contact, installation, usage : trois portées distinctes."),
        "resilience": (
            "Collecter. Conserver. Reprendre.",
            "Une file locale durable face aux interruptions de transport.",
        ),
    }
    c.text(60, 117, titles[story][0], 51, role="bold")
    c.text(62, 190, titles[story][1], 25, "muted")
    c.line(((60, 242), (1220, 242)), "border", alpha=0.45)
    c.line(((60, 638), (1220, 638)), "border", alpha=0.45)
    c.text(
        60,
        669,
        {"footprint": "01 / VISIBILITÉ", "evidence": "02 / CONFIANCE", "resilience": "03 / CONTINUITÉ"}[story],
        15,
        "mint",
        "mono",
    )
    return c


def source_icon(c: Canvas, x: float, y: float, kind: int, alpha: float):
    if kind == 0:
        c.line(((x, y), (x + 18, y - 11), (x + 36, y)), "mint", 2, alpha)
        c.line(((x, y), (x + 18, y + 11), (x + 36, y)), "mint", 2, alpha)
        for xx, yy in ((x, y), (x + 18, y - 11), (x + 36, y), (x + 18, y + 11)):
            c.circle(xx, yy, 3, "mint", alpha)
    elif kind == 1:
        c.box((x, y - 14, x + 35, y + 10), "panel", "mint", 4, alpha, 2)
        c.line(((x + 9, y + 15), (x + 26, y + 15)), "mint", 2, alpha)
        c.line(((x + 17, y + 10), (x + 17, y + 15)), "mint", 2, alpha)
    else:
        c.circle(x + 17, y - 8, 6, "panel", alpha, "mint", 2)
        c.draw.arc(
            tuple(round(v * SCALE) for v in (x + 4, y, x + 30, y + 22)), 180, 360, color("mint", alpha), 2 * SCALE
        )


def footprint(t: float, base: Image.Image) -> Image.Image:
    c = Canvas(base)
    source_y = (303, 403, 503)
    category_y = (281, 364, 447, 530)
    for i, y in enumerate(source_y):
        path = ((340, y + 36), (423, y + 36), (422, 409), (500, 409))
        c.curve(path, "border", 1.4, 0.7)
        active = reveal(t, 0.5 + i * 0.5)
        c.curve(path, "mint", 2, active * 0.25)
        for j in range(2):
            u = (t - 0.65 - i * 0.5 - j * 0.7) / 1.3
            if 0 < u < 1:
                x, yy = cubic(path, smooth(u))
                c.circle(x, yy, 4, "mint", math.sin(math.pi * u))
        c.box((60, y, 340, y + 72), "panel", "border", 14, 1)
        c.box((60, y, 340, y + 72), "raised", "mint", 14, active * 0.45)
        source_icon(c, 80, y + 36, i, 0.5 + 0.5 * active)
        c.text(132, y + 12, ("Réseau", "Postes", "AD / Entra")[i], 25, role="bold")
        c.text(132, y + 43, ("Contacts observés", "Outils installés", "Identités importées")[i], 17, "muted")
    c.circle(585, 409, 86, "panel", 1, "border", 1)
    core = reveal(t, 1.7)
    c.circle(585, 409, 75, "raised", core * 0.6)
    c.aperture(582, 409, 49, 0.5 + 0.5 * core)
    c.text(585, 515, "PREUVES COLLECTÉES", 18, "mint", "mono", anchor="mt")
    c.text(585, 543, "selon les sources", 18, "muted", anchor="mt")
    c.text(585, 568, "disponibles", 18, "muted", anchor="mt")
    for i, y in enumerate(category_y):
        path = ((674, 409), (759, 409), (759, y + 30), (840, y + 30))
        active = reveal(t, 3.1 + i * 0.6)
        c.curve(path, "border", 1.3, 0.65)
        c.curve(path, "mint", 2, active * 0.65)
        u = (t - 2.8 - i * 0.6) / 1.1
        if 0 < u < 1:
            x, yy = cubic(path, smooth(u))
            c.circle(x, yy, 4, "mint", math.sin(math.pi * u))
        c.box((840, y, 1220, y + 61), "panel", "border", 13)
        c.box((840, y, 1220, y + 61), "raised", "mint", 13, active * 0.55)
        c.circle(862, y + 30, 4, "mint", 0.25 + 0.75 * active)
        c.text(886, y + 14, ("LLM", "Code", "Images & audio", "API & modèles")[i], 27, role="bold")
    c.text(1220, 667, "Une visibilité partielle, étayée par les signaux collectés.", 20, "muted", anchor="rt")
    return c.finish()


def evidence(t: float, base: Image.Image) -> Image.Image:
    c = Canvas(base)
    positions = (60, 454, 848)
    for i, x in enumerate(positions):
        active = reveal(t, 0.6 + 2.05 * i)
        c.box((x, 288, x + 372, 605), "panel", "border", 18)
        c.box((x, 288, x + 372, 605), "raised", "mint", 18, active * 0.38)
        c.text(x + 24, 315, f"0{i + 1}", 18, "mint", "mono")
        c.text(
            x + 24,
            353,
            ("Contact réseau", "Outil installé", "Usage instrumenté")[i],
            28,
            role="bold",
            alpha=0.6 + 0.4 * active,
        )
        c.text(x + 24, 396, ("Service contacté", "Présence constatée", "Événement explicite")[i], 21, "muted")
        c.line(((x + 24, 447), (x + 348, 447)), "border", alpha=0.65)
        c.circle(x + 28, 473, 3, "mint", 0.3 + 0.7 * active)
        c.text(x + 42, 462, ("SOURCE · RÉSEAU", "SOURCE · POSTE", "SOURCE · API")[i], 17, "mint", "mono")
        c.text(
            x + 24,
            505,
            ("Contact · confiance moyenne", "Installation · confiance élevée", "Usage déclaré · confiance élevée")[i],
            19,
        )
        c.text(x + 24, 546, ("Usage : non établi", "Usage : non établi", "Modèle : si renseigné")[i], 21, "muted")
        c.text(x + 24, 575, ("Modèle : inconnu", "Modèle : inconnu", "dans la preuve explicite")[i], 19, "muted")
        c.line(((x + 24, 432), (x + 24 + 70 * active, 432)), "mint", 3, active)
    c.text(1220, 667, "Corroborer = croiser des sources indépendantes.", 20, "muted", anchor="rt")
    return c.finish()


def arrow(c: Canvas, a: tuple[float, float], b: tuple[float, float], fill="border", alpha=1):
    c.line((a, b), fill, 2, alpha)
    c.line(((b[0] - 8, b[1] - 5), b, (b[0] - 8, b[1] + 5)), fill, 2, alpha)


def resilience(t: float, base: Image.Image) -> Image.Image:
    c = Canvas(base)
    act = reveal(t, 0.35)
    outage = smooth((t - 2) / 0.5) * (1 - smooth((t - 4.8) / 0.5))
    reset = 1 - smooth((t - 8.1) / 0.9)
    arrow(c, (348, 421), (442, 421), "mint", 0.2 + 0.55 * act)
    arrow(c, (837, 421), (935, 421), "mint", 0.2 + 0.55 * act * (1 - outage))
    if outage > 0:
        c.box((866, 401, 903, 441), "bg", radius=5, alpha=outage)
        c.line(((875, 411), (894, 432)), "amber", 2, outage)
        c.line(((894, 411), (875, 432)), "amber", 2, outage)
    c.box((60, 313, 348, 548), "panel", "border", 18)
    source_icon(c, 178, 367, 1, 0.5 + 0.5 * act)
    c.text(204, 407, "Collecteur", 29, role="bold", anchor="mt")
    c.text(204, 458, "Événements locaux", 20, "muted", anchor="mt")
    c.text(204, 488, "à transmettre", 20, "muted", anchor="mt")
    c.box((442, 278, 837, 585), "raised", "border", 20)
    c.text(467, 305, "FILE LOCALE DURABLE", 19, "mint", "mono")
    c.text(467, 343, "Conserver avant l’envoi", 26, role="bold")
    # Illustrative queue occupancy. The bars are events, not a production metric.
    queued = 1 + 4 * smooth((t - 1.7) / 2.2) - 4 * smooth((t - 5.4) / 1.6)
    queued = 1 + (queued - 1) * reset
    for i in range(5):
        x = 470 + i * 65
        amount = smooth(queued - i)
        c.box((x, 405, x + 49, 477), "panel", "border", 8)
        c.box((x, 405, x + 49, 477), "mint", radius=8, alpha=amount * 0.85)
        for y in (426, 439, 452):
            c.line(((x + 10, y), (x + 38, y)), "bg" if amount > 0.5 else "border", 2, 0.7)
    c.text(467, 508, "Événements en attente", 20, "muted")
    c.text(467, 541, "puis nouvelle tentative", 20, "muted")
    c.box((935, 313, 1220, 548), "panel", "border", 18)
    c.box((1062, 357, 1094, 384), "panel", "mint", 6, 0.5 + 0.5 * act, 2)
    c.draw.arc(
        tuple(round(v * SCALE) for v in (1068, 344, 1088, 371)), 180, 360, color("mint", 0.5 + 0.5 * act), 2 * SCALE
    )
    c.circle(1078, 370, 2, "mint", 0.5 + 0.5 * act)
    c.text(1078, 407, "API protégée", 29, role="bold", anchor="mt")
    c.text(1078, 458, "Clé de collecteur", 20, "muted", anchor="mt")
    c.text(1078, 488, "à portée limitée", 20, "muted", anchor="mt")
    for launch in (0.65, 1.45, 2.25, 3.05, 3.85, 4.65, 5.45, 6.25, 7.05):
        u = (t - launch) / 0.7
        if 0 < u < 1:
            c.circle(356 + 78 * smooth(u), 421, 4, "mint", math.sin(math.pi * u) * reset)
    for launch in (0.9, 1.65, 5.5, 6.0, 6.5, 7.0, 7.5):
        u = (t - launch) / 0.65
        if 0 < u < 1:
            c.circle(845 + 80 * smooth(u), 421, 4, "mint", math.sin(math.pi * u) * (1 - outage) * reset)
    # Fade through a clear label at phase boundaries; restore the opening pose.
    boundaries = (2.1, 4.95, 6.55, 8.3)
    labels = ("Collecte locale", "Interruption simulée", "Nouvelle tentative", "Reprise des envois", "Collecte locale")
    stage = sum(t >= boundary for boundary in boundaries)
    label = labels[stage]
    label_alpha = min(smooth(abs(t - boundary) / 0.16) for boundary in boundaries)
    c.text(62, 605, "SCÉNARIO", 15, "dim", "mono")
    c.text(184, 600, label, 23, "amber" if label.startswith("Interruption") else "mint", alpha=label_alpha)
    c.text(1220, 667, "Selon la configuration et les ressources locales.", 20, "muted", anchor="rt")
    return c.finish()


RENDERERS = {"footprint": footprint, "evidence": evidence, "resilience": resilience}


def ffmpeg_path(explicit: str | None) -> str:
    if explicit:
        if not Path(explicit).is_file():
            raise FileNotFoundError(explicit)
        return str(Path(explicit).resolve())
    installed = shutil.which("ffmpeg")
    if installed:
        return installed
    try:
        import imageio_ffmpeg

        return imageio_ffmpeg.get_ffmpeg_exe()
    except ImportError as exc:
        raise RuntimeError("Install tools/motion/requirements.txt or pass --ffmpeg.") from exc


def encode_video(name: str, base: Image.Image, ffmpeg: str):
    cmd = [
        ffmpeg,
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-f",
        "rawvideo",
        "-vcodec",
        "rawvideo",
        "-pix_fmt",
        "rgb24",
        "-s",
        f"{W}x{H}",
        "-r",
        str(FPS),
        "-i",
        "-",
        "-an",
        "-c:v",
        "libx264",
        "-preset",
        "slow",
        "-crf",
        "19",
        "-threads",
        "1",
        "-pix_fmt",
        "yuv420p",
        "-movflags",
        "+faststart",
        "-map_metadata",
        "-1",
        str(OUT / f"{name}.mp4"),
    ]
    with subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            for frame in range(FPS * SECONDS):
                process.stdin.write(RENDERERS[name](frame / FPS, base).tobytes())
            process.stdin.close()
            errors = process.stderr.read().decode("utf-8", "replace")
            if process.wait() != 0:
                raise RuntimeError(errors)
        except Exception:
            process.kill()
            raise


def encode_gif(name: str, ffmpeg: str):
    target = OUT / f"{name}.gif"
    for fps, palette in ((12, 96), (10, 64)):
        graph = (
            f"fps={fps},scale=960:540:flags=lanczos,split[a][b];"
            f"[a]palettegen=max_colors={palette}:stats_mode=diff[p];"
            "[b][p]paletteuse=dither=none:diff_mode=rectangle"
        )
        subprocess.run(
            [
                ffmpeg,
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-i",
                str(OUT / f"{name}.mp4"),
                "-filter_complex",
                graph,
                "-an",
                "-loop",
                "0",
                str(target),
            ],
            check=True,
        )
        if target.stat().st_size <= 3_000_000:
            return fps, palette
    raise RuntimeError(f"GIF exceeds 3 MB: {target}")


def manifest(ffmpeg: str, gif_settings: dict):
    result = {
        "schema_version": 1,
        "renderer": "tools/motion/render.py",
        "synthetic_data": True,
        "label": "ILLUSTRATION · DONNÉES FICTIVES",
        "duration_seconds": SECONDS,
        "video": {"width": W, "height": H, "fps": FPS, "codec": "h264", "pixel_format": "yuv420p", "audio": False},
        "gif": {"width": 960, "height": 540, "loop": 0},
        "pillow_version": pillow_version,
        "ffmpeg_version": subprocess.check_output([ffmpeg, "-version"], text=True).splitlines()[0],
        "fonts": {
            role: {"filename": Path(path).name, "sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest()}
            for role, path in FONTS.items()
        },
        "assets": [],
    }
    for name in STORIES:
        for ext in ("mp4", "gif", "webp"):
            path = OUT / f"{name}.{ext}"
            asset = {
                "file": path.name,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            if ext == "gif":
                asset.update(fps=gif_settings[name][0], palette_colors=gif_settings[name][1])
            if ext == "webp":
                asset.update(width=W, height=H, poster_time_seconds=POSTER_TIMES[name])
            result["assets"].append(asset)
    if sum(a["bytes"] for a in result["assets"] if a["file"].endswith(".gif")) > 8_000_000:
        raise RuntimeError("Combined GIFs exceed 8 MB")
    (OUT / "manifest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def timeline_sheets(bases: dict[str, Image.Image], directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    times = (0, 1.5, 3, 5.3, 6.9, SECONDS - 1 / FPS)
    for name in STORIES:
        sheet = Image.new("RGB", (1920, 784), COLORS["bg"])
        draw = ImageDraw.Draw(sheet)
        for i, t in enumerate(times):
            x, y = (i % 3) * 640, (i // 3) * 392
            frame = RENDERERS[name](t, bases[name]).resize((640, 360), Image.Resampling.LANCZOS)
            sheet.paste(frame, (x, y))
            draw.text(
                (x + 16, y + 363),
                f"{name} · {t:.2f} s",
                font=ImageFont.truetype(FONTS["mono"], 17),
                fill=COLORS["muted"],
            )
        sheet.save(directory / f"{name}-timeline.png")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--posters-only", action="store_true")
    parser.add_argument("--ffmpeg")
    parser.add_argument("--font-regular")
    parser.add_argument("--font-bold")
    parser.add_argument("--font-mono")
    parser.add_argument("--contact-sheet", type=Path, help="Optional temporary image for visual review")
    parser.add_argument(
        "--timeline-sheets", type=Path, help="Optional directory for first/middle/loop-boundary previews"
    )
    args = parser.parse_args()
    for role in FONT_CHOICES:
        FONTS[role] = resolve_font(role, getattr(args, f"font_{role}"))
    OUT.mkdir(parents=True, exist_ok=True)
    bases = {name: common(name).image for name in STORIES}
    posters = []
    for name in STORIES:
        poster = RENDERERS[name](POSTER_TIMES[name], bases[name])
        poster.save(OUT / f"{name}.webp", format="WEBP", lossless=True, method=6)
        posters.append(poster)
        print(f"Poster: {name}", flush=True)
    if args.contact_sheet:
        sheet = Image.new("RGB", (W, H * len(posters)), COLORS["bg"])
        for i, poster in enumerate(posters):
            sheet.paste(poster, (0, i * H))
        args.contact_sheet.parent.mkdir(parents=True, exist_ok=True)
        sheet.save(args.contact_sheet)
    if args.timeline_sheets:
        timeline_sheets(bases, args.timeline_sheets)
    if args.posters_only:
        return
    ffmpeg = ffmpeg_path(args.ffmpeg)
    gif_settings = {}
    for name in STORIES:
        encode_video(name, bases[name], ffmpeg)
        gif_settings[name] = encode_gif(name, ffmpeg)
        print(f"Exported: {name}", flush=True)
    manifest(ffmpeg, gif_settings)
    print("Manifest written", flush=True)


if __name__ == "__main__":
    main()
