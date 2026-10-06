"""Independently validate the published motion asset contract and full decoding."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

from PIL import Image, ImageChops, ImageDraw, ImageFont, ImageStat
from render import OUT, STORIES, ffmpeg_path

LABEL_BOX = (806, 42, 1220, 78)


def require(condition: bool, message: str):
    if not condition:
        raise AssertionError(message)


def difference(a: Image.Image, b: Image.Image) -> float:
    return sum(ImageStat.Stat(ImageChops.difference(a, b)).mean) / 3


def atoms(path: Path) -> dict[str, int]:
    offsets = {}
    size = path.stat().st_size
    with path.open("rb") as stream:
        offset = 0
        while offset < size:
            stream.seek(offset)
            header = stream.read(8)
            require(len(header) == 8, f"Truncated MP4 header: {path}")
            length, kind = struct.unpack(">I4s", header)
            if length == 1:
                extended = stream.read(8)
                require(len(extended) == 8, f"Truncated extended MP4 atom: {path}")
                length = struct.unpack(">Q", extended)[0]
            elif length == 0:
                length = size - offset
            require(length >= 8 and offset + length <= size, f"Invalid MP4 atom: {path}")
            offsets.setdefault(kind.decode("ascii", "replace"), offset)
            offset += length
    return offsets


def check_label(frame: Image.Image, baseline: Image.Image, scale: float = 1):
    rect = tuple(round(v * scale) for v in LABEL_BOX)
    label = frame.crop(rect)
    reference = baseline.crop(rect)
    require(difference(label, reference) < 3, "Persistent fictional-data label changes or disappears")
    require(sum(ImageStat.Stat(label).stddev) > 40, "Fictional-data label has no visible text")


def check_gif(path: Path, expected: dict) -> dict:
    with Image.open(path) as image:
        require(image.size == (960, 540), f"GIF dimensions: {path}")
        require(image.info.get("loop") == 0, f"GIF does not loop indefinitely: {path}")
        require(80 <= image.n_frames <= 110, f"Unexpected GIF frame count: {path}")
        total = 0
        first, last = None, None
        for i in range(image.n_frames):
            image.seek(i)
            total += image.info.get("duration", 0)
            frame = image.convert("RGB")
            if first is None:
                first = frame.copy()
            check_label(frame, first, 0.75)
            require(sum(ImageStat.Stat(frame).mean) / 3 > 15, f"Black GIF frame {i}: {path}")
            last = frame.copy()
        require(abs(total / 1000 - 9) < 0.15, f"Unexpected GIF duration {total} ms: {path}")
        require(difference(first, last) < 1, f"Abrupt GIF loop reset: {path}")
        require(abs(image.n_frames / (total / 1000) - expected["fps"]) < 0.2, f"GIF frame rate: {path}")
        return {
            "frames": image.n_frames,
            "duration_seconds": total / 1000,
            "loop_difference": round(difference(first, last), 4),
        }


def check_video(path: Path, ffmpeg: str, sample_directory: Path | None = None) -> dict:
    container = atoms(path)
    require(
        "moov" in container and "mdat" in container and container["moov"] < container["mdat"],
        f"MP4 is not faststart: {path}",
    )
    # Decode the complete stream, rather than inspecting only its declared metadata.
    result = subprocess.run(
        [
            ffmpeg,
            "-hide_banner",
            "-nostats",
            "-i",
            str(path),
            "-map",
            "0:v:0",
            "-an",
            "-progress",
            "pipe:1",
            "-f",
            "null",
            "-",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    require("Video: h264" in result.stderr and "yuv420p" in result.stderr, f"Wrong video codec/pixel format: {path}")
    require("1280x720" in result.stderr and "24 fps" in result.stderr, f"Wrong video dimensions/frame rate: {path}")
    require("Audio:" not in result.stderr, f"Unexpected audio stream: {path}")
    frames = [int(value) for value in re.findall(r"(?m)^frame=(\d+)$", result.stdout)]
    require(frames and frames[-1] == 216, f"Video did not decode 216 frames: {path}")
    duration = re.search(r"Duration: (\d+):(\d+):([\d.]+)", result.stderr)
    require(duration is not None, f"Missing video duration: {path}")
    seconds = int(duration[1]) * 3600 + int(duration[2]) * 60 + float(duration[3])
    require(abs(seconds - 9) < 0.05, f"Wrong video duration: {path}")
    indices = (0, 36, 72, 127, 165, 215)
    select = "+".join(f"eq(n,{i})" for i in indices)
    decoded = subprocess.check_output(
        [
            ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-i",
            str(path),
            "-vf",
            f"select='{select}'",
            "-fps_mode",
            "passthrough",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "rgb24",
            "pipe:1",
        ]
    )
    chunk = 1280 * 720 * 3
    require(len(decoded) == chunk * len(indices), f"Video sample decode incomplete: {path}")
    samples = [Image.frombytes("RGB", (1280, 720), decoded[i : i + chunk]) for i in range(0, len(decoded), chunk)]
    for frame in samples:
        check_label(frame, samples[0])
        require(sum(ImageStat.Stat(frame).mean) / 3 > 15, f"Black video frame: {path}")
    delta = difference(samples[0], samples[-1])
    require(delta < 1, f"Abrupt MP4 loop reset: {path}")
    if sample_directory:
        sample_directory.mkdir(parents=True, exist_ok=True)
        sheet = Image.new("RGB", (1920, 784), "#0c1217")
        draw = ImageDraw.Draw(sheet)
        for i, (frame, index) in enumerate(zip(samples, indices, strict=True)):
            x, y = (i % 3) * 640, (i // 3) * 392
            sheet.paste(frame.resize((640, 360), Image.Resampling.LANCZOS), (x, y))
            draw.text(
                (x + 16, y + 363),
                f"{path.stem} / decoded MP4 / {index / 24:.2f} s",
                font=ImageFont.load_default(size=17),
                fill="#a8b9c2",
            )
        sheet.save(sample_directory / f"{path.stem}-decoded.png")
    return {"frames": frames[-1], "duration_seconds": seconds, "loop_difference": round(delta, 4), "faststart": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ffmpeg")
    parser.add_argument(
        "--sample-sheets", type=Path, help="Optional temporary directory for decoded MP4 frame previews"
    )
    args = parser.parse_args()
    ffmpeg = ffmpeg_path(args.ffmpeg)
    manifest = json.loads((OUT / "manifest.json").read_text(encoding="utf-8"))
    require(
        manifest["synthetic_data"] is True and manifest["label"] == "ILLUSTRATION · DONNÉES FICTIVES",
        "Missing synthetic-data manifest declaration",
    )
    expected = {f"{name}.{ext}" for name in STORIES for ext in ("mp4", "gif", "webp")}
    actual = {asset["file"] for asset in manifest["assets"]}
    require(actual == expected and len(manifest["assets"]) == 9, "Manifest must contain exactly nine unique assets")
    gif_total = 0
    checks = {}
    for asset in manifest["assets"]:
        path = OUT / asset["file"]
        require(path.is_file(), f"Missing asset: {path}")
        require(path.stat().st_size == asset["bytes"], f"Manifest byte mismatch: {path}")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == asset["sha256"], f"Manifest hash mismatch: {path}")
        if path.suffix == ".gif":
            require(asset["bytes"] <= 3_000_000, f"GIF exceeds 3 MB: {path}")
            gif_total += asset["bytes"]
            checks[path.name] = check_gif(path, asset)
        elif path.suffix == ".mp4":
            checks[path.name] = check_video(path, ffmpeg, args.sample_sheets)
        else:
            with Image.open(path) as image:
                require(image.size == (1280, 720) and image.n_frames == 1, f"Unexpected poster: {path}")
                image.load()
                check_label(image.convert("RGB"), image.convert("RGB"))
            checks[path.name] = {"decoded": True}
    require(gif_total <= 8_000_000, "Combined GIF budget exceeds 8 MB")
    print(json.dumps({"passed": True, "gif_total_bytes": gif_total, "checks": checks}, indent=2))


if __name__ == "__main__":
    main()
