"""Render invariants: safe typography, stable label, deterministic times and smooth resets."""

from __future__ import annotations

import unittest

import render
from PIL import ImageChops, ImageStat


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for role in render.FONT_CHOICES:
            render.FONTS[role] = render.resolve_font(role, None)
        cls.bases = {name: render.common(name).image for name in render.STORIES}

    def frame(self, name, t):
        return render.RENDERERS[name](t, self.bases[name])

    def test_determinism(self):
        for name in render.STORIES:
            self.assertEqual(self.frame(name, 3.8).tobytes(), self.frame(name, 3.8).tobytes())

    def test_label_stays_identical_across_scene_boundaries(self):
        for name in render.STORIES:
            reference = self.frame(name, 0).crop((806, 42, 1220, 78)).tobytes()
            for t in (0.5, 2.1, 4.95, 6.55, 8.3, 9 - 1 / 24, 9):
                frame = self.frame(name, t)
                self.assertEqual(frame.size, (1280, 720))
                self.assertEqual(reference, frame.crop((806, 42, 1220, 78)).tobytes())

    def test_loop_returns_to_opening_pose(self):
        for name in render.STORIES:
            first = self.frame(name, 0)
            for end in (9 - 1 / 24, 9):
                diff = ImageStat.Stat(ImageChops.difference(first, self.frame(name, end))).mean
                self.assertLess(sum(diff) / 3, 0.1, name)

    def test_phase_boundaries_are_continuous(self):
        for name in render.STORIES:
            for boundary in (2.1, 4.95, 6.55, 8.1, 8.3):
                delta = ImageStat.Stat(
                    ImageChops.difference(self.frame(name, boundary - 0.001), self.frame(name, boundary + 0.001))
                ).mean
                self.assertLess(sum(delta) / 3, 0.1, f"{name} at {boundary}")

    def test_missing_explicit_font_fails_clearly(self):
        with self.assertRaises(FileNotFoundError):
            render.resolve_font("regular", "tmp/motion-tools/does-not-exist.ttf")

    def test_accents_are_distinct_glyphs(self):
        for accented, basic in (("é", "e"), ("è", "e"), ("à", "a"), ("É", "E")):
            face = render.font(28)
            self.assertNotEqual(bytes(face.getmask(accented)), bytes(face.getmask(basic)))

    def test_text_outside_canvas_is_rejected(self):
        with self.assertRaises(ValueError):
            render.Canvas().text(1270, 20, "Texte trop long", 20)

    def test_zero_opacity_text_does_not_change_canvas(self):
        canvas = render.Canvas()
        before = canvas.image.tobytes()
        canvas.text(184, 600, "Interruption simulée", 23, alpha=0)
        self.assertEqual(before, canvas.image.tobytes())

    def test_reveal_is_bounded_and_finishes_reset(self):
        for start in (0.5, 1.7, 3.1, 4.9):
            for i in range(217):
                value = render.reveal(i / 24, start)
                self.assertGreaterEqual(value, 0)
                self.assertLessEqual(value, 1)
            self.assertEqual(render.reveal(9, start), 0)


if __name__ == "__main__":
    unittest.main()
