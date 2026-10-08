"""Translated entry points preserve executable procedures and document structure."""

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
GROUPS = (
    ("README.md", "README.fr.md", "README.zh-CN.md"),
    ("docs/en/README.md", "docs/fr/README.md", "docs/zh-CN/README.md"),
    ("docs/roadmap.md", "docs/fr/roadmap.md", "docs/zh-CN/roadmap.md"),
)
FENCE = re.compile(
    r"^ {0,3}(?:(?P<backtick>`{3,})|(?P<tilde>~{3,}))(?P<language>[^\n]*)\n(?P<body>.*?)"
    r"(?:^ {0,3}(?(backtick)(?P=backtick)`*|(?P=tilde)~*)[ \t]*(?:\n|$)|\Z)",
    re.MULTILINE | re.DOTALL,
)


def read_document(path):
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def procedures(document):
    blocks = []
    for match in FENCE.finditer(document):
        language, body = match.group("language", "body")
        if language == "mermaid":
            # Only quoted node labels may be localized; IDs, edges and directives stay exact.
            body = re.sub(r'\["[^"\n]*"\]', '["LABEL"]', body)
        blocks.append((language, body))
    return blocks


def sections(document):
    prose = FENCE.sub("", document)
    return [
        (len(level), re.match(r"([0-9]+)\.", title).group(1) if re.match(r"([0-9]+)\.", title) else None)
        for level, title in re.findall(r"^(#{1,6})[ \t]+(.+)$", prose, re.MULTILINE)
    ]


def local_targets(path, document):
    targets = set()
    for target in re.findall(r"\]\(([^\s)]+)\)", document):
        url = urlsplit(target)
        if not url.scheme and not url.netloc and url.path:
            targets.add((path.parent / unquote(url.path)).resolve())
    return targets


@pytest.mark.parametrize("group", GROUPS, ids=("introduction", "handbook", "roadmap"))
@pytest.mark.parametrize("language", (1, 2), ids=("fr", "zh-CN"))
def test_translations_preserve_procedures_sections_and_language_navigation(group, language):
    canonical_path = ROOT / group[0]
    translated_path = ROOT / group[language]
    canonical = read_document(canonical_path)
    translated = read_document(translated_path)
    assert procedures(canonical), f"No canonical procedures in {canonical_path}"
    assert procedures(translated) == procedures(canonical), f"Procedure drift in {translated_path}"
    assert sections(translated) == sections(canonical), f"Section drift in {translated_path}"
    required = {(ROOT / entry).resolve() for entry in group}
    for path, document in ((canonical_path, canonical), (translated_path, translated)):
        assert required <= local_targets(path, document), f"Missing language navigation in {path}"
        assert all(target.is_file() for target in required)


def test_documentation_index_resolves_all_localized_entry_points():
    index = ROOT / "docs/README.md"
    required = {(ROOT / entry).resolve() for group in GROUPS[:2] for entry in group}
    assert required <= local_targets(index, read_document(index))
    assert all(target.is_file() for group in GROUPS for target in (ROOT / entry for entry in group))
