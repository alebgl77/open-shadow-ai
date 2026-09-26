"""Static deployment validation and safe bootstrap regression checks."""
from __future__ import annotations
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
import yaml

root = Path(__file__).resolve().parents[1]
for pattern in ("docker-compose*.yml", "deploy/**/*.yaml", "config/*.example", ".github/**/*.yml"):
    for path in root.glob(pattern):
        if path.suffix == ".example" and path.name == ".env.example":
            continue
        list(yaml.safe_load_all(path.read_text(encoding="utf-8-sig")))
for path in (root / "docs/assets").glob("*"):
    if path.suffix in {".svg", ".drawio"}:
        ET.parse(path)
with tempfile.TemporaryDirectory(prefix="open-shadow-ai-bootstrap-") as temporary:
    target = Path(temporary) / "pilot"
    command = [sys.executable, str(root / "scripts/bootstrap.py"), "--directory", str(target)]
    result = subprocess.run([*command, "--dry-run"], check=True, capture_output=True, text=True)
    assert not target.exists(), "Dry run wrote files"
    generated = subprocess.run(command, check=True, capture_output=True, text=True)
    before = {path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()}
    generated = subprocess.run(command, check=True, capture_output=True, text=True)
    after = {path.relative_to(target): path.read_bytes() for path in target.rglob("*") if path.is_file()}
    assert before == after, "Bootstrap overwrote existing configuration"
    assert len(list((target / "secrets").glob("*.txt"))) == 6
    for value in before.values():
        assert value.decode().strip() not in result.stdout + generated.stdout, "Secret in output"
    # Windows read-only files must be writable for TemporaryDirectory cleanup.
    for path in (target / "secrets").glob("*.txt"):
        path.chmod(0o600)
print("PASS: YAML/XML, bootstrap dry run, six generated secrets, repeat-run preservation")
