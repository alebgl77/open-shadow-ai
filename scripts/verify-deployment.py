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
base = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8-sig"))
identity = yaml.safe_load((root / "docker-compose.sso.yml").read_text(encoding="utf-8-sig"))
assert set(identity["services"]) == {"api"}, "Identity configuration must remain API-only"
assert set(identity["secrets"]) == {"oidc_client_secret", "scim_bearer_token"}
assert len(base["services"]["api"]["secrets"]) == 6, "Base API secret requirements changed"
for service in base["services"].values():
    assert not any(
        key.startswith(("OIDC_", "SCIM_")) for key in service.get("environment", {})
    ), "Identity enabled in base deployment"
for name in identity["secrets"]:
    assert name not in base["secrets"], "Optional secret required by base deployment"
    assert identity["secrets"][name] == {"file": f"./secrets/{name}.txt"}
    assert identity["services"]["api"]["environment"].get({
        "oidc_client_secret": "OIDC_CLIENT_SECRET_FILE",
        "scim_bearer_token": "SCIM_BEARER_TOKEN_FILE",
    }[name]) == f"/run/secrets/{name}", "Identity secret mount and configuration disagree"
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
print("PASS: YAML/XML, API-only optional identity configuration, "
      "bootstrap dry run, six generated secrets, repeat-run preservation")
