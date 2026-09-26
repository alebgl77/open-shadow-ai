"""Resolve mounted database secrets without printing them, then replace this process."""
import os
import sys
from pathlib import Path
from urllib.parse import quote

def secret(name: str) -> str:
    return Path(os.environ[name]).read_text(encoding="utf-8").strip()

if "DATABASE_URL" not in os.environ and os.environ.get("PG_PASSWORD_FILE"):
    password = quote(secret("PG_PASSWORD_FILE"), safe="")
    os.environ["DATABASE_URL"] = f"postgresql+asyncpg://shadai:{password}@postgres:5432/shadai"
if "REDIS_URL" not in os.environ and os.environ.get("REDIS_PASSWORD_FILE"):
    password = quote(secret("REDIS_PASSWORD_FILE"), safe="")
    os.environ["REDIS_URL"] = f"redis://:{password}@redis:6379/0"
if len(sys.argv) < 2:
    raise SystemExit("A service command is required")
os.execvp(sys.argv[1], sys.argv[1:])
