"""Agent configuration."""

from __future__ import annotations

import os
import platform
import socket
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from shadai_agent.delivery_spool import MAX_BATCHES, MAX_BYTES, MAX_TTL_SECONDS, _check_path


@dataclass
class AgentConfig:
    server_url: str = "https://localhost:8443"
    api_key: str = ""
    ca_bundle: str = ""
    poll_interval_seconds: int = 300
    collect_processes: bool = True
    collect_containers: bool = True
    collect_extensions: bool = True
    collect_local_ai: bool = True
    hostname: str = field(default_factory=socket.gethostname)
    platform: str = field(default_factory=platform.system)
    collector_id: str = ""
    spool_dir: str = ""
    spool_max_bytes: int = 64 * 1024 * 1024
    spool_max_batches: int = 2048
    spool_ttl_seconds: int = 7 * 86400


def load_agent_config(path: str | None = None) -> AgentConfig:
    path = path or os.environ.get("SHADAI_AGENT_CONFIG", "shadai-agent.yaml")
    config = AgentConfig()
    if Path(path).exists():
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        for key, value in raw.items():
            if hasattr(config, key):
                setattr(config, key, value)
    if key_path := os.environ.get("AGENT_API_KEY_FILE"):
        key_file = Path(key_path)
        _check_path(key_file, directory=False)
        before = key_file.lstat()
        if before.st_size > 4096:
            raise ValueError("Invalid agent API key file")
        descriptor = os.open(key_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            opened = os.fstat(source.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(opened.st_mode):
                raise ValueError("Agent API key file changed while opening")
            config.api_key = source.read(4097).strip()
    elif key := os.environ.get("AGENT_API_KEY"):
        config.api_key = key
    if ca := os.environ.get("SHADAI_CA_BUNDLE"):
        config.ca_bundle = ca
    if spool_dir := os.environ.get("SHADAI_AGENT_SPOOL_DIR"):
        config.spool_dir = spool_dir
    if not 32 <= len(config.api_key.encode()) <= 4096 or any(ord(c) < 32 for c in config.api_key):
        raise ValueError("A strong agent API key is required")
    if not config.server_url.startswith("https://"):
        raise ValueError("Agent server_url must use HTTPS")
    endpoint = urlsplit(config.server_url)
    if (not endpoint.hostname or endpoint.username is not None or endpoint.password is not None
            or endpoint.query or endpoint.fragment or endpoint.path not in {"", "/"}
            or any(c.isspace() or ord(c) < 32 for c in config.server_url) or "\\" in config.server_url):
        raise ValueError("Agent server_url must be an HTTPS origin without credentials")
    _ = endpoint.port
    if config.poll_interval_seconds < 30:
        raise ValueError("Poll interval must be at least 30 seconds")
    if (not 1 <= config.spool_max_bytes <= MAX_BYTES
            or not 1 <= config.spool_max_batches <= MAX_BATCHES
            or not 1 <= config.spool_ttl_seconds <= MAX_TTL_SECONDS):
        raise ValueError("Invalid durable spool bounds")
    return config
