"""Agent configuration."""

from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass, field
from pathlib import Path

import yaml


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
        config.api_key = Path(key_path).read_text().strip()
    elif key := os.environ.get("AGENT_API_KEY"):
        config.api_key = key
    if ca := os.environ.get("SHADAI_CA_BUNDLE"):
        config.ca_bundle = ca
    if len(config.api_key.encode()) < 32:
        raise ValueError("A strong agent API key is required")
    if not config.server_url.startswith("https://"):
        raise ValueError("Agent server_url must use HTTPS")
    if config.poll_interval_seconds < 30:
        raise ValueError("Poll interval must be at least 30 seconds")
    return config
