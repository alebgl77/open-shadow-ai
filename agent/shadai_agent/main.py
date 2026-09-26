"""ShadAI Agent entry point."""

from __future__ import annotations

import logging
import signal
import time
from datetime import UTC, datetime

import requests

from shadai_agent.collectors.browser_ext import collect_extensions
from shadai_agent.collectors.container import collect_containers
from shadai_agent.collectors.local_ai import detect_local_ai, detect_model_files
from shadai_agent.collectors.process import collect_processes
from shadai_agent.config import load_agent_config

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("shadai-agent")

_running = True


def _handle_signal(signum, frame):
    global _running
    logger.info(f"Received signal {signum}, shutting down...")
    _running = False


def main():
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    config = load_agent_config()
    logger.info(f"ShadAI Agent starting on {config.hostname} (poll every {config.poll_interval_seconds}s)")

    while _running:
        try:
            batch = {"hostname": config.hostname, "agent_version": "0.1.0", "timestamp": datetime.now(UTC).isoformat()}

            # Collect processes
            if config.collect_processes:
                processes = collect_processes()
                batch["processes"] = processes
                logger.info(f"Collected {len(processes)} processes")
            else:
                batch["processes"] = []
                processes = []

            # Collect containers
            if config.collect_containers:
                containers = collect_containers()
                batch["containers"] = containers
                logger.info(f"Collected {len(containers)} containers")
            else:
                batch["containers"] = []

            # Detect local AI
            if config.collect_local_ai:
                ai_hits = detect_local_ai(processes)
                model_files = detect_model_files()
                batch["local_ai_hits"] = ai_hits
                batch["model_files"] = model_files
                if ai_hits:
                    logger.info(f"Detected {len(ai_hits)} local AI processes")
            else:
                batch["local_ai_hits"] = []
                batch["model_files"] = []

            # Collect browser extensions
            if config.collect_extensions:
                extensions = collect_extensions()
                batch["extensions"] = extensions
                logger.info(f"Collected {len(extensions)} browser extensions")
            else:
                batch["extensions"] = []

            # Send telemetry
            url = f"{config.server_url.rstrip('/')}/api/v1/agent/telemetry"
            headers = {"X-API-Key": config.api_key, "Content-Type": "application/json"}

            for attempt in range(3):
                try:
                    resp = requests.post(url, json=batch, headers=headers, timeout=30, verify=config.ca_bundle or True)
                    if resp.status_code == 200:
                        data = resp.json()
                        logger.info(f"Telemetry sent: {data.get('received', 0)} events accepted")
                        break
                    else:
                        logger.warning(f"Server returned HTTP {resp.status_code}")
                except requests.RequestException as e:
                    logger.warning(f"Send attempt {attempt + 1} failed: {type(e).__name__}")
                    time.sleep(2**attempt)

        except Exception as e:
            logger.error(f"Collection error: {type(e).__name__}")

        # Sleep with interruptibility
        for _ in range(config.poll_interval_seconds):
            if not _running:
                break
            time.sleep(1)

    logger.info("ShadAI Agent stopped")


if __name__ == "__main__":
    main()
