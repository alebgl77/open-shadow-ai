"""Docker/Podman container collector."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def collect_containers() -> list[dict]:
    """List running containers with image, ports, and status."""
    try:
        import docker

        client = docker.from_env()
        containers = client.containers.list()
        results = []
        for c in containers:
            ports = c.ports or {}
            exposed_port = 0
            for container_port, host_bindings in ports.items():
                if host_bindings:
                    exposed_port = int(host_bindings[0].get("HostPort", 0))
                    break

            results.append(
                {
                    "name": c.name,
                    "image": c.image.tags[0] if c.image.tags else str(c.image.id)[:12],
                    "status": c.status,
                    "port": exposed_port,
                }
            )
        return results
    except ImportError:
        logger.debug("docker package not installed, skipping container collection")
        return []
    except Exception as e:
        logger.warning(f"Container collection failed: {e}")
        return []
