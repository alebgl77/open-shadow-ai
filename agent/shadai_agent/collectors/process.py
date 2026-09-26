"""Process and socket collector using psutil."""

from __future__ import annotations

import psutil


def collect_processes() -> list[dict]:
    """Collect all running processes with key attributes."""
    results = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "ppid", "create_time"]):
        try:
            info = proc.info
            entry = {
                "pid": info["pid"],
                "name": info.get("name", ""),
                "path": info.get("exe", "") or "",
                "username": info.get("username", "") or "",
                "parent": "",
            }
            # Get parent process name
            if info.get("ppid"):
                try:
                    parent = psutil.Process(info["ppid"])
                    entry["parent"] = parent.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Check for listening ports
            try:
                connections = proc.net_connections(kind="inet")
                for conn in connections:
                    if conn.status == "LISTEN":
                        entry["listening_port"] = conn.laddr.port
                        break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            results.append(entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results
