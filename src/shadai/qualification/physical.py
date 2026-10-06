"""Physical exporter proof against host /proc and statvfs, without filesystem sums."""

import os
import re
import subprocess
import time
from pathlib import Path

from shadai.qualification.processes import remaining
from shadai.qualification.schemas import QualificationError


def compare_scrape(metrics, memory, filesystem):
    def sample(name, match=None):
        rows = []
        for line in metrics.splitlines():
            result = re.fullmatch(re.escape(name) + r"(?:\{([^}]*)\})?\s+([0-9.eE+-]+)", line)
            if result and (match is None or match in (result[1] or "")):
                rows.append(float(result[2]))
        if len(rows) != 1:
            raise QualificationError("Required exporter series is absent or ambiguous")
        return rows[0]

    total = sample("node_memory_MemTotal_bytes")
    available = sample("node_memory_MemAvailable_bytes")
    size = sample("node_filesystem_size_bytes", 'mountpoint="/"')
    free = sample("node_filesystem_avail_bytes", 'mountpoint="/"')
    if total != memory["MemTotal"] or abs(available - memory["MemAvailable"]) > max(total * 0.05, 64 * 1048576):
        raise QualificationError("Memory scrape differs from host /proc outside time tolerance")
    if size != filesystem["size"] or abs(free - filesystem["available"]) > max(size * 0.01, 64 * 1048576):
        raise QualificationError("Filesystem scrape differs from host statvfs outside time tolerance")
    return {
        "memory_total_bytes": total,
        "memory_available_bytes": available,
        "root_filesystem_size_bytes": size,
        "root_filesystem_available_bytes": free,
        "provenance": "node_exporter actual scrape versus host /proc/meminfo and statvfs(/)",
        "memory_time_tolerance_fraction": 0.05,
        "filesystem_time_tolerance_fraction": 0.01,
        "filesystem_sum": False,
    }


def host_exporter_proof(context, project, exporter_id, *, deadline=None):
    started = time.monotonic()
    deadline = deadline if deadline is not None else started + 15
    remaining(deadline)
    memory = {
        line.split(":")[0]: int(line.split()[1]) * 1024
        for line in Path("/proc/meminfo").read_text().splitlines()
        if line.startswith(("MemTotal:", "MemAvailable:"))
    }
    disk = os.statvfs("/")
    filesystem = {"size": disk.f_blocks * disk.f_frsize, "available": disk.f_bavail * disk.f_frsize}
    # The target is an exact verified local exporter container. wget is present
    # in the official image's BusyBox base; no host/public listening port needed.
    result = subprocess.run(
        [
            "docker",
            "--context",
            context,
            "container",
            "exec",
            exporter_id,
            "wget",
            "-qO-",
            "http://127.0.0.1:9100/metrics",
        ],
        capture_output=True,
        text=True,
        timeout=min(15, remaining(deadline)),
    )
    if result.returncode or len(result.stdout) > 4 * 1048576 or time.monotonic() >= deadline:
        raise QualificationError("Actual exporter scrape is unavailable")
    return {
        **compare_scrape(result.stdout, memory, filesystem),
        "docker_project": project,
        "sample_interval_seconds": time.monotonic() - started,
    }
