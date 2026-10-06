"""A real child process reserves stdout for its strict operational JSON result."""

import json
import runpy
import subprocess
import sys
from pathlib import Path


def test_operational_child_diagnostics_remain_on_stderr_and_stdout_is_exact_json():
    fixture = Path(__file__).with_name("test_operational_health_integration.py")
    child = runpy.run_path(str(fixture))["CHILD"]
    # Exercise the actual child configuration without requiring a Redis service;
    # the real-store test continues to execute the full consumer/ACK path.
    prefix, _ = child.rsplit("asyncio.run(run())", 1)
    protocol = prefix + """
structlog.get_logger().warning('message_processing_failed', error_type='OSError', message_id='synthetic-protocol')
print(json.dumps({'duplicate_ack': 1}))
"""
    result = subprocess.run([sys.executable, "-c", protocol], capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0
    assert json.loads(result.stdout) == {"duplicate_ack": 1}
    assert len(result.stdout.splitlines()) == 1
    assert "message_processing_failed" in result.stderr and "synthetic-protocol" in result.stderr
    assert "message_processing_failed" not in result.stdout
