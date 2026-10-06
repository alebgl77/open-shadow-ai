"""Monotonic HTTP deadlines enforced by disposable, explicitly reaped children."""

import base64
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

from shadai.qualification.schemas import QualificationError

MAX_BODY = 16 * 1048576
MAX_OUTPUT = 90000
CLEANUP_SECONDS = 1


class HttpTransport:
    def __init__(self, cancelled=None, *, clock=time.monotonic):
        self.cancelled = cancelled or threading.Event()
        self.clock = clock
        self._children = set()
        self._lock = threading.Lock()

    @property
    def children(self):
        with self._lock:
            return tuple(self._children)

    def request(self, url, *, deadline, timeout, method="GET", body=b"", credential=""):
        started = self.clock()
        request_deadline = min(deadline, started + timeout)
        if self.cancelled.is_set() or started >= request_deadline:
            return 0, b"", "unconfirmed"
        if len(body) > MAX_BODY or len(credential) > 4096 or len(url) > 8192:
            raise QualificationError("HTTP envelope exceeds its private byte budget")
        payload = json.dumps(
            {
                "schema": 1,
                "method": method,
                "url": url,
                "body": base64.b64encode(body).decode(),
                "credential": credential,
                "timeout_seconds": min(timeout, request_deadline - started),
            },
            separators=(",", ":"),
            allow_nan=False,
        ).encode()
        if len(payload) > 4 * ((MAX_BODY + 2) // 3) + 65536:
            raise QualificationError("HTTP envelope exceeds its private byte budget")
        if self.cancelled.is_set() or self.clock() >= request_deadline:
            return 0, b"", "unconfirmed"
        child = None
        try:
            child = subprocess.Popen(
                [sys.executable, "-I", str(Path(__file__).with_name("http_worker.py").resolve())],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            with self._lock:
                self._children.add(child)
            first = True
            while True:
                remaining = request_deadline - self.clock()
                if self.cancelled.is_set() or remaining <= 0:
                    return 0, b"", "unconfirmed"
                try:
                    output, _ = child.communicate(input=payload if first else None, timeout=min(0.1, remaining))
                    if self.cancelled.is_set() or self.clock() >= request_deadline:
                        return 0, b"", "unconfirmed"
                    break
                except subprocess.TimeoutExpired:
                    first = False
            if child.returncode or len(output) > MAX_OUTPUT:
                raise QualificationError("HTTP worker did not produce bounded proof")
            result = json.loads(output)
            if (
                not isinstance(result, dict)
                or set(result) != {"schema", "status", "body", "error"}
                or type(result["schema"]) is not int
                or result["schema"] != 1
                or type(result["status"]) is not int
                or result["status"] != 0
                and not 100 <= result["status"] <= 599
                or result["error"] not in {"none", "transport", "body_limit", "protocol"}
                or not isinstance(result["body"], str)
            ):
                raise QualificationError("HTTP worker proof is malformed")
            content = base64.b64decode(result["body"], validate=True)
            if len(content) > 65536 or result["error"] in {"body_limit", "protocol"}:
                raise QualificationError("HTTP response exceeds its proof boundary")
            return result["status"], content, result["error"]
        except (OSError, ValueError) as error:
            if isinstance(error, QualificationError):
                raise
            raise QualificationError("HTTP transport prerequisite failed") from None
        finally:
            if child is not None:
                try:
                    self._reap(child)
                finally:
                    with self._lock:
                        self._children.discard(child)

    @staticmethod
    def _reap(child):
        cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
        try:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=max(0.001, cleanup_deadline - time.monotonic()))
            child.wait(timeout=max(0.001, cleanup_deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            raise QualificationError("HTTP child could not be reaped within its cleanup budget") from None
        finally:
            for pipe in (child.stdin, child.stdout):
                if pipe is not None:
                    pipe.close()
