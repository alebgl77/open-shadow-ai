"""Bounded ownership of the optional POSIX browser process group."""

import os
import signal
import subprocess
import threading
import time

from shadai.qualification.schemas import QualificationError


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise QualificationError("Qualification wall budget exhausted")
    return value


def run_browser_group(command, *, deadline, cancelled=None):
    if os.name != "posix":
        raise QualificationError("Optional browser proof requires POSIX process-group cleanup")
    stopped = cancelled or threading.Event()
    remaining(deadline)
    if stopped.is_set():
        raise QualificationError("Optional browser proof cancelled")
    child = None
    group = None
    try:
        child = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        # start_new_session makes this child the leader of this owned group.
        group = child.pid
        while True:
            if stopped.is_set():
                raise QualificationError("Optional browser proof cancelled")
            budget = remaining(deadline)
            try:
                code = child.wait(timeout=min(0.1, budget))
                if code:
                    raise QualificationError("Optional browser proof unavailable")
                return
            except subprocess.TimeoutExpired:
                pass
    finally:
        if child is not None:
            cleanup_group(group, child)


def cleanup_group(group, child):
    def send(sig):
        try:
            os.killpg(group, sig)
        except ProcessLookupError:
            pass

    # Group cleanup also runs after Node exits: abandoned browser descendants
    # cannot survive merely because their direct parent produced a proof file.
    try:
        send(signal.SIGTERM)
        grace = time.monotonic() + 0.5
        while time.monotonic() < grace:
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                break
            time.sleep(min(0.02, max(0, grace - time.monotonic())))
        send(signal.SIGKILL)
        child.wait(timeout=1)
    except (OSError, subprocess.TimeoutExpired):
        raise QualificationError("Optional browser group cleanup could not be proved") from None
