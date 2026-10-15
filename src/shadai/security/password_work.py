"""Lifespan-owned, bounded native password work for async request handlers."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import TypeVar

import anyio
import bcrypt

from shadai.security.auth import hash_password

# Generated once at cost 12. Never generate a dummy hash on a request or at startup.
DUMMY_HASH = "$2b$12$3ilQsmZfdehUk47oao9/l.aDCCbpFcQ2YswM.rd43G8iNGwiBvhcm"
_DUMMY_PASSWORD = b"shadai-invalid-password"
T = TypeVar("T")


class PasswordWorkBusyError(Exception):
    """All native password slots are occupied."""


class PasswordWorkUnavailableError(Exception):
    """The lifespan's password worker cannot accept work."""


def _verify_password(plain: str, hashed: str) -> bool:
    try:
        encoded = plain.encode("utf-8")
    except UnicodeError:
        encoded = _DUMMY_PASSWORD
        valid_input = False
    else:
        valid_input = len(encoded) <= 72
        if not valid_input:
            encoded = _DUMMY_PASSWORD
    if not valid_input:
        bcrypt.checkpw(encoded, DUMMY_HASH.encode("ascii"))
        return False
    try:
        return bcrypt.checkpw(encoded, hashed.encode("utf-8"))
    except (ValueError, UnicodeError):
        bcrypt.checkpw(encoded, DUMMY_HASH.encode("ascii"))
        return False


class PasswordWork:
    """A permit belongs to its native job, never to the task awaiting it."""

    def __init__(self, workers: int = 4):
        if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 16:
            raise ValueError("Password workers must be an integer between 1 and 16")
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="shadai-password")
        self._slots = threading.BoundedSemaphore(workers)
        self._admission_lock = threading.Lock()
        self._closed = False

    async def verify(self, plain: str, hashed: str) -> bool:
        return await self._run(_verify_password, plain, hashed)

    async def hash(self, plain: str) -> str:
        return await self._run(hash_password, plain)

    async def _run(self, operation: Callable[..., T], *args: str | bytes) -> T:
        if any(not isinstance(arg, (str, bytes)) for arg in args):
            raise TypeError("Password workers accept only text or bytes")
        loop = asyncio.get_running_loop()
        # This owned future is independent of both executor and asyncio cancellation.
        job: Future[T] = Future()

        def native_wrapper():
            if not job.set_running_or_notify_cancel():
                return
            try:
                result = operation(*args)
            except BaseException as exc:
                job.set_exception(exc)
            else:
                job.set_result(result)

        def native_done(native):
            if native.cancelled():
                job.cancel()
            elif (error := native.exception()) is not None:
                # A wrapper failure before RUNNING must also settle the owned job.
                if not job.done() and (job.running() or job.set_running_or_notify_cancel()):
                    job.set_exception(error)

        with self._admission_lock:
            if self._closed:
                raise PasswordWorkUnavailableError() from None
            if not self._slots.acquire(blocking=False):
                raise PasswordWorkBusyError() from None
            job.add_done_callback(lambda _: self._slots.release())
            try:
                native = self._executor.submit(native_wrapper)
                native.add_done_callback(native_done)
            except BaseException as exc:
                # submit() can enqueue before thread startup raises. Poison and drain
                # that executor; a RUNNING job alone continues to own its permit.
                self._closed = True
                job.cancel()
                self._executor.shutdown(wait=False, cancel_futures=True)
                if not isinstance(exc, Exception):
                    raise
                raise PasswordWorkUnavailableError() from None

        waiter = loop.create_future()
        waiter.add_done_callback(lambda done: None if done.cancelled() else done.exception())

        def deliver():
            if waiter.done():
                return
            if job.cancelled():
                waiter.set_exception(PasswordWorkUnavailableError())
            elif (error := job.exception()) is not None:
                waiter.set_exception(error)
            else:
                waiter.set_result(job.result())

        def completed(_):
            try:
                loop.call_soon_threadsafe(deliver)
            except RuntimeError:
                # The originating request loop may already have been closed.
                pass

        job.add_done_callback(completed)
        return await waiter

    def close(self) -> None:
        """Stop admission and cancel work that has not started."""
        with self._admission_lock:
            self._closed = True
            self._executor.shutdown(wait=False, cancel_futures=True)

    async def aclose(self) -> None:
        """Drain native threads off-loop, even when the shutdown task is cancelled."""
        self.close()
        loop = asyncio.get_running_loop()
        try:
            joined = loop.run_in_executor(None, self._executor.shutdown, True)
        except RuntimeError:
            # A stopped default executor cannot host the join. Cleanup still wins.
            self._executor.shutdown(wait=True, cancel_futures=True)
            return
        cancelled = None
        with anyio.CancelScope(shield=True):
            while True:
                try:
                    await asyncio.shield(joined)
                    break
                except asyncio.CancelledError as exc:
                    if joined.cancelled():
                        # The join future itself was lost, rather than just its
                        # awaiting task. Finish cleanup before preserving cancellation.
                        self._executor.shutdown(wait=True, cancel_futures=True)
                        raise
                    cancelled = exc
        if cancelled is not None:
            raise cancelled
