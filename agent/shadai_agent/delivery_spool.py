"""Bounded private metadata spool; stdlib only, vendored verbatim by the endpoint agent.

FULL-synchronous SQLite transactions persist immutable bytes before delivery. Claims
are leases, so a killed sender can resume; logical event IDs must remain in payloads
to suppress an acknowledged-but-unrecorded delivery. Quarantine shares the budget.
"""

from __future__ import annotations

import hashlib
import os
import random
import sqlite3
import stat
import subprocess
import threading
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_BATCHES = 2048
DEFAULT_TTL_SECONDS = 7 * 86400
MAX_BYTES = 16 * 1024 * 1024 * 1024
MAX_BATCHES = 100_000
MAX_TTL_SECONDS = 365 * 86400
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024
MAX_CLAIM_BATCHES = 64
MAX_CLAIM_BYTES = 16 * 1024 * 1024


class SpoolError(RuntimeError):
    """A bounded, secret-free reason suitable for operational reporting."""


class SpoolFullError(SpoolError):
    pass


@dataclass(frozen=True)
class PendingBatch:
    batch_id: str
    payload: bytes
    token: str
    attempts: int


def default_spool_dir(component: str) -> Path:
    if not component or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in component):
        raise ValueError("Invalid spool component")
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local")))
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state")))
    return base / "shadai" / component


def _windows_private(path: Path, *, create: bool = False) -> bool:
    """Create or verify a current-user/SYSTEM/Administrators-only native DACL."""
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = """
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$allowed = @($sid.Value, 'S-1-5-18', 'S-1-5-32-544')
if ($env:SHADAI_SPOOL_CREATE_PRIVATE -eq '1') {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($identity in $allowed) {
        $principal = New-Object Security.Principal.SecurityIdentifier($identity)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl',
            'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [IO.Directory]::CreateDirectory($env:SHADAI_SPOOL_PRIVATE_PATH, $acl) | Out-Null
}
$item = Get-Item -LiteralPath $env:SHADAI_SPOOL_PRIVATE_PATH -Force
if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 1 }
$acl = Get-Acl -LiteralPath $item.FullName
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { exit 1 }
foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed) { exit 1 }
}
exit 0
"""
    environment = {key: value for key, value in os.environ.items() if key.casefold() != "psmodulepath"}
    environment["PSMODULEPATH"] = str(powershell.parent / "Modules")
    environment["SHADAI_SPOOL_PRIVATE_PATH"] = str(path)
    environment["SHADAI_SPOOL_CREATE_PRIVATE"] = "1" if create else "0"
    try:
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-NonInteractive", "-Command", script], env=environment,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _check_path(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise SpoolError("spool_unsafe_path")
    if os.name == "nt":
        if not _windows_private(path):
            raise SpoolError("spool_private_acl_required")
    elif stat.S_IMODE(info.st_mode) & 0o077 or info.st_uid != os.getuid():
        raise SpoolError("spool_private_permissions_required")
    if not directory and info.st_nlink != 1:
        raise SpoolError("spool_unsafe_hardlink")


def _check_sqlite_sidecars(database: Path) -> None:
    """Validate fixed optional SQLite files without mistaking removal for privacy."""
    for suffix in ("-journal", "-wal", "-shm"):
        path = Path(str(database) + suffix)
        try:
            _check_path(path, directory=False)
        except FileNotFoundError:
            continue
        except SpoolError as error:
            if os.name != "nt" or str(error) != "spool_private_acl_required":
                raise
            # Another SQLite connection may remove its journal after lstat but
            # before native Get-Item/Get-Acl. Only definitive absence is optional;
            # a present file or unknown/read failure still fails closed.
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            raise


def _private_ancestors(path: Path) -> None:
    """Reject directories that another user can replace while SQLite opens files."""
    if os.name != "nt":
        for ancestor in path.parents:
            info = ancestor.stat()
            if info.st_uid not in {0, os.getuid()} or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                raise SpoolError("spool_unsafe_parent")
        return
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = """
$ErrorActionPreference = 'Stop'
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
# Windows volume roots may be owned/managed by the exact TrustedInstaller service.
# This ancestor trust does not relax the private leaf/database DACL.
$allowed = @($sid, 'S-1-5-18', 'S-1-5-32-544',
             'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
$directory = [IO.DirectoryInfo]$env:SHADAI_SPOOL_PARENT_PATH
while ($null -ne $directory) {
    if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 1 }
    $acl = Get-Acl -LiteralPath $directory.FullName
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { exit 1 }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $allowed -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band 852032)) { exit 1 }
    }
    $directory = $directory.Parent
}
exit 0
"""
    environment = {key: value for key, value in os.environ.items() if key.casefold() != "psmodulepath"}
    environment["PSMODULEPATH"] = str(powershell.parent / "Modules")
    environment["SHADAI_SPOOL_PARENT_PATH"] = str(path.parent)
    try:
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
                                env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=15, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired):
        raise SpoolError("spool_unsafe_parent") from None
    if result.returncode:
        raise SpoolError("spool_unsafe_parent")


def _private_directory(path: Path) -> Path:
    # Check lexical ancestors before resolving: resolve() would hide a symlink.
    path = Path(os.path.abspath(path.expanduser()))
    for ancestor in (*reversed(path.parents), path):
        if ancestor.exists() or ancestor.is_symlink():
            info = ancestor.lstat()
            if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise SpoolError("spool_unsafe_path")
    if os.name == "nt" and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not _windows_private(path, create=True):
            raise SpoolError("spool_private_acl_required")
    else:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_ancestors(path)
    _check_path(path, directory=True)
    return path


class DurableSpool:
    def __init__(self, directory: str | Path, *, max_bytes: int = DEFAULT_MAX_BYTES,
                 max_batches: int = DEFAULT_MAX_BATCHES, ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 clock=time.time):
        if not 1 <= max_bytes <= MAX_BYTES or not 1 <= max_batches <= MAX_BATCHES:
            raise ValueError("Spool budget exceeds supported bounds")
        if not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError("Spool TTL must be 1 second to 365 days and within server ingestion age")
        self.max_bytes, self.max_batches, self.ttl_seconds = max_bytes, max_batches, ttl_seconds
        self.clock = clock
        self.directory = _private_directory(Path(directory))
        self.owner = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._volatile = Counter()
        database = self.directory / "delivery.sqlite3"
        try:
            descriptor = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            pass
        else:
            os.close(descriptor)
        _check_path(database, directory=False)
        _check_sqlite_sidecars(database)
        self.db = sqlite3.connect(database, timeout=5, isolation_level=None, check_same_thread=False)
        try:
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA secure_delete=ON")
            self.db.execute("PRAGMA auto_vacuum=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS batches (
                    id TEXT PRIMARY KEY, payload BLOB NOT NULL, created REAL NOT NULL, event_count INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
                    next_at REAL NOT NULL DEFAULT 0, token TEXT, lease_until REAL NOT NULL DEFAULT 0,
                    reason TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS batches_due ON batches(state, next_at, lease_until);
                CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS bindings (scope TEXT PRIMARY KEY, digest TEXT NOT NULL);
            """)
            # Persist the first directory entry, as well as SQLite's FULL commits.
            if os.name != "nt":
                descriptor = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except (OSError, sqlite3.Error):
            self.db.close()
            raise SpoolError("spool_storage_failure") from None

    @contextmanager
    def _transaction(self):
        with self._lock:
            try:
                self.db.execute("BEGIN IMMEDIATE")
                yield
                self.db.execute("COMMIT")
            except sqlite3.Error:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                self._volatile["storage_failures"] += 1
                raise SpoolError("spool_storage_failure") from None
            except Exception:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise

    def _count(self, name: str, amount: int = 1) -> None:
        self.db.execute("INSERT INTO counters VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                        (name, amount))

    def _expire(self) -> None:
        cutoff = self.clock() - self.ttl_seconds
        expired = self.db.execute("SELECT coalesce(sum(event_count),0) FROM batches WHERE created<=?",
                                  (cutoff,)).fetchone()[0]
        removed = self.db.execute("DELETE FROM batches WHERE created <= ?", (cutoff,)).rowcount
        if removed:
            self._count("expired", removed)
            self._count("expired_events", expired)

    def enqueue(self, payload: bytes, *, event_count: int = 1) -> str:
        try:
            return self._enqueue(payload, event_count=event_count)
        except SpoolFullError:
            raise
        except SpoolError:
            self._volatile["storage_failed_events"] += event_count
            raise

    def _enqueue(self, payload: bytes, *, event_count: int) -> str:
        if not isinstance(payload, bytes) or not payload:
            raise ValueError("Spool requires nonempty immutable bytes")
        if not isinstance(event_count, int) or isinstance(event_count, bool) or not 0 <= event_count <= 1_000_000:
            raise ValueError("Invalid event count")
        batch_id = hashlib.sha256(payload).hexdigest()
        full = False
        with self._transaction():
            self._expire()
            if self.db.execute("SELECT 1 FROM batches WHERE id=?", (batch_id,)).fetchone():
                return batch_id
            count, size = self.db.execute("SELECT count(*), coalesce(sum(length(payload)),0) FROM batches").fetchone()
            if count >= self.max_batches or size + len(payload) > self.max_bytes or len(payload) > MAX_PAYLOAD_BYTES:
                self._count("overflow")
                self._count("overflow_events", event_count)
                full = True
            else:
                self.db.execute("INSERT INTO batches(id,payload,created,event_count) VALUES (?,?,?,?)",
                                (batch_id, payload, self.clock(), event_count))
                self._count("enqueued")
                self._count("enqueued_events", event_count)
        if full:
            raise SpoolFullError("spool_batch_size_exceeded" if len(payload) > MAX_PAYLOAD_BYTES
                                 else "spool_budget_exceeded")
        return batch_id

    def claim(self, *, limit: int = 50, lease_seconds: int = 120) -> list[PendingBatch]:
        if not 1 <= limit <= MAX_CLAIM_BATCHES or not 1 <= lease_seconds <= 300:
            raise ValueError("Invalid spool claim bounds")
        limit = min(limit, self.max_batches)
        batches = []
        with self._transaction():
            self._expire()
            rows = self.db.execute(
                "SELECT id,length(payload),attempts FROM batches "
                "WHERE state='pending' AND next_at<=? AND lease_until<=? "
                "ORDER BY created,id LIMIT ?", (self.clock(), self.clock(), limit),
            ).fetchall()
            total_bytes = 0
            for batch_id, payload_bytes, attempts in rows:
                if total_bytes + payload_bytes > MAX_CLAIM_BYTES:
                    break
                payload = self.db.execute("SELECT payload FROM batches WHERE id=?", (batch_id,)).fetchone()[0]
                total_bytes += payload_bytes
                token = self.owner + ":" + uuid.uuid4().hex
                self.db.execute("UPDATE batches SET token=?,lease_until=? WHERE id=?",
                                (token, self.clock() + lease_seconds, batch_id))
                batches.append(PendingBatch(batch_id, bytes(payload), token, attempts))
        return batches

    def ack(self, batch: PendingBatch) -> bool:
        with self._transaction():
            row = self.db.execute("SELECT event_count FROM batches WHERE id=? AND token=?",
                                  (batch.batch_id, batch.token)).fetchone()
            removed = self.db.execute("DELETE FROM batches WHERE id=? AND token=?",
                                      (batch.batch_id, batch.token)).rowcount
            if removed:
                self._count("delivered")
                self._count("delivered_events", row[0])
        return bool(removed)

    def retry(self, batch: PendingBatch, *, delay: float | None = None) -> bool:
        attempts = min(batch.attempts + 1, 65535)
        delay = min(60, 2 ** min(attempts, 5)) * random.uniform(0.75, 1.25) if delay is None else delay
        if not 0 <= delay <= 300:
            raise ValueError("Invalid retry delay")
        with self._transaction():
            updated = self.db.execute(
                "UPDATE batches SET attempts=?,next_at=?,token=NULL,lease_until=0 WHERE id=? AND token=?",
                (attempts, self.clock() + delay, batch.batch_id, batch.token),
            ).rowcount
            if updated:
                self._count("delivery_failures")
                self._count("retried")
        return bool(updated)

    def quarantine(self, batch: PendingBatch, reason: str) -> bool:
        # Reasons are enums/status codes, never exception messages, URLs, keys, or payloads.
        if len(reason) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in reason):
            raise ValueError("Invalid quarantine reason")
        with self._transaction():
            row = self.db.execute("SELECT event_count FROM batches WHERE id=? AND token=?",
                                  (batch.batch_id, batch.token)).fetchone()
            updated = self.db.execute(
                "UPDATE batches SET state='quarantine',reason=?,token=NULL,lease_until=0 WHERE id=? AND token=?",
                (reason, batch.batch_id, batch.token),
            ).rowcount
            if updated:
                self._count("delivery_failures")
                self._count("quarantined")
                self._count("quarantined_events", row[0])
        return bool(updated)

    def stats(self) -> dict[str, int]:
        with self._transaction():
            self._expire()
            counters = dict(self.db.execute("SELECT name,value FROM counters").fetchall())
            count, size = self.db.execute("SELECT count(*),coalesce(sum(length(payload)),0) FROM batches").fetchone()
            pending = self.db.execute("SELECT count(*) FROM batches WHERE state='pending'").fetchone()[0]
            queued_events = self.db.execute(
                "SELECT coalesce(sum(event_count),0) FROM batches WHERE state='pending'",
            ).fetchone()[0]
            queued_bytes = self.db.execute(
                "SELECT coalesce(sum(length(payload)),0) FROM batches WHERE state='pending'",
            ).fetchone()[0]
        counters.update({"batches": count, "payload_bytes": size, "pending": pending, "quarantine": count - pending})
        counters["queued_events"] = queued_events
        counters["queued_bytes"] = queued_bytes
        for name, amount in self._volatile.items():
            counters[name] = counters.get(name, 0) + amount
        return counters

    def bind(self, scope: str, value: str) -> None:
        if scope not in {"target", "collector"} or not isinstance(value, str) or not value:
            raise ValueError("Invalid spool binding")
        digest = hashlib.sha256(value.encode()).hexdigest()
        with self._transaction():
            current = self.db.execute("SELECT digest FROM bindings WHERE scope=?", (scope,)).fetchone()
            if current is not None and current[0] != digest:
                raise SpoolError("spool_binding_mismatch")
            self.db.execute("INSERT OR IGNORE INTO bindings VALUES (?,?)", (scope, digest))

    def has_binding(self, scope: str) -> bool:
        if scope not in {"target", "collector"}:
            raise ValueError("Invalid spool binding")
        with self._transaction():
            return self.db.execute("SELECT 1 FROM bindings WHERE scope=?", (scope,)).fetchone() is not None

    def close(self) -> None:
        with self._lock:
            if self.db is None:
                return
            try:
                with self._transaction():
                    self.db.execute("UPDATE batches SET token=NULL,lease_until=0 WHERE token LIKE ?",
                                    (self.owner + ":%",))
            finally:
                self.db.close()
                self.db = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
