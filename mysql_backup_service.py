#!/usr/bin/env python3
"""MySQL Backup Service v2.1.

Production-oriented MySQL logical full + binary-log differential backup daemon.

Highlights:
- Per-database schedules and retention policies.
- Encrypted backups (age, GPG, or OpenSSL AES-256-CBC/PBKDF2).
- Atomic rclone remote replication to S3-compatible, B2, SFTP, FTP, and others.
- Optional S3-compatible Object Lock retention through AWS CLI.
- Exact point-in-time recovery using mysqlbinlog --stop-datetime.
- Scheduled Docker restore verification.
- GFS smart retention.
- Process, local-stream, and remote bandwidth throttling.
- Table exclusion and schema-only table backup.

The implementation intentionally uses only the Python standard library. Optional
features call mature external tools (rclone, age/gpg/openssl, aws, docker).
"""

from __future__ import annotations

import argparse
import configparser
import contextlib
import datetime as dt
import fcntl
import gzip
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import BinaryIO, Iterator, List, Optional, Sequence, Set, Tuple
from urllib import request as urllib_request

VERSION = "2.1.0"
DEFAULT_CONFIG = "/etc/mysql-backup-service/mysql-backup.conf"
SYSTEM_DATABASES = {"information_schema", "performance_schema", "sys"}
LOG = logging.getLogger("mysql-backup-service")
STOP_REQUESTED = False


class BackupError(RuntimeError):
    pass


def now_local() -> dt.datetime:
    return dt.datetime.now().astimezone()


def iso_now() -> str:
    return now_local().isoformat(timespec="seconds")


def timestamp_for_file(value: Optional[dt.datetime] = None) -> str:
    return (value or now_local()).strftime("%Y-%m-%d_%H-%M-%S")


def parse_iso(value: str) -> dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise BackupError(f"invalid datetime {value!r}; use ISO format such as 2026-09-20 14:37:12") from exc
    if parsed.tzinfo is None:
        # Interpret naive input as local wall-clock time at *that historical date*.
        # Using now_local().tzinfo would freeze today's UTC offset and can be wrong
        # across DST transitions. time.mktime() asks the OS timezone database to
        # resolve the supplied local date/time instead.
        try:
            epoch = time.mktime(parsed.timetuple()) + parsed.microsecond / 1_000_000
            parsed = dt.datetime.fromtimestamp(epoch).astimezone()
        except (OverflowError, OSError, ValueError) as exc:
            raise BackupError(f"datetime is outside the supported local-time range: {value!r}") from exc
    return parsed


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on", "y"}:
        return True
    if normalized in {"0", "false", "no", "off", "n"}:
        return False
    raise BackupError(f"invalid boolean value: {value!r}")


def csv_list(value: str) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def safe_db_dir(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip(".")
    if not cleaned:
        cleaned = "database"
    if cleaned != name:
        cleaned += "_" + hashlib.sha1(name.encode("utf-8")).hexdigest()[:8]
    return cleaned


def validate_mysql_identifier(value: str, label: str = "identifier") -> str:
    # Database/table names are passed as command arguments. Reject control
    # characters, path-like values, and option-looking names so a legitimate
    # MySQL identifier can never be reinterpreted as a client CLI flag.
    if (
        not value
        or value.startswith("-")
        or any(ord(ch) < 32 for ch in value)
        or "/" in value
        or "\\" in value
    ):
        raise BackupError(f"invalid MySQL {label}: {value!r}")
    return value


def sql_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def sql_identifier(value: str) -> str:
    return "`" + value.replace("`", "``") + "`"


def human_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fsync_file(path: Path) -> None:
    with path.open("rb") as fh:
        os.fsync(fh.fileno())


def fsync_directory(path: Path) -> None:
    # Directory fsync makes rename/create metadata durable across sudden power
    # loss on filesystems that support it. Some network filesystems reject it;
    # that should not invalidate an otherwise complete backup.
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_json_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
        fsync_directory(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)


def atomic_text_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
        fsync_directory(path.parent)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)


class Settings:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists():
            raise BackupError(f"config file not found: {self.path}")
        parser = configparser.ConfigParser(
            interpolation=None,
            inline_comment_prefixes=("#", ";"),
        )
        parser.read(self.path, encoding="utf-8")
        self.p = parser

    def get(self, section: str, key: str, default: str = "") -> str:
        return self.p.get(section, key, fallback=default).strip()

    def getint(self, section: str, key: str, default: int) -> int:
        try:
            return self.p.getint(section, key, fallback=default)
        except ValueError as exc:
            raise BackupError(f"{section}.{key} must be an integer") from exc

    def getfloat(self, section: str, key: str, default: float) -> float:
        try:
            return self.p.getfloat(section, key, fallback=default)
        except ValueError as exc:
            raise BackupError(f"{section}.{key} must be numeric") from exc

    def getbool(self, section: str, key: str, default: bool) -> bool:
        return parse_bool(self.get(section, key, str(default)), default)

    @property
    def backup_root(self) -> Path:
        root = Path(self.get("general", "backup_root", "/backup"))
        namespace = self.get("general", "backup_namespace", "mysql_backup")
        return root / namespace

    @property
    def state_dir(self) -> Path:
        return Path(self.get("general", "state_dir", "/var/lib/mysql-backup-service"))

    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def lock_file(self) -> Path:
        return Path(self.get("general", "lock_file", "/run/mysql-backup-service.lock"))

    def database_section(self, db: str) -> str:
        return f"database:{db}"

    def database_sections(self) -> List[str]:
        return sorted(section.split(":", 1)[1] for section in self.p.sections() if section.startswith("database:"))

    def db_get(self, db: str, key: str, global_section: str, global_key: Optional[str] = None, default: str = "") -> str:
        section = self.database_section(db)
        if self.p.has_option(section, key):
            return self.get(section, key, default)
        return self.get(global_section, global_key or key, default)

    def db_getint(self, db: str, key: str, global_section: str, global_key: Optional[str], default: int) -> int:
        value = self.db_get(db, key, global_section, global_key, str(default))
        try:
            return int(value)
        except ValueError as exc:
            raise BackupError(f"database:{db}.{key} must be an integer") from exc

    def db_getbool(self, db: str, key: str, global_section: str, global_key: Optional[str], default: bool) -> bool:
        return parse_bool(self.db_get(db, key, global_section, global_key, str(default)), default)

    def validate(self) -> None:
        # Parse every supported boolean up front so typos such as `treu` fail
        # config-test instead of silently disabling a safety feature.
        boolean_options = [
            ("general", "verify_after_backup", True),
            ("general", "verify_before_restore", True),
            ("general", "write_sha256_file", True),
            ("general", "stop_on_database_error", False),
            ("mysql", "set_gtid_purged_off", True),
            ("mysql", "no_tablespaces", True),
            ("mysql", "add_drop_database", True),
            ("schedule", "full_on_start_if_missing", True),
            ("diff", "enabled", True),
            ("diff", "filter_by_database", True),
            ("diff", "require_row_binlog", True),
            ("encryption", "enabled", False),
            ("remote", "enabled", False),
            ("remote", "prune_with_local", False),
            ("object_lock", "enabled", False),
            ("restore_test", "enabled", False),
            ("notifications", "on_success", False),
            ("notifications", "on_failure", True),
        ]
        if self.p.has_section("restore_target"):
            boolean_options.append(("restore_target", "enabled", False))
        for section, key, default in boolean_options:
            self.getbool(section, key, default)

        if self.getint("schedule", "poll_seconds", 20) < 1:
            raise BackupError("schedule.poll_seconds must be >= 1")
        if self.getint("schedule", "retry_cooldown_seconds", 300) < 0:
            raise BackupError("schedule.retry_cooldown_seconds must be >= 0")
        if self.getint("retention", "full_days", 30) < 0 or self.getint("retention", "diff_days", 14) < 0:
            raise BackupError("retention days must be >= 0")
        if self.getint("retention", "minimum_full_backups", 2) < 0:
            raise BackupError("retention.minimum_full_backups must be >= 0")
        for key in ("gfs_daily", "gfs_weekly", "gfs_monthly"):
            if self.getint("retention", key, 0) < 0:
                raise BackupError(f"retention.{key} must be >= 0")
        if self.getint("remote", "retries", 3) < 1:
            raise BackupError("remote.retries must be >= 1")
        if self.getfloat("throttle", "local_stream_mbps", 0.0) < 0:
            raise BackupError("throttle.local_stream_mbps must be >= 0")
        io_class = self.getint("throttle", "ionice_class", 0)
        if io_class not in {0, 1, 2, 3}:
            raise BackupError("throttle.ionice_class must be 0, 1, 2, or 3")
        if not 0 <= self.getint("throttle", "ionice_level", 7) <= 7:
            raise BackupError("throttle.ionice_level must be between 0 and 7")
        if not -20 <= self.getint("throttle", "nice", 0) <= 19:
            raise BackupError("throttle.nice must be between -20 and 19")
        if self.getint("restore_test", "startup_timeout_seconds", 120) < 1:
            raise BackupError("restore_test.startup_timeout_seconds must be >= 1")

        for section in ("mysql", "restore_target"):
            if section == "restore_target" and not self.p.has_section(section):
                continue
            mode = self.get(section, "mode", self.get("mysql", "mode", "native")).lower()
            if mode not in {"native", "docker"}:
                raise BackupError(f"{section}.mode must be native or docker")
            self.getint(section, "port", self.getint("mysql", "port", 3306))
            self.getint(section, "container_port", self.getint("mysql", "container_port", 3306))

        # Validate global schedules.
        for key in ("full", "diff"):
            expr = self.get("schedule", key, "off")
            if expr.lower() != "off":
                CronSchedule(expr)
        rt = self.get("restore_test", "schedule", "off")
        if rt.lower() != "off":
            CronSchedule(rt)

        if self.getint("general", "gzip_level", 6) not in range(1, 10):
            raise BackupError("general.gzip_level must be between 1 and 9")

        provider = self.get("encryption", "provider", "none").lower()
        if provider not in {"none", "age", "gpg", "openssl"}:
            raise BackupError("encryption.provider must be none, age, gpg, or openssl")
        if self.getbool("encryption", "enabled", False):
            if provider == "none":
                raise BackupError("encryption.enabled=true requires a provider")
            if provider == "age" and not self.get("encryption", "age_recipient", ""):
                raise BackupError("age encryption requires encryption.age_recipient")
            if provider == "gpg" and not self.get("encryption", "gpg_recipient", ""):
                raise BackupError("GPG encryption requires encryption.gpg_recipient")
            if provider == "openssl" and not self.get("encryption", "openssl_passphrase_file", ""):
                raise BackupError("OpenSSL encryption requires encryption.openssl_passphrase_file")
            if provider == "openssl" and self.getint("encryption", "openssl_pbkdf2_iterations", 200000) < 1:
                raise BackupError("encryption.openssl_pbkdf2_iterations must be >= 1")

        if self.getbool("remote", "enabled", False):
            if self.get("remote", "backend", "rclone").lower() != "rclone":
                raise BackupError("remote.backend currently supports rclone")
            if not self.get("remote", "destination", ""):
                raise BackupError("remote.enabled=true requires remote.destination")

        if self.getbool("object_lock", "enabled", False):
            if not self.getbool("remote", "enabled", False):
                raise BackupError("Object Lock requires remote.enabled=true")
            if not self.get("object_lock", "bucket", ""):
                raise BackupError("object_lock.bucket is required")
            mode = self.get("object_lock", "mode", "GOVERNANCE").upper()
            if mode not in {"GOVERNANCE", "COMPLIANCE"}:
                raise BackupError("object_lock.mode must be GOVERNANCE or COMPLIANCE")
            if self.getint("object_lock", "retention_days", 30) < 1:
                raise BackupError("object_lock.retention_days must be >= 1")

        global_excluded = set(csv_list(self.get("tables", "exclude_tables", "")))
        global_schema_only = set(csv_list(self.get("tables", "schema_only_tables", "")))
        if global_excluded & global_schema_only:
            raise BackupError("tables: a table cannot be both excluded and schema-only")
        if (global_excluded or global_schema_only) and self.getbool("diff", "enabled", True) and self.get("schedule", "diff", "off").lower() != "off":
            raise BackupError(
                "global table exclusion/schema-only policy requires schedule.diff=off; "
                "use per-database table policy with diff_schedule=off when only selected databases need it"
            )

        for db in self.database_sections():
            validate_mysql_identifier(db, "database name")
            if self.p.has_option(self.database_section(db), "enabled"):
                self.getbool(self.database_section(db), "enabled", True)
            for key in ("full_days", "diff_days", "minimum_full_backups", "gfs_daily", "gfs_weekly", "gfs_monthly"):
                if self.p.has_option(self.database_section(db), key) and self.db_getint(db, key, "retention", key, 0) < 0:
                    raise BackupError(f"database:{db}.{key} must be >= 0")
            for key, global_section in (("full_schedule", "schedule"), ("diff_schedule", "schedule")):
                global_key = "full" if key.startswith("full") else "diff"
                expr = self.db_get(db, key, global_section, global_key, "off")
                if expr.lower() != "off":
                    CronSchedule(expr)
            excluded = set(csv_list(self.db_get(db, "exclude_tables", "tables", "exclude_tables", "")))
            schema_only = set(csv_list(self.db_get(db, "schema_only_tables", "tables", "schema_only_tables", "")))
            overlap = excluded & schema_only
            if overlap:
                raise BackupError(f"database:{db}: tables cannot be both excluded and schema-only: {sorted(overlap)}")
            for table in excluded | schema_only:
                validate_mysql_identifier(table, "table name")
            diff_expr = self.db_get(db, "diff_schedule", "schedule", "diff", "off")
            if (excluded or schema_only) and self.getbool("diff", "enabled", True) and diff_expr.lower() != "off":
                raise BackupError(
                    f"database:{db}: table exclusion/schema-only policies require diff_schedule=off; "
                    "mysqlbinlog cannot safely exclude individual tables from executable row-event replay"
                )


class StateStore:
    def __init__(self, settings: Settings):
        self.path = settings.state_file
        self.data = {
            "version": VERSION,
            "scheduler": {},
            "databases": {},
            "restore_test": {},
            "last_error": None,
            "last_success": None,
        }
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                existing = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(existing, dict):
                    self.data.update(existing)
            except Exception as exc:
                LOG.warning("Could not read state file %s: %s", self.path, exc)
        self.data["version"] = VERSION

    def save(self) -> None:
        atomic_json_write(self.path, self.data)

    def db(self, name: str) -> dict:
        return self.data.setdefault("databases", {}).setdefault(name, {})

    def set_error(self, message: str) -> None:
        self.data["last_error"] = {"time": iso_now(), "message": message}
        self.save()

    def set_success(self) -> None:
        self.data["last_success"] = iso_now()
        self.data["last_error"] = None
        self.save()


class BackupLock:
    def __init__(self, path: Path, blocking: bool = False):
        self.path = path
        self.blocking = blocking
        self.fh = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = self.path.open("a+")
        flags = fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(self.fh.fileno(), flags)
        except BlockingIOError as exc:
            self.fh.close()
            raise BackupError("another backup/restore operation is already running") from exc
        self.fh.seek(0)
        self.fh.truncate()
        self.fh.write(str(os.getpid()))
        self.fh.flush()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.fh:
            with contextlib.suppress(Exception):
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()


class CronField:
    def __init__(self, expr: str, minimum: int, maximum: int, dow: bool = False):
        self.expr = expr.strip()
        self.minimum = minimum
        self.maximum = maximum
        self.dow = dow
        self.is_wildcard = self.expr == "*"
        self.values = self._parse(self.expr)

    def _normalize(self, n: int) -> int:
        if self.dow and n == 7:
            return 0
        return n

    def _parse(self, expr: str) -> Set[int]:
        result: Set[int] = set()
        for part in expr.split(","):
            part = part.strip()
            if not part:
                raise BackupError(f"invalid cron field: {expr!r}")
            base, sep, step_text = part.partition("/")
            try:
                step = int(step_text) if sep else 1
            except ValueError as exc:
                raise BackupError(f"invalid cron step: {part!r}") from exc
            if step <= 0:
                raise BackupError(f"invalid cron step: {step}")
            try:
                if base == "*":
                    start, end = self.minimum, self.maximum
                elif "-" in base:
                    a, b = base.split("-", 1)
                    start, end = int(a), int(b)
                else:
                    start = end = int(base)
            except ValueError as exc:
                raise BackupError(f"invalid cron value: {part!r}") from exc
            if start > end:
                raise BackupError("cron ranges may not wrap around")
            for n in range(start, end + 1, step):
                normalized = self._normalize(n)
                if not (self.minimum <= normalized <= self.maximum):
                    raise BackupError(f"cron value out of range: {n} in {expr!r}")
                result.add(normalized)
        return result

    def matches(self, value: int) -> bool:
        return self._normalize(value) in self.values


class CronSchedule:
    def __init__(self, expr: str):
        parts = expr.split()
        if len(parts) != 5:
            raise BackupError(f"cron expression must have 5 fields: {expr!r}")
        self.expr = expr
        self.minute = CronField(parts[0], 0, 59)
        self.hour = CronField(parts[1], 0, 23)
        self.dom = CronField(parts[2], 1, 31)
        self.month = CronField(parts[3], 1, 12)
        self.dow = CronField(parts[4], 0, 6, dow=True)

    def matches(self, when: dt.datetime) -> bool:
        cron_dow = (when.weekday() + 1) % 7
        if not self.minute.matches(when.minute) or not self.hour.matches(when.hour) or not self.month.matches(when.month):
            return False
        dom_match = self.dom.matches(when.day)
        dow_match = self.dow.matches(cron_dow)
        if self.dom.is_wildcard and self.dow.is_wildcard:
            return True
        if self.dom.is_wildcard:
            return dow_match
        if self.dow.is_wildcard:
            return dom_match
        return dom_match or dow_match

    def next_runs(self, start: Optional[dt.datetime] = None, count: int = 3) -> List[dt.datetime]:
        cursor = (start or now_local()).replace(second=0, microsecond=0) + dt.timedelta(minutes=1)
        found: List[dt.datetime] = []
        limit = cursor + dt.timedelta(days=370)
        while cursor <= limit and len(found) < count:
            if self.matches(cursor):
                found.append(cursor)
            cursor += dt.timedelta(minutes=1)
        return found


@dataclass
class DatabasePolicy:
    database: str
    enabled: bool
    full_schedule: str
    diff_schedule: str
    full_days: int
    diff_days: int
    minimum_full_backups: int
    gfs_daily: int
    gfs_weekly: int
    gfs_monthly: int
    exclude_tables: List[str]
    schema_only_tables: List[str]


class RateLimiter:
    def __init__(self, mbps: float):
        self.bytes_per_second = max(0.0, mbps) * 1024 * 1024
        self.started = time.monotonic()
        self.total = 0

    def account(self, n: int) -> None:
        if self.bytes_per_second <= 0:
            return
        self.total += n
        expected = self.total / self.bytes_per_second
        elapsed = time.monotonic() - self.started
        if expected > elapsed:
            time.sleep(expected - elapsed)


def copy_limited(src: BinaryIO, dst: BinaryIO, mbps: float = 0.0, chunk_size: int = 1024 * 1024) -> int:
    limiter = RateLimiter(mbps)
    total = 0
    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            break
        dst.write(chunk)
        total += len(chunk)
        limiter.account(len(chunk))
    return total


class MySQLClient:
    def __init__(self, settings: Settings, section: str = "mysql"):
        self.s = settings
        requested_section = section
        if section != "mysql" and (not self.s.p.has_section(section) or not self.s.getbool(section, "enabled", False)):
            section = "mysql"
        self.section = section
        self.requested_section = requested_section
        self.uses_fallback = requested_section != "mysql" and section == "mysql"

        def cfg(key: str, default: str = "") -> str:
            if section != "mysql" and self.s.p.has_option(section, key):
                return self.s.get(section, key, default)
            return self.s.get("mysql", key, default)

        def cfg_int(key: str, default: int) -> int:
            if section != "mysql" and self.s.p.has_option(section, key):
                return self.s.getint(section, key, default)
            return self.s.getint("mysql", key, default)

        self._cfg = cfg
        self.mode = cfg("mode", "native").lower()
        if self.mode not in {"native", "docker"}:
            raise BackupError(f"{section}.mode must be native or docker")
        self.host = cfg("host", "127.0.0.1")
        self.port = cfg_int("port", 3306)
        self.socket = cfg("socket", "")
        self.user = cfg("user", "backup")
        self.password = cfg("password", "")
        self.defaults_file = cfg("defaults_extra_file", "")
        self.container = cfg("container", "mysql")
        # Docker Official mysql:8.4 is based on mysql-community-server-minimal
        # and does not ship mysqlbinlog. A companion tools container can be
        # configured without changing the database container itself.
        self.binlog_container = cfg("binlog_container", "").strip() or self.container
        self.container_host = cfg("container_host", "127.0.0.1")
        self.container_port = cfg_int("container_port", 3306)
        self._dump_help: Optional[str] = None

    def _priority_prefix(self) -> List[str]:
        prefix: List[str] = []
        io_class = self.s.getint("throttle", "ionice_class", 0)
        io_level = self.s.getint("throttle", "ionice_level", 7)
        if io_class and shutil.which("ionice"):
            prefix += ["ionice", "-c", str(io_class)]
            if io_class in {2, 3} and io_class != 3:
                prefix += ["-n", str(max(0, min(7, io_level)))]
        nice_level = self.s.getint("throttle", "nice", 0)
        if nice_level and shutil.which("nice"):
            prefix += ["nice", "-n", str(nice_level)]
        return prefix

    def _base_tool(self, tool: str, *, for_binlog: bool = False, priority: bool = True) -> Tuple[List[str], dict]:
        env = os.environ.copy()
        if self.password:
            env["MYSQL_PWD"] = self.password
        if self.mode == "docker":
            args = ["docker", "exec", "-i"]
            if self.password:
                args += ["-e", f"MYSQL_PWD={self.password}"]
            tool_container = self.binlog_container if tool == "mysqlbinlog" else self.container
            args += [tool_container, tool]
            host, port = self.container_host, self.container_port
        else:
            args = [tool]
            host, port = self.host, self.port
        if self.defaults_file:
            args.append(f"--defaults-extra-file={self.defaults_file}")
        args.append(f"--user={self.user}")
        if self.socket and not for_binlog and self.mode == "native":
            args.append(f"--socket={self.socket}")
        else:
            args += [f"--host={host}", f"--port={port}"]
        return (self._priority_prefix() + args if priority else args), env

    @staticmethod
    def run(args: Sequence[str], env: Optional[dict] = None, check: bool = True, timeout: Optional[int] = None) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(list(args), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise BackupError(f"required executable not found: {args[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise BackupError(f"command timed out after {timeout}s: {args[0]}") from exc
        if check and proc.returncode != 0:
            detail = proc.stderr.strip() or proc.stdout.strip()
            raise BackupError(f"command failed ({proc.returncode}): {detail}")
        return proc

    def query(self, sql: str, check: bool = True) -> List[List[str]]:
        args, env = self._base_tool("mysql", priority=False)
        args += ["--batch", "--skip-column-names", "--raw", "--execute", sql]
        proc = self.run(args, env, check=check)
        if proc.returncode != 0:
            return []
        return [line.split("\t") for line in proc.stdout.splitlines()]

    def server_version(self) -> str:
        rows = self.query("SELECT VERSION()")
        return rows[0][0] if rows else "unknown"

    def variable(self, name: str) -> str:
        rows = self.query(f"SHOW VARIABLES LIKE {sql_quote(name)}")
        return rows[0][1] if rows and len(rows[0]) > 1 else ""

    def databases(self) -> List[str]:
        rows = self.query("SHOW DATABASES")
        include = csv_list(self.s.get("mysql", "include_databases", "*")) or ["*"]
        exclude = set(csv_list(self.s.get("mysql", "exclude_databases", "information_schema,performance_schema,sys,mysql")))
        found = [r[0] for r in rows if r and r[0] not in SYSTEM_DATABASES and r[0] not in exclude]
        if include != ["*"]:
            allowed = set(include)
            found = [db for db in found if db in allowed]
        return sorted(found)

    def binary_log_status(self) -> Tuple[str, int]:
        rows = self.query("SHOW BINARY LOG STATUS", check=False) or self.query("SHOW MASTER STATUS", check=False)
        if not rows or len(rows[0]) < 2:
            raise BackupError("binary logging unavailable or backup user cannot read binary log status")
        return rows[0][0], int(rows[0][1])

    def binary_logs(self) -> List[str]:
        return [r[0] for r in self.query("SHOW BINARY LOGS") if r]

    def dump_help(self) -> str:
        if self._dump_help is None:
            if self.mode == "docker":
                args = ["docker", "exec", "-i", self.container, "mysqldump", "--help"]
            else:
                args = ["mysqldump", "--help"]
            proc = self.run(args, check=False)
            self._dump_help = proc.stdout + proc.stderr
        return self._dump_help

    def source_data_option(self) -> str:
        text = self.dump_help()
        if "--source-data" in text:
            return "--source-data=2"
        if "--master-data" in text:
            return "--master-data=2"
        raise BackupError("mysqldump lacks --source-data/--master-data")

    def dump_command(self, database: str, need_coordinates: bool, ignore_tables: Sequence[str] = ()) -> Tuple[List[str], dict]:
        validate_mysql_identifier(database, "database")
        args, env = self._base_tool("mysqldump")
        help_text = self.dump_help()
        args += ["--single-transaction", "--quick", "--routines", "--events", "--triggers", "--hex-blob", "--default-character-set=utf8mb4"]
        if "--set-gtid-purged" in help_text and self.s.getbool("mysql", "set_gtid_purged_off", True):
            args.append("--set-gtid-purged=OFF")
        if "--no-tablespaces" in help_text and self.s.getbool("mysql", "no_tablespaces", True):
            args.append("--no-tablespaces")
        if need_coordinates:
            args.append(self.source_data_option())
        if self.s.getbool("mysql", "add_drop_database", True) and database not in {"mysql", "information_schema", "performance_schema", "sys"}:
            args.append("--add-drop-database")
        for table in ignore_tables:
            args.append(f"--ignore-table={database}.{validate_mysql_identifier(table, 'table')}")
        extra = self.s.get("mysql", "dump_extra_args", "")
        if extra:
            args += shlex.split(extra)
        args += ["--databases", database]
        return args, env

    def schema_only_command(self, database: str, tables: Sequence[str]) -> Tuple[List[str], dict]:
        validate_mysql_identifier(database, "database")
        args, env = self._base_tool("mysqldump")
        help_text = self.dump_help()
        args += ["--no-data", "--triggers", "--hex-blob", "--default-character-set=utf8mb4"]
        if "--set-gtid-purged" in help_text:
            args.append("--set-gtid-purged=OFF")
        if "--no-tablespaces" in help_text:
            args.append("--no-tablespaces")
        args += [database]
        args += [validate_mysql_identifier(t, "table") for t in tables]
        return args, env

    def mysqlbinlog_command(self, database: str, logs: Sequence[str], start_position: Optional[int] = None, stop_position: Optional[int] = None, stop_datetime: Optional[str] = None, to_last_log: bool = False) -> Tuple[List[str], dict]:
        validate_mysql_identifier(database, "database")
        args, env = self._base_tool("mysqlbinlog", for_binlog=True)
        args += ["--read-from-remote-server", "--verify-binlog-checksum"]
        if self.s.getbool("diff", "filter_by_database", True):
            args.append(f"--database={database}")
        if start_position is not None:
            args.append(f"--start-position={start_position}")
        if stop_position is not None:
            args.append(f"--stop-position={stop_position}")
        if stop_datetime:
            args.append(f"--stop-datetime={stop_datetime}")
        if to_last_log:
            args.append("--to-last-log")
        extra = self.s.get("mysql", "mysqlbinlog_extra_args", "")
        if extra:
            args += shlex.split(extra)
        args += list(logs)
        return args, env

    def mysql_restore_command(self) -> Tuple[List[str], dict]:
        args, env = self._base_tool("mysql", priority=False)
        args.append("--binary-mode")
        extra = self._cfg("mysql_extra_args", "")
        if extra:
            args += shlex.split(extra)
        return args, env

    def mysqlbinlog_timezone(self, when: Optional[dt.datetime] = None) -> dt.tzinfo:
        # mysqlbinlog interprets --stop-datetime in the local timezone of the
        # machine/container where the utility runs. Resolve the offset at the
        # requested historical instant so DST transitions are handled correctly.
        when = when or now_local()
        if self.mode == "native":
            return dt.datetime.fromtimestamp(when.timestamp()).astimezone().tzinfo or dt.timezone.utc
        epoch = int(when.timestamp())
        proc = self.run(["docker", "exec", self.binlog_container, "date", "-d", f"@{epoch}", "+%z"], check=False)
        if proc.returncode != 0:
            LOG.warning("Container date does not support historical offset lookup; using its current UTC offset")
            proc = self.run(["docker", "exec", self.binlog_container, "date", "+%z"], check=False)
        text = proc.stdout.strip() if proc.returncode == 0 else ""
        match = re.fullmatch(r"([+-])(\d{2})(\d{2})", text)
        if not match:
            LOG.warning("Could not determine mysqlbinlog container timezone; using host local timezone")
            return dt.datetime.fromtimestamp(when.timestamp()).astimezone().tzinfo or dt.timezone.utc
        sign = 1 if match.group(1) == "+" else -1
        minutes = sign * (int(match.group(2)) * 60 + int(match.group(3)))
        return dt.timezone(dt.timedelta(minutes=minutes))


COORD_PATTERNS = [
    re.compile(r"SOURCE_LOG_FILE='([^']+)'.*SOURCE_LOG_POS=(\d+)", re.I),
    re.compile(r"MASTER_LOG_FILE='([^']+)'.*MASTER_LOG_POS=(\d+)", re.I),
]


def parse_dump_coordinates(path: Path) -> Optional[Tuple[str, int]]:
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i > 1000:
                    break
                for pattern in COORD_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        return match.group(1), int(match.group(2))
    except Exception as exc:
        raise BackupError(f"could not inspect dump coordinates in {path}: {exc}") from exc
    return None


class EncryptionManager:
    def __init__(self, settings: Settings):
        self.s = settings
        self.enabled = self.s.getbool("encryption", "enabled", False)
        self.provider = self.s.get("encryption", "provider", "none").lower()

    @property
    def extension(self) -> str:
        if not self.enabled:
            return ""
        return {"age": ".age", "gpg": ".gpg", "openssl": ".enc"}[self.provider]

    def required_tool(self) -> Optional[str]:
        if not self.enabled:
            return None
        return {"age": "age", "gpg": "gpg", "openssl": "openssl"}[self.provider]

    def metadata(self) -> dict:
        metadata = {"enabled": self.enabled, "provider": self.provider if self.enabled else "none"}
        if self.enabled and self.provider == "openssl":
            metadata.update({
                "cipher": "aes-256-cbc",
                "kdf": "pbkdf2",
                "pbkdf2_iterations": self.s.getint("encryption", "openssl_pbkdf2_iterations", 200000),
            })
        return metadata

    def encrypt(self, source: Path, destination_partial: Path) -> None:
        if not self.enabled:
            shutil.copyfile(source, destination_partial)
            return
        if self.provider == "age":
            cmd = ["age", "--encrypt", "--recipient", self.s.get("encryption", "age_recipient", ""), "--output", str(destination_partial), str(source)]
        elif self.provider == "gpg":
            cmd = ["gpg", "--batch", "--yes", "--trust-model", "always"]
            homedir = self.s.get("encryption", "gpg_homedir", "")
            if homedir:
                cmd += ["--homedir", homedir]
            cmd += ["--encrypt", "--recipient", self.s.get("encryption", "gpg_recipient", ""), "--output", str(destination_partial), str(source)]
        elif self.provider == "openssl":
            passfile = self.s.get("encryption", "openssl_passphrase_file", "")
            iterations = self.s.getint("encryption", "openssl_pbkdf2_iterations", 200000)
            cmd = ["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", str(iterations), "-pass", f"file:{passfile}", "-in", str(source), "-out", str(destination_partial)]
        else:
            raise BackupError(f"unsupported encryption provider: {self.provider}")
        MySQLClient.run(cmd)

    @contextlib.contextmanager
    def decrypted_binary_stream(self, source: Path, metadata: Optional[dict] = None) -> Iterator[BinaryIO]:
        enabled = self.enabled if metadata is None else parse_bool(str(metadata.get("enabled", False)), False)
        provider = self.provider if metadata is None else str(metadata.get("provider", "none")).lower()
        if not enabled:
            with source.open("rb") as fh:
                yield fh
            return
        if provider == "age":
            identity = self.s.get("encryption", "age_identity_file", "")
            if not identity:
                raise BackupError("restore/verify requires encryption.age_identity_file")
            cmd = ["age", "--decrypt", "--identity", identity, str(source)]
        elif provider == "gpg":
            cmd = ["gpg", "--batch", "--quiet"]
            homedir = self.s.get("encryption", "gpg_homedir", "")
            if homedir:
                cmd += ["--homedir", homedir]
            cmd += ["--decrypt", str(source)]
        elif provider == "openssl":
            passfile = self.s.get("encryption", "openssl_passphrase_file", "")
            cipher = str((metadata or {}).get("cipher", "aes-256-cbc")).lower()
            kdf = str((metadata or {}).get("kdf", "pbkdf2")).lower()
            if cipher != "aes-256-cbc" or kdf != "pbkdf2":
                raise BackupError(f"unsupported OpenSSL backup parameters: cipher={cipher}, kdf={kdf}")
            iterations = int((metadata or {}).get("pbkdf2_iterations", self.s.getint("encryption", "openssl_pbkdf2_iterations", 200000)))
            if iterations < 1:
                raise BackupError("invalid OpenSSL PBKDF2 iteration count in backup metadata")
            cmd = ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", str(iterations), "-pass", f"file:{passfile}", "-in", str(source)]
        else:
            raise BackupError(f"unsupported backup encryption provider: {provider}")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError as exc:
            raise BackupError(f"required executable not found: {cmd[0]}") from exc
        assert proc.stdout is not None
        try:
            yield proc.stdout
        finally:
            with contextlib.suppress(Exception):
                proc.stdout.close()
            stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            if proc.stderr:
                proc.stderr.close()
            rc = proc.wait()
            if rc != 0:
                raise BackupError(f"decryption failed ({rc}): {stderr.strip()}")

    @contextlib.contextmanager
    def payload_stream(self, source: Path, metadata: Optional[dict] = None) -> Iterator[BinaryIO]:
        with self.decrypted_binary_stream(source, metadata) as encrypted_or_plain:
            gz = gzip.GzipFile(fileobj=encrypted_or_plain, mode="rb")
            try:
                yield gz
            finally:
                gz.close()

    def verify_payload(self, source: Path, metadata: Optional[dict] = None) -> None:
        with self.payload_stream(source, metadata) as fh:
            for _ in iter(lambda: fh.read(1024 * 1024), b""):
                pass


class RemoteStore:
    def __init__(self, settings: Settings, root: Path):
        self.s = settings
        self.root = root
        self.enabled = self.s.getbool("remote", "enabled", False)
        self.destination = self.s.get("remote", "destination", "").rstrip("/")
        self.rclone_config = self.s.get("remote", "rclone_config", "")
        self.bwlimit = self.s.get("remote", "bwlimit", "")
        self.retries = self.s.getint("remote", "retries", 3)

    def _rclone(self, *parts: str, check: bool = True) -> subprocess.CompletedProcess:
        cmd = ["rclone", *parts]
        if self.rclone_config:
            cmd += ["--config", self.rclone_config]
        if self.bwlimit:
            cmd += ["--bwlimit", self.bwlimit]
        cmd += ["--retries", str(max(1, self.retries)), "--low-level-retries", str(max(1, self.retries * 2))]
        return MySQLClient.run(cmd, check=check)

    def relative_key(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError as exc:
            raise BackupError(f"remote upload path {path} is outside backup root {self.root}") from exc

    def remote_path(self, rel: str) -> str:
        return f"{self.destination}/{rel.lstrip('/')}"

    def _verify_remote_size(self, remote_path: str, expected: int) -> None:
        proc = self._rclone("lsjson", remote_path, "--stat")
        try:
            payload = json.loads(proc.stdout)
            actual = int(payload["Size"])
        except Exception as exc:
            raise BackupError(f"could not verify remote object size for {remote_path}") from exc
        if actual != expected:
            raise BackupError(f"remote size mismatch for {remote_path}: local={expected}, remote={actual}")

    def _object_lock_command(self, rel: str) -> Optional[List[str]]:
        if not self.s.getbool("object_lock", "enabled", False):
            return None
        bucket = self.s.get("object_lock", "bucket", "")
        prefix = self.s.get("object_lock", "prefix", "").strip("/")
        key = f"{prefix}/{rel}" if prefix else rel
        mode = self.s.get("object_lock", "mode", "GOVERNANCE").upper()
        days = self.s.getint("object_lock", "retention_days", 30)
        retain_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        cmd = ["aws", "s3api", "put-object-retention", "--bucket", bucket, "--key", key, "--retention", json.dumps({"Mode": mode, "RetainUntilDate": retain_until})]
        endpoint = self.s.get("object_lock", "endpoint_url", "")
        profile = self.s.get("object_lock", "aws_profile", "")
        region = self.s.get("object_lock", "region", "")
        if endpoint:
            cmd += ["--endpoint-url", endpoint]
        if profile:
            cmd += ["--profile", profile]
        if region:
            cmd += ["--region", region]
        return cmd

    def apply_object_lock(self, rel: str) -> None:
        cmd = self._object_lock_command(rel)
        if cmd:
            MySQLClient.run(cmd)

    def _remote_size_matches(self, remote_path: str, expected: int) -> bool:
        proc = self._rclone("lsjson", remote_path, "--stat", check=False)
        if proc.returncode != 0:
            return False
        try:
            payload = json.loads(proc.stdout)
            return int(payload["Size"]) == expected
        except Exception:
            return False

    def bundle_complete(self, data_path: Path) -> bool:
        if not self.enabled:
            return True
        manifest = Path(str(data_path) + ".json")
        if not manifest.exists():
            return False
        return self._remote_size_matches(self.remote_path(self.relative_key(manifest)), manifest.stat().st_size)

    def ensure_bundle(self, data_path: Path) -> None:
        if not self.enabled or self.bundle_complete(data_path):
            return
        manifest = Path(str(data_path) + ".json")
        if not manifest.exists():
            raise BackupError(f"cannot publish remote bundle without local manifest: {manifest}")
        sha = Path(str(data_path) + ".sha256")
        bundle = [data_path] + ([sha] if sha.exists() else []) + [manifest]
        LOG.warning("Remote completion marker missing; republishing base backup bundle: %s", data_path)
        self.upload_bundle(bundle)

    def upload_bundle(self, paths: Sequence[Path]) -> None:
        if not self.enabled:
            return
        manifests = [p for p in paths if p.name.endswith(".json")]
        if len(manifests) != 1:
            raise BackupError("remote backup bundle must contain exactly one manifest")
        manifest = manifests[0]
        ordered = [p for p in paths if p != manifest] + [manifest]
        staged: List[Tuple[Path, str, str]] = []
        finalized: List[Tuple[Path, str]] = []
        token = uuid.uuid4().hex[:12]
        try:
            # Staging objects are intentionally not completion markers. On S3
            # backends moveto may be implemented as copy+delete rather than an
            # atomic rename, so correctness relies on manifest-last publication.
            for path in ordered:
                rel = self.relative_key(path)
                final = self.remote_path(rel)
                if self._remote_size_matches(final, path.stat().st_size):
                    self.apply_object_lock(rel)
                    LOG.info("Remote object already present with matching size: %s", final)
                    continue
                partial = final + f".partial.{token}"
                self._rclone("copyto", str(path), partial)
                self._verify_remote_size(partial, path.stat().st_size)
                staged.append((path, partial, final))

            for path, partial, final in staged:
                self._rclone("moveto", partial, final)
                self._verify_remote_size(final, path.stat().st_size)
                finalized.append((path, final))
                rel = self.relative_key(path)
                self.apply_object_lock(rel)
                LOG.info("Remote upload finalized: %s", final)
        except Exception:
            for _, partial, _ in staged:
                with contextlib.suppress(Exception):
                    self._rclone("deletefile", partial, check=False)
            # Best-effort rollback. Object Lock may intentionally prevent deleting
            # payload objects; without the final manifest they are not considered
            # a complete backup bundle.
            for path, final in reversed(finalized):
                with contextlib.suppress(Exception):
                    self._rclone("deletefile", final, check=False)
            raise

    def delete_local_counterpart(self, path: Path) -> None:
        if not self.enabled or not self.s.getbool("remote", "prune_with_local", False):
            return
        remote = self.remote_path(self.relative_key(path))
        proc = self._rclone("deletefile", remote, check=False)
        if proc.returncode != 0:
            LOG.warning("Remote prune could not delete %s (possibly immutable/Object Locked): %s", remote, proc.stderr.strip())


class BackupManager:
    def __init__(self, settings: Settings):
        self.s = settings
        self.mysql = MySQLClient(settings, "mysql")
        self.restore_mysql = MySQLClient(settings, "restore_target")
        self.state = StateStore(settings)
        self.root = settings.backup_root
        self.root.mkdir(parents=True, exist_ok=True)
        self.s.state_dir.mkdir(parents=True, exist_ok=True)
        self.encryption = EncryptionManager(settings)
        self.remote = RemoteStore(settings, self.root)

    def db_paths(self, db: str) -> Tuple[Path, Path, Path]:
        base = self.root / safe_db_dir(db)
        return base, base / "full", base / "diff"

    def policy(self, db: str) -> DatabasePolicy:
        s = self.s.database_section(db)
        enabled = self.s.getbool(s, "enabled", True) if self.s.p.has_section(s) else True
        return DatabasePolicy(
            database=db,
            enabled=enabled,
            full_schedule=self.s.db_get(db, "full_schedule", "schedule", "full", "off"),
            diff_schedule=self.s.db_get(db, "diff_schedule", "schedule", "diff", "off"),
            full_days=self.s.db_getint(db, "full_days", "retention", "full_days", 30),
            diff_days=self.s.db_getint(db, "diff_days", "retention", "diff_days", 14),
            minimum_full_backups=self.s.db_getint(db, "minimum_full_backups", "retention", "minimum_full_backups", 2),
            gfs_daily=self.s.db_getint(db, "gfs_daily", "retention", "gfs_daily", 7),
            gfs_weekly=self.s.db_getint(db, "gfs_weekly", "retention", "gfs_weekly", 4),
            gfs_monthly=self.s.db_getint(db, "gfs_monthly", "retention", "gfs_monthly", 12),
            exclude_tables=csv_list(self.s.db_get(db, "exclude_tables", "tables", "exclude_tables", "")),
            schema_only_tables=csv_list(self.s.db_get(db, "schema_only_tables", "tables", "schema_only_tables", "")),
        )

    def databases(self) -> List[str]:
        discovered = set(self.mysql.databases())
        explicit = set(self.s.database_sections())
        selected = sorted(discovered | explicit)
        result: List[str] = []
        for db in selected:
            if db in discovered and self.policy(db).enabled:
                result.append(validate_mysql_identifier(db, "database"))
        return result

    @staticmethod
    def _unique_plain_path(folder: Path, filename: str) -> Path:
        candidate = folder / filename
        if not any(folder.glob(candidate.name + "*")):
            return candidate
        stem = candidate.name[:-7] if candidate.name.endswith(".sql.gz") else candidate.stem
        return folder / f"{stem}__{secrets.token_hex(4)}.sql.gz"

    def check_free_space(self) -> None:
        usage = shutil.disk_usage(self.root)
        min_mb = self.s.getint("general", "min_free_space_mb", 1024)
        min_pct = self.s.getfloat("general", "min_free_space_percent", 5.0)
        free_pct = (usage.free / usage.total * 100.0) if usage.total else 0.0
        if min_mb > 0 and usage.free < min_mb * 1024 * 1024:
            raise BackupError(f"free space below {min_mb} MiB: {human_bytes(usage.free)}")
        if min_pct > 0 and free_pct < min_pct:
            raise BackupError(f"free space below {min_pct}%: {free_pct:.1f}%")

    def _notify(self, status: str, backup_type: str, database: str, detail: str) -> None:
        url = self.s.get("notifications", "webhook_url", "")
        if not url:
            return
        if status == "success" and not self.s.getbool("notifications", "on_success", False):
            return
        if status != "success" and not self.s.getbool("notifications", "on_failure", True):
            return
        payload = json.dumps({"service": "mysql-backup-service", "version": VERSION, "time": iso_now(), "status": status, "type": backup_type, "database": database, "detail": detail}).encode("utf-8")
        try:
            req = urllib_request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            with urllib_request.urlopen(req, timeout=10) as response:
                response.read(1)
        except Exception as exc:
            LOG.warning("Webhook notification failed: %s", exc)

    def _stream_command_to_gzip(
        self, args: Sequence[str], env: dict, gz_path: Path, append: bool = False, prefix: bytes = b""
    ) -> None:
        mode = "ab" if append else "wb"
        rate = self.s.getfloat("throttle", "local_stream_mbps", 0.0)
        with tempfile.TemporaryFile() as err, gz_path.open(mode) as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=self.s.getint("general", "gzip_level", 6), mtime=0) as gz:
                if prefix:
                    gz.write(prefix)
                try:
                    proc = subprocess.Popen(list(args), env=env, stdout=subprocess.PIPE, stderr=err)
                except FileNotFoundError as exc:
                    raise BackupError(f"required executable not found: {args[0]}") from exc
                assert proc.stdout is not None
                stream_error: Optional[Exception] = None
                try:
                    copy_limited(proc.stdout, gz, rate)
                except Exception as exc:
                    stream_error = exc
                finally:
                    proc.stdout.close()
                rc = proc.wait()
            if rc != 0:
                err.seek(0)
                detail = err.read().decode("utf-8", errors="replace").strip()
                raise BackupError(f"backup command failed ({rc}): {detail}")
            if stream_error is not None:
                if isinstance(stream_error, BackupError):
                    raise stream_error
                raise BackupError(f"failed while writing backup stream: {stream_error}") from stream_error

    def _finalize_plain_backup(self, plain_gz: Path, final_base: Path, manifest: dict) -> Tuple[Path, Path, Optional[Path]]:
        final_path = Path(str(final_base) + self.encryption.extension)
        final_partial = Path(str(final_path) + ".partial")
        try:
            if self.encryption.enabled:
                self.encryption.encrypt(plain_gz, final_partial)
                fsync_file(final_partial)
                os.replace(final_partial, final_path)
            else:
                os.replace(plain_gz, final_path)
            fsync_file(final_path)
            fsync_directory(final_path.parent)
            digest = sha256_file(final_path)
            manifest.update({
                "version": VERSION,
                "file": final_path.name,
                "size_bytes": final_path.stat().st_size,
                "sha256": digest,
                "encryption": self.encryption.metadata(),
            })
            sha_path: Optional[Path] = None
            if self.s.getbool("general", "write_sha256_file", True):
                sha_path = Path(str(final_path) + ".sha256")
                atomic_text_write(sha_path, f"{digest}  {final_path.name}\n")
            # The manifest is the local and remote completion marker and is
            # therefore written/published last.
            manifest_path = Path(str(final_path) + ".json")
            atomic_json_write(manifest_path, manifest)
            bundle = [final_path] + ([sha_path] if sha_path else []) + [manifest_path]
            self.remote.upload_bundle(bundle)
            return final_path, manifest_path, sha_path
        finally:
            with contextlib.suppress(FileNotFoundError):
                final_partial.unlink()
            with contextlib.suppress(FileNotFoundError):
                plain_gz.unlink()

    @staticmethod
    def manifest_path(path: Path) -> Path:
        return Path(str(path) + ".json")

    @staticmethod
    def sha_path(path: Path) -> Path:
        return Path(str(path) + ".sha256")

    def read_manifest(self, path: Path) -> dict:
        mp = self.manifest_path(path)
        if not mp.exists():
            raise BackupError(f"manifest missing: {mp}")
        try:
            return json.loads(mp.read_text(encoding="utf-8"))
        except Exception as exc:
            raise BackupError(f"invalid manifest {mp}: {exc}") from exc

    def verify_backup(self, path: Path, expected_db: Optional[str] = None, expected_type: Optional[str] = None, deep: bool = True) -> dict:
        if not path.exists():
            raise BackupError(f"backup file missing: {path}")
        manifest = self.read_manifest(path)
        if expected_db and manifest.get("database") != expected_db:
            raise BackupError(f"database mismatch: expected {expected_db}, backup is {manifest.get('database')}")
        if expected_type and manifest.get("type") != expected_type:
            raise BackupError(f"backup type mismatch: expected {expected_type}, backup is {manifest.get('type')}")
        expected_hash = manifest.get("sha256")
        sidecar = self.sha_path(path)
        sidecar_hash: Optional[str] = None
        if sidecar.exists():
            try:
                parts = sidecar.read_text(encoding="utf-8").strip().split()
                if not parts:
                    raise ValueError("empty SHA-256 sidecar")
                sidecar_hash = parts[0].lower()
                if len(parts) > 1 and parts[-1] != path.name:
                    raise BackupError(f"SHA-256 sidecar filename mismatch for {path}")
            except BackupError:
                raise
            except Exception as exc:
                raise BackupError(f"invalid SHA-256 sidecar {sidecar}: {exc}") from exc
        if expected_hash or sidecar_hash:
            actual = sha256_file(path)
            if expected_hash and actual != str(expected_hash).lower():
                raise BackupError(f"SHA-256 mismatch for {path}")
            if sidecar_hash and actual != sidecar_hash:
                raise BackupError(f"SHA-256 sidecar mismatch for {path}")
            if expected_hash and sidecar_hash and str(expected_hash).lower() != sidecar_hash:
                raise BackupError(f"manifest/SHA-256 sidecar disagreement for {path}")
        if deep:
            self.encryption.verify_payload(path, manifest.get("encryption", {"enabled": False, "provider": "none"}))
        return manifest

    def create_full(self, db: str) -> Path:
        policy = self.policy(db)
        self.check_free_space()
        _, full_dir, _ = self.db_paths(db)
        full_dir.mkdir(parents=True, exist_ok=True)
        started = now_local()
        stamp = timestamp_for_file(started)
        plain_final = self._unique_plain_path(full_dir, f"{safe_db_dir(db)}__full__{stamp}.sql.gz")
        plain_partial = Path(str(plain_final) + ".partial")
        LOG.info("Full backup started: database=%s", db)
        try:
            ignored = sorted(set(policy.exclude_tables) | set(policy.schema_only_tables))
            need_coordinates = self.s.getbool("diff", "enabled", True) and not ignored
            args, env = self.mysql.dump_command(db, need_coordinates=need_coordinates, ignore_tables=ignored)
            self._stream_command_to_gzip(args, env, plain_partial)
            if policy.schema_only_tables:
                args, env = self.mysql.schema_only_command(db, policy.schema_only_tables)
                prefix = f"\n-- mysql-backup-service schema-only tables\nUSE {sql_identifier(db)};\n".encode("utf-8")
                self._stream_command_to_gzip(args, env, plain_partial, append=True, prefix=prefix)
            if self.s.getbool("general", "verify_after_backup", True):
                with gzip.open(plain_partial, "rb") as fh:
                    for _ in iter(lambda: fh.read(1024 * 1024), b""):
                        pass
            coords = parse_dump_coordinates(plain_partial) if need_coordinates else None
            if need_coordinates and not coords:
                raise BackupError("full backup did not contain binary-log coordinates")
            manifest = {
                "type": "full",
                "database": db,
                "started_at": started.isoformat(timespec="seconds"),
                "completed_at": iso_now(),
                "mysql_version": self.mysql.server_version(),
                "binlog": {"file": coords[0], "position": coords[1]} if coords else None,
                "policy": {"exclude_tables": policy.exclude_tables, "schema_only_tables": policy.schema_only_tables},
            }
            final, _, _ = self._finalize_plain_backup(plain_partial, plain_final, manifest)
            state = self.state.db(db)
            state["last_full"] = {"time": iso_now(), "file": str(final)}
            self.state.set_success()
            self._notify("success", "full", db, str(final))
            LOG.info("Full backup completed: %s (%s)", final, human_bytes(final.stat().st_size))
            return final
        except Exception as exc:
            with contextlib.suppress(FileNotFoundError):
                plain_partial.unlink()
            self.state.set_error(str(exc))
            self._notify("failure", "full", db, str(exc))
            raise

    def _backup_candidates(self, db: str, backup_type: str) -> List[Path]:
        _, full_dir, diff_dir = self.db_paths(db)
        folder = full_dir if backup_type == "full" else diff_dir
        if not folder.exists():
            return []
        result: List[Path] = []
        for mp in folder.glob("*.json"):
            data_path = Path(str(mp)[:-5])
            if data_path.exists():
                result.append(data_path)
        def sort_key(path: Path) -> dt.datetime:
            try:
                return self._manifest_time(self.read_manifest(path), path)
            except Exception:
                return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=now_local().tzinfo)
        result.sort(key=sort_key, reverse=True)
        return result

    def latest_full(self, db: str) -> Optional[Path]:
        items = self._backup_candidates(db, "full")
        return items[0] if items else None

    def full_for_time(self, db: str, target: dt.datetime) -> Optional[Path]:
        for path in self._backup_candidates(db, "full"):
            with contextlib.suppress(Exception):
                manifest = self.read_manifest(path)
                completed = self._manifest_time(manifest, path)
                if completed <= target:
                    return path
        return None

    def latest_diff_for_full(self, db: str, full_path: Path) -> Optional[Path]:
        matches: List[Path] = []
        for path in self._backup_candidates(db, "diff"):
            with contextlib.suppress(Exception):
                manifest = self.read_manifest(path)
                if manifest.get("base_full") == full_path.name:
                    matches.append(path)
        return matches[0] if matches else None

    def create_diff(self, db: str) -> Path:
        if not self.s.getbool("diff", "enabled", True):
            raise BackupError("differential backups are disabled")
        policy = self.policy(db)
        if policy.exclude_tables or policy.schema_only_tables:
            raise BackupError(
                f"Diff/PITR is disabled for {db} because table-level exclusion/schema-only policy is configured"
            )
        full = self.latest_full(db)
        if full is None:
            policy = self.s.get("diff", "missing_full_policy", "full").lower()
            if policy == "full":
                LOG.warning("No Full exists for %s; creating one before Diff", db)
                full = self.create_full(db)
            else:
                raise BackupError(f"no full backup exists for {db}")
        full_manifest = self.read_manifest(full)
        base_policy = full_manifest.get("policy") or {}
        if base_policy.get("exclude_tables") or base_policy.get("schema_only_tables"):
            LOG.warning("Latest Full for %s was table-filtered; creating a new unfiltered Full before Diff", db)
            full = self.create_full(db)
            full_manifest = self.read_manifest(full)
        # If an earlier remote upload failed after the local Full committed, do
        # not publish a Diff that references a missing remote base. Republish
        # the Full idempotently first.
        self.remote.ensure_bundle(full)
        coord = full_manifest.get("binlog") or {}
        start_file, start_pos = coord.get("file"), coord.get("position")
        if not start_file or not start_pos:
            raise BackupError(f"Full backup lacks binary-log coordinates: {full}")
        logs = self.mysql.binary_logs()
        if start_file not in logs:
            if self.s.get("diff", "gap_policy", "full").lower() == "full":
                LOG.warning("Base binlog %s expired for %s; creating new Full", start_file, db)
                full = self.create_full(db)
                full_manifest = self.read_manifest(full)
                coord = full_manifest.get("binlog") or {}
                start_file, start_pos = coord.get("file"), coord.get("position")
                logs = self.mysql.binary_logs()
            else:
                raise BackupError(f"base binary log has expired: {start_file}")
        end_file, end_pos = self.mysql.binary_log_status()
        if start_file not in logs or end_file not in logs:
            raise BackupError("required binary-log range is unavailable")
        start_index, end_index = logs.index(start_file), logs.index(end_file)
        selected_logs = logs[start_index:end_index + 1]
        self.check_free_space()
        _, _, diff_dir = self.db_paths(db)
        diff_dir.mkdir(parents=True, exist_ok=True)
        started = now_local()
        stamp = timestamp_for_file(started)
        base_tag = full.name.replace(".sql.gz", "").replace(".age", "").replace(".gpg", "").replace(".enc", "")
        plain_final = self._unique_plain_path(diff_dir, f"{safe_db_dir(db)}__diff__{stamp}__base-{base_tag}.sql.gz")
        plain_partial = Path(str(plain_final) + ".partial")
        LOG.info("Diff backup started: database=%s base=%s", db, full.name)
        try:
            args, env = self.mysql.mysqlbinlog_command(db, selected_logs, start_position=int(start_pos), stop_position=int(end_pos))
            self._stream_command_to_gzip(args, env, plain_partial)
            if self.s.getbool("general", "verify_after_backup", True):
                with gzip.open(plain_partial, "rb") as fh:
                    for _ in iter(lambda: fh.read(1024 * 1024), b""):
                        pass
            manifest = {
                "type": "diff",
                "database": db,
                "started_at": started.isoformat(timespec="seconds"),
                "completed_at": iso_now(),
                "mysql_version": self.mysql.server_version(),
                "base_full": full.name,
                "start_binlog": {"file": start_file, "position": int(start_pos)},
                "end_binlog": {"file": end_file, "position": int(end_pos)},
                "binlog_files": selected_logs,
            }
            final, _, _ = self._finalize_plain_backup(plain_partial, plain_final, manifest)
            self.state.db(db)["last_diff"] = {"time": iso_now(), "file": str(final), "base_full": full.name}
            self.state.set_success()
            self._notify("success", "diff", db, str(final))
            LOG.info("Diff backup completed: %s (%s)", final, human_bytes(final.stat().st_size))
            return final
        except Exception as exc:
            with contextlib.suppress(FileNotFoundError):
                plain_partial.unlink()
            self.state.set_error(str(exc))
            self._notify("failure", "diff", db, str(exc))
            raise

    def backup(self, backup_type: str, databases: Optional[Sequence[str]] = None) -> None:
        dbs = list(databases or self.databases())
        if not dbs:
            raise BackupError("no databases selected")
        errors: List[str] = []
        for db in dbs:
            try:
                if backup_type == "full":
                    self.create_full(db)
                else:
                    self.create_diff(db)
            except Exception as exc:
                LOG.exception("%s backup failed for %s", backup_type, db)
                errors.append(f"{db}: {exc}")
                if self.s.getbool("general", "stop_on_database_error", False):
                    break
        if errors:
            raise BackupError("; ".join(errors))

    def _restore_streams_to_command(self, command: Sequence[str], env: dict, streams: Sequence[BinaryIO], extra_process: Optional[subprocess.Popen] = None) -> None:
        with tempfile.TemporaryFile() as err:
            try:
                proc = subprocess.Popen(list(command), env=env, stdin=subprocess.PIPE, stderr=err)
            except FileNotFoundError as exc:
                raise BackupError(f"required executable not found: {command[0]}") from exc
            assert proc.stdin is not None
            pipeline_error: Optional[Exception] = None
            extra_error: Optional[BackupError] = None
            try:
                for stream in streams:
                    copy_limited(stream, proc.stdin, 0)
                if extra_process is not None:
                    assert extra_process.stdout is not None
                    copy_limited(extra_process.stdout, proc.stdin, 0)
                    extra_process.stdout.close()
                    e_stderr = extra_process.stderr.read().decode("utf-8", errors="replace") if extra_process.stderr else ""
                    e_rc = extra_process.wait()
                    if e_rc != 0:
                        extra_error = BackupError(f"mysqlbinlog PITR failed ({e_rc}): {e_stderr.strip()}")
            except Exception as exc:
                pipeline_error = exc
            finally:
                with contextlib.suppress(Exception):
                    proc.stdin.close()
                if extra_process is not None and extra_process.poll() is None:
                    with contextlib.suppress(Exception):
                        extra_process.terminate()
                    with contextlib.suppress(Exception):
                        extra_process.wait(timeout=5)
                    if extra_process.poll() is None:
                        with contextlib.suppress(Exception):
                            extra_process.kill()
            rc = proc.wait()
            if rc != 0:
                err.seek(0)
                detail = err.read().decode("utf-8", errors="replace").strip()
                raise BackupError(f"MySQL restore failed ({rc}): {detail}")
            if extra_error is not None:
                raise extra_error
            if pipeline_error is not None:
                if isinstance(pipeline_error, BackupError):
                    raise pipeline_error
                raise BackupError(f"restore stream failed: {pipeline_error}") from pipeline_error

    def restore(self, db: str, full: Optional[Path], diff: Optional[Path], latest: bool, yes: bool, to_time: Optional[str] = None) -> None:
        validate_mysql_identifier(db, "database")
        if not yes:
            raise BackupError("restore is destructive; pass --yes after verifying the target")
        if to_time and diff is not None:
            raise BackupError("--diff cannot be combined with --to-time; PITR replays source binary logs directly")
        target_time = parse_iso(to_time) if to_time else None
        if target_time and target_time > now_local() + dt.timedelta(seconds=1):
            raise BackupError("PITR target cannot be in the future")
        if latest:
            full = self.full_for_time(db, target_time) if target_time else self.latest_full(db)
            if full is None:
                if target_time:
                    raise BackupError(f"no Full backup at or before PITR target {target_time.isoformat(timespec='seconds')} for {db}")
                raise BackupError(f"no Full backup found for {db}")
            if not to_time:
                diff = self.latest_diff_for_full(db, full)
        if full is None:
            raise BackupError("--full is required unless --latest is used")
        full_manifest = self.verify_backup(full, db, "full", deep=self.s.getbool("general", "verify_before_restore", True))
        if diff:
            diff_manifest = self.verify_backup(diff, db, "diff", deep=self.s.getbool("general", "verify_before_restore", True))
            if diff_manifest.get("base_full") != full.name:
                raise BackupError("Diff backup does not belong to selected Full")
        args, env = self.restore_mysql.mysql_restore_command()
        with contextlib.ExitStack() as stack:
            streams: List[BinaryIO] = [stack.enter_context(self.encryption.payload_stream(full, full_manifest.get("encryption", {"enabled": False, "provider": "none"})))]
            pitr_proc: Optional[subprocess.Popen] = None
            if to_time:
                target = target_time or parse_iso(to_time)
                backup_policy = full_manifest.get("policy") or {}
                if backup_policy.get("exclude_tables") or backup_policy.get("schema_only_tables"):
                    raise BackupError("PITR cannot use a table-filtered/schema-only Full backup")
                completed = parse_iso(full_manifest.get("completed_at", full_manifest.get("started_at", iso_now())))
                if target < completed:
                    raise BackupError("PITR target is earlier than the selected Full backup completion time")
                coord = full_manifest.get("binlog") or {}
                base_log, base_pos = coord.get("file"), coord.get("position")
                if not base_log or not base_pos:
                    raise BackupError("selected Full has no binlog coordinate for PITR")
                available_logs = self.mysql.binary_logs()
                if base_log not in available_logs:
                    raise BackupError(f"PITR cannot proceed: source binary log {base_log} is no longer available")
                end_log, end_pos = self.mysql.binary_log_status()
                if end_log not in available_logs:
                    raise BackupError(f"PITR cannot proceed: current binary log {end_log} is unavailable")
                selected_logs = available_logs[available_logs.index(base_log):available_logs.index(end_log) + 1]
                # mysqlbinlog stops before the first event whose timestamp is
                # >= --stop-datetime. Add one second so a user target of
                # 14:37:12 includes events timestamped 14:37:12 while still
                # excluding 14:37:13 and later. Binary-log timestamps are
                # second-granularity.
                inclusive_stop = target + dt.timedelta(seconds=1)
                mysql_time = inclusive_stop.astimezone(self.mysql.mysqlbinlog_timezone(inclusive_stop)).strftime("%Y-%m-%d %H:%M:%S")
                bargs, benv = self.mysql.mysqlbinlog_command(
                    db, selected_logs, start_position=int(base_pos), stop_position=int(end_pos), stop_datetime=mysql_time
                )
                try:
                    pitr_proc = subprocess.Popen(bargs, env=benv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except FileNotFoundError as exc:
                    raise BackupError(f"required executable not found: {bargs[0]}") from exc
                LOG.warning(
                    "PITR uses a fixed source binlog snapshot %s:%s -> %s:%s, stopping at %s",
                    base_log, base_pos, end_log, end_pos, mysql_time
                )
            elif diff:
                diff_manifest = self.read_manifest(diff)
                streams.append(stack.enter_context(self.encryption.payload_stream(diff, diff_manifest.get("encryption", {"enabled": False, "provider": "none"}))))
            self._restore_streams_to_command(args, env, streams, extra_process=pitr_proc)
        LOG.info("Restore completed: database=%s full=%s diff=%s to_time=%s", db, full, diff, to_time)

    def _remove_backup_bundle(self, path: Path) -> None:
        # Remove the completion marker first so a concurrent observer never
        # interprets a partially pruned bundle as a complete backup.
        for p in (self.manifest_path(path), self.sha_path(path), path):
            if p.exists():
                self.remote.delete_local_counterpart(p)
                p.unlink()
                LOG.info("Pruned %s", p)

    @staticmethod
    def _manifest_time(manifest: dict, path: Path) -> dt.datetime:
        value = manifest.get("completed_at") or manifest.get("started_at")
        if value:
            with contextlib.suppress(Exception):
                return parse_iso(value)
        return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=now_local().tzinfo)

    def _gfs_keep(self, items: List[Tuple[Path, dict]], policy: DatabasePolicy) -> Set[str]:
        if not items:
            return set()
        now = now_local()
        sorted_items = sorted(items, key=lambda x: self._manifest_time(x[1], x[0]), reverse=True)
        keep: Set[str] = {p.name for p, _ in sorted_items[:max(0, policy.minimum_full_backups)]}

        # GFS retention chooses the newest restore point in each calendar bucket.
        seen_daily: Set[Tuple[int, int, int]] = set()
        seen_weekly: Set[Tuple[int, int]] = set()
        seen_monthly: Set[Tuple[int, int]] = set()
        for path, manifest in sorted_items:
            when = self._manifest_time(manifest, path).astimezone(now.tzinfo)
            age_days = (now.date() - when.date()).days
            if policy.gfs_daily > 0 and 0 <= age_days < policy.gfs_daily:
                key = (when.year, when.month, when.day)
                if key not in seen_daily:
                    seen_daily.add(key)
                    keep.add(path.name)
            iso = when.isocalendar()
            # Monday anchors make week distance robust across year boundaries.
            when_monday = when.date() - dt.timedelta(days=when.weekday())
            now_monday = now.date() - dt.timedelta(days=now.weekday())
            week_age = (now_monday - when_monday).days // 7
            if policy.gfs_weekly > 0 and 0 <= week_age < policy.gfs_weekly:
                # Python 3.8 returns a tuple-like value without .year/.week attributes.
                keyw = (iso[0], iso[1])
                if keyw not in seen_weekly:
                    seen_weekly.add(keyw)
                    keep.add(path.name)
            month_age = (now.year - when.year) * 12 + now.month - when.month
            if policy.gfs_monthly > 0 and 0 <= month_age < policy.gfs_monthly:
                keym = (when.year, when.month)
                if keym not in seen_monthly:
                    seen_monthly.add(keym)
                    keep.add(path.name)
        return keep

    def prune_database(self, db: str, dry_run: bool = False) -> dict:
        policy = self.policy(db)
        now = now_local()
        diffs = [(p, self.read_manifest(p)) for p in self._backup_candidates(db, "diff")]
        fulls = [(p, self.read_manifest(p)) for p in self._backup_candidates(db, "full")]
        removed = {"full": 0, "diff": 0}

        retained_diffs: List[Tuple[Path, dict]] = []
        for path, manifest in diffs:
            age = (now - self._manifest_time(manifest, path)).total_seconds() / 86400
            expired = policy.diff_days > 0 and age > policy.diff_days
            if expired:
                if not dry_run:
                    self._remove_backup_bundle(path)
                removed["diff"] += 1
            else:
                retained_diffs.append((path, manifest))

        referenced = {m.get("base_full") for _, m in retained_diffs if m.get("base_full")}
        gfs_enabled = any(x > 0 for x in (policy.gfs_daily, policy.gfs_weekly, policy.gfs_monthly))
        keep_names = self._gfs_keep(fulls, policy) if gfs_enabled else {p.name for p, _ in sorted(fulls, key=lambda x: self._manifest_time(x[1], x[0]), reverse=True)[:policy.minimum_full_backups]}
        keep_names |= referenced
        for path, manifest in fulls:
            when = self._manifest_time(manifest, path)
            age = (now - when).total_seconds() / 86400
            if gfs_enabled:
                remove = path.name not in keep_names
            else:
                remove = policy.full_days > 0 and age > policy.full_days and path.name not in keep_names
            if remove:
                if not dry_run:
                    self._remove_backup_bundle(path)
                removed["full"] += 1

        # Clean stale partials and orphaned finalized payloads whose manifest
        # was never committed (for example, a crash between data rename and
        # manifest creation).
        base, full_dir, diff_dir = self.db_paths(db)
        if base.exists() and not dry_run:
            cutoff = time.time() - 86400
            for partial in base.rglob("*.partial*"):
                with contextlib.suppress(OSError):
                    if partial.stat().st_mtime < cutoff:
                        partial.unlink()
            for typ, folder in (("full", full_dir), ("diff", diff_dir)):
                if not folder.exists():
                    continue
                prefix = f"{safe_db_dir(db)}__{typ}__"
                for candidate in folder.iterdir():
                    if not candidate.is_file() or not candidate.name.startswith(prefix):
                        continue
                    if candidate.name.endswith((".json", ".sha256")) or ".partial" in candidate.name:
                        continue
                    with contextlib.suppress(OSError):
                        if candidate.stat().st_mtime < cutoff and not self.manifest_path(candidate).exists():
                            LOG.warning("Removing orphaned incomplete backup payload: %s", candidate)
                            self.remote.delete_local_counterpart(candidate)
                            with contextlib.suppress(FileNotFoundError):
                                self.sha_path(candidate).unlink()
                            candidate.unlink()
        return removed

    def prune(self, databases: Optional[Sequence[str]] = None, dry_run: bool = False) -> None:
        for db in databases or self.databases():
            result = self.prune_database(db, dry_run=dry_run)
            LOG.info("Retention %s for %s: %s", "dry-run" if dry_run else "completed", db, result)

    def verify(self, databases: Optional[Sequence[str]] = None, backup_type: str = "all", deep: bool = True) -> None:
        failures: List[str] = []
        for db in databases or self.databases():
            types = ("full", "diff") if backup_type == "all" else (backup_type,)
            for typ in types:
                for path in self._backup_candidates(db, typ):
                    try:
                        self.verify_backup(path, db, typ, deep=deep)
                        print(f"OK\t{typ}\t{db}\t{path}")
                    except Exception as exc:
                        print(f"FAIL\t{typ}\t{db}\t{path}\t{exc}")
                        failures.append(str(path))
        if failures:
            raise BackupError(f"verification failed for {len(failures)} backup(s)")

    def list_backups(self, database: Optional[str] = None) -> None:
        dbs = [database] if database else self.databases()
        for db in dbs:
            for typ in ("full", "diff"):
                for path in self._backup_candidates(db, typ):
                    manifest = self.read_manifest(path)
                    remote = "configured" if self.remote.enabled else "disabled"
                    print(f"{typ}\t{db}\t{manifest.get('completed_at','')}\t{human_bytes(path.stat().st_size)}\tencrypted={manifest.get('encryption',{}).get('enabled',False)}\tremote_target={remote}\t{path}")

    def status(self, as_json: bool = False) -> None:
        payload = dict(self.state.data)
        payload["backup_root"] = str(self.root)
        payload["version"] = VERSION
        if as_json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"MySQL Backup Service {VERSION}")
            print(f"Backup root: {self.root}")
            print(f"Last success: {payload.get('last_success')}")
            print(f"Last error: {payload.get('last_error')}")
            for db, data in sorted(payload.get("databases", {}).items()):
                print(f"{db}: full={data.get('last_full')} diff={data.get('last_diff')}")
            if payload.get("restore_test"):
                print(f"Restore test: {payload['restore_test']}")

    def config_test(self) -> None:
        self.s.validate()
        print(f"Configuration OK: {self.s.path}")

    def doctor(self) -> None:
        self.s.validate()
        errors: List[str] = []
        warnings: List[str] = []
        checks: List[Tuple[str, str]] = []

        def ok(name: str, detail: str) -> None:
            checks.append((name, detail))

        if self.mysql.mode == "native":
            for tool in ("mysql", "mysqldump", "mysqlbinlog"):
                if shutil.which(tool):
                    ok(tool, shutil.which(tool) or "")
                else:
                    errors.append(f"missing executable: {tool}")
        else:
            if shutil.which("docker"):
                ok("docker", shutil.which("docker") or "")
                for tool in ("mysql", "mysqldump"):
                    probe = self.mysql.run(["docker", "exec", self.mysql.container, tool, "--version"], check=False)
                    if probe.returncode == 0:
                        ok(tool, f"docker:{self.mysql.container}")
                    else:
                        errors.append(f"{tool} is unavailable in Docker source container {self.mysql.container}")
            else:
                errors.append("docker executable is missing")

        enc_tool = self.encryption.required_tool()
        if enc_tool:
            if shutil.which(enc_tool):
                ok("encryption", f"{self.encryption.provider}: {shutil.which(enc_tool)}")
            else:
                errors.append(f"encryption tool missing: {enc_tool}")
        if self.encryption.provider == "openssl" and self.encryption.enabled:
            pf = Path(self.s.get("encryption", "openssl_passphrase_file", ""))
            if not pf.exists():
                errors.append(f"OpenSSL passphrase file missing: {pf}")
            elif pf.stat().st_mode & 0o077:
                warnings.append(f"OpenSSL passphrase file is accessible by group/others: {pf}")

        for label, client in (("source", self.mysql), ("restore-target", self.restore_mysql)):
            if client.defaults_file:
                credential = Path(client.defaults_file)
                if client.mode == "native":
                    if not credential.exists():
                        errors.append(f"{label} defaults file missing: {credential}")
                    elif credential.stat().st_mode & 0o077:
                        warnings.append(f"{label} defaults file should be chmod 600: {credential}")

        if self.remote.enabled:
            if shutil.which("rclone"):
                ok("remote", f"rclone -> {self.remote.destination}")
            else:
                errors.append("remote.enabled=true but rclone is missing")
        if self.s.getbool("object_lock", "enabled", False):
            if shutil.which("aws"):
                ok("object-lock", "AWS CLI available")
            else:
                errors.append("Object Lock enabled but aws CLI is missing")

        try:
            version = self.mysql.server_version()
            ok("mysql", f"connected, version={version}")
            dbs = self.databases()
            ok("databases", ", ".join(dbs) or "none")
            if not self.s.getbool("mysql", "add_drop_database", True):
                warnings.append("mysql.add_drop_database=false can leave stale objects during restore; true is recommended for exact replacement restores")
            if "mysql" in dbs:
                warnings.append("the mysql system schema is selected; system-schema restore is version-sensitive and --add-drop-database is intentionally not used for it")
            diff_capable = self.s.getbool("diff", "enabled", True) and any(
                not (self.policy(db).exclude_tables or self.policy(db).schema_only_tables) for db in dbs
            )
            if diff_capable:
                if self.mysql.mode == "docker":
                    probe = self.mysql.run(
                        ["docker", "exec", self.mysql.binlog_container, "mysqlbinlog", "--version"],
                        check=False,
                    )
                    if probe.returncode == 0:
                        ok("mysqlbinlog", f"docker:{self.mysql.binlog_container}")
                    else:
                        errors.append(
                            "mysqlbinlog is unavailable in Docker binlog container "
                            f"{self.mysql.binlog_container}; configure mysql.binlog_container to a companion "
                            "tools container (see docker/mysql-tools/Dockerfile) or use a custom MySQL image "
                            "that includes mysql-community-client"
                        )
                log_bin = self.mysql.variable("log_bin")
                fmt = self.mysql.variable("binlog_format")
                if log_bin.upper() not in {"ON", "1"}:
                    errors.append("binary logging is disabled")
                else:
                    ok("log_bin", log_bin)
                if self.s.getbool("diff", "require_row_binlog", True) and fmt.upper() != "ROW":
                    errors.append(f"binlog_format must be ROW (current={fmt})")
                else:
                    ok("binlog_format", fmt)
                try:
                    f, p = self.mysql.binary_log_status()
                    ok("binlog-position", f"{f}:{p}")
                except Exception as exc:
                    errors.append(str(exc))
        except Exception as exc:
            errors.append(f"MySQL source connectivity failed: {exc}")

        try:
            target_version = self.restore_mysql.server_version()
            ok("restore-target", f"connected, version={target_version}, mode={self.restore_mysql.mode}")
        except Exception as exc:
            errors.append(f"Restore target connectivity failed: {exc}")

        try:
            self.check_free_space()
            ok("free-space", human_bytes(shutil.disk_usage(self.root).free))
        except Exception as exc:
            errors.append(str(exc))

        if self.s.getbool("restore_test", "enabled", False) and not shutil.which("docker"):
            errors.append("restore_test.enabled=true requires docker")

        for name, detail in checks:
            print(f"OK   {name}: {detail}")
        for warning in warnings:
            print(f"WARN {warning}")
        for error in errors:
            print(f"FAIL {error}")
        if errors:
            raise BackupError(f"doctor found {len(errors)} problem(s)")
        print("Doctor: all required checks passed")

    def schedule_report(self) -> None:
        for db in self.databases():
            p = self.policy(db)
            print(f"[{db}]")
            for typ, expr in (("full", p.full_schedule), ("diff", p.diff_schedule)):
                if expr.lower() == "off":
                    print(f"  {typ}: off")
                    continue
                next_runs = CronSchedule(expr).next_runs(count=3)
                print(f"  {typ}: {expr}")
                for run in next_runs:
                    print(f"    next: {run.isoformat(timespec='minutes')}")
        rt = self.s.get("restore_test", "schedule", "off")
        print("[restore-test]")
        if rt.lower() == "off" or not self.s.getbool("restore_test", "enabled", False):
            print("  off")
        else:
            print(f"  {rt}")
            for run in CronSchedule(rt).next_runs(count=3):
                print(f"    next: {run.isoformat(timespec='minutes')}")

    def _docker_restore_command(self, container: str, password: str) -> Tuple[List[str], dict]:
        env = os.environ.copy()
        return ["docker", "exec", "-i", "-e", f"MYSQL_PWD={password}", container, "mysql", "-uroot", "--binary-mode"], env

    def restore_test(self, databases: Optional[Sequence[str]] = None) -> None:
        if not self.s.getbool("restore_test", "enabled", False):
            raise BackupError("restore tests are disabled")
        image = self.s.get("restore_test", "docker_image", "mysql:8.4")
        timeout = self.s.getint("restore_test", "startup_timeout_seconds", 120)
        requested = csv_list(self.s.get("restore_test", "databases", "*"))
        dbs = list(databases or self.databases())
        if requested and requested != ["*"]:
            dbs = [db for db in dbs if db in set(requested)]
        if not dbs:
            raise BackupError("restore test has no selected databases")
        name = f"mysql-backup-verify-{os.getpid()}-{secrets.token_hex(3)}"
        password = secrets.token_urlsafe(24)
        started = iso_now()
        run = MySQLClient.run
        LOG.info("Restore test starting with image %s for %s", image, ",".join(dbs))
        try:
            cmd = ["docker", "run", "--rm", "-d", "--name", name, "-e", f"MYSQL_ROOT_PASSWORD={password}", image, "--skip-log-bin"]
            run(cmd)
            deadline = time.time() + timeout
            ready = False
            while time.time() < deadline:
                probe = run(
                    ["docker", "exec", "-e", f"MYSQL_PWD={password}", name, "mysql", "-uroot", "--batch", "--skip-column-names", "-e", "SELECT 1"],
                    check=False,
                )
                if probe.returncode == 0:
                    ready = True
                    break
                time.sleep(2)
            if not ready:
                raise BackupError(f"restore test MySQL container was not ready within {timeout}s")

            for db in dbs:
                full = self.latest_full(db)
                if not full:
                    raise BackupError(f"restore test: no Full backup for {db}")
                diff = self.latest_diff_for_full(db, full)
                full_manifest = self.verify_backup(full, db, "full", deep=True)
                diff_manifest = None
                if diff:
                    diff_manifest = self.verify_backup(diff, db, "diff", deep=True)
                target_cmd, target_env = self._docker_restore_command(name, password)
                with contextlib.ExitStack() as stack:
                    streams: List[BinaryIO] = [stack.enter_context(self.encryption.payload_stream(full, full_manifest.get("encryption", {"enabled": False, "provider": "none"})))]
                    if diff and diff_manifest:
                        streams.append(stack.enter_context(self.encryption.payload_stream(diff, diff_manifest.get("encryption", {"enabled": False, "provider": "none"}))))
                    self._restore_streams_to_command(target_cmd, target_env, streams)
                q = f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema={sql_quote(db)};"
                result = run(["docker", "exec", "-e", f"MYSQL_PWD={password}", name, "mysql", "-uroot", "--batch", "--skip-column-names", "-e", q])
                LOG.info("Restore test database=%s tables=%s", db, result.stdout.strip())

                custom = self.s.get("restore_test", "validation_queries", "")
                if custom:
                    for query in [q.strip() for q in custom.split("||") if q.strip()]:
                        query = query.replace("{{database}}", db)
                        run(["docker", "exec", "-e", f"MYSQL_PWD={password}", name, "mysql", "-uroot", "--batch", "--skip-column-names", "-e", query])

            self.state.data["restore_test"] = {"status": "success", "started_at": started, "completed_at": iso_now(), "databases": dbs, "image": image}
            self.state.save()
            self._notify("success", "restore-test", ",".join(dbs), "automated restore verification succeeded")
            LOG.info("Automated restore test passed")
        except Exception as exc:
            self.state.data["restore_test"] = {"status": "failure", "started_at": started, "completed_at": iso_now(), "databases": dbs, "image": image, "error": str(exc)}
            self.state.save()
            self._notify("failure", "restore-test", ",".join(dbs), str(exc))
            raise
        finally:
            run(["docker", "rm", "-f", name], check=False)

    def _max_age_due(self, db: str, typ: str, now: dt.datetime) -> bool:
        db_state = self.state.db(db)
        state = db_state.get(f"last_{typ}") or {}
        when = state.get("time")
        if typ == "diff":
            full_when = (db_state.get("last_full") or {}).get("time")
            if full_when and (not when or parse_iso(full_when) > parse_iso(when)):
                when = full_when
        if not when:
            return typ == "full" and self.s.getbool("schedule", "full_on_start_if_missing", True)
        age = now - parse_iso(when)
        if typ == "full":
            limit = self.s.getint("schedule", "full_max_age_hours", 0)
            return limit > 0 and age.total_seconds() > limit * 3600
        limit = self.s.getint("schedule", "diff_max_age_minutes", 0)
        return limit > 0 and age.total_seconds() > limit * 60

    def _scheduler_due(self, key: str, expr: str, now: dt.datetime) -> bool:
        if expr.lower() == "off":
            return False
        schedule = CronSchedule(expr)
        if not schedule.matches(now):
            return False
        minute_key = now.strftime("%Y-%m-%dT%H:%M")
        return self.state.data.setdefault("scheduler", {}).get(key) != minute_key

    def _mark_scheduler(self, key: str, now: dt.datetime) -> None:
        self.state.data.setdefault("scheduler", {})[key] = now.strftime("%Y-%m-%dT%H:%M")
        self.state.data.setdefault("scheduler_retry", {}).pop(key, None)
        self.state.save()

    def _retry_allowed(self, key: str, now: dt.datetime) -> bool:
        raw = self.state.data.setdefault("scheduler_retry", {}).get(key)
        if not raw:
            return True
        try:
            return now >= parse_iso(raw)
        except Exception:
            return True

    def _mark_scheduler_failure(self, key: str, now: dt.datetime, error: Exception) -> None:
        cooldown = self.s.getint("schedule", "retry_cooldown_seconds", 300)
        retry_at = now + dt.timedelta(seconds=max(0, cooldown))
        self.state.data.setdefault("scheduler_retry", {})[key] = retry_at.isoformat(timespec="seconds")
        self.state.set_error(f"{key}: {error}")

    def run_daemon(self) -> None:
        poll = max(5, self.s.getint("schedule", "poll_seconds", 20))
        LOG.info("MySQL Backup Service %s started; poll=%ss", VERSION, poll)
        while not STOP_REQUESTED:
            now = now_local().replace(second=0, microsecond=0)
            try:
                dbs = self.databases()
            except Exception as exc:
                LOG.exception("Database discovery failed")
                self.state.set_error(str(exc))
                dbs = []

            for db in dbs:
                policy = self.policy(db)
                full_key = f"{db}:full"
                diff_key = f"{db}:diff"
                full_created = False

                try:
                    full_due = (
                        self._scheduler_due(full_key, policy.full_schedule, now)
                        or self._max_age_due(db, "full", now)
                        or (self.s.getbool("schedule", "full_on_start_if_missing", True) and self.latest_full(db) is None)
                    )
                    if full_due and self._retry_allowed(full_key, now):
                        with BackupLock(self.s.lock_file):
                            self.create_full(db)
                            self.prune_database(db)
                        self._mark_scheduler(full_key, now)
                        full_created = True
                        # A new Full is a stronger restore point than an immediate
                        # Diff. Treat the same minute as satisfied and let max-age
                        # calculations use last_full until a later Diff succeeds.
                        self._mark_scheduler(diff_key, now)
                except Exception as exc:
                    LOG.exception("Scheduled Full failed for %s", db)
                    self._mark_scheduler_failure(full_key, now, exc)
                    if self.s.getbool("general", "stop_on_database_error", False):
                        break

                try:
                    diff_due = self._scheduler_due(diff_key, policy.diff_schedule, now) or self._max_age_due(db, "diff", now)
                    if (
                        not full_created
                        and diff_due
                        and self.s.getbool("diff", "enabled", True)
                        and self._retry_allowed(diff_key, now)
                    ):
                        with BackupLock(self.s.lock_file):
                            self.create_diff(db)
                            self.prune_database(db)
                        self._mark_scheduler(diff_key, now)
                except Exception as exc:
                    LOG.exception("Scheduled Diff failed for %s", db)
                    self._mark_scheduler_failure(diff_key, now, exc)
                    if self.s.getbool("general", "stop_on_database_error", False):
                        break

            rt_expr = self.s.get("restore_test", "schedule", "off")
            if self.s.getbool("restore_test", "enabled", False) and self._scheduler_due("restore-test", rt_expr, now) and self._retry_allowed("restore-test", now):
                try:
                    with BackupLock(self.s.lock_file):
                        self.restore_test()
                    self._mark_scheduler("restore-test", now)
                except Exception as exc:
                    LOG.exception("Scheduled restore test failed")
                    self._mark_scheduler_failure("restore-test", now, exc)

            for _ in range(poll):
                if STOP_REQUESTED:
                    break
                time.sleep(1)
        LOG.info("MySQL Backup Service stopped")



def setup_logging(settings: Settings, foreground: bool = True) -> None:
    level_name = settings.get("general", "log_level", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    LOG.setLevel(level)
    LOG.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream = logging.StreamHandler(sys.stdout if foreground else sys.stderr)
    stream.setFormatter(formatter)
    LOG.addHandler(stream)
    log_file = settings.get("general", "log_file", "/var/log/mysql-backup-service/backup.log")
    if log_file:
        try:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(path, maxBytes=settings.getint("general", "log_max_mb", 20) * 1024 * 1024, backupCount=settings.getint("general", "log_backups", 5))
            handler.setFormatter(formatter)
            LOG.addHandler(handler)
        except PermissionError:
            LOG.warning("Cannot open configured log file %s; using console/journald only", log_file)


def signal_handler(signum, frame) -> None:  # type: ignore[no-untyped-def]
    global STOP_REQUESTED
    STOP_REQUESTED = True


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Production MySQL backup service")
    p.add_argument("--config", default=os.environ.get("MYSQL_BACKUP_CONFIG", DEFAULT_CONFIG))
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="run scheduler daemon")

    b = sub.add_parser("backup", help="run backup immediately")
    b.add_argument("--type", choices=("full", "diff"), required=True)
    b.add_argument("--database", action="append", default=[])

    r = sub.add_parser("restore", help="restore a Full + Diff chain or exact point in time")
    r.add_argument("--database", required=True)
    r.add_argument("--full", type=Path)
    r.add_argument("--diff", type=Path)
    r.add_argument("--latest", action="store_true")
    r.add_argument("--to-time", help="exact PITR target, e.g. '2026-09-20 14:37:12'; uses source binary logs")
    r.add_argument("--yes", action="store_true")

    v = sub.add_parser("verify", help="verify manifests/checksums/decryption/gzip")
    v.add_argument("--database", action="append", default=[])
    v.add_argument("--type", choices=("all", "full", "diff"), default="all")
    v.add_argument("--quick", action="store_true", help="checksum/manifest only; skip decrypt+gzip scan")

    l = sub.add_parser("list", help="list backups")
    l.add_argument("--database")

    st = sub.add_parser("status", help="show service state")
    st.add_argument("--json", action="store_true")

    pr = sub.add_parser("prune", help="apply retention/GFS policy")
    pr.add_argument("--database", action="append", default=[])
    pr.add_argument("--dry-run", action="store_true")

    # Backward compatibility aliases.
    cl = sub.add_parser("cleanup", help="alias for prune")
    cl.add_argument("--database", action="append", default=[])
    cl.add_argument("--dry-run", action="store_true")
    sub.add_parser("doctor", help="validate configuration and runtime dependencies")
    sub.add_parser("check", help="alias for doctor")
    sub.add_parser("config-test", help="validate configuration without connecting to MySQL")
    sub.add_parser("schedule", help="show per-database schedules and next runs")
    sub.add_parser("version", help="print version")

    rt = sub.add_parser("restore-test", help="run automated Docker restore verification now")
    rt.add_argument("--database", action="append", default=[])
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Backup payloads, manifests, state, and credential-adjacent artifacts must
    # never become group/world-readable merely because the invoking shell used a
    # permissive umask. systemd also sets UMask=0077, but CLI invocations need it.
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(VERSION)
        return 0
    try:
        settings = Settings(args.config)
        setup_logging(settings)
        settings.validate()
        if args.command == "config-test":
            print(f"Configuration OK: {settings.path}")
            return 0
        manager = BackupManager(settings)
        if args.command == "run":
            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)
            manager.run_daemon()
        elif args.command == "backup":
            with BackupLock(settings.lock_file):
                manager.backup(args.type, args.database or None)
        elif args.command == "restore":
            with BackupLock(settings.lock_file):
                manager.restore(args.database, args.full, args.diff, args.latest, args.yes, args.to_time)
        elif args.command == "verify":
            manager.verify(args.database or None, args.type, deep=not args.quick)
        elif args.command == "list":
            manager.list_backups(args.database)
        elif args.command == "status":
            manager.status(args.json)
        elif args.command in {"prune", "cleanup"}:
            with BackupLock(settings.lock_file):
                manager.prune(args.database or None, args.dry_run)
        elif args.command in {"doctor", "check"}:
            manager.doctor()
        elif args.command == "schedule":
            manager.schedule_report()
        elif args.command == "restore-test":
            with BackupLock(settings.lock_file):
                manager.restore_test(args.database or None)
        else:
            raise BackupError(f"unsupported command: {args.command}")
        return 0
    except BackupError as exc:
        LOG.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
