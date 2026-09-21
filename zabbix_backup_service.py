#!/usr/bin/env python3
"""Zabbix Backup Service v2.1.

Zabbix-specific orchestration around mysql_backup_service.py.

The MySQL engine remains the same production-tested implementation used by
omidx/mysql-backup-service. This wrapper adds:

* automatic MySQL connection discovery from zabbix_server.conf
* secure ephemeral MySQL option files under /run
* Zabbix configuration/frontend/script file archives
* encryption, remote replication, Object Lock and retention for file archives
* one systemd service that supervises the database scheduler and file scheduler
* Zabbix-aware doctor/config/list/status/verify/prune/restore commands
"""

from __future__ import annotations

import argparse
import configparser
import contextlib
import datetime as dt
import fnmatch
import glob
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import mysql_backup_service as core

VERSION = "2.1.0"
DEFAULT_CONFIG = "/etc/zabbix-backup-service/zabbix-backup.conf"
LOG = logging.getLogger("zabbix-backup-service")
STOP_REQUESTED = False


class ZabbixBackupError(core.BackupError):
    pass


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _strict_bool(value: str, default: bool = False) -> bool:
    if value is None or str(value).strip() == "":
        return default
    return core.parse_bool(str(value), default)


def _option_value(value: str) -> str:
    """Quote a MySQL option-file value without exposing it on argv."""
    escaped = (
        str(value)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _atomic_text(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        os.chmod(path, mode)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def _fsync_file(path: Path) -> None:
    with path.open("rb") as fh:
        os.fsync(fh.fileno())


def _within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def parse_zabbix_server_config(path: Path, max_depth: int = 16) -> Dict[str, str]:
    """Parse Zabbix key=value config files, including Include= globs.

    Zabbix comments begin at the start of a line. Inline '#' is preserved because
    it may legitimately be part of a password or another option value.
    """

    values: Dict[str, str] = {}
    visited: Set[Path] = set()

    def load(one: Path, depth: int) -> None:
        if depth > max_depth:
            raise ZabbixBackupError("Zabbix Include nesting is too deep")
        try:
            resolved = one.expanduser().resolve(strict=True)
        except FileNotFoundError as exc:
            raise ZabbixBackupError(f"Zabbix configuration file not found: {one}") from exc
        if resolved in visited:
            return
        visited.add(resolved)
        try:
            content = resolved.read_text(encoding="utf-8-sig")
        except OSError as exc:
            raise ZabbixBackupError(f"cannot read Zabbix configuration {resolved}: {exc}") from exc
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key == "Include":
                pattern = os.path.expandvars(os.path.expanduser(value))
                if not os.path.isabs(pattern):
                    pattern = str(resolved.parent / pattern)
                matches = sorted(glob.glob(pattern))
                if not matches:
                    LOG.warning("Zabbix Include pattern matched no files: %s", value)
                for match in matches:
                    load(Path(match), depth + 1)
            else:
                values[key] = value

    load(path, 0)
    if not values.get("DBName"):
        raise ZabbixBackupError(f"DBName is missing from Zabbix configuration: {path}")
    return values


class ZabbixSettings:
    def __init__(self, path: str):
        self.path = Path(path)
        if not self.path.exists():
            raise ZabbixBackupError(f"config file not found: {self.path}")
        parser = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=("#", ";"))
        parser.optionxform = str.lower
        parser.read(self.path, encoding="utf-8")
        self.p = parser

    def get(self, section: str, key: str, default: str = "") -> str:
        return self.p.get(section, key, fallback=default).strip()

    def getint(self, section: str, key: str, default: int) -> int:
        try:
            return self.p.getint(section, key, fallback=default)
        except ValueError as exc:
            raise ZabbixBackupError(f"invalid integer {section}.{key}") from exc

    def getbool(self, section: str, key: str, default: bool) -> bool:
        return _strict_bool(self.get(section, key, ""), default)

    @property
    def runtime_dir(self) -> Path:
        return Path(self.get("zabbix", "runtime_dir", "/run/zabbix-backup-service"))

    @property
    def server_config(self) -> Path:
        return Path(self.get("zabbix", "server_config", "/etc/zabbix/zabbix_server.conf"))

    @property
    def auto_database(self) -> bool:
        return self.getbool("zabbix", "database_from_server_config", True)

    def validate(self) -> None:
        if not self.p.has_section("zabbix"):
            raise ZabbixBackupError("missing [zabbix] section")
        if not self.p.has_section("zabbix_files"):
            raise ZabbixBackupError("missing [zabbix_files] section")
        if self.auto_database:
            mode = self.get("mysql", "mode", "native").lower()
            if mode != "native":
                raise ZabbixBackupError(
                    "zabbix.database_from_server_config=true currently requires mysql.mode=native; "
                    "set it false for Docker/manual database settings"
                )
            parsed = parse_zabbix_server_config(self.server_config)
            core.validate_mysql_identifier(parsed["DBName"], "Zabbix DBName")
        schedule = self.get("zabbix_files", "schedule", "off")
        if schedule.lower() not in {"off", "disabled", "none", ""}:
            core.CronSchedule(schedule)
        for key in ("retention_days", "minimum_backups", "gfs_daily", "gfs_weekly", "gfs_monthly"):
            if self.getint("zabbix_files", key, 0) < 0:
                raise ZabbixBackupError(f"zabbix_files.{key} may not be negative")


class EffectiveConfig:
    """Create a secret-safe runtime config consumed by mysql_backup_service.py."""

    def __init__(self, settings: ZabbixSettings):
        self.settings = settings
        self.runtime_dir = settings.runtime_dir
        self.effective_path = self.runtime_dir / "mysql-effective.conf"
        self.client_path = self.runtime_dir / "mysql-client.cnf"
        self.database_name: Optional[str] = None
        self.zabbix_values: Dict[str, str] = {}

    def _clone_parser(self) -> configparser.ConfigParser:
        p = configparser.ConfigParser(interpolation=None)
        p.optionxform = str.lower
        for section in self.settings.p.sections():
            p.add_section(section)
            for key, value in self.settings.p.items(section):
                p.set(section, key, value)
        return p

    def _write_client_file(self, z: Dict[str, str]) -> None:
        user = z.get("DBUser", "zabbix") or "zabbix"
        password = z.get("DBPassword", "")
        original_host = z.get("DBHost", "localhost")
        host = original_host if original_host not in {"", "localhost"} else "127.0.0.1"
        port = z.get("DBPort", "3306") or "3306"
        socket = z.get("DBSocket", "")
        lines = ["[client]", f"user={_option_value(user)}", f"password={_option_value(password)}"]
        if socket:
            lines.append(f"socket={_option_value(socket)}")
        else:
            lines += [f"host={_option_value(host)}", f"port={port}"]

        tls_mode = z.get("DBTLSConnect", "").lower()
        tls_map = {"required": "REQUIRED", "verify_ca": "VERIFY_CA", "verify_full": "VERIFY_IDENTITY"}
        if tls_mode:
            if tls_mode not in tls_map:
                raise ZabbixBackupError(f"unsupported Zabbix DBTLSConnect value: {tls_mode}")
            lines.append(f"ssl-mode={tls_map[tls_mode]}")
        for zkey, opt in (("DBTLSCAFile", "ssl-ca"), ("DBTLSCertFile", "ssl-cert"), ("DBTLSKeyFile", "ssl-key")):
            if z.get(zkey):
                lines.append(f"{opt}={_option_value(z[zkey])}")
        _atomic_text(self.client_path, "\n".join(lines) + "\n", 0o600)

    def prepare(self) -> Path:
        self.settings.validate()
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.runtime_dir, 0o700)
        p = self._clone_parser()
        if self.settings.auto_database:
            z = parse_zabbix_server_config(self.settings.server_config)
            self.zabbix_values = z
            self.database_name = core.validate_mysql_identifier(z["DBName"], "Zabbix DBName")
            self._write_client_file(z)
            if not p.has_section("mysql"):
                p.add_section("mysql")
            original_host = z.get("DBHost", "localhost")
            tcp_host = original_host if original_host not in {"", "localhost"} else "127.0.0.1"
            p.set("mysql", "mode", "native")
            p.set("mysql", "host", tcp_host)
            p.set("mysql", "port", z.get("DBPort", "3306") or "3306")
            p.set("mysql", "socket", z.get("DBSocket", ""))
            p.set("mysql", "user", z.get("DBUser", "zabbix") or "zabbix")
            p.set("mysql", "password", "")
            p.set("mysql", "defaults_extra_file", str(self.client_path))
            p.set("mysql", "include_databases", self.database_name)
            p.set("mysql", "exclude_databases", "information_schema,performance_schema,sys,mysql")
        else:
            includes = self.settings.get("mysql", "include_databases", "")
            if includes and includes != "*":
                candidates = _split_csv(includes)
                if len(candidates) == 1:
                    self.database_name = candidates[0]

        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(self.runtime_dir), delete=False) as fh:
            p.write(fh)
            fh.flush()
            os.fsync(fh.fileno())
            tmp = Path(fh.name)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.effective_path)
        os.chmod(self.effective_path, 0o600)

        effective = core.Settings(str(self.effective_path))
        effective.validate()
        return self.effective_path

    def core_settings(self) -> core.Settings:
        if not self.effective_path.exists():
            self.prepare()
        return core.Settings(str(self.effective_path))

    def cleanup(self) -> None:
        for path in (self.effective_path, self.client_path):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()


class ZabbixFileBackupManager:
    def __init__(self, settings: ZabbixSettings, effective: EffectiveConfig):
        self.s = settings
        self.effective = effective
        self.core_settings = effective.core_settings()
        self.root = self.core_settings.backup_root
        self.files_dir = self.root / "zabbix_files" / "full"
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.encryption = core.EncryptionManager(self.core_settings)
        self.remote = core.RemoteStore(self.core_settings, self.root)
        self.state_path = Path(
            self.s.get("zabbix_files", "state_file", str(self.core_settings.state_dir / "zabbix-files-state.json"))
        )

    def _patterns(self) -> List[str]:
        return _split_csv(self.s.get("zabbix_files", "paths", "/etc/zabbix,/usr/share/zabbix,/usr/share/zabbix-*"))

    def source_paths(self) -> List[Path]:
        found: List[Path] = []
        seen: Set[Path] = set()
        for pattern in self._patterns():
            expanded = os.path.expandvars(os.path.expanduser(pattern))
            matches = glob.glob(expanded)
            if not matches and Path(expanded).exists():
                matches = [expanded]
            for match in sorted(matches):
                path = Path(match).resolve()
                if path in seen:
                    continue
                if _within(self.root, path) or _within(path, self.root):
                    raise ZabbixBackupError(
                        f"Zabbix files source {path} overlaps backup root {self.root}; refusing recursive backup"
                    )
                seen.add(path)
                found.append(path)
        if not found and not self.s.getbool("zabbix_files", "allow_empty_paths", False):
            raise ZabbixBackupError("none of zabbix_files.paths exists")
        return found

    def _excluded(self, absolute: Path, member_name: str) -> bool:
        patterns = _split_csv(self.s.get("zabbix_files", "exclude_patterns", "*.sock,*.pid"))
        absolute_text = str(absolute)
        return any(fnmatch.fnmatch(member_name, pat) or fnmatch.fnmatch(absolute_text, pat) for pat in patterns)

    def _tar_filter(self, info: tarfile.TarInfo) -> Optional[tarfile.TarInfo]:
        # Archives are restored relative to /, never with absolute member names.
        info.name = info.name.lstrip("/")
        if self._excluded(Path("/") / info.name, info.name):
            return None
        return info

    def _unique_path(self, base: Path) -> Path:
        if not base.exists() and not Path(str(base) + ".json").exists():
            return base
        stem = base.name
        for n in range(1, 1000):
            candidate = base.with_name(f"{stem}.{n}")
            if not candidate.exists() and not Path(str(candidate) + ".json").exists():
                return candidate
        raise ZabbixBackupError(f"could not allocate unique backup filename for {base}")

    def _zabbix_version(self) -> str:
        try:
            proc = subprocess.run(["zabbix_server", "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
            first = proc.stdout.splitlines()[0].strip() if proc.stdout else ""
            return first or "unknown"
        except (OSError, subprocess.SubprocessError):
            return "unknown"

    def create(self) -> Path:
        sources = self.source_paths()
        started = core.now_local()
        stamp = core.timestamp_for_file(started)
        raw_partial = self.files_dir / f"zabbix_files__full__{stamp}.tar.gz.plain.partial"
        final_base = self.files_dir / f"zabbix_files__full__{stamp}.tar.gz{self.encryption.extension}"
        final_path = self._unique_path(final_base)
        final_partial = Path(str(final_path) + ".partial")
        gzip_level = max(1, min(9, self.core_settings.getint("general", "gzip_level", 6)))

        LOG.info("Creating Zabbix files backup from %d source path(s)", len(sources))
        try:
            with tarfile.open(raw_partial, "w:gz", compresslevel=gzip_level, dereference=False) as tar:
                for source in sources:
                    arcname = source.as_posix().lstrip("/") or source.name
                    tar.add(str(source), arcname=arcname, recursive=True, filter=self._tar_filter)
            _fsync_file(raw_partial)

            if self.encryption.enabled:
                self.encryption.encrypt(raw_partial, final_partial)
                _fsync_file(final_partial)
                os.replace(final_partial, final_path)
                raw_partial.unlink()
            else:
                os.replace(raw_partial, final_path)
            os.chmod(final_path, 0o600)
            _fsync_file(final_path)

            sha = core.sha256_file(final_path)
            manifest = {
                "service": "zabbix-backup-service",
                "version": VERSION,
                "type": "zabbix_files_full",
                "started_at": started.isoformat(timespec="seconds"),
                "completed_at": core.iso_now(),
                "file": final_path.name,
                "size_bytes": final_path.stat().st_size,
                "sha256": sha,
                "sources": [str(p) for p in sources],
                "zabbix_server_config": str(self.s.server_config),
                "zabbix_version": self._zabbix_version(),
                "encryption": self.encryption.metadata(),
            }
            manifest_path = Path(str(final_path) + ".json")
            core.atomic_json_write(manifest_path, manifest)
            sidecar = Path(str(final_path) + ".sha256")
            if self.core_settings.getbool("general", "write_sha256_file", True):
                _atomic_text(sidecar, f"{sha}  {final_path.name}\n", 0o600)

            if self.s.getbool("zabbix_files", "verify_after_backup", True):
                self.verify_one(final_path)

            bundle = [final_path]
            if sidecar.exists():
                bundle.append(sidecar)
            bundle.append(manifest_path)
            self.remote.upload_bundle(bundle)
            self._save_state({"last_success": core.iso_now(), "last_file": str(final_path), "last_error": None})
            LOG.info("Zabbix files backup completed: %s", final_path)
            return final_path
        except Exception as exc:
            self._save_state({"last_error": {"time": core.iso_now(), "message": str(exc)}})
            for path in (raw_partial, final_partial):
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
            raise

    def _manifest(self, data: Path) -> dict:
        path = Path(str(data) + ".json")
        if not path.exists():
            raise ZabbixBackupError(f"manifest missing for {data}")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ZabbixBackupError(f"invalid manifest {path}: {exc}") from exc
        if payload.get("type") != "zabbix_files_full":
            raise ZabbixBackupError(f"unexpected manifest type for {data}: {payload.get('type')}")
        return payload

    def verify_one(self, data: Path) -> None:
        manifest = self._manifest(data)
        expected = str(manifest.get("sha256", ""))
        actual = core.sha256_file(data)
        if not expected or actual != expected:
            raise ZabbixBackupError(f"SHA-256 mismatch for {data}")
        sidecar = Path(str(data) + ".sha256")
        if sidecar.exists():
            token = sidecar.read_text(encoding="utf-8").split()[0]
            if token != expected:
                raise ZabbixBackupError(f"SHA-256 sidecar mismatch for {data}")
        with self.encryption.decrypted_binary_stream(data, manifest.get("encryption")) as stream:
            try:
                with tarfile.open(fileobj=stream, mode="r|gz") as tar:
                    for _ in tar:
                        pass
            except (tarfile.TarError, OSError) as exc:
                raise ZabbixBackupError(f"tar verification failed for {data}: {exc}") from exc

    def backups(self) -> List[Tuple[Path, dict]]:
        items: List[Tuple[Path, dict]] = []
        for manifest_path in self.files_dir.glob("*.json"):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                name = manifest.get("file")
                if not name:
                    continue
                data = manifest_path.parent / name
                if data.exists():
                    items.append((data, manifest))
            except Exception:
                LOG.warning("Ignoring unreadable Zabbix files manifest: %s", manifest_path)
        items.sort(key=lambda item: core.parse_iso(item[1].get("completed_at", item[1].get("started_at", "1970-01-01T00:00:00+00:00"))), reverse=True)
        return items

    def verify_all(self) -> None:
        items = self.backups()
        if not items:
            raise ZabbixBackupError("no Zabbix files backups found")
        for path, _ in items:
            self.verify_one(path)
            print(f"OK files {path}")

    def list(self) -> None:
        items = self.backups()
        if not items:
            print("No Zabbix files backups found")
            return
        for path, manifest in items:
            print(
                f"files {manifest.get('completed_at','?')} {path} "
                f"size={core.human_bytes(path.stat().st_size)} sha256={manifest.get('sha256','')[:12]}..."
            )

    @staticmethod
    def _safe_member(member: tarfile.TarInfo, target: Path) -> None:
        name = member.name.replace("\\", "/")
        if not name or name.startswith("/") or ".." in Path(name).parts:
            raise ZabbixBackupError(f"unsafe archive member: {member.name}")
        destination = (target / name).resolve()
        if not _within(destination, target):
            raise ZabbixBackupError(f"archive path escapes restore target: {member.name}")
        if member.ischr() or member.isblk() or member.isfifo():
            raise ZabbixBackupError(f"special device/FIFO member is not allowed: {member.name}")
        if member.issym() or member.islnk():
            link = Path(member.linkname)
            if link.is_absolute():
                link_target = (target / str(link).lstrip("/"))
            else:
                link_target = destination.parent / link
            if not _within(link_target.resolve(strict=False), target):
                raise ZabbixBackupError(f"archive link escapes restore target: {member.name} -> {member.linkname}")

    def restore(self, data: Path, target: Path, yes: bool) -> None:
        if not yes:
            raise ZabbixBackupError("restore-files requires --yes")
        data = data.resolve()
        target.mkdir(parents=True, exist_ok=True)
        target = target.resolve()
        manifest = self._manifest(data)
        self.verify_one(data)
        with tempfile.NamedTemporaryFile(prefix="zabbix-files-restore-", suffix=".tar.gz", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            with self.encryption.decrypted_binary_stream(data, manifest.get("encryption")) as source:
                shutil.copyfileobj(source, tmp, length=1024 * 1024)
            tmp.flush()
            os.fsync(tmp.fileno())
        try:
            with tarfile.open(tmp_path, "r:gz") as tar:
                members = tar.getmembers()
                for member in members:
                    self._safe_member(member, target)
                for member in members:
                    tar.extract(member, path=target)
        finally:
            with contextlib.suppress(FileNotFoundError):
                tmp_path.unlink()
        print(f"Zabbix files restored to {target}")

    def _gfs_keep(self, items: List[Tuple[Path, dict]]) -> Set[Path]:
        daily = self.s.getint("zabbix_files", "gfs_daily", 7)
        weekly = self.s.getint("zabbix_files", "gfs_weekly", 4)
        monthly = self.s.getint("zabbix_files", "gfs_monthly", 12)
        keep: Set[Path] = set()

        def select(limit: int, keyfunc) -> None:
            if limit <= 0:
                return
            buckets = set()
            for path, manifest in items:
                when = core.parse_iso(manifest.get("completed_at", manifest.get("started_at")))
                key = keyfunc(when)
                if key in buckets:
                    continue
                buckets.add(key)
                keep.add(path)
                if len(buckets) >= limit:
                    break

        select(daily, lambda x: x.date())
        select(weekly, lambda x: (x.isocalendar()[0], x.isocalendar()[1]))
        select(monthly, lambda x: (x.year, x.month))
        return keep

    def prune(self, dry_run: bool = False) -> None:
        items = self.backups()
        if not items:
            return
        minimum = self.s.getint("zabbix_files", "minimum_backups", 2)
        retention_days = self.s.getint("zabbix_files", "retention_days", 30)
        keep: Set[Path] = {p for p, _ in items[:minimum]}
        keep |= self._gfs_keep(items)
        cutoff = core.now_local() - dt.timedelta(days=retention_days) if retention_days > 0 else None
        for path, manifest in items:
            when = core.parse_iso(manifest.get("completed_at", manifest.get("started_at")))
            expired = cutoff is not None and when < cutoff
            gfs_enabled = any(self.s.getint("zabbix_files", k, 0) > 0 for k in ("gfs_daily", "gfs_weekly", "gfs_monthly"))
            if path in keep:
                continue
            if not expired and not gfs_enabled:
                continue
            manifest_path = Path(str(path) + ".json")
            sidecar = Path(str(path) + ".sha256")
            if dry_run:
                print(f"Would prune files backup: {path}")
                continue
            # Manifest-first deletion means a partial local/remote delete cannot
            # remain advertised as a complete backup bundle.
            local_bundle = [manifest_path, sidecar, path]
            if self.remote.enabled and self.core_settings.getbool("remote", "prune_with_local", False):
                for item in local_bundle:
                    if item.exists():
                        rel = self.remote.relative_key(item)
                        with contextlib.suppress(Exception):
                            self.remote._rclone("deletefile", self.remote.remote_path(rel), check=False)
            for item in local_bundle:
                with contextlib.suppress(FileNotFoundError):
                    item.unlink()
            LOG.info("Pruned Zabbix files backup: %s", path)

    def _load_state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _save_state(self, update: dict) -> None:
        state = self._load_state()
        state.update(update)
        core.atomic_json_write(self.state_path, state)

    def schedule_due(self, now: dt.datetime) -> bool:
        schedule = self.s.get("zabbix_files", "schedule", "off")
        if schedule.lower() in {"off", "disabled", "none", ""}:
            return False
        if not core.CronSchedule(schedule).matches(now):
            return False
        minute = now.strftime("%Y-%m-%dT%H:%M")
        return self._load_state().get("last_schedule_minute") != minute

    def mark_schedule(self, now: dt.datetime) -> None:
        self._save_state({"last_schedule_minute": now.strftime("%Y-%m-%dT%H:%M")})

    def status(self) -> None:
        print(json.dumps(self._load_state(), indent=2, sort_keys=True))


def setup_logging(settings: ZabbixSettings) -> None:
    level_name = settings.get("general", "log_level", "INFO").upper()
    LOG.setLevel(getattr(logging, level_name, logging.INFO))
    LOG.handlers.clear()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    LOG.addHandler(stream)
    log_file = settings.get("zabbix_files", "log_file", "/var/log/zabbix-backup-service/files.log")
    if log_file:
        try:
            path = Path(log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = RotatingFileHandler(
                path,
                maxBytes=settings.getint("general", "log_max_mb", 20) * 1024 * 1024,
                backupCount=settings.getint("general", "log_backups", 5),
            )
            handler.setFormatter(formatter)
            LOG.addHandler(handler)
        except PermissionError:
            LOG.warning("Cannot open file log %s; using stdout/journald only", log_file)


def _core_command(effective: Path, args: Sequence[str]) -> List[str]:
    core_script = Path(__file__).with_name("mysql_backup_service.py")
    return [sys.executable, str(core_script), "--config", str(effective), *args]


def _run_core(effective: Path, args: Sequence[str], check: bool = True) -> int:
    proc = subprocess.run(_core_command(effective, args))
    if check and proc.returncode != 0:
        raise ZabbixBackupError(f"database backup engine failed with exit code {proc.returncode}")
    return proc.returncode


def _database_for_restore(runtime: EffectiveConfig, explicit: Optional[str]) -> str:
    if explicit:
        return core.validate_mysql_identifier(explicit, "database")
    if runtime.database_name:
        return core.validate_mysql_identifier(runtime.database_name, "database")
    raise ZabbixBackupError("--database is required when a single Zabbix database cannot be inferred")


def doctor(settings: ZabbixSettings, runtime: EffectiveConfig, files: ZabbixFileBackupManager) -> None:
    print(f"Zabbix config: {settings.server_config}")
    z = parse_zabbix_server_config(settings.server_config)
    print(f"Zabbix DBName: {z.get('DBName')}")
    if settings.auto_database:
        print("Database credentials: discovered from zabbix_server.conf into /run (0600)")
    sources = files.source_paths()
    print("Zabbix file sources:")
    for source in sources:
        print(f"  - {source}")
    print(f"Zabbix server version: {files._zabbix_version()}")
    _run_core(runtime.effective_path, ["doctor"])


def run_service(settings: ZabbixSettings, runtime: EffectiveConfig, files: ZabbixFileBackupManager) -> None:
    global STOP_REQUESTED
    child = subprocess.Popen(_core_command(runtime.effective_path, ["run"]))
    poll = max(5, settings.getint("schedule", "poll_seconds", 20))
    LOG.info("Zabbix Backup Service %s started; database scheduler pid=%s", VERSION, child.pid)
    try:
        while not STOP_REQUESTED:
            rc = child.poll()
            if rc is not None:
                raise ZabbixBackupError(f"database scheduler exited unexpectedly with status {rc}")
            now = core.now_local().replace(second=0, microsecond=0)
            if settings.getbool("zabbix_files", "enabled", True) and files.schedule_due(now):
                try:
                    with core.BackupLock(runtime.core_settings().lock_file):
                        files.create()
                        files.prune(False)
                    files.mark_schedule(now)
                except core.BackupError as exc:
                    # A concurrent database backup owns the shared lock. Retry
                    # later in this minute instead of recording a false failure.
                    if "another backup operation" in str(exc).lower():
                        LOG.info("Database backup is active; deferring Zabbix files backup")
                    else:
                        LOG.exception("Scheduled Zabbix files backup failed")
                except Exception:
                    LOG.exception("Scheduled Zabbix files backup failed")
            time.sleep(poll)
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)


def signal_handler(signum, frame) -> None:  # type: ignore[no-untyped-def]
    global STOP_REQUESTED
    STOP_REQUESTED = True


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Production Zabbix backup service")
    p.add_argument("--config", default=os.environ.get("ZABBIX_BACKUP_CONFIG", DEFAULT_CONFIG))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run database + Zabbix files schedulers")

    b = sub.add_parser("backup", help="run an immediate backup")
    b.add_argument("--type", choices=("full", "diff", "files", "bundle"), required=True)

    r = sub.add_parser("restore", help="restore the Zabbix database")
    r.add_argument("--database")
    r.add_argument("--full", type=Path)
    r.add_argument("--diff", type=Path)
    r.add_argument("--latest", action="store_true")
    r.add_argument("--to-time")
    r.add_argument("--yes", action="store_true")

    rf = sub.add_parser("restore-files", help="restore a Zabbix files archive")
    rf.add_argument("--archive", type=Path, required=True)
    rf.add_argument("--target", type=Path, default=Path("/"))
    rf.add_argument("--yes", action="store_true")

    v = sub.add_parser("verify", help="verify database and/or file backups")
    v.add_argument("--component", choices=("all", "database", "files"), default="all")
    v.add_argument("--quick", action="store_true")

    l = sub.add_parser("list", help="list database and Zabbix files backups")
    l.add_argument("--component", choices=("all", "database", "files"), default="all")

    st = sub.add_parser("status", help="show database + file scheduler state")
    st.add_argument("--json", action="store_true")

    pr = sub.add_parser("prune", help="apply database and files retention")
    pr.add_argument("--component", choices=("all", "database", "files"), default="all")
    pr.add_argument("--dry-run", action="store_true")

    sub.add_parser("doctor", help="validate Zabbix, MySQL and runtime dependencies")
    sub.add_parser("check", help="alias for doctor")
    sub.add_parser("config-test", help="validate Zabbix + generated database configuration")
    sub.add_parser("schedule", help="show database and files schedules")
    sub.add_parser("version", help="print versions")
    rt = sub.add_parser("restore-test", help="run database restore verification now")
    rt.add_argument("--database")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    os.umask(0o077)
    args = build_parser().parse_args(argv)
    if args.command == "version":
        print(f"Zabbix Backup Service {VERSION} (MySQL engine {core.VERSION})")
        return 0

    runtime: Optional[EffectiveConfig] = None
    try:
        settings = ZabbixSettings(args.config)
        setup_logging(settings)
        settings.validate()
        runtime = EffectiveConfig(settings)
        runtime.prepare()
        files = ZabbixFileBackupManager(settings, runtime)

        if args.command == "config-test":
            _run_core(runtime.effective_path, ["config-test"])
            files.source_paths()
            print(f"Zabbix configuration OK: {settings.path}")
            return 0

        if args.command in {"doctor", "check"}:
            doctor(settings, runtime, files)
            return 0

        if args.command == "run":
            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)
            run_service(settings, runtime, files)
        elif args.command == "backup":
            if args.type in {"full", "diff"}:
                _run_core(runtime.effective_path, ["backup", "--type", args.type])
            elif args.type == "files":
                with core.BackupLock(runtime.core_settings().lock_file):
                    files.create()
            else:
                _run_core(runtime.effective_path, ["backup", "--type", "full"])
                with core.BackupLock(runtime.core_settings().lock_file):
                    files.create()
                    files.prune(False)
        elif args.command == "restore":
            db = _database_for_restore(runtime, args.database)
            call = ["restore", "--database", db]
            if args.full:
                call += ["--full", str(args.full)]
            if args.diff:
                call += ["--diff", str(args.diff)]
            if args.latest:
                call.append("--latest")
            if args.to_time:
                call += ["--to-time", args.to_time]
            if args.yes:
                call.append("--yes")
            _run_core(runtime.effective_path, call)
        elif args.command == "restore-files":
            files.restore(args.archive, args.target, args.yes)
        elif args.command == "verify":
            if args.component in {"all", "database"}:
                call = ["verify"]
                if args.quick:
                    call.append("--quick")
                _run_core(runtime.effective_path, call)
            if args.component in {"all", "files"}:
                files.verify_all()
        elif args.command == "list":
            if args.component in {"all", "database"}:
                _run_core(runtime.effective_path, ["list"])
            if args.component in {"all", "files"}:
                files.list()
        elif args.command == "status":
            _run_core(runtime.effective_path, ["status"] + (["--json"] if args.json else []))
            print("Zabbix files state:")
            files.status()
        elif args.command == "prune":
            if args.component in {"all", "database"}:
                call = ["prune"] + (["--dry-run"] if args.dry_run else [])
                _run_core(runtime.effective_path, call)
            if args.component in {"all", "files"}:
                files.prune(args.dry_run)
        elif args.command == "schedule":
            _run_core(runtime.effective_path, ["schedule"])
            schedule = settings.get("zabbix_files", "schedule", "off")
            print(f"Zabbix files schedule: {schedule}")
            if schedule.lower() not in {"off", "disabled", "none", ""}:
                for when in core.CronSchedule(schedule).next_runs(core.now_local(), 5):
                    print(f"  {when.isoformat(timespec='minutes')}")
        elif args.command == "restore-test":
            call = ["restore-test"]
            if args.database:
                call += ["--database", args.database]
            _run_core(runtime.effective_path, call)
        else:
            raise ZabbixBackupError(f"unsupported command: {args.command}")
        return 0
    except (core.BackupError, ZabbixBackupError, OSError, ValueError) as exc:
        LOG.error("%s", exc)
        return 1
    finally:
        if runtime is not None:
            runtime.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
