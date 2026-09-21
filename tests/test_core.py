import datetime as dt
import gzip
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("mysql_backup_service", ROOT / "mysql_backup_service.py")
mod = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = mod
assert spec.loader
spec.loader.exec_module(mod)


class TempConfigMixin:
    def config(self, text: str):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        path = Path(td.name) / "test.ini"
        path.write_text(text, encoding="utf-8")
        return mod.Settings(str(path)), Path(td.name)


class CronTests(unittest.TestCase):
    def test_hourly(self):
        c = mod.CronSchedule("0 * * * *")
        self.assertTrue(c.matches(dt.datetime(2026, 9, 20, 10, 0)))
        self.assertFalse(c.matches(dt.datetime(2026, 9, 20, 10, 1)))

    def test_steps(self):
        c = mod.CronSchedule("*/15 */6 * * *")
        self.assertTrue(c.matches(dt.datetime(2026, 9, 20, 12, 30)))
        self.assertFalse(c.matches(dt.datetime(2026, 9, 20, 13, 30)))

    def test_sunday_zero_and_seven(self):
        sunday = dt.datetime(2026, 9, 20, 3, 0)
        self.assertTrue(mod.CronSchedule("0 3 * * 0").matches(sunday))
        self.assertTrue(mod.CronSchedule("0 3 * * 7").matches(sunday))

    def test_next_runs(self):
        c = mod.CronSchedule("0 2 * * *")
        start = dt.datetime(2026, 9, 20, 1, 59, tzinfo=dt.timezone.utc)
        runs = c.next_runs(start, 2)
        self.assertEqual((runs[0].day, runs[0].hour), (20, 2))
        self.assertEqual(runs[1].day, 21)

    def test_invalid_step(self):
        with self.assertRaises(mod.BackupError):
            mod.CronSchedule("*/0 * * * *")

    def test_invalid_cron_token_is_backup_error(self):
        with self.assertRaises(mod.BackupError):
            mod.CronSchedule("x * * * *")


class UtilityTests(unittest.TestCase):
    def test_strict_boolean(self):
        self.assertTrue(mod.parse_bool("yes"))
        self.assertFalse(mod.parse_bool("OFF", True))
        with self.assertRaises(mod.BackupError):
            mod.parse_bool("treu")

    def test_identifier_rejects_option_like_name(self):
        with self.assertRaises(mod.BackupError):
            mod.validate_mysql_identifier("--defaults-file=x", "database")

    def test_safe_db_dir(self):
        self.assertEqual(mod.safe_db_dir("app-db"), "app-db")
        self.assertTrue(mod.safe_db_dir("app/db").startswith("app_db_"))

    def test_parse_zulu_time(self):
        parsed = mod.parse_iso("2026-09-20T12:00:00Z")
        self.assertEqual(parsed.utcoffset(), dt.timedelta(0))


class CoordinateTests(unittest.TestCase):
    def test_source_coordinates(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "backup.sql.gz"
            with gzip.open(path, "wt") as fh:
                fh.write("-- CHANGE REPLICATION SOURCE TO SOURCE_LOG_FILE='binlog.000123', SOURCE_LOG_POS=456;\n")
            self.assertEqual(mod.parse_dump_coordinates(path), ("binlog.000123", 456))

    def test_legacy_coordinates(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "backup.sql.gz"
            with gzip.open(path, "wt") as fh:
                fh.write("-- CHANGE MASTER TO MASTER_LOG_FILE='mysql-bin.000002', MASTER_LOG_POS=789;\n")
            self.assertEqual(mod.parse_dump_coordinates(path), ("mysql-bin.000002", 789))


class ConfigTests(TempConfigMixin, unittest.TestCase):
    def test_per_database_policy_override(self):
        s, _ = self.config("""
[general]
backup_root=/tmp
[schedule]
full=0 2 * * *
diff=0 * * * *
[retention]
full_days=30
diff_days=14
minimum_full_backups=2
gfs_daily=7
gfs_weekly=4
gfs_monthly=12
[database:app]
full_schedule=0 3 * * 0
diff_schedule=30 3 * * *
full_days=90
""")
        m = object.__new__(mod.BackupManager)
        m.s = s
        p = mod.BackupManager.policy(m, "app")
        self.assertEqual(p.full_schedule, "0 3 * * 0")
        self.assertEqual(p.full_days, 90)
        self.assertEqual(p.gfs_monthly, 12)

    def test_table_filters_require_diff_off(self):
        s, _ = self.config("""
[schedule]
full=0 2 * * *
diff=0 * * * *
[database:app]
exclude_tables=audit_logs
""")
        with self.assertRaises(mod.BackupError):
            s.validate()

    def test_global_table_filters_require_global_diff_off(self):
        s, _ = self.config("""
[schedule]
full=0 2 * * *
diff=0 * * * *
[tables]
exclude_tables=audit_logs
""")
        with self.assertRaises(mod.BackupError):
            s.validate()

    def test_table_filters_allowed_when_diff_off(self):
        s, _ = self.config("""
[schedule]
full=0 2 * * *
diff=0 * * * *
[database:app]
diff_schedule=off
exclude_tables=audit_logs
schema_only_tables=history
""")
        s.validate()

    def test_table_filters_allowed_when_global_diff_disabled(self):
        s, _ = self.config("""
[schedule]
full=0 2 * * *
diff=0 * * * *
[diff]
enabled=false
[tables]
exclude_tables=audit_logs
""")
        s.validate()

    def test_invalid_boolean_fails_config_test(self):
        s, _ = self.config("""
[general]
verify_after_backup=treu
""")
        with self.assertRaises(mod.BackupError):
            s.validate()

    def test_negative_retention_rejected(self):
        s, _ = self.config("""
[retention]
full_days=-1
""")
        with self.assertRaises(mod.BackupError):
            s.validate()

    def test_restore_target_bad_mode_rejected(self):
        s, _ = self.config("""
[restore_target]
enabled=true
mode=spaceship
""")
        with self.assertRaises(mod.BackupError):
            s.validate()


class ClientTests(TempConfigMixin, unittest.TestCase):
    def test_pitr_command_contains_range_and_datetime(self):
        s, _ = self.config("""
[mysql]
mode=native
host=127.0.0.1
port=3306
user=backup
[diff]
filter_by_database=true
""")
        client = mod.MySQLClient(s)
        args, _ = client.mysqlbinlog_command(
            "app", ["bin.000001", "bin.000002"], start_position=123, stop_position=999,
            stop_datetime="2026-09-20 14:37:13"
        )
        joined = " ".join(args)
        self.assertIn("--start-position=123", joined)
        self.assertIn("--stop-position=999", joined)
        self.assertIn("--stop-datetime=2026-09-20 14:37:13", joined)
        self.assertIn("--database=app", joined)
        self.assertTrue(joined.endswith("bin.000001 bin.000002"))

    def test_docker_mysqlbinlog_uses_companion_container(self):
        s, _ = self.config("""
[mysql]
mode=docker
container=mysql-source
binlog_container=mysql-tools
container_host=127.0.0.1
container_port=3306
user=backup
password=secret
""")
        c = mod.MySQLClient(s)
        args, _ = c.mysqlbinlog_command("app", ["bin.000001"], start_position=4)
        self.assertIn("mysql-tools", args)
        self.assertNotIn("mysql-source", args)
        self.assertIn("mysqlbinlog", args)

    def test_docker_mysqlbinlog_defaults_to_source_container(self):
        s, _ = self.config("""
[mysql]
mode=docker
container=mysql-source
user=backup
""")
        c = mod.MySQLClient(s)
        args, _ = c.mysqlbinlog_command("app", ["bin.000001"])
        self.assertIn("mysql-source", args)

    def test_restore_target_falls_back_when_disabled(self):
        s, _ = self.config("""
[mysql]
mode=native
host=10.0.0.1
user=backup
[restore_target]
enabled=false
host=10.0.0.2
user=restore
""")
        client = mod.MySQLClient(s, "restore_target")
        self.assertTrue(client.uses_fallback)
        self.assertEqual(client.host, "10.0.0.1")
        self.assertEqual(client.user, "backup")

    def test_restore_target_independent_when_enabled(self):
        s, _ = self.config("""
[mysql]
mode=native
host=10.0.0.1
user=backup
[restore_target]
enabled=true
mode=native
host=10.0.0.2
user=restore
""")
        client = mod.MySQLClient(s, "restore_target")
        self.assertFalse(client.uses_fallback)
        self.assertEqual(client.host, "10.0.0.2")
        self.assertEqual(client.user, "restore")

    def test_add_drop_database_default_and_mysql_exception(self):
        s, _ = self.config("""
[mysql]
mode=native
""")
        c = mod.MySQLClient(s)
        c._dump_help = "--source-data --set-gtid-purged --no-tablespaces"
        app, _ = c.dump_command("app", False)
        mysql, _ = c.dump_command("mysql", False)
        self.assertIn("--add-drop-database", app)
        self.assertNotIn("--add-drop-database", mysql)

    def test_default_database_exclusion_contains_mysql(self):
        s, _ = self.config("""
[mysql]
mode=native
""")
        c = mod.MySQLClient(s)
        c.query = mock.Mock(return_value=[["app"], ["mysql"], ["sys"], ["information_schema"]])
        self.assertEqual(c.databases(), ["app"])

    def test_missing_executable_becomes_backup_error(self):
        with self.assertRaises(mod.BackupError):
            mod.MySQLClient.run(["/definitely/not/a/program"])


class EncryptionTests(TempConfigMixin, unittest.TestCase):
    def test_unencrypted_old_manifest_works_when_encryption_now_enabled(self):
        s, td = self.config("""
[encryption]
enabled=true
provider=age
age_recipient=age1example
age_identity_file=/nonexistent
""")
        e = mod.EncryptionManager(s)
        backup = td / "x.sql.gz"
        with gzip.open(backup, "wb") as fh:
            fh.write(b"SELECT 1;\n")
        e.verify_payload(backup, {"enabled": False, "provider": "none"})

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_openssl_manifest_preserves_kdf_iterations(self):
        s1, td = self.config("""
[encryption]
enabled=true
provider=openssl
openssl_passphrase_file={passfile}
openssl_pbkdf2_iterations=1000
""".replace("{passfile}", "/tmp/placeholder"))
        passfile = td / "pass"
        passfile.write_text("correct horse battery staple\n")
        # Re-read with actual pass path.
        cfg1 = td / "enc1.ini"
        cfg1.write_text(f"""[encryption]\nenabled=true\nprovider=openssl\nopenssl_passphrase_file={passfile}\nopenssl_pbkdf2_iterations=1000\n""")
        enc1 = mod.EncryptionManager(mod.Settings(str(cfg1)))
        plain = td / "data.sql.gz"
        with gzip.open(plain, "wb") as fh:
            fh.write(b"CREATE DATABASE test;\n")
        encrypted = td / "data.sql.gz.enc"
        enc1.encrypt(plain, encrypted)
        metadata = enc1.metadata()
        self.assertEqual(metadata["pbkdf2_iterations"], 1000)

        cfg2 = td / "enc2.ini"
        cfg2.write_text(f"""[encryption]\nenabled=true\nprovider=openssl\nopenssl_passphrase_file={passfile}\nopenssl_pbkdf2_iterations=9999\n""")
        enc2 = mod.EncryptionManager(mod.Settings(str(cfg2)))
        # Must use 1000 from backup metadata, not current 9999.
        enc2.verify_payload(encrypted, metadata)


class RemoteTests(TempConfigMixin, unittest.TestCase):
    def test_object_lock_command(self):
        s, _ = self.config("""
[remote]
enabled=true
backend=rclone
destination=minio:bucket/root
[object_lock]
enabled=true
bucket=bucket
prefix=root
mode=COMPLIANCE
retention_days=30
endpoint_url=https://minio.example
""")
        r = mod.RemoteStore(s, Path("/backup/mysql_backup"))
        cmd = r._object_lock_command("app/full/file.sql.gz")
        self.assertIsNotNone(cmd)
        joined = " ".join(cmd or [])
        self.assertIn("put-object-retention", joined)
        self.assertIn("COMPLIANCE", joined)
        self.assertIn("root/app/full/file.sql.gz", joined)

    def test_manifest_is_promoted_last_and_final_sizes_verified(self):
        s, td = self.config("""
[remote]
enabled=true
backend=rclone
destination=remote:bucket
retries=1
""")
        root = td / "root"
        root.mkdir()
        data = root / "x.sql.gz"
        sha = root / "x.sql.gz.sha256"
        manifest = root / "x.sql.gz.json"
        for p, content in ((data, b"data"), (sha, b"hash"), (manifest, b"{}")):
            p.write_bytes(content)
        r = mod.RemoteStore(s, root)
        commands = []
        verified = []
        r._rclone = mock.Mock(side_effect=lambda *parts, **kwargs: commands.append(parts) or subprocess.CompletedProcess(parts, 0, "", ""))
        r._verify_remote_size = mock.Mock(side_effect=lambda path, size: verified.append(path))
        r.apply_object_lock = mock.Mock()
        r.upload_bundle([manifest, data, sha])
        moves = [cmd for cmd in commands if cmd and cmd[0] == "moveto"]
        self.assertTrue(moves[-1][2].endswith(".json"))
        self.assertTrue(verified[-1].endswith(".json"))



    def test_ensure_bundle_republishes_missing_remote_manifest(self):
        s, td = self.config("""
[remote]
enabled=true
backend=rclone
destination=remote:bucket
""")
        root = td / "root"
        root.mkdir()
        data = root / "x.sql.gz"
        data.write_bytes(b"data")
        Path(str(data) + ".json").write_text("{}")
        r = mod.RemoteStore(s, root)
        r.bundle_complete = mock.Mock(return_value=False)
        r.upload_bundle = mock.Mock()
        r.ensure_bundle(data)
        r.upload_bundle.assert_called_once()


class BackupManagerTests(TempConfigMixin, unittest.TestCase):
    def manager_without_init(self, settings):
        m = object.__new__(mod.BackupManager)
        m.s = settings
        m.root = settings.backup_root
        m.root.mkdir(parents=True, exist_ok=True)
        m.state = mod.StateStore(settings)
        m.remote = mod.RemoteStore(settings, m.root)
        m.encryption = mod.EncryptionManager(settings)
        return m

    def test_gfs_keeps_one_per_bucket(self):
        s, td = self.config(f"""
[general]
backup_root={td if False else '/tmp'}
[retention]
minimum_full_backups=1
gfs_daily=7
gfs_weekly=4
gfs_monthly=12
""")
        m = object.__new__(mod.BackupManager)
        m.s = s
        policy = mod.BackupManager.policy(m, "app")
        now = mod.now_local()
        with tempfile.TemporaryDirectory() as temp:
            items = []
            for hours in (1, 2, 25, 26):
                p = Path(temp) / f"f{hours}.sql.gz"
                p.write_bytes(b"x")
                when = now - dt.timedelta(hours=hours)
                items.append((p, {"completed_at": when.isoformat()}))
            keep = mod.BackupManager._gfs_keep(m, items, policy)
            self.assertLessEqual(len(keep), 3)
            self.assertGreaterEqual(len(keep), 2)

    def test_backup_candidates_use_manifest_time_not_mtime(self):
        s, td = self.config(f"""
[general]
backup_root={td if False else '/tmp'}
""")
        # Create a separate config with the actual temporary root.
        cfg = td / "real.ini"
        cfg.write_text(f"[general]\nbackup_root={td}\nbackup_namespace=b\nstate_dir={td}/state\n")
        s = mod.Settings(str(cfg))
        m = self.manager_without_init(s)
        _, full_dir, _ = m.db_paths("app")
        full_dir.mkdir(parents=True)
        older = full_dir / "app__full__old.sql.gz"
        newer = full_dir / "app__full__new.sql.gz"
        older.write_bytes(b"x")
        newer.write_bytes(b"y")
        mod.atomic_json_write(m.manifest_path(older), {"completed_at": "2026-09-20T10:00:00+00:00"})
        mod.atomic_json_write(m.manifest_path(newer), {"completed_at": "2026-09-20T11:00:00+00:00"})
        os.utime(older, (time.time() + 1000, time.time() + 1000))
        os.utime(newer, (time.time() - 1000, time.time() - 1000))
        self.assertEqual(m._backup_candidates("app", "full")[0], newer)

    def test_unique_filename_on_collision(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            first = folder / "app__full__2026-01-01_00-00-00.sql.gz.age"
            first.write_bytes(b"x")
            candidate = mod.BackupManager._unique_plain_path(folder, "app__full__2026-01-01_00-00-00.sql.gz")
            self.assertNotEqual(candidate.name, "app__full__2026-01-01_00-00-00.sql.gz")
            self.assertTrue(candidate.name.endswith(".sql.gz"))

    def test_sha_sidecar_disagreement_is_rejected(self):
        cfgtd = tempfile.TemporaryDirectory()
        self.addCleanup(cfgtd.cleanup)
        td = Path(cfgtd.name)
        cfg = td / "c.ini"
        cfg.write_text(f"[general]\nbackup_root={td}\nbackup_namespace=b\nstate_dir={td}/state\n")
        s = mod.Settings(str(cfg))
        m = self.manager_without_init(s)
        path = td / "b" / "app" / "full" / "x.sql.gz"
        path.parent.mkdir(parents=True)
        with gzip.open(path, "wb") as fh:
            fh.write(b"SELECT 1;")
        digest = mod.sha256_file(path)
        mod.atomic_json_write(m.manifest_path(path), {"type":"full", "database":"app", "sha256":digest, "encryption":{"enabled":False,"provider":"none"}})
        m.sha_path(path).write_text("0" * 64 + f"  {path.name}\n")
        with self.assertRaises(mod.BackupError):
            m.verify_backup(path, "app", "full", deep=False)

    def test_remove_bundle_manifest_first(self):
        cfgtd = tempfile.TemporaryDirectory()
        self.addCleanup(cfgtd.cleanup)
        td = Path(cfgtd.name)
        cfg = td / "c.ini"
        cfg.write_text(f"[general]\nbackup_root={td}\nbackup_namespace=b\nstate_dir={td}/state\n")
        s = mod.Settings(str(cfg))
        m = self.manager_without_init(s)
        path = td / "b" / "app" / "full" / "x.sql.gz"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"x")
        m.sha_path(path).write_text("x")
        m.manifest_path(path).write_text("{}")
        order = []
        m.remote.delete_local_counterpart = mock.Mock(side_effect=lambda p: order.append(p.name))
        m._remove_backup_bundle(path)
        self.assertTrue(order[0].endswith(".json"))
        self.assertEqual(order[-1], path.name)

    def test_orphan_payload_is_cleaned(self):
        cfgtd = tempfile.TemporaryDirectory()
        self.addCleanup(cfgtd.cleanup)
        td = Path(cfgtd.name)
        cfg = td / "c.ini"
        cfg.write_text(f"""[general]\nbackup_root={td}\nbackup_namespace=b\nstate_dir={td}/state\n[retention]\ngfs_daily=0\ngfs_weekly=0\ngfs_monthly=0\n""")
        s = mod.Settings(str(cfg))
        m = self.manager_without_init(s)
        _, full_dir, _ = m.db_paths("app")
        full_dir.mkdir(parents=True)
        orphan = full_dir / "app__full__2026-01-01_00-00-00.sql.gz"
        orphan.write_bytes(b"x")
        old = time.time() - 90000
        os.utime(orphan, (old, old))
        m.prune_database("app")
        self.assertFalse(orphan.exists())

    def test_diff_max_age_uses_newer_full_as_restore_point(self):
        cfgtd = tempfile.TemporaryDirectory()
        self.addCleanup(cfgtd.cleanup)
        td = Path(cfgtd.name)
        cfg = td / "c.ini"
        cfg.write_text(f"""[general]\nstate_dir={td}/state\nbackup_root={td}\n[schedule]\ndiff_max_age_minutes=60\n""")
        s = mod.Settings(str(cfg))
        m = self.manager_without_init(s)
        now = mod.now_local()
        m.state.db("app")["last_diff"] = {"time": (now-dt.timedelta(hours=3)).isoformat()}
        m.state.db("app")["last_full"] = {"time": (now-dt.timedelta(minutes=10)).isoformat()}
        self.assertFalse(m._max_age_due("app", "diff", now))

    def test_retry_cooldown(self):
        cfgtd = tempfile.TemporaryDirectory()
        self.addCleanup(cfgtd.cleanup)
        td = Path(cfgtd.name)
        cfg = td / "c.ini"
        cfg.write_text(f"""[general]\nstate_dir={td}/state\nbackup_root={td}\n[schedule]\nretry_cooldown_seconds=300\n""")
        s = mod.Settings(str(cfg))
        m = self.manager_without_init(s)
        now = mod.now_local().replace(microsecond=0)
        m._mark_scheduler_failure("app:full", now, mod.BackupError("boom"))
        self.assertFalse(m._retry_allowed("app:full", now + dt.timedelta(seconds=299)))
        self.assertTrue(m._retry_allowed("app:full", now + dt.timedelta(seconds=300)))


    def test_scheduler_failure_isolated_per_database(self):
        cfgtd = tempfile.TemporaryDirectory()
        self.addCleanup(cfgtd.cleanup)
        td = Path(cfgtd.name)
        cfg = td / "c.ini"
        cfg.write_text(f"""[general]
state_dir={td}/state
backup_root={td}
lock_file={td}/service.lock
stop_on_database_error=false
[schedule]
full=* * * * *
diff=off
poll_seconds=5
full_on_start_if_missing=false
retry_cooldown_seconds=300
[diff]
enabled=false
""")
        s = mod.Settings(str(cfg))
        m = self.manager_without_init(s)
        m.databases = mock.Mock(return_value=["bad", "good"])
        m.prune_database = mock.Mock()
        calls = []
        def create(db):
            calls.append(db)
            if db == "bad":
                raise mod.BackupError("boom")
            return Path("ok")
        m.create_full = mock.Mock(side_effect=create)
        m.create_diff = mock.Mock()
        old_stop = mod.STOP_REQUESTED
        mod.STOP_REQUESTED = False
        try:
            def stop_sleep(_):
                mod.STOP_REQUESTED = True
            with mock.patch.object(mod.time, "sleep", side_effect=stop_sleep):
                m.run_daemon()
        finally:
            mod.STOP_REQUESTED = old_stop
        self.assertEqual(calls, ["bad", "good"])

    def test_fresh_full_suppresses_same_cycle_diff(self):
        cfgtd = tempfile.TemporaryDirectory()
        self.addCleanup(cfgtd.cleanup)
        td = Path(cfgtd.name)
        cfg = td / "c.ini"
        cfg.write_text(f"""[general]
state_dir={td}/state
backup_root={td}
lock_file={td}/service.lock
[schedule]
full=* * * * *
diff=* * * * *
poll_seconds=5
full_on_start_if_missing=false
[diff]
enabled=true
""")
        s = mod.Settings(str(cfg))
        m = self.manager_without_init(s)
        m.databases = mock.Mock(return_value=["app"])
        m.create_full = mock.Mock(return_value=Path("full"))
        m.create_diff = mock.Mock(return_value=Path("diff"))
        m.prune_database = mock.Mock()
        old_stop = mod.STOP_REQUESTED
        mod.STOP_REQUESTED = False
        try:
            def stop_sleep(_):
                mod.STOP_REQUESTED = True
            with mock.patch.object(mod.time, "sleep", side_effect=stop_sleep):
                m.run_daemon()
        finally:
            mod.STOP_REQUESTED = old_stop
        m.create_full.assert_called_once_with("app")
        m.create_diff.assert_not_called()


class RestoreSafetyTests(TempConfigMixin, unittest.TestCase):
    def make_manager(self, td: Path):
        cfg = td / "c.ini"
        cfg.write_text(f"""
[general]
backup_root={td}
backup_namespace=b
state_dir={td}/state
verify_before_restore=false
[mysql]
mode=native
[restore_target]
enabled=true
mode=native
host=target
user=restore
""")
        m = object.__new__(mod.BackupManager)
        m.s = mod.Settings(str(cfg))
        m.mysql = mod.MySQLClient(m.s, "mysql")
        m.restore_mysql = mod.MySQLClient(m.s, "restore_target")
        m.encryption = mod.EncryptionManager(m.s)
        m.root = m.s.backup_root
        m.state = mod.StateStore(m.s)
        m.remote = mod.RemoteStore(m.s, m.root)
        return m

    def test_diff_and_pitr_are_mutually_exclusive(self):
        with tempfile.TemporaryDirectory() as tdstr:
            m = self.make_manager(Path(tdstr))
            with self.assertRaises(mod.BackupError):
                m.restore("app", Path("f"), Path("d"), False, True, "2026-09-20 12:00:00")

    def test_future_pitr_rejected(self):
        with tempfile.TemporaryDirectory() as tdstr:
            m = self.make_manager(Path(tdstr))
            future = (mod.now_local() + dt.timedelta(days=1)).isoformat()
            with self.assertRaises(mod.BackupError):
                m.restore("app", Path("f"), None, False, True, future)

    def test_table_filtered_full_cannot_pitr(self):
        with tempfile.TemporaryDirectory() as tdstr:
            m = self.make_manager(Path(tdstr))
            full = Path(tdstr) / "full.sql.gz"
            full.write_bytes(b"x")
            manifest = {
                "type":"full", "database":"app", "completed_at":"2026-09-20T10:00:00+00:00",
                "policy":{"exclude_tables":["audit"],"schema_only_tables":[]},
                "encryption":{"enabled":False,"provider":"none"},
            }
            m.verify_backup = mock.Mock(return_value=manifest)
            with self.assertRaisesRegex(mod.BackupError, "table-filtered"):
                m.restore("app", full, None, False, True, "2026-09-20T11:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
