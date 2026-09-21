import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("zabbix_backup_service", ROOT / "zabbix_backup_service.py")
mod = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(mod)


class ZabbixTestCase(unittest.TestCase):
    def make_config(self, td: Path, server_conf: Path, paths, auto=True):
        cfg = td / "zabbix-backup.conf"
        cfg.write_text(f"""
[general]
backup_root = {td / 'backup-root'}
backup_namespace = zabbix_backup
state_dir = {td / 'state'}
lock_file = {td / 'service.lock'}
log_file =
min_free_space_mb = 0
min_free_space_percent = 0
write_sha256_file = true

[zabbix]
server_config = {server_conf}
database_from_server_config = {'true' if auto else 'false'}
runtime_dir = {td / 'run'}

[mysql]
mode = native
host = 127.0.0.1
port = 3306
user = backup
password =
defaults_extra_file =
include_databases = zabbix
exclude_databases = information_schema,performance_schema,sys,mysql
add_drop_database = true

[restore_target]
enabled = false

[schedule]
full = off
diff = off
full_on_start_if_missing = false
retry_cooldown_seconds = 5

[diff]
enabled = false

[retention]
full_days = 30
diff_days = 14
minimum_full_backups = 1
gfs_daily = 0
gfs_weekly = 0
gfs_monthly = 0

[zabbix_files]
enabled = true
schedule = off
paths = {','.join(str(p) for p in paths)}
exclude_patterns = *.sock,*.pid
verify_after_backup = true
retention_days = 30
minimum_backups = 1
gfs_daily = 0
gfs_weekly = 0
gfs_monthly = 0
state_file = {td / 'state' / 'files.json'}
log_file =

[encryption]
enabled = false
provider = age

[remote]
enabled = false
destination =
prune_with_local = false

[object_lock]
enabled = false

[throttle]
nice = 0
ionice_class = 0
local_stream_mbps = 0

[restore_test]
enabled = false
schedule = off

[notifications]
on_success = false
on_failure = false
""", encoding="utf-8")
        return cfg

    def fixture(self, td: Path):
        etc = td / "fixture" / "etc" / "zabbix"
        web = td / "fixture" / "usr" / "share" / "zabbix"
        etc.mkdir(parents=True)
        web.mkdir(parents=True)
        server = etc / "zabbix_server.conf"
        server.write_text("DBName=zabbix\nDBUser=zabbixuser\nDBPassword=p#ss=word\nDBHost=localhost\nDBPort=3306\n", encoding="utf-8")
        (web / "index.php").write_text("<?php echo 'zabbix'; ?>\n", encoding="utf-8")
        return server, etc, web


class ConfigParserTests(ZabbixTestCase):
    def test_reads_key_value_and_preserves_hash_in_password(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            main = td / "zabbix_server.conf"
            inc = td / "db.conf"
            inc.write_text("DBName=zabbix\nDBUser=backup\nDBPassword=abc#123=xyz\n", encoding="utf-8")
            main.write_text(f"Include={inc}\nDBHost=127.0.0.1\n", encoding="utf-8")
            parsed = mod.parse_zabbix_server_config(main)
            self.assertEqual(parsed["DBName"], "zabbix")
            self.assertEqual(parsed["DBPassword"], "abc#123=xyz")
            self.assertEqual(parsed["DBHost"], "127.0.0.1")

    def test_runtime_config_never_embeds_password(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            server, etc, web = self.fixture(td)
            cfg = self.make_config(td, server, [etc, web])
            s = mod.ZabbixSettings(str(cfg))
            runtime = mod.EffectiveConfig(s)
            runtime.prepare()
            try:
                effective = runtime.effective_path.read_text(encoding="utf-8")
                client = runtime.client_path.read_text(encoding="utf-8")
                self.assertNotIn("p#ss=word", effective)
                self.assertIn("p#ss=word", client)
                self.assertEqual(oct(runtime.client_path.stat().st_mode & 0o777), "0o600")
                self.assertIn("include_databases = zabbix", effective)
            finally:
                runtime.cleanup()

    def test_auto_database_rejects_docker_mode(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            server, etc, web = self.fixture(td)
            cfg = self.make_config(td, server, [etc, web])
            text = cfg.read_text(encoding="utf-8").replace("mode = native", "mode = docker", 1)
            cfg.write_text(text, encoding="utf-8")
            with self.assertRaises(mod.ZabbixBackupError):
                mod.ZabbixSettings(str(cfg)).validate()


class FilesBackupTests(ZabbixTestCase):
    def test_files_backup_verify_and_restore(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            server, etc, web = self.fixture(td)
            cfg = self.make_config(td, server, [etc, web])
            s = mod.ZabbixSettings(str(cfg))
            runtime = mod.EffectiveConfig(s)
            runtime.prepare()
            try:
                manager = mod.ZabbixFileBackupManager(s, runtime)
                archive = manager.create()
                self.assertTrue(archive.exists())
                self.assertTrue(Path(str(archive) + ".json").exists())
                manager.verify_one(archive)

                target = td / "restore"
                manager.restore(archive, target, True)
                expected = target / str(web).lstrip("/") / "index.php"
                self.assertTrue(expected.exists())
                self.assertIn("zabbix", expected.read_text(encoding="utf-8"))
            finally:
                runtime.cleanup()

    def test_rejects_unsafe_archive_member(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            info = tarfile.TarInfo("../escape")
            with self.assertRaises(mod.ZabbixBackupError):
                mod.ZabbixFileBackupManager._safe_member(info, td)

    def test_backup_root_overlap_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            td = Path(raw)
            server, _, _ = self.fixture(td)
            backup_root = td / "backup-root"
            backup_root.mkdir()
            cfg = self.make_config(td, server, [td])
            s = mod.ZabbixSettings(str(cfg))
            runtime = mod.EffectiveConfig(s)
            runtime.prepare()
            try:
                manager = mod.ZabbixFileBackupManager(s, runtime)
                with self.assertRaises(mod.ZabbixBackupError):
                    manager.source_paths()
            finally:
                runtime.cleanup()


if __name__ == "__main__":
    unittest.main()
