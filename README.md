# Zabbix Backup Service v2.1

Production-grade backup and recovery service for **Zabbix with a MySQL/MariaDB database**.

This repository started as a small Bash script that dumped the Zabbix database and archived the frontend directory. Version 2.1 keeps that Zabbix-specific goal but rebuilds the project on top of the same tested backup engine used by [`omidx/mysql-backup-service`](https://github.com/omidx/mysql-backup-service).

It backs up both sides of a Zabbix deployment:

1. **Zabbix database** — Full logical backup + binary-log Diff/PITR.
2. **Zabbix files** — server configuration, frontend/PHP files and optional scripts/binaries.

## What changed from the old script

The original `zabbix-backup.sh`:

- expected three hard-coded variables in the script;
- passed the MySQL password on the command line;
- attempted to parse `zabbix_server.conf` as PHP `define(...)` statements;
- created one database dump and one `/usr/share/zabbix` tar file;
- had no retention engine, verification, restore command, remote copy, encryption or service scheduler.

Version 2.1 replaces that with:

- correct parsing of Zabbix `DBName=`, `DBUser=`, `DBPassword=`, `DBHost=`, `DBPort=`, `DBSocket=` and `DBTLS*` settings;
- recursive support for Zabbix `Include=` configuration globs;
- secret-safe temporary MySQL option files under `/run` with mode `0600`;
- Full + binlog-based Diff backups;
- exact Point-in-Time Restore (PITR);
- independent restore target support;
- Zabbix configuration/frontend/script archives;
- SHA-256, manifests and verification;
- `age`, GPG or OpenSSL AES-256-CBC/PBKDF2 encryption;
- S3/MinIO/B2/SFTP/FTP replication through rclone;
- staged remote publication with manifest-last completion semantics;
- optional S3-compatible Object Lock;
- GFS retention;
- bandwidth/I/O throttling;
- automated Docker database restore tests;
- systemd auto-start;
- CI on Python 3.8, 3.11 and 3.13 plus MySQL 8.4 end-to-end tests.

## Backup layout

Default configuration:

```ini
[general]
backup_root = /backup
backup_namespace = zabbix_backup
```

Example output:

```text
/backup/zabbix_backup/
├── zabbix/
│   ├── full/
│   │   ├── zabbix__full__2026-09-21_02-00-00.sql.gz
│   │   ├── ...json
│   │   └── ...sha256
│   └── diff/
│       └── zabbix__diff__2026-09-21_03-00-00__base-....sql.gz
└── zabbix_files/
    └── full/
        ├── zabbix_files__full__2026-09-21_02-15-00.tar.gz
        ├── ...json
        └── ...sha256
```

When encryption is enabled, payload extensions become `.age`, `.gpg` or `.enc`.

## Zabbix database auto-discovery

The default mode reads the real Zabbix server configuration:

```ini
[zabbix]
server_config = /etc/zabbix/zabbix_server.conf
database_from_server_config = true
```

The service understands normal Zabbix syntax such as:

```text
DBHost=localhost
DBName=zabbix
DBUser=zabbix
DBPassword=CHANGE_ME
DBPort=3306
```

It also follows `Include=` patterns recursively.

The database password is **not** copied into the persistent service configuration and is not placed on a process command line. At startup, the service writes a private MySQL option file below:

```text
/run/zabbix-backup-service/mysql-client.cnf
```

with mode `0600`. The file lives under `/run` and is removed when the wrapper exits normally.

### Docker database deployments

For Docker/containerized Zabbix databases, use explicit database settings:

```ini
[zabbix]
database_from_server_config = false

[mysql]
mode = docker
container = mysql
binlog_container = mysql-backup-tools
user = backup
password = CHANGE_ME
include_databases = zabbix
```

The repository includes `docker/mysql-tools/Dockerfile` because the minimal official MySQL 8.4 server image does not include every client utility required for remote binlog collection.

## Zabbix files backup

Defaults:

```ini
[zabbix_files]
enabled = true
schedule = 15 2 * * *
paths = /etc/zabbix,/usr/share/zabbix,/usr/share/zabbix-*,/usr/lib/zabbix
exclude_patterns = *.sock,*.pid
```

Only paths that actually exist are archived. Wildcards are supported.

The 02:15 default intentionally follows the default database Full backup at 02:00 to reduce I/O overlap.

You can add custom alert scripts, external scripts, web-server configuration or any other deployment-specific files:

```ini
paths = /etc/zabbix,/usr/share/zabbix,/usr/lib/zabbix,/etc/nginx/conf.d/zabbix.conf
```

The service rejects configurations where a source path overlaps the backup destination, preventing recursive backup growth.

## Database backup model

The database engine is the same as `mysql-backup-service` v2.1.

### Full

A Full backup uses `mysqldump` with safe production defaults such as:

- `--single-transaction`
- `--quick`
- routines/events/triggers
- binary-log coordinates
- SHA-256 and JSON manifest

### Diff

A Diff is reconstructed from MySQL binary logs from the latest compatible Full coordinate to the current coordinate.

Default:

```ini
[schedule]
full = 0 2 * * *
diff = 0 * * * *
```

For reliable per-database row-event recovery, binary logging and ROW format are expected when Diff is enabled.

### Exact PITR

Example:

```bash
sudo zabbix-backup-service restore \
  --latest \
  --to-time "2026-09-21 14:37:12" \
  --yes
```

When DBName was auto-discovered, `--database` is optional.

PITR reads binary logs from the source server and can apply them to a separate restore target.

## Separate restore target

Recommended for DR testing and production recovery:

```ini
[restore_target]
enabled = true
mode = native
host = 10.10.10.50
port = 3306
user = restore
defaults_extra_file = /etc/zabbix-backup-service/mysql-restore-client.cnf
```

This prevents an accidental restore from automatically writing back to the production Zabbix database.

## Installation

```bash
git clone https://github.com/omidx/zabbix-backup-service.git
cd zabbix-backup-service
sudo ./install.sh
```

The installer creates:

```text
/usr/local/lib/zabbix-backup-service/
/usr/local/bin/zabbix-backup-service
/etc/zabbix-backup-service/zabbix-backup.conf
/var/lib/zabbix-backup-service/
/var/log/zabbix-backup-service/
/etc/systemd/system/zabbix-backup-service.service
```

It enables the systemd unit but does not start it before you review the configuration.

Validate:

```bash
sudo zabbix-backup-service config-test
sudo zabbix-backup-service doctor
```

Run one complete Zabbix backup before enabling production scheduling:

```bash
sudo zabbix-backup-service backup --type bundle
```

Then start:

```bash
sudo systemctl start zabbix-backup-service
sudo systemctl status zabbix-backup-service
sudo journalctl -u zabbix-backup-service -f
```

## CLI

```text
zabbix-backup-service run
zabbix-backup-service backup --type full
zabbix-backup-service backup --type diff
zabbix-backup-service backup --type files
zabbix-backup-service backup --type bundle
zabbix-backup-service restore [--database zabbix] --latest --yes
zabbix-backup-service restore --latest --to-time "YYYY-MM-DD HH:MM:SS" --yes
zabbix-backup-service restore-files --archive FILE --target / --yes
zabbix-backup-service verify --component all
zabbix-backup-service list --component all
zabbix-backup-service status
zabbix-backup-service prune --component all [--dry-run]
zabbix-backup-service doctor
zabbix-backup-service config-test
zabbix-backup-service schedule
zabbix-backup-service restore-test
zabbix-backup-service version
```

`zabbix-backup.sh` remains as a compatibility wrapper. Running it with no arguments starts the daemon; arguments are forwarded to the Python service.

## Remote/Object Storage

Remote replication uses rclone:

```ini
[remote]
enabled = true
destination = minio:zabbix-backups/server01
rclone_config = /root/.config/rclone/rclone.conf
bwlimit = 50M
```

Examples include:

- MinIO / S3-compatible storage
- AWS S3
- Backblaze B2
- SFTP
- FTP
- local/off-host rclone targets

Upload uses temporary remote objects and verifies object size. The JSON manifest is finalized last and acts as the completed-bundle marker.

## Encryption at rest

### age

```ini
[encryption]
enabled = true
provider = age
age_recipient = age1...
age_identity_file = /etc/zabbix-backup-service/age.key
```

### OpenSSL AES-256

```ini
[encryption]
enabled = true
provider = openssl
openssl_passphrase_file = /etc/zabbix-backup-service/backup.passphrase
openssl_pbkdf2_iterations = 200000
```

Database and Zabbix files payloads use the same configured encryption policy.

## Object Lock / immutability

For a compatible S3/MinIO bucket created with Object Lock/versioning:

```ini
[object_lock]
enabled = true
bucket = zabbix-backups
prefix = zabbix/server01
mode = COMPLIANCE
retention_days = 30
endpoint_url = https://minio.example.com
```

The AWS CLI is used only for object-retention operations; rclone still transfers the payloads.

## GFS retention

Database defaults:

```ini
[retention]
gfs_daily = 7
gfs_weekly = 4
gfs_monthly = 12
```

Zabbix files have an independent policy:

```ini
[zabbix_files]
retention_days = 30
minimum_backups = 2
gfs_daily = 7
gfs_weekly = 4
gfs_monthly = 12
```

Use dry-run before changing retention on a production host:

```bash
sudo zabbix-backup-service prune --component all --dry-run
```

## Restoring Zabbix files

The archive stores paths relative to filesystem root. Example:

```bash
sudo zabbix-backup-service restore-files \
  --archive /backup/zabbix_backup/zabbix_files/full/zabbix_files__full__....tar.gz \
  --target / \
  --yes
```

For a safe test restore:

```bash
mkdir -p /tmp/zabbix-restore-test
sudo zabbix-backup-service restore-files --archive FILE --target /tmp/zabbix-restore-test --yes
```

Restore rejects path traversal, escaping symlinks, device nodes and FIFOs before extraction.

## Zabbix history/trend tables

The service **does not exclude Zabbix history or trend data by default**. A backup advertised as a Zabbix backup should preserve the monitoring data unless the administrator explicitly chooses otherwise.

The generic engine supports `exclude_tables` and `schema_only_tables`, but table-filtered Full backups cannot safely be combined with arbitrary executable binlog Diff/PITR. If you intentionally exclude large history tables, disable Diff for that database and understand that those data will not be recoverable from the backup.

## Security notes

- Keep service configuration and credential files mode `0600`.
- Prefer the automatic Zabbix credential discovery for native deployments.
- Use a separate restore target/account for DR operations.
- Protect `rclone.conf`, encryption identities and passphrase files.
- Use Object Lock/immutability when your S3-compatible backend supports it.
- Keep an off-host copy; a local backup alone is not sufficient against host/storage loss or ransomware.
- Run `restore-test` and periodic Zabbix files restore tests.
- Do not commit production credentials to this repository.

## Important PITR limitation

Exact PITR requires the necessary binary logs to still be available from the configured MySQL source. Full/Diff backups stored remotely remain valid restore points, but arbitrary second-level PITR after total source loss requires a separate continuous raw-binlog archival design.

## Development / CI

CI validates:

- Python syntax on 3.8 / 3.11 / 3.13
- upstream database-engine unit tests
- Zabbix-specific parser/config/files tests
- Bash + systemd syntax
- MySQL 8.4 database-engine integration
- Zabbix bundle integration: database + files + encryption + remote + restore

Local checks:

```bash
python3 -m py_compile mysql_backup_service.py zabbix_backup_service.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
bash -n zabbix-backup.sh install.sh tests/integration.sh tests/integration_zabbix.sh
```

## License

GNU GPL v3. See [LICENSE.md](LICENSE.md).
