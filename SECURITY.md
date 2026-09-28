# Security policy

## Supported versions

Security fixes target the current `main` branch and subsequent releases. The Zabbix wrapper and shared MySQL engine currently identify themselves as **2.1.0**. No backport schedule is promised for earlier versions.

| Version | Security maintenance |
| --- | --- |
| Current `main` / 2.1.x | Report issues; fixes are evaluated for the current code |
| Earlier versions | No promised backports |

## Privately report a vulnerability

Use **Security → Report a vulnerability** in this repository if GitHub's private vulnerability reporting is available. Otherwise use a private contact method from the [maintainer's GitHub profile](https://github.com/omidx). Avoid public issues for exploit details. Never attach live Zabbix configuration, database dumps, API tokens, credentials, or identifying logs to a public report.

Give the affected commit/version, Python version, Zabbix/MySQL deployment mode, non-secret configuration, a reproduction in a disposable environment and the impact. Redact paths or hostnames if they identify a private deployment. Reports will be triaged as capacity allows; no fixed acknowledgement or remediation deadline is promised. Coordinate public disclosure after a fix is available.

If secrets or backups are exposed, rotate the affected credentials, isolate storage and follow your incident process immediately.

## Trust boundaries and deployment

The included unit runs as `root`. The wrapper reads `zabbix_server.conf` and any recursively included files, produces a `0600` temporary MySQL option file under `/run/zabbix-backup-service`, and invokes the shared `mysql_backup_service.py` engine. It also archives the configured Zabbix paths. Access to the Docker socket, service configuration, Zabbix source files, local backup directory, remote credentials and encryption keys is security sensitive.

- Keep Zabbix server configuration, `zabbix-backup.conf`, credential files, `/run/zabbix-backup-service`, the backup volume, log/state directories, rclone config and encryption keys accessible only to trusted service administrators. The process sets umask `0077`; check directory ownership and remote ACLs separately.
- Native auto-discovery reads DB credentials from Zabbix configuration into a private runtime option file, removed on normal wrapper exit. Abnormal termination can leave a file in `/run` until cleanup or reboot. With manual/Docker mode, do not put the database password in a committed config or image. The shared engine may pass inline Docker passwords in `docker exec -e MYSQL_PWD=...` arguments.
- A Zabbix files archive can contain `zabbix_server.conf`, TLS keys, frontend config, scripts and other secrets. The local `.tar.gz.plain.partial` file exists before optional encryption. Protect the local filesystem and snapshots; encrypted final archives do not make that transient copy secret.
- Configure and verify `[restore_target] enabled = true` with an isolated destination for database restore. When false, `restore --yes` falls back to the source MySQL connection. The `restore-files` command writes to `/` by default when `--target` is omitted: always specify a staging directory for drills and inspect the archive before a production restore.
- Restore only archives from a trusted source. Current code rejects path traversal, absolute symbolic links, hard links and device entries and rechecks members during extraction. Backups and their SHA-256 files are **not authenticated signatures**; an attacker controlling both can replace them. Prefer encrypted storage, independent access controls and external verification.
- Prefer age or GPG for final payload encryption. The OpenSSL AES-256-CBC/PBKDF2 option is not authenticated encryption. Keep private keys/passphrases away from the backups and test that they can be retrieved during disaster recovery.
- Use TLS-backed object storage or SFTP; avoid FTP for confidential data. Remote size checks and manifest-last publication are useful completion checks, not a cryptographic verification of the remote object. Test download and deep verification. Object Lock must be configured and tested on the destination itself.
- Restrict Docker socket access. `restore-test` verifies only the database in a disposable container; separately test restoration of Zabbix files and application behavior. It does not archive raw binary logs, so exact PITR still depends on the source binlogs surviving.
- The Zabbix paths glob can include more than `/etc/zabbix`; review `zabbix_files.paths` and `exclude_patterns` so the archive covers required assets without capturing unintended secrets or the backup root itself.

## Routine checks

Run `config-test`, `doctor`, `verify --component all`, `prune --dry-run`, and staged database/file restores on a schedule appropriate to your recovery objectives. Monitor both database and file state; a successful database backup does not prove that the Zabbix files archive succeeded. Validate the destination, permissions and keys independently.

For commands and recovery procedure, see the [README](README.md) and [Wiki](https://github.com/omidx/zabbix-backup-service/wiki). Shared-engine vulnerabilities should be reported privately to both projects when they affect both.
