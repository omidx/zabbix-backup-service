#!/usr/bin/env bash
set -Eeuo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/usr/local/lib/zabbix-backup-service"
BIN_PATH="/usr/local/bin/zabbix-backup-service"
CONF_DIR="/etc/zabbix-backup-service"
STATE_DIR="/var/lib/zabbix-backup-service"
LOG_DIR="/var/log/zabbix-backup-service"
SERVICE_PATH="/etc/systemd/system/zabbix-backup-service.service"

if [[ $EUID -ne 0 ]]; then
  echo "Run this installer as root (sudo ./install.sh)." >&2
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

install -d -m 0755 "$APP_DIR" "$CONF_DIR" "$STATE_DIR" "$LOG_DIR"
install -m 0755 "$REPO_DIR/zabbix_backup_service.py" "$APP_DIR/zabbix_backup_service.py"
install -m 0755 "$REPO_DIR/mysql_backup_service.py" "$APP_DIR/mysql_backup_service.py"
install -m 0755 "$REPO_DIR/zabbix-backup.sh" "$BIN_PATH"
install -m 0644 "$REPO_DIR/zabbix-backup.service" "$SERVICE_PATH"

if [[ ! -f "$CONF_DIR/zabbix-backup.conf" ]]; then
  install -m 0600 "$REPO_DIR/zabbix-backup.conf.example" "$CONF_DIR/zabbix-backup.conf"
  echo "Created $CONF_DIR/zabbix-backup.conf"
else
  echo "Keeping existing $CONF_DIR/zabbix-backup.conf"
fi
if [[ ! -f "$CONF_DIR/mysql-client.cnf" ]]; then
  install -m 0600 "$REPO_DIR/mysql-client.cnf.example" "$CONF_DIR/mysql-client.cnf"
fi
if [[ ! -f "$CONF_DIR/mysql-restore-client.cnf" ]]; then
  install -m 0600 "$REPO_DIR/mysql-restore-client.cnf.example" "$CONF_DIR/mysql-restore-client.cnf"
fi

systemctl daemon-reload
systemctl enable zabbix-backup-service.service

cat <<EOF2

Installed Zabbix Backup Service v2.1.

Next steps:
  1. Review $CONF_DIR/zabbix-backup.conf
  2. Validate: $BIN_PATH config-test
  3. Doctor:   $BIN_PATH doctor
  4. Test:     $BIN_PATH backup --type bundle
  5. Start:    systemctl start zabbix-backup-service
  6. Logs:     journalctl -u zabbix-backup-service -f

With database_from_server_config=true (default), Zabbix DB credentials are read
from /etc/zabbix/zabbix_server.conf into a private 0600 file under /run. They are
not copied into the persistent service configuration or command line.
EOF2
