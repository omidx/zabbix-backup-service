#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${ZABBIX_BACKUP_CONFIG:-/etc/zabbix-backup-service/zabbix-backup.conf}"

if [[ -x "${SCRIPT_DIR}/zabbix_backup_service.py" ]]; then
  APP="${SCRIPT_DIR}/zabbix_backup_service.py"
elif [[ -x "/usr/local/lib/zabbix-backup-service/zabbix_backup_service.py" ]]; then
  APP="/usr/local/lib/zabbix-backup-service/zabbix_backup_service.py"
else
  echo "zabbix_backup_service.py not found" >&2
  exit 1
fi

if [[ $# -eq 0 ]]; then
  exec python3 "$APP" --config "$CONFIG" run
fi

for arg in "$@"; do
  if [[ "$arg" == "--config" || "$arg" == --config=* ]]; then
    exec python3 "$APP" "$@"
  fi
done

exec python3 "$APP" --config "$CONFIG" "$@"
