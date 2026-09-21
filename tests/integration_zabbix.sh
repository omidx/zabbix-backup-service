#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
SOURCE_CONTAINER="zbx-backup-src-${RANDOM}-${RANDOM}"
TARGET_CONTAINER="zbx-backup-dst-${RANDOM}-${RANDOM}"
TOOLS_CONTAINER="zbx-backup-tools-${RANDOM}-${RANDOM}"
TOOLS_IMAGE="zabbix-backup-tools:ci"
ROOT_PASSWORD='ZabbixIntegration-42!'
CONFIG="$WORK_DIR/zabbix.ini"
PASSPHRASE="$WORK_DIR/passphrase"

cleanup() {
  docker rm -f "$SOURCE_CONTAINER" "$TARGET_CONTAINER" "$TOOLS_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

wait_mysql() {
  local container="$1"
  for _ in $(seq 1 90); do
    if docker exec -e MYSQL_PWD="$ROOT_PASSWORD" "$container" mysql -uroot --batch --skip-column-names -e 'SELECT 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  docker logs "$container" >&2 || true
  return 1
}

mysql_exec() {
  local container="$1"
  shift
  docker exec -e MYSQL_PWD="$ROOT_PASSWORD" "$container" mysql -uroot --batch --skip-column-names "$@"
}

mkdir -p "$WORK_DIR/backups" "$WORK_DIR/state" "$WORK_DIR/remote" "$WORK_DIR/run"
mkdir -p "$WORK_DIR/fixture/etc/zabbix" "$WORK_DIR/fixture/usr/share/zabbix"
echo "DBName=zabbix" > "$WORK_DIR/fixture/etc/zabbix/zabbix_server.conf"
echo "DBUser=root" >> "$WORK_DIR/fixture/etc/zabbix/zabbix_server.conf"
echo "<?php echo 'fixture'; ?>" > "$WORK_DIR/fixture/usr/share/zabbix/index.php"
echo 'zabbix-integration-passphrase' > "$PASSPHRASE"
chmod 600 "$PASSPHRASE"

docker run -d --name "$SOURCE_CONTAINER" -e MYSQL_ROOT_PASSWORD="$ROOT_PASSWORD" -e MYSQL_ROOT_HOST='%' \
  mysql:8.4 --server-id=201 --log-bin=mysql-bin --binlog-format=ROW --binlog-row-image=FULL >/dev/null
docker run -d --name "$TARGET_CONTAINER" -e MYSQL_ROOT_PASSWORD="$ROOT_PASSWORD" -e MYSQL_ROOT_HOST='%' \
  mysql:8.4 --skip-log-bin >/dev/null
wait_mysql "$SOURCE_CONTAINER"
wait_mysql "$TARGET_CONTAINER"

docker build -q -f "$ROOT_DIR/docker/mysql-tools/Dockerfile" -t "$TOOLS_IMAGE" "$ROOT_DIR" >/dev/null
docker run -d --name "$TOOLS_CONTAINER" --network container:"$SOURCE_CONTAINER" "$TOOLS_IMAGE" sleep infinity >/dev/null

mysql_exec "$SOURCE_CONTAINER" -e "CREATE DATABASE zabbix; CREATE TABLE zabbix.hosts(id INT PRIMARY KEY, name VARCHAR(100)); INSERT INTO zabbix.hosts VALUES (1,'one'),(2,'two');"

cat > "$CONFIG" <<EOF_CONFIG
[general]
backup_root = $WORK_DIR
backup_namespace = backups
state_dir = $WORK_DIR/state
lock_file = $WORK_DIR/service.lock
log_file =
gzip_level = 6
verify_after_backup = true
verify_before_restore = true
write_sha256_file = true
min_free_space_mb = 0
min_free_space_percent = 0

[zabbix]
server_config = $WORK_DIR/fixture/etc/zabbix/zabbix_server.conf
database_from_server_config = false
runtime_dir = $WORK_DIR/run

[mysql]
mode = docker
container = $SOURCE_CONTAINER
binlog_container = $TOOLS_CONTAINER
container_host = 127.0.0.1
container_port = 3306
user = root
password = $ROOT_PASSWORD
defaults_extra_file =
include_databases = zabbix
exclude_databases = information_schema,performance_schema,sys,mysql
add_drop_database = true

[restore_target]
enabled = true
mode = docker
container = $TARGET_CONTAINER
container_host = 127.0.0.1
container_port = 3306
user = root
password = $ROOT_PASSWORD
defaults_extra_file =

[schedule]
full = off
diff = off
poll_seconds = 5
retry_cooldown_seconds = 5
full_on_start_if_missing = false

[diff]
enabled = true
filter_by_database = true
require_row_binlog = true
gap_policy = full
missing_full_policy = full

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
paths = $WORK_DIR/fixture/etc/zabbix,$WORK_DIR/fixture/usr/share/zabbix
exclude_patterns = *.sock,*.pid
verify_after_backup = true
retention_days = 30
minimum_backups = 1
gfs_daily = 0
gfs_weekly = 0
gfs_monthly = 0
state_file = $WORK_DIR/state/files.json
log_file =

[encryption]
enabled = true
provider = openssl
openssl_passphrase_file = $PASSPHRASE
openssl_pbkdf2_iterations = 10000

[remote]
enabled = true
backend = rclone
destination = $WORK_DIR/remote
rclone_config =
retries = 1
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
EOF_CONFIG

cd "$ROOT_DIR"
python3 zabbix_backup_service.py --config "$CONFIG" config-test
python3 zabbix_backup_service.py --config "$CONFIG" doctor
python3 zabbix_backup_service.py --config "$CONFIG" backup --type bundle

FULL_FILE="$(find "$WORK_DIR/backups/zabbix/full" -maxdepth 1 -type f -name '*.sql.gz.enc' | head -n1)"
FILES_ARCHIVE="$(find "$WORK_DIR/backups/zabbix_files/full" -maxdepth 1 -type f -name '*.tar.gz.enc' | head -n1)"
test -n "$FULL_FILE"
test -n "$FILES_ARCHIVE"
test -f "$WORK_DIR/remote/zabbix/full/$(basename "$FULL_FILE").json"
test -f "$WORK_DIR/remote/zabbix_files/full/$(basename "$FILES_ARCHIVE").json"

mysql_exec "$SOURCE_CONTAINER" -e "INSERT INTO zabbix.hosts VALUES (3,'three');"
python3 zabbix_backup_service.py --config "$CONFIG" backup --type diff
python3 zabbix_backup_service.py --config "$CONFIG" restore --latest --yes
COUNT="$(mysql_exec "$TARGET_CONTAINER" -e 'SELECT COUNT(*) FROM zabbix.hosts;')"
test "$COUNT" = "3"

RESTORE_ROOT="$WORK_DIR/restored-files"
python3 zabbix_backup_service.py --config "$CONFIG" restore-files --archive "$FILES_ARCHIVE" --target "$RESTORE_ROOT" --yes
test -f "$RESTORE_ROOT/${WORK_DIR#/}/fixture/usr/share/zabbix/index.php"
python3 zabbix_backup_service.py --config "$CONFIG" verify --component all

echo "Zabbix integration passed: bundle + encrypted remote + Diff restore + files restore"
