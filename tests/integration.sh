#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
SOURCE_CONTAINER="mysql-backup-src-${RANDOM}-${RANDOM}"
TARGET_CONTAINER="mysql-backup-dst-${RANDOM}-${RANDOM}"
TOOLS_CONTAINER="mysql-backup-tools-${RANDOM}-${RANDOM}"
TOOLS_IMAGE="mysql-backup-tools:ci"
ROOT_PASSWORD='IntegrationRoot-42!'
CONFIG="$WORK_DIR/integration.ini"
PASSPHRASE="$WORK_DIR/backup.passphrase"

cleanup() {
  docker rm -f "$SOURCE_CONTAINER" "$TARGET_CONTAINER" "$TOOLS_CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

wait_mysql() {
  local container="$1"
  for _ in $(seq 1 90); do
    # mysqladmin ping returns success even when authentication is denied, so
    # use an authenticated SQL query to wait for initialization to finish.
    if docker exec -e MYSQL_PWD="$ROOT_PASSWORD" "$container" \
      mysql -uroot --batch --skip-column-names -e 'SELECT 1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  echo "MySQL container did not become ready: $container" >&2
  docker logs "$container" >&2 || true
  return 1
}

mysql_exec() {
  local container="$1"
  shift
  docker exec -e MYSQL_PWD="$ROOT_PASSWORD" "$container" mysql -uroot --batch --skip-column-names "$@"
}

echo 'integration-backup-passphrase' > "$PASSPHRASE"
chmod 600 "$PASSPHRASE"

mkdir -p "$WORK_DIR/backups" "$WORK_DIR/state" "$WORK_DIR/remote"

docker run -d --name "$SOURCE_CONTAINER" \
  -e MYSQL_ROOT_PASSWORD="$ROOT_PASSWORD" \
  -e MYSQL_ROOT_HOST='%' \
  mysql:8.4 \
  --server-id=101 --log-bin=mysql-bin --binlog-format=ROW --binlog-row-image=FULL >/dev/null

docker run -d --name "$TARGET_CONTAINER" \
  -e MYSQL_ROOT_PASSWORD="$ROOT_PASSWORD" \
  -e MYSQL_ROOT_HOST='%' \
  mysql:8.4 --skip-log-bin >/dev/null

wait_mysql "$SOURCE_CONTAINER"
wait_mysql "$TARGET_CONTAINER"

# Docker Official mysql:8.4 uses mysql-community-server-minimal and does not
# include mysqlbinlog. Build the repo's companion tools image and share the
# source container's network namespace so 127.0.0.1:3306 reaches the source.
docker build -q -f "$ROOT_DIR/docker/mysql-tools/Dockerfile" -t "$TOOLS_IMAGE" "$ROOT_DIR" >/dev/null
docker run -d --name "$TOOLS_CONTAINER" --network container:"$SOURCE_CONTAINER" \
  "$TOOLS_IMAGE" sleep infinity >/dev/null
docker exec "$TOOLS_CONTAINER" mysqlbinlog --version >/dev/null

mysql_exec "$SOURCE_CONTAINER" -e "CREATE DATABASE appdb; CREATE TABLE appdb.items(id INT PRIMARY KEY, note VARCHAR(100)); INSERT INTO appdb.items VALUES (1,'one'),(2,'two');"

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
stop_on_database_error = false

[mysql]
mode = docker
container = $SOURCE_CONTAINER
binlog_container = $TOOLS_CONTAINER
container_host = 127.0.0.1
container_port = 3306
user = root
password = $ROOT_PASSWORD
defaults_extra_file =
include_databases = appdb
exclude_databases = information_schema,performance_schema,sys,mysql
set_gtid_purged_off = true
no_tablespaces = true
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
bwlimit =
prune_with_local = false

[object_lock]
enabled = false

[throttle]
nice = 0
ionice_class = 0
ionice_level = 7
local_stream_mbps = 0

[restore_test]
enabled = false
schedule = off
startup_timeout_seconds = 120

[notifications]
on_success = false
on_failure = false
EOF_CONFIG

cd "$ROOT_DIR"
python3 mysql_backup_service.py --config "$CONFIG" config-test
python3 mysql_backup_service.py --config "$CONFIG" doctor

# Full backup -> encrypted local payload + remote manifest.
python3 mysql_backup_service.py --config "$CONFIG" backup --type full --database appdb
FULL_FILE="$(find "$WORK_DIR/backups/appdb/full" -maxdepth 1 -type f -name '*.sql.gz.enc' | head -n1)"
test -n "$FULL_FILE"
test -f "$FULL_FILE.json"
test -f "$FULL_FILE.sha256"
test -f "$WORK_DIR/remote/appdb/full/$(basename "$FULL_FILE").json"

# Change source and create a differential backup.
mysql_exec "$SOURCE_CONTAINER" -e "INSERT INTO appdb.items VALUES (3,'three');"
python3 mysql_backup_service.py --config "$CONFIG" backup --type diff --database appdb
DIFF_FILE="$(find "$WORK_DIR/backups/appdb/diff" -maxdepth 1 -type f -name '*.sql.gz.enc' | head -n1)"
test -n "$DIFF_FILE"
test -f "$DIFF_FILE.json"
test -f "$WORK_DIR/remote/appdb/diff/$(basename "$DIFF_FILE").json"

# Restore Full + latest compatible Diff into a different MySQL target.
python3 mysql_backup_service.py --config "$CONFIG" restore --database appdb --latest --yes
COUNT="$(mysql_exec "$TARGET_CONTAINER" -e 'SELECT COUNT(*) FROM appdb.items;')"
test "$COUNT" = "3"

# Create one event that should be included and one that must be excluded by PITR.
sleep 2
mysql_exec "$SOURCE_CONTAINER" -e "INSERT INTO appdb.items VALUES (4,'four');"
sleep 2
PITR_TARGET="$(date -u '+%Y-%m-%d %H:%M:%S')"
sleep 2
mysql_exec "$SOURCE_CONTAINER" -e "INSERT INTO appdb.items VALUES (5,'five');"
sleep 1

# Exact PITR reads binary logs from SOURCE while applying SQL to TARGET.
python3 mysql_backup_service.py --config "$CONFIG" restore \
  --database appdb --latest --to-time "$PITR_TARGET" --yes

IDS="$(mysql_exec "$TARGET_CONTAINER" -e 'SELECT GROUP_CONCAT(id ORDER BY id) FROM appdb.items;')"
test "$IDS" = "1,2,3,4"
SOURCE_IDS="$(mysql_exec "$SOURCE_CONTAINER" -e 'SELECT GROUP_CONCAT(id ORDER BY id) FROM appdb.items;')"
test "$SOURCE_IDS" = "1,2,3,4,5"

python3 mysql_backup_service.py --config "$CONFIG" verify --database appdb

echo "Integration test passed: encrypted Full + Diff + rclone remote + separate-target restore + PITR"
