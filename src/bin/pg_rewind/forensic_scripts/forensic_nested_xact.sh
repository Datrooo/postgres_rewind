#!/usr/bin/env bash
#--------------------------------------------------------------------------
# forensic_nested_xact.sh
#
# Проверяет декодирование изменений внутри вложенной транзакции (SAVEPOINT).
#--------------------------------------------------------------------------
set -euo pipefail

PGPORT_PRIMARY=${PGPORT_PRIMARY:-5604}
PGPORT_STANDBY=${PGPORT_STANDBY:-5605}
BASEDIR=$(mktemp -d /tmp/pg_forensic_nested.XXXX)
PRIMARY=$BASEDIR/primary
STANDBY=$BASEDIR/standby
FORENSIC_DIR=/tmp/pg_rewind_wal

PASS=0
FAIL=0
assert_ok() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  [OK] $desc"
    PASS=$((PASS+1))
  else
    echo "  [FAIL] $desc"
    FAIL=$((FAIL+1))
  fi
}
assert_file_exists() { assert_ok "$1" test -f "$2"; }
assert_not_empty()   { assert_ok "$1" test -s "$2"; }
assert_grep()        { assert_ok "$1" grep -q "$2" "$3"; }
assert_not_grep() {
  local desc="$1" pattern="$2" file="$3"
  if grep -q "$pattern" "$file" >/dev/null 2>&1; then
    echo "  [FAIL] $desc"
    FAIL=$((FAIL+1))
  else
    echo "  [OK] $desc"
    PASS=$((PASS+1))
  fi
}

cleanup_clusters() {
  set +e
  pg_ctl -D "$PRIMARY" -m fast stop >/dev/null 2>&1 || true
  pg_ctl -D "$STANDBY" -m fast stop >/dev/null 2>&1 || true
}

prepare_forensic_dir() {
  mkdir -p "$FORENSIC_DIR"
  : > "$FORENSIC_DIR/heap_analysis.sql"
  : > "$FORENSIC_DIR/physical_decode.txt"
  : > "$FORENSIC_DIR/summary.txt"
  rm -rf "$FORENSIC_DIR/saved_wal" "$FORENSIC_DIR/saved_data"
}

print_final_sql() {
  echo ""
  echo "--- Итоговый SQL (heap_analysis.sql) ---"
  if [ -f "$FORENSIC_DIR/heap_analysis.sql" ]; then
    cat "$FORENSIC_DIR/heap_analysis.sql"
  else
    echo "Файл $FORENSIC_DIR/heap_analysis.sql не найден"
  fi
}

on_exit() {
  local rc=$?
  trap - EXIT
  cleanup_clusters
  print_final_sql
  exit "$rc"
}
trap on_exit EXIT

echo "=== forensic_nested_xact ==="
echo "BASEDIR=$BASEDIR"

initdb -D "$PRIMARY" -A trust -U postgres >"$BASEDIR/initdb.log" 2>&1
cat >>"$PRIMARY/postgresql.conf" <<EOF2
wal_level = replica
max_wal_senders = 5
max_replication_slots = 5
EOF2
pg_ctl -D "$PRIMARY" -o "-k $BASEDIR -p $PGPORT_PRIMARY" -w start
psql -h "$BASEDIR" -p "$PGPORT_PRIMARY" -U postgres \
  -c "CREATE ROLE repl LOGIN REPLICATION" >/dev/null 2>&1

pg_basebackup -h "$BASEDIR" -p "$PGPORT_PRIMARY" -U repl \
  -D "$STANDBY" -R -X stream -C -S "rewind_slot_nested" \
  >"$BASEDIR/basebackup.log" 2>&1
pg_ctl -D "$STANDBY" -o "-k $BASEDIR -p $PGPORT_STANDBY" -w start

psql -h "$BASEDIR" -p "$PGPORT_PRIMARY" -U postgres -q <<'SQL'
CREATE TABLE nested_tx_t(
  id int PRIMARY KEY,
  note text
);
INSERT INTO nested_tx_t VALUES (1, 'before-failover');
SQL

pg_ctl -D "$PRIMARY" -m fast stop -w
pg_ctl -D "$PRIMARY" -o "-k $BASEDIR -p $PGPORT_PRIMARY" -w start
pg_ctl -D "$STANDBY" promote -w

psql -h "$BASEDIR" -p "$PGPORT_PRIMARY" -U postgres -q <<'SQL'
BEGIN;
  INSERT INTO nested_tx_t VALUES (2, 'top-level-before-savepoint');
  SAVEPOINT sp1;
    INSERT INTO nested_tx_t VALUES (3, 'rolled-back-inside-savepoint');
  ROLLBACK TO SAVEPOINT sp1;
  INSERT INTO nested_tx_t VALUES (4, 'after-rollback-savepoint');
  SAVEPOINT sp2;
    INSERT INTO nested_tx_t VALUES (5, 'nested-committed');
  RELEASE SAVEPOINT sp2;
COMMIT;
SQL

psql -h "$BASEDIR" -p "$PGPORT_STANDBY" -U postgres -q <<'SQL'
INSERT INTO nested_tx_t VALUES (100, 'standby-row');
SQL

pg_ctl -D "$PRIMARY" -m fast stop -w
pg_ctl -D "$STANDBY" -m fast stop -w

prepare_forensic_dir
pg_rewind \
  --source-pgdata="$STANDBY" \
  --target-pgdata="$PRIMARY" \
  --no-sync --decode --debug \
  >"$BASEDIR/pg_rewind.log" 2>&1 || true

echo "--- checks ---"
assert_file_exists "heap_analysis.sql создан" "$FORENSIC_DIR/heap_analysis.sql"
assert_not_empty "heap_analysis.sql не пуст" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "INSERT INTO nested_tx_t найден" "INSERT INTO .*nested_tx_t" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "топ-уровень транзакции декодирован" "top-level-before-savepoint" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "строка после rollback savepoint декодирована" "after-rollback-savepoint" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "строка из вложенной транзакции декодирована" "nested-committed" "$FORENSIC_DIR/heap_analysis.sql"
assert_not_grep "откаченная строка из savepoint не декодирована" "rolled-back-inside-savepoint" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "WAL-анализатор запущен" "parsing WAL records" "$BASEDIR/pg_rewind.log"

echo "============================================"
echo "Итог: $PASS прошло, $FAIL не прошло"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo "Есть проваленные проверки."
  exit 1
fi

echo "Все проверки пройдены."
