#!/usr/bin/env bash
#--------------------------------------------------------------------------
# forensic_multi_update.sh
#
# Проверяет корректное декодирование нескольких UPDATE/INSERT в lost ветке.
#--------------------------------------------------------------------------
set -euo pipefail

PGPORT_PRIMARY=${PGPORT_PRIMARY:-5598}
PGPORT_STANDBY=${PGPORT_STANDBY:-5599}
BASEDIR=$(mktemp -d /tmp/pg_forensic_mupd.XXXX)
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
assert_min_count() {
  local desc="$1" pattern="$2" file="$3" min_count="$4"
  local cnt
  cnt=$(grep -E -c "$pattern" "$file" 2>/dev/null || true)
  assert_ok "$desc (найдено $cnt, ожидалось >= $min_count)" test "$cnt" -ge "$min_count"
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

echo "=== forensic_multi_update ==="
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
  -D "$STANDBY" -R -X stream -C -S "rewind_slot_mupd" \
  >"$BASEDIR/basebackup.log" 2>&1
pg_ctl -D "$STANDBY" -o "-k $BASEDIR -p $PGPORT_STANDBY" -w start

psql -h "$BASEDIR" -p "$PGPORT_PRIMARY" -U postgres -q <<'SQL'
CREATE TABLE products(
  id serial PRIMARY KEY,
  name text NOT NULL,
  price numeric(10,2) NOT NULL,
  category text DEFAULT 'general',
  updated_at timestamptz DEFAULT now()
);
INSERT INTO products(name, price, category) VALUES
  ('Widget',  10.00, 'hardware'),
  ('Gadget',  25.50, 'electronics'),
  ('Gizmo',   99.99, 'electronics'),
  ('Doohicky', 5.75, 'hardware'),
  ('Thingamajig', 150.00, 'premium');
SQL

pg_ctl -D "$PRIMARY" -m fast stop -w
pg_ctl -D "$PRIMARY" -o "-k $BASEDIR -p $PGPORT_PRIMARY" -w start
pg_ctl -D "$STANDBY" promote -w
sleep 0.3

psql -h "$BASEDIR" -p "$PGPORT_PRIMARY" -U postgres -q <<'SQL'
UPDATE products SET price = 12.99 WHERE id = 1;
UPDATE products SET name = 'SuperGadget', price = 35.00 WHERE id = 2;
UPDATE products SET price = 15.50, category = 'premium-hardware' WHERE id = 1;
UPDATE products SET price = 79.99 WHERE id = 3;
INSERT INTO products(name, price, category) VALUES ('NewItem', 42.00, 'new');
SQL

psql -h "$BASEDIR" -p "$PGPORT_STANDBY" -U postgres -q <<'SQL'
INSERT INTO products(name, price) VALUES ('StandbyItem', 1.00);
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
assert_grep "INSERT INTO products найден" "INSERT INTO .*products" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "Widget найден" "Widget" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "premium-hardware найден" "premium-hardware" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "SuperGadget найден" "SuperGadget" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "Gizmo найден" "Gizmo" "$FORENSIC_DIR/heap_analysis.sql"
assert_grep "NewItem найден" "NewItem" "$FORENSIC_DIR/heap_analysis.sql"
assert_min_count "Декодировано несколько операций products" "(INSERT|UPDATE) INTO .*products" "$FORENSIC_DIR/heap_analysis.sql" 4
assert_grep "WAL-анализатор запущен" "parsing WAL records" "$BASEDIR/pg_rewind.log"
assert_grep "Найдены modified tables" "modified tables" "$BASEDIR/pg_rewind.log"

echo "============================================"
echo "Итог: $PASS прошло, $FAIL не прошло"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo "Есть проваленные проверки."
  exit 1
fi

echo "Все проверки пройдены."
