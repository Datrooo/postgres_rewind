#!/usr/bin/env bash
#--------------------------------------------------------------------------
# forensic_run_all.sh
#
# Запускает все forensic-скрипты в каталоге forensic_scripts и показывает
# сводку по успешным/неуспешным прогонам.
#--------------------------------------------------------------------------
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF_NAME="$(basename "$0")"

# shellcheck source=/dev/null
source "$SCRIPT_DIR/forensic_env.sh"

PASS=0
FAIL=0
declare -a FAILED_SCRIPTS=()

echo "=== forensic_run_all ==="
echo "SCRIPT_DIR=$SCRIPT_DIR"
echo ""

for script in "$SCRIPT_DIR"/forensic_*.sh; do
  name="$(basename "$script")"

  if [[ "$name" == "forensic_env.sh" || "$name" == "$SELF_NAME" ]]; then
    continue
  fi

  echo ">>> running $name"
  if bash "$script"; then
    echo ">>> [OK] $name"
    PASS=$((PASS + 1))
  else
    echo ">>> [FAIL] $name"
    FAIL=$((FAIL + 1))
    FAILED_SCRIPTS+=("$name")
  fi
  echo ""
done

echo "============================================"
echo "Итог: $PASS прошло, $FAIL не прошло"
echo "============================================"

if (( FAIL > 0 )); then
  echo "Проваленные скрипты:"
  for name in "${FAILED_SCRIPTS[@]}"; do
    echo "  - $name"
  done
  exit 1
fi

echo "Все forensic-скрипты пройдены."
