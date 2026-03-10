#!/usr/bin/env sh
# Задача этого скрипта - настроить окружение для запуска скриптов в папке forensic_scripts.
#
# Usage:
#   source ./forensic_env.sh


_search="$PWD"
_repo_root=""
_i=0
while [ "$_i" -lt 8 ]; do
  if [ -d "$_search/install/bin" ] && [ -d "$_search/src/bin/pg_rewind" ]; then
    _repo_root="$_search"
    break
  fi
  _parent="$(dirname "$_search")"
  if [ "$_parent" = "$_search" ]; then
    break
  fi
  _search="$_parent"
  _i=$((_i + 1))
done

if [ -z "$_repo_root" ]; then
  echo "Could not locate postgres repo root from: $PWD"
  echo "Expected directories: install/bin and src/bin/pg_rewind"
  return 1 2>/dev/null || exit 1
fi

mkdir -p /tmp/pgbin_nospace
ln -sfn "$_repo_root/install/bin" /tmp/pgbin_nospace/bin

export ROOT="$_repo_root"
export PATH="$_repo_root/src/bin/pg_rewind:$_repo_root/install/bin:$PATH"
export PG_BINDIR="/tmp/pgbin_nospace/bin"
export DYLD_LIBRARY_PATH="$_repo_root/install/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

echo "forensic env configured:"
echo "  ROOT=$ROOT"
echo "  PG_BINDIR=$PG_BINDIR"
echo "  PATH prefix=$ROOT/src/bin/pg_rewind:$ROOT/install/bin"
