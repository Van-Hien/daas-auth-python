#!/usr/bin/env bash
# Proves two things about the audit history (the old versions of changed rows):
#   1. neither DB account is allowed to wipe it,
#   2. a backup made with --dump-history brings it back after a restore.
#
# Run from anywhere:  bash scripts/restore-check.sh
# Needs:              the service's MariaDB running (docker compose up -d mariadb)
# Leaves behind:      nothing. The throwaway database and the dump file are removed at the end.
set -euo pipefail   # stop at the first error, at an unset variable, and at a failing pipe
cd "$(dirname "$0")/.."   # work from the repo root, wherever the script is called from

# ---------------------------------------------------------------- settings
RESTORE_NAME=daas-auth-restore          # name of the throwaway database container
RESTORE_IMAGE=mariadb:10.11.6           # same version as the service's MariaDB
RESTORE_ROOT_PW=restore-only            # the throwaway holds no real data, so no real secret
DUMP=var/daas_auth-dump.sql             # var/ is ignored by git

# Every table that keeps a history. A new versioned table goes in this list.
VERSIONED_TABLES=(
  user_roles
  users_to_user_groups
  desktops_to_desktop_groups
  desktopgroup_usergroup
)

# ---------------------------------------------------------------- helpers
# Colours only on a terminal, and not if NO_COLOR is set (no-color.org).
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
  green=$'\e[32m' red=$'\e[31m' bold=$'\e[1m' reset=$'\e[0m'
else
  green='' red='' bold='' reset=''
fi

heading() { printf '\n%s%s%s\n' "$bold" "$1" "$reset"; }
indent()  { sed 's/^/  /'; }                      # two spaces in front of every line
table()   { column -t -s$'\t' | indent; }          # tab-separated text in, aligned columns out
fail()    { printf '\n%sFAIL%s  %s\n' "$red" "$reset" "$1" >&2; exit 1; }

# One line per table: its name, its current rows, and all its rows ever (history included).
build_count_query() {
  local t query=""
  for t in "${VERSIONED_TABLES[@]}"; do
    [[ -n $query ]] && query+=" UNION ALL "
    query+="SELECT '$t' t, COUNT(*) now, (SELECT COUNT(*) FROM $t FOR SYSTEM_TIME ALL) hist FROM $t"
  done
  printf '%s' "$query"
}
COUNT_QUERY=$(build_count_query)
VERSION_QUERY='SELECT version_num FROM alembic_version'

# Removes the throwaway database and the dump. Runs on every exit, also after an error.
cleanup() {
  docker stop "$RESTORE_NAME" >/dev/null 2>&1 || true
  rm -f "$DUMP"   # the dump holds password hashes
}
trap cleanup EXIT

# ---------------------------------------------------------------- the steps
# Prints one account's grants. Args: account name, and the container variable holding its password.
# The GRANT USAGE line holds a password hash (it contains IDENTIFIED), so it is cut out.
show_grants() {
  docker compose exec -T -e ACCOUNT="$1" -e PW_VAR="$2" mariadb sh -c \
    'mariadb -u"$ACCOUNT" -p"$(printenv "$PW_VAR")" -N -e "SHOW GRANTS"' | grep -v IDENTIFIED
}

check_grants() {
  local all="" grants
  grants=$(show_grants daas_app DAAS_DB_APP_PASSWORD)
  printf '%s\n' "daas_app (the service):" "$grants" | sed '2,$s/^/  /' | indent
  all+=$grants
  grants=$(show_grants daas_migrate DAAS_DB_MIGRATE_PASSWORD)
  printf '%s\n' "daas_migrate (Alembic):" "$grants" | sed '2,$s/^/  /' | indent
  all+=$grants

  if grep -Eq 'ALL PRIVILEGES|DELETE HISTORY' <<<"$all"; then
    fail "an account may wipe the history"
  fi
  echo "  -> neither account has ALL PRIVILEGES or DELETE HISTORY"
}

# Runs a query in the service's database. Prints tab-separated lines, header first.
query_original() {
  docker compose exec -T -e Q="$1" mariadb sh -c \
    'mariadb -udaas_app -p"$DAAS_DB_APP_PASSWORD" daas_auth -e "$Q"'
}

make_dump() {
  mkdir -p var
  # umask makes the file owner-only; chmod repeats it because an ACL on var/ widened it once.
  (umask 077
   docker compose exec -T mariadb sh -c \
     'mariadb-dump -uroot -p"$MARIADB_ROOT_PASSWORD" --single-transaction --routines --triggers --dump-history daas_auth' \
     >"$DUMP")
  chmod 600 "$DUMP"
  stat -c '%n   %s bytes   mode %a' "$DUMP" | indent
}

start_restore_db() {
  # A leftover from an earlier failed run would block the name.
  docker rm -f "$RESTORE_NAME" >/dev/null 2>&1 || true
  docker run -d --rm --name "$RESTORE_NAME" \
    -e MARIADB_ROOT_PASSWORD="$RESTORE_ROOT_PW" -e MARIADB_DATABASE=daas_auth \
    "$RESTORE_IMAGE" >/dev/null

  local tries
  for tries in $(seq 1 60); do   # up to 2 minutes
    docker exec "$RESTORE_NAME" healthcheck.sh --connect --innodb_initialized 2>/dev/null && return
    sleep 2
  done
  fail "the restore database did not start"
}

load_dump() {
  docker exec -i "$RESTORE_NAME" mariadb -uroot -p"$RESTORE_ROOT_PW" daas_auth <"$DUMP"
}

# Runs a query in the throwaway database, same output shape as query_original.
query_restored() {
  docker exec "$RESTORE_NAME" mariadb -uroot -p"$RESTORE_ROOT_PW" daas_auth -e "$1"
}

# Original and restored counts side by side. Both inputs: tab-separated, header first.
compare_table() {
  paste <(echo "$1") <(echo "$2") | awk -F'\t' '
    NR == 1 { print "table\toriginal now\toriginal hist\trestored now\trestored hist\tsame?"; next }
            { same = ($2 == $5 && $3 == $6) ? "yes" : "NO"
              print $1 "\t" $2 "\t" $3 "\t" $5 "\t" $6 "\t" same }'
}

# ---------------------------------------------------------------- run
heading "1/5  Grants: what each account may do"
check_grants

heading "2/5  Counts in the original database"
counts_before=$(query_original "$COUNT_QUERY")
version_before=$(query_original "$VERSION_QUERY" | tail -n 1)
table <<<"$counts_before"
echo "  migration version: $version_before"

heading "3/5  Dump with history"
make_dump

heading "4/5  Restore into an empty MariaDB"
start_restore_db
echo "  throwaway database $RESTORE_NAME is up ($RESTORE_IMAGE)"
load_dump
echo "  dump loaded"

heading "5/5  Original against restored"
counts_after=$(query_restored "$COUNT_QUERY")
version_after=$(query_restored "$VERSION_QUERY" | tail -n 1)
compare_table "$counts_before" "$counts_after" | table
echo "  migration version: $version_before -> $version_after"

if [[ $counts_before != "$counts_after" || $version_before != "$version_after" ]]; then
  fail "the restore differs from the original"
fi

# A table whose history equals its current rows never changed, so this run proves nothing for it.
awk -F'\t' 'NR > 1 && $2 == $3 { print "  NOTE  no history yet in " $1 }' <<<"$counts_after"

printf '\n%sOK%s    grants fine, restore identical, history kept\n' "$green" "$reset"
