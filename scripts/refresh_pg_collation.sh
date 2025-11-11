#!/usr/bin/env bash

set -euo pipefail

print_usage() {
  cat <<'USAGE'
Usage: refresh_pg_collation.sh [--database-url URL] [--auto-reindex]

Refresh PostgreSQL collation metadata to fix "collation version mismatch".

Options:
  --database-url URL  PostgreSQL connection string. If omitted, uses $DATABASE_URL
  --auto-reindex      If refresh fails due to collation-dependent indexes, run
                      REINDEX DATABASE (requires downtime)

Notes:
  - This script will terminate other sessions on the target database to avoid locks.
  - Requires PostgreSQL >= 13 for REFRESH COLLATION VERSION.
  - REINDEX DATABASE cannot run CONCURRENTLY; prefer a maintenance window.
USAGE
}

DATABASE_URL_ENV="${DATABASE_URL:-}"
DATABASE_URL_ARG=""
AUTO_REINDEX=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --database-url)
      DATABASE_URL_ARG="$2"; shift 2 ;;
    --auto-reindex)
      AUTO_REINDEX=true; shift ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2
      print_usage
      exit 2 ;;
  esac
done

if ! command -v psql >/dev/null 2>&1; then
  echo "Error: psql is not installed or not in PATH." >&2
  exit 1
fi

DATABASE_URL_EFFECTIVE="${DATABASE_URL_ARG:-$DATABASE_URL_ENV}"
if [[ -z "$DATABASE_URL_EFFECTIVE" ]]; then
  echo "Error: DATABASE_URL not provided. Use --database-url or set env var." >&2
  exit 1
fi

echo "Connecting with provided DATABASE_URL..."

# Terminate other sessions connected to the current database to avoid locks
echo "Terminating other sessions on the target database..."
psql "$DATABASE_URL_EFFECTIVE" \
  -v ON_ERROR_STOP=1 \
  -X -q \
  -c "SELECT pg_terminate_backend(pid)
         FROM pg_stat_activity
        WHERE datname = current_database()
          AND pid <> pg_backend_pid();"

echo "Refreshing collation metadata..."
set +e
REFRESH_OUTPUT=$(psql "$DATABASE_URL_EFFECTIVE" -v ON_ERROR_STOP=1 -X -q -At \
  -c "SELECT format('ALTER DATABASE %I REFRESH COLLATION VERSION;', current_database());" \
  -c "\\gexec" 2>&1)
REFRESH_STATUS=$?
set -e

if [[ $REFRESH_STATUS -eq 0 ]]; then
  echo "Success: Collation metadata refreshed."
  exit 0
fi

echo "REFRESH failed. Details:\n$REFRESH_OUTPUT" >&2

if [[ "$AUTO_REINDEX" != true ]]; then
  echo "Hint: Re-run with --auto-reindex to rebuild collation-dependent indexes during downtime." >&2
  exit 1
fi

echo "Attempting full database reindex (this requires downtime)..."
psql "$DATABASE_URL_EFFECTIVE" -v ON_ERROR_STOP=1 -X -q -c "REINDEX DATABASE CURRENT_DATABASE;" 2>/dev/null || {
  # CURRENT_DATABASE cannot be used directly in REINDEX; resolve name first
  DBNAME=$(psql "$DATABASE_URL_EFFECTIVE" -X -q -At -c "SELECT current_database();")
  if [[ -z "$DBNAME" ]]; then
    echo "Error: Unable to determine current database name for reindex." >&2
    exit 1
  fi
  psql "$DATABASE_URL_EFFECTIVE" -v ON_ERROR_STOP=1 -X -q -c "REINDEX DATABASE \"$DBNAME\";"
}

echo "Reindex complete. Retrying collation refresh..."
psql "$DATABASE_URL_EFFECTIVE" -v ON_ERROR_STOP=1 -X -q \
  -c "SELECT format('ALTER DATABASE %I REFRESH COLLATION VERSION;', current_database());" \
  -c "\\gexec"

echo "Done. Collation is refreshed and indexes rebuilt."

