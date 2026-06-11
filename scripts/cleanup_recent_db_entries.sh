#!/usr/bin/env bash
set -euo pipefail

namespace="cyber-news-alert"
pod="postgres-0"
container="postgres"
context=""
execute=false
days=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/cleanup_recent_db_entries.sh DAYS [--execute] [options]

Deletes database entries inserted in the last DAYS day(s), based on
articles.created_at. Related alerts and article_fingerprints rows are included.

The default mode is dry-run and prints row counts without deleting anything.

Options:
  --execute             Delete matching rows. Without this, only counts are shown.
  --namespace NAME      Kubernetes namespace. Default: cyber-news-alert
  --context NAME        kubectl context to use. Default: current context
  --pod NAME            PostgreSQL pod name. Default: postgres-0
  --container NAME      PostgreSQL container name. Default: postgres
  -h, --help            Show this help.

Examples:
  scripts/cleanup_recent_db_entries.sh 3
  scripts/cleanup_recent_db_entries.sh 3 --execute
  scripts/cleanup_recent_db_entries.sh 7 --namespace cyber-news-alert --context prod
USAGE
}

die() {
  printf 'Error: %s\n\n' "$1" >&2
  usage >&2
  exit 2
}

while (($#)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --execute)
      execute=true
      shift
      ;;
    --namespace)
      [[ $# -ge 2 ]] || die "--namespace requires a value"
      namespace="$2"
      shift 2
      ;;
    --namespace=*)
      namespace="${1#*=}"
      shift
      ;;
    --context)
      [[ $# -ge 2 ]] || die "--context requires a value"
      context="$2"
      shift 2
      ;;
    --context=*)
      context="${1#*=}"
      shift
      ;;
    --pod)
      [[ $# -ge 2 ]] || die "--pod requires a value"
      pod="$2"
      shift 2
      ;;
    --pod=*)
      pod="${1#*=}"
      shift
      ;;
    --container)
      [[ $# -ge 2 ]] || die "--container requires a value"
      container="$2"
      shift 2
      ;;
    --container=*)
      container="${1#*=}"
      shift
      ;;
    --*)
      die "unknown option: $1"
      ;;
    *)
      [[ -z "$days" ]] || die "unexpected argument: $1"
      days="$1"
      shift
      ;;
  esac
done

[[ -n "$days" ]] || die "DAYS is required"
[[ "$days" =~ ^[1-9][0-9]*$ ]] || die "DAYS must be a positive integer"
[[ -n "$namespace" ]] || die "--namespace cannot be empty"
[[ -n "$pod" ]] || die "--pod cannot be empty"
[[ -n "$container" ]] || die "--container cannot be empty"

command -v kubectl >/dev/null 2>&1 || die "kubectl is required but was not found in PATH"

run_psql() {
  local kubectl_cmd=(kubectl)

  if [[ -n "$context" ]]; then
    kubectl_cmd+=(--context "$context")
  fi

  kubectl_cmd+=(exec -i -n "$namespace" "$pod" -c "$container" --)

  "${kubectl_cmd[@]}" sh -c '
    set -eu
    : "${POSTGRES_DB:?POSTGRES_DB is not set in the PostgreSQL pod}"
    : "${POSTGRES_USER:?POSTGRES_USER is not set in the PostgreSQL pod}"
    : "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is not set in the PostgreSQL pod}"

    PGPASSWORD="$POSTGRES_PASSWORD" psql \
      -v ON_ERROR_STOP=1 \
      -v cleanup_days="$1" \
      -U "$POSTGRES_USER" \
      -d "$POSTGRES_DB"
  ' sh "$days"
}

if [[ "$execute" == true ]]; then
  printf 'Deleting rows inserted in the last %s day(s) from %s/%s...\n' "$days" "$namespace" "$pod"
  run_psql <<'SQL'
BEGIN;

CREATE TEMP TABLE cleanup_targets ON COMMIT DROP AS
SELECT id
FROM articles
WHERE created_at >= now() - (CAST(:'cleanup_days' AS integer) * interval '1 day');

CREATE TEMP TABLE deleted_alerts_count ON COMMIT DROP AS
WITH deleted AS (
  DELETE FROM alerts
  WHERE article_id IN (SELECT id FROM cleanup_targets)
  RETURNING 1
)
SELECT count(*)::bigint AS count FROM deleted;

CREATE TEMP TABLE deleted_fingerprints_count ON COMMIT DROP AS
WITH deleted AS (
  DELETE FROM article_fingerprints
  WHERE article_id IN (SELECT id FROM cleanup_targets)
  RETURNING 1
)
SELECT count(*)::bigint AS count FROM deleted;

CREATE TEMP TABLE deleted_articles_count ON COMMIT DROP AS
WITH deleted AS (
  DELETE FROM articles
  WHERE id IN (SELECT id FROM cleanup_targets)
  RETURNING 1
)
SELECT count(*)::bigint AS count FROM deleted;

SELECT
  CAST(:'cleanup_days' AS integer) AS days,
  (SELECT count FROM deleted_articles_count) AS articles_deleted,
  (SELECT count FROM deleted_alerts_count) AS alerts_deleted,
  (SELECT count FROM deleted_fingerprints_count) AS article_fingerprints_deleted;

COMMIT;
SQL
else
  printf 'Dry run: counting rows inserted in the last %s day(s) from %s/%s.\n' "$days" "$namespace" "$pod"
  printf 'Pass --execute to delete matching rows.\n'
  run_psql <<'SQL'
BEGIN;

CREATE TEMP TABLE cleanup_targets ON COMMIT DROP AS
SELECT id
FROM articles
WHERE created_at >= now() - (CAST(:'cleanup_days' AS integer) * interval '1 day');

SELECT
  CAST(:'cleanup_days' AS integer) AS days,
  (SELECT count(*) FROM cleanup_targets) AS articles_to_delete,
  (SELECT count(*) FROM alerts WHERE article_id IN (SELECT id FROM cleanup_targets)) AS alerts_to_delete,
  (SELECT count(*) FROM article_fingerprints WHERE article_id IN (SELECT id FROM cleanup_targets)) AS article_fingerprints_to_delete;

ROLLBACK;
SQL
fi
