#!/usr/bin/env bash
set -euo pipefail
cd /home/c1ay/4zreark
DB="${1:?usage: meituan_export.sh <db_url> <out_dir>}"
OUT="${2:?usage: meituan_export.sh <db_url> <out_dir>}"
mkdir -p "$OUT"
export PGPASSWORD="${ZRE_PG_PASSWORD:?需要 ZRE_PG_PASSWORD}"
PSQL=(psql "$DB" -At)

TABLES=(
  "projects|id=1"
  "seeds|project_id::text='1'"
  "sites|project_id::text='1'"
  "site_endpoints|site_id in (select id from zre.sites where project_id::text='1')"
  "site_routes|project_id::text='1'"
  "scan_results|task_id in (select id from zre.tasks where project_id::text='1')"
  "vulnerabilities|task_id in (select id from zre.tasks where project_id::text='1')"
  "verifications|site_id in (select id from zre.sites where project_id::text='1')"
  "fingerprint_hits|site_id in (select id from zre.sites where project_id::text='1')"
  "raw_records|project_id::text='1'"
  "asset_candidates|project_id::text='1'"
  "asset_events|project_id::text='1'"
  "discovery_runs|project_id::text='1'"
  "tasks|project_id::text='1'"
  "task_logs|task_id in (select id from zre.tasks where project_id::text='1')"
  "collection_plans|project_id::text='1'"
  "collection_stages|plan_id in (select id from zre.collection_plans where project_id::text='1')"
  "raw_snapshots|task_id in (select id from zre.tasks where project_id::text='1')"
  "ai_gate_verdicts|raw_id in (select id::text from zre.raw_records where project_id::text='1')"
  "ai_items|raw_id in (select id::text from zre.raw_records where project_id::text='1')"
  "diff_jobs|entity_id like '%meituan%'"
)

for spec in "${TABLES[@]}"; do
  t="${spec%%|*}"
  w="${spec#*|}"
  "${PSQL[@]}" -c "select coalesce(json_agg(x),'[]'::json) from (select * from zre.$t where $w) x" > "$OUT/$t.json"
done

"${PSQL[@]}" -c "
select 'seeds='||count(*) from zre.seeds where project_id::text='1'
union all select 'sites='||count(*) from zre.sites where project_id::text='1'
union all select 'tasks='||count(*) from zre.tasks where project_id::text='1'
union all select 'scan_results='||count(*) from zre.scan_results where task_id in (select id from zre.tasks where project_id::text='1')
union all select 'vulnerabilities='||count(*) from zre.vulnerabilities where task_id in (select id from zre.tasks where project_id::text='1')
union all select 'raw_records='||count(*) from zre.raw_records where project_id::text='1';
" > "$OUT/counts.txt"

echo "export done: $DB -> $OUT"
