#!/usr/bin/env bash
set -uo pipefail
cd /home/c1ay/4zreark
export ZRE_PG_PASSWORD="${ZRE_PG_PASSWORD:?需要 ZRE_PG_PASSWORD}"
export PGPASSWORD="$ZRE_PG_PASSWORD"
PSQL=(psql "postgres://zre@127.0.0.1:25433/zreark?sslmode=disable" -At)
OUT=reports/meituan-after-20261110
LOG="$OUT/finish.log"
REPORT=reports/meituan-recollect-20261110.md
mkdir -p "$OUT"

TASK="${1:-$("${PSQL[@]}" -c "select id from zre.tasks where project_id::text='1' and type='collection' order by created_at desc limit 1")}"
echo "watching task=$TASK" | tee -a "$LOG"
deadline=$(( $(date +%s) + 9 * 3600 ))

while true; do
  st="$("${PSQL[@]}" -c "select status from zre.tasks where id='$TASK'")"
  prog="$("${PSQL[@]}" -c "select progress from zre.tasks where id='$TASK'")"
  echo "$(date '+%F %T') status=$st progress=$prog" >> "$LOG"
  case "$st" in
    completed|failed|cancelled) break ;;
  esac
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "$(date '+%F %T') deadline reached" >> "$LOG"
    break
  fi
  sleep 120
done

bash scripts/meituan_export_after.sh >> "$LOG" 2>&1
python3 scripts/meituan_compare.py >> "$LOG" 2>&1

# 脱敏与产物校验
if [ -s "$REPORT" ] && ! grep -qE 'gOQEk|ZRE_PG_PASSWORD|sk-[A-Za-z0-9]{8,}' "$REPORT"; then
  echo "verify=ok" >> "$LOG"
else
  echo "verify=failed" >> "$LOG"
fi
ls -lh "$REPORT" reports/meituan-diff-20261110.json reports/meituan-before-20261110/zreark.dump >> "$LOG" 2>&1
echo "done" >> "$LOG"
