#!/usr/bin/env bash
set -uo pipefail
cd /home/c1ay/4zreark
export ZRE_PG_PASSWORD="${ZRE_PG_PASSWORD:?需要 ZRE_PG_PASSWORD}"
export PGPASSWORD="$ZRE_PG_PASSWORD"
TASK="${1:?需要任务 ID}"
LOG=reports/meituan-after-20261110/restart.log

while true; do
  st="$(psql "postgres://zre@127.0.0.1:25433/zreark?sslmode=disable" -Atc "select status from zre.tasks where id='$TASK'")"
  echo "$(date '+%F %T') status=$st" >> "$LOG"
  case "$st" in
    completed|failed|cancelled) break ;;
  esac
  sleep 120
done

# 任务终态后重启服务，加载 taskColumns/task_repo 修复。
pkill -f './zreark -role all' 2>/dev/null || true
sleep 5
ZRE_PG_PASSWORD="$ZRE_PG_PASSWORD" nohup ./zreark -role all >> /tmp/zreark-run.log 2>&1 &
echo "$(date '+%F %T') restarted pid=$!" >> "$LOG"
