#!/usr/bin/env bash
set -euo pipefail
cd /home/c1ay/4zreark
export ZRE_PG_PASSWORD="${ZRE_PG_PASSWORD:?需要 ZRE_PG_PASSWORD}"
exec bash scripts/meituan_export.sh \
  "postgres://zre@127.0.0.1:25433/zreark?sslmode=disable" \
  reports/meituan-after-20261110
