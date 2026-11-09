#!/usr/bin/env bash
# 4zreark 数据库初始化 / 升级：按依赖顺序执行 docs/sql 下的全部脚本。
#
# 为什么需要这个脚本
# ------------------
# docs/sql 下的脚本存在真实依赖：schema_governance.sql 第 22 行对 projects 表
# 做 ALTER，而 projects 由 migration_assets_p0.sql 创建。按文件名排序时
# "migration_*" 排在 "schema_*" 之后，任何 `for f in *.sql` 的批量执行都会
# 让 governance 在 projects 不存在时失败；而它整段是一个事务，失败后
# seeds / monitoring_plans / runs / run_targets / site_endpoints 等 20 多张表
# 一起回滚，psql 默认又不中断，最终得到一个「看起来建完了」的半残库。
#
# 用法
# ----
#   ./apply_all.sh                    # 用 PG* 环境变量或默认连接
#   ./apply_all.sh --with-backfill    # 追加执行 backfill_*.sql（数据回填，慢）
#   PGURL='postgres://user:pass@host:5432/zreark' ./apply_all.sh
#
# 行为
# ----
#   * 每个文件单独执行，ON_ERROR_STOP=1，任一语句失败立即中止并打印文件与错误；
#   * 文件自带 BEGIN 的按其自身事务边界执行；不自带的用 --single-transaction 包住；
#   * 结束后校验核心表清单，缺表则以非零码退出（不会静默成功）。

set -Eeuo pipefail
cd "$(dirname "$0")"

PSQL_BIN="${PSQL_BIN:-psql}"
WITH_BACKFILL=0
for arg in "$@"; do
    case "$arg" in
        --with-backfill) WITH_BACKFILL=1 ;;
        -h|--help)
            sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "未知参数: $arg（支持 --with-backfill / --help）" >&2
            exit 2
            ;;
    esac
done

if ! command -v "$PSQL_BIN" >/dev/null 2>&1; then
    echo "找不到 psql（可用 PSQL_BIN 指定绝对路径）" >&2
    exit 1
fi

DSN_ARGS=()
if [[ -n "${PGURL:-}" ]]; then
    DSN_ARGS=(-d "$PGURL")
fi

# 依赖顺序。前三步是硬依赖，不要调整：
#   schema_init        建 users / tasks / scan_results 等基础表
#   migration_assets_p0 建 projects / sites / raw_records 等 P0 六表
#   schema_governance  依赖 projects，并建 seeds / runs / site_endpoints 等
# 其余 schema_* 只依赖上面几步；文件名按字母序即可，这里仍显式列出以便审阅。
CORE_FILES=(
    schema_init.sql
    migration_assets_p0.sql
    schema_governance.sql
    schema_fingerprint.sql
    schema_api_key.sql
    schema_icon.sql
    schema_notify.sql
    schema_poc_template_optional.sql
    schema_ops_finalize.sql
    schema_sentinel.sql
)

MIGRATION_FILES=()
# 用临时文件而不是进程替换 <(...)：精简容器里常常没有 /dev/fd，
# 进程替换会直接报 "没有那个文件或目录"，脚本在建表前就死掉。
LIST_TMP="$(mktemp "${TMPDIR:-/tmp}/zre-sql-list.XXXXXX")"
trap 'rm -f "$LIST_TMP"' EXIT
ls migration_*.sql 2>/dev/null | grep -v '^migration_assets_p0\.sql$' | sort > "$LIST_TMP"
while IFS= read -r f; do
    MIGRATION_FILES+=("$f")
done < "$LIST_TMP"

BACKFILL_FILES=()
if [[ $WITH_BACKFILL -eq 1 ]]; then
    ls backfill_*.sql 2>/dev/null | sort > "$LIST_TMP"
    while IFS= read -r f; do
        BACKFILL_FILES+=("$f")
    done < "$LIST_TMP"
fi

apply_file() {
    local file="$1" label="$2"
    local start end
    start=$(date +%s)
    printf '[%s] %-46s' "$label" "$file"

    local -a args=(-X -q -v ON_ERROR_STOP=1 -f "$file")
    # CREATE INDEX CONCURRENTLY 不能跑在事务块里（migration_raw_records_evidence_trgm.sql 就是），
    # 这类脚本必须让它自己逐条 autocommit；其余不自带 BEGIN 的才用单事务包住。
    if ! grep -qiE '^[[:space:]]*BEGIN[[:space:]]*;' "$file" && ! grep -qi 'concurrently' "$file"; then
        args=(-X -q -v ON_ERROR_STOP=1 --single-transaction -f "$file")
    fi

    set +e
    LAST_OUT=$("$PSQL_BIN" "${DSN_ARGS[@]}" "${args[@]}" 2>&1)
    LAST_RC=$?
    set -e

    end=$(date +%s)
    printf ' (%ss)\n' "$((end - start))"
    if [[ $LAST_RC -ne 0 ]]; then
        return 1
    fi
    if [[ -n "$LAST_OUT" ]]; then
        echo "$LAST_OUT" | grep -viE '^(NOTICE|psql:.*NOTICE|说明)' | sed 's/^/         /' || true
    fi
    return 0
}

print_failure() {
    local file="$1"
    echo "---- $file ----------------------------------------------" >&2
    echo "$LAST_OUT" >&2
    echo "---------------------------------------------------------" >&2
}

# 迁移脚本彼此也存在依赖（例如 migration_digital_candidates.sql 建外键指向
# enterprise_jobs，而后者在字母序更靠后的 migration_enterprise_entities.sql 里）。
# 与其维护一张人工拓扑排序表 —— 它一定会随着新增脚本而腐坏 —— 不如按依赖重试：
# 只有明确是「对象不存在」的失败才延后到下一轮，其余错误立即中止。
# 某一轮毫无进展时说明存在真实错误或循环依赖，把剩余失败一次性打出来。
is_dependency_error() {
    grep -qE 'ERROR:.*(does not exist|不存在)' <<<"$LAST_OUT"
}

run_with_retry() {
    local -a pending=("$@")
    local round=1 label f
    while [[ ${#pending[@]} -gt 0 ]]; do
        local -a deferred=()
        local progressed=0
        for f in "${pending[@]}"; do
            label="r${round}"
            if apply_file "$f" "$label"; then
                progressed=$((progressed + 1))
                continue
            fi
            if is_dependency_error; then
                deferred+=("$f")
            else
                print_failure "$f"
                echo "已在 $f 中止。前面的文件已提交，修好后可直接重跑本脚本（脚本均为幂等 DDL）。" >&2
                exit 1
            fi
        done

        if [[ ${#deferred[@]} -eq 0 ]]; then
            break
        fi
        if [[ $progressed -eq 0 ]]; then
            echo >&2
            echo "以下 ${#deferred[@]} 个脚本互相等待，或依赖了不存在的对象：" >&2
            for f in "${deferred[@]}"; do
                apply_file "$f" "x" >/dev/null 2>&1 || true
                print_failure "$f"
            done
            echo "检查这些脚本的前置 DDL 是否遗漏。" >&2
            exit 1
        fi
        echo "        第 $round 轮：$progressed 个成功，${#deferred[@]} 个因依赖未就绪延后，进入第 $((round + 1)) 轮"
        pending=("${deferred[@]}")
        round=$((round + 1))
    done
}

TOTAL=$(( ${#CORE_FILES[@]} + ${#MIGRATION_FILES[@]} + ${#BACKFILL_FILES[@]} ))
echo "目标库: ${PGURL:-${PGDATABASE:-<默认>} @ ${PGHOST:-<默认>}:${PGPORT:-5432}}"
echo "共 $TOTAL 个脚本（core ${#CORE_FILES[@]} / migration ${#MIGRATION_FILES[@]} / backfill ${#BACKFILL_FILES[@]}）"
echo

for f in "${CORE_FILES[@]}"; do
    if ! apply_file "$f" "core"; then
        print_failure "$f"
        echo "核心脚本失败，后面的依赖都不会成立，已中止。" >&2
        exit 1
    fi
done

if [[ ${#MIGRATION_FILES[@]} -gt 0 ]]; then
    echo "— 迁移脚本按依赖重试 —"
    run_with_retry "${MIGRATION_FILES[@]}"
fi

if [[ ${#BACKFILL_FILES[@]} -gt 0 ]]; then
    echo "— 数据回填 —"
    run_with_retry "${BACKFILL_FILES[@]}"
fi

# 收尾校验：核心表清单与 repo.requiredTables 保持一致口径。
# 缺表时以非零码退出，避免「脚本跑完但库是半残」这种最难排查的状态。
REQUIRED_TABLES=(
    users tasks task_jobs scan_results vulnerabilities result_dedup token_blacklist schema_migrations
    projects sites raw_records asset_events
    seeds monitoring_plans runs run_targets site_endpoints
    icp_queries icp_filings
    fingerprint_rules
    repo commit judgment finding artifact
    conversation message run run_event attachment audit
)
CHECK_SQL="select t from unnest(array[$(printf "'%s'," "${REQUIRED_TABLES[@]}" | sed 's/,$//')]) as t
            where to_regclass(t) is null"
MISSING=$("$PSQL_BIN" "${DSN_ARGS[@]}" -X -q -t -A -c "$CHECK_SQL" 2>/dev/null || true)

TABLE_COUNT=$("$PSQL_BIN" "${DSN_ARGS[@]}" -X -q -t -A \
    -c "select count(*) from information_schema.tables where table_schema = current_schema()" 2>/dev/null || echo '?')

echo
echo "完成：public 表数量 $TABLE_COUNT"
if [[ -n "$MISSING" ]]; then
    echo "缺少核心表：" >&2
    echo "$MISSING" | sed 's/^/  - /' >&2
    echo "请检查上面输出中是否有被跳过的脚本。" >&2
    exit 1
fi
echo "核心表校验通过（${#REQUIRED_TABLES[@]} 张）"
