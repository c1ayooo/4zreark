# 任务队列（River + PostgreSQL）

> 本文描述当前实现。旧版文档中的 Redis List/Stream、四类队列、`queue.redis` 配置均已废弃：
> 当前存储只有 PostgreSQL 16，队列由 [River](https://riverqueue.com/) 在 `river_job` 表上实现。

## 队列一览

| 队列 | kind | 消费方 | 默认并发 | 超时 | 重试 |
|---|---|---|---|---|---|
| `scan` | `scan_task` | master 派单 / all 本地执行 | `node.max_tasks`（默认 5，硬顶 64） | 24h | 3 次 |
| `sentinel_collect` | `sentinel_collect_repo` | 控制面采集 worker | 4 | 30m | 3 次 |
| `sentinel_judge` | `sentinel_judge_commit` | 控制面判定 worker | 8 | 30m | 3 次 |
| `sentinel_repro` | `sentinel_repro_finding` | 独立进程 `cmd/pocsmith` | 2 | 40m | 2 次 |
| `collection_gate` | `collection_gate_raw` | 控制面 Gate worker（影子） | 4 | 30m | 3 次 |

另有通用 `task_jobs`（`kind='job'`）队列，只服务 `/api/queue` 的演示/运维任务，与扫描和 AI 判定无关。

## 重试与失败语义

- 重试次数：`scan` / `sentinel_*` / `collection_gate` 的 River 客户端默认 `MaxAttempts=3`，
  每次入队也显式带 3；`sentinel_repro` 为 2。
- 限流：`llm.ErrRateLimited` → `river.JobSnooze(5m)`；配置错误/永久错误 → `river.JobCancel`；
  其它错误交回 River 默认退避。
- 扫描任务落库为 `failed` 后主动 `JobCancel`，避免 River 反复重跑；人工重试会重新入队。
- AI 判定失败状态机（`commit.judge_attempts/last_judge_error/next_judge_at`）：
  - 永久错误/未配置密钥 → 终态 `failed`，不再自动重投；
  - 限流 → 保留 `pending`，5 分钟后由调度器重投；
  - 临时错误 → 30s 退避重投，最多 5 次，耗尽后转人工。
- `collection_gate` 只写 `ai_gate_verdicts`，不参与扫描调度/重试/限流；影子模式默认关闭。

## 去重与幂等

- 入队使用 `UniqueOpts{ByArgs: true, ByState: 活跃态}`：
  `scan` 按 `task_id`、`sentinel_collect` 按 `repo_id`、`sentinel_judge` 按 `commit_id`、
  `collection_gate` 按 `raw_id`。
- 扫描阶段计划使用 `(plan_id, stage)` 唯一键，重复推进不会重复建任务。

## 失败终态与清理

- River 的 `discarded` 终态保留在 `river_job` 表；队列页通过 `river_discarded` 计数展示。
- 终态任务遗留的未完成 job 由 `ScanQueue.CancelTerminal` 走 `JobCancel`；
  **默认不再 DELETE `river_job`**，长时间 `running` 的僵尸交给 River 的
  `RescueStuckJobsAfter` 回收。
- 仅当 `scanner.force_clean_terminal_jobs=true` 时保留旧强删（执行前写审计日志），
  用于极端运维场景。
- 通用 `task_jobs` 有完整死信：`status='dead'`，支持列表、重试与清空（`/api/queue/tasks/deadletter`）。

## 并发预算

所有队列共享 `pgxpool`（`postgres.max_conns=50`，PG `max_connections=80`）。
默认分配：scan 5、collection_gate 4、sentinel collect 4 / judge 8 / repro 2、
通用队列 10、探测执行器 8。超出时优先降 Gate 与通用队列，不动扫描主链。

## 迁移与启动自检

1. 执行迁移（核心表 → `migration_*.sql` → 回填三段自动排序）：
   ```bash
   PGURL='postgres://user:pass@host:5432/db?sslmode=disable' bash docs/sql/apply_all.sh
   ```
2. 启动自检会检查 6 张新表：`collection_plans`、`collection_stages`、`raw_snapshots`、
   `ai_gate_verdicts`、`ai_items`、`diff_jobs`。缺表直接退出（exit 2），避免带病运行。
3. 验收 SQL：
   ```sql
   select column_name from information_schema.columns
    where table_name='tasks' and column_name in ('plan_id','parent_id','stage','collection_mode');
   select conname from pg_constraint where conname='tasks_type_chk';
   select to_regclass('collection_plans'), to_regclass('collection_stages'),
          to_regclass('raw_snapshots'), to_regclass('ai_gate_verdicts'),
          to_regclass('ai_items'), to_regclass('diff_jobs');
   ```
4. 启动日志应出现
   `[Budget] scan=... gate=... collect=... judge=... repro=... task=... probe=... total=... max_conns=...`；
   超预算时会看到 `[Budget] ... 夹紧`。

## 与旧文档的差异

| 旧文档 | 当前实现 |
|---|---|
| Redis 分布式队列 / List/Stream | PostgreSQL `river_job` |
| 普通/高优先/慢速/死信四类队列 | `scan` + sentinel 三队列 + `collection_gate` + `task_jobs` |
| `queue.max_retries` 配置段 | 重试硬编码在队列客户端；通用队列用 `scanner.retry_count` |
| 动态调整优先级 | 仅 `scan` 入队时按 0–255 映射 Priority 1–4 |
