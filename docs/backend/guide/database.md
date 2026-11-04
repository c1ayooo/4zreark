# 数据库设计

4zreark 的主存储是 **PostgreSQL**（早期文档写的 MongoDB 已废弃：当前代码库没有任何
Mongo 驱动，全部读写走 `repo/` 层的 pgx 实现）。所有表由 `docs/sql/` 下的脚本建出，
按「核心表 → 迁移 → 回填」三段执行。

## 0. 初始化与迁移

```bash
# 推荐：按依赖顺序执行 core → migration → backfill，失败即停
PGURL='postgres://zreark@127.0.0.1:55432/zreark?sslmode=disable' \
  bash docs/sql/apply_all.sh
# 需要重建历史数据时追加 --with-backfill（慢）
```

`apply_all.sh` 做三件此前手工执行做不对的事：

1. **显式排序**：`schema_init.sql` / `schema_governance.sql` 等核心表先建，
   `migration_*.sql` 次之，`backfill_*.sql` 最后。按 `ls` 的字母序执行会因
   `schema_governance.sql` 里对 `projects` 的 `ALTER` 早于建表而整段回滚。
2. **事务语义**：没写 `BEGIN` 的脚本用 `--single-transaction` 包起来，
   写了 `BEGIN/COMMIT` 的原样执行，避免"改了一半"。
3. **依赖重试**：因前置对象缺失而失败的脚本自动延后重试一轮，不让单个
   依赖问题打断整批。

启动时 `repo.SelfCheck` 会校验核心业务表是否齐全，缺表直接报出缺失清单
（早期只校验 8 张表，`sites` 缺失也能启动，随后扫描结果静默丢光）。

## 1. 接入层：项目与种子

| 表 | 作用 | 关键列 |
|----|------|--------|
| `projects` | 资产归集单元，任务必须挂在项目下 | `id`, `code`, `name`, `cycle_interval_days` |
| `seeds` | 采集种子，`(project_id, kind, value)` 唯一 | `kind`(`domain`/`company`/`ip`/`cidr`), `value`, `capability` |
| `monitoring_plans` | 种子的周期监控计划，**一个种子一条** | `seed_id`(FK→seeds, ON DELETE CASCADE), `interval_hours`, `next_run_at` |
| `seed_collection_jobs` | 种子展开作业 | `project_id`, `status` |

`monitoring_plans.seed_id` 必须有唯一约束与外键：早期两者都缺，删种子后计划变孤儿，
调度器仍按 `next_run_at` 触发，白烧采集配额且日志无异常
（`migration_monitoring_plans_fk.sql` 修的就是这个）。

## 2. 采集层：ICP 备案与企业信息

| 表 | 作用 | 关键列 |
|----|------|--------|
| `icp_queries` | 工信部 ICP 查询任务 | `query`(公司名), `service_type`, `status`, `fetched`, `auto_promote`, `promote_interval_hours`, `promoted_count` |
| `icp_filings` | 查询结果快照（一条备案一行） | `query_id`, `domain`, `main_licence`, `unit_name` |
| `enterprise_entities` | 企业实体，`(project_id, name)` 唯一 | `name`, `credit_code`, `source` |
| `enterprise_candidates` | 候选域名，`(project_id, domain)` 唯一 | `domain`, `confidence` |
| `enterprise_jobs` | 多平台企业采集作业 | `provider`, `status` |

`icp_filings` 是链路里的关键一环：查询完成后由 `PromoteICPFilings` 把
`domain` 回灌成 `seeds(kind='domain')`，再触发扫描任务。备案库里存在大量
中文域名（`mi.中国`、`小米科技有限责任公司.中国`），回灌时统一用 IDN 转成
punycode（`mi.xn--fiqs8s`）——原样写进 `seeds` 会让下游任务创建被目标校验整批拒绝。

## 3. 资产域

| 表 | 粒度 | 说明 |
|----|------|------|
| `raw_records` | 一次观测 | 扫描的原始记录，`dedup_key` 去重，`task_id` 归因 |
| `sites` | 一台站点 | `site_key` 唯一，承载标题、状态码、技术栈 `tech`、证书、内容指纹 |
| `site_endpoints` | 站点 × 协议 × 端口 | `UNIQUE (site_id, scheme, port)`，端口视图 |
| `site_routes` | 站点 × 方法 × 路径 | 爬虫发现的接口，`UNIQUE (site_id, method, path)` |
| `asset_icons` | favicon | 按 `sha256` 去重，站点只存引用 |
| `asset_events` | 变更事件 | 站点字段 diff（标题/状态码/IP） |
| `asset_candidates` | 待确认资产 | 采集/巡航发现的新内容，等人工确认后转正式资产 |

写入路径：`task_executor` 每攒够一批（≥20 条记录 / ≥50 条路由）就
`assets.Ingest` 一次，任务结束时强制 flush。`Ingest` 在一个事务里同时写
`raw_records` + `sites` + `site_endpoints` + `asset_icons`，任一失败整批回滚。

> 注意：`sites` 的富集列（`body_hash` / `cert_org` / `cookie_names` /
> `js_frameworks` / `api_hosts`）与 `site_endpoints` 的 `last_seen_at` 曾长期
> 只存在于代码里、没有对应 DDL，导致所有扫描结果入库必然失败而任务仍显示
> "completed"。相应的迁移见 `migration_sites_enrich_columns.sql` 与
> `migration_site_endpoints_reconcile.sql`。

## 4. 扫描执行

| 表 | 作用 |
|----|------|
| `tasks` | 扫描任务；`targets` 是数组，`result_stats` 落在 `total_targets/scanned_targets/discovered_*` 列 |
| `task_jobs` | 任务下的作业分片（worker 维度） |
| `task_logs` | 任务运行明细，`category` 区分模块（`subdomain`/`fingerprint`/`ingest`…） |
| `scan_results` | 分月分区表（`scan_results_2026_11` 等），中间结果 |
| `vulnerabilities` | 漏洞记录，`severity` + `status` + `template_id` |
| `vuln_reports` / `vuln_reviews` | 报告与复核 |
| `river_job` | River 队列（PostgreSQL 后端），任务调度靠它 |

`tasks.status` 的 `completed` **只表示流水线跑完**，不代表有结果落库。
判断是否真的产出，看 `result_stats.discovered_assets` 与 `sites` 表；
落库失败会在 `task_logs` 留一条 `category=ingest, level=error` 的记录。

## 5. 指纹与技术栈

| 表 | 作用 |
|----|------|
| `fingerprint_rules` | 规则库；`expression`(DSL) / `condition_tree` / `rule_hash` / `dsl_version` |
| `fingerprint_sources` | 上游规则源，`sync.go` 按源同步 |
| `fingerprint_hits` | 「站点 × 规则」命中事实行，主键 `(site_id, rule_id)`，`rule_id` 外键到规则库 |
| `dictionaries` / `dict_entries` / `dict_learning` | 子域/路径字典与自学习热词 |

运行时规则集 = 上游快照（dddd 等）+ 内置种子，启动日志会打印
`规则集就绪: ... 编译生效 N 条`。技术栈结论落到 `sites.tech`（数组，合并不是覆盖）。

指纹命中由资产入库事务写入：`AssetRepo.ImportRecords` 在站点 upsert 之后，按
`fingerprint_rules.name` 精确匹配把本次命中写成 `fingerprint_hits` 行
（`ON CONFLICT (site_id, rule_id)` 只刷 `observed_at`），资产表的指纹数、
看板 24h 命中数、按指纹筛资产三个读方都依赖它。

> 未收录进规则库的指纹名会被跳过（不为命中结果伪造 `rule_id`）。内置种子
> 目前不落 `fingerprint_rules`，所以内置规则命中查不到对应行 —— 这是
> 「内置种子从不落库」的同一个根因，属已知待修项。

## 6. 治理与账号

| 表 | 作用 |
|----|------|
| `users` / `roles` / `permissions` | 账号与 RBAC；`roles.permissions` 是权限码数组 |
| `api_keys` / `token_blacklist` | 开放接口凭据与登出吊销 |
| `operation_logs` | 操作审计 |
| `app_settings` / `connectivity_policies` / `notify_configs` | 系统设置、出网代理策略、通知 |
| `schema_migrations` | 迁移执行记录 |

`users.role` 写入前必须校验：只有 `admin` 能改角色，且目标角色要存在于 `roles`
（此前无白名单，配合中间件对 `admin` 的硬放行可完成提权）。

## 7. 索引与运维约定

- 所有 `site_key` / `(project_id, kind, value)` / `(site_id, scheme, port)` 类业务键
  都建唯一索引，幂等写入靠 `ON CONFLICT`。
- 时间列统一 `timestamptz`，按需建部分索引（如 `idx_sites_body_hash ... where body_hash is not null`）。
- `scan_results` 按月分区，历史分区由数据保留策略（`retention_repo`）清理。
- 迁移脚本一律幂等（`IF NOT EXISTS` / `DO $$ ... $$` 守卫），可重复执行。
