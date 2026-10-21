# 4zreark

资产侦察与漏洞管理平台。后端 Go 1.26 + PostgreSQL，前端 React 18 + Vite 5，覆盖资产治理、漏洞管理、任务调度、情报富化与企业信息收集。

当前状态：**Go + PostgreSQL 后端、前端页面与治理域已落地；剩余项见 `docs/交接-资产治理P0现状与后续-20261020.md`**。

---

## 目录

• `src/backend` — Go 1.24，188 条路由，module `github.com/c1ayooo/4zreark`；数据层已全部落 PostgreSQL，
  `database/` 包（Mongo 连接）已删除，启动不再连 Mongo
• `src/frontend` — React 18 + Vite 5 + TS + Tailwind + Radix + TanStack，20 个页面、25 个组件
• `docs/` — 两份设计方案
• `reference/v0.6-源码` — 上游早期 v0.6（GORM + PG、114 路由、前端只有 dist），仅作功能与页面参考
• `reference/前端-1209-子集` — 12-09 前端的部分快照，已被 `src/frontend` 覆盖
• `releases/` — 已发出的三个源码包

---

## 方案索引

• `docs/方案-4zreark-Go重写与PG存储-20261020.md` — 存储层重画：表结构、索引、分区、队列、仓储拆分、迁移路径、验收口径
• `docs/方案-4zreark-PG化与前端优化及情报模板移植-20261020.md` — 最终口径：18 张业务表 + 3 张运行态表、前端 token 与逐页改造、9 个情报源与七段流水线、里程碑与工期
• `docs/方案-4zreark-PG改造交接规格-20261020.md` — 给编码 agent 的执行规格：类型映射、配置契约、仓储接口、逐服务顺序、关键 SQL、验收清单、四份派工分片
• `docs/方案-reconkit并入与去重-20261020.md` — reconkit 并进 backend 的裁决表：哪些能力用 reconkit 替换、哪些保留 backend、哪些是纯补洞；含建表冲突、severity 词汇、favicon 哈希空间三处静默风险
• `docs/派单-reconkit并入-20261020.md` — 上述方案的 14 张工单（T0 前置 + 阶段 A 补洞 7 张 + 阶段 B 去重 6 张），带依赖边与可执行验收
• `docs/sql/schema_init.sql` — 可直接执行的初始化 DDL（30 张表、117 个索引、结果表按月分区），已在本机 PG 16 验证通过
• `docs/sql/schema_api_key.sql` — API key 增量 DDL：只存 SHA-256、按项目绑定、支持停用/过期/调用审计
• `docs/sql/schema_notify.sql` — 通知增量 DDL：渠道配置 `notify_configs`、站内通知 `notifications`、按用户已读 `notification_reads`
• `docs/sql/migration_report_kind_template.sql` — 报告增量列：`report_kind`（vuln / asset）、`template`、`delivery`；信息收集报告与漏洞报告共用 `vuln_reports` 台账
• `docs/sql/migration_vuln_reviews.sql` — 复核台账：`vuln_reviews` 记录每次状态流转（谁/何时/为什么），`vulnerabilities` 加 reviewer / review_note / reviewed_at / review_count
• `docs/sql/migration_relation_observations.sql` — 关系层观测值：`sites.cert_sha256` / `final_host`，`relations.type` 扩展到八类（同 IP / C 段 / 证书 / 图标 / 技术栈 / 父子域 / 跳转 / CNAME）
• `docs/sql/migration_cycle_change_trigger.sql` — 巡航触发方式：`monitoring_plans.trigger_mode`（interval / on_change / both）+ `change_cooldown_minutes`
• 报告：`GET /api/reports/templates` 列模板，`POST /api/reports/generate` 传 `kind=asset|vuln` 生成；信息收集报告输出域名/站点/端口/指纹/状态，漏洞报告输出清单、复现、证据与修复建议，各含 SRC / 客户 / 内部三档模板
• 通知：页面铃铛读 `notifications`，飞书支持群 Webhook 与企业应用机器人；企业应用凭据可走通知管理页，或环境变量 `ZRE_FEISHU_APP_ID` / `ZRE_FEISHU_APP_SECRET` / `ZRE_FEISHU_RECEIVE_ID` / `ZRE_FEISHU_RECEIVE_ID_TYPE`
• `docs/MCP-接入-20261021.md` — 外部平台 / MCP 接入：设置页签发带权限的 key，`POST /api/mcp` 按 scope 执行资产读取、项目/治理/任务/扫描/漏洞/POC 操作
• 存储口径：不引入 Redis。扫描作业队列用 River（`river_job`，启动自动迁移）、通用队列仍为 `task_jobs`、跨月去重 `result_dedup`、单端登出 `token_blacklist` + `users.token_version`；迁移脚本按内容命名，不用数字序号
• 分布式节点：worker 不再持有数据库账号，只用平台签发的可吊销节点密钥（`scanner_nodes.token_hash`）连 Master；新增库需执行 `docs/sql/migration_node_token.sql`

### 本机数据库

• 容器 `4zreark-pg`（`postgres:16-alpine`），`127.0.0.1:25433`，库 `zreark`，用户 `zre`，schema `zre`
• 密码在仓库根 `.pgpass.local`（600 权限，不入文档不入 git）
• 当前状态：DDL 已执行，30 张表 + 117 个索引就位；用户、任务、队列三域已接 PG

---

## 构建

后端需要 `libpcap-dev`（naabu/ksubdomain 依赖）。

```bash
cd src/backend
export PATH="$HOME/.local/go/bin:$PATH"
export GOPROXY=https://goproxy.cn,direct
export GOFLAGS=-mod=mod
go build -o 4zreark .
```

启动前导出数据库密码（密码不入库文件，按交接规格 §5 走环境变量；未设置则启动自检失败、退出码 2）：

```bash
export ZRE_PG_PASSWORD=$(cat ../../.pgpass.local)
./4zreark
```

```bash
cd src/frontend
npm ci --registry=https://registry.npmmirror.com
npx vite build
```

本机验证记录：后端产物 25MB，`gofmt -l` 为 0；前端 2460 个模块，产物 1.6MB JS（gzip 450KB）+ 44KB CSS。

---

## 命名约定

• 目录、仓库、二进制：`4zreark`
• Go module：`github.com/c1ayooo/4zreark`
• PG 库名：`4zreark`（PG 标识符不能以数字开头，此时 `4zreark` 作库名不合法，实际用 `zreark`）；schema 用 `zre`
• 环境变量前缀：`ZRE_`
• 工具与 MCP 前缀：`zr_`

---

## 红线

• 上游无许可证（`license.spdx_id` 为 `null`）：对外交付前必须做代码溯源清理，禁止直接分发上游代码
• 情报自动生成模板默认关闭（`auto_nuclei=false`），草稿必须人工确认才进模板库
• 禁止把 `reference/v0.6-源码` 里的配置直接用于部署（含明文凭据与外部地址）
