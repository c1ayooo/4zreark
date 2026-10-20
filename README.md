# 4zreark

资产侦察与漏洞管理平台。基线是望月塔 2025-12-09 版（前后端齐全那一版），本仓在此基础上做三件事：后端 Go + PostgreSQL、前端设计系统与页面重构、漏洞情报与 AI 自动生成 nuclei 模板。

当前状态：**基线已落地、构建通过；PG 化与改造尚未开工**。

---

## 目录

• `src/backend` — Go 1.24，127 个 `.go`，188 条路由，module `github.com/c1ayooo/4zreark`；当前数据层仍是 MongoDB（16 个集合、209 处调用、10 处聚合）
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
• `docs/sql/schema_init.sql` — 可直接执行的初始化 DDL（30 张表、117 个索引、结果表按月分区），已在本机 PG 16 验证通过
• 存储口径：不引入 Redis。队列 `task_jobs`、跨月去重 `result_dedup`、单端登出 `token_blacklist` + `users.token_version`；迁移脚本按内容命名，不用数字序号

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
