# 4zreark

资产侦察与漏洞管理平台：从企业/域名种子出发做资产展开、企业股权穿透、数字资产采集、指纹与服务识别、漏洞复核，并把结果归并成可检索、可下钻的资产图谱。内置 **CommitSentinel** 工作台，对开源仓库提交做漏洞发现、PoC 验证与代码审计。

- 控制面：Go 1.26 + Gin + PostgreSQL 16 + River 队列
- 前端：React 18 + TypeScript + Vite 5 + Ant Design 6 + Tailwind + TanStack Query
- 扫描：单控制面 + 多扫描节点，节点不持有数据库账号
- 存储：只用 PostgreSQL，不依赖 MongoDB / Redis

> 本项目只用于**已获授权**的资产与漏洞测试。启动任务前请确认项目种子就是授权边界。

---

## 当前状态

- 控制面、前端、资产治理域、任务队列和分布式节点已跑通。
- 采集链路闭环：种子 → 子域/发现轮 → 站点 → 巡检 → 采集完成综合评估通知。
- 企业穿透（小蓝本 BFS）与数字资产采集（候选池→人工确认）已上线。
- CommitSentinel 工作台已接入：仓库提交采集、AI 判定、PoC 候选、代码审计任务、对话式 agent。
- 生产配置使用 `master` 角色，扫描交给远程 worker；漏洞扫描默认关闭，信息收集类任务不含攻击性验证。

---

## 功能

菜单与路由一一对应，下面按前端侧栏分组说明。

### CommitSentinel 工作台

| 菜单 | 路由 | 说明 |
| --- | --- | --- |
| 对话 | `/sentinel/chat` | 与 agent 多轮交互，实时展示回复与工具事件流 |
| 哨兵总览 | `/sentinel` | 仓库/提交/判定/审计的整体态势 |
| 分析任务 | `/sentinel/audit/tasks` | 代码包或仓库的静态扫描 + LLM 审阅任务 |
| 分析结果 | `/sentinel/audit/results` | 候选漏洞列表与证据 |
| 分析产物 | `/sentinel/audit/artifacts` | 任务产出的报告、片段与中间产物 |
| 仓库 | `/sentinel/repos` | 纳管仓库、拉取策略与镜像目录 |
| 提交 | `/sentinel/commits` | 提交列表与单条提交的判定详情 |

- 提交采集：按仓库镜像/克隆拉取，按 `sentinel.collect_*` 配置限流与并发。
- AI 判定：`sentinel.judge_model` 指定的模型，配合 `llm` 统一接入层；预算、hunk 行数、每次提交数均可配。
- 审计队列：`sentinel.enable_audit_queue` 打开后由 worker 轮询消费。
- 产出物不外发：PoC 与审计结论只落库，人工确认后才进入后续流程。

### 概览与资产

- 仪表盘：概览卡、资产增长趋势、采集管道健康、项目资产分布、接口面 TOP、JS 密钥审计命中、事件流、端口/技术栈分布、测绘引擎用量，全部可点下钻。
- 项目管理、种子管理（domain / cidr / company / repo / app / dict / cert）。
- 资产总览、资产探索（DSL 查询、风险评分）、指纹评分、资产星图。
- 原始记录保留采集原貌，站点按 `host` 归并，端口落 `site_endpoints`；路由表跟随站点真实状态（404/410/5xx 反向删除）。

### 数字足迹

- 数字资产候选池：入池对账、批量确认、撤销回退，小蓝本 + ENScan_GO 双数据源。
- 企业身份：小蓝本 BFS 穿透子公司树（root/branch/invest），页面操作全局串行锁。
- 本地文档、ICP 备案归属域名自动转种子。

### 变更与验证

- 变更时间线、验证状态、关系图谱（根 → 类型 → 分组 → 站点，边证据可逐行核查）。
- 资产存活验证、复验、失联判定与批量清理。
- 指纹变化事件（含「消失」）。

### 侦察任务

- 任务模板与自定义任务，目标支持域名、IP、URL、CIDR。
- 扫描模块：子域名枚举、接管检测、端口扫描、指纹识别、Web 爬虫、目录扫描、敏感信息、JS 产物密钥审计、漏洞扫描（默认关闭）。
- 爬虫带 JS 接口提取（katana `-jc`/`-jsl`，SPA headless XHR 渲染），接口落 `site_routes`。
- 自动巡航：被动发现 / 端口 / 指纹 / 爬虫 / 企业深度 / 数字资产多类型错峰调度。
- 执行记录、任务日志；暂停/继续/停止/重试/重新扫描，结果边发现边写入。

### 情报库

- 指纹库：规则导入、预览、合并、启停与上游同步（wappalyzer / webanalyze / dddd 等）。
- 数据源：测绘引擎、被动源、会话托管（扫码登录、会话落库、失效告警）。
- 字典：爬虫热词计频晋升、节点分布式回传。
- GitHub 泄露监控：关键字规则、命中发现与抑制管理。

### 漏洞

- 漏洞管理：严重程度、状态流转、复核台账。
- 漏洞情报：拉取、分析、模板草稿（自动生成默认关闭，需人工确认）。
- POC 管理：Nuclei 模板/POC 导入、运行时执行、批量验证。

### 节点与执行

- 节点管理：一次性 token、密钥轮换/吊销、SSH 一键部署、gost 反连、worker 自更新。
- 任务队列：River 队列积压与重试可视化。
- 工具箱：外部扫描工具（gogo / spray / katana / nuclei / rem / enscan）的下载、校验、更新与回滚。

### 平台扩展与管理

- 插件管理、通知管理（站内 / 邮件 / 飞书群 Webhook / 企业应用机器人）。
- 用户与角色、审计日志、API Key、MCP 接入与治理（工具开关、限流）。
- 系统设置：出网代理（全局 + 模块级）、保留策略、TLS/HTTPS、公开注册开关。

---

## 架构

```text
                        ┌────────────────────────────────────────────┐
  Browser ────────────► │ master（控制面）                            │
                        │  :8080  Web / REST / JWT / API Key          │
                        │  :9443  节点专用 TLS 网关（WebSocket）       │
                        │  River 队列 / 巡航调度 / 资产与结果落库       │
                        └──────────────┬─────────────────────────────┘
                                       │ pgx
                        ┌──────────────▼─────────────────────────────┐
                        │ PostgreSQL 16                               │
                        │  schema=zre，业务表 + River + 按月分区结果表 │
                        └──────────────▲─────────────────────────────┘
                                       │ WebSocket + HTTPS（不连 PG）
                        ┌──────────────┴─────────────────────────────┐
                        │ worker 1..N（数据面）                        │
                        │  只认 platform_url + node token             │
                        │  执行扫描 → 回传结果 / 资产 / 路由            │
                        └────────────────────────────────────────────┘
```

### 任务链路

```text
项目种子
  └─ 巡航计划 / 手工任务
       └─ TaskService.Create
            └─ River 入队（按 task_id 唯一）
                 └─ master 取 job → NodeHub.Dispatch(capability)
                      └─ WebSocket 下发 scan 指令
                           └─ worker 拉任务 → StreamingPipeline
                                └─ 子域 → 接管 → 端口 → 指纹 → 爬虫 → 目录 → 敏感 → 漏洞
                                     └─ 结果/资产/路由回传 → master 落库
```

### 角色

| 角色 | 作用 | 是否连 PG |
| --- | --- | --- |
| `master` | Web/API、队列、巡航、派单、落库 | 是 |
| `worker` | 执行扫描、回传结果 | 否，只连平台 |
| `all` | 单机开发，控制面 + 本地执行器 | 是 |

启动参数（覆盖配置文件同名项）：`-role`、`-node-name`、`-node-id`、`-max-tasks`、`-platform-url`、`-node-token`。

---

## 技术栈

**后端**

- Go 1.26（`go.mod` 声明 `1.26.10`）、Gin、gorilla/websocket
- pgx/v5 + 原生 SQL，无 ORM
- River（PostgreSQL 队列）、robfig/cron
- miekg/dns、goquery、goja、go-rod
- JWT + RBAC + API Key + MCP；bcrypt 口令哈希
- 统一 LLM 接入层（`llm` 配置段，OpenAI 兼容接口）

**前端**

- React 18、TypeScript 5、Vite 5
- Ant Design 6（主题 token 与 Tailwind CSS 变量同源桥接，明暗双主题）、TanStack Query
- framer-motion（路由过渡/微动效，尊重 prefers-reduced-motion）
- Recharts、React Flow

**外部扫描工具**

后端按需调用 `gogo`（端口/协议/内置 poc）、`spray`（目录）、`katana`（爬虫）、`nuclei`（漏洞）、`rem`（节点部署反向隧道）、`enscan`（企业信息，可选）、`chromium`（报告渲染）等外部二进制。子域枚举、测绘引擎、指纹识别、存活验证等能力为纯 Go 原生实现。`gogo`/`spray`/`katana`/`rem` 由工具运行时自动下载、校验、更新与回滚，worker 按清单同步；`nuclei` 由独立运行时自更新——均无需手工安装。

---

## 仓库结构

```text
.                        仓库根 = Go module 根（module github.com/c1ayooo/4zreark）
├── main.go              入口（master / worker / all）
├── cmd/                 独立子命令：backup、cyclecheck、fpmine、opscheck、sentinel-eval、wbcheck、zreimport、zremigrate
├── api/                 HTTP / WebSocket / 节点网关 / CommitSentinel 接口
├── middleware/          JWT、RBAC、幂等、强制改密、API Key
├── config/              配置加载、字典、Nuclei 模板
├── configs/             验证 playbook
├── internal/            浏览器、指纹、验证、凭据、recon 能力包、githubleak
├── models/              数据模型
├── oid/                 ObjectID 生成与解析
├── repo/                PostgreSQL 仓储
├── router/              路由装配
├── report/              报告渲染
├── scanner/             子域、端口、指纹、Web、漏洞扫描
├── service/             业务服务、任务执行器、巡航、报告、CommitSentinel
├── frontend/            React 前端
├── docs/                使用文档（docs/backend/guide）与 SQL 迁移（docs/sql）
├── test/                集成测试
└── scripts/             节点打包等运维脚本
```

---

## 快速开始

### 1. 环境要求

- Go **1.26.10+**
- Node.js 20+（建议 22）
- PostgreSQL **16**
- Linux 建议安装 `ca-certificates`、`tzdata`

### 2. 初始化数据库

```bash
createuser zre --pwprompt
createdb -O zre zreark
psql -d zreark -c 'CREATE SCHEMA IF NOT EXISTS zre AUTHORIZATION zre;'
```

执行建库脚本（推荐一次性跑完，脚本内部按依赖排序并重试）：

```bash
PGURL='postgres://zre:你的密码@127.0.0.1:5432/zreark?sslmode=disable' \
  bash docs/sql/apply_all.sh
```

`apply_all.sh` 显式按 **核心表 → 增量迁移 → 回填** 三段执行，无 `BEGIN` 的脚本自动包在单事务里，因前置对象缺失而失败的脚本延后重试一轮。

> 不要按文件名顺序逐个 `psql`：`schema_governance.sql` 里有对 `projects` 的 `ALTER`，字母序会排在 `schema_init.sql` 之前并整段回滚，结果是缺表而服务仍能起。

后端启动会做表、迁移账本和分区自检，核心业务表缺失时以退出码 2 失败并列出缺失清单。

### 3. 构建

```bash
export CGO_ENABLED=1
go build -trimpath -ldflags="-s -w" -o 4zreark .

cd frontend
npm ci
npm run build      # 产物 frontend/dist
```

后端按 `ZRE_FRONTEND_DIST → ./frontend/dist → ./dist` 顺序查找前端产物。

### 4. 启动 master

```bash
export ZRE_PG_PASSWORD='你的数据库密码'
export ZRE_SECRET_KEY="$(openssl rand -hex 32)"   # 数据源凭据加密密钥，务必固定保存
export ZRE_JWT_SECRET="$(openssl rand -hex 32)"   # JWT 签名密钥

./4zreark -role master
```

默认端口：

- Web / API：`http://0.0.0.0:8080`
- 节点网关：`https://0.0.0.0:9443`（自签证书自动生成）

### 5. 首次初始化管理员

平台**不再自动生成 admin 账号**：

1. 首次访问页面会被引导到「初始化管理员」页（`/setup`）；
2. 自行设定用户名、密码（至少 8 位，可填邮箱），创建的是 admin 角色；
3. 创建成功后直接登录进入系统，初始化入口随即永久关闭。

对应接口：`GET /api/auth/bootstrap` 查询是否需初始化，`POST /api/auth/bootstrap` 建号；库中已有账号后 POST 一律返回 403。之后只能通过 `/api/auth/login` 登录。

### 6. 启动 worker

先在「节点管理」里添加节点并复制一次性 token，然后在扫描主机上启动：

```bash
./4zreark -role worker \
  -platform-url https://<master-host>:9443 \
  -node-token '<节点 token>' \
  -node-name worker-1 \
  -max-tasks 4
```

worker 不配置 PostgreSQL。若平台使用自签 CA，把 CA 放到 worker 并设置 `ZRE_NODE_PLATFORM_CA`，或在配置里设置 `node.platform_ca`。

### 7. 单机开发模式

```bash
./4zreark -role all
```

`all` 在本机执行扫描，适合开发联调，不建议作为生产拓扑。

### 8. Docker Compose

`Dockerfile` 与 `docker-compose.yml` 已是 PostgreSQL-only 版本：多阶段构建（Node 产前端、Go 产后端、alpine 运行时），镜像发布到 `ghcr.io/c1ayooo/4zreark`。

```bash
export ZRE_PG_PASSWORD='你的数据库密码'
export ZRE_JWT_SECRET="$(openssl rand -hex 32)"
export ZRE_SECRET_KEY="$(openssl rand -hex 32)"    # 可选，保存数据源凭据时需要

docker compose up -d postgres
# 首次部署：对映射到宿主机的 25433 端口执行建库脚本
PGURL="postgres://zre:${ZRE_PG_PASSWORD}@127.0.0.1:25433/zreark?sslmode=disable" \
  bash docs/sql/apply_all.sh
docker compose up -d app                          # 本地改动加 --build
```

外部扫描工具目录 `tools/` 以只读方式挂载到 `/app/tools`（不入库）。

### 9. systemd 示例

`/etc/systemd/system/4zreark.service`：

```ini
[Unit]
Description=4zreark master
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/4zreark
Environment=ZRE_PG_PASSWORD=change-me
Environment=ZRE_JWT_SECRET=change-me-to-a-fixed-random-hex
Environment=ZRE_SECRET_KEY=change-me-to-a-fixed-32-byte-key
ExecStart=/opt/4zreark/4zreark -role master
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now 4zreark
```

worker 用同一份二进制，只把 `ExecStart` 换成 `-role worker -platform-url ... -node-token ...`。

---

## 配置

配置文件 `config/config.yaml`，环境变量优先级更高，适合容器与密钥注入。主要配置段：

| 段 | 内容 |
| --- | --- |
| `server` | 监听地址、`public_url`、TLS 证书、强制 HTTPS |
| `auth` | `allow_public_registration`（默认关闭） |
| `jwt` | `secret`（留空则控制面拒绝启动）、`expire`、`issuer` |
| `postgres` | 连接参数、`schema`、连接池大小 |
| `node` | 角色、节点网关、证书、平台地址与 token、并发与能力标签 |
| `scanner` | worker 数、超时、重试 |
| `alert` / `thirdparty` | 通知与测绘引擎 |
| `auto_verify` | 指纹命中后的 nuclei 最小验证（默认关闭） |
| `mcp` | MCP 接入限流 |
| `sentinel` | CommitSentinel：镜像目录、采集周期、判定模型、审计队列 |
| `llm` | OpenAI 兼容接口地址、密钥环境变量名、模型与重试 |

常用环境变量：

| 变量 | 说明 |
| --- | --- |
| `CONFIG_PATH` | 配置文件路径 |
| `ZRE_PG_HOST` / `ZRE_PG_PORT` / `ZRE_PG_USER` / `ZRE_PG_DBNAME` / `ZRE_PG_SCHEMA` | PostgreSQL 连接 |
| `ZRE_PG_PASSWORD` | 数据库密码，未设置时启动自检失败 |
| `ZRE_JWT_SECRET` | JWT 签名密钥；留空或使用默认值会拒绝启动控制面 |
| `ZRE_SECRET_KEY` | 数据源凭据 AES-256-GCM 主密钥；未设置时拒绝保存凭据 |
| `ZRE_FRONTEND_DIST` | 前端构建产物目录 |
| `ZRE_NODE_ROLE` | `master` / `worker` / `all` |
| `ZRE_PLATFORM_URL` / `ZRE_NODE_TOKEN` | worker 连接平台 |
| `ZRE_NODE_NAME` / `ZRE_NODE_ID` / `ZRE_NODE_MAX_TASKS` | 节点身份与并发 |
| `ZRE_NODE_PLATFORM_CA` | worker 校验平台自签证书 |
| `ZRE_WORKER_BINARY` | 平台托管的 worker 自更新二进制 |
| `ZRE_ALLOW_PUBLIC_REGISTRATION` | 公开注册开关，默认关闭 |
| `ZRE_FORCE_HTTPS` / `ZRE_TLS_CERT` / `ZRE_TLS_KEY` | 传输安全 |
| `ZRE_AUTOVERIFY_ENABLED` / `ZRE_AUTOVERIFY_LIMIT` / `ZRE_AUTOVERIFY_PARALLEL` / `ZRE_AUTOVERIFY_INTERVAL_SEC` | 自动验证 |
| `ZRE_RETENTION_*` | 扫描结果/原始记录/验证/事件的保留策略 |
| `ZRE_LLM_API_KEY` | LLM 密钥（变量名由 `llm.api_key_env` 指定） |
| `ZRE_FEISHU_APP_ID` / `ZRE_FEISHU_APP_SECRET` | 飞书企业应用通知 |

不要把 `.pgpass.local`、节点 token、JWT secret、`ZRE_SECRET_KEY`、LLM 密钥提交到仓库。

---

## 开发与测试

```bash
# 后端
gofmt -w .
go build ./...
go vet ./...
go test ./...

# 前端
cd frontend
npx tsc --noEmit
npm run build
```

集成测试使用本机 PostgreSQL，连接参数见 `test/` 的测试辅助代码。
CI（`.github/workflows/ci.yml`）在 push / PR 到 `main`/`master` 时跑后端编译、静态检查与全量测试；Release 工作流构建并推送多架构（amd64/arm64）镜像。

---

## 文档

- [SQL 迁移目录](docs/sql)：建库与增量迁移脚本
- [入门](docs/backend/guide/getting-started.md)：本地起服务与首次初始化
- [配置说明](docs/backend/guide/configuration.md)：配置项与环境变量
- [架构](docs/backend/guide/architecture.md)：控制面/数据面与数据模型
- [扫描器](docs/backend/guide/scanners.md)：各扫描模块的能力与参数
- [节点](docs/backend/guide/nodes.md)：部署、token 与自更新
- [队列](docs/backend/guide/queue.md)：River 任务与重试
- [巡航](docs/backend/guide/cruise.md)：调度与错峰
- [插件](docs/backend/guide/plugins.md)：插件机制
- [数据库设计](docs/backend/guide/database.md)：表结构与资产域写入路径
- [公司名 → 资产全链路](docs/backend/guide/company-to-assets.md)：输入公司名的完整链路与排查清单
- [审计修复记录](docs/backend/guide/audit-fixes.md) / [待修清单](docs/backend/guide/pending-fixes.md)

设计/交接类文档（`docs/*.md`）与自定义指纹种子含授权目标信息，已在 `.gitignore` 中排除，仅本地保留。

---

## 致谢

- [ScopeSentry](https://github.com/Autumn-27/ScopeSentry) —— 本项目的资产侦察思路深受其启发：资产查询 DSL 的语法设计与巡航调度理念都参考了 ScopeSentry 的实测体验，在此向原作者 [Autumn-27](https://github.com/Autumn-27) 致谢。
- 同时感谢本项目集成与借鉴的各开源工具及其作者：[katana](https://github.com/projectdiscovery/katana)、[spray](https://github.com/chainreactors/spray)、[gogo](https://github.com/chainreactors/gogo)、[nuclei](https://github.com/projectdiscovery/nuclei)、[ENScan_GO](https://github.com/wgpsec/ENScan_GO)、[go-rod](https://github.com/go-rod/rod)、[River](https://github.com/riverqueue/river)。

---

## 安全与授权

- 仅对已授权目标使用；项目种子即授权边界，不要跨项目复用扫描结果。
- 首次初始化时设置强口令；生产环境必须替换 `ZRE_JWT_SECRET`、`ZRE_SECRET_KEY` 与数据库密码。
- 初始化入口（`/api/auth/bootstrap`）只对空库开放，建成首个账号后立即失效。
- 节点 token 只显示一次；泄露后在节点管理里轮换或吊销。
- 情报自动生成模板默认关闭，进入模板库前必须人工确认；CommitSentinel 产出物不外发。
- 仓库暂未附 LICENSE 文件；对外分发前请先确认代码来源与授权。
