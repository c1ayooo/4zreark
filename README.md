# 4zreark

资产侦察与漏洞管理平台：从项目种子出发做资产展开、指纹与服务识别、漏洞复核，并把结果归并成可检索的资产图谱。

- 控制面：Go + Gin + PostgreSQL 16 + River 队列
- 前端：React 18 + TypeScript + Vite 5 + Tailwind + Radix UI + TanStack Query
- 扫描：单控制面 + 多扫描节点，节点不持有数据库账号
- 存储：只用 PostgreSQL，不依赖 MongoDB / Redis

> 本项目只用于**已获授权**的资产与漏洞测试。启动任务前请确认项目种子就是授权边界。

---

## 当前状态

- 控制面、前端、资产治理域、任务队列和分布式节点已跑通。
- 扫描结果按发现增量落库，不再等任务结束统一提交。
- 生产配置使用 `master` 角色，扫描交给远程 worker。
- 剩余项和现场记录见 [`docs/交接-资产治理P0现状与后续-20261020.md`](docs/交接-资产治理P0现状与后续-20261020.md)。

---

## 功能

### 资产治理

- 项目 / 种子 / 站点 / 入口 / 路由 / 原始记录 / 关系与证据链。
- 子域、端口、URL、技术栈、图标、状态码按项目归并。
- 资产存活验证、复验、失联判定与批量清理。
- 资产 DSL 查询、风险评分、技术栈/图标聚类、资产星图。
- 原始记录保留采集原貌，站点按 `host` 归并，端口落 `site_endpoints`。

### 侦察任务

- 任务模板和自定义任务，支持域名、IP、URL、CIDR 目标。
- 扫描模块：子域名枚举、接管检测、端口扫描、指纹识别、Web 爬虫、目录扫描、敏感信息、漏洞扫描。
- 任务级限速、目标间隔、并发、端口模式、子域/目录字典。
- 暂停、继续、停止、重试、重新扫描、运行中查看进度。
- 停止后可编辑目标/扫描类型/字典，再重试或从头扫描。
- 结果边发现边写入，扫描结果和资产增量落库。

### 分布式节点

- `master` 负责 Web/API、PostgreSQL、River、巡航调度和派单。
- `worker` 只持有平台签发的可吊销 token，通过 WebSocket 接单、HTTPS 拉任务和回传结果。
- 按任务能力选择节点，节点有心跳、并发上限、在线状态和版本信息。
- 支持节点密钥轮换/吊销、节点删除、worker 二进制自更新。
- 提供 SSH 一键部署、gost 反连和 WebShell 分片上传脚本。

### 指纹与情报

- 指纹规则导入、预览、合并、启停和上游同步（wappalyzer / webanalyze / dddd 等）。
- 漏洞情报拉取、分析和模板草稿；自动生成默认关闭，需人工确认。
- 组件画像、CVE 关联、验证 playbook。

### 漏洞管理

- 漏洞清单、严重程度、状态流转和复核台账。
- Nuclei 模板/POC 管理、运行时执行、批量验证。
- 漏洞报告与信息收集报告，支持 SRC / 客户 / 内部分档。

### 数字足迹与平台能力

- ICP 备案、企业身份、数字资产、本地文档。
- 变更时间线、关系图谱、页面监控、自动巡航。
- 用户 / 角色 / 权限、审计日志、API Key、MCP 接入。
- 站内通知、邮件、飞书群 Webhook / 企业应用机器人。
- 保留策略：扫描结果、原始记录、验证记录、资产事件按天清理。

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

---

## 技术栈

**后端**

- Go 1.26.3、Gin、gorilla/websocket
- pgx/v5 + 原生 SQL，无 ORM
- River（PostgreSQL 队列）、robfig/cron
- miekg/dns、goquery、goja、go-rod
- JWT、RBAC、API Key、MCP

**前端**

- React 18、TypeScript、Vite 5
- Tailwind CSS、Radix UI、shadcn 风格组件、TanStack Query
- Recharts、React Flow、d3-force

**外部扫描工具**

后端会按需调用 `gogo`、`spray`、`katana`、`rad`、`nuclei`、`ksubdomain` 等二进制。它们不随仓库提交，需要在 worker 主机安装并确保在 `PATH` 或配置路径中。

---

## 仓库结构

```text
.
├── src/backend/          Go 后端、扫描器、队列、节点网关
│   ├── api/              HTTP / WebSocket / 节点网关
│   ├── config/           配置、字典、Nuclei 模板
│   ├── internal/         浏览器、指纹、验证、凭据、recon 能力包
│   ├── models/           数据模型
│   ├── repo/             PostgreSQL 仓储
│   ├── router/           路由装配
│   ├── scanner/          子域、端口、指纹、Web、漏洞扫描
│   ├── service/          业务服务、任务执行器、巡航、报告
│   └── docs/             后端使用文档
├── src/frontend/         React 前端
├── docs/                 设计、交接、SQL 迁移与现场记录
├── reconkit/             侦察能力源码（独立 Go module）
├── scripts/              节点打包等运维脚本
└── src/backend/configs/  验证 playbook
```

---

## 快速开始

### 1. 环境要求

- Go **1.26.3+**
- Node.js 20+（建议 22）
- PostgreSQL **16**
- `libpcap-dev`（扫描器构建依赖）
- Linux 建议安装 `ca-certificates`、`tzdata`

### 2. 初始化数据库

```bash
createuser zre --pwprompt
createdb -O zre zreark
psql -d zreark -c 'CREATE SCHEMA IF NOT EXISTS zre AUTHORIZATION zre;'
```

执行基础 DDL 和治理迁移：

```bash
export PGPASSWORD='你的数据库密码'

psql -h 127.0.0.1 -U zre -d zreark -v ON_ERROR_STOP=1 \
  -f docs/sql/schema_init.sql

psql -h 127.0.0.1 -U zre -d zreark -v ON_ERROR_STOP=1 \
  -f docs/sql/migration_assets_p0.sql

psql -h 127.0.0.1 -U zre -d zreark -v ON_ERROR_STOP=1 \
  -f docs/sql/schema_governance.sql
```

其余 `docs/sql/migration_*.sql` 是增量迁移；按
[`docs/交接-资产治理P0现状与后续-20261020.md`](docs/交接-资产治理P0现状与后续-20261020.md)
中的执行记录顺序应用。后端启动会做表、迁移账本和分区自检，缺表会以退出码 2 失败。

### 3. 构建后端

```bash
cd src/backend

export CGO_ENABLED=1
go build -trimpath -ldflags="-s -w" -o 4zreark .
```

### 4. 构建前端

```bash
cd src/frontend
npm ci
npm run build
```

产物在 `src/frontend/dist`。后端默认从 `../frontend/dist` 读取；路径不同时设置 `ZRE_FRONTEND_DIST`。

### 5. 启动 master

```bash
cd src/backend

export ZRE_PG_PASSWORD='你的数据库密码'
export ZRE_SECRET_KEY="$(openssl rand -hex 32)"   # 数据源凭据加密密钥，务必固定保存

./4zreark -role master
```

默认端口：

- Web / API：`http://0.0.0.0:8080`
- 节点网关：`https://0.0.0.0:9443`（自签证书自动生成）

首次启动会创建管理员账号 `admin`，初始密码 `admin123`。**登录后第一件事是修改密码。**

### 6. 启动 worker

先在「节点管理」里添加节点并复制一次性 token，然后在扫描主机上启动：

```bash
./4zreark -role worker \
  -platform-url https://<master-host>:9443 \
  -node-token '<节点 token>' \
  -node-name worker-1 \
  -max-tasks 4
```

worker 不配置 PostgreSQL。若平台使用自签 CA，把 CA 放到 worker 并设置
`ZRE_NODE_PLATFORM_CA`，或在配置里设置 `node.platform_ca`。

### 7. 单机开发模式

```bash
./4zreark -role all
```

`all` 会在本机执行扫描，适合开发和联调，不建议作为生产拓扑。

> 仓库里的 `src/backend/Dockerfile` 和 `src/backend/docker-compose.yml` 是 Mongo/Redis 时期的历史文件，尚未按当前 PostgreSQL-only 运行时更新。生产部署请使用上面的二进制/systemd 方式，或先把这两个文件改成 PostgreSQL 版本再使用。

### 8. systemd 示例

`/etc/systemd/system/4zreark.service`：

```ini
[Unit]
Description=4zreark master
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/4zreark/src/backend
Environment=ZRE_PG_PASSWORD=change-me
Environment=ZRE_SECRET_KEY=change-me-to-a-fixed-32-byte-key
ExecStart=/opt/4zreark/src/backend/4zreark -role master
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

配置文件：`src/backend/config/config.yaml`。环境变量优先级更高，适合容器和密钥注入。

常用环境变量：

| 变量 | 说明 |
| --- | --- |
| `ZRE_PG_HOST` / `ZRE_PG_PORT` / `ZRE_PG_USER` / `ZRE_PG_DBNAME` / `ZRE_PG_SCHEMA` | PostgreSQL 连接 |
| `ZRE_PG_PASSWORD` | 数据库密码，未设置时启动自检失败 |
| `ZRE_SECRET_KEY` | 数据源凭据 AES-256-GCM 密钥；未设置时拒绝保存凭据 |
| `ZRE_FRONTEND_DIST` | 前端构建产物目录 |
| `ZRE_NODE_ROLE` | `master` / `worker` / `all` |
| `ZRE_PLATFORM_URL` / `ZRE_NODE_TOKEN` | worker 连接平台 |
| `ZRE_NODE_NAME` / `ZRE_NODE_ID` / `ZRE_NODE_MAX_TASKS` | 节点身份与并发 |
| `ZRE_NODE_PLATFORM_CA` | worker 校验平台自签证书 |
| `ZRE_WORKER_BINARY` | 平台托管的 worker 自更新二进制 |
| `ZRE_AUTOVERIFY_ENABLED` | 自动存活验证开关，`0` 关闭 |
| `ZRE_AUTOVERIFY_LIMIT` / `ZRE_AUTOVERIFY_PARALLEL` / `ZRE_AUTOVERIFY_INTERVAL_SEC` | 自动验证批次、并发、间隔 |
| `ZRE_RETENTION_*` | 扫描结果/原始记录/验证/事件的保留策略 |
| `ZRE_FEISHU_APP_ID` / `ZRE_FEISHU_APP_SECRET` | 飞书企业应用通知 |

不要把 `.pgpass.local`、节点 token、JWT secret、`ZRE_SECRET_KEY` 提交到仓库。

---

## 开发与测试

```bash
# 后端
cd src/backend
gofmt -w .
go build ./...
go vet ./...
go test ./...

# 前端
cd src/frontend
npx tsc --noEmit
npm run build
```

集成测试使用本机 PostgreSQL，连接参数见 `src/backend/test` 的测试辅助代码和交接文档。

---

## 文档

- [技术实现细节](docs/参考-4zreark-技术实现细节-20261021.md)
- [功能设计与能力地图](docs/设计-4zreark-功能设计与能力地图-20261021.md)
- [交接：资产治理 P0 现状与后续](docs/交接-资产治理P0现状与后续-20261020.md)
- [MCP 接入](docs/MCP-接入-20261021.md)
- [PostgreSQL 遗留项](docs/遗留-4zreark-PG化未完成项-20261020.md)
- [SQL 迁移目录](docs/sql)

---

## 安全与授权

- 仅对已授权目标使用；项目种子即授权边界，不要跨项目复用扫描结果。
- 生产环境必须修改默认管理员密码、JWT secret 和数据库密码。
- 节点 token 只显示一次；泄露后在节点管理里轮换或吊销。
- 情报自动生成模板默认关闭，进入模板库前必须人工确认。
- 仓库暂未附 LICENSE 文件；对外分发前请先确认代码来源与授权。
