# 4zreark

资产侦察与漏洞管理平台：从企业/域名种子出发做资产展开、企业股权穿透、数字资产采集、指纹与服务识别、漏洞复核，并把结果归并成可检索、可下钻的资产图谱。

- 控制面：Go + Gin + PostgreSQL 16 + River 队列
- 前端：React 18 + TypeScript + Vite 5 + Tailwind + Radix UI + TanStack Query
- 扫描：单控制面 + 多扫描节点，节点不持有数据库账号
- 存储：只用 PostgreSQL，不依赖 MongoDB / Redis

> 本项目只用于**已获授权**的资产与漏洞测试。启动任务前请确认项目种子就是授权边界。

---

## 当前状态

- 控制面、前端、资产治理域、任务队列和分布式节点已跑通。
- 采集链路闭环：种子 → 子域/发现轮 → 站点 → 巡检 → 采集完成综合评估通知。
- 企业穿透（小蓝本 BFS）与数字资产采集（候选池→人工确认）已上线。
- 生产配置使用 `master` 角色，扫描交给远程 worker。
- 漏洞扫描默认关闭；信息收集类任务不包含任何攻击性验证。

---

## 功能

### 资产治理

- 项目 / 种子 / 站点 / 入口 / 路由 / 原始记录 / 关系与证据链。
- 子域、端口、URL、技术栈、图标、状态码按项目归并。
- 资产存活验证、复验、失联判定与批量清理。
- 资产 DSL 查询、风险评分、技术栈/图标聚类、资产星图。
- 原始记录保留采集原貌，站点按 `host` 归并，端口落 `site_endpoints`。
- 数据清洗：爬虫路由实测 404/410/5xx 反向删除，死站（http 404/410）结果拒收、巡检慢爬守卫，路由表跟着站点真实状态走。
- 关系图谱树形视图（根 → 类型 → 分组 → 站点），边证据抽屉逐行核查。

### 信息收集

- 种子体系：domain / cidr / company / repo / app / dict / cert；**备案归属域名自动转种子**（ICP 非空且归属 root/branch/invest 视为百分百归属，group 保留人工确认）。
- 发现轮：证书透明日志 + 测绘引擎 + 免 key 被动源组，每日巡航被动发现。
- 企业深度采集：小蓝本（qcc 系）数据源 BFS 穿透子公司树（root/branch/invest），可选集团成员展开；页面操作全局串行锁、单节点失败跳过不中止整轮。
- 数字资产采集：候选池（入池对账 / 批量确认 / 撤销回退），小蓝本 + ENScan_GO 双数据源，深度采集顺带、定时巡航采集。
- 数据源会话托管：平台内扫码登录（无头浏览器托管出码、轮询刷新、凭据回落），会话落库 + 失效全局告警，live 实测工具。
- 字典自学习：爬虫热词计频晋升，节点分布式回传。
- GitHub 泄露监控：关键字规则、命中发现、抑制管理。

### 侦察任务

- 任务模板和自定义任务，支持域名、IP、URL、CIDR 目标。
- 扫描模块：子域名枚举、接管检测、端口扫描、指纹识别、Web 爬虫、目录扫描、敏感信息、JS 产物密钥审计、漏洞扫描（默认关闭）。
- 爬虫带 JS 接口提取（katana `-jc`/`-jsl`，SPA headless XHR 渲染），接口落 `site_routes` 可下钻。
- 任务级限速、目标间隔、并发、端口模式、子域/目录字典；引擎级每主机限速保护业务站。
- 暂停、继续、停止、重试、重新扫描、运行中查看进度；结果边发现边写入。

### 仪表盘

- 看板矩阵：概览卡（监控项目/任务/漏洞/节点/资产）、资产增长趋势、采集管道健康、项目资产分布、接口面 TOP、JS 密钥审计命中、资产动态事件流、新发现站点、站点状态、端口分布、技术栈 TOP、测绘引擎用量、内置能力盘点。
- 全部指标可点下钻：落到带过滤条件的资产/事件/漏洞/种子列表（URL 参数可分享还原）。

### 分布式节点

- `master` 负责 Web/API、PostgreSQL、River、巡航调度和派单。
- `worker` 只持有平台签发的可吊销 token，通过 WebSocket 接单、HTTPS 拉任务和回传结果。
- 按任务能力选择节点，节点有心跳、并发上限、在线状态和版本信息。
- 支持节点密钥轮换/吊销、节点删除、worker 二进制自更新。
- 提供 SSH 一键部署、gost 反连和 WebShell 分片上传脚本。

### 指纹与情报

- 指纹规则导入、预览、合并、启停和上游同步（wappalyzer / webanalyze / dddd 等）。
- fpmine 指纹挖掘：favicon 聚类 + 路径共性挖掘 + 人工确认种子。
- 指纹变化事件（变更时间线含「消失」）。
- whois 域名注册信息查询（IANA 转介 + 权威二次查询）。
- 漏洞情报拉取、分析和模板草稿；自动生成默认关闭，需人工确认。
- 组件画像、CVE 关联、验证 playbook。

### 漏洞管理

- 漏洞清单、严重程度、状态流转和复核台账。
- Nuclei 模板/POC 管理、运行时执行、批量验证。
- JS 产物密钥审计命中（AK/SK、token 泄露规则，nuclei file 模板）独立展示。
- 漏洞报告与信息收集报告，支持 SRC / 客户 / 内部分档。

### 监控与巡航

- 页面内容监控（24h 批量巡检、变更事件、慢爬复核同站冷却）。
- 自动巡航：被动发现 / 端口 / 指纹 / 爬虫 / 企业深度 / 数字资产多类型错峰调度。
- 采集完成综合评估：资产类型/数目 + 风险面（注销主体、无备案域名、非常规端口、明文 HTTP 等）+ 一句话结论，飞书卡片带「前往处置」；评估快照落表 + 趋势 API。
- 项目详情页资产面综合评估卡片，注销主体一键清理（purge-dead 连带候选）。

### 数字足迹与平台能力

- ICP 备案、企业身份、数字资产、本地文档。
- 变更时间线、关系图谱、页面监控、自动巡航。
- 用户 / 角色 / 权限、审计日志、API Key、MCP 接入。
- 站内通知、邮件、飞书群 Webhook / 企业应用机器人；会话失效、漏洞发现、资产变更均接入告警。
- 出网代理：全局开关 + 模块级覆盖 + 连通性测试（扫描目标流量保持直连）。
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
- Ant Design v6（主题 token 与 Tailwind CSS 变量同源桥接，明暗双主题）、TanStack Query
- framer-motion（路由过渡/微动效，尊重 prefers-reduced-motion）
- Recharts、React Flow

**外部扫描工具**

后端会按需调用 `gogo`（端口/协议/内置 poc）、`spray`（目录）、`katana`（爬虫）、`nuclei`（漏洞）、`rem`（节点部署反向隧道）、`enscan`（企业信息，可选）、`chromium`（报告渲染）等外部二进制。子域枚举、测绘引擎、指纹识别、存活验证等能力均为纯 Go 原生实现。`gogo`/`spray`/`katana`/`rem` 由工具运行时（toolruntime）自动下载、checksums 校验、更新与回滚，worker 节点按清单自动同步；`nuclei` 由独立运行时自更新——均无需手工安装。设计与运维见 [`docs/方案-toolruntime-20261022.md`](docs/方案-toolruntime-20261022.md)。

---

## 仓库结构

```text
.                        仓库根 = Go module 根（module github.com/c1ayooo/4zreark）
├── main.go              入口
├── api/                 HTTP / WebSocket / 节点网关
├── config/              配置、字典、Nuclei 模板
├── configs/             验证 playbook
├── internal/            浏览器、指纹、验证、凭据、recon 能力包
├── models/              数据模型
├── repo/                PostgreSQL 仓储
├── router/              路由装配
├── scanner/             子域、端口、指纹、Web、漏洞扫描
├── service/             业务服务、任务执行器、巡航、报告
├── frontend/            React 前端
├── docs/                使用文档与 SQL 迁移（docs/sql）
└── scripts/             节点打包等运维脚本

> 侦察能力源码原以独立的 `reconkit/` module 存在，2026-10 已并入
> `internal/recon/` 并确认无差异后删除；`internal/recon` 是唯一正本。

---

## 快速开始

### 1. 环境要求

- Go **1.26.3+**
- Node.js 20+（建议 22）
- PostgreSQL **16**
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

其余 `docs/sql/migration_*.sql` 是增量迁移，按文件名日期顺序应用即可；后端启动会做表、迁移账本和分区自检，缺表会以退出码 2 失败。

### 3. 构建后端

```bash
export CGO_ENABLED=1
go build -trimpath -ldflags="-s -w" -o 4zreark .
```

### 4. 构建前端

```bash
cd frontend
npm ci
npm run build
```

产物在 `frontend/dist`。后端默认按 `ZRE_FRONTEND_DIST → ./frontend/dist → ./dist` 顺序查找；路径不同时设置 `ZRE_FRONTEND_DIST`。

### 5. 启动 master

```bash
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

> 仓库里的 `Dockerfile` 和 `docker-compose.yml` 是 Mongo/Redis 时期的历史文件，尚未按当前 PostgreSQL-only 运行时更新。生产部署请使用上面的二进制/systemd 方式，或先把这两个文件改成 PostgreSQL 版本再使用。

### 8. systemd 示例

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

配置文件：`config/config.yaml`。环境变量优先级更高，适合容器和密钥注入。

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

---

## 文档

设计与交接类文档**不进仓库**（含运营现场信息）：`docs/*.md` 已在 `.gitignore` 中排除，仅本地保留。仓库内只保留：

- [SQL 迁移目录](docs/sql)：建库与增量迁移脚本
- MCP 接入、toolruntime 方案等文档如有需要随发行说明单独提供

---

## 致谢

- [ScopeSentry](https://github.com/Autumn-27/ScopeSentry) —— 本项目的资产侦察思路深受其启发：资产查询 DSL 的语法设计与巡航调度理念都参考了 ScopeSentry 的实测体验，在此向原作者 [Autumn-27](https://github.com/Autumn-27) 致谢。
- 同时感谢本项目集成与借鉴的各开源工具及其作者：[katana](https://github.com/projectdiscovery/katana)、[spray](https://github.com/chainreactors/spray)、[gogo](https://github.com/chainreactors/gogo)、[nuclei](https://github.com/projectdiscovery/nuclei)、[ENScan_GO](https://github.com/wgpsec/ENScan_GO)、[go-rod](https://github.com/go-rod/rod)、[River](https://github.com/riverqueue/river)。

---

## 安全与授权

- 仅对已授权目标使用；项目种子即授权边界，不要跨项目复用扫描结果。
- 生产环境必须修改默认管理员密码、JWT secret 和数据库密码。
- 节点 token 只显示一次；泄露后在节点管理里轮换或吊销。
- 情报自动生成模板默认关闭，进入模板库前必须人工确认。
- 仓库暂未附 LICENSE 文件；对外分发前请先确认代码来源与授权。
- 设计/交接文档与自定义指纹种子（可能含授权目标信息）不进仓库，见 `.gitignore`。
