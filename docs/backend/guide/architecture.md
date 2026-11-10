# 架构设计

> 本文已按当前实现重写。旧版中的 MongoDB、Redis、`backend/` 子目录、Ksubdomain/Rad 等描述均已过时。

## 总览

```text
Browser ──:8080──► master（Web / REST / JWT / WebSocket）
                     │  River 队列、巡航、阶段编排、派单、落库
                     ▼
                 PostgreSQL 16（schema=zre）
                     ▲
worker 1..N ──:9443 WSS/HTTPS──► master
（不连 PG，只认 platform_url + 可吊销 node token）
```

- 存储只有 PostgreSQL 16，不依赖 MongoDB / Redis。
- 控制面与扫描面分离：`master` 持库并派单；`worker` 不持库，经节点网关接单并回传结果；
  `all` 为单机开发模式（控制面 + 本地执行器）。
- 节点网关是独立 TLS 端口（默认 9443），只暴露 `/api/node/*`，不复用 Web 端口。

## 分层

| 层 | 职责 |
|---|---|
| `api/` | HTTP / WebSocket / 节点网关 Handler |
| `router/` | 路由装配与权限 |
| `middleware/` | JWT、RBAC、幂等、API Key、请求体限制 |
| `service/` | 业务服务、任务执行器、巡航、阶段编排、CommitSentinel、MCP |
| `service/pipeline/` | 生产扫描流水线：模块链、端口/探活/爬虫/指纹/目录/敏感 |
| `repo/` | 唯一允许写 SQL / import pgx 的层，无 ORM |
| `scanner/` | 扫描能力封装（子域、端口、Web、指纹、漏洞） |
| `internal/` | 内部能力包（llm、recon、toolruntime、nucleiruntime、browser 等） |
| `models/` | 数据结构 |
| `report/` | 报告渲染与导出 |

## 任务链路

```text
项目种子
  └─ 手工任务 / 巡航计划
       └─ TaskService.CreateTask
            ├─ collection + auto/staged → CollectionPlanService（阶段子任务）
            └─ 普通任务 → River scan 队列
                 └─ master：NodeHub.Dispatch（WSS）
                      └─ worker：StreamingPipeline
                           └─ 子域 → 接管 → 端口 → 指纹 → 爬虫 → JS/接口/目录/敏感
                                └─ 结果/资产/路由回传 → master 落库
```

### 信息收集阶段（可选）

`collection.mode=staged` 或 auto 判据命中时，父计划拆成阶段子任务：

```text
S1 域名收集（不主动探目标） → S2 探活（httpx / 纯 Go）
  → S3a 爬虫 + S3b 端口（顺序推进，共享速率预算）
  → S4 指纹/JS/接口/目录/敏感 → S5 综合评估
```

阶段推进走 `(plan_id, stage)` 幂等键；完成钩子缺失时由 30s reconciler 兜底。
阶段输入取上一阶段窗口内落库的 `raw_records`；没有输入则标 `skipped` 并留原因。

## 扫描器与工具

- 子域枚举、DNS、指纹、存活验证为纯 Go 实现（不调 subfinder/ksubdomain）。
- 外部二进制：`gogo`（端口/协议）、`spray`（目录）、`katana`（爬虫）、
  `nuclei`（漏洞）、`httpx`（探活）、`rem`（反连）、`chromium`（报告渲染）。
- 统一路径：`ZRE_TOOL_<NAME>_PATH` → `data/tools/<os>/<name>`（托管）→
  `tools/<os>/<name>`（vendored）→ `PATH`；节点经清单自动同步。
- 信息收集默认模块集：子域、接管、探活、端口、指纹、爬虫、JS 审计、接口探测、目录、敏感；
  漏洞扫描、自动验证、弱口令、PoC、gogo 内置 POC 默认关闭。

## 信息收集查询与 AI 影子

- 只读接口：`GET /api/collection/plans`、`GET /api/collection/plans/:id`
  （权限 `task:read`），返回计划 + 阶段时间线（含子任务名称/状态/进度/跳过原因）。
- 任务完成后异步写 `raw_snapshots`，并按 `collection.gate_mode` 投递 `collection_gate`：
  `shadow` 只写 `ai_gate_verdicts`；`enforce` 且 `keep` 才写 `ai_items`，
  `repo@ref` 形态再按 `(entity_id, window)` 幂等触发 `diff_jobs`。
- Gate/路由失败只告警，不影响任务状态与扫描主链；`gate_mode=off` 时完全不写快照。
- 启动时汇总 scan/gate/collect/judge/repro/task/probe 并发，超出 `pgxpool.max_conns`
  时按 Gate → 通用队列 → 探测夹紧并告警，扫描队列不动。

## 数据模型

- 任务：`tasks`（`config` 为 jsonb；阶段编排列 `plan_id/parent_id/stage/collection_mode`）。
- 资产：`projects`、`seeds`、`sites`、`site_endpoints`、`raw_records`、`scan_results`。
- 队列：`river_job`、通用 `task_jobs`。
- AI：`raw_snapshots`、`ai_gate_verdicts`、`ai_items`、`diff_jobs`、`llm_usage`。
- CommitSentinel：`repo`、`commit`、`judgment`、`finding`、`run`、`run_event`。

## 技术栈

- 后端：Go 1.26、Gin、pgx/v5 原生 SQL、River、robfig/cron、gorilla/websocket。
- 前端：React 18、TypeScript 5、Vite 5、Ant Design 6、Tailwind CSS 3、TanStack Query。
- 模型：`internal/llm` 的 eino OpenAI 兼容层（`cloudwego/eino`），AI 编排只走 `compose.Graph`。

## 目录

仓库根即 Go module 根，无 `backend/` 子目录：

```text
main.go  api/  router/  middleware/  service/  repo/  scanner/
internal/  models/  config/  configs/  report/  oid/  utils/
cmd/  docs/  frontend/  test/  tools/  scripts/  pocs/
```

`pocs/` 为空目录（运行时资产）；`tools/` 只提交说明与 `.gitignore`，二进制不入库。
