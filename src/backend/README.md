# 4zreark backend

4zreark 的 Go 后端：Gin HTTP/WebSocket、PostgreSQL 16、River 队列、分布式节点网关和扫描流水线。

完整的功能、架构和部署说明见仓库根 [README](../../README.md)。

## 运行角色

由 `config/config.yaml` 的 `node.role` 或命令行 `-role` 决定：

| 角色 | 启动内容 | 数据库 |
| --- | --- | --- |
| `master` | Web/API、River、巡航调度、节点网关、派单 | 需要 |
| `worker` | WebSocket 接单、HTTPS 拉任务/回结果、本地扫描 | 不需要 |
| `all` | 控制面 + 本地扫描执行器 | 需要 |

## 构建

```bash
export CGO_ENABLED=1
go build -trimpath -ldflags="-s -w" -o 4zreark .
```

构建依赖 Go 1.26.3+、`libpcap-dev`、`ca-certificates`。

## 启动

```bash
export ZRE_PG_PASSWORD='...'
export ZRE_SECRET_KEY="$(openssl rand -hex 32)"

# 控制面
./4zreark -role master

# 扫描节点
./4zreark -role worker \
  -platform-url https://<master>:9443 \
  -node-token '<node-token>' \
  -node-name worker-1 \
  -max-tasks 4
```

Web/API 默认 `:8080`，节点网关默认 `:9443`。前端构建产物由 `ZRE_FRONTEND_DIST` 指定，默认读取 `../frontend/dist`。

## 目录

```text
api/          HTTP 处理器、节点 WebSocket 网关、MCP
config/       配置、字典、Nuclei 模板
internal/     浏览器、指纹、验证、凭据、recon 能力
middleware/   JWT、RBAC、API Key、幂等、日志
models/       数据模型
repo/         PostgreSQL 仓储（pgx，原生 SQL）
router/       路由装配
scanner/      子域、端口、指纹、Web、漏洞扫描
service/      任务执行器、节点、巡航、资产、报告、通知
cmd/          迁移和运维辅助命令
test/         跨包集成测试
```

## 数据库

基础 DDL 和迁移顺序见根 README 的「初始化数据库」。启动时会校验：

- PostgreSQL 连接
- `schema_migrations` 迁移账本
- 必需业务表
- `scan_results` 当月/次月分区

任一项失败会以退出码 2 退出。

## 测试

```bash
gofmt -w .
go build ./...
go vet ./...
go test ./...
```

集成测试需要本机 PostgreSQL；连接参数由测试辅助代码和 `docs/交接-资产治理P0现状与后续-20261020.md` 说明。

## 外部扫描工具

`gogo`、`spray`、`katana`、`rad`、`nuclei`、`ksubdomain` 等二进制不随仓库提交，需要在 worker 主机安装并可从 `PATH` 或配置路径找到。
