# 节点管理 (Node Management)

节点管理页用于签发/吊销节点密钥、查看在线状态和调度扫描任务。当前架构是
**Master–Worker + River 队列 + 节点密钥**：

- **Master（控制面）**：持有 PostgreSQL 和 River 队列，负责 Web/API、巡航、治理、
  情报轮询，以及通过**独立的 HTTPS/WSS 节点网关**（默认 9443）把任务推给 worker。
- **Worker（扫描节点）**：**不连接数据库**，只持有平台节点网关地址和一个可吊销的节点密钥。
  它主动连节点网关的 WSS 接单，通过 HTTPS 回传任务状态、进度、结果和 POC 请求。
- **单机模式（`all`，默认）**：一个进程同时承担控制面和本机扫描；有远程 worker 连接时
  优先派给远程节点，没有可用节点时回退本机执行。

Web UI/管理 API 仍然在 `server.port`（默认 8080）；节点数据面走
`node.gateway_port`（默认 9443，TLS），**不共用 Web 端口**。

节点侧不再出现数据库账号或连接串。即使 worker 被逆向，拿到的也只是平台签发的
节点密钥；该密钥可以在节点页随时重置或吊销，吊销后 HTTP 与 WebSocket 都会返回 401。

## 调度模型

- Master 的 River worker 从 `scan` 队列领取任务，然后选一个已连接、有容量、能力匹配的
  worker，通过 WebSocket 发送 `scan` 指令。
- Worker 收到指令后执行流水线；任务状态/进度/结果通过 `/api/node/*` HTTP 接口回传，
  由 Master 统一写 `tasks`、`scan_results`、资产表和漏洞表。
- 一个扫描任务对应一条 River 作业，由**一个**节点执行；多个任务会在节点之间分摊，
  单个任务不会拆到多个节点并行。
- 节点心跳通过 WebSocket 上报：CPU、内存、当前任务数、能力、标签、最后心跳时间。
- 节点页的“停用”会阻止 Master 继续向该节点派单；已在执行的任务继续完成。
- 控制面每隔 3 个心跳周期（最少 90 秒）把没有心跳的节点标为离线。
- 升级前的 `task_jobs(kind='scan')` 排队作业会在控制面启动时迁移到 River；
  `/api/queue` 那套通用队列仍使用 `task_jobs(kind='job')`，与扫描队列互不影响。

## 节点密钥

- 在节点页点“添加节点”，平台创建节点并返回**一次性密钥**（只显示一次）。
- 平台库中只存密钥的 SHA-256（`scanner_nodes.token_hash`），不存原文。
- 节点配置里只写：

  ```yaml
  node:
    role: worker
    platform_url: "https://master:9443"
    platform_ca: "/opt/4zreark-worker/config/node-gateway.crt"
    token: "<平台签发的密钥>"
    max_tasks: 5
  ```

- **重置密钥**：旧密钥立即失效，在线连接被断开，节点需要用新密钥重连。
- **吊销密钥**：清空哈希、节点置为离线、断开 WebSocket；之后该节点无法再连接平台。
- 节点被删除或密钥被吊销后，Master 不会再向它派单。

## 节点网关（独立 TLS 端口）

- `server.port`（默认 8080）只用于 Web UI 和管理 API；`/api/node/*` **不再挂在 Web 端口**。
- `node.gateway_port`（默认 9443）是节点专用 TLS 网关，只暴露 `/api/node/*` 和 `/health`。
- 默认自动生成自签证书，存放在 `node.tls_dir`（默认 `data/node-tls`）；也可以配置
  `node.tls_cert` / `node.tls_key` / `node.tls_ca` 使用自己的证书。
- worker 通过 `node.platform_ca` 信任该证书；一键部署会把证书上传到 worker 并自动写入。
- 直连部署时 `platform_url = https://<平台主机>:9443`；
  rem 反连时 `platform_url = https://127.0.0.1:<隧道端口>`，隧道目标为
  `127.0.0.1:9443`（不是 8080）。
- 如果证书是自签的，平台重启会复用同一张证书；删除 `tls_dir` 会重新生成，已有 worker
  需要重新部署或更新 `platform_ca`。

## SSH 一键部署

节点页的“一键部署”可以用 SSH 密码或私钥把节点装到目标主机：

1. 选择目标系统：**Linux amd64** 或 **Windows amd64**。
2. 填写 SSH 主机、端口、用户名，以及密码或私钥（私钥支持口令）。
3. 平台通过 SFTP 上传 worker 二进制和一个只包含 `node.role=worker`、`platform_url`、
   节点密钥、并发配置的 `config/config.yaml`（**不含数据库账号**）。
4. Linux 执行 `nohup ./worker` 启动；Windows 用 PowerShell 在隐藏窗口启动 `worker.exe`。
5. worker 自动连回 Master，节点页显示在线；启动日志随部署结果返回。

Linux 安装目录默认 `/opt/4zreark-worker`，Windows 默认 `C:\4zreark-worker`。Windows 的
配置位于 `C:\4zreark-worker\config\config.yaml`，日志为 `worker.log` / `worker.err.log`。

### Windows 二进制

一键部署 Windows 需要提前构建好 `worker-windows-amd64.exe`：

```bash
cd src/backend
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o worker-windows-amd64.exe .
```

把生成的文件放到 server 可执行文件同目录，或配置：

```yaml
node:
  windows_binary: "/path/to/worker-windows-amd64.exe"
```

目标 Windows 需要启用 OpenSSH Server（带 SFTP 子系统）和 PowerShell。

### 自动 rem 反连（推荐）

部署页默认开启“自动 rem 反连”。只需要填 SSH 主机/端口/用户名，以及密码或私钥，
平台会自动完成：

1. 检查目标机是否有 rem；没有就把 Master 侧 rem 上传到 `/usr/local/bin/rem`
   （约 3MB；Master 侧由工具运行时管理，也可用 `node.rem_binary` 指定路径）。
2. 在目标机启动 rem 服务端（默认 relay 端口 `18421`，`-k` 通道密钥自动生成）。
3. 从目标机 rem 日志提取带 wrapper 加密参数的完整 LINK。
4. 在 Master 本机启动 rem 反向转发客户端（默认隧道端口 `18080`）：
   `rem -c <LINK> -r port://127.0.0.1:18080/127.0.0.1:9443`，
   目标机 `127.0.0.1:18080` 的流量经隧道回到 Master 并进入 `127.0.0.1:9443`（节点网关 TLS 端口）。
5. 从目标机探测 `https://127.0.0.1:18080/health`，确认隧道真的通到节点网关。
6. 部署 worker，并自动把 `platform_url` 设为 `https://127.0.0.1:18080`。

要点：

- relay 端口必须允许 Master 访问（云安全组/防火墙）；隧道端口只绑定目标机
  `127.0.0.1`，不会暴露到公网。
- 通道密钥与 LINK 记录在 Master 的 `/tmp/4zreark-tunnels/<node_id>.json`（0600）。
  rem 的链路认证是 `-k` 共享密钥 + wrapper 加密，没有 gost 那种 relay URL 级
  user:pass；relay 端口暴露面应尽量收窄（安全组只放行 Master IP）。
- 删除/吊销节点会停止 Master 侧客户端；目标机上的 rem 服务端进程会保留，需要手动停止
  或重启目标机。
- **平台启动时会自动恢复已有隧道**：进程还活着则跳过；进程已死就用记录里的 LINK 重新拉起。
  注意 LINK 里的 wrapper 参数由目标机 rem 服务端每次启动时生成——目标机重启过服务端的，
  记录里的 LINK 失效，需要重新部署。隧道记录默认在 `/tmp/4zreark-tunnels`；如果希望主机
  重启后也能恢复，把 `node.tunnel_dir` 指到持久目录（例如 `/var/lib/4zreark/rem-tunnels`）。
- **rem 二进制必须是含反向转发修复的构建**：官方 v0.3.0 的反向端口转发数据面不通
  （fork 补丁见 `~/rem` 仓 commit “fix: 反向端口转发数据面不通”，判定测试
  `ZRE_REM_VERDICT=1 go test ./internal/toolruntime/ -run TestRemReverseForwardVerdict`）。
  官方发布修复后可换回官方 release。
- rem 反连目前只支持 Linux 目标机；Windows 目标机关掉该开关走直接部署。
- 目标机 sshd 如果禁用了密码认证，请在部署页改用私钥登录。

### 网络与代理

如果不使用自动反连，worker 仍然只需要**出站**访问平台（WebSocket + HTTP）：

- 平台有公网地址/端口映射：直接填平台地址，不需要中继。
- 目标机只能通过现成代理访问平台：在部署页“代理”里填 `socks5://...` 或 `http://...`。
- 平台在 NAT 后面、目标机也访问不到平台：必须有公网中继；自动 rem 反连就是为此设计的。

worker 配置对应字段：

```yaml
node:
  proxy: "socks5://user:pass@relay:1080"   # 或 http://relay:8080
```

也支持环境变量 `ZRE_NODE_PROXY`。

### 要求与限制

- Linux 目标机要求 Master 运行在 linux/amd64；Windows 目标机使用单独构建的 exe。
- 目标机需要已有扫描工具、字典、`pocs/` 等运行资产；一键部署只传二进制和节点配置。
- SSH 用户需要对安装目录有写权限（Linux 默认 `/opt` 通常需要 root 或 sudo）。
- SSH 密码/私钥只在该请求内使用，不落库、不写日志；请求本身应走 HTTPS。
- 默认使用 `ssh.InsecureIgnoreHostKey()`，不校验目标机 host key；高安全环境建议改成固定指纹校验。
- 部署完成后返回启动日志；若 worker 未上线，查看目标机的 `worker.log` 和节点页状态。

## 配置

Master / 单机：

```yaml
postgres:
  host: "127.0.0.1"
  port: 25433
  user: "zre"
  password: ""
  dbname: "zreark"
  schema: "zre"
  sslmode: "disable"

node:
  role: "all"        # all | master
  name: ""
  max_tasks: 5
  heartbeat_interval: 30
```

Worker：

```yaml
node:
  role: "worker"
  platform_url: "https://master:9443"
  token: "<节点密钥>"
  proxy: ""                # 可选：socks5://user:pass@relay:1080
  name: "worker-hk-1"
  max_tasks: 10
  heartbeat_interval: 30
  capabilities: ["subdomain", "port_scan", "fingerprint", "vuln_scan", "crawler", "dir_scan", "sensitive"]
  tags: ["overseas"]
```

命令行/环境变量（生产环境建议用配置文件或环境变量传密钥，命令行参数会出现在 `ps` 里）：

```bash
./server --role worker \
  --platform-url https://master:9443 \
  --node-token '<节点密钥>' \
  --node-name worker-hk-1 \
  --max-tasks 10

ZRE_NODE_ROLE=worker \
ZRE_PLATFORM_URL=https://master:9443 \
ZRE_NODE_TOKEN='<节点密钥>' \
ZRE_NODE_NAME=worker-hk-1 \
ZRE_NODE_MAX_TASKS=10 \
./server
```

Worker 侧仍需要扫描工具、字典、`pocs/` 等运行资产；但不需要 `postgres` 配置，也不需要
能访问数据库的网络。**不要把含真实数据库密码的 `config.yaml` 拷到 worker**——worker 模式
虽然会忽略 `postgres` 段，但文件本身仍会被逆向读出。

## 部署一个分布式集群

1. **控制面**（一台）：`node.role=master`，连接 PostgreSQL；启动后在节点页“添加节点”，
   保存返回的密钥。
2. **扫描节点**（可多台）：`node.role=worker`，只配置 `platform_url` + `token`；
   启动后会自动连上控制面并出现在节点列表。
3. Worker 需要能**出站访问**控制面的 HTTP/WebSocket 端口；不需要给 Worker 开放入站端口。
4. 创建任务后，Master 会把任务派给已连接的 worker；结果由 Master 统一落库。

> 安全提示：节点密钥等同于该节点的登录凭证，泄露后请立即在节点页重置或吊销。
> Master 的 PostgreSQL 不应暴露到公网；Worker 不再需要数据库账号。

## 故障处理

- **Worker 断线**：Master 的派单调用失败，River 会将作业重试；Worker 恢复后重连即可。
- **Worker 被吊销**：WebSocket 断开，重连返回 401，Worker 停止重连并退出连接循环。
- **Worker 被强制杀死**：River 作业在 `JobTimeout + 1h`（默认 25 小时）后由 rescued 机制回收；
  正常退出时作业会立即 snooze 回队列。需要更快恢复可先对任务点“重试”。
- **队列积压**：增加 Worker 数量，或提高 Worker 的 `max_tasks`（启动时生效）。
- **单个任务很慢**：当前是任务级调度，单个任务只在一个节点上跑；需要单任务并行时，
  应拆成多个任务提交。
