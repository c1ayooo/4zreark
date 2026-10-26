# 外部工具目录

二进制查找由 **toolruntime** 统一管理（`internal/toolruntime`），解析序：

1. `ZRE_TOOL_<NAME>_PATH` 环境变量
2. `data/tools/<os>/<name>` —— toolruntime 托管（**首选，更新落点**）
3. `tools/<os>/<name>` —— 本目录 vendored（兜底）
4. `PATH`

本目录只提交说明与 `.gitignore`，二进制不入库。完整设计见
`docs/方案-toolruntime-20261022.md`。

## 受管工具（toolruntime 自动下载 / 校验 / 更新 / 回滚）

| 工具 | 用途 | 来源 |
|---|---|---|
| `gogo` | 端口 / 协议 / 内置 poc | chainreactors/gogo releases（checksums 校验 + flag 探针门） |
| `spray` | 目录扫描 / 1000 词爆破 | chainreactors/spray releases |
| `katana` | 爬虫 | projectdiscovery/katana releases |
| `rem` | 节点部署反向隧道 | **必须用本仓 fork 构建**（~/rem，官方 v0.3.0 反向转发不通） |

状态/更新/回滚：Web 设置页「工具运行时」，或
`GET|POST /api/tools[/{name}/check|update|rollback]`。
worker 节点经节点网关按清单自动同步（心跳携带 tools_hash），无需手工安装。

## 独立运行时 / 非受管

| 工具 | 用途 | 说明 |
|---|---|---|
| `nuclei` | 漏洞模板执行 / 自动验证 | 独立 nucleiruntime 自动下载 v3.11.1 + 模板并小时级自更新 |
| `enscan` | 企业信息（可选，生产默认用原生 internal/enterprise） | 需手工放置 |
| `chromium` | 报告 PDF / headless | 需手工安装 |

## rem 的 fork 构建（官方修复反向转发前）

```bash
cd ~/rem   # fork 仓，补丁 commit「fix: 反向端口转发数据面不通」
GOPROXY=https://goproxy.cn go build -tags "forceposix osusergo netgo" \
  -o /home/c1ay/4zreark/src/backend/data/tools/linux/rem . && chmod 755 $_
# 换装判定（上游发新版后跑，绿了可换回官方 release）：
cd ../.. && ZRE_REM_VERDICT=1 go test ./internal/toolruntime/ -run TestRemReverseForwardVerdict -v
```
