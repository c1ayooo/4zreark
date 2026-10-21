# 外部工具目录

`scanner/core.ToolsManager` 按 `tools/<os>/<name>` 查找外部二进制（linux 为 `tools/linux/`）。
本目录只提交说明与 `.gitignore`，二进制不入库。

## 当前已安装（本机 linux/amd64）

| 工具 | 用途 | 来源 |
|---|---|---|
| `nuclei` | 漏洞模板执行 / 自动验证 | `~/.local/bin/nuclei`（symlink） |
| `katana` | 爬虫（主） | `~/.local/bin/katana`（symlink） |
| `enscan` | 企业信息（可选） | `~/.local/bin/enscan`（symlink） |
| `gogo` | 端口 / 协议识别 | v2.15.0 release |
| `spray` | 目录扫描 / 1000 词爆破 | v1.3.2 源码构建（Go proxy） |
| `rad` | 浏览器爬虫（可选） | **未安装**：上游 `chainreactors/rad` 已 404，Katana 可完整替代 |

## 安装/更新命令

```bash
cd src/backend
mkdir -p tools/linux

# 已在 PATH 的工具直接软链
ln -sf "$(command -v nuclei)" tools/linux/nuclei
ln -sf "$(command -v katana)" tools/linux/katana
ln -sf "$(command -v enscan)" tools/linux/enscan 2>/dev/null || true

# gogo（GitHub 直连不通时用镜像）
curl -fL --max-time 300 \
  https://ghproxy.net/https://github.com/chainreactors/gogo/releases/download/v2.15.0/gogo_linux_amd64 \
  -o tools/linux/gogo && chmod +x tools/linux/gogo

# spray：Go proxy 下载模块 zip，用 go1.26.3 工具链构建
curl -fL --max-time 120 \
  https://goproxy.cn/github.com/chainreactors/spray/@v/v1.3.2.zip -o /tmp/spray.zip
mkdir -p /tmp/spraybuild && unzip -qo /tmp/spray.zip -d /tmp/spraybuild
cd /tmp/spraybuild/github.com/chainreactors/spray@v1.3.2
GOTOOLCHAIN=go1.26.3 GOPROXY=https://goproxy.cn GOSUMDB=sum.golang.org \
  go build -o /home/c1ay/4zreark/src/backend/tools/linux/spray .
```

MongoDB 导出工具（迁移器可选）：

```bash
curl -fL --max-time 300 \
  https://fastdl.mongodb.org/tools/db/mongodb-database-tools-ubuntu2204-x86_64-100.9.4.tgz \
  -o /tmp/mongo-tools.tgz
tar -xzf /tmp/mongo-tools.tgz -C /tmp
cp /tmp/mongodb-database-tools-*/bin/{mongodump,mongoexport,mongorestore,mongoimport} ~/.local/bin/
```

## 验收

```bash
cd src/backend
ZRE_PG_PASSWORD=... go test ./test/ -run 'TestSpray1000WordlistSoft404|TestGogoLocalPort' -v

# 公网 / 外部工具用例默认跳过，需要显式打开：
ZRE_NETWORK_LIVE=1 ZRE_PG_PASSWORD=... go test ./test/ -v
```

- `TestSpray1000WordlistSoft404`：本机靶场 1002 个词、200 req/s，实测约 6.8s、
  1012 次请求、2 条真实命中，软 404 路径被过滤。
- `TestGogoLocalPort`：本地 HTTP 端口识别，返回 service=http 与页面标题。
