# 多阶段构建：node 官方镜像产前端、golang 官方镜像产静态后端、alpine 运行时。
# 全部走 Docker 官方镜像，构建产物自包含（前端 dist 烤进镜像，不再依赖宿主机挂载）。
# 本地数据/文档/配置由 .dockerignore 挡在构建上下文之外，不会进入任何镜像层。

# ---- 前端 ----
FROM node:22-alpine AS frontend
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- 后端 ----
FROM golang:1.26-alpine AS builder
# GOPROXY 可按网络环境覆盖：docker build --build-arg GOPROXY=https://goproxy.cn,direct .
# 模块经代理下载，不需要 git；基础镜像已带 ca-certificates。
ARG GOPROXY=https://proxy.golang.org,direct
WORKDIR /src
COPY go.mod go.sum ./
RUN go env -w GOPROXY=${GOPROXY} && go mod download
COPY . .
# server（控制面）与 pocsmith（复现/靶场验证 worker）是同一个二进制的不同进程角色；
# 不编 pocsmith 的话 compose 里的验证队列无人消费，作业入队后永远「没拉 docker 验证」。
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server . && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pocsmith ./cmd/pocsmith

# ---- docker CLI ----
# 官方 cli 镜像里 docker 二进制的位置随基础镜像变过（/usr/bin 或 /usr/local/bin），
# 用 command -v 取到再复制，避免写死路径导致构建失败。
FROM docker:27-cli AS dockercli
RUN mkdir -p /out && cp "$(command -v docker)" /out/docker

# ---- 运行时 ----
# 本层零网络下载（apk 在受限网络下不可靠）：证书复用 golang 基础镜像的，
# 时区用 Go 自带的 zoneinfo.zip（Go 运行时优先读 ZONEINFO 环境变量）。
# docker CLI 从官方 cli 镜像复制（不 apk、不引 SDK），供 pocsmith 通过挂载的
# /var/run/docker.sock 执行 pull / network / run。
FROM alpine:3.20
WORKDIR /app

COPY --from=builder /usr/local/go/lib/time/zoneinfo.zip /app/zoneinfo.zip
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/server /app/server
COPY --from=builder /out/pocsmith /app/pocsmith
COPY --from=dockercli /out/docker /usr/local/bin/docker
COPY --from=frontend /web/dist /app/frontend/dist
COPY config /app/config

# 外部扫描工具（tools/<os>/）不在镜像内，运行时按需挂载宿主机目录。
ENV ZONEINFO=/app/zoneinfo.zip
ENV ZRE_FRONTEND_DIST=/app/frontend/dist
EXPOSE 8080 9443
ENTRYPOINT ["/app/server"]
