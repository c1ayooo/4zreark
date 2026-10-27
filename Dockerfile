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
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go env -w GOPROXY=https://proxy.golang.org,direct && go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server .

# ---- 运行时 ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

COPY --from=builder /out/server /app/server
COPY --from=frontend /web/dist /app/frontend/dist
COPY config /app/config

# 外部扫描工具（tools/<os>/）不在镜像内，运行时按需挂载宿主机目录。
ENV ZRE_FRONTEND_DIST=/app/frontend/dist
EXPOSE 8080 9443
ENTRYPOINT ["/app/server"]
