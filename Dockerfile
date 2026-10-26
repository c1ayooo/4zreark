FROM golang:1.26-alpine AS builder
WORKDIR /src

RUN apk add --no-cache git ca-certificates build-base

COPY go.mod go.sum ./
RUN go env -w GOPROXY=https://proxy.golang.org,direct
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o 4zreark .

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app

COPY --from=builder /src/4zreark /app/4zreark
COPY config /app/config

# 外部扫描工具（tools/<os>/，gitignore 不入库）；前端产物经 ZRE_FRONTEND_DIST 指定挂载。
EXPOSE 8080 9443
ENTRYPOINT ["/app/4zreark"]
CMD ["-role", "all"]
