// dbprobe.go 数据库凭据实连探测(只读验证):postgres 走 pgx 标准库连接 +
// 最小只读查询(version/当前用户/库名);redis 走裸 RESP 协议(PING/AUTH/INFO
// server),不引驱动依赖。mysql/mongodb/elasticsearch 暂未支持——返回明确
// 错误而不是假成功。移植自 4zreco internal/dbclient 的验证面(台账/浏览面
// 不在本单范围),协议细节与超时语义对齐。
package creds

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DBProbeInput 一次数据库凭据验证的入参。
type DBProbeInput struct {
	Type     string // postgres | redis(mysql/mongodb/elasticsearch 未支持)
	Host     string
	Port     int // 0 = 默认端口
	Username string
	Password string
	Database string // postgres 可选
	Timeout  time.Duration
}

// DBProbeResult 实连结论:存活性 + 权限面(当前用户/版本/库)。
type DBProbeResult struct {
	Alive    bool   `json:"alive"`
	Authed   bool   `json:"authed"`   // redis: AUTH 结果
	User     string `json:"user"`     // 当前用户(postgres)
	Version  string `json:"version"`  // server 版本
	Database string `json:"database"` // 连接库名
	Detail   string `json:"detail"`   // 人读结论
}

// DefaultDBPort 类型默认端口。
func DefaultDBPort(typ string) int {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "postgres", "postgresql":
		return 5432
	case "redis":
		return 6379
	case "mysql":
		return 3306
	case "mongodb":
		return 27017
	case "elasticsearch":
		return 9200
	}
	return 0
}

// VerifyDB 实连验证。凭据无效/网络不通都返回明确 Detail,不返回假成功。
func VerifyDB(ctx context.Context, in DBProbeInput) (*DBProbeResult, error) {
	typ := strings.ToLower(strings.TrimSpace(in.Type))
	if in.Port <= 0 {
		in.Port = DefaultDBPort(typ)
	}
	timeout := in.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch typ {
	case "postgres", "postgresql":
		return verifyPostgres(ctx, in)
	case "redis":
		return verifyRedis(ctx, in)
	case "mysql", "mongodb", "elasticsearch":
		return nil, fmt.Errorf("%s 实连验证暂未支持(本平台未引入对应驱动);请用 psql/redis-cli 等客户端工具经 Bash 验证", typ)
	default:
		return nil, fmt.Errorf("不支持的数据库类型 %q(postgres/redis)", typ)
	}
}

func verifyPostgres(ctx context.Context, in DBProbeInput) (*DBProbeResult, error) {
	db := in.Database
	if db == "" {
		db = "postgres"
	}
	var auth strings.Builder
	if in.Username != "" {
		fmt.Fprintf(&auth, " user=%s", in.Username)
	}
	if in.Password != "" {
		fmt.Fprintf(&auth, " password=%s", in.Password)
	}
	dsn := fmt.Sprintf("host=%s port=%d%s dbname=%s sslmode=disable connect_timeout=8",
		in.Host, in.Port, auth.String(), db)
	// sql.Open 不建连;Ping 才是真验证。
	handle, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("驱动初始化失败: %w", err)
	}
	defer handle.Close()
	if err := handle.PingContext(ctx); err != nil {
		return &DBProbeResult{Alive: true, Detail: fmt.Sprintf("连接失败(凭据无效或库不存在): %v", err)}, nil
	}
	var user, version string
	_ = handle.QueryRowContext(ctx, `SELECT current_user, current_setting('server_version')`).Scan(&user, &version)
	// 权限面:当前用户对库的权限概览(只读)。
	var canCreate, isSuper bool
	_ = handle.QueryRowContext(ctx, `SELECT rolcreatedb, rolsuper FROM pg_roles WHERE rolname=current_user`).Scan(&canCreate, &isSuper)
	detail := fmt.Sprintf("连接成功:用户 %s@%s/%s,PG %s", user, in.Host, db, version)
	if isSuper {
		detail += ",超级用户(rolsuper)"
	} else if canCreate {
		detail += ",可建库(rolcreatedb)"
	}
	return &DBProbeResult{Alive: true, Authed: true, User: user, Version: version, Database: db, Detail: detail}, nil
}

// verifyRedis 裸 RESP:PING/AUTH/INFO server。
func verifyRedis(ctx context.Context, in DBProbeInput) (*DBProbeResult, error) {
	addr := net.JoinHostPort(in.Host, strconv.Itoa(in.Port))
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return &DBProbeResult{Alive: false, Detail: fmt.Sprintf("端口不通: %v", err)}, nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	send := func(cmd ...string) (string, error) {
		var b strings.Builder
		fmt.Fprintf(&b, "*%d\r\n", len(cmd))
		for _, c := range cmd {
			fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(c), c)
		}
		if _, err := conn.Write([]byte(b.String())); err != nil {
			return "", err
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return "", fmt.Errorf("读取响应失败: %v", err)
		}
		return string(buf[:n]), nil
	}
	// 有密码先 AUTH(用户名空=单密码模式)。没有密码时 authed 必须先为 false:
	// 目标可能启用了 requirepass,此时 PING 返回 -NOAUTH,不能当成认证成功
	// (否则空口令会被写进连接台账并标注"验证成功")。
	authed := false
	if in.Password != "" {
		var authCmd = []string{"AUTH", in.Password}
		if in.Username != "" {
			authCmd = []string{"AUTH", in.Username, in.Password}
		}
		resp, err := send(authCmd...)
		if err != nil {
			return &DBProbeResult{Alive: true, Detail: "协议交互失败: " + err.Error()}, nil
		}
		if !strings.HasPrefix(resp, "+OK") {
			return &DBProbeResult{Alive: true, Authed: false, Detail: "AUTH 失败(密码无效): " + strings.TrimSpace(resp)}, nil
		}
		authed = true
	}
	pong, err := send("PING")
	if err != nil || !strings.HasPrefix(pong, "+PONG") {
		return &DBProbeResult{Alive: true, Authed: false, Detail: "PING 异常: " + strings.TrimSpace(pong)}, nil
	}
	// PING 成功 = 当前凭据(含"无密码")可以执行命令。无密码且能 PING 通,
	// 说明实例是未授权开放的,由调用方决定是否登记,但不应保存空口令凭据。
	authed = true
	info, _ := send("INFO", "server")
	version := ""
	for _, line := range strings.Split(info, "\n") {
		if v := strings.TrimPrefix(strings.TrimSpace(line), "redis_version:"); v != strings.TrimSpace(line) {
			version = v
		}
	}
	return &DBProbeResult{Alive: true, Authed: authed, Version: version,
		Detail: fmt.Sprintf("连接成功:Redis %s @%s%s", version, addr, passwordNote(in.Password))}, nil
}

func passwordNote(pw string) string {
	if pw == "" {
		return "(无密码,未授权访问!)"
	}
	return ""
}
