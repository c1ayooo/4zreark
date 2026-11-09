// Package entityid 统一收集侧与 diff 分析的实体标识。
// 收集侧（站点/接口/组件）与 CommitSentinel（repo@ref）必须复用同一个函数，
// 否则后续关联、回溯、统计会断。
package entityid

import (
	"net/url"
	"strings"
)

// RepoRef 生成仓库实体键：owner/repo@ref。
func RepoRef(repo, ref string) string {
	repo = strings.TrimSpace(strings.ToLower(repo))
	repo = strings.TrimSuffix(repo, ".git")
	ref = strings.TrimSpace(ref)
	if repo == "" {
		return ""
	}
	if ref == "" {
		return repo
	}
	return repo + "@" + ref
}

// HostPort 生成站点实体键：host:port（port 为空时只保留 host）。
func HostPort(host, port string) string {
	h := NormalizeHost(host)
	if h == "" {
		return ""
	}
	port = strings.TrimSpace(port)
	if port == "" {
		return h
	}
	return h + ":" + port
}

// NormalizeHost 去掉协议、路径、用户信息和默认端口，统一小写。
func NormalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			raw = u.Host
		}
	}
	raw = strings.ToLower(raw)
	raw = strings.TrimSuffix(raw, "/")
	switch {
	case strings.HasSuffix(raw, ":80"):
		raw = strings.TrimSuffix(raw, ":80")
	case strings.HasSuffix(raw, ":443"):
		raw = strings.TrimSuffix(raw, ":443")
	}
	return raw
}

// DiffJobKey 是 diff 触发的幂等键：(entity_id, window)。
func DiffJobKey(entityID, window string) string {
	return strings.TrimSpace(entityID) + "|" + strings.TrimSpace(window)
}
