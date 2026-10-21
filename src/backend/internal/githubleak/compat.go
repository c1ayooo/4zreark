package githubleak

import (
	"database/sql"
	"time"
)

// SearchItem 是 GitHub 代码搜索返回的一条候选文件（从 4zreco provider.go 摘取）。
type SearchItem struct {
	Repository    string
	RepoNodeID    string
	Path          string
	BlobSHA       string
	HTMLURL       string
	Fragments     []string
	RepoPushedAt  time.Time
	RepoArchived  bool
	RepoFork      bool
	RepoStars     int
	RepoCreatedAt time.Time
}

// Store 是静默规则的 SQL 存储（原 4zreco store.go 的最小定义）。
type Store struct{ db *sql.DB }

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}
