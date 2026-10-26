package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// G4：两段式导入。预览结果只存在内存（单进程部署），15 分钟有效；
// 确认时一次性消费 token，过期或被消费后都不能再次提交。
//
// 预览不写库：只做规范化、批内去重与抽样，真正的归并/事件写在 Commit 时
// 由 AssetRepo.ImportRecords 完成（沿用 G1 的唯一写入口）。

const (
	ImportPreviewTTL = 15 * time.Minute
	maxPreviewItems  = 5000
)

var ErrImportPreviewExpired = errors.New("导入预览已过期（15 分钟有效），请重新预览")

type ImportPreview struct {
	Token      string           `json:"token"`
	ExpiresAt  time.Time        `json:"expires_at"`
	Total      int              `json:"total"`
	Unique     int              `json:"unique"`
	Duplicates int              `json:"duplicates"`
	Invalid    int              `json:"invalid"`
	Sample     []repo.RawRecord `json:"sample"`
}

type importPreviewEntry struct {
	projectID int64
	source    string
	records   []repo.RawRecord
	expiresAt time.Time
}

type importPreviewStore struct {
	mu    sync.Mutex
	items map[string]*importPreviewEntry
}

var importPreviews = &importPreviewStore{items: map[string]*importPreviewEntry{}}

// importPreviewNow 允许测试注入时钟。
var importPreviewNow = time.Now

func (s *AssetService) PreviewImport(ctx context.Context, projectID int64, source string, records []repo.RawRecord) (*ImportPreview, error) {
	if projectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	if len(records) == 0 || len(records) > maxPreviewItems {
		return nil, fmt.Errorf("records 数量需在 1..%d，收到 %d", maxPreviewItems, len(records))
	}
	if strings.TrimSpace(source) == "" {
		source = "api"
	}

	seen := make(map[string]bool, len(records))
	sample := make([]repo.RawRecord, 0, 20)
	duplicates, invalid := 0, 0
	for _, rec := range records {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rec.Host), "."))
		if host == "" {
			invalid++
			continue
		}
		key := importDedupKey(host, rec.Port, rec.Protocol, rec.Value)
		if seen[key] {
			duplicates++
			continue
		}
		seen[key] = true
		if len(sample) < 20 {
			sample = append(sample, rec)
		}
	}

	now := importPreviewNow()
	token := randomToken()
	importPreviews.mu.Lock()
	// 顺便清理过期项，避免内存里堆 token
	for k, v := range importPreviews.items {
		if now.After(v.expiresAt) {
			delete(importPreviews.items, k)
		}
	}
	importPreviews.items[token] = &importPreviewEntry{
		projectID: projectID,
		source:    source,
		records:   records,
		expiresAt: now.Add(ImportPreviewTTL),
	}
	importPreviews.mu.Unlock()

	return &ImportPreview{
		Token:      token,
		ExpiresAt:  now.Add(ImportPreviewTTL),
		Total:      len(records),
		Unique:     len(seen),
		Duplicates: duplicates,
		Invalid:    invalid,
		Sample:     sample,
	}, nil
}

// CommitImport 消费预览 token 并真正导入。
func (s *AssetService) CommitImport(ctx context.Context, token string) (*repo.ImportResult, error) {
	importPreviews.mu.Lock()
	entry, ok := importPreviews.items[token]
	if ok {
		delete(importPreviews.items, token) // 一次性消费，成功失败都不复用
	}
	importPreviews.mu.Unlock()

	if !ok {
		return nil, errors.New("导入预览不存在或已被使用")
	}
	if importPreviewNow().After(entry.expiresAt) {
		return nil, ErrImportPreviewExpired
	}
	return s.Ingest(ctx, entry.projectID, entry.source, entry.records)
}

func importDedupKey(host string, port int, protocol, value string) string {
	if protocol == "" {
		protocol = "https"
	}
	return fmt.Sprintf("%s|%d|%s|%s", host, port, protocol, strings.TrimSpace(value))
}

func randomToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
