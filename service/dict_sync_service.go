package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// DictSyncService 内置词表自动同步：把仓库内置（embed）与磁盘 config/dicts/txt
// 的词表按文件名归类为 subdomain / directory 字典，落进 dictionaries/dict_entries，
// 字典页与目录扫描/种子展开即可直接使用。
//
// 节奏：启动后 90 秒首跑，之后每日一次。内容以 sha 指纹判断变化，没变化的
// 词表只跳过条目重写；磁盘文件现场覆盖 embed 后同样会被同步进来。
type DictSyncService struct {
	stopOnce sync.Once
	stopCh   chan struct{}
}

var (
	dictSyncOnce sync.Once
	dictSyncSvc  *DictSyncService
)

func GetDictSyncService() *DictSyncService {
	dictSyncOnce.Do(func() {
		dictSyncSvc = &DictSyncService{stopCh: make(chan struct{})}
	})
	return dictSyncSvc
}

// Start 启动同步循环（仅 master；worker 无库，词表走 embed 直接读文件）。
func (s *DictSyncService) Start() {
	go func() {
		select {
		case <-time.After(90 * time.Second):
		case <-s.stopCh:
			return
		}
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			_, err := s.Sync(ctx)
			cancel()
			if err != nil {
				log.Printf("[DictSync] 同步失败: %v", err)
			}
			select {
			case <-s.stopCh:
				return
			case <-time.After(24 * time.Hour):
			}
		}
	}()
}

func (s *DictSyncService) Stop() {
	s.stopOnce.Do(func() { close(s.stopCh) })
}

// DictSyncSummary 一次同步的回执。
type DictSyncSummary struct {
	Files    int `json:"files"`
	Inserted int `json:"inserted"`
	Rewrote  int `json:"rewrote"`
}

// Sync 执行一次同步。
func (s *DictSyncService) Sync(ctx context.Context) (*DictSyncSummary, error) {
	files := s.enumerate()
	summary := &DictSyncSummary{Files: len(files)}
	if len(files) == 0 {
		return summary, nil
	}
	store := repo.Default().Dictionaries()
	for _, f := range files {
		if skippedDictFiles()[f] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return summary, err
		}
		content, err := config.ReadDictFile(filepath.Join(config.GetDictBasePath(), "txt", f))
		if err != nil {
			log.Printf("[DictSync] 读取 %s 失败: %v", f, err)
			continue
		}
		values := parseDictValues(string(content))
		if len(values) == 0 {
			continue
		}
		sum := sha256.Sum256(content)
		marker := fmt.Sprintf("builtin:%s@%s", f, hex.EncodeToString(sum[:])[:12])

		stem := strings.TrimSuffix(f, ".txt")
		d := &models.Dictionary{
			Name:        stem,
			Type:        builtinDictType(stem),
			Description: "内置词表（自动同步，磁盘 config/dicts/txt 可覆盖）",
			LineCount:   len(values),
		}
		inserted, rew, err := store.UpsertBuiltin(ctx, d, marker, 50000, values)
		if err != nil {
			log.Printf("[DictSync] 同步 %s 失败: %v", f, err)
			continue
		}
		summary.Inserted += int(inserted)
		if rew {
			summary.Rewrote++
			log.Printf("[DictSync] %s (%s): %d 条已入库", stem, d.Type, len(values))
		}
	}
	log.Printf("[DictSync] 完成: %d 个文件, 重写 %d 个词表, 新增 %d 条", summary.Files, summary.Rewrote, summary.Inserted)
	return summary, nil
}

// enumerate 合并 embed 与磁盘 config/dicts/txt 的 .txt 文件名（去重排序）。
func (s *DictSyncService) enumerate() []string {
	seen := map[string]bool{}
	if sub, err := fs.Sub(config.EmbeddedDicts(), "dicts/txt"); err == nil {
		if entries, err := fs.ReadDir(sub, "."); err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
					seen[e.Name()] = true
				}
			}
		}
	}
	if entries, err := os.ReadDir(filepath.Join(config.GetDictBasePath(), "txt")); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
				seen[e.Name()] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// skippedDictFiles 不进字典库的内置文件：top1000/top5000 是端口扫描用的
// 端口列表（单行逗号分隔），不是词表；yaml 是各扫描器的功能配置。
func skippedDictFiles() map[string]bool {
	return map[string]bool{"top1000.txt": true, "top5000.txt": true}
}

// builtinDictType 按文件名归类：子域类词表进 subdomain，其余按目录字典处理。
func builtinDictType(stem string) string {
	switch stem {
	case "subdomains":
		return "subdomain"
	default:
		return "directory"
	}
}

// parseDictValues 拆词表：去空行与 # 注释行，其余原样保留。
func parseDictValues(content string) []string {
	out := make([]string, 0, 1024)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
