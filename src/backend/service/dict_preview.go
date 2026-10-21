package service

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// G4：字典两段式导入（预览 15 分钟有效，确认时一次性消费）。
// 词表按 5 万行一段物化到 dict_entries；预览只统计不落库。

const (
	DictPreviewTTL  = 15 * time.Minute
	DictSegmentSize = 50000
)

var ErrDictPreviewExpired = errors.New("字典预览已过期（15 分钟有效），请重新预览")

type DictionaryPreview struct {
	Token      string    `json:"token"`
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	ExpiresAt  time.Time `json:"expires_at"`
	Total      int       `json:"total"`
	Unique     int       `json:"unique"`
	Duplicates int       `json:"duplicates"`
	Segments   int       `json:"segments"`
	Sample     []string  `json:"sample"`
}

type dictPreviewEntry struct {
	name      string
	dictType  string
	values    []string
	expiresAt time.Time
}

type dictPreviewStore struct {
	mu    sync.Mutex
	items map[string]*dictPreviewEntry
}

var dictPreviews = &dictPreviewStore{items: map[string]*dictPreviewEntry{}}

var dictTypes = map[string]bool{
	"subdomain": true, "directory": true, "username": true, "password": true,
	"business": true, "custom": true,
}

func (s *PluginService) PreviewDictionary(name, dictType, text string) (*DictionaryPreview, error) {
	return s.PreviewDictionaryFormatted(name, dictType, text, "text")
}

// PreviewDictionaryFormatted 支持 text / csv / tsv；XLSX 走 PreviewDictionaryXLSX。
func (s *PluginService) PreviewDictionaryFormatted(name, dictType, text, format string) (*DictionaryPreview, error) {
	values, total, dups, sample, err := parseDictionaryValues(text, format)
	if err != nil {
		return nil, err
	}
	return s.finishDictionaryPreview(name, dictType, values, total, dups, sample)
}

// PreviewDictionaryXLSX 解析 XLSX 第一列作为词表；首行表头自动跳过。
func (s *PluginService) PreviewDictionaryXLSX(name, dictType string, data []byte) (*DictionaryPreview, error) {
	rows, err := readXLSXRows(data)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	values := []string{}
	sample := []string{}
	total, dups := 0, 0
	for i, row := range rows {
		if len(row) == 0 {
			continue
		}
		v := strings.TrimSpace(row[0])
		if v == "" {
			continue
		}
		if i == 0 && isDictionaryHeader(v) {
			continue
		}
		total++
		if seen[v] {
			dups++
			continue
		}
		seen[v] = true
		values = append(values, v)
		if len(sample) < 20 {
			sample = append(sample, v)
		}
	}
	return s.finishDictionaryPreview(name, dictType, values, total, dups, sample)
}

func (s *PluginService) finishDictionaryPreview(name, dictType string, values []string, total, dups int, sample []string) (*DictionaryPreview, error) {
	name = strings.TrimSpace(name)
	dictType = strings.ToLower(strings.TrimSpace(dictType))
	if name == "" {
		return nil, errors.New("字典名不能为空")
	}
	if !dictTypes[dictType] {
		return nil, fmt.Errorf("不支持的字典类型 %q", dictType)
	}
	if len(values) == 0 {
		return nil, errors.New("词表为空")
	}

	now := time.Now()
	token := randomToken()
	segments := (len(values) + DictSegmentSize - 1) / DictSegmentSize

	dictPreviews.mu.Lock()
	for k, v := range dictPreviews.items {
		if now.After(v.expiresAt) {
			delete(dictPreviews.items, k)
		}
	}
	dictPreviews.items[token] = &dictPreviewEntry{
		name:      name,
		dictType:  dictType,
		values:    values,
		expiresAt: now.Add(DictPreviewTTL),
	}
	dictPreviews.mu.Unlock()

	return &DictionaryPreview{
		Token: token, Name: name, Type: dictType, ExpiresAt: now.Add(DictPreviewTTL),
		Total: total, Unique: len(values), Duplicates: dups, Segments: segments, Sample: sample,
	}, nil
}

// ImportDictionary 消费预览 token，创建字典并物化词表条目。
func (s *PluginService) ImportDictionary(ctx context.Context, token string) (*models.Dictionary, int64, error) {
	dictPreviews.mu.Lock()
	entry, ok := dictPreviews.items[token]
	if ok {
		delete(dictPreviews.items, token)
	}
	dictPreviews.mu.Unlock()

	if !ok {
		return nil, 0, errors.New("字典预览不存在或已被使用")
	}
	if time.Now().After(entry.expiresAt) {
		return nil, 0, ErrDictPreviewExpired
	}

	store, err := s.dicts()
	if err != nil {
		return nil, 0, err
	}
	dict := &models.Dictionary{
		Name:        entry.name,
		Type:        entry.dictType,
		Description: "preview import",
		LineCount:   len(entry.values),
	}
	inserted, err := store.CreateWithEntries(ctx, dict, DictSegmentSize, entry.values)
	if err != nil {
		if errors.Is(err, repo.ErrDuplicate) {
			return nil, 0, errors.New("同类型同名的字典已存在")
		}
		return nil, 0, err
	}
	return dict, inserted, nil
}

func (s *PluginService) ListDictionaryEntries(ctx context.Context, dictID string, segment, page, pageSize int) ([]string, int64, error) {
	store, err := s.dicts()
	if err != nil {
		return nil, 0, err
	}
	return store.ListEntries(ctx, dictID, segment, page, pageSize)
}

// parseDictionaryValues 把不同格式的词表解析成去重后的值列表。
// CSV/TSV 取第一列；首行是 word/value/domain/name/词 这类表头时跳过。
func parseDictionaryValues(text, format string) (values []string, total, dups int, sample []string, err error) {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "text"
	}
	seen := map[string]bool{}
	values = []string{}
	sample = []string{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		total++
		if seen[v] {
			dups++
			return
		}
		seen[v] = true
		values = append(values, v)
		if len(sample) < 20 {
			sample = append(sample, v)
		}
	}

	switch format {
	case "text", "txt":
		for _, line := range strings.Split(text, "\n") {
			add(line)
		}
	case "csv", "tsv":
		reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(text, "\ufeff")))
		reader.FieldsPerRecord = -1
		reader.LazyQuotes = true
		if format == "tsv" {
			reader.Comma = '\t'
		}
		records, rerr := reader.ReadAll()
		if rerr != nil {
			return nil, 0, 0, nil, fmt.Errorf("解析 %s 失败: %v", strings.ToUpper(format), rerr)
		}
		first := true
		for _, rec := range records {
			if len(rec) == 0 {
				continue
			}
			v := strings.TrimSpace(rec[0])
			if first {
				first = false
				if isDictionaryHeader(v) {
					continue
				}
			}
			add(v)
		}
	case "xlsx", "xls":
		return nil, 0, 0, nil, errors.New("XLSX 暂未支持，请另存为 CSV 或 TXT 后再导入")
	default:
		return nil, 0, 0, nil, fmt.Errorf("不支持的词表格式 %q（支持 text/csv/tsv）", format)
	}
	return values, total, dups, sample, nil
}

func isDictionaryHeader(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "word", "words", "value", "values", "domain", "domains", "subdomain", "subdomains",
		"name", "username", "password", "path", "paths", "词", "字典", "域名", "子域名", "路径":
		return true
	}
	return false
}
