package service

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/repo"
)

// 本地文档导入（HAR / JSON / CSV / TXT）：只解析文本，不重放请求、不执行页面 JS。
// 提取出的 host 走既有 Ingest 入库；APP/公众号等名称走 digital_assets，两者解耦。
// XLSX 暂未引入解析依赖，提示用户另存为 CSV。

const (
	MaxLocalDocBytes = 4 << 20
	LocalDocTTL      = 15 * time.Minute
	maxLocalDocItems = 5000
)

var (
	ErrLocalDocPreviewExpired = errors.New("文档预览已过期（15 分钟有效），请重新上传")
	ErrLocalDocTooLarge       = errors.New("文档超过 4 MiB 上限")
)

type LocalDocPreview struct {
	Token       string                   `json:"token"`
	ExpiresAt   time.Time                `json:"expires_at"`
	ProjectID   int64                    `json:"project_id"`
	Filename    string                   `json:"filename"`
	Format      string                   `json:"format"`
	Total       int                      `json:"total"`
	Hosts       int                      `json:"hosts"`
	Names       int                      `json:"names"`
	Duplicates  int                      `json:"duplicates"`
	Invalid     int                      `json:"invalid"`
	SampleHosts []string                 `json:"sample_hosts"`
	SampleNames []repo.DigitalAssetInput `json:"sample_names"`
}

type localDocEntry struct {
	projectID int64
	filename  string
	format    string
	hosts     []repo.RawRecord
	assets    []repo.DigitalAssetInput
	expiresAt time.Time
}

type localDocStore struct {
	mu    sync.Mutex
	items map[string]*localDocEntry
}

var localDocs = &localDocStore{items: map[string]*localDocEntry{}}
var localDocNow = time.Now

type LocalDocCommit struct {
	Batch    *repo.ImportBatch  `json:"batch"`
	Inserted int64              `json:"inserted"`
	Hosts    *repo.ImportResult `json:"hosts"`
}

// LocalDocService 提供本地文档的两段式导入。
type LocalDocService struct {
	assets *AssetService
}

func NewLocalDocService() *LocalDocService {
	return &LocalDocService{assets: NewAssetService()}
}

// Preview 解析文档并缓存候选，15 分钟内可确认一次。
func (s *LocalDocService) Preview(ctx context.Context, projectID int64, filename string, data []byte) (*LocalDocPreview, error) {
	if projectID <= 0 {
		return nil, errors.New("project_id 必填")
	}
	if len(data) == 0 {
		return nil, errors.New("文件为空")
	}
	if len(data) > MaxLocalDocBytes {
		return nil, ErrLocalDocTooLarge
	}
	format := strings.TrimPrefix(strings.ToLower(filepath.Ext(filename)), ".")
	switch format {
	case "har", "json", "csv", "txt", "xlsx":
	case "xls":
		return nil, errors.New("旧版 .xls 暂不支持，请另存为 .xlsx 或 CSV 后再导入")
	default:
		return nil, fmt.Errorf("不支持的文件类型 %q（支持 har/json/csv/txt/xlsx）", format)
	}

	acc := &localDocAcc{
		hostSeen: map[string]bool{},
		nameSeen: map[string]bool{},
	}
	switch format {
	case "har":
		if err := parseHAR(data, acc); err != nil {
			return nil, fmt.Errorf("HAR 解析失败: %w", err)
		}
	case "json":
		if err := parseJSONDoc(data, acc); err != nil {
			return nil, fmt.Errorf("JSON 解析失败: %w", err)
		}
	case "csv":
		if err := parseCSVDoc(data, acc); err != nil {
			return nil, fmt.Errorf("CSV 解析失败: %w", err)
		}
	case "xlsx":
		rows, err := readXLSXRows(data)
		if err != nil {
			return nil, fmt.Errorf("XLSX 解析失败: %w", err)
		}
		applyTabularRows(rows, acc)
	default:
		parseTextDoc(data, acc)
	}

	if len(acc.hosts) == 0 && len(acc.assets) == 0 {
		return nil, errors.New("没有解析出可导入的 host 或名称")
	}

	now := localDocNow()
	token := randomToken()
	localDocs.mu.Lock()
	for k, v := range localDocs.items {
		if now.After(v.expiresAt) {
			delete(localDocs.items, k)
		}
	}
	localDocs.items[token] = &localDocEntry{
		projectID: projectID, filename: filename, format: format,
		hosts: acc.hosts, assets: acc.assets,
		expiresAt: now.Add(LocalDocTTL),
	}
	localDocs.mu.Unlock()

	sampleHosts := make([]string, 0, 20)
	for i, h := range acc.hosts {
		if i >= 20 {
			break
		}
		sampleHosts = append(sampleHosts, h.Host)
	}
	sampleNames := make([]repo.DigitalAssetInput, 0, 20)
	for i, a := range acc.assets {
		if i >= 20 {
			break
		}
		sampleNames = append(sampleNames, a)
	}

	return &LocalDocPreview{
		Token: token, ExpiresAt: now.Add(LocalDocTTL),
		ProjectID: projectID, Filename: filename, Format: format,
		Total: len(acc.hosts) + len(acc.assets),
		Hosts: len(acc.hosts), Names: len(acc.assets),
		Duplicates: acc.duplicates, Invalid: acc.invalid,
		SampleHosts: sampleHosts, SampleNames: sampleNames,
	}, nil
}

// Commit 消费 token：host 走资产唯一写入口，名称写入 digital_assets 并生成回执。
func (s *LocalDocService) Commit(ctx context.Context, token, createdBy string) (*LocalDocCommit, error) {
	localDocs.mu.Lock()
	entry, ok := localDocs.items[token]
	if ok {
		delete(localDocs.items, token)
	}
	localDocs.mu.Unlock()
	if !ok {
		return nil, errors.New("文档预览不存在或已被使用")
	}
	if localDocNow().After(entry.expiresAt) {
		return nil, ErrLocalDocPreviewExpired
	}

	out := &LocalDocCommit{}
	if len(entry.assets) > 0 {
		dr := repo.Default()
		if dr == nil {
			return nil, errors.New("数据层未初始化")
		}
		batch, inserted, err := dr.Digital().InsertBatch(ctx, entry.projectID, "local_doc", entry.assets,
			map[string]any{"source": entry.filename, "format": entry.format}, createdBy)
		if err != nil {
			return nil, err
		}
		out.Batch, out.Inserted = batch, inserted
	}
	if len(entry.hosts) > 0 {
		res, err := s.assets.Ingest(ctx, entry.projectID, "local_doc", entry.hosts)
		if err != nil {
			return out, err
		}
		out.Hosts = res
	}
	return out, nil
}

func CancelLocalDocPreview(token string) bool {
	localDocs.mu.Lock()
	defer localDocs.mu.Unlock()
	if _, ok := localDocs.items[token]; ok {
		delete(localDocs.items, token)
		return true
	}
	return false
}

// ---- 解析 ----

type localDocAcc struct {
	hosts      []repo.RawRecord
	assets     []repo.DigitalAssetInput
	hostSeen   map[string]bool
	nameSeen   map[string]bool
	duplicates int
	invalid    int
}

func (a *localDocAcc) addHost(raw string) {
	host, port, scheme, value, ok := normalizeHostInput(raw)
	if !ok {
		a.invalid++
		return
	}
	key := fmt.Sprintf("%s|%d|%s", host, port, scheme)
	if a.hostSeen[key] {
		a.duplicates++
		return
	}
	if len(a.hosts) >= maxLocalDocItems {
		a.invalid++
		return
	}
	a.hostSeen[key] = true
	a.hosts = append(a.hosts, repo.RawRecord{
		Source: "local_doc", Host: host, Port: port, Protocol: scheme, Value: value,
	})
}

func (a *localDocAcc) addName(kind, name, company, platform, source string) {
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		a.invalid++
		return
	}
	kind = strings.TrimSpace(kind)
	if !digitalKinds[kind] {
		kind = "app"
	}
	key := kind + "|" + strings.ToLower(name)
	if a.nameSeen[key] {
		a.duplicates++
		return
	}
	if len(a.assets) >= maxLocalDocItems {
		a.invalid++
		return
	}
	a.nameSeen[key] = true
	if strings.TrimSpace(source) == "" {
		source = "local_doc"
	}
	a.assets = append(a.assets, repo.DigitalAssetInput{
		Kind: kind, Name: name, Company: company, Platform: platform, Source: source,
	})
}

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				URL string `json:"url"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

func parseHAR(data []byte, acc *localDocAcc) error {
	var h harFile
	if err := json.Unmarshal(data, &h); err != nil {
		return err
	}
	for _, e := range h.Log.Entries {
		if strings.TrimSpace(e.Request.URL) != "" {
			acc.addHost(e.Request.URL)
		}
	}
	return nil
}

func parseJSONDoc(data []byte, acc *localDocAcc) error {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return err
	}
	walkJSON(root, acc, 0)
	return nil
}

func walkJSON(v any, acc *localDocAcc, depth int) {
	if depth > 8 {
		return
	}
	switch x := v.(type) {
	case string:
		addLooseValue(x, acc)
	case []any:
		for _, item := range x {
			walkJSON(item, acc, depth+1)
		}
	case map[string]any:
		urlVal := firstString(x, "url", "uri", "link")
		if urlVal != "" {
			acc.addHost(urlVal)
		}
		if hostVal := firstString(x, "host", "hostname", "domain", "domain_name"); hostVal != "" {
			acc.addHost(hostVal)
		}
		name := firstString(x, "name", "app", "app_name", "official_account", "miniapp")
		if name != "" {
			acc.addName(firstString(x, "kind", "type"), name,
				firstString(x, "company", "developer", "owner"),
				firstString(x, "platform", "store"), firstString(x, "source"))
		}
		for _, key := range []string{"assets", "items", "data", "list", "hosts", "names", "entries"} {
			if child, ok := x[key]; ok {
				walkJSON(child, acc, depth+1)
			}
		}
	case float64, bool, nil:
		// 忽略
	default:
		acc.invalid++
	}
}

// applyTabularRows 与 parseCSVDoc 同一套规则，供 XLSX 解析后的二维数组复用。
func applyTabularRows(rows [][]string, acc *localDocAcc) {
	if len(rows) == 0 {
		return
	}
	header := map[string]int{}
	for i, cell := range rows[0] {
		header[strings.ToLower(strings.TrimSpace(cell))] = i
	}
	_, hasName := header["name"]
	_, hasHost := header["host"]
	_, hasURL := header["url"]
	_, hasDomain := header["domain"]
	structured := hasName || hasHost || hasURL || hasDomain
	cell := func(row []string, keys ...string) string {
		for _, k := range keys {
			if idx, ok := header[k]; ok && idx < len(row) {
				if s := strings.TrimSpace(row[idx]); s != "" {
					return s
				}
			}
		}
		return ""
	}
	for i, row := range rows {
		if i == 0 && structured {
			continue
		}
		if structured {
			if h := cell(row, "url", "host", "domain"); h != "" {
				acc.addHost(h)
			}
			if n := cell(row, "name", "app", "app_name"); n != "" {
				acc.addName(cell(row, "kind", "type"), n,
					cell(row, "company", "developer"), cell(row, "platform", "store"),
					cell(row, "source"))
			}
			continue
		}
		for _, c := range row {
			if strings.TrimSpace(c) != "" {
				addLooseValue(c, acc)
				break
			}
		}
	}
}

func parseCSVDoc(data []byte, acc *localDocAcc) error {
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff")))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return err
	}
	applyTabularRows(rows, acc)
	return nil
}

func parseTextDoc(data []byte, acc *localDocAcc) {
	for _, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		addLooseValue(line, acc)
	}
}

// addLooseValue 把单行/单值分为 host 或名称：带 scheme、斜杠或点号且无空格的当 host。
func addLooseValue(v string, acc *localDocAcc) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if strings.Contains(v, "://") {
		acc.addHost(v)
		return
	}
	if !strings.ContainsAny(v, " \t") && strings.Contains(v, ".") {
		acc.addHost(v)
		return
	}
	acc.addName("app", v, "", "", "local_doc")
}

// normalizeHostInput 返回 host/port/scheme/value；裸域名默认 https:443。
func normalizeHostInput(raw string) (host string, port int, scheme, value string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, "", "", false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return "", 0, "", "", false
		}
		scheme = strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", 0, "", "", false
		}
		port = 443
		if scheme == "http" {
			port = 80
		}
		if p := u.Port(); p != "" {
			fmt.Sscanf(p, "%d", &port)
			if port <= 0 || port > 65535 {
				return "", 0, "", "", false
			}
		}
		return strings.ToLower(strings.TrimSuffix(u.Hostname(), ".")), port, scheme, raw, true
	}
	host = strings.ToLower(strings.TrimSuffix(strings.SplitN(raw, "/", 2)[0], "."))
	if host == "" || strings.ContainsAny(host, " \t") {
		return "", 0, "", "", false
	}
	return host, 443, "https", "", true
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
