package nucleiruntime

import (
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	SourceOfficial = "official"
	SourceCustom   = "custom"
)

// TemplateMeta 是一条 nuclei 模板的检索元数据。Path 是相对其来源目录的路径。
type TemplateMeta struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	Type        string   `json:"type"`
	Path        string   `json:"path"`
	Source      string   `json:"source"` // official | custom
	Author      string   `json:"author,omitempty"`
	Description string   `json:"description,omitempty"`
}

// Filters 是模板检索的过滤条件；空字段表示不过滤。
type Filters struct {
	Severity []string
	Tags     []string
	Type     string
	Source   string
}

// IndexDir 是一个参与索引的模板目录。官方目录和自定义目录可以同时存在。
type IndexDir struct {
	Path   string
	Source string
}

// ListOptions 是分页列表参数。
type ListOptions struct {
	Query   string
	Filters Filters
	Page    int
	Size    int
}

// Index 是模板目录的内存索引。首次检索时构建，更新/写入后由 Manager 失效重建。
// 自定义模板目录还会在每次检索前做一次轻量变更检测，外部直接放文件也无需重启。
type Index struct {
	dirs []IndexDir

	mu        sync.RWMutex
	built     bool
	items     []TemplateMeta
	byID      map[string]int
	buildErr  error
	lastCheck time.Time
	customSig string
}

// indexRefreshInterval 限制自定义目录变更检测的频率，避免每个请求都走文件系统。
var indexRefreshInterval = 2 * time.Second

// NewIndex 创建单目录索引（兼容旧调用，来源标记为 official）。
func NewIndex(dir string) *Index {
	return NewMultiIndex([]IndexDir{{Path: dir, Source: SourceOfficial}})
}

// NewMultiIndex 创建多目录索引。目录不存在时跳过（自定义目录允许为空）。
func NewMultiIndex(dirs []IndexDir) *Index {
	clean := make([]IndexDir, 0, len(dirs))
	seen := map[string]bool{}
	for _, d := range dirs {
		path := strings.TrimSpace(d.Path)
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		if seen[path] {
			continue
		}
		seen[path] = true
		source := strings.TrimSpace(d.Source)
		if source == "" {
			source = SourceOfficial
		}
		clean = append(clean, IndexDir{Path: path, Source: source})
	}
	return &Index{dirs: clean, byID: map[string]int{}}
}

func (i *Index) Dirs() []IndexDir {
	if i == nil {
		return nil
	}
	return append([]IndexDir(nil), i.dirs...)
}

// Dir 返回第一个目录（官方目录），保留旧调用语义。
func (i *Index) Dir() string {
	if i == nil || len(i.dirs) == 0 {
		return ""
	}
	return i.dirs[0].Path
}

// Refresh 强制重建索引。
func (i *Index) Refresh() error {
	sig := indexDirSignature(i.dirs)
	items, byID, err := buildIndexDirs(i.dirs)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.items, i.byID, i.buildErr = items, byID, err
	i.built = err == nil
	i.customSig = sig
	i.lastCheck = time.Now()
	return err
}

func (i *Index) ensure() error {
	i.refreshCustomIfChanged()
	i.mu.RLock()
	built, err := i.built, i.buildErr
	i.mu.RUnlock()
	if built {
		return nil
	}
	if err != nil {
		// 上次构建失败：允许下一次调用重试（模板可能刚更新完）。
		i.mu.Lock()
		i.built, i.buildErr = false, nil
		i.mu.Unlock()
	}
	return i.Refresh()
}

// refreshCustomIfChanged 检测自定义模板目录的变化（新增/删除/改名/内容修改），
// 有变化时重建索引。官方目录由 Manager 的更新流程显式刷新，不在这里扫描。
func (i *Index) refreshCustomIfChanged() {
	if i == nil {
		return
	}
	i.mu.RLock()
	last := i.lastCheck
	i.mu.RUnlock()
	if time.Since(last) < indexRefreshInterval {
		return
	}
	sig := indexDirSignature(i.dirs)
	i.mu.Lock()
	changed := sig != i.customSig
	i.lastCheck = time.Now()
	i.mu.Unlock()
	if changed {
		_ = i.Refresh()
	}
}

// indexDirSignature 为自定义模板目录生成轻量签名：文件路径 + 大小 + mtime。
// 官方目录不参与，因为官方模板只会通过 Manager.Update 变更并显式刷新。
func indexDirSignature(dirs []IndexDir) string {
	h := fnv.New64a()
	for _, d := range dirs {
		if d.Source != SourceCustom {
			continue
		}
		root, err := filepath.Abs(d.Path)
		if err != nil {
			fmt.Fprintf(h, "%s|abs-error\n", d.Path)
			continue
		}
		st, err := os.Stat(root)
		if err != nil || !st.IsDir() {
			fmt.Fprintf(h, "%s|missing\n", root)
			continue
		}
		type fileSig struct {
			path string
			size int64
			mod  int64
		}
		files := []fileSig{}
		_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			files = append(files, fileSig{path: path, size: info.Size(), mod: info.ModTime().UnixNano()})
			return nil
		})
		sort.Slice(files, func(a, b int) bool { return files[a].path < files[b].path })
		fmt.Fprintf(h, "dir:%s\n", root)
		for _, f := range files {
			fmt.Fprintf(h, "%s|%d|%d\n", f.path, f.size, f.mod)
		}
	}
	return fmt.Sprintf("%x", h.Sum64())
}

// Search 返回过滤后的模板元数据（最多 limit 条）和过滤前总数。
func (i *Index) Search(query string, f Filters, limit int) ([]TemplateMeta, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	items, total, err := i.List(ListOptions{Query: query, Filters: f, Page: 1, Size: limit})
	return items, total, err
}

// List 返回分页后的模板元数据。
func (i *Index) List(opts ListOptions) ([]TemplateMeta, int, error) {
	if err := i.ensure(); err != nil {
		return nil, 0, err
	}
	page, size := opts.Page, opts.Size
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}
	i.mu.RLock()
	filtered := filterTemplateItems(i.items, opts.Query, opts.Filters)
	i.mu.RUnlock()
	total := len(filtered)
	start := (page - 1) * size
	if start >= total {
		return []TemplateMeta{}, total, nil
	}
	end := start + size
	if end > total {
		end = total
	}
	return filtered[start:end], total, nil
}

// Get 按 ID 查一条模板元数据（ID 大小写不敏感）。
func (i *Index) Get(id string) (TemplateMeta, bool) {
	if i == nil {
		return TemplateMeta{}, false
	}
	if err := i.ensure(); err != nil {
		return TemplateMeta{}, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	idx, ok := i.byID[strings.ToLower(strings.TrimSpace(id))]
	if !ok {
		return TemplateMeta{}, false
	}
	return i.items[idx], true
}

// Read 返回模板元数据和 YAML 原文。
func (i *Index) Read(id string) (TemplateMeta, string, error) {
	meta, ok := i.Get(id)
	if !ok {
		return TemplateMeta{}, "", fmt.Errorf("模板 ID 未找到: %s", id)
	}
	base := i.baseDir(meta.Source)
	if base == "" {
		return TemplateMeta{}, "", fmt.Errorf("模板来源目录未找到: %s", meta.Source)
	}
	b, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(meta.Path)))
	if err != nil {
		return TemplateMeta{}, "", fmt.Errorf("读取模板失败: %w", err)
	}
	return meta, string(b), nil
}

// Resolve 把模板 ID / 相对路径解析成绝对路径。
// 绝对路径、越界路径和不存在文件一律拒绝，防止扫描任意本地 YAML。
// 路径可带 official/ 或 custom/ 前缀指定来源；不带前缀时优先自定义目录。
func (i *Index) Resolve(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if err := i.ensure(); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		source := ""
		for _, candidate := range []string{SourceCustom, SourceOfficial} {
			prefix := candidate + "/"
			if strings.HasPrefix(name, prefix) {
				source = candidate
				name = strings.TrimPrefix(name, prefix)
				break
			}
		}
		var abs string
		if looksLikePath(name) {
			var err error
			abs, err = i.resolvePath(name, source)
			if err != nil {
				return nil, err
			}
		} else {
			i.mu.RLock()
			idx, ok := i.byID[strings.ToLower(name)]
			var meta TemplateMeta
			if ok {
				meta = i.items[idx]
			}
			i.mu.RUnlock()
			if !ok {
				return nil, fmt.Errorf("模板 ID 未找到: %s（先用 nuclei_template_search 检索）", name)
			}
			if source != "" && meta.Source != source {
				return nil, fmt.Errorf("模板 %s 不属于 %s 目录", name, source)
			}
			base := i.baseDir(meta.Source)
			if base == "" {
				return nil, fmt.Errorf("模板来源目录未找到: %s", meta.Source)
			}
			abs = filepath.Join(base, filepath.FromSlash(meta.Path))
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out, nil
}

func looksLikePath(name string) bool {
	return strings.ContainsAny(name, `/\`) ||
		strings.HasSuffix(strings.ToLower(name), ".yaml") ||
		strings.HasSuffix(strings.ToLower(name), ".yml")
}

func (i *Index) resolvePath(name, source string) (string, error) {
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("模板路径必须是模板目录内的相对路径: %s", name)
	}
	clean := filepath.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("模板路径不能越出模板目录: %s", name)
	}
	bases := make([]string, 0, len(i.dirs))
	if source != "" {
		if base := i.baseDir(source); base != "" {
			bases = append(bases, base)
		}
	} else {
		// 不带来源前缀时优先自定义目录（用户新建的模板通常想覆盖同名路径）。
		for _, want := range []string{SourceCustom, SourceOfficial} {
			if base := i.baseDir(want); base != "" {
				bases = append(bases, base)
			}
		}
	}
	for _, base := range bases {
		root, err := filepath.Abs(base)
		if err != nil {
			continue
		}
		abs := filepath.Join(root, clean)
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		fi, err := os.Stat(abs)
		if err == nil && fi.Mode().IsRegular() {
			return abs, nil
		}
	}
	if source != "" {
		return "", fmt.Errorf("模板文件不存在于 %s 目录: %s", source, name)
	}
	return "", fmt.Errorf("模板文件不存在: %s", name)
}

func (i *Index) baseDir(source string) string {
	for _, d := range i.dirs {
		if d.Source == source {
			return d.Path
		}
	}
	return ""
}

func (i *Index) Count() int {
	if err := i.ensure(); err != nil {
		return 0
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.items)
}

func filterTemplateItems(items []TemplateMeta, query string, f Filters) []TemplateMeta {
	terms := strings.Fields(strings.ToLower(strings.TrimSpace(query)))
	severity := lowerSet(f.Severity)
	tags := lowerSet(f.Tags)
	typ := strings.ToLower(strings.TrimSpace(f.Type))
	source := strings.ToLower(strings.TrimSpace(f.Source))
	out := make([]TemplateMeta, 0, len(items))
	for _, t := range items {
		if len(severity) > 0 && !severity[strings.ToLower(t.Severity)] {
			continue
		}
		if typ != "" && strings.ToLower(t.Type) != typ {
			continue
		}
		if source != "" && strings.ToLower(t.Source) != source {
			continue
		}
		if len(tags) > 0 && !hasAnyLower(t.Tags, tags) {
			continue
		}
		if len(terms) > 0 {
			hay := strings.ToLower(t.ID + "\n" + t.Name + "\n" + strings.Join(t.Tags, " ") +
				"\n" + strings.Join(t.CVE, " ") + "\n" + t.Description)
			ok := true
			for _, term := range terms {
				if !strings.Contains(hay, term) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, t)
	}
	sort.SliceStable(out, func(a, b int) bool {
		ra, rb := severityRank(out[a].Severity), severityRank(out[b].Severity)
		if ra != rb {
			return ra > rb
		}
		return out[a].ID < out[b].ID
	})
	return out
}

func buildIndexDirs(dirs []IndexDir) ([]TemplateMeta, map[string]int, error) {
	var items []TemplateMeta
	for _, d := range dirs {
		root, err := filepath.Abs(d.Path)
		if err != nil {
			continue
		}
		fi, err := os.Stat(root)
		if err != nil || !fi.IsDir() {
			continue // 自定义目录允许尚不存在
		}
		err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil // 单个目录/文件读不了不阻断整体索引
			}
			if entry.IsDir() {
				return nil
			}
			// WalkDir 不跟随目录符号链接；文件符号链接也跳过，避免索引到模板目录外。
			if entry.Type()&os.ModeSymlink != 0 {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(entry.Name()))
			if ext != ".yaml" && ext != ".yml" {
				return nil
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 1<<20 {
				return nil
			}
			meta, ok := parseTemplateFile(path)
			if !ok {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return nil
			}
			meta.Path = filepath.ToSlash(rel)
			meta.Source = d.Source
			items = append(items, meta)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	if len(items) == 0 {
		return nil, nil, fmt.Errorf("模板目录内没有可用模板")
	}
	sort.Slice(items, func(a, b int) bool { return items[a].ID < items[b].ID })
	byID := make(map[string]int, len(items))
	for idx, item := range items {
		key := strings.ToLower(item.ID)
		if existing, exists := byID[key]; exists {
			// 同 ID 冲突时自定义模板优先，便于本地覆盖。
			if item.Source == SourceCustom && items[existing].Source != SourceCustom {
				byID[key] = idx
			}
			continue
		}
		byID[key] = idx
	}
	return items, byID, nil
}

type templateDoc struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string     `yaml:"name"`
		Author         string     `yaml:"author"`
		Severity       string     `yaml:"severity"`
		Description    string     `yaml:"description"`
		Tags           stringList `yaml:"tags"`
		Classification struct {
			CVEID stringList `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
	HTTP       any `yaml:"http"`
	DNS        any `yaml:"dns"`
	TCP        any `yaml:"tcp"`
	File       any `yaml:"file"`
	Headless   any `yaml:"headless"`
	Code       any `yaml:"code"`
	JavaScript any `yaml:"javascript"`
	SSL        any `yaml:"ssl"`
	Websocket  any `yaml:"websocket"`
	Whois      any `yaml:"whois"`
	Workflows  any `yaml:"workflows"`
}

// ParseTemplateYAML 解析并校验一段自定义模板 YAML。
func ParseTemplateYAML(b []byte) (TemplateMeta, error) {
	if len(b) == 0 {
		return TemplateMeta{}, fmt.Errorf("模板内容为空")
	}
	if len(b) > 1<<20 {
		return TemplateMeta{}, fmt.Errorf("模板超过 1MB 上限")
	}
	var doc templateDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return TemplateMeta{}, fmt.Errorf("YAML 解析失败: %w", err)
	}
	id := strings.TrimSpace(doc.ID)
	name := strings.TrimSpace(doc.Info.Name)
	if id == "" {
		return TemplateMeta{}, fmt.Errorf("模板缺少 id")
	}
	if name == "" {
		return TemplateMeta{}, fmt.Errorf("模板缺少 info.name")
	}
	if !validTemplateID(id) {
		return TemplateMeta{}, fmt.Errorf("模板 id 只能包含字母、数字、点、下划线和短横线: %s", id)
	}
	typ := templateType(doc)
	if typ == "unknown" {
		return TemplateMeta{}, fmt.Errorf("模板缺少协议段（http/dns/tcp/file/headless/code/javascript/ssl/websocket/whois/workflows）")
	}
	severity := strings.ToLower(strings.TrimSpace(doc.Info.Severity))
	if severity == "" {
		severity = "unknown"
	}
	return TemplateMeta{
		ID:          id,
		Name:        name,
		Severity:    severity,
		Tags:        doc.Info.Tags,
		CVE:         doc.Info.Classification.CVEID,
		Type:        typ,
		Author:      strings.TrimSpace(doc.Info.Author),
		Description: strings.TrimSpace(doc.Info.Description),
	}, nil
}

func validTemplateID(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func parseTemplateFile(path string) (TemplateMeta, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return TemplateMeta{}, false
	}
	meta, err := ParseTemplateYAML(b)
	if err != nil {
		return TemplateMeta{}, false
	}
	return meta, true
}

func templateType(d templateDoc) string {
	switch {
	case d.HTTP != nil:
		return "http"
	case d.DNS != nil:
		return "dns"
	case d.TCP != nil:
		return "tcp"
	case d.File != nil:
		return "file"
	case d.Headless != nil:
		return "headless"
	case d.Code != nil:
		return "code"
	case d.JavaScript != nil:
		return "javascript"
	case d.SSL != nil:
		return "ssl"
	case d.Websocket != nil:
		return "websocket"
	case d.Whois != nil:
		return "whois"
	case d.Workflows != nil:
		return "workflow"
	default:
		return "unknown"
	}
}

// stringList 兼容 nuclei 模板里常见的两种写法：
//
//	tags: cve,rce
//	tags: [cve, rce]
//
// cve-id 同样有字符串和数组两种形态。
type stringList []string

func (s *stringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var raw string
		if err := value.Decode(&raw); err != nil {
			return err
		}
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				*s = append(*s, p)
			}
		}
	case yaml.SequenceNode:
		for _, node := range value.Content {
			var raw string
			if err := node.Decode(&raw); err == nil {
				if raw = strings.TrimSpace(raw); raw != "" {
					*s = append(*s, raw)
				}
			}
		}
	}
	return nil
}

func lowerSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, v := range in {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			out[v] = true
		}
	}
	return out
}

func hasAnyLower(have []string, want map[string]bool) bool {
	for _, v := range have {
		if want[strings.ToLower(strings.TrimSpace(v))] {
			return true
		}
	}
	return false
}

func severityRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// hasTemplates 快速判断模板目录里是否至少有一个 YAML；不解析内容。
func hasTemplates(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	found := false
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return nil
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yaml" || ext == ".yml" {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

func countTemplateFiles(dir string) int {
	if strings.TrimSpace(dir) == "" {
		return 0
	}
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext == ".yaml" || ext == ".yml" {
			n++
		}
		return nil
	})
	return n
}
