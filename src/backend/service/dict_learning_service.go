package service

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
)

// DictLearningConfig 字典自学习配置，存 app_settings（key: dict_learning）。
// 阈值是「多少个不同任务观察到该词后晋升进词表」——任务数而非出现次数，
// 单个任务里被多个引擎重复发现不会虚高。
type DictLearningConfig struct {
	Enabled          bool `json:"enabled"`
	SubdomainMinHits int  `json:"subdomain_min_hits"`
	PathMinHits      int  `json:"path_min_hits"`
}

const dictLearningSettingsKey = "dict_learning"

// DefaultDictLearningConfig 返回默认配置。
func DefaultDictLearningConfig() DictLearningConfig {
	return DictLearningConfig{
		Enabled:          true,
		SubdomainMinHits: 3,
		PathMinHits:      3,
	}
}

// LoadDictLearningConfig 读配置，缺省项回落默认值。
func LoadDictLearningConfig(ctx context.Context) (DictLearningConfig, error) {
	cfg := DefaultDictLearningConfig()
	if repo.Default() == nil {
		return cfg, nil
	}
	stored, err := repo.Default().Settings().Get(ctx, dictLearningSettingsKey, &cfg)
	if err != nil {
		return DefaultDictLearningConfig(), err
	}
	if !stored {
		return DefaultDictLearningConfig(), nil
	}
	return cfg, nil
}

// SaveDictLearningConfig 校验并保存配置。阈值限制在 1..500。
func SaveDictLearningConfig(ctx context.Context, cfg DictLearningConfig) error {
	if cfg.SubdomainMinHits < 1 || cfg.SubdomainMinHits > 500 {
		return fmt.Errorf("子域晋升阈值需在 1-500 之间")
	}
	if cfg.PathMinHits < 1 || cfg.PathMinHits > 500 {
		return fmt.Errorf("路径晋升阈值需在 1-500 之间")
	}
	if repo.Default() == nil {
		return fmt.Errorf("数据层未初始化")
	}
	return repo.Default().Settings().Set(ctx, dictLearningSettingsKey, cfg)
}

// RecordDictObservations 把一个任务观察到的子域首标签与路径批量计频并按阈值晋升。
// 学习开关关闭时静默跳过；失败只记日志——学习是旁路，不能影响任务主流程。
func RecordDictObservations(ctx context.Context, projectID int64, subLabels, paths []string) {
	if repo.Default() == nil {
		return
	}
	cfg, err := LoadDictLearningConfig(ctx)
	if err != nil {
		log.Printf("[DictLearning] 读取配置失败，跳过本批学习: %v", err)
		return
	}
	if !cfg.Enabled {
		return
	}
	lr := repo.Default().DictLearning()
	if len(subLabels) > 0 {
		if n, err := lr.RecordBatch(ctx, repo.DictKindSubdomain, subLabels, projectID, cfg.SubdomainMinHits); err != nil {
			log.Printf("[DictLearning] 子域热词计频失败: %v", err)
		} else if n > 0 {
			log.Printf("[DictLearning] %d 个子域热词晋升进词表（阈值 %d 个任务）", n, cfg.SubdomainMinHits)
		}
	}
	if len(paths) > 0 {
		if n, err := lr.RecordBatch(ctx, repo.DictKindPath, paths, projectID, cfg.PathMinHits); err != nil {
			log.Printf("[DictLearning] 路径热词计频失败: %v", err)
		} else if n > 0 {
			log.Printf("[DictLearning] %d 个路径热词晋升进词表（阈值 %d 个任务）", n, cfg.PathMinHits)
		}
	}
}

var dictLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// ExtractSubdomainLabel 取子域名相对根域的首段标签（爆破词的位置）。
// a-b.example.com 相对 example.com → "a-b"；多级前缀取最左段；
// host 就是根域或无法剥离时返回空。返回小写。
func ExtractSubdomainLabel(host, rootDomain string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	root := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rootDomain), "."))
	if host == "" || root == "" || host == root {
		return ""
	}
	prefix := strings.TrimSuffix(host, "."+root)
	if prefix == "" || prefix == host { // host 不以根域结尾（跨域数据），保守跳过
		return ""
	}
	// 多级前缀（a.b.example.com）取最左段——爆破与递归枚举拼的都是首标签位置。
	label := strings.SplitN(prefix, ".", 2)[0]
	if !dictLabelRe.MatchString(label) {
		return ""
	}
	return label
}

var (
	dictPathIDRe    = regexp.MustCompile(`^(\d+|[0-9a-fA-F]{16,})$`)
	dictPathUUIDRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	dictPathSFileRe = regexp.MustCompile(`\.[a-zA-Z0-9]{1,8}$`)
	dictPathBadRe   = regexp.MustCompile(`[^a-zA-Z0-9\-_./]`)
)

// ExtractLearnedPath 从 URL 提取可进目录字典的路径：
// 去查询串/锚点；末段像文件（带扩展名）或像 ID（纯数字/长 hex/UUID）就丢掉；
// 最多保留 3 段、总长 120。/api/v1/user/123 → /api/v1/user；/admin → /admin。
func ExtractLearnedPath(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" || u.Path == "/" {
		return ""
	}
	segments := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segments) == 0 {
		return ""
	}
	// 末段像文件或 ID 就丢掉：字典要的是路径，不是具体资源。
	last := segments[len(segments)-1]
	if dictPathSFileRe.MatchString(last) || dictPathIDRe.MatchString(last) || dictPathUUIDRe.MatchString(last) {
		segments = segments[:len(segments)-1]
	}
	if len(segments) == 0 {
		return ""
	}
	if len(segments) > 3 {
		segments = segments[:3]
	}
	for _, seg := range segments {
		if seg == "" || len(seg) > 64 || dictPathBadRe.MatchString(seg) {
			return ""
		}
	}
	p := "/" + strings.Join(segments, "/")
	if len(p) > 120 {
		return ""
	}
	return p
}
