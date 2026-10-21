package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// ResultService 负责扫描结果的写入、查询与标签维护。
// 数据全部走 repo.ResultRepo，本文件不出现任何 SQL 或驱动调用。
type ResultService struct{}

func NewResultService() *ResultService { return &ResultService{} }

func (s *ResultService) store() (repo.ResultRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r.Results(), nil
}

// normalizeServiceURL 标准化 URL，移除默认端口（用于 Service 去重）
func normalizeServiceURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	// 移除 :443 (HTTPS 默认端口)
	if len(rawURL) > 4 {
		rawURL = strings.Replace(rawURL, ":443/", "/", 1)
		if strings.HasSuffix(rawURL, ":443") {
			rawURL = rawURL[:len(rawURL)-4]
		}
	}

	// 移除 :80 (HTTP 默认端口)
	if len(rawURL) > 3 {
		rawURL = strings.Replace(rawURL, ":80/", "/", 1)
		if strings.HasSuffix(rawURL, ":80") {
			rawURL = rawURL[:len(rawURL)-3]
		}
	}

	return rawURL
}

// extractHostFromURL 从 URL 中提取 host（用于 Web 服务按 host 去重）
func extractHostFromURL(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	// 移除协议前缀
	host := rawURL
	if strings.HasPrefix(host, "https://") {
		host = host[8:]
	} else if strings.HasPrefix(host, "http://") {
		host = host[7:]
	}

	// 移除路径
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// 移除默认端口
	if strings.HasSuffix(host, ":443") {
		host = host[:len(host)-4]
	} else if strings.HasSuffix(host, ":80") {
		host = host[:len(host)-3]
	}

	return host
}

// applyDedupKey 按类型推导跨月去重键，并顺带补齐去重用的派生字段。
// 这套规则逐条对应改造前的 Mongo 过滤条件，唯一差别是：
// 改造前业务键为空时会退化成「同任务同类型只留一条」，这里改为按 data 摘要，
// 避免 takeover / monitor 这类没有业务键的结果被互相覆盖。
func applyDedupKey(res *models.ScanResult) {
	if res.Data == nil {
		res.Data = map[string]interface{}{}
	}
	taskID := res.TaskID.Hex()
	data := res.Data

	getString := func(key string) string {
		if v, ok := data[key].(string); ok {
			return v
		}
		return ""
	}

	var parts []string
	switch res.Type {
	case models.ResultTypeSubdomain:
		parts = []string{getString("subdomain")}
	case models.ResultTypePort:
		ip := getString("ip")
		port := ""
		if v, ok := data["port"]; ok {
			port = fmt.Sprintf("%v", v)
		}
		parts = []string{ip, port}
	case models.ResultTypeService:
		// Web 服务按 host 去重（同一 host 的 http / https 只保留一条）
		if rawURL := getString("url"); rawURL != "" {
			host := extractHostFromURL(rawURL)
			data["dedup_host"] = host
			data["normalized_url"] = normalizeServiceURL(rawURL)
			parts = []string{host}
		}
	case models.ResultTypeURL, models.ResultTypeCrawler, models.ResultTypeDirScan:
		if rawURL := getString("url"); rawURL != "" {
			normalized := normalizeServiceURL(rawURL)
			data["normalized_url"] = normalized
			parts = []string{normalized}
		}
	case models.ResultTypeVuln:
		parts = []string{getString("vuln_id"), getString("target")}
	case models.ResultTypeSensitive:
		parts = []string{getString("url"), getString("type")}
	}

	// 业务键不完整（含上面没覆盖的类型）→ 用 data 摘要兜底
	usable := len(parts) > 0
	for _, p := range parts {
		if p == "" {
			usable = false
			break
		}
	}
	if !usable {
		res.DedupKey = repo.BuildDedupKeyFromData(taskID, res.Type, data)
		return
	}
	res.DedupKey = repo.BuildDedupKey(taskID, res.Type, parts...)
}

// CreateResult 创建扫描结果（不做去重判断，但同样登记去重键，
// 便于后续 CreateResultWithDedup 认出这条已存在的记录）
func (s *ResultService) CreateResult(result *models.ScanResult) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	applyDedupKey(result)

	ctx, cancel := dbCtx()
	defer cancel()
	return store.Create(ctx, result)
}

// CreateResultWithDedup 创建扫描结果（按类型去重）
func (s *ResultService) CreateResultWithDedup(result *models.ScanResult) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	applyDedupKey(result)

	ctx, cancel := dbCtx()
	defer cancel()
	_, err = store.CreateWithDedup(ctx, result)
	return err
}

// BatchCreateResults 批量创建扫描结果
func (s *ResultService) BatchCreateResults(results []models.ScanResult) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	for i := range results {
		applyDedupKey(&results[i])
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.BatchCreate(ctx, results)
}

// BatchCreateResultsWithDedup 批量创建扫描结果（带去重）
// 返回 (新增, 更新) 条数；整批在一个事务里完成。
func (s *ResultService) BatchCreateResultsWithDedup(results []models.ScanResult) (int, int, error) {
	ptrs := make([]*models.ScanResult, 0, len(results))
	for i := range results {
		ptrs = append(ptrs, &results[i])
	}
	return s.BatchCreateResultPtrsWithDedup(ptrs)
}

// BatchCreateResultPtrsWithDedup 是指针版本，供 worker 回传直接复用。
func (s *ResultService) BatchCreateResultPtrsWithDedup(results []*models.ScanResult) (int, int, error) {
	store, err := s.store()
	if err != nil {
		return 0, 0, err
	}
	for _, res := range results {
		if res != nil {
			applyDedupKey(res)
		}
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.BatchCreateWithDedup(ctx, results)
}

// GetResultsByTask 获取任务的扫描结果
func (s *ResultService) GetResultsByTask(taskID string, resultType models.ResultType, page, pageSize int, search string, statusCode int) ([]*models.ScanResult, int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	// URL 页签读的是 crawler 记录去重后的派生视图，不是 type='url' 的独立记录。
	if resultType == models.ResultTypeURL {
		return store.ListURLsByTask(ctx, taskID, page, pageSize, search)
	}
	return store.ListByTask(ctx, taskID, string(resultType), page, pageSize, search, statusCode)
}

// GetResultStats 获取任务结果统计（按类型计数）
func (s *ResultService) GetResultStats(taskID string) (map[string]int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.StatsByTask(ctx, taskID)
}

// DeleteResultsByTask 删除任务的所有结果
func (s *ResultService) DeleteResultsByTask(taskID string) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.DeleteByTask(ctx, taskID)
}

// UpdateResultTags 覆盖结果标签
func (s *ResultService) UpdateResultTags(id string, tags []string) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.SetTags(ctx, id, tags)
}

// AddResultTag 添加标签
func (s *ResultService) AddResultTag(id string, tag string) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.AddTag(ctx, id, tag)
}

// RemoveResultTag 移除标签
func (s *ResultService) RemoveResultTag(id string, tag string) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.RemoveTag(ctx, id, tag)
}

// ExportResults 导出结果（不分页）
func (s *ResultService) ExportResults(taskID string, resultType models.ResultType) ([]*models.ScanResult, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.ExportByTask(ctx, taskID, string(resultType))
}

// UpdateSubdomainCDN 更新子域名的 CDN 信息
func (s *ResultService) UpdateSubdomainCDN(taskID string, domain string, cdnProvider string) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.UpdateSubdomainCDN(ctx, taskID, domain, cdnProvider)
}

// BatchDeleteResults 批量删除结果
func (s *ResultService) BatchDeleteResults(ids []string) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.DeleteByIDs(ctx, ids)
}

// GetSubdomainResults 获取子域名结果（联合 service 结果补充 title / status_code / 指纹）
func (s *ResultService) GetSubdomainResults(taskID string, page, pageSize int, search string) ([]map[string]interface{}, int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}

	ctx, cancel := dbCtx()
	serviceMap, err := store.ServiceDataByHost(ctx, taskID)
	cancel()
	if err != nil {
		return nil, 0, err
	}

	ctx, cancel = dbCtx()
	rows, total, err := store.ListSubdomains(ctx, taskID, page, pageSize, search)
	cancel()
	if err != nil {
		return nil, 0, err
	}

	out := make([]map[string]interface{}, 0, len(rows))
	for _, result := range rows {
		item := map[string]interface{}{
			"id":         result.ID.Hex(),
			"task_id":    result.TaskID.Hex(),
			"type":       result.Type,
			"tags":       result.Tags,
			"project":    result.Project,
			"created_at": result.CreatedAt,
		}
		for k, v := range result.Data {
			item[k] = v
		}

		// 优先用 subdomain 字段（完整子域名），因为 service 的 host 也是完整子域名
		domainName := ""
		if v, ok := result.Data["subdomain"].(string); ok && v != "" {
			domainName = v
		} else if v, ok := result.Data["domain"].(string); ok && v != "" {
			domainName = v
		}

		if domainName != "" {
			if info, exists := serviceMap[domainName]; exists {
				if title, ok := info["title"].(string); ok && title != "" {
					item["title"] = title
				}
				if code, ok := asInt(info["status_code"]); ok {
					item["status_code"] = code
				}
				if server, ok := info["server"].(string); ok && server != "" {
					item["web_server"] = server
				}
				if techs := asStringSlice(info["technologies"]); len(techs) > 0 {
					item["fingerprint"] = techs
					item["technologies"] = techs
				}
				if fps := asStringSlice(info["fingerprints"]); len(fps) > 0 {
					if item["fingerprint"] == nil {
						item["fingerprint"] = fps
					}
				}
				if url, ok := info["url"].(string); ok && url != "" {
					item["url"] = url
				}
			}
		}

		out = append(out, item)
	}
	return out, total, nil
}

// GetPortResultsAggregated 获取聚合后的端口结果（按 IP 聚合，合并端口）
func (s *ResultService) GetPortResultsAggregated(taskID string, page, pageSize int, search string) ([]map[string]interface{}, int64, error) {
	store, err := s.store()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	groups, total, err := store.AggregatePorts(ctx, taskID, page, pageSize, search)
	if err != nil {
		return nil, 0, err
	}

	out := make([]map[string]interface{}, 0, len(groups))
	for _, g := range groups {
		ports := g.Ports
		if ports == nil {
			ports = []string{}
		}
		services := g.Services
		if services == nil {
			services = []string{}
		}
		out = append(out, map[string]interface{}{
			"ip":         g.IP,
			"host":       g.Host,
			"ports":      ports,
			"port_count": len(ports),
			"services":   services,
			"created_at": g.CreatedAt,
		})
	}
	return out, total, nil
}

// asInt 兼容 jsonb 解出来的各种整数形态。
func asInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}

// asStringSlice 兼容 []interface{} 与 []string 两种形态。
func asStringSlice(v interface{}) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}
