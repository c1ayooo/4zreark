package service

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/recon/spacemap"
	"github.com/c1ayooo/4zreark/internal/recon/spacemap/certquery"
	"github.com/c1ayooo/4zreark/internal/recon/spacemap/icpquery"
	"github.com/c1ayooo/4zreark/repo"

	"golang.org/x/net/idna"
)

// 种子展开：把 seed(kind,value,capability) 变成可复现的 []TargetInput。
//
// P0 只做静态展开：domain（项目内已归并站点）、cidr（网段切分）、dict（字典拼接）。
// company / repo / app 需要外部数据源，静态模式下明确返回 warning，不静默空跑；
// live 展开在 P1 接入，当前同样只返回未接入提示。
//
// preview 与计划执行共用本文件，保证「预览看到什么，批次就展开什么」。

const (
	SeedMaxTargets        = 5000
	SeedPreviewSampleSize = 200
)

// ErrSeedValidation 表示种子参数不合法，调用方应返回 400。
var ErrSeedValidation = errors.New("种子参数不合法")

func invalidSeed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSeedValidation, fmt.Sprintf(format, args...))
}

var validSeedKinds = map[string]bool{
	"domain": true, "cidr": true, "company": true, "cert": true,
	"repo": true, "app": true, "dict": true,
}

type SeedPreviewRequest struct {
	ProjectID  int64          `json:"project_id"`
	Kind       string         `json:"kind"`
	Value      string         `json:"value"`
	Capability map[string]any `json:"capability"`
	Live       bool           `json:"live"`
}

type SeedExpandResult struct {
	Kind            string             `json:"kind"`
	NormalizedValue string             `json:"normalized_value"`
	Mode            string             `json:"mode"`
	Source          string             `json:"source"`
	Total           int                `json:"total"`
	Shown           int                `json:"shown"`
	Truncated       bool               `json:"truncated"`
	Targets         []repo.TargetInput `json:"targets"`
	Warnings        []string           `json:"warnings"`
	EmptyReason     string             `json:"empty_reason,omitempty"`
}

// PreviewSeed 是 POST /api/seeds/preview 的入口：只展开，不落库、不探测目标。
func (s *CycleService) PreviewSeed(ctx context.Context, req SeedPreviewRequest) (*SeedExpandResult, error) {
	if req.ProjectID <= 0 {
		return nil, invalidSeed("project_id 必填")
	}
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if !validSeedKinds[kind] {
		return nil, invalidSeed("kind 只支持 domain / cidr / company / cert / repo / app / dict")
	}
	if strings.TrimSpace(req.Value) == "" {
		return nil, invalidSeed("种子值必填")
	}
	seed := &repo.Seed{
		ProjectID:  req.ProjectID,
		Kind:       kind,
		Value:      req.Value,
		Capability: req.Capability,
		Enabled:    true,
	}
	return s.ExpandSeed(ctx, seed, req.Live, SeedMaxTargets, SeedPreviewSampleSize)
}

// ExpandSeed 对单个种子做展开。maxTargets 是硬上限，sampleLimit 是返回样本上限。
func (s *CycleService) ExpandSeed(ctx context.Context, seed *repo.Seed, live bool, maxTargets, sampleLimit int) (*SeedExpandResult, error) {
	if seed == nil {
		return nil, invalidSeed("缺少种子")
	}
	if maxTargets <= 0 || maxTargets > SeedMaxTargets {
		maxTargets = SeedMaxTargets
	}
	if sampleLimit <= 0 || sampleLimit > maxTargets {
		sampleLimit = maxTargets
	}

	kind := strings.ToLower(strings.TrimSpace(seed.Kind))
	if !validSeedKinds[kind] {
		return nil, invalidSeed("kind 只支持 domain / cidr / company / cert / repo / app / dict")
	}
	value := strings.TrimSpace(seed.Value)
	if value == "" {
		return nil, invalidSeed("种子值必填")
	}

	mode := "static"
	if live {
		mode = "live"
	}
	result := &SeedExpandResult{
		Kind:     kind,
		Mode:     mode,
		Source:   kind,
		Targets:  []repo.TargetInput{},
		Warnings: []string{},
	}

	var (
		targets  []repo.TargetInput
		warnings []string
		emptyWhy string
		err      error
	)

	switch kind {
	case "domain":
		normalized, nerr := normalizeDomainValue(value)
		if nerr != nil {
			return nil, nerr
		}
		result.NormalizedValue = normalized
		if live {
			targets, warnings, err = s.expandDomainLive(ctx, seed.ProjectID, normalized, seed.Capability, maxTargets)
		} else {
			targets, warnings, err = s.expandDomain(ctx, seed.ProjectID, normalized, maxTargets)
		}
		if len(targets) == 0 && err == nil {
			emptyWhy = "domain_no_targets"
		}

	case "cidr":
		targets, warnings, err = expandCIDR(value, seed.Capability, maxTargets)
		if err == nil {
			if _, network, cerr := net.ParseCIDR(value); cerr == nil {
				result.NormalizedValue = network.String()
			}
		}

	case "dict":
		normalized, nerr := normalizeDomainValue(value)
		if nerr != nil {
			return nil, nerr
		}
		result.NormalizedValue = normalized
		targets, warnings, err = s.expandDict(ctx, normalized, seed.Capability, maxTargets)
		if len(targets) == 0 && err == nil {
			emptyWhy = "dictionary_empty"
		}

	case "company":
		normalized := strings.TrimSpace(value)
		result.NormalizedValue = normalized
		if !live {
			warnings = append(warnings, "company 种子的展开需要外部 live 数据源；请打开 live 后再试")
			emptyWhy = "company_live_source_required"
			break
		}
		targets, warnings, err = s.expandCompanyLive(ctx, seed.ProjectID, normalized, seed.Capability, maxTargets)
		if len(targets) == 0 && err == nil {
			emptyWhy = "company_no_domains"
		}

	case "cert":
		normalized := certquery.NormalizeOrg(value)
		if normalized == "" {
			return nil, invalidSeed("证书组织名过短或为空（至少 3 个字符）")
		}
		result.NormalizedValue = normalized
		if !live {
			warnings = append(warnings, "cert 种子的展开需要外部 live 数据源；请打开 live 后再试")
			emptyWhy = "cert_live_source_required"
			break
		}
		targets, warnings, err = s.expandCertLive(ctx, seed.ProjectID, normalized, seed.Capability, maxTargets)
		if len(targets) == 0 && err == nil {
			emptyWhy = "cert_no_domains"
		}

	case "repo":
		normalized := strings.TrimSpace(value)
		result.NormalizedValue = normalized
		if !live {
			warnings = append(warnings, "repo 种子的展开需要外部 live 数据源；请打开 live 后再试")
			emptyWhy = "repo_live_source_required"
			break
		}
		targets, warnings, err = s.expandRepoLive(ctx, seed.ProjectID, normalized, seed.Capability, maxTargets)
		if len(targets) == 0 && err == nil {
			emptyWhy = "repo_no_domains"
		}

	case "app":
		warnings = append(warnings, "app 种子的展开需要商店数据源，当前版本尚未接入；本次预览不会产生目标")
		if live {
			warnings = append(warnings, "live 展开尚未实现，仍在 P1 排期")
		}
		emptyWhy = "app_live_source_required"
		result.NormalizedValue = value
	}

	if err != nil {
		return nil, err
	}

	// 种子级 probe=false：只收集目标清单，不向目标发探测请求。
	if probe, ok := seed.Capability["probe"].(bool); ok && !probe {
		for i := range targets {
			if targets[i].Capability == nil {
				targets[i].Capability = map[string]any{}
			}
			targets[i].Capability["probe"] = false
		}
	}

	finalTargets, total, capWarnings := finalizeSeedTargets(targets, maxTargets)
	warnings = append(warnings, capWarnings...)
	shown := total
	if shown > sampleLimit {
		shown = sampleLimit
		result.Truncated = true
	}
	result.Targets = finalTargets[:shown]
	result.Total = total
	result.Shown = shown
	result.Warnings = append(result.Warnings, warnings...)
	if total == 0 {
		result.EmptyReason = emptyWhy
	}
	return result, nil
}

// finalizeSeedTargets 去重、稳定排序、按硬上限截断。
func finalizeSeedTargets(in []repo.TargetInput, maxTargets int) ([]repo.TargetInput, int, []string) {
	warnings := []string{}
	seen := make(map[string]bool, len(in))
	out := make([]repo.TargetInput, 0, len(in))
	for _, t := range in {
		if t.Host == "" || t.Port <= 0 {
			continue
		}
		key := t.Host + "\x00" + strconv.Itoa(t.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		if t.Capability == nil {
			t.Capability = map[string]any{"probe": true}
		}
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		return out[i].Port < out[j].Port
	})
	if len(out) > maxTargets {
		warnings = append(warnings, fmt.Sprintf(
			"展开目标 %d 个，超过上限 %d，已截断", len(out), maxTargets))
		out = out[:maxTargets]
	}
	return out, len(out), warnings
}

// expandDomain：项目内已归并站点的入口优先；一个站点都没有时回落根域 443。
func (s *CycleService) expandDomain(ctx context.Context, projectID int64, value string, maxTargets int) ([]repo.TargetInput, []string, error) {
	root, err := normalizeDomainValue(value)
	if err != nil {
		return nil, nil, err
	}
	r := repo.Default()
	if r == nil {
		return nil, nil, errors.New("数据层未初始化")
	}
	warnings := []string{}
	targets, err := r.AssetTargetsForDomain(ctx, projectID, root, maxTargets)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		warnings = append(warnings, fmt.Sprintf(
			"项目内还没有 %s 的站点，本次只展开根域 443", root))
		targets = []repo.TargetInput{{
			Host:       root,
			Port:       443,
			Capability: map[string]any{"probe": true, "source": "seed_fallback"},
		}}
	}
	return targets, warnings, nil
}

// normalizeDomainValue 处理 scheme/端口/尾点/大小写/IDN，产出可落库的 ASCII 域名。
func normalizeDomainValue(raw string) (string, error) {
	v := strings.TrimSpace(strings.ToLower(raw))
	if v == "" {
		return "", invalidSeed("域名必填")
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil || u.Hostname() == "" {
			return "", invalidSeed("域名不合法: %s", raw)
		}
		v = u.Hostname()
	}
	if i := strings.Index(v, "/"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSuffix(v, ".")
	if host, _, err := net.SplitHostPort(v); err == nil {
		v = host
	}
	if net.ParseIP(v) != nil {
		return v, nil
	}
	ascii, err := idna.Lookup.ToASCII(v)
	if err != nil {
		return "", invalidSeed("域名不合法: %s", raw)
	}
	if !isValidDomainName(ascii) {
		return "", invalidSeed("域名不合法: %s", raw)
	}
	return ascii, nil
}

func isValidDomainName(v string) bool {
	if len(v) == 0 || len(v) > 253 || strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") {
		return false
	}
	labels := strings.Split(v, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func expandCIDR(value string, capability map[string]any, maxTargets int) ([]repo.TargetInput, []string, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(value))
	if err != nil {
		return nil, nil, invalidSeed("CIDR 不合法: %v", err)
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, nil, invalidSeed("暂不支持 IPv6 网段")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 {
		return nil, nil, invalidSeed("暂不支持 IPv6 网段")
	}
	if ones < 16 {
		return nil, nil, invalidSeed("网段过大（最小 /16），请先收窄范围")
	}
	ports, err := capabilityPorts(capability["ports"], []int{80, 443})
	if err != nil {
		return nil, nil, err
	}

	warnings := []string{}
	maxHosts := maxTargets / len(ports)
	if maxHosts < 1 {
		maxHosts = 1
	}
	if n := capabilityInt(capability["max_hosts"]); n > 0 && n < maxHosts {
		maxHosts = n
	}

	base := binary.BigEndian.Uint32(network.IP.To4())
	hostCount := uint64(1) << uint(32-ones)
	var first, last uint64
	if hostCount <= 2 {
		first, last = 0, hostCount-1
		warnings = append(warnings, fmt.Sprintf("/%d 按 RFC 3021 取全部地址", ones))
	} else {
		first, last = 1, hostCount-2
		warnings = append(warnings, "已跳过网络地址与广播地址")
	}
	usable := last - first + 1
	if usable > uint64(maxHosts) {
		warnings = append(warnings, fmt.Sprintf(
			"可用主机 %d 个，超过本次上限 %d，已截断", usable, maxHosts))
		usable = uint64(maxHosts)
	}

	out := make([]repo.TargetInput, 0, int(usable)*len(ports))
	for i := uint64(0); i < usable; i++ {
		ipVal := base + uint32(first+i)
		host := net.IPv4(byte(ipVal>>24), byte(ipVal>>16), byte(ipVal>>8), byte(ipVal)).String()
		for _, port := range ports {
			out = append(out, repo.TargetInput{
				Host:       host,
				Port:       port,
				Capability: map[string]any{"probe": true, "source": "cidr"},
			})
		}
	}
	return out, warnings, nil
}

// expandDomainLive 用测绘引擎按域名反查资产，叠加项目内已有站点，再统一展开。
// 无数据源/无结果时回落到静态展开，保证计划不会因为外部源故障完全空跑。
func (s *CycleService) expandDomainLive(ctx context.Context, projectID int64, root string, capability map[string]any, maxTargets int) ([]repo.TargetInput, []string, error) {
	keys := companyEngineKeys(ctx)
	engines := capabilityStrings(capability["engines"])
	if len(engines) == 0 {
		engines = []string{"quake", "fofa", "hunter"}
	}
	warnings := []string{}
	domains := map[string]bool{root: true}
	used := []string{}

	queryCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for _, raw := range engines {
		engine := strings.ToLower(strings.TrimSpace(raw))
		if !spacemap.ValidProvider(engine) {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 不是受支持的测绘引擎，已跳过", engine))
			continue
		}
		if strings.TrimSpace(keys[engine]) == "" {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 未配置 API Key，已跳过", engine))
			continue
		}
		rows, err := companySearchRows(queryCtx, keys, engine, spacemap.DomainQuery(engine, root), 100)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 查询失败：%v", engine, err))
			continue
		}
		used = append(used, engine)
		for _, row := range rows {
			for _, d := range icpquery.DomainsFromRow(engine, row) {
				domains[d] = true
			}
		}
	}

	if len(used) == 0 {
		warnings = append(warnings, "没有可用的 live 数据源，回落到项目内已有站点 / 根域 443")
		targets, staticWarnings, err := s.expandDomain(ctx, projectID, root, maxTargets)
		warnings = append(warnings, staticWarnings...)
		return targets, warnings, err
	}

	list := make([]string, 0, len(domains))
	for d := range domains {
		list = append(list, d)
	}
	sort.Strings(list)
	limit := capabilityInt(capability["max_domains"])
	if limit <= 0 {
		limit = 300
	}
	if limit > 500 {
		limit = 500
	}
	if len(list) > limit {
		warnings = append(warnings, fmt.Sprintf("反查域名 %d 个，超过上限 %d，已截断", len(list), limit))
		list = list[:limit]
	}

	targets, targetWarnings := s.expandDomainList(ctx, projectID, list, "domain_live", maxTargets)
	warnings = append(warnings, targetWarnings...)
	warnings = append(warnings, fmt.Sprintf(
		"从 %s 反查 %d 个域名，展开 %d 个目标", strings.Join(used, ", "), len(list), len(targets)))
	return targets, warnings, nil
}

func (s *CycleService) expandDict(ctx context.Context, value string, capability map[string]any, maxTargets int) ([]repo.TargetInput, []string, error) {
	base, err := normalizeDomainValue(value)
	if err != nil {
		return nil, nil, err
	}
	ids := capabilityStrings(capability["dictionary_ids"])
	if len(ids) == 0 {
		return nil, nil, invalidSeed("dict 种子必须提供 capability.dictionary_ids")
	}
	ports, err := capabilityPorts(capability["ports"], []int{443})
	if err != nil {
		return nil, nil, err
	}
	maxPerPort := maxTargets / len(ports)
	if maxPerPort < 1 {
		maxPerPort = 1
	}

	r := repo.Default()
	if r == nil {
		return nil, nil, errors.New("数据层未初始化")
	}
	dicts := r.Dictionaries()

	warnings := []string{}
	out := make([]repo.TargetInput, 0, maxTargets)
	for _, port := range ports {
		out = append(out, repo.TargetInput{
			Host:       base,
			Port:       port,
			Capability: map[string]any{"probe": true, "source": "dict_base"},
		})
	}

	seen := map[string]bool{base: true}
	wordBudget := maxPerPort - 1
	if wordBudget < 0 {
		wordBudget = 0
	}
	truncated := false
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if !repo.ValidID(id) {
			return nil, nil, invalidSeed("字典 ID 不合法: %s", id)
		}
		if _, err := dicts.GetByID(ctx, id); err != nil {
			if errors.Is(err, repo.ErrNotFound) {
				return nil, nil, invalidSeed("字典不存在: %s", id)
			}
			return nil, nil, err
		}
		entries, err := dicts.ListEntriesForExpand(ctx, id, wordBudget+1)
		if err != nil {
			return nil, nil, err
		}
		if len(entries) == 0 {
			warnings = append(warnings, fmt.Sprintf("字典 %s 没有词条", id))
			continue
		}
		invalidWords := 0
		for _, entry := range entries {
			if len(out) >= maxTargets {
				truncated = true
				break
			}
			word := strings.ToLower(strings.TrimSpace(entry))
			if !isValidDictLabel(word) {
				invalidWords++
				continue
			}
			host := word + "." + base
			if seen[host] {
				continue
			}
			seen[host] = true
			for _, port := range ports {
				if len(out) >= maxTargets {
					truncated = true
					break
				}
				out = append(out, repo.TargetInput{
					Host:       host,
					Port:       port,
					Capability: map[string]any{"probe": true, "source": "dict"},
				})
			}
		}
		if invalidWords > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"字典 %s 有 %d 个非单标签词条已跳过", id, invalidWords))
		}
		if truncated {
			warnings = append(warnings, "字典展开超过目标上限，已截断")
			break
		}
	}
	return out, warnings, nil
}

func isValidDictLabel(v string) bool {
	if v == "" || len(v) > 63 {
		return false
	}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return false
	}
	return v[0] != '-' && v[len(v)-1] != '-'
}

// 允许单测替换的测绘引擎访问点；生产实现直接复用 spacemap 客户端。
var (
	companyEngineKeys = func(ctx context.Context) map[string]string {
		return NewSourceService().EngineKeys(ctx)
	}
	companySearchRows = func(ctx context.Context, keys map[string]string, engine, query string, limit int) ([]map[string]any, error) {
		// 按天额度闸门（master 侧调用点统一在这里把关：公司反查与证书反查共用）
		if budget := GetEngineBudgetService(); budget.CanAccount() && !budget.AllowMasterQuery(ctx, engine) {
			return nil, fmt.Errorf("引擎 %s 今日查询额度已用尽（治理面板可调整限额）", engine)
		}
		client := spacemap.NewClient()
		client.KeyResolver = func(provider string) string {
			return keys[strings.ToLower(strings.TrimSpace(provider))]
		}
		_, rows, _, err := client.SearchEngineAssets(ctx, engine, query, limit, 1)
		// 无论成败都消耗一次额度（上游按请求计费）
		GetEngineBudgetService().Consume(ctx, engine, 1)
		return rows, err
	}
)

func (s *CycleService) expandDomainForCompany(ctx context.Context, projectID int64, domain string, maxTargets int) ([]repo.TargetInput, []string, error) {
	if s.expandDomainHook != nil {
		return s.expandDomainHook(ctx, projectID, domain, maxTargets)
	}
	return s.expandDomain(ctx, projectID, domain, maxTargets)
}

// expandCompanyLive 用官方 ICP / 测绘引擎按「主办单位」反查域名，再把域名展开成目标。
// 只接受 live 模式；数据源不可用或引擎报错时返回 warning，不静默失败。
func (s *CycleService) expandCompanyLive(ctx context.Context, projectID int64, company string, capability map[string]any, maxTargets int) ([]repo.TargetInput, []string, error) {
	if company == "" {
		return nil, nil, invalidSeed("公司名必填")
	}
	keys := companyEngineKeys(ctx)

	engines := capabilityStrings(capability["engines"])
	if len(engines) == 0 {
		if len(keys) == 0 {
			// 没有测绘引擎 Key 时默认走官方备案查询，开箱可用。
			engines = []string{"icp_official"}
		} else {
			engines = []string{"fofa", "hunter"}
		}
	}
	limit := capabilityInt(capability["max_domains"])
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}

	// 官方 ICP 单页约 15–20s，最多取 2 页；总超时放宽到 90s。
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	warnings := []string{}
	domains := map[string]bool{}
	usedEngines := []string{}
	for _, raw := range engines {
		engine := strings.ToLower(strings.TrimSpace(raw))
		if isOfficialICPEngine(engine) {
			filings, total, qerr := DefaultICPService().QueryDirect(ctx, company, 1, 40, 2)
			if qerr != nil {
				warnings = append(warnings, fmt.Sprintf("官方 ICP 查询失败：%v", qerr))
				continue
			}
			usedEngines = append(usedEngines, "icp_official")
			for _, f := range filings {
				if d := strings.ToLower(strings.TrimSpace(f.Domain)); d != "" {
					domains[d] = true
				}
			}
			if total > len(filings) {
				warnings = append(warnings, fmt.Sprintf(
					"官方 ICP 共有 %d 条备案，本次仅取前 %d 条（限速保护）", total, len(filings)))
			}
			continue
		}
		query, ok := icpquery.QueryFor(engine, icpquery.KindCompany, company)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 不支持按主办单位反查，已跳过", engine))
			continue
		}
		if strings.TrimSpace(keys[engine]) == "" {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 未配置 API Key，已跳过", engine))
			continue
		}
		rows, err := companySearchRows(ctx, keys, engine, query, 100)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 查询失败：%v", engine, err))
			continue
		}
		usedEngines = append(usedEngines, engine)
		for _, row := range rows {
			for _, d := range icpquery.DomainsFromRow(engine, row) {
				domains[d] = true
			}
		}
	}
	if len(usedEngines) == 0 {
		warnings = append(warnings, "没有可用的 live 数据源，未产生目标")
		return nil, warnings, nil
	}
	if len(domains) == 0 {
		warnings = append(warnings, "引擎没有返回域名，请检查公司名、API Key 与配额")
		return nil, warnings, nil
	}

	list := make([]string, 0, len(domains))
	for d := range domains {
		list = append(list, d)
	}
	sort.Strings(list)
	if len(list) > limit {
		warnings = append(warnings, fmt.Sprintf(
			"引擎返回 %d 个域名，超过上限 %d，已截断", len(list), limit))
		list = list[:limit]
	}

	out, targetWarnings := s.expandDomainList(ctx, projectID, list, "company", maxTargets)
	warnings = append(warnings, targetWarnings...)
	warnings = append(warnings, fmt.Sprintf(
		"从 %s 展开 %d 个域名", strings.Join(usedEngines, ", "), len(list)))
	return out, warnings, nil
}

// expandDomainList 把一组域名逐个展开成目标，统一打上 via 标记。
// expandCertLive 按证书组织名（O=）反查资产：certquery 注册表适配五引擎语法，
// 行内域名提取复用 icpquery 的引擎行适配（cert→icp→company 三角互证设计）。
// 默认只用精确匹配引擎（fofa/hunter/shodan）；quake/zoomeye 是证书全文匹配、
// 噪音高，仅在 capability.engines 显式指定时启用。
func (s *CycleService) expandCertLive(ctx context.Context, projectID int64, org string, capability map[string]any, maxTargets int) ([]repo.TargetInput, []string, error) {
	if org == "" {
		return nil, nil, invalidSeed("证书组织名必填")
	}
	keys := companyEngineKeys(ctx)

	engines := capabilityStrings(capability["engines"])
	if len(engines) == 0 {
		engines = certquery.ExactEngines()
	}
	limit := capabilityInt(capability["max_domains"])
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	warnings := []string{}
	domains := map[string]bool{}
	usedEngines := []string{}
	for _, raw := range engines {
		engine := strings.ToLower(strings.TrimSpace(raw))
		query, ok := certquery.QueryFor(engine, org)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 不支持按证书组织反查，已跳过", engine))
			continue
		}
		if strings.TrimSpace(keys[engine]) == "" {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 未配置 API Key，已跳过", engine))
			continue
		}
		rows, err := companySearchRows(ctx, keys, engine, query, 100)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("引擎 %s 查询失败：%v", engine, err))
			continue
		}
		usedEngines = append(usedEngines, engine)
		for _, row := range rows {
			for _, d := range icpquery.DomainsFromRow(engine, row) {
				domains[d] = true
			}
		}
	}
	if len(usedEngines) == 0 {
		warnings = append(warnings, "没有可用的 live 数据源，未产生目标")
		return nil, warnings, nil
	}
	if len(domains) == 0 {
		warnings = append(warnings, "引擎没有返回域名，请检查组织名（需与证书 Subject O= 完全一致）、API Key 与配额")
		return nil, warnings, nil
	}

	list := make([]string, 0, len(domains))
	for d := range domains {
		list = append(list, d)
	}
	sort.Strings(list)
	if len(list) > limit {
		warnings = append(warnings, fmt.Sprintf(
			"引擎返回 %d 个域名，超过上限 %d，已截断", len(list), limit))
		list = list[:limit]
	}

	out, targetWarnings := s.expandDomainList(ctx, projectID, list, "cert", maxTargets)
	warnings = append(warnings, targetWarnings...)
	warnings = append(warnings, fmt.Sprintf(
		"从 %s 按证书组织展开 %d 个域名", strings.Join(usedEngines, ", "), len(list)))
	return out, warnings, nil
}

func (s *CycleService) expandDomainList(ctx context.Context, projectID int64, domains []string, via string, maxTargets int) ([]repo.TargetInput, []string) {
	warnings := []string{}
	out := make([]repo.TargetInput, 0, len(domains))
	for _, domain := range domains {
		if len(out) >= maxTargets {
			warnings = append(warnings, "展开目标超过总数上限，已截断")
			break
		}
		root, err := normalizeDomainValue(domain)
		if err != nil {
			continue
		}
		remaining := maxTargets - len(out)
		targets, _, err := s.expandDomainForCompany(ctx, projectID, root, remaining)
		if err != nil {
			continue
		}
		for _, t := range targets {
			if t.Capability == nil {
				t.Capability = map[string]any{"probe": true}
			}
			t.Capability["via"] = via
			out = append(out, t)
		}
	}
	return out, warnings
}

func capabilityPorts(v any, def []int) ([]int, error) {
	if v == nil {
		return def, nil
	}
	raw := []int{}
	switch x := v.(type) {
	case []int:
		raw = append(raw, x...)
	case []string:
		for _, s := range x {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				return nil, invalidSeed("端口不合法: %s", s)
			}
			raw = append(raw, n)
		}
	case []any:
		for _, item := range x {
			n := capabilityInt(item)
			if n <= 0 {
				return nil, invalidSeed("端口不合法: %v", item)
			}
			raw = append(raw, n)
		}
	default:
		if n := capabilityInt(x); n > 0 {
			raw = append(raw, n)
		}
	}
	if len(raw) == 0 {
		return nil, invalidSeed("capability.ports 不能为空")
	}
	seen := map[int]bool{}
	out := make([]int, 0, len(raw))
	for _, p := range raw {
		if p < 1 || p > 65535 {
			return nil, invalidSeed("端口需在 1..65535，收到 %d", p)
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func capabilityInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(x))
		return n
	default:
		return 0
	}
}

// officialICPEngine 官方工信部备案查询的引擎别名（capability.engines 里可用）。
var officialICPEngine = map[string]bool{
	"icp_official": true, "miit": true, "icp": true, "official": true,
}

func isOfficialICPEngine(engine string) bool { return officialICPEngine[engine] }

func capabilityStrings(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		return []string{x}
	default:
		return nil
	}
}
