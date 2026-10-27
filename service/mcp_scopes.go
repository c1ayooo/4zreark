package service

import (
	"errors"
	"strings"

	"github.com/c1ayooo/4zreark/repo"
)

// MCP / 外部平台的权限点。命名统一为「域:动作」，写权限天然包含同域读权限的判断由工具各自声明，
// 这里只做白名单校验，不做隐式继承，避免授权结果依赖实现细节。
const (
	ScopeAssetsRead      = "assets:read"
	ScopeAssetsWrite     = "assets:write"
	ScopeProjectsRead    = "projects:read"
	ScopeProjectsWrite   = "projects:write"
	ScopeGovernanceRead  = "governance:read"
	ScopeGovernanceWrite = "governance:write"
	ScopeTasksRead       = "tasks:read"
	ScopeTasksWrite      = "tasks:write"
	ScopeScansRun        = "scans:run"
	ScopeVulnsRead       = "vulns:read"
	ScopeVulnsWrite      = "vulns:write"
	ScopePOCsRead        = "pocs:read"
	ScopePOCsWrite       = "pocs:write"
	ScopeEnterpriseRead  = "enterprise:read"
	ScopeEnterpriseWrite = "enterprise:write"
)

// ScopeInfo 是设置页渲染权限选项与说明的唯一来源。
type ScopeInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Group       string `json:"group"`
	Description string `json:"description"`
	Dangerous   bool   `json:"dangerous"`
}

var ScopeCatalog = []ScopeInfo{
	{ScopeAssetsRead, "读资产", "资产", "查询项目、资产列表、资产详情、站点路由与变更事件", false},
	{ScopeAssetsWrite, "改资产", "资产", "导入资产、人工验证、探测、保护与失联归档", true},
	{ScopeProjectsRead, "读项目", "项目", "读取项目采集状态等扩展信息", false},
	{ScopeProjectsWrite, "改项目", "项目", "新建/编辑/暂停/恢复/删除项目", true},
	{ScopeGovernanceRead, "读治理", "治理", "查看种子、计划、批次与执行单元", false},
	{ScopeGovernanceWrite, "改治理", "治理", "维护种子/计划、触发批次、重建关系与回放结果", true},
	{ScopeTasksRead, "读任务", "任务", "查看任务、日志、结果与统计", false},
	{ScopeTasksWrite, "改任务", "任务", "创建/编辑/删除/启停/重试/续扫任务", true},
	{ScopeScansRun, "执行扫描", "扫描", "直接执行端口、子域名、指纹、漏洞、目录、爬虫、弱口令、接管与 nuclei 扫描", true},
	{ScopeVulnsRead, "读漏洞", "漏洞", "查看漏洞列表、详情与统计（仅全项目 key）", false},
	{ScopeVulnsWrite, "改漏洞", "漏洞", "创建/编辑/删除漏洞、改状态与复核（仅全项目 key）", true},
	{ScopePOCsRead, "读 POC", "POC", "查看 POC 模板与统计（仅全项目 key）", false},
	{ScopePOCsWrite, "改 POC", "POC", "创建/编辑/删除/启停 POC（仅全项目 key）", true},
	{ScopeEnterpriseRead, "读企业", "企业", "查看企业数据源、深度采集任务状态与采集上限", false},
	{ScopeEnterpriseWrite, "企业采集", "企业", "发起/取消子公司深度采集、调整采集上限（热更新，立即生效）", true},
}

// AllScopes 按目录顺序返回全部权限点，供 UI 或校验使用。
func AllScopes() []string {
	out := make([]string, 0, len(ScopeCatalog))
	for _, s := range ScopeCatalog {
		out = append(out, s.Name)
	}
	return out
}

var scopeSet = func() map[string]bool {
	m := make(map[string]bool, len(ScopeCatalog))
	for _, s := range ScopeCatalog {
		m[s.Name] = true
	}
	return m
}()

// ValidateScopes 去重、trim 并校验白名单；空列表回落到只读资产，
// 保证老客户端不传 scopes 时行为与旧版本一致。
func ValidateScopes(scopes []string) ([]string, error) {
	seen := make(map[string]bool, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, raw := range scopes {
		s := strings.TrimSpace(raw)
		if s == "" || seen[s] {
			continue
		}
		if !scopeSet[s] {
			return nil, errors.New("未知权限点: " + s)
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		out = []string{ScopeAssetsRead}
	}
	return out, nil
}

func hasScope(key *repo.APIKey, scope string) bool {
	if key == nil {
		return false
	}
	for _, s := range key.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}
