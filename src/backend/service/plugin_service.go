package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// PluginService 覆盖插件、指纹规则、字典三块。读写全部走 repo 层。
type PluginService struct{}

func NewPluginService() *PluginService {
	return &PluginService{}
}

func (s *PluginService) plugins() (repo.PluginRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Plugins(), nil
}

func (s *PluginService) dicts() (repo.DictRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Dictionaries(), nil
}

func (s *PluginService) rules() (repo.FingerprintRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Fingerprints(), nil
}

// CreatePlugin 创建插件
func (s *PluginService) CreatePlugin(plugin *models.Plugin) error {
	store, err := s.plugins()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if _, err := store.GetByName(ctx, plugin.Name); err == nil {
		return errors.New("插件名称已存在")
	}

	plugin.Installed = true
	plugin.Enabled = true
	plugin.CreatedAt = time.Now()
	plugin.UpdatedAt = time.Now()

	if err := store.Create(ctx, plugin); err != nil {
		if errors.Is(err, repo.ErrDuplicate) {
			return errors.New("插件名称已存在")
		}
		return errors.New("创建插件失败")
	}
	return nil
}

// GetPluginByID 按 ID 取插件
func (s *PluginService) GetPluginByID(pluginID string) (*models.Plugin, error) {
	if !repo.ValidID(pluginID) {
		return nil, errors.New("无效的插件ID")
	}
	store, err := s.plugins()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	plugin, err := store.GetByID(ctx, pluginID)
	if err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return nil, errors.New("插件不存在")
		}
		return nil, errors.New("查询插件失败")
	}
	return plugin, nil
}

// ListPlugins 分页查询插件
func (s *PluginService) ListPlugins(pluginType, language string, enabled *bool, keyword string, page, pageSize int) ([]*models.Plugin, int64, error) {
	store, err := s.plugins()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	plugins, total, err := store.List(ctx, repo.PluginFilter{
		Type:     pluginType,
		Language: language,
		Enabled:  enabled,
		Keyword:  keyword,
		Page:     page,
		PageSize: pageSize,
	})
	if err != nil {
		return nil, 0, errors.New("查询插件列表失败")
	}
	return plugins, total, nil
}

// UpdatePlugin 更新插件
func (s *PluginService) UpdatePlugin(pluginID string, updates map[string]interface{}) error {
	if !repo.ValidID(pluginID) {
		return errors.New("无效的插件ID")
	}
	store, err := s.plugins()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.UpdateFields(ctx, pluginID, updates); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("插件不存在")
		}
		return errors.New("更新插件失败")
	}
	return nil
}

// DeletePlugin 删除插件
func (s *PluginService) DeletePlugin(pluginID string) error {
	if !repo.ValidID(pluginID) {
		return errors.New("无效的插件ID")
	}
	store, err := s.plugins()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.Delete(ctx, pluginID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("插件不存在")
		}
		return errors.New("删除插件失败")
	}
	return nil
}

// TogglePlugin 启停插件
func (s *PluginService) TogglePlugin(pluginID string, enabled bool) error {
	return s.UpdatePlugin(pluginID, map[string]interface{}{"enabled": enabled})
}

// InstallPlugin 安装插件
func (s *PluginService) InstallPlugin(pluginID string) error {
	return s.UpdatePlugin(pluginID, map[string]interface{}{"installed": true})
}

// UninstallPlugin 卸载插件
func (s *PluginService) UninstallPlugin(pluginID string) error {
	return s.UpdatePlugin(pluginID, map[string]interface{}{
		"installed": false,
		"enabled":   false,
	})
}

// ---------------------------------------------------------------- 指纹规则
//
// 这里只提供旧的扁平视图（models.FingerprintRule）。
// 条件树那套走 governance 的 /api/governance/fingerprints。

func (s *PluginService) CreateFingerprintRule(rule *models.FingerprintRule) error {
	store, err := s.rules()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	legacy := make([]repo.LegacyMatch, 0, len(rule.Rules))
	for _, m := range rule.Rules {
		legacy = append(legacy, repo.LegacyMatch{
			Type:     m.Type,
			Key:      m.Key,
			Pattern:  m.Pattern,
			Operator: m.Operator,
		})
	}

	fp := &repo.FpRule{
		Name:       rule.Name,
		Category:   rule.Category,
		Version:    rule.Version,
		Legacy:     legacy,
		Enabled:    true,
		DSLVersion: 1, // 扁平规则按 AND 语义执行
		Source:     "plugin",
	}
	if err := store.UpsertRule(ctx, fp); err != nil {
		return errors.New("创建指纹规则失败")
	}
	if id, convErr := repo.ParseID(fp.ID); convErr == nil {
		rule.ID = id
	}
	rule.Enabled = true
	return nil
}

func (s *PluginService) ListFingerprintRules(category, keyword string, page, pageSize int) ([]*models.FingerprintRule, int64, error) {
	store, err := s.rules()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	rows, total, err := store.ListRulesFiltered(ctx, category, keyword, page, pageSize)
	if err != nil {
		return nil, 0, errors.New("查询指纹规则失败")
	}

	out := make([]*models.FingerprintRule, 0, len(rows))
	for _, r := range rows {
		matches := make([]models.FingerprintMatch, 0, len(r.Legacy))
		for _, m := range r.Legacy {
			matches = append(matches, models.FingerprintMatch{
				Type:     m.Type,
				Key:      m.Key,
				Pattern:  m.Pattern,
				Operator: m.Operator,
			})
		}
		item := models.FingerprintRule{
			Name:      r.Name,
			Category:  r.Category,
			Version:   r.Version,
			Rules:     matches,
			Enabled:   r.Enabled,
			Source:    r.Source,
			CreatedAt: r.CreatedAt,
			UpdatedAt: r.UpdatedAt,
		}
		if id, convErr := repo.ParseID(r.ID); convErr == nil {
			item.ID = id
		}
		out = append(out, &item)
	}
	return out, total, nil
}

func (s *PluginService) DeleteFingerprintRule(ruleID string) error {
	if !repo.ValidID(ruleID) {
		return errors.New("无效的规则ID")
	}
	store, err := s.rules()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	if err := store.DeleteRuleByID(ctx, ruleID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("规则不存在")
		}
		return errors.New("删除规则失败")
	}
	return nil
}

// ---------------------------------------------------------------- 字典

func (s *PluginService) CreateDictionary(dict *models.Dictionary) error {
	store, err := s.dicts()
	if err != nil {
		return err
	}
	dict.CreatedAt = time.Now()
	dict.UpdatedAt = time.Now()

	ctx, cancel := dbCtx()
	defer cancel()
	if err := store.Create(ctx, dict); err != nil {
		if errors.Is(err, repo.ErrDuplicate) {
			return errors.New("同类型同名的字典已存在")
		}
		return errors.New("创建字典失败")
	}
	return nil
}

func (s *PluginService) ListDictionaries(dictType string, page, pageSize int) ([]*models.Dictionary, int64, error) {
	store, err := s.dicts()
	if err != nil {
		return nil, 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	dicts, total, err := store.List(ctx, dictType, page, pageSize)
	if err != nil {
		return nil, 0, errors.New("查询字典失败")
	}
	return dicts, total, nil
}

func (s *PluginService) DeleteDictionary(dictID string) error {
	if !repo.ValidID(dictID) {
		return errors.New("无效的字典ID")
	}
	store, err := s.dicts()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	dict, err := store.GetByID(ctx, dictID)
	if err == nil && dict.IsBuiltin {
		return errors.New("不能删除内置字典")
	}
	// G4：被种子（计划通过种子引用）的字典不可删除
	if err == nil {
		refs, rerr := store.CountSeedRefs(ctx, dictID, dict.Name)
		if rerr != nil {
			return errors.New("检查字典引用失败")
		}
		if refs > 0 {
			return fmt.Errorf("字典被 %d 个种子引用，不能删除（先删除相关计划/种子）", refs)
		}
	}
	if err := store.Delete(ctx, dictID); err != nil {
		if errors.Is(err, repo.ErrNotFound) {
			return errors.New("字典不存在")
		}
		return errors.New("删除字典失败")
	}
	return nil
}
