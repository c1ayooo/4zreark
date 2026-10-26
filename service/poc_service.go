package service

import (
	"archive/zip"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"

	"gopkg.in/yaml.v3"
)

// POCService 的读写全部走 repo 层。
type POCService struct{}

func NewPOCService() *POCService {
	return &POCService{}
}

func (s *POCService) store() (repo.PocRepo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据库未就绪")
	}
	return r.Pocs(), nil
}

// ImportResult ZIP 导入结果
type ImportResult struct {
	Imported int      `json:"imported"`
	Failed   int      `json:"failed"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors"`
}

// stringOrSlice 兼容 nuclei 模板里的两种写法：
//
//	reference: https://example.com
//	reference:
//	  - https://example.com
//
// 真实模板库里两种都有，只认数组会丢掉一大批模板。
type stringOrSlice []string

func (s *stringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		v := strings.TrimSpace(value.Value)
		if v == "" {
			*s = nil
		} else {
			*s = []string{v}
		}
		return nil
	}
	var list []string
	if err := value.Decode(&list); err != nil {
		return err
	}
	*s = list
	return nil
}

// NucleiTemplate Nuclei 模板结构（用于解析）
type NucleiTemplate struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string        `yaml:"name"`
		Author         string        `yaml:"author"`
		Severity       string        `yaml:"severity"`
		Description    string        `yaml:"description"`
		Reference      stringOrSlice `yaml:"reference"`
		Tags           string        `yaml:"tags"`
		Classification struct {
			CVEID stringOrSlice `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
}

// sanitizePGText 去掉 NUL 字节。PostgreSQL 的 text/varchar 不接受 0x00
// (SQLSTATE 22021)；nuclei 模板里 `"\u0000"` 这类转义解码后就是真 NUL。
func sanitizePGText(s string) string {
	if !strings.ContainsRune(s, 0) {
		return s
	}
	return strings.ReplaceAll(s, "\x00", "")
}

type parsedPOC struct {
	poc        *models.POC
	templateID string
	name       string
}

// parseTemplate 解析单个 YAML，返回 POC 或错误原因。
func parseTemplate(content []byte, label string) (*parsedPOC, error) {
	var template NucleiTemplate
	if err := yaml.Unmarshal(content, &template); err != nil {
		return nil, errors.New("Failed to parse " + label + ": " + err.Error())
	}
	if template.ID == "" || template.Info.Name == "" {
		return nil, errors.New("Invalid template " + label + ": missing id or name")
	}

	var tags []string
	if template.Info.Tags != "" {
		tags = strings.Split(template.Info.Tags, ",")
		for i := range tags {
			tags[i] = strings.TrimSpace(tags[i])
		}
	}

	cves := make([]string, 0, len(template.Info.Classification.CVEID))
	for _, c := range template.Info.Classification.CVEID {
		cves = append(cves, sanitizePGText(strings.TrimSpace(c)))
	}
	refs := make([]string, 0, len(template.Info.Reference))
	for _, r := range template.Info.Reference {
		refs = append(refs, sanitizePGText(strings.TrimSpace(r)))
	}

	return &parsedPOC{
		templateID: sanitizePGText(template.ID),
		name:       sanitizePGText(template.Info.Name),
		poc: &models.POC{
			Name:        sanitizePGText(template.Info.Name),
			TemplateID:  sanitizePGText(template.ID),
			Description: sanitizePGText(template.Info.Description),
			Author:      sanitizePGText(template.Info.Author),
			Severity:    models.VulnSeverity(strings.ToLower(sanitizePGText(template.Info.Severity))),
			Type:        "nuclei",
			Tags:        tags,
			Content:     sanitizePGText(string(content)),
			CVEID:       cves,
			References:  refs,
			Enabled:     true,
			Version:     "1.0",
		},
	}, nil
}

// importParsed 先批量查重，再批量写入；单条失败不影响整批。
func (s *POCService) importParsed(parsed []parsedPOC, result *ImportResult) error {
	if len(parsed) == 0 {
		return nil
	}

	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	templateIDs := make([]string, 0, len(parsed))
	names := make([]string, 0, len(parsed))
	for _, p := range parsed {
		templateIDs = append(templateIDs, p.templateID)
		names = append(names, p.name)
	}

	existTemplate, existName, err := store.ExistingKeys(ctx, templateIDs, names)
	if err != nil {
		return errors.New("查询已有 POC 失败: " + err.Error())
	}

	toInsert := make([]*models.POC, 0, len(parsed))
	for _, p := range parsed {
		if existTemplate[p.templateID] || existName[p.name] {
			result.Skipped++
			continue
		}
		// 同批次内也去重
		existTemplate[p.templateID] = true
		existName[p.name] = true
		toInsert = append(toInsert, p.poc)
	}

	inserted, errs, err := store.InsertBatch(ctx, toInsert)
	if err != nil {
		return errors.New("写入 POC 失败: " + err.Error())
	}
	result.Imported += inserted
	result.Failed += len(errs)
	result.Errors = append(result.Errors, errs...)
	return nil
}

// ImportFromZip 从 ZIP 文件导入 POC
func (s *POCService) ImportFromZip(reader io.ReaderAt, size int64) (*ImportResult, error) {
	result := &ImportResult{Errors: make([]string, 0)}

	zipReader, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, errors.New("failed to read ZIP file: " + err.Error())
	}

	var parsed []parsedPOC
	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(file.Name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		baseName := filepath.Base(file.Name)
		if strings.HasPrefix(baseName, ".") || strings.HasPrefix(baseName, "__MACOSX") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to open "+file.Name+": "+err.Error())
			continue
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to read "+file.Name+": "+err.Error())
			continue
		}

		p, err := parseTemplate(content, file.Name)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, err.Error())
			continue
		}
		p.poc.Source = "import"
		parsed = append(parsed, *p)
	}

	if err := s.importParsed(parsed, result); err != nil {
		return nil, err
	}
	return result, nil
}

// ImportFromDirectory 从目录导入 POC（支持递归扫描子目录）
func (s *POCService) ImportFromDirectory(dirPath string) (*ImportResult, error) {
	result := &ImportResult{Errors: make([]string, 0)}

	info, err := os.Stat(dirPath)
	if os.IsNotExist(err) {
		return result, nil
	}
	if err != nil {
		return nil, errors.New("failed to access directory: " + err.Error())
	}
	if !info.IsDir() {
		return nil, errors.New("path is not a directory: " + dirPath)
	}

	var parsed []parsedPOC
	walkErr := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		if strings.HasPrefix(filepath.Base(path), ".") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, "Failed to read "+path+": "+err.Error())
			return nil
		}
		p, err := parseTemplate(content, path)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, err.Error())
			return nil
		}
		p.poc.Source = "directory"
		parsed = append(parsed, *p)
		return nil
	})
	if walkErr != nil {
		return nil, errors.New("failed to walk directory: " + walkErr.Error())
	}

	if err := s.importParsed(parsed, result); err != nil {
		return nil, err
	}
	return result, nil
}

// ScanPOCDirectory 扫描 POC 目录并自动导入（启动时调用）
func (s *POCService) ScanPOCDirectory(pocDir string) {
	log.Printf("[POCService] Scanning POC directory: %s", pocDir)

	result, err := s.ImportFromDirectory(pocDir)
	if err != nil {
		log.Printf("[POCService] Failed to scan POC directory: %v", err)
		return
	}

	if result.Imported > 0 || result.Skipped > 0 || result.Failed > 0 {
		log.Printf("[POCService] POC directory scan complete: imported=%d, skipped=%d, failed=%d",
			result.Imported, result.Skipped, result.Failed)
	} else {
		log.Printf("[POCService] No POC files found in directory: %s", pocDir)
	}

	for i, msg := range result.Errors {
		if i >= 10 {
			log.Printf("[POCService] %d import errors (showing first 10)", len(result.Errors))
			break
		}
		log.Printf("[POCService] Import error: %s", msg)
	}
}

// GetByName 通过名称取 POC
func (s *POCService) GetByName(name string) (*models.POC, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.GetByName(ctx, name)
}

// GetByTemplateID 通过 Nuclei 模板 ID 取 POC
func (s *POCService) GetByTemplateID(templateID string) (*models.POC, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.GetByTemplateID(ctx, templateID)
}

// Create 按 template_id 或 name 覆盖写，与原来的「已存在则替换」语义一致。
func (s *POCService) Create(poc *models.POC) error {
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.Upsert(ctx, poc)
}

func (s *POCService) GetByID(id string) (*models.POC, error) {
	if !repo.ValidID(id) {
		return nil, errors.New("invalid poc id")
	}
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	poc, err := store.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return poc, nil
}

func (s *POCService) Update(id string, update map[string]interface{}) error {
	if !repo.ValidID(id) {
		return errors.New("invalid poc id")
	}
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.UpdateFields(ctx, id, update)
}

func (s *POCService) Delete(id string) error {
	if !repo.ValidID(id) {
		return errors.New("invalid poc id")
	}
	store, err := s.store()
	if err != nil {
		return err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.Delete(ctx, id)
}

// BatchDelete 批量删除 POC
func (s *POCService) BatchDelete(ids []string) (int, int) {
	store, err := s.store()
	if err != nil {
		return 0, len(ids)
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.BatchDelete(ctx, ids)
}

// ClearAll 清除所有 POC
func (s *POCService) ClearAll() (int64, error) {
	store, err := s.store()
	if err != nil {
		return 0, err
	}
	ctx, cancel := dbCtx()
	defer cancel()
	return store.ClearAll(ctx)
}

type POCListParams struct {
	Page     int64
	PageSize int64
	Type     string
	Severity string
	Enabled  *bool
	Search   string
}

type POCListResult struct {
	POCs  []models.POC `json:"pocs"`
	Total int64        `json:"total"`
}

func (s *POCService) List(params POCListParams) (*POCListResult, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	pocs, total, err := store.List(ctx, repo.POCFilter{
		Type:     params.Type,
		Severity: params.Severity,
		Enabled:  params.Enabled,
		Keyword:  params.Search,
		Page:     int(params.Page),
		PageSize: int(params.PageSize),
	})
	if err != nil {
		return nil, err
	}

	out := make([]models.POC, 0, len(pocs))
	for _, p := range pocs {
		out = append(out, *p)
	}
	return &POCListResult{POCs: out, Total: total}, nil
}

func (s *POCService) ToggleEnabled(id string, enabled bool) error {
	return s.Update(id, map[string]interface{}{"enabled": enabled})
}

func (s *POCService) GetStatistics() (map[string]interface{}, error) {
	store, err := s.store()
	if err != nil {
		return nil, err
	}
	ctx, cancel := dbCtx()
	defer cancel()

	stats, err := store.Stats(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"total":       stats.Total,
		"enabled":     stats.Enabled,
		"disabled":    stats.Total - stats.Enabled,
		"by_severity": stats.BySeverity,
		"by_type":     stats.ByType,
	}, nil
}

// ParseNucleiTemplateYAML 解析一份 nuclei 模板 YAML，返回可直接入库的 POC。
// 对外暴露是给 nuclei 模板接口复用同一套解析口径（与 zip/目录导入一致）。
func ParseNucleiTemplateYAML(content []byte) (*models.POC, error) {
	parsed, err := parseTemplate(content, "template")
	if err != nil {
		return nil, err
	}
	return parsed.poc, nil
}
