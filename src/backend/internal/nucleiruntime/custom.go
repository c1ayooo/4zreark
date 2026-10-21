package nucleiruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateCustomTemplate 解析并校验自定义模板 YAML，同时检查 ID 是否与官方
// 模板冲突。它不写盘，供前端“验证”按钮使用。
func (m *Manager) ValidateCustomTemplate(yamlText string) (TemplateMeta, error) {
	meta, err := ParseTemplateYAML([]byte(yamlText))
	if err != nil {
		return TemplateMeta{}, err
	}
	if err := requireTemplateAuthor(meta); err != nil {
		return meta, err
	}
	if existing, ok := m.Index().Get(meta.ID); ok && existing.Source == SourceOfficial {
		return meta, fmt.Errorf("模板 id 与官方模板重复: %s，请改名后再保存", meta.ID)
	}
	return meta, nil
}

func requireTemplateAuthor(meta TemplateMeta) error {
	if strings.TrimSpace(meta.Author) == "" {
		return fmt.Errorf("模板缺少 info.author（nuclei 要求，例如 author: 4zreark）")
	}
	return nil
}

// SaveCustomTemplate 新建自定义模板。overwrite=false 时同 ID 已存在会报错；
// 文件固定写到 <customTemplatesDir>/<id>.yaml，采用临时文件 + rename 原子落盘。
func (m *Manager) SaveCustomTemplate(yamlText string, overwrite bool) (TemplateMeta, error) {
	meta, err := ParseTemplateYAML([]byte(yamlText))
	if err != nil {
		return TemplateMeta{}, err
	}
	if err := requireTemplateAuthor(meta); err != nil {
		return TemplateMeta{}, err
	}
	if existing, ok := m.Index().Get(meta.ID); ok {
		if existing.Source == SourceOfficial {
			return TemplateMeta{}, fmt.Errorf("模板 id 与官方模板重复: %s，请改名后再保存", meta.ID)
		}
		if !overwrite {
			return TemplateMeta{}, fmt.Errorf("自定义模板已存在: %s（请编辑或改名）", meta.ID)
		}
	}
	dir := m.CustomTemplatesDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return TemplateMeta{}, fmt.Errorf("创建自定义模板目录失败: %w", err)
	}
	rel := meta.ID + ".yaml"
	path := filepath.Join(dir, rel)
	if existing, ok := m.Index().Get(meta.ID); ok && existing.Source == SourceCustom {
		// 已存在（overwrite=true）时沿用原路径，兼容历史子目录文件。
		path = filepath.Join(dir, filepath.FromSlash(existing.Path))
		rel = existing.Path
	}
	if !withinDir(dir, path) {
		return TemplateMeta{}, fmt.Errorf("模板路径越出自定义目录")
	}
	if err := writeFileAtomic(path, yamlText); err != nil {
		return TemplateMeta{}, err
	}
	meta.Source = SourceCustom
	meta.Path = filepath.ToSlash(rel)
	m.invalidateIndex()
	return meta, nil
}

// UpdateCustomTemplate 更新一条已存在的自定义模板。更新时不允许改 ID，
// 需要换 ID 请新建后再删除旧模板。
func (m *Manager) UpdateCustomTemplate(id, yamlText string) (TemplateMeta, error) {
	id = strings.TrimSpace(id)
	existing, ok := m.Index().Get(id)
	if !ok {
		return TemplateMeta{}, fmt.Errorf("模板 ID 未找到: %s", id)
	}
	if existing.Source != SourceCustom {
		return TemplateMeta{}, fmt.Errorf("官方模板只读，不能编辑: %s", id)
	}
	meta, err := ParseTemplateYAML([]byte(yamlText))
	if err != nil {
		return TemplateMeta{}, err
	}
	if err := requireTemplateAuthor(meta); err != nil {
		return TemplateMeta{}, err
	}
	if !strings.EqualFold(meta.ID, id) {
		return TemplateMeta{}, fmt.Errorf("更新时不能修改模板 id（%s → %s）；请新建模板后再删除旧模板", id, meta.ID)
	}
	dir := m.CustomTemplatesDir()
	path := filepath.Join(dir, filepath.FromSlash(existing.Path))
	if !withinDir(dir, path) {
		return TemplateMeta{}, fmt.Errorf("模板路径越出自定义目录")
	}
	if err := writeFileAtomic(path, yamlText); err != nil {
		return TemplateMeta{}, err
	}
	meta.Source = SourceCustom
	meta.Path = existing.Path
	m.invalidateIndex()
	return meta, nil
}

// DeleteCustomTemplate 删除一条自定义模板。官方模板一律拒绝。
func (m *Manager) DeleteCustomTemplate(id string) error {
	id = strings.TrimSpace(id)
	meta, ok := m.Index().Get(id)
	if !ok {
		return fmt.Errorf("模板 ID 未找到: %s", id)
	}
	if meta.Source != SourceCustom {
		return fmt.Errorf("官方模板只读，不能删除: %s", id)
	}
	dir := m.CustomTemplatesDir()
	path := filepath.Join(dir, filepath.FromSlash(meta.Path))
	if !withinDir(dir, path) {
		return fmt.Errorf("模板路径越出自定义目录")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("删除模板失败: %w", err)
	}
	m.invalidateIndex()
	return nil
}

func writeFileAtomic(path, content string) error {
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	if len(content) > 1<<20 {
		return fmt.Errorf("模板超过 1MB 上限")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".template-*.yaml")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("写入模板失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("写入模板失败: %w", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("设置模板权限失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("保存模板失败: %w", err)
	}
	return nil
}

func withinDir(dir, path string) bool {
	root, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
