package nucleiruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func officialTemplate(id string) string {
	return `
id: ` + id + `
info:
  name: Demo RCE
  author: 4zreark
  severity: critical
  tags: demo,rce
http:
  - method: GET
    path:
      - "{{BaseURL}}/x"
`
}

func customTemplate(id string) string {
	return `
id: ` + id + `
info:
  name: Custom Check
  author: 4zreark
  severity: medium
  tags: custom
http:
  - method: GET
    path:
      - "{{BaseURL}}/custom"
`
}

func TestMultiIndexSourceAndRead(t *testing.T) {
	root := t.TempDir()
	official := filepath.Join(root, "templates")
	custom := filepath.Join(root, "custom-templates")
	writeFile(t, filepath.Join(official, "http", "demo.yaml"), officialTemplate("official-demo"))
	writeFile(t, filepath.Join(custom, "http", "mine.yaml"), customTemplate("custom-mine"))

	idx := NewMultiIndex([]IndexDir{
		{Path: official, Source: SourceOfficial},
		{Path: custom, Source: SourceCustom},
	})
	items, total, err := idx.List(ListOptions{Page: 1, Size: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("list = %d/%d", total, len(items))
	}
	items, total, err = idx.List(ListOptions{Filters: Filters{Source: SourceCustom}, Page: 1, Size: 10})
	if err != nil || total != 1 || items[0].Source != SourceCustom {
		t.Fatalf("custom filter: %+v %d %v", items, total, err)
	}
	meta, content, err := idx.Read("custom-mine")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Source != SourceCustom || !strings.Contains(content, "Custom Check") {
		t.Fatalf("read: %+v %q", meta, content)
	}
	paths, err := idx.Resolve([]string{"custom/custom-mine"})
	if err != nil || len(paths) != 1 || !strings.HasPrefix(paths[0], custom) {
		t.Fatalf("resolve custom = %v, %v", paths, err)
	}
	if _, err := idx.Resolve([]string{"custom/official-demo"}); err == nil {
		t.Fatal("source-prefixed miss should fail")
	}
}

func TestCustomTemplateCRUD(t *testing.T) {
	root := t.TempDir()
	// 官方模板用于验证 ID 冲突。
	writeFile(t, filepath.Join(root, "templates", "http", "official.yaml"), officialTemplate("official-demo"))
	m := New(root, nil)

	if _, err := m.ValidateCustomTemplate(`id: bad`); err == nil {
		t.Fatal("invalid template should fail validation")
	}
	if _, err := m.SaveCustomTemplate(officialTemplate("official-demo"), false); err == nil {
		t.Fatal("official id collision should be rejected")
	}

	saved, err := m.SaveCustomTemplate(customTemplate("custom-mine"), false)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Source != SourceCustom || saved.Path != "custom-mine.yaml" {
		t.Fatalf("saved = %+v", saved)
	}
	path := filepath.Join(root, "custom-templates", "custom-mine.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("custom file missing: %v", err)
	}
	if _, err := m.SaveCustomTemplate(customTemplate("custom-mine"), false); err == nil {
		t.Fatal("duplicate save without overwrite should fail")
	}

	meta, content, err := m.Index().Read("custom-mine")
	if err != nil || meta.Source != SourceCustom || !strings.Contains(content, "Custom Check") {
		t.Fatalf("read custom: %+v %q %v", meta, content, err)
	}

	updated := strings.ReplaceAll(customTemplate("custom-mine"), "Custom Check", "Custom Check v2")
	if _, err := m.UpdateCustomTemplate("custom-mine", updated); err != nil {
		t.Fatal(err)
	}
	if _, content, _ := m.Index().Read("custom-mine"); !strings.Contains(content, "v2") {
		t.Fatalf("update not persisted: %q", content)
	}
	if _, err := m.UpdateCustomTemplate("official-demo", updated); err == nil {
		t.Fatal("official template update must be rejected")
	}

	if err := m.DeleteCustomTemplate("official-demo"); err == nil {
		t.Fatal("official template delete must be rejected")
	}
	if err := m.DeleteCustomTemplate("custom-mine"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("custom file should be gone, stat err=%v", err)
	}
}
