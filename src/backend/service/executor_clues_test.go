package service

import (
	"testing"

	"github.com/c1ayooo/4zreark/models"
)

func TestClueResultContract(t *testing.T) {
	task := &models.Task{Name: "t7"}
	r := clueResult(task, "example.com", "saas", "zendesk", "Zendesk（客服）", "saas-rules",
		map[string]interface{}{"service_id": "zendesk"})

	if r.Type != models.ResultTypeClue {
		t.Fatalf("结果类型应为 clue，实际 %s", r.Type)
	}
	for _, k := range []string{"kind", "domain", "value", "detail", "source", "service_id"} {
		if _, ok := r.Data[k]; !ok {
			t.Fatalf("Data 缺字段 %q: %+v", k, r.Data)
		}
	}
	if len(r.Tags) != 2 || r.Tags[0] != "clue" || r.Tags[1] != "saas" {
		t.Fatalf("Tags 不符: %+v", r.Tags)
	}
}
