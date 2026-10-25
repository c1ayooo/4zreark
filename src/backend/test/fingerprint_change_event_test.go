package test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 指纹集合变化要产生 fingerprint_change 事件：变更时间线此前对
// 「指纹消失」完全不可见（只记新增，不记移除）。
func TestFingerprintChangeEvent(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	ruleAlpha := "fpchg-alpha-" + suffix
	ruleBeta := "fpchg-beta-" + suffix

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: "fpchg" + suffix, Name: "fingerprint change test",
	})
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		for _, name := range []string{ruleAlpha, ruleBeta} {
			_ = r.Fingerprints().DeleteRule(context.Background(), name)
		}
		_, _ = r.Pool().Exec(context.Background(),
			`DELETE FROM asset_events WHERE project_id = $1 AND event_type = 'fingerprint_change'`, project.ID)
		_, _ = r.Pool().Exec(context.Background(),
			`DELETE FROM fingerprint_hits WHERE site_id IN (SELECT id FROM sites WHERE project_id = $1)`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM sites WHERE project_id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		service.NewFingerprintService().Invalidate()
	})

	enabled := true
	fpRepo := r.Fingerprints()
	// id 列是 char(24)，用 ObjectID hex；name 唯一即可。
	ids := map[string]string{
		ruleAlpha: oid.NewObjectID().Hex(),
		ruleBeta:  oid.NewObjectID().Hex(),
	}
	for name, kw := range map[string]string{
		ruleAlpha: "AlphaLanding", ruleBeta: "BetaConsole",
	} {
		if err := fpRepo.UpsertRule(ctx, &repo.FpRule{
			ID: ids[name], Name: name, Enabled: enabled, DSLVersion: 2,
			Condition: &repo.Condition{Type: "title", Op: "contains", Value: kw},
			Source:    "test",
		}); err != nil {
			t.Fatalf("写入规则 %s 失败: %v", name, err)
		}
	}
	svc := service.NewFingerprintService()
	svc.Invalidate()

	if _, err := repo.NewAssetRepo().ImportRecords(ctx, project.ID, "test", []repo.RawRecord{
		{Host: "fpchg.example.com", Port: 443, Protocol: "https", Value: "https://fpchg.example.com"},
	}); err != nil {
		t.Fatalf("导入测试站点失败: %v", err)
	}
	siteID, err := repo.NewAssetRepo().SiteIDByHost(ctx, project.ID, "fpchg.example.com")
	if err != nil {
		t.Fatal(err)
	}

	// 第一轮：命中 Alpha。
	if _, _, err := svc.ApplyToSite(ctx, siteID, service.ResponseSnapshot{
		StatusCode: 200, Title: "Welcome to AlphaLanding",
	}, nil); err != nil {
		t.Fatalf("第一轮 ApplyToSite 失败: %v", err)
	}
	countEvents := func() int {
		n := 0
		if err := r.Pool().QueryRow(ctx, `
SELECT count(*) FROM asset_events
 WHERE site_id = $1 AND event_type = 'fingerprint_change'`, siteID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := countEvents(); n != 0 {
		t.Fatalf("首轮命中不应产生事件（无旧集合可比）, got %d", n)
	}

	// 第二轮：换成 Beta —— Alpha 移除、Beta 新增，应有一条事件。
	if _, _, err := svc.ApplyToSite(ctx, siteID, service.ResponseSnapshot{
		StatusCode: 200, Title: "BetaConsole Login",
	}, nil); err != nil {
		t.Fatalf("第二轮 ApplyToSite 失败: %v", err)
	}
	if n := countEvents(); n != 1 {
		t.Fatalf("指纹集合变化应产生恰好 1 条事件, got %d", n)
	}

	var title string
	var beforeRaw, afterRaw []byte
	if err := r.Pool().QueryRow(ctx, `
SELECT title, before, after FROM asset_events
 WHERE site_id = $1 AND event_type = 'fingerprint_change'
 ORDER BY created_at DESC LIMIT 1`, siteID).Scan(&title, &beforeRaw, &afterRaw); err != nil {
		t.Fatal(err)
	}
	if title != "指纹变化：+"+ruleBeta+" -"+ruleAlpha {
		t.Errorf("事件标题 = %q", title)
	}
	var before, after map[string]any
	_ = json.Unmarshal(beforeRaw, &before)
	_ = json.Unmarshal(afterRaw, &after)
	if got, _ := before["technologies"].([]any); len(got) != 1 || got[0] != ruleAlpha {
		t.Errorf("before.technologies = %v, want [%s]", got, ruleAlpha)
	}
	if got, _ := after["technologies"].([]any); len(got) != 1 || got[0] != ruleBeta {
		t.Errorf("after.technologies = %v, want [%s]", got, ruleBeta)
	}

	// 第三轮：同样命中 Beta，集合未变，不应再产生事件。
	if _, _, err := svc.ApplyToSite(ctx, siteID, service.ResponseSnapshot{
		StatusCode: 200, Title: "BetaConsole Dashboard",
	}, nil); err != nil {
		t.Fatalf("第三轮 ApplyToSite 失败: %v", err)
	}
	if n := countEvents(); n != 1 {
		t.Fatalf("集合未变不应重复产生事件, got %d", n)
	}
}
