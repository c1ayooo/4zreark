package test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 导入的部分失败语义（pending-fixes P1-4）：
// 资产是主产物、指纹是附属——命中名在规则库查不到时只跳过并记明细，
// 不阻断资产落库。这里锁住：导入成功、站点在库、计数与明细都能对上名字。
//
// 边界说明：SAVEPOINT 降级路径（指纹 INSERT 在事务里真抛错，验证资产仍落库）
// 需要侵入式手段（如临时改表结构或 mock 事务）才能构造，本测试刻意不硬造，
// 该路径由代码评审兜底。
func TestImportRecordsSemantics(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	missingRule := "no-such-rule-" + suffix

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: "imprt" + suffix, Name: "import semantics test",
	})
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(),
			`DELETE FROM fingerprint_hits WHERE site_id IN (SELECT id FROM sites WHERE project_id = $1)`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM sites WHERE project_id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
	})

	host := "import-sem-" + suffix + ".example.com"
	res, err := repo.NewAssetRepo().ImportRecords(ctx, project.ID, "scan", []repo.RawRecord{
		{Host: host, Port: 443, Protocol: "https", StatusCode: 200, Fingerprints: []string{missingRule}},
	})
	if err != nil {
		t.Fatalf("导入应成功（未知规则名只降级不回滚资产）: %v", err)
	}
	if res.UnmatchedRules <= 0 {
		t.Fatalf("未收录规则名计数应 > 0，实际 %d", res.UnmatchedRules)
	}
	if !slices.Contains(res.SkippedRuleNames, missingRule) {
		t.Fatalf("SkippedRuleNames 应含 %q，实际 %v", missingRule, res.SkippedRuleNames)
	}

	siteID, err := repo.NewAssetRepo().SiteIDByHost(ctx, project.ID, host)
	if err != nil {
		t.Fatalf("站点应在库（指纹降级不得影响资产主干）: %v", err)
	}
	if siteID <= 0 {
		t.Fatalf("站点 ID 应 > 0，实际 %d", siteID)
	}
}
