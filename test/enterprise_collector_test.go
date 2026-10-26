package test

import (
	"context"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// fakeProvider 固定拓扑：root -> (branch b1, invest i1) -> deep。
type fakeProvider struct{}

func (f *fakeProvider) Name() string { return "fake" }
func (f *fakeProvider) Search(context.Context, string, int) ([]enterprise.CompanyRef, error) {
	return []enterprise.CompanyRef{{ExtID: "root", Name: "根企业"}}, nil
}
func (f *fakeProvider) Detail(_ context.Context, extID string) (*enterprise.CompanyDetail, error) {
	d := &enterprise.CompanyDetail{ExtID: extID, Name: extID + "-公司", OpenStatus: "在业"}
	if extID == "root" {
		d.Domains = []enterprise.DomainHit{{Domain: "Root.Com", Site: "官网", ICP: "京ICP证000001号"}}
	}
	return d, nil
}
func (f *fakeProvider) Branches(_ context.Context, extID string, page, _ int) ([]enterprise.CompanyRef, bool, error) {
	if extID == "root" && page == 1 {
		return []enterprise.CompanyRef{{ExtID: "b1", Name: "分支一"}, {ExtID: "root", Name: "根企业"}}, false, nil
	}
	return nil, false, nil
}
func (f *fakeProvider) Investments(_ context.Context, extID string, page, _ int) ([]enterprise.CompanyRef, bool, error) {
	if extID == "root" && page == 1 {
		return []enterprise.CompanyRef{{ExtID: "i1", Name: "投资一"}}, false, nil
	}
	if extID == "i1" && page == 1 {
		return []enterprise.CompanyRef{{ExtID: "deep", Name: "深层企业"}}, false, nil
	}
	return nil, false, nil
}
func (f *fakeProvider) Domains(_ context.Context, extID string, page, _ int) ([]enterprise.DomainHit, bool, error) {
	if extID == "i1" && page == 1 {
		return []enterprise.DomainHit{{Domain: "https://Sub.Example.com/path", ICP: "粤ICP备000002号"}}, false, nil
	}
	return nil, false, nil
}

// 4zreco collector 的移植验收：BFS 深度、节点去重、实体树、候选域名归一化。
func TestEnterpriseCollectorBFS(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := fmt.Sprintf("ent-bfs-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
	})

	c := enterprise.NewCollector(r, log.New(io.Discard, "", 0))
	c.SetRateLimit(0)
	job, err := c.Start(ctx, &fakeProvider{}, enterprise.Job{
		ProjectID: fmt.Sprint(projectID), Owner: "tester", Provider: "fake",
		Keyword: "根企业", Depth: 2, MaxNodes: 10,
	}, enterprise.CompanyRef{ExtID: "root", Name: "根企业"})
	if err != nil {
		t.Fatalf("启动采集失败: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := r.GetEnterpriseJob(ctx, job.ID)
		if err != nil {
			t.Fatalf("读取任务失败: %v", err)
		}
		if got.Status != "running" {
			if got.Status != "done" {
				t.Fatalf("任务状态=%s error=%q", got.Status, got.Error)
			}
			// root + b1 + i1 + deep = 4；root 在分支列表里重复出现被 visited 去重
			if got.Entities != 4 || got.Domains != 2 || got.Nodes != 4 {
				t.Fatalf("任务计数不符: %+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("等待采集任务超时")
		}
		time.Sleep(20 * time.Millisecond)
	}

	var branchType, parent string
	var depth int
	if err := r.Pool().QueryRow(ctx,
		`select entity_type, parent_ext_id, depth from enterprise_entities where project_id=$1 and ext_id='b1'`,
		projectID).Scan(&branchType, &parent, &depth); err != nil {
		t.Fatalf("分支实体未落库: %v", err)
	}
	if branchType != "branch" || parent != "root" || depth != 1 {
		t.Fatalf("分支关系错误: type=%s parent=%s depth=%d", branchType, parent, depth)
	}

	candidates, err := r.ListEnterpriseCandidates(ctx, projectID, "", 50)
	if err != nil {
		t.Fatalf("候选域名查询失败: %v", err)
	}
	found := map[string]bool{}
	for _, a := range candidates {
		found[a.Value] = true
	}
	if !found["root.com"] || !found["sub.example.com"] {
		t.Fatalf("候选域名归一化缺失: %+v", candidates)
	}
}

func TestNormalizeDomainExported(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/a?b=1": "example.com",
		"http://sub.x.cn:8080/":     "sub.x.cn",
		"  BAD_DOMAIN;; ":           "",
		"localhost":                 "",
		"ok-co.io":                  "ok-co.io",
	}
	for in, want := range cases {
		if got := enterprise.NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q)=%q want %q", in, got, want)
		}
	}
}

// digitalSinkProvider 在 fakeProvider 拓扑上叠加数字资产拉取。
type digitalSinkProvider struct{ fakeProvider }

func (f *digitalSinkProvider) DigitalAssets(_ context.Context, extID string, _, _ int) ([]enterprise.DigitalHit, bool, error) {
	return []enterprise.DigitalHit{
		{Kind: "app", Name: "BFS-" + extID + "-App", Platform: "Android", Evidence: "详情页 apps"},
		{Kind: "miniapp", Name: "BFS-" + extID + "-Mini", Platform: "微信"},
	}, false, nil
}

// BFS 顺带数字资产：每个实体详情后入候选池，任务统计含 digital；域名采集不受影响。
func TestEnterpriseCollectorDigitalSink(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := fmt.Sprintf("ent-dig-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
	})

	c := enterprise.NewCollector(r, log.New(io.Discard, "", 0))
	c.SetRateLimit(0)
	job, err := c.StartWithDigitalSink(ctx, &digitalSinkProvider{}, enterprise.Job{
		ProjectID: fmt.Sprint(projectID), Owner: "tester", Provider: "fake",
		Keyword: "根企业", Depth: 2, MaxNodes: 10,
	}, enterprise.CompanyRef{ExtID: "root", Name: "根企业"}, &digitalSinkProvider{})
	if err != nil {
		t.Fatalf("启动采集失败: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	var done enterprise.Job
	for {
		got, err := r.GetEnterpriseJob(ctx, job.ID)
		if err != nil {
			t.Fatalf("读取任务失败: %v", err)
		}
		if got.Status != "running" {
			done = got
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("任务未在期限内结束: %+v", got)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if done.Status != "done" || done.Digital < 2 {
		t.Fatalf("任务结果不符: status=%s digital=%d (期望 done 且 >=2)", done.Status, done.Digital)
	}

	dig := service.NewDigitalService()
	items, total, err := dig.ListCandidates(ctx, repo.DigitalCandidateFilter{ProjectID: projectID})
	if err != nil || total < 2 {
		t.Fatalf("数字资产候选不符: total=%d len=%d err=%v", total, len(items), err)
	}
	for _, it := range items {
		if it.Source != "fake" || it.EntityName == "" {
			t.Fatalf("候选来源/归属企业不符: %+v", it)
		}
	}
}

// groupExpandProvider 在数字资产 sink 之上叠加集团成员枚举。
type groupExpandProvider struct{ digitalSinkProvider }

func (f *groupExpandProvider) GroupCompanies(_ context.Context, extID string, page, _ int) ([]enterprise.CompanyRef, bool, error) {
	if extID == "root" && page == 1 {
		return []enterprise.CompanyRef{{ExtID: "g1", Name: "集团成员一"}}, false, nil
	}
	return nil, false, nil
}

// BFS 集团展开：ExpandGroup=true 时 group 实体入树；false（或不支持）不展开。
func TestEnterpriseCollectorGroupExpand(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := fmt.Sprintf("ent-grp-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
	})

	runJob := func(expandGroup bool) {
		c := enterprise.NewCollector(r, log.New(io.Discard, "", 0))
		c.SetRateLimit(0)
		job, err := c.StartWithDigitalSink(ctx, &groupExpandProvider{}, enterprise.Job{
			ProjectID: fmt.Sprint(projectID), Owner: "tester", Provider: "fake",
			Keyword: "根企业", Depth: 2, MaxNodes: 20, ExpandGroup: expandGroup,
		}, enterprise.CompanyRef{ExtID: "root", Name: "根企业"}, &groupExpandProvider{})
		if err != nil {
			t.Fatalf("启动采集失败: %v", err)
		}
		deadline := time.Now().Add(20 * time.Second)
		for {
			got, gerr := r.GetEnterpriseJob(ctx, job.ID)
			if gerr != nil {
				t.Fatalf("读取任务失败: %v", gerr)
			}
			if got.Status != "running" {
				if got.Status != "done" {
					t.Fatalf("任务异常结束: %+v", got)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("任务未在期限内结束")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	// 先跑一次不展开，建立基线（root/b1/i1/deep）
	runJob(false)
	var groupCount int
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := r.Pool().QueryRow(ctx,
			`SELECT count(*) FROM enterprise_entities WHERE project_id=$1 AND entity_type='group'`,
			projectID).Scan(&groupCount); err != nil {
			t.Fatalf("查询 group 实体失败: %v", err)
		}
		if groupCount == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if groupCount != 0 {
		t.Fatalf("未开启展开时不应有 group 实体: %d", groupCount)
	}

	// 再跑展开：g1 应以 entity_type=group 入树
	runJob(true)
	deadline = time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if err := r.Pool().QueryRow(ctx,
			`SELECT count(*) FROM enterprise_entities WHERE project_id=$1 AND entity_type='group'`,
			projectID).Scan(&groupCount); err != nil {
			t.Fatalf("查询 group 实体失败: %v", err)
		}
		if groupCount > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if groupCount != 1 {
		t.Fatalf("展开后应有 1 个 group 实体: %d", groupCount)
	}
}

// groupDomainsProvider 给集团成员 g1 配带 ICP 的域名，验证 group 口径不自动转种子。
func (f *groupExpandProvider) Domains(ctx context.Context, extID string, page, size int) ([]enterprise.DomainHit, bool, error) {
	if extID == "g1" && page == 1 {
		return []enterprise.DomainHit{{Domain: "g1-mcd.com", ICP: "粤ICP备33333333号", Site: "成员站"}}, false, nil
	}
	return f.fakeProvider.Domains(ctx, extID, page, size)
}

// 备案归属自动转种子：root/invest 的 ICP 域名转种子并置 imported；
// group 成员的 ICP 域名保持 candidate 人工确认。
func TestEnterpriseCollectorAutoSeed(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := fmt.Sprintf("ent-autoseed-%d", time.Now().UnixNano())
	var projectID int64
	if err := r.Pool().QueryRow(ctx,
		`INSERT INTO projects (code, name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&projectID); err != nil {
		t.Fatalf("建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id=$1`, projectID)
	})

	c := enterprise.NewCollector(r, log.New(io.Discard, "", 0))
	c.SetRateLimit(0)
	job, err := c.StartWithDigitalSink(ctx, &groupExpandProvider{}, enterprise.Job{
		ProjectID: fmt.Sprint(projectID), Owner: "tester", Provider: "fake",
		Keyword: "根企业", Depth: 2, MaxNodes: 20, ExpandGroup: true,
	}, enterprise.CompanyRef{ExtID: "root", Name: "根企业"}, &groupExpandProvider{})
	if err != nil {
		t.Fatalf("启动采集失败: %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		got, gerr := r.GetEnterpriseJob(ctx, job.ID)
		if gerr != nil {
			t.Fatalf("读取任务失败: %v", gerr)
		}
		if got.Status != "running" {
			if got.Status != "done" {
				t.Fatalf("任务异常: %s %q", got.Status, got.Error)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("任务超时")
		}
		time.Sleep(50 * time.Millisecond)
	}

	seedExists := func(domain string) bool {
		var ok bool
		if err := r.Pool().QueryRow(ctx,
			`select exists(select 1 from seeds where project_id=$1 and kind='domain' and value=$2)`,
			projectID, domain).Scan(&ok); err != nil {
			t.Fatalf("查种子失败: %v", err)
		}
		return ok
	}
	candStatus := func(domain string) string {
		var st string
		if err := r.Pool().QueryRow(ctx,
			`select status from enterprise_candidates where project_id=$1 and domain=$2`,
			projectID, domain).Scan(&st); err != nil {
			return "<missing>"
		}
		return st
	}

	// fakeProvider.Detail: root 域名 Root.Com 带 ICP；Domains(): i1 的 Sub.Example.com 带条 ICP → 都应转种子
	if !seedExists("root.com") || !seedExists("sub.example.com") {
		t.Fatalf("ICP 归属域名应自动转种子: root.com=%v sub.example.com=%v",
			seedExists("root.com"), seedExists("sub.example.com"))
	}
	if st := candStatus("root.com"); st != "imported" {
		t.Fatalf("root.com 候选应置 imported: %s", st)
	}
	// 集团成员 g1 的域名不自动转，保持人工确认
	if seedExists("g1-mcd.com") {
		t.Fatal("group 成员域名不应自动转种子")
	}
	if st := candStatus("g1-mcd.com"); st != "candidate" {
		t.Fatalf("g1-mcd.com 应保持 candidate: %s", st)
	}
}
