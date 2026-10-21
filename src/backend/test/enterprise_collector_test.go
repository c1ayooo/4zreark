package test

import (
	"context"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
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
