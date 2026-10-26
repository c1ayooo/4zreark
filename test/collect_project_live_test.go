package test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/internal/enterprise"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// TestCollectForProjectLive 按项目名从数据源（当前支持 xiaolanben）采集企业线索与
// 数字资产候选并落库——给真实项目做首轮数据填充用，不清理数据。
//
// 环境变量：ZRE_PG_PASSWORD、XLB_USER、XLB_PASS 必填；
// COLLECT_PROJECT（项目名，必填）、COLLECT_KEYWORD（检索词，默认项目名）、
// COLLECT_LIMIT（企业数上限，默认 5，最大 10）、COLLECT_MAX_ASSETS（单企业资产上限，默认 200）。
func TestCollectForProjectLive(t *testing.T) {
	user, pass := os.Getenv("XLB_USER"), os.Getenv("XLB_PASS")
	projectName := os.Getenv("COLLECT_PROJECT")
	if user == "" || pass == "" || projectName == "" {
		t.Skip("未设置 XLB_USER / XLB_PASS / COLLECT_PROJECT")
	}
	keyword := os.Getenv("COLLECT_KEYWORD")
	if keyword == "" {
		keyword = projectName
	}
	limit := 5
	if v := os.Getenv("COLLECT_LIMIT"); v != "" {
		fmt.Sscanf(v, "%d", &limit)
	}
	if limit <= 0 || limit > 10 {
		limit = 5
	}
	maxAssets := 200
	if v := os.Getenv("COLLECT_MAX_ASSETS"); v != "" {
		fmt.Sscanf(v, "%d", &maxAssets)
	}

	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var projectID int64
	err := r.Pool().QueryRow(ctx,
		`SELECT id FROM projects WHERE name = $1`, projectName).Scan(&projectID)
	if err != nil {
		err = r.Pool().QueryRow(ctx,
			`SELECT id FROM projects WHERE name ILIKE $1`, "%"+projectName+"%").Scan(&projectID)
	}
	if err != nil {
		t.Fatalf("找不到项目 %q: %v", projectName, err)
	}
	t.Logf("目标项目 #%d %q，检索词 %q，企业上限 %d", projectID, projectName, keyword, limit)

	provider, err := enterprise.NewXiaolanbenProvider(user, pass, "")
	if err != nil {
		t.Fatalf("构造数据源失败: %v", err)
	}
	dp, ok := provider.(enterprise.DigitalAssetsProvider)
	if !ok {
		t.Fatal("数据源不支持数字资产采集")
	}

	refs, err := provider.Search(ctx, keyword, limit)
	if err != nil {
		t.Fatalf("企业检索失败: %v", err)
	}
	t.Logf("检索到 %d 家企业", len(refs))

	dig := service.NewDigitalService()
	warnings := []string{}
	totalHits, totalCandidates, totalImported := 0, 0, 0
	for _, ref := range refs {
		// 企业线索：详情落库（域名/备案仅随线索存储，不入站点库）。
		detail, derr := provider.Detail(ctx, ref.ExtID)
		if derr != nil || detail == nil {
			warnings = append(warnings, ref.Name+"：详情获取失败")
		} else {
			icps := map[string]bool{}
			domains := make([]repo.EnterpriseDomain, 0, len(detail.Domains))
			for _, d := range detail.Domains {
				domains = append(domains, repo.EnterpriseDomain{
					Domain: d.Domain, Site: d.Site, ICP: d.ICP, Evidence: d.Evidence,
				})
				if d.ICP != "" {
					icps[d.ICP] = true
				}
			}
			icpList := make([]string, 0, len(icps))
			for v := range icps {
				icpList = append(icpList, v)
			}
			capWan, _ := enterprise.ParseCapitalWan(detail.RegisteredCapital)
			if _, uerr := r.Enterprises().Upsert(ctx, projectID, repo.EnterpriseInput{
				Name: detail.Name, LegalPerson: detail.LegalPerson, OpenStatus: detail.OpenStatus,
				CreditCode: detail.CreditCode, Address: detail.Address, Industry: detail.Industry,
				RegisteredCapital: detail.RegisteredCapital, RegisteredCapitalWan: capWan,
				ICPNumbers: icpList, Domains: domains,
				Source: "xiaolanben", Status: "unverified", Notes: "来自小蓝本检索（" + keyword + "）",
			}); uerr != nil {
				warnings = append(warnings, ref.Name+"：企业线索入库失败")
			} else {
				t.Logf("企业线索: %s（%s，%s）", detail.Name, detail.OpenStatus, detail.Industry)
			}
		}

		// 数字资产：候选入池（对账语义保证不重复）。
		hits, _, herr := dp.DigitalAssets(ctx, ref.ExtID, 1, maxAssets)
		if herr != nil {
			warnings = append(warnings, ref.Name+"：数字资产拉取失败")
			continue
		}
		items := make([]repo.DigitalCandidateInput, 0, len(hits))
		for _, h := range hits {
			entityName := h.EntityName
			if entityName == "" {
				entityName = ref.Name
			}
			companyName := h.Company
			if companyName == "" {
				companyName = ref.Name
			}
			items = append(items, repo.DigitalCandidateInput{
				Kind: h.Kind, Name: h.Name, Company: companyName, Platform: h.Platform,
				Source: "xiaolanben", EntityName: entityName, Evidence: h.Evidence,
			})
		}
		if len(items) == 0 {
			t.Logf("  %s：无数字资产", ref.Name)
			continue
		}
		candidates, imported, uerr := dig.UpsertCandidates(ctx, projectID, items)
		if uerr != nil {
			warnings = append(warnings, ref.Name+"：候选入池失败")
			continue
		}
		totalHits += len(items)
		totalCandidates += int(candidates)
		totalImported += int(imported)
		t.Logf("  %s：资产 %d 条（新候选 %d，已在名单 %d）", ref.Name, len(items), candidates, imported)
		time.Sleep(2 * time.Second) // 上游节奏放缓
	}

	t.Logf("==== 汇总：资产 %d 条，新候选 %d，已在名单 %d，警告 %d",
		totalHits, totalCandidates, totalImported, len(warnings))
	for _, w := range warnings {
		t.Logf("WARN %s", w)
	}

	items, total, err := dig.ListCandidates(ctx, repo.DigitalCandidateFilter{
		ProjectID: projectID, Status: "candidate", Page: 1, PageSize: 100,
	})
	if err != nil {
		t.Fatalf("候选列表失败: %v", err)
	}
	t.Logf("==== 项目 %q 待确认候选 %d 条：", projectName, total)
	for _, c := range items {
		if c.ID == 0 {
			continue
		}
		t.Logf("  [%s] %s | %s | 来源企业=%s",
			strings.ToUpper(c.Kind[:1])+c.Kind[1:], c.Name, c.Platform, c.EntityName)
	}
}
