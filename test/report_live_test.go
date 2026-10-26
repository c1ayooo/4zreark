package test

import (
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
)

// 报告生成 P0：真实库取数 -> HTML 渲染 -> 落 vuln_reports -> 文件可读。
func TestReportGenerateLive(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	suffix := fmt.Sprintf("smoke-report-%d", time.Now().UnixNano())
	names := []string{"冒烟 SQL 注入", "冒烟越权访问", "冒烟信息泄露"}
	severities := []string{"critical", "high", "medium"}
	for i := range names {
		sum := md5.Sum([]byte(fmt.Sprintf("%s-%d", suffix, i)))
		id := fmt.Sprintf("%x", sum)[:24]
		if _, err := r.Pool().Exec(ctx, `
insert into vulnerabilities (id, name, description, severity, status, type, template_id,
                             target, request, response, solution)
values ($1,$2,$3,$4,'new','web',$5,$6,$7,$8,$9)`,
			id, names[i], "冒烟报告证据", severities[i], suffix+"-"+fmt.Sprint(i),
			"https://example.test/"+fmt.Sprint(i),
			"GET /"+fmt.Sprint(i)+" HTTP/1.1\nHost: example.test",
			"HTTP/1.1 200 OK\n\nproof-"+fmt.Sprint(i),
			"修复建议：参数化查询 / 权限校验",
		); err != nil {
			t.Fatalf("准备漏洞失败: %v", err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `delete from vulnerabilities where template_id like $1`, suffix+"%")
	})

	svc := service.NewReportService()
	rep, err := svc.Generate(ctx, service.ReportGenInput{
		Name: suffix, Title: "冒烟安全评估报告", Format: "html",
	})
	if err != nil {
		t.Fatalf("生成报告失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = r.Pool().Exec(bg, `delete from vuln_reports where id=$1`, rep.ID.Hex())
		if rep.FilePath != "" {
			_ = os.Remove(rep.FilePath)
		}
	})

	if rep.Type != "html" || rep.FilePath == "" {
		t.Fatalf("报告台账不符: type=%s path=%s", rep.Type, rep.FilePath)
	}
	data, err := os.ReadFile(rep.FilePath)
	if err != nil {
		t.Fatalf("读取报告文件失败: %v", err)
	}
	html := string(data)
	for _, want := range []string{"冒烟安全评估报告", "冒烟 SQL 注入", "冒烟越权访问", "冒烟信息泄露", "critical"} {
		if !strings.Contains(html, want) {
			t.Errorf("报告缺少 %q（长度 %d）", want, len(html))
		}
	}
	if !strings.Contains(html, "修复建议") {
		t.Error("报告缺少修复建议段落")
	}

	// Chrome 可用时顺带验证 PDF 分支；没有浏览器则跳过（HTML 降级语义已由服务保证）。
	if _, lookErr := exec.LookPath("google-chrome"); lookErr == nil {
		pdfRep, perr := svc.Generate(ctx, service.ReportGenInput{
			Name: suffix + "-pdf", Title: "冒烟安全评估报告", Format: "pdf",
		})
		if perr != nil {
			t.Fatalf("生成 PDF 失败: %v", perr)
		}
		t.Cleanup(func() {
			bg := context.Background()
			_, _ = r.Pool().Exec(bg, `delete from vuln_reports where id=$1`, pdfRep.ID.Hex())
			if pdfRep.FilePath != "" {
				_ = os.Remove(pdfRep.FilePath)
			}
		})
		if pdfRep.Type != "pdf" || filepath.Ext(pdfRep.FilePath) != ".pdf" {
			t.Fatalf("PDF 报告不符: type=%s path=%s", pdfRep.Type, pdfRep.FilePath)
		}
		st, serr := os.Stat(pdfRep.FilePath)
		if serr != nil {
			t.Fatalf("PDF 文件不存在: %v", serr)
		}
		if st.Size() < 1000 {
			t.Fatalf("PDF 文件过小: %d", st.Size())
		}
	}
}
