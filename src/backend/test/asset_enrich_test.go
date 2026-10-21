package test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 扫描结果里的指纹/图标应随 ImportRecords 自动落到站点画像与 asset_icons。
func TestImportRecordsStoresTechAndIcon(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("enrich%d", time.Now().UnixNano()),
		Name: "asset enrich test",
	})
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	iconPNG := makeTestPNG(t, 4, 4)
	sum := sha256.Sum256(iconPNG)
	sha := hex.EncodeToString(sum[:])
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM asset_icons WHERE sha256 = $1`, sha)
	})

	rec := repo.RawRecord{
		Host: "enrich.example", Port: 443, Protocol: "https", Value: "https://enrich.example",
		StatusCode: 200, Title: "enrich", Server: "nginx/1.24",
		Tech:       []string{"nginx", "Bootstrap"},
		IconSHA256: sha, IconMMH3: 123456, IconContentType: "image/png", IconData: iconPNG,
	}
	res, err := repo.NewAssetRepo().ImportRecords(ctx, project.ID, "scan", []repo.RawRecord{rec})
	if err != nil || res.NewSites != 1 {
		t.Fatalf("导入失败: %+v err=%v", res, err)
	}

	var tech, iconSHA, server string
	var iconMMH3 int64
	if err := r.Pool().QueryRow(ctx, `
		SELECT coalesce(tech::text,'[]'), coalesce(icon_sha256,''), coalesce(icon_mmh3,0)
		  FROM sites WHERE project_id = $1 AND host = 'enrich.example'`, project.ID).
		Scan(&tech, &iconSHA, &iconMMH3); err != nil {
		t.Fatalf("读取站点画像失败: %v", err)
	}
	if !bytes.Contains([]byte(tech), []byte("nginx")) || iconSHA != sha || iconMMH3 != 123456 {
		t.Fatalf("站点画像不符: tech=%s icon=%s mmh3=%d", tech, iconSHA, iconMMH3)
	}
	if err := r.Pool().QueryRow(ctx,
		`SELECT coalesce(server,'') FROM raw_records WHERE project_id = $1 AND host = 'enrich.example'`, project.ID).
		Scan(&server); err != nil {
		t.Fatalf("读取原始记录 server 失败: %v", err)
	}
	if server != "nginx/1.24" {
		t.Fatalf("raw_records.server 不符: %q", server)
	}
	icon, err := r.Clusters().GetIcon(ctx, sha)
	if err != nil || !bytes.Equal(icon.Data, iconPNG) {
		t.Fatalf("图标字节未落库: %+v err=%v", icon, err)
	}
}

// 只有 tcp 入口的站点不能按“失联”处理：HTTP 探测覆盖不到这些协议。
func TestProbeSiteSkipsNonHTTPEndpoints(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("nonhttp%d", time.Now().UnixNano()),
		Name: "non-http endpoint test",
	})
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
	})

	assets := repo.NewAssetRepo()
	if _, err := assets.ImportRecords(ctx, project.ID, "scan", []repo.RawRecord{
		{Host: "nonhttp.example", Port: 22, Protocol: "tcp", Value: "nonhttp.example:22"},
	}); err != nil {
		t.Fatalf("导入 tcp 入口失败: %v", err)
	}
	siteID, err := assets.SiteIDByHost(ctx, project.ID, "nonhttp.example")
	if err != nil {
		t.Fatal(err)
	}
	report, err := service.NewVerifyService().ProbeSite(ctx, siteID)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if report.Verdict != "inconclusive" || report.ReasonCode != "non_http_only" {
		t.Fatalf("非 HTTP 入口应判 inconclusive/non_http_only，实际 %+v", report)
	}
	var state string
	if err := r.Pool().QueryRow(ctx, `SELECT state FROM sites WHERE id = $1`, siteID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state == "lost" {
		t.Fatal("非 HTTP 入口不能把站点判成 lost")
	}
}
