package test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// 新导入的 HTTP 站点会被后台自动验证；只有 tcp 入口的站点不参与 HTTP 存活探测。
func TestAutoVerifyPendingSites(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("auto%d", time.Now().UnixNano()),
		Name: "auto verify test",
	})
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte("<html><title>auto verify</title></html>"))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	assets := repo.NewAssetRepo()
	if _, err := assets.ImportRecords(ctx, project.ID, "scan", []repo.RawRecord{
		{Host: "127.0.0.1", Port: port, Protocol: "http", Value: fmt.Sprintf("http://127.0.0.1:%d", port)},
		{Host: "tcp-only.example", Port: 22, Protocol: "tcp", Value: "tcp-only.example:22"},
	}); err != nil {
		t.Fatalf("导入站点失败: %v", err)
	}

	svc := service.NewAutoVerifyService()
	stats, err := svc.RunOnce(ctx, project.ID, 10)
	if err != nil {
		t.Fatalf("自动验证失败: %v", err)
	}
	if stats.Picked != 1 || stats.Reachable != 1 {
		t.Fatalf("自动验证统计不符: %+v", stats)
	}

	var state string
	var status int
	if err := r.Pool().QueryRow(ctx, `
		SELECT state, http_status FROM sites WHERE project_id = $1 AND host = '127.0.0.1'`, project.ID).
		Scan(&state, &status); err != nil {
		t.Fatal(err)
	}
	if state != "reachable" || status != 200 {
		t.Fatalf("自动验证后状态不符: state=%s status=%d", state, status)
	}

	stats, err = svc.RunOnce(ctx, project.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Picked != 0 {
		t.Fatalf("tcp-only 站点不应被 HTTP 自动验证选中: %+v", stats)
	}
}
