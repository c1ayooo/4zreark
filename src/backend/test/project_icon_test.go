package test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

func makeTestPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("生成测试 PNG 失败: %v", err)
	}
	return buf.Bytes()
}

func TestProjectIconUploadAndStats(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("picon%d", time.Now().UnixNano()),
		Name: "project icon test",
	})
	if err != nil {
		t.Fatalf("创建项目失败: %v", err)
	}
	svc := service.NewProjectOpsService()
	iconPNG := makeTestPNG(t, 32, 32)
	iconSHA := ""
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
		if iconSHA != "" {
			_, _ = r.Pool().Exec(context.Background(), `DELETE FROM asset_icons WHERE sha256 = $1`, iconSHA)
		}
	})

	p, err := svc.SetIcon(ctx, project.ID, iconPNG, "image/png")
	if err != nil {
		t.Fatalf("上传图标失败: %v", err)
	}
	if p.IconSHA256 == "" {
		t.Fatal("项目应带上 icon_sha256")
	}
	iconSHA = p.IconSHA256

	icon, err := r.Clusters().GetIcon(ctx, iconSHA)
	if err != nil {
		t.Fatalf("读取图标失败: %v", err)
	}
	if !bytes.Equal(icon.Data, iconPNG) || icon.ContentType != "image/png" || icon.Size != len(iconPNG) {
		t.Fatalf("图标字节/类型不符: %+v", icon)
	}
	data, ctype, err := service.NewAssetService().IconBytes(ctx, iconSHA)
	if err != nil || !bytes.Equal(data, iconPNG) || ctype != "image/png" {
		t.Fatalf("公开图标读取失败: ctype=%s err=%v", ctype, err)
	}

	if _, err := svc.SetIcon(ctx, project.ID, []byte("not an image"), "text/plain"); !errors.Is(err, service.ErrProjectInput) {
		t.Fatalf("非法类型应被拒绝，实际 %v", err)
	}
	large := makeTestPNG(t, 1200, 1200)
	if _, err := svc.SetIcon(ctx, project.ID, large, "image/png"); !errors.Is(err, service.ErrProjectInput) {
		t.Fatalf("超过像素上限应被拒绝，实际 %v", err)
	}

	opts, err := svc.Options(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, o := range opts {
		if o.ID == project.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("项目下拉选项里找不到测试项目")
	}
	stats, err := svc.Stats(ctx)
	if err != nil || stats.Projects < 1 {
		t.Fatalf("项目统计不符: %+v err=%v", stats, err)
	}
	if _, err := svc.CycleStatus(ctx); err != nil {
		t.Fatalf("调度态查询失败: %v", err)
	}

	p, err = svc.ClearIcon(ctx, project.ID)
	if err != nil || p.IconSHA256 != "" {
		t.Fatalf("清除图标失败: %+v err=%v", p, err)
	}
}
