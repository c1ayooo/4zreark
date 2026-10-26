package test

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/service"
)

// G4 数据源：凭据密文落库、接口只回 has_secret、连接测试与删除级联。
func TestG4SourcesCredential(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Setenv("ZRE_SECRET_KEY", hex.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	svc := service.NewSourceService()
	src, err := svc.Create(ctx, service.SourceInput{
		Kind: "custom", Name: fmt.Sprintf("g4-src-%d", time.Now().UnixNano()),
		Endpoint: srv.URL, Enabled: true, Secret: "token-123",
	})
	if err != nil {
		t.Fatalf("创建数据源失败: %v", err)
	}
	t.Cleanup(func() {
		_ = svc.Delete(context.Background(), src.ID)
	})
	if !src.HasSecret || src.CredentialRef == "" {
		t.Fatalf("数据源应标记 has_secret: %+v", src)
	}

	// 密文可解密回原文
	ct, nonce, err := r.Sources().LoadCredential(ctx, src.CredentialRef)
	if err != nil {
		t.Fatalf("读取凭据失败: %v", err)
	}
	plain, err := service.DecryptSecret(ct, nonce)
	if err != nil || plain != "token-123" {
		t.Fatalf("凭据解密不符: %q err=%v", plain, err)
	}

	// 列表只回 has_secret，不返回密文/明文
	items, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, it := range items {
		if it.ID == src.ID {
			found = true
			if !it.HasSecret || it.CredentialRef == "" {
				t.Fatalf("列表项 has_secret 不符: %+v", it)
			}
		}
	}
	if !found {
		t.Fatal("列表里找不到刚建的数据源")
	}

	// 连接测试
	res, err := svc.Test(ctx, src.ID)
	if err != nil || !res.OK || res.Status != 200 {
		t.Fatalf("连接测试失败: res=%+v err=%v", res, err)
	}

	// 更新凭据
	if _, err := svc.Update(ctx, src.ID, service.SourceInput{
		Kind: "custom", Name: src.Name, Endpoint: srv.URL, Enabled: true, Secret: "token-456",
	}); err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	ct2, nonce2, err := r.Sources().LoadCredential(ctx, src.CredentialRef)
	if err != nil {
		t.Fatal(err)
	}
	plain2, _ := service.DecryptSecret(ct2, nonce2)
	if plain2 != "token-456" {
		t.Fatalf("更新后的凭据不符: %q", plain2)
	}

	// 删除数据源 -> 凭据一起删
	if err := svc.Delete(ctx, src.ID); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, _, err := r.Sources().LoadCredential(ctx, src.CredentialRef); err == nil {
		t.Fatal("删除数据源后凭据应被清理")
	}

	// 兼容层：旧 /thirdparty/config 的读写落到 sources 表
	if _, err := svc.UpdateLegacy(ctx, map[string]string{
		"fofa_key": "legacy-fofa-key",
	}); err != nil {
		t.Fatalf("兼容层写入失败: %v", err)
	}
	if got := svc.EngineKey(ctx, "fofa"); got != "legacy-fofa-key" {
		t.Fatalf("EngineKey(fofa)=%q", got)
	}
	legacyCfg, configured, err := svc.LegacyConfig(ctx)
	if err != nil {
		t.Fatalf("兼容层读取失败: %v", err)
	}
	if !strings.HasPrefix(legacyCfg["fofa_key"], "****") {
		t.Fatalf("兼容层 key 应脱敏: %q", legacyCfg["fofa_key"])
	}
	var hasFofa bool
	for _, k := range configured {
		if k == "fofa" {
			hasFofa = true
		}
	}
	if !hasFofa {
		t.Fatalf("configured_sources 应包含 fofa: %v", configured)
	}
	// 清理兼容层创建的 fofa 源
	if fofa, err := r.Sources().FindByKind(ctx, "fofa"); err == nil {
		_ = svc.Delete(ctx, fofa.ID)
	}
}

// GitHub 类型的连接测试必须带上 token：否则匿名 200 只能证明网络通，
// 证明不了凭据可用。
func TestGitHubSourceTestSendsToken(t *testing.T) {
	r := openTestRepo(t)
	_ = r
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Setenv("ZRE_SECRET_KEY", hex.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		seen = req.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"resources":{}}`))
	}))
	defer srv.Close()

	svc := service.NewSourceService()
	src, err := svc.Create(ctx, service.SourceInput{
		Kind: "github", Name: fmt.Sprintf("gh-test-%d", time.Now().UnixNano()),
		Endpoint: srv.URL, Enabled: true, Secret: "ghp_test_token",
	})
	if err != nil {
		t.Fatalf("创建 GitHub 数据源失败: %v", err)
	}
	t.Cleanup(func() {
		_ = svc.Delete(context.Background(), src.ID)
	})

	res, err := svc.Test(ctx, src.ID)
	if err != nil || !res.OK {
		t.Fatalf("GitHub 连接测试失败: res=%+v err=%v", res, err)
	}
	if seen != "Bearer ghp_test_token" {
		t.Fatalf("测试请求未带 token，Authorization=%q", seen)
	}
}
