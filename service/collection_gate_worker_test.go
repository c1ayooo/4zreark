package service

import (
	"context"
	"testing"

	"github.com/c1ayooo/4zreark/config"
	"github.com/cloudwego/eino/compose"
)

func TestLLMConfigFingerprintStable(t *testing.T) {
	a := config.LLMConfig{BaseURL: "https://example/v1", Model: "model-a", APIKey: "key-a"}
	b := a
	if llmConfigFingerprint(a) != llmConfigFingerprint(b) {
		t.Fatal("相同配置的指纹必须一致")
	}
	b.Model = "model-b"
	if llmConfigFingerprint(a) == llmConfigFingerprint(b) {
		t.Fatal("模型变化应改变指纹")
	}
	c := a
	c.APIKey = "key-c"
	if llmConfigFingerprint(a) == llmConfigFingerprint(c) {
		t.Fatal("密钥变化应改变指纹")
	}
}

func TestCollectionGateRebuildsOnlyOnConfigChange(t *testing.T) {
	g := &CollectionGate{
		fallback: config.LLMConfig{BaseURL: "https://example/v1", Model: "model-a", APIKey: "key-a"},
	}
	g.effective = func(_ context.Context, fallback config.LLMConfig) config.LLMConfig {
		return fallback
	}
	builds := 0
	g.build = func(_ context.Context, _ config.LLMConfig) (compose.Runnable[GatePrompt, *gateRunOutput], error) {
		builds++
		return nil, nil
	}

	if _, _, err := g.ensureGraph(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.ensureGraph(context.Background()); err != nil {
		t.Fatal(err)
	}
	if builds != 1 {
		t.Fatalf("相同配置应复用图，实际 build=%d", builds)
	}

	g.fallback.Model = "model-b"
	if _, _, err := g.ensureGraph(context.Background()); err != nil {
		t.Fatal(err)
	}
	if builds != 2 {
		t.Fatalf("配置变化应重建图，实际 build=%d", builds)
	}
}

func TestCollectionGateNoKeyDoesNotPanic(t *testing.T) {
	g := NewCollectionGate(config.LLMConfig{})
	if err := g.Evaluate(context.Background(), "raw-1"); err != nil {
		t.Fatalf("无密钥/无数据层时 Evaluate 应安全返回: %v", err)
	}
}
