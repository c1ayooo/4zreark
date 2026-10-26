package vulnverify

// 自动验证服务白盒测试：假执行器 + 内存台账 + 假回调，覆盖
// scope 拦截 / miss / hit / 执行失败 / 参数构建 / JSONL 解析全路径。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// memJobStore 内存台账（EnqueueJob 永不入队去重，记录 FinishJob 调用）。
type memJobStore struct {
	mu         sync.Mutex
	finish     []string // status 顺序
	taskQueued []Task
}

func (m *memJobStore) EnqueueJob(ctx context.Context, task Task, recheckDays int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.taskQueued = append(m.taskQueued, task)
	return true, nil
}

func (m *memJobStore) FinishJob(task Task, status, vulnID, errMsg string, templateIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.finish = append(m.finish, status+"|"+vulnID)
	return nil
}

// newTestService 构建被测服务与捕获器。
type captures struct {
	mu       sync.Mutex
	hits     []HitResult
	scooped  []string
	runnerBB []string
}

func newTestService(t *testing.T, cfg Config, cap *captures,
	scopeErr error, refs []TemplateRef, stdout string, runErr error) (*Service, *memJobStore) {
	t.Helper()
	store := &memJobStore{}
	svc := New(Options{
		Store:         store,
		Cfg:           func() Config { return cfg },
		BinPath:       func() string { return "/opt/nuclei" },
		TemplatesRoot: func() string { return "/tpl" },
		ScopeCheck: func(ctx context.Context, projectID, target string) error {
			cap.mu.Lock()
			cap.scooped = append(cap.scooped, projectID+"|"+target)
			cap.mu.Unlock()
			return scopeErr
		},
		Recall: func(ctx context.Context, projectID, product string) ([]TemplateRef, error) {
			return refs, nil
		},
		RecordHit: func(ctx context.Context, hit HitResult) (string, error) {
			cap.mu.Lock()
			cap.hits = append(cap.hits, hit)
			cap.mu.Unlock()
			return "vuln-123", nil
		},
		Runner: func(ctx context.Context, binPath string, args []string, timeout time.Duration) (string, error) {
			cap.mu.Lock()
			cap.runnerBB = append(cap.runnerBB, binPath+" "+strings.Join(args, " "))
			cap.mu.Unlock()
			return stdout, runErr
		},
	})
	return svc, store
}

func TestProcessScopeRejected(t *testing.T) {
	cap := &captures{}
	svc, store := newTestService(t, Config{}, cap, errors.New("目标不在 scope"), nil, "", nil)
	svc.process(context.Background(), Task{ProjectID: "p1", Target: "http://x", Product: "shiro"})
	if len(store.finish) != 1 || !strings.HasPrefix(store.finish[0], "skipped_out_of_scope") {
		t.Fatalf("应标记出界跳过: %v", store.finish)
	}
	if len(cap.runnerBB) != 0 {
		t.Fatalf("出界目标不应执行 nuclei")
	}
}

func TestProcessScopeCheckerNilFailsClosed(t *testing.T) {
	store := &memJobStore{}
	svc := New(Options{Store: store, Cfg: func() Config { return Config{} }})
	svc.process(context.Background(), Task{ProjectID: "p", Target: "http://x", Product: "y"})
	if len(store.finish) != 1 || !strings.HasPrefix(store.finish[0], "skipped_out_of_scope") {
		t.Fatalf("无 scope 校验器必须 fail-closed: %v", store.finish)
	}
}

func TestProcessNoRecallMiss(t *testing.T) {
	cap := &captures{}
	svc, store := newTestService(t, Config{}, cap, nil, nil, "", nil)
	svc.process(context.Background(), Task{ProjectID: "p1", Target: "http://x", Product: "unknown-prod"})
	if len(store.finish) != 1 || store.finish[0] != "miss|" {
		t.Fatalf("无召回应标 miss: %v", store.finish)
	}
	if len(cap.runnerBB) != 0 {
		t.Fatalf("无召回不应执行 nuclei")
	}
}

func TestProcessHitFlow(t *testing.T) {
	dir := t.TempDir()
	// 模板文件必须真实存在（构建参数时 os.Stat 检查）
	tpl := filepath.Join(dir, "http", "cves", "2021")
	if err := os.MkdirAll(tpl, 0o750); err != nil {
		t.Fatal(err)
	}
	tplFile := filepath.Join(tpl, "CVE-2021-44228.yaml")
	if err := os.WriteFile(tplFile, []byte("id: x\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	stdout := `{"template-id":"CVE-2021-44228","matcher-status":true,"matched-at":"2026-09-19T00:00:00Z","host":"http://x","info":{"severity":"critical"}}
{"template-id":"no-match-tpl","matcher-status":false}
not-json-line
{"template-id":"CVE-2021-44228","matcher-status":true}`
	cap := &captures{}
	refs := []TemplateRef{{ID: "CVE-2021-44228", Path: "http/cves/2021/CVE-2021-44228.yaml", Severity: "critical"}}
	svc, store := newTestService(t, Config{}, cap, nil, refs, stdout, nil)
	svc.opts.TemplatesRoot = func() string { return dir }
	svc.process(context.Background(), Task{ProjectID: "p1", Target: "http://x", Product: "log4j"})

	if len(store.finish) != 1 || store.finish[0] != "hit|vuln-123" {
		t.Fatalf("应标 hit 且回填漏洞 id: %v", store.finish)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if len(cap.hits) != 1 {
		t.Fatalf("命中回调应 1 次（去重后），实得 %d", len(cap.hits))
	}
	hit := cap.hits[0]
	if hit.TemplateID != "CVE-2021-44228" || hit.Severity != "critical" || hit.Product != "log4j" {
		t.Fatalf("命中字段不符: %+v", hit)
	}
	if !strings.Contains(hit.Command, "-t "+tplFile) {
		t.Fatalf("复现命令应含模板绝对路径: %s", hit.Command)
	}
	if !strings.Contains(cap.runnerBB[0], "-severity critical,high,medium") {
		t.Fatalf("最小验证应带 severity 过滤: %s", cap.runnerBB[0])
	}
	if !strings.Contains(cap.runnerBB[0], "-rl 10") || !strings.Contains(cap.runnerBB[0], "-timeout 8") {
		t.Fatalf("限流/超时参数缺失: %s", cap.runnerBB[0])
	}
}

func TestProcessRunFailure(t *testing.T) {
	dir := t.TempDir()
	tplDir := filepath.Join(dir, "http")
	if err := os.MkdirAll(tplDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tplDir, "x.yaml"), []byte("id: x\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	cap := &captures{}
	refs := []TemplateRef{{ID: "x", Path: "http/x.yaml", Severity: "high"}}
	svc, store := newTestService(t, Config{}, cap, nil, refs, "", errors.New("exit 1"))
	svc.opts.TemplatesRoot = func() string { return dir }
	svc.process(context.Background(), Task{ProjectID: "p", Target: "http://x", Product: "y"})
	if len(store.finish) != 1 || !strings.HasPrefix(store.finish[0], "failed|") {
		t.Fatalf("执行失败应标 failed: %v", store.finish)
	}
}

func TestProcessDisabled(t *testing.T) {
	cap := &captures{}
	svc, store := newTestService(t, Config{}, cap, nil, nil, "", nil)
	svc.opts.Cfg = func() Config {
		return Config{Configured: true, Enabled: false}
	}
	svc.process(context.Background(), Task{ProjectID: "p", Target: "http://x", Product: "y"})
	if len(store.finish) != 1 || !strings.HasPrefix(store.finish[0], "skipped_disabled") {
		t.Fatalf("禁用时应跳过: %v", store.finish)
	}
}

func TestBuildNucleiArgsFiltersNonHTTPAndMissing(t *testing.T) {
	dir := t.TempDir()
	httpFile := filepath.Join(dir, "http", "a.yaml")
	netFile := filepath.Join(dir, "network", "b.yaml")
	if err := os.MkdirAll(filepath.Dir(httpFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(netFile), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(httpFile, []byte("id: a\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	refs := []TemplateRef{
		{ID: "a", Path: "http/a.yaml", Severity: "critical"},
		{ID: "b", Path: "network/b.yaml", Severity: "high"},    // 非 http：拒绝
		{ID: "c", Path: "http/missing.yaml", Severity: "high"}, // 文件缺失：跳过
	}
	args, paths := buildNucleiArgs("http://x", dir, refs, []string{"critical", "high", "medium"}, 10, "-jsonl")
	if len(paths) != 1 || paths[0] != httpFile {
		t.Fatalf("只应收 http 且存在的模板: %v", paths)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-u http://x") || !strings.Contains(joined, "-t "+httpFile) {
		t.Fatalf("参数构建不符: %s", joined)
	}
	if strings.Contains(joined, "network") {
		t.Fatalf("非 http 模板不得进入参数: %s", joined)
	}

	// 全部不可用 → nil
	args, paths = buildNucleiArgs("http://x", dir, refs[1:], []string{"critical"}, 10, "-jsonl")
	if args != nil || paths != nil {
		t.Fatalf("全缺失应返回空: %v %v", args, paths)
	}

	// rate 硬上限
	_, _ = buildNucleiArgs("http://x", dir, refs[:1], []string{"critical"}, 9999, "-jsonl")
	// （9999 会被截到 50；通过 join 校验）
	args2, _ := buildNucleiArgs("http://x", dir, refs[:1], []string{"critical"}, 9999, "-jsonl")
	if strings.Contains(strings.Join(args2, " "), "-rl 9999") {
		t.Fatal("速率必须被硬上限截断")
	}
}

func TestParseNucleiJSONL(t *testing.T) {
	stdout := `{"template-id":"a","matcher-status":true,"matched-at":"T1","host":"h","ip":"1.2.3.4","info":{"severity":"Critical"},"extracted-results":["e1"],"request":"GET /sftp.json HTTP/1.1","response":"<html>phpinfo</html>","curl-command":"curl 'http://h/sftp.json'"}
{"template-id":"b","matcher-status":false}
garbage
{"template-id":"a","matcher-status":true}
{"template-id":"c","matcher-status":true,"info":{"severity":"high"}}`
	matches := ParseNucleiJSONL(stdout)
	if len(matches) != 2 {
		t.Fatalf("应解析出 2 条命中（去重、滤 false/垃圾行）: %+v", matches)
	}
	if matches[0].TemplateID != "a" || matches[0].Severity != "critical" || len(matches[0].Extracted) != 1 {
		t.Fatalf("第一条解析不符: %+v", matches[0])
	}
	if matches[0].IP != "1.2.3.4" || !strings.Contains(matches[0].Request, "sftp.json") ||
		!strings.Contains(matches[0].Response, "phpinfo") || !strings.Contains(matches[0].CurlCommand, "curl") {
		t.Fatalf("第一条 request/response/curl/ip 解析不符: %+v", matches[0])
	}
	if matches[1].TemplateID != "c" {
		t.Fatalf("第二条不符: %+v", matches[1])
	}
	if len(ParseNucleiJSONL("")) != 0 {
		t.Fatal("空输出应为空")
	}
}

func TestEnqueueDedupEmptyFields(t *testing.T) {
	store := &memJobStore{}
	svc := New(Options{Store: store})
	svc.Enqueue(Task{ProjectID: "p", Target: "", Product: "y"})
	svc.Enqueue(Task{ProjectID: "p", Target: "http://x", Product: ""})
	if len(store.taskQueued) != 0 {
		t.Fatal("空 target/product 不应入队")
	}
}
