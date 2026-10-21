package test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// P2：capability.probe=false 的执行单元只登记、不发请求；
// 同批次其他目标照常探测，批次在全部目标落终态后结案。
func TestProbeExecutorHonorsCapability(t *testing.T) {
	r := openTestRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	project, err := service.NewAssetService().CreateProject(ctx, repo.ProjectInput{
		Code: fmt.Sprintf("pcb%d", time.Now().UnixNano()),
		Name: "probe capability test",
	})
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = r.Pool().Exec(context.Background(), `DELETE FROM projects WHERE id = $1`, project.ID)
	})

	var probed int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&probed, 1)
		_, _ = w.Write([]byte("<html><title>alive</title></html>"))
	}))
	defer srv.Close()
	var skippedHits int32
	skipSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&skippedHits, 1)
		_, _ = w.Write([]byte("should-not-be-called"))
	}))
	defer skipSrv.Close()

	port := srv.Listener.Addr().(*net.TCPAddr).Port
	skipPort := skipSrv.Listener.Addr().(*net.TCPAddr).Port
	if _, err := repo.NewAssetRepo().ImportRecords(ctx, project.ID, "test", []repo.RawRecord{
		{Host: "127.0.0.1", Port: port, Protocol: "http", Value: fmt.Sprintf("http://127.0.0.1:%d", port)},
	}); err != nil {
		t.Fatalf("导入站点失败: %v", err)
	}

	seeds := r.Seeds()
	seed := &repo.Seed{ProjectID: project.ID, Kind: "domain", Value: "127.0.0.1", Enabled: true}
	if err := seeds.CreateSeed(ctx, seed); err != nil {
		t.Fatal(err)
	}
	plan := &repo.Plan{SeedID: seed.ID, IntervalHours: 24, Enabled: true}
	if err := seeds.CreatePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	run, _, err := r.Runs().CreateRun(ctx, repo.CreateRunInput{
		PlanID: plan.ID, ProjectID: project.ID, CycleStart: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	added, err := r.Runs().AddTargets(ctx, run.ID, []repo.TargetInput{
		{Host: "127.0.0.2", Port: skipPort, Capability: map[string]any{"probe": false, "source": "collect-only"}},
		{Host: "127.0.0.1", Port: port, Capability: map[string]any{"probe": true, "source": "site"}},
	})
	if err != nil || added != 2 {
		t.Fatalf("写入执行单元失败: added=%d err=%v", added, err)
	}

	stats, err := service.NewProbeExecutor(2).ProcessOnce(ctx, run.ID, 10)
	if err != nil {
		t.Fatalf("执行批次失败: %v", err)
	}
	if stats.Claimed != 2 || stats.Skipped != 1 || stats.Reachable != 1 || stats.Targets != 1 || stats.RunsDone != 1 {
		t.Fatalf("执行统计不符: %+v", stats)
	}
	if atomic.LoadInt32(&skippedHits) != 0 {
		t.Fatalf("probe=false 的目标不应发请求，实际命中 %d 次", skippedHits)
	}
	if atomic.LoadInt32(&probed) == 0 {
		t.Fatal("probe=true 的目标应真实探测")
	}

	targets, err := r.Runs().ListTargets(ctx, run.ID, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	state := map[int]string{}
	for _, tg := range targets {
		state[tg.Port] = tg.State
	}
	if state[skipPort] != "skipped" || state[port] != "done" {
		t.Fatalf("执行单元终态不符: %+v", state)
	}
	gotRun, err := r.Runs().GetRun(ctx, run.ID)
	if err != nil || gotRun.Status != "done" {
		t.Fatalf("批次应结案为 done: %+v err=%v", gotRun, err)
	}
}
