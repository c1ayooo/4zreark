package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 平台本体自更新（Web 进程从 GitHub Release 拉取新版本）：
// 检测（GET /system/version，内存缓存 10 分钟）→ 下载 tar.gz（字节级进度）→
// sha256 对校验 → 解出 server 二进制 → 备份旧文件 → 原子替换 → 延迟退出
// （supervise 循环会把新版本拉起来）。

const githubRepo = "c1ayooo/4zreark"

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	PublishedAt time.Time `json:"published_at"`
	HtmlURL     string    `json:"html_url"`
	Body        string    `json:"body"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

type UpdateStage string

const (
	UpdateIdle        UpdateStage = "idle"
	UpdateChecking    UpdateStage = "checking"
	UpdateDownloading UpdateStage = "downloading"
	UpdateVerifying   UpdateStage = "verifying"
	UpdateReplacing   UpdateStage = "replacing"
	UpdateRestarting  UpdateStage = "restarting"
	UpdateDone        UpdateStage = "done"
	UpdateError       UpdateStage = "error"
)

type UpdateState struct {
	Stage         UpdateStage `json:"stage"`
	Percent       float64     `json:"percent"`
	Downloaded    int64       `json:"downloaded"`
	Total         int64       `json:"total"`
	TargetVersion string      `json:"target_version"`
	Error         string      `json:"error"`
	StartedAt     string      `json:"started_at"`
}

var (
	updateMu       sync.Mutex
	updateState    = UpdateState{Stage: UpdateIdle}
	latestCacheMu  sync.Mutex
	latestCache    *ghRelease
	latestCacheAt  time.Time
	latestCacheErr string
)

// VersionInfo 版本检测结果。
type VersionInfo struct {
	Current     string `json:"current"`
	Latest      string `json:"latest,omitempty"`
	HasUpdate   bool   `json:"has_update"`
	PublishedAt string `json:"published_at,omitempty"`
	ReleaseURL  string `json:"release_url,omitempty"`
	Notes       string `json:"notes,omitempty"`
	AssetSize   int64  `json:"asset_size,omitempty"`
	Error       string `json:"error,omitempty"`
}

// compareVersion 比较语义化版本（v 前缀可省）：>0 表示 a 更新。
func compareVersion(a, b string) int {
	num := func(s string) []int {
		s = strings.TrimPrefix(strings.TrimSpace(s), "v")
		parts := strings.Split(s, ".")
		out := make([]int, 0, 3)
		for _, p := range parts {
			n, _ := strconv.Atoi(strings.TrimSpace(p))
			out = append(out, n)
		}
		return out
	}
	av, bv := num(a), num(b)
	for i := 0; i < 3; i++ {
		var x, y int
		if i < len(av) {
			x = av[i]
		}
		if i < len(bv) {
			y = bv[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

// updateHTTPClient GitHub 资产下载/检测统一客户端：强制直连（理由见 ghGet）。
func updateHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true},
	}
}

// ghGet 带「直连 ↔ 出网代理」交替重试的 GET（GitHub 直连被间歇性干扰是常态：
// 直连 EOF/超时、代理出口 403 限流，三条路里总有一条通）。
func ghGet(ctx context.Context, url string, attempts int) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		// 显式 Proxy: nil 强制直连——服务进程继承了 https_proxy 环境变量指向的
		// 本地代理（7897），实测其对 Go 的 TLS CONNECT 稳定 EOF，直连反而 200。
		// 不可改回默认 transport，否则会掉进坏代理。
		resp, err := updateHTTPClient(20 * time.Second).Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("GitHub 返回 %d（出口 IP 限流）", resp.StatusCode)
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	return nil, lastErr
}

func fetchLatestRelease(ctx context.Context) (*ghRelease, error) {
	resp, err := ghGet(ctx, "https://api.github.com/repos/"+githubRepo+"/releases/latest", 3)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	return &rel, nil
}

// CheckVersion 检测 GitHub 是否有更高版本（结果缓存 10 分钟）。
func CheckVersion(ctx context.Context) *VersionInfo {
	info := &VersionInfo{Current: AppVersion}

	latestCacheMu.Lock()
	cache, cacheAt := latestCache, latestCacheAt
	cacheErr := latestCacheErr
	latestCacheMu.Unlock()

	fresh := time.Since(cacheAt) < 10*time.Minute
	if !fresh {
		latestCacheMu.Lock()
		rel, err := fetchLatestRelease(ctx)
		latestCache, latestCacheAt, latestCacheErr = rel, time.Now(), ""
		if err != nil {
			latestCacheErr = err.Error()
			rel = nil
		}
		latestCacheMu.Unlock()
		cache, cacheAt, cacheErr = rel, latestCacheAt, latestCacheErr
	}
	_ = cacheAt

	if cache == nil {
		info.Error = cacheErr
		if AppVersion == "dev" {
			info.HasUpdate = false
		}
		return info
	}

	info.Latest = cache.TagName
	info.PublishedAt = cache.PublishedAt.Format("2006-01-02 15:04")
	info.ReleaseURL = cache.HtmlURL
	info.Notes = cache.Body
	if AppVersion == "dev" || compareVersion(cache.TagName, AppVersion) > 0 {
		info.HasUpdate = true
	}
	for _, a := range cache.Assets {
		if strings.Contains(a.Name, "linux_"+runtime.GOARCH+".tar.gz") {
			info.AssetSize = a.Size
			break
		}
	}
	return info
}

// GetUpdateState 当前更新进度（前端轮询）。
func GetUpdateState() UpdateState {
	updateMu.Lock()
	defer updateMu.Unlock()
	return updateState
}

func setUpdateState(stage UpdateStage, percent float64, downloaded, total int64, target, errMsg string) {
	updateMu.Lock()
	defer updateMu.Unlock()
	updateState = UpdateState{
		Stage: stage, Percent: percent, Downloaded: downloaded, Total: total,
		TargetVersion: target, Error: errMsg,
		StartedAt: updateState.StartedAt,
	}
	if updateState.StartedAt == "" {
		updateState.StartedAt = time.Now().Format("2006-01-02 15:04:05")
	}
}

// StartSelfUpdate 启动自更新（幂等：进行中直接返回当前状态）。
func StartSelfUpdate(targetVersion string) (UpdateState, error) {
	updateMu.Lock()
	if updateState.Stage != UpdateIdle && updateState.Stage != UpdateDone && updateState.Stage != UpdateError {
		st := updateState
		updateMu.Unlock()
		return st, nil
	}
	updateState = UpdateState{Stage: UpdateChecking, StartedAt: time.Now().Format("2006-01-02 15:04:05"), TargetVersion: targetVersion}
	updateMu.Unlock()

	go runSelfUpdate(targetVersion)
	return GetUpdateState(), nil
}

func runSelfUpdate(targetVersion string) {
	// 45 分钟总上限：出网代理速度 ~15KB/s 时 25MB 资产要跑 28 分钟，
	// 10 分钟的旧上限会在下载中段把整体 ctx 掐死（表现为"两路均失败"）。
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	// 1. 找到目标版本对应平台架构的 tar.gz 资产
	rel, err := fetchLatestRelease(ctx)
	if err != nil {
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, "获取 Release 失败: "+err.Error())
		return
	}
	wantTar := "4zreark_" + strings.TrimPrefix(rel.TagName, "v") + "_linux_" + runtime.GOARCH + ".tar.gz"
	var tarURL string
	var tarSize int64
	var checksumURL string
	for _, a := range rel.Assets {
		if a.Name == wantTar {
			tarURL, tarSize = a.BrowserDownloadURL, a.Size
		}
		if a.Name == "checksums.txt" {
			checksumURL = a.BrowserDownloadURL
		}
	}
	if tarURL == "" {
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, "Release 缺少资产 "+wantTar)
		return
	}

	// 2. 下载（字节级进度）
	exe, err := os.Executable()
	if err != nil {
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, err.Error())
		return
	}
	if real, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = real
	}
	dir := filepath.Dir(exe)
	tmpTar := filepath.Join(dir, ".update.new.tar.gz")

	// 下载双路重试：GitHub 的 release CDN 直连会被间歇性掐断（实测 1KB/s 停滞），
	// 出网代理反而能跑满（15KB/s）。第一路强制直连 + 30 秒无进展看门狗，
	// 第二路走环境代理（ProxyFromEnvironment，服务进程继承 https_proxy）。
	var downloaded int64
	downloadErr := error(nil)
	for _, mode := range []struct {
		label    string
		useProxy bool
	}{
		{"直连", false},
		{"环境代理", true},
	} {
		downloaded = 0
		downloadErr = downloadReleaseAsset(ctx, tarURL, tmpTar, mode.useProxy, &downloaded, tarSize, targetVersion)
		if downloadErr == nil {
			break
		}
		log.Printf("[self-update] %s下载失败（已取 %d 字节）: %v，切换下一路", mode.label, downloaded, downloadErr)
		setUpdateState(UpdateDownloading, 0, 0, tarSize, targetVersion, "")
	}
	if downloadErr != nil {
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, "两路下载均失败（直连+环境代理）: "+downloadErr.Error())
		return
	}

	// 3. sha256 校验（对照 checksums.txt）——校验是安全底线，拉不到校验文件视为失败
	setUpdateState(UpdateVerifying, 100, downloaded, tarSize, targetVersion, "")
	resp2, err := ghGet(ctx, checksumURL, 3)
	if err != nil {
		_ = os.Remove(tmpTar)
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, "拉取 checksums.txt 失败: "+err.Error())
		return
	}
	sumsBytes, err := io.ReadAll(io.LimitReader(resp2.Body, 1<<20))
	resp2.Body.Close()
	if err != nil {
		_ = os.Remove(tmpTar)
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, err.Error())
		return
	}
	want := findChecksum(string(sumsBytes), wantTar)
	if want == "" {
		_ = os.Remove(tmpTar)
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, "checksums.txt 中没有 "+wantTar)
		return
	}
	got, herr := fileSHA256(tmpTar)
	if herr != nil || got != want {
		_ = os.Remove(tmpTar)
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, "校验失败: want="+shortHash(want)+" got="+shortHash(got))
		return
	}

	// 4. 解出 server 二进制
	setUpdateState(UpdateReplacing, 100, downloaded, tarSize, targetVersion, "")
	newBin, err := extractServerBinary(tmpTar, dir)
	if err != nil {
		_ = os.Remove(tmpTar)
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, err.Error())
		return
	}
	_ = os.Remove(tmpTar)

	// 5. 备份旧版 → 原子替换 → 延迟退出（supervise 拉起新版本）
	backup := exe + ".bak"
	_ = os.Remove(backup)
	if err := os.Rename(exe, backup); err != nil {
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, "备份旧版失败: "+err.Error())
		return
	}
	if err := os.Rename(newBin, exe); err != nil {
		_ = os.Rename(backup, exe) // 回滚
		setUpdateState(UpdateError, 0, 0, 0, targetVersion, "替换失败: "+err.Error())
		return
	}
	_ = os.Chmod(exe, 0o755)
	setUpdateState(UpdateRestarting, 100, downloaded, tarSize, targetVersion, "")
	log.Printf("[self-update] 已替换为新版本 %s，2 秒后退出重启", rel.TagName)
	time.AfterFunc(2*time.Second, func() {
		os.Exit(0) // supervise 循环自动拉起新二进制
	})
}

func fetchText(ctx context.Context, url string) (string, error) {
	client := updateHTTPClient(30 * time.Second)
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func findChecksum(sums, filename string) string {
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.HasSuffix(fields[1], filename) {
			return fields[0]
		}
	}
	return ""
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func shortHash(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// downloadReleaseAsset 单路下载（带 30 秒无进展看门狗），写 dest 并实时回报进度。
func downloadReleaseAsset(ctx context.Context, url, dest string, useEnvProxy bool, downloaded *int64, total int64, targetVersion string) error {
	transport := &http.Transport{Proxy: nil}
	if useEnvProxy {
		transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	client := &http.Client{Timeout: 10 * time.Minute, Transport: transport}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if total <= 0 && resp.ContentLength > 0 {
		total = resp.ContentLength
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	var lastProgress time.Time = time.Now()
	lastProgressBytes := int64(0)
	buf := make([]byte, 64<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			*downloaded += int64(n)
			lastProgress = time.Now()
			if _, werr := f.Write(buf[:n]); werr != nil {
				return werr
			}
			if total > 0 {
				setUpdateState(UpdateDownloading, float64(*downloaded)/float64(total)*100, *downloaded, total, targetVersion, "")
			}
		}
		if rerr != nil {
			if strings.Contains(rerr.Error(), "EOF") {
				// 流"正常"结束也必须核对字节数：被掐断的连接同样以 EOF 收尾，
				// 短包不解压直接判失败（否则截断包会在解压阶段才暴露）
				if total > 0 && *downloaded < total {
					return fmt.Errorf("下载不完整 %d/%d 字节，连接被中途掐断", *downloaded, total)
				}
				return nil
			}
			return rerr
		}
		// 看门狗（速度感知）：完全停滞 30 秒，或 30 秒内进展不足 64KB（<2KB/s，
		// 实测直连 GitHub CDN 会被压到这个量级），放弃本路换下一路
		if time.Since(lastProgress) > 30*time.Second {
			return fmt.Errorf("30 秒完全无进展，疑似连接被掐断")
		}
		if time.Since(lastProgress) > 30*time.Second {
			if *downloaded == lastProgressBytes {
				return fmt.Errorf("30 秒完全无进展，疑似连接被掐断")
			}
			if *downloaded-lastProgressBytes < 64<<10 {
				return fmt.Errorf("下载速度过低（30 秒 <64KB），切换线路")
			}
			lastProgressBytes = *downloaded
			lastProgress = time.Now()
		}
	}
}

// extractServerBinary 从 tar.gz 里解出 server 二进制到 dir/.update.new。
func extractServerBinary(tarPath, dir string) (string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("解压失败: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := filepath.Join(dir, ".update.new")
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		if filepath.Base(hdr.Name) != "server" || hdr.Typeflag != tar.TypeReg {
			continue
		}
		outF, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(outF, tr); err != nil {
			outF.Close()
			return "", err
		}
		outF.Close()
		return out, nil
	}
	return "", fmt.Errorf("压缩包里没有 server 二进制")
}
