package toolruntime

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	downloadLimit = 256 << 20 // 单个 release 资产上限，256MB 足够覆盖所有受管工具
	// rootDirEnv 托管根目录（默认 data/tools）；worker 与 master 同一套代码。
	rootDirEnv = "ZRE_TOOLS_DIR"
	// allowUncheckedEnv=1 时允许在 release 无 checksums 清单的情况下安装（TOFU）。
	allowUncheckedEnv = "ZRE_TOOL_ALLOW_UNCHECKED"

	probeTimeout    = 20 * time.Second
	statusOK        = "ok"
	statusStale     = "stale"
	statusMissing   = "missing"
	statusReview    = "needs_review"
	defaultInterval = 24
)

// ToolState 一个受管工具的持久状态（master 存 PG，worker 存本地 JSON）。
type ToolState struct {
	Name               string    `json:"name"`
	Repo               string    `json:"repo"`
	PinnedVersion      string    `json:"pinned_version"` // 非空时 Update 固定装这个版本
	InstalledVersion   string    `json:"installed_version"`
	InstalledSHA256    string    `json:"installed_sha256"`
	PrevVersion        string    `json:"prev_version"`
	PrevSHA256         string    `json:"prev_sha256"`
	LatestVersion      string    `json:"latest_version"`
	LatestCheckedAt    time.Time `json:"latest_checked_at"`
	AutoUpdate         bool      `json:"auto_update"`
	CheckIntervalHours int       `json:"check_interval_hours"`
	Status             string    `json:"status"`
	StatusNote         string    `json:"status_note"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// UpdateRecord 一次安装/回滚的历史。
type UpdateRecord struct {
	Tool        string    `json:"tool"`
	FromVersion string    `json:"from_version"`
	ToVersion   string    `json:"to_version"`
	SHA256      string    `json:"sha256"`
	OK          bool      `json:"ok"`
	Note        string    `json:"note"`
	CreatedAt   time.Time `json:"created_at"`
}

// Store 是状态持久化的最小接口（repo 层用 pgx 实现；worker 用文件实现）。
type Store interface {
	LoadState(ctx context.Context, name string) (*ToolState, error) // 未初始化时返回 nil,nil
	SaveState(ctx context.Context, st *ToolState) error
	AppendRecord(ctx context.Context, rec UpdateRecord) error
}

// Manager 管理所有受管工具。零值不可用，用 New 或 Default。
type Manager struct {
	root    string
	store   Store
	client  *http.Client
	toolMu  map[string]*sync.Mutex
	muGuard sync.Mutex

	// updateMu.TryLock 防并发更新（手动触发 + 定时循环撞车）。
	updateMu sync.Mutex

	// versionCache 按 sha256 缓存「二进制自报版本」，避免每次 Status 都跑子进程。
	versionCache sync.Map // sha256 → string

	// memStates 是无 Store（worker/测试）时的内存态兜底：
	// 否则每次 loadState 都拿到空状态，Check/Update 的结果会被自己丢掉。
	memStates sync.Map // name → *ToolState
}

// New 创建管理器。root 是托管目录（data/tools）；store 可为 nil（worker/测试）。
func New(root string, store Store) *Manager {
	return &Manager{
		root:   filepath.Clean(root),
		store:  store,
		client: &http.Client{Timeout: 15 * time.Minute},
		toolMu: map[string]*sync.Mutex{},
	}
}

var (
	defaultOnce sync.Once
	defaultMgr  *Manager
)

// Default 进程级单例：root 取 ZRE_TOOLS_DIR 或 data/tools，无 Store。
// master 的服务层负责在启动时把 repo 仓储注入（SetStore）。
func Default() *Manager {
	defaultOnce.Do(func() {
		root := strings.TrimSpace(os.Getenv(rootDirEnv))
		if root == "" {
			root = filepath.Join("data", "tools")
		}
		defaultMgr = New(root, nil)
	})
	return defaultMgr
}

// SetStore 注入持久化（master 启动时接 PG 仓储）。只应调用一次。
func (m *Manager) SetStore(s Store) { m.store = s }

// InstallDir 当前平台的托管安装目录（data/tools/<os>/）。
func (m *Manager) InstallDir() string {
	return filepath.Join(m.root, OSDir(runtime.GOOS))
}

// BinaryPath 工具在托管目录里的路径。
func (m *Manager) BinaryPath(name string) string {
	return filepath.Join(m.InstallDir(), exeName(name))
}

func (m *Manager) stageDir() string { return filepath.Join(m.root, "stage") }

func (m *Manager) lockTool(name string) *sync.Mutex {
	m.muGuard.Lock()
	defer m.muGuard.Unlock()
	mu, ok := m.toolMu[name]
	if !ok {
		mu = &sync.Mutex{}
		m.toolMu[name] = mu
	}
	return mu
}

// ---------------------------------------------------------------------------
// 路径解析
// ---------------------------------------------------------------------------

// ResolveToolPath 返回工具当前应使用的二进制路径，找不到返回 ""。
// 解析序（更新即时生效的关键：每次调用都重新解析，不做进程级缓存）：
//  1. 环境变量 ZRE_TOOL_<NAME>_PATH 显式覆盖
//  2. 托管目录 <root>/<os>/<name>（toolruntime 安装/更新在这里落盘）
//  3. vendored tools/<os>/<name>（可执行文件目录及相对路径搜索）
//  4. PATH
func (m *Manager) ResolveToolPath(name string) string {
	if p := strings.TrimSpace(os.Getenv("ZRE_TOOL_" + strings.ToUpper(name) + "_PATH")); p != "" {
		if fileExists(p) {
			return p
		}
	}
	if p := m.BinaryPath(name); fileExists(p) {
		return p
	}
	for _, dir := range legacyToolDirs() {
		p := filepath.Join(dir, OSDir(runtime.GOOS), exeName(name))
		if fileExists(p) {
			return p
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// legacyToolDirs 返回 vendored tools 目录的候选（与旧版 getToolsDir 语义一致）。
func legacyToolDirs() []string {
	var dirs []string
	if execPath, err := os.Executable(); err == nil {
		execDir := filepath.Dir(execPath)
		dirs = append(dirs,
			filepath.Join(execDir, "tools"),
			filepath.Join(execDir, "..", "tools"),
		)
	}
	dirs = append(dirs, "tools", filepath.Join("..", "tools"))
	return dirs
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// LocalSHA256 返回托管目录里该工具的 sha256；未安装返回空串。
// worker 用它和平台清单比对，决定是否拉取。
func (m *Manager) LocalSHA256(name string) string {
	p := m.BinaryPath(name)
	if !fileExists(p) {
		return ""
	}
	sum, err := fileSHA256(p)
	if err != nil {
		return ""
	}
	return sum
}

// InstallFromBytes 用平台下发的字节流原子安装工具（worker 模式）：
// 校验 sha256 → 暂存 → chmod → 原子换入托管目录。校验失败直接报错不落盘。
func (m *Manager) InstallFromBytes(name, wantSHA string, data []byte) error {
	if _, ok := Spec(name); !ok {
		return fmt.Errorf("未知工具: %s", name)
	}
	if wantSHA == "" {
		return fmt.Errorf("%s 清单缺少 sha256，拒绝安装", name)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != wantSHA {
		return fmt.Errorf("%s sha256 不匹配（清单 %s != 实际 %s）", name, wantSHA[:12], got[:12])
	}
	if err := os.MkdirAll(m.InstallDir(), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(m.stageDir(), 0o700); err != nil {
		return err
	}
	staged := filepath.Join(m.stageDir(), exeName(name)+".from-master")
	if err := os.WriteFile(staged, data, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(staged, 0o755); err != nil {
		return err
	}
	dest := m.BinaryPath(name)
	if runtime.GOOS == "windows" {
		_ = os.Remove(dest)
	}
	if err := os.Rename(staged, dest); err != nil {
		return err
	}
	return os.Chmod(dest, 0o755)
}

// ToolVersion 返回工具的已知版本（安装台账优先，其次探测二进制自报），
// 供各 runner 在结果日志里归因；拿不到返回空串。
func (m *Manager) ToolVersion(name string) string {
	if st := m.loadState(context.Background(), name); st != nil && st.InstalledVersion != "" {
		return st.InstalledVersion
	}
	if p := m.ResolveToolPath(name); p != "" {
		return m.probeVersion(context.Background(), name, p)
	}
	return ""
}

// ---------------------------------------------------------------------------
// 探针
// ---------------------------------------------------------------------------

// runProbe 运行二进制并返回合并输出（stdout+stderr）。
func runProbe(ctx context.Context, path string, args []string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, path, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// flagTokenRe 匹配 flag 出现在帮助文本中：flag 前必须是行首/空白，
// 后必须是非 flag 字符（避免 -o 误命中 -ob、-d 误命中 --depth）。
func flagTokenRe(flag string) *regexp.Regexp {
	quoted := regexp.QuoteMeta(flag)
	return regexp.MustCompile(`(?m)(?:^|\s)` + quoted + `(?:[^0-9A-Za-z_-]|$)`)
}

// checkFlags 门禁：HelpArgs 输出必须包含全部必需 flag。
func checkFlags(ctx context.Context, path string, spec ToolSpec) (missing []string, err error) {
	out, perr := runProbe(ctx, path, spec.HelpArgs, probeTimeout)
	if perr != nil && strings.TrimSpace(out) == "" {
		return nil, fmt.Errorf("运行 %s %s 失败: %w", filepath.Base(path), strings.Join(spec.HelpArgs, " "), perr)
	}
	for _, f := range spec.RequiredFlags {
		if !flagTokenRe(f).MatchString(out) {
			missing = append(missing, f)
		}
	}
	return missing, nil
}

// probeVersion 尽力提取二进制自报版本；失败不阻断（版本号不是换版门）。
func (m *Manager) probeVersion(ctx context.Context, name, path string) string {
	spec, ok := Spec(name)
	if !ok || len(spec.VersionProbeArgs) == 0 {
		return ""
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return ""
	}
	if cached, ok := m.versionCache.Load(sum); ok {
		s, _ := cached.(string)
		return s
	}
	out, _ := runProbe(ctx, path, spec.VersionProbeArgs, probeTimeout)
	v := ""
	if parsed, err := parseVersion(out); err == nil {
		v = parsed.String()
	}
	m.versionCache.Store(sum, v)
	return v
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, downloadLimit)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

func (m *Manager) loadState(ctx context.Context, name string) *ToolState {
	spec, ok := Spec(name)
	if !ok {
		return nil
	}
	if m.store != nil {
		if st, err := m.store.LoadState(ctx, name); err == nil && st != nil {
			return m.normalize(st, spec)
		}
	}
	if cached, ok := m.memStates.Load(name); ok {
		if st, ok := cached.(*ToolState); ok {
			return st
		}
	}
	fresh := m.normalize(&ToolState{Name: name, Repo: spec.Repo}, spec)
	// 新状态的 auto_update 取 spec 的显式默认（rem 因 fork 依赖默认关）。
	// Go 零值是 false，不在这里赋值的话首次 Check 落库会把「默认开」写成关。
	fresh.AutoUpdate = spec.AutoUpdateByDefault
	m.memStates.Store(name, fresh)
	return fresh
}

// normalize 把缺省字段补齐（新建行时 AutoUpdate 默认开、间隔默认 24h）。
func (m *Manager) normalize(st *ToolState, spec ToolSpec) *ToolState {
	if st.Repo == "" {
		st.Repo = spec.Repo
	}
	if st.CheckIntervalHours <= 0 {
		st.CheckIntervalHours = defaultInterval
	}
	if st.Status == "" {
		st.Status = statusMissing
	}
	return st
}

func (m *Manager) saveState(ctx context.Context, st *ToolState) {
	st.UpdatedAt = time.Now()
	m.memStates.Store(st.Name, st)
	if m.store == nil {
		return
	}
	if err := m.store.SaveState(ctx, st); err != nil {
		fmt.Printf("[toolruntime] 保存 %s 状态失败: %v\n", st.Name, err)
	}
}

func (m *Manager) record(ctx context.Context, rec UpdateRecord) {
	if m.store == nil {
		return
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now()
	}
	_ = m.store.AppendRecord(ctx, rec)
}

// ToolStatus 是对外（API/前端）的状态视图：DB 状态 + 磁盘事实合并。
type ToolStatus struct {
	ToolState
	Path            string `json:"path"`
	Managed         bool   `json:"managed"`      // 路径来自托管目录
	DiskVersion     string `json:"disk_version"` // 二进制自报版本（尽力而为）
	DiskSHA256      string `json:"disk_sha256"`
	UpdateAvailable bool   `json:"update_available"`
}

// Status 汇总全部受管工具状态。
func (m *Manager) Status(ctx context.Context) []ToolStatus {
	out := make([]ToolStatus, 0, len(Specs))
	for _, spec := range Specs {
		st := m.loadState(ctx, spec.Name)
		status := ToolStatus{ToolState: *st}
		status.Path = m.ResolveToolPath(spec.Name)
		status.Managed = status.Path != "" && samePath(status.Path, m.BinaryPath(spec.Name))
		if status.Path != "" {
			status.DiskSHA256, _ = fileSHA256(status.Path)
			status.DiskVersion = m.probeVersion(ctx, spec.Name, status.Path)
			if status.InstalledVersion == "" && status.DiskVersion != "" {
				status.InstalledVersion = status.DiskVersion
			}
		}
		switch {
		case status.Path == "":
			status.Status = statusMissing
		case status.Status == statusReview:
			// 保留 needs_review，直到人工处理
		case m.newerAvailable(st):
			status.Status = statusStale
		default:
			status.Status = statusOK
		}
		status.UpdateAvailable = m.newerAvailable(st) && st.PinnedVersion == ""
		out = append(out, status)
	}
	return out
}

func (m *Manager) newerAvailable(st *ToolState) bool {
	if st.LatestVersion == "" || st.PinnedVersion != "" {
		return false
	}
	cur := st.InstalledVersion
	if cur == "" {
		return true
	}
	c, err := compareVersion(cur, st.LatestVersion)
	return err == nil && c < 0
}

func samePath(a, b string) bool {
	ra, err1 := filepath.Abs(a)
	rb, err2 := filepath.Abs(b)
	return err1 == nil && err2 == nil && ra == rb
}

// ---------------------------------------------------------------------------
// 检查与更新
// ---------------------------------------------------------------------------

// Check 查询上游最新版本并落库；不执行安装。
func (m *Manager) Check(ctx context.Context, name string) (*ToolStatus, error) {
	spec, ok := Spec(name)
	if !ok {
		return nil, fmt.Errorf("未知工具: %s", name)
	}
	mu := m.lockTool(name)
	mu.Lock()
	defer mu.Unlock()

	releases, err := m.listReleases(ctx, spec.Repo)
	if err != nil {
		return nil, err
	}
	st := m.loadState(ctx, name)
	if best, found := pickLatest(releases, spec.MinVersion); found {
		st.LatestVersion = trimV(best.TagName)
		st.LatestCheckedAt = time.Now()
		m.saveState(ctx, st)
	}
	return m.oneStatus(ctx, st), nil
}

func (m *Manager) oneStatus(ctx context.Context, st *ToolState) *ToolStatus {
	for _, s := range m.Status(ctx) {
		if s.Name == st.Name {
			return &s
		}
	}
	return &ToolStatus{ToolState: *st}
}

// CheckDue 检查到期工具（供定时循环）。autoUpdateOnly=true 时只处理
// auto_update 开启的工具，且发现新版本直接更新。
func (m *Manager) CheckDue(ctx context.Context, autoUpdateOnly bool) {
	for _, spec := range Specs {
		st := m.loadState(ctx, spec.Name)
		if autoUpdateOnly && !st.AutoUpdate {
			continue
		}
		if !m.checkDueForState(st) {
			continue
		}
		if _, err := m.Check(ctx, spec.Name); err != nil {
			fmt.Printf("[toolruntime] 检查 %s 更新失败: %v\n", spec.Name, err)
			continue
		}
		if autoUpdateOnly {
			updated := m.loadState(ctx, spec.Name)
			if m.newerAvailable(updated) {
				if _, err := m.Update(ctx, spec.Name, false); err != nil {
					fmt.Printf("[toolruntime] 自动更新 %s 失败: %v\n", spec.Name, err)
				}
			}
		}
	}
}

// checkDueForState 判断某工具是否到了检查周期。
func (m *Manager) checkDueForState(st *ToolState) bool {
	return st.LatestCheckedAt.IsZero() ||
		time.Since(st.LatestCheckedAt) > time.Duration(st.CheckIntervalHours)*time.Hour
}

// EnsureInstalled 确保工具可用：本地任何位置都没有且 auto_update 开启时，
// 安装 DefaultVersion。供服务启动/部署流调用；扫描路径不调它（不阻断扫描）。
func (m *Manager) EnsureInstalled(ctx context.Context, name string) (string, error) {
	if p := m.ResolveToolPath(name); p != "" {
		return p, nil
	}
	st := m.loadState(ctx, name)
	if !st.AutoUpdate {
		return "", fmt.Errorf("%s 未安装且 auto_update 关闭", name)
	}
	if _, err := m.install(ctx, name, st.PinnedVersion, false); err != nil {
		return "", err
	}
	return m.BinaryPath(name), nil
}

// Update 安装指定/最新/pin 的版本。force=true 时同版本也重装。
func (m *Manager) Update(ctx context.Context, name string, force bool) (*ToolStatus, error) {
	spec, ok := Spec(name)
	if !ok {
		return nil, fmt.Errorf("未知工具: %s", name)
	}
	mu := m.lockTool(name)
	mu.Lock()
	defer mu.Unlock()

	if !m.updateMu.TryLock() {
		return nil, errors.New("已有更新流程在进行中")
	}
	defer m.updateMu.Unlock()

	st := m.loadState(ctx, name)
	target := st.PinnedVersion
	if target == "" {
		if st.LatestCheckedAt.IsZero() || time.Since(st.LatestCheckedAt) > 2*time.Hour {
			releases, err := m.listReleases(ctx, spec.Repo)
			if err != nil {
				return nil, err
			}
			if best, found := pickLatest(releases, spec.MinVersion); found {
				st.LatestVersion = trimV(best.TagName)
			}
		}
		target = st.LatestVersion
		if target == "" {
			target = spec.DefaultVersion
		}
	}
	newSt, err := m.install(ctx, name, target, force)
	if err != nil {
		return m.oneStatus(ctx, newSt), err
	}
	return m.oneStatus(ctx, newSt), nil
}

// install staged 安装核心流程：下载→校验→解压→探针→原子换入→落账。
// 返回最终状态（失败时也会带 needs_review 状态返回）。
func (m *Manager) install(ctx context.Context, name, version string, force bool) (*ToolState, error) {
	spec, _ := Spec(name)
	st := m.loadState(ctx, name)
	version = trimV(version)
	if version == "" {
		version = spec.DefaultVersion
	}

	// 同版本且二进制在位：force 才重装
	if !force && st.InstalledVersion == version && fileExists(m.BinaryPath(name)) {
		return st, nil
	}
	if st.PinnedVersion != "" && st.PinnedVersion != version && st.InstalledVersion == trimV(st.PinnedVersion) {
		// pin 与请求版本冲突时以 pin 为准
		version = trimV(st.PinnedVersion)
	}

	if err := os.MkdirAll(m.InstallDir(), 0o755); err != nil {
		return st, fmt.Errorf("创建安装目录失败: %w", err)
	}
	if err := os.MkdirAll(m.stageDir(), 0o700); err != nil {
		return st, fmt.Errorf("创建暂存目录失败: %w", err)
	}

	asset, err := spec.AssetName(version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return st, err
	}
	assetPath := filepath.Join(m.stageDir(), asset)
	if err := m.downloadToFile(ctx, spec.Repo, "v"+version, asset, assetPath); err != nil {
		return st, err
	}

	// sha256 校验：优先 release 附带的 checksums 清单
	sum, err := fileSHA256(assetPath)
	if err != nil {
		return st, err
	}
	if want, checked, err := m.verifyChecksum(ctx, spec, version, asset, sum); err != nil {
		return st, err
	} else if !checked {
		if os.Getenv(allowUncheckedEnv) != "1" {
			return st, fmt.Errorf("%s@%s 无 checksums 清单可用，拒绝安装（可用 %s=1 放行）",
				name, version, allowUncheckedEnv)
		}
		fmt.Printf("[toolruntime] 警告: %s@%s 未校验 checksum（TOFU sha256=%s）\n", name, version, sum[:12])
	} else if want != sum {
		return st, fmt.Errorf("%s@%s sha256 不匹配（清单 %s != 实际 %s）", name, version, want[:12], sum[:12])
	}

	// 解压/整理出可执行文件
	binPath, err := m.materializeBinary(spec, assetPath)
	if err != nil {
		return st, err
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		return st, err
	}

	// 探针门：flag 缺失 → needs_review，保持旧版本在位
	if missing, err := checkFlags(ctx, binPath, spec); err != nil {
		m.markReview(ctx, st, "探针无法执行: "+err.Error())
		m.record(ctx, UpdateRecord{Tool: name, ToVersion: version, SHA256: sum, OK: false, Note: err.Error()})
		return st, err
	} else if len(missing) > 0 {
		err := fmt.Errorf("%s@%s 帮助输出缺少 flag: %s（疑似上游不兼容改动，已保持 %s）",
			name, version, strings.Join(missing, " "), st.InstalledVersion)
		m.markReview(ctx, st, fmt.Sprintf("缺少 flag: %s", strings.Join(missing, " ")))
		m.record(ctx, UpdateRecord{Tool: name, ToVersion: version, SHA256: sum, OK: false, Note: err.Error()})
		return st, err
	}

	// 原子换入：旧二进制挪到 .prev 供回滚
	dest := m.BinaryPath(name)
	prev := dest + ".prev"
	if fileExists(dest) {
		if runtime.GOOS == "windows" {
			_ = os.Remove(prev)
		}
		if err := os.Rename(dest, prev); err != nil {
			return st, fmt.Errorf("备份旧版本失败: %w", err)
		}
	}
	if err := os.Rename(binPath, dest); err != nil {
		// 尽力恢复
		if fileExists(prev) {
			_ = os.Rename(prev, dest)
		}
		return st, fmt.Errorf("换入新版本失败: %w", err)
	}
	_ = os.Remove(assetPath)

	oldVersion, oldSum := st.InstalledVersion, st.InstalledSHA256
	st.PrevVersion, st.PrevSHA256 = oldVersion, oldSum
	st.InstalledVersion, st.InstalledSHA256 = version, sum
	if v := m.probeVersion(ctx, name, dest); v != "" {
		st.InstalledVersion = v
	}
	st.Status, st.StatusNote = statusOK, ""
	m.saveState(ctx, st)
	m.record(ctx, UpdateRecord{
		Tool: name, FromVersion: oldVersion, ToVersion: st.InstalledVersion,
		SHA256: sum, OK: true, Note: "install",
	})
	fmt.Printf("[toolruntime] %s 已更新到 %s (%s)\n", name, st.InstalledVersion, sum[:12])
	return st, nil
}

// verifyChecksum 下载并比对 release 的 checksums 清单。
// 返回 (期望值, 是否完成校验, 错误)。
func (m *Manager) verifyChecksum(ctx context.Context, spec ToolSpec, version, asset, actual string) (string, bool, error) {
	manifestName := spec.checksumAssetName(version)
	if manifestName == "" {
		return "", false, nil
	}
	manifestPath := filepath.Join(m.stageDir(), manifestName)
	if err := m.downloadToFile(ctx, spec.Repo, "v"+version, manifestName, manifestPath); err != nil {
		// 清单下载失败视为「无法校验」，由调用方决定是否放行
		return "", false, nil
	}
	defer os.Remove(manifestPath)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", false, nil
	}
	want, ok := parseChecksums(data)[asset]
	if !ok {
		return "", false, nil
	}
	return want, true, nil
}

// materializeBinary 把下载的资产整理成单个可执行文件。
// zip 资产取包内 basename 以工具名开头的条目；tar.gz 同理；
// 裸二进制直接用。
func (m *Manager) materializeBinary(spec ToolSpec, assetPath string) (string, error) {
	if err := os.MkdirAll(m.stageDir(), 0o700); err != nil {
		return "", err
	}
	head := make([]byte, 4)
	f, err := os.Open(assetPath)
	if err != nil {
		return "", err
	}
	_, _ = f.Read(head)
	f.Close()

	out := filepath.Join(m.stageDir(), exeName(spec.Name)+".staged")
	switch {
	case bytes.Equal(head, []byte("PK\x03\x04")):
		if err := extractZipBinary(spec.Name, assetPath, out); err != nil {
			return "", err
		}
	case bytes.Equal(head, []byte("\x1f\x8b")):
		if err := extractTarGzBinary(spec.Name, assetPath, out); err != nil {
			return "", err
		}
	default:
		// 裸二进制
		if err := os.Rename(assetPath, out); err != nil {
			return "", err
		}
	}
	return out, nil
}

// extractZipBinary 只取压缩包里 basename 匹配工具名的单个可执行文件，
// 不展开目录，从根上避免 zip-slip。
func extractZipBinary(name, zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("打开 %s release 压缩包失败: %w", name, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasPrefix(filepath.Base(f.Name), name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		err = writeLimited(rc, dest)
		rc.Close()
		return err
	}
	return fmt.Errorf("%s 压缩包里没有找到可执行文件", name)
}

// extractTarGzBinary 同 extractZipBinary，针对 tar.gz（gost 系）。
func extractTarGzBinary(name, archivePath, dest string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("打开 %s gzip 失败: %w", name, err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 %s tar 失败: %w", name, err)
		}
		if hdr.Typeflag != tar.TypeReg || !strings.HasPrefix(filepath.Base(hdr.Name), name) {
			continue
		}
		return writeLimited(tr, dest)
	}
	return fmt.Errorf("%s 压缩包里没有找到可执行文件", name)
}

func writeLimited(r io.Reader, dest string) error {
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(r, downloadLimit))
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("解压失败: %w", copyErr)
	}
	return closeErr
}

// Rollback 回滚到上一个版本（.prev）。
func (m *Manager) Rollback(ctx context.Context, name string) (*ToolStatus, error) {
	if _, ok := Spec(name); !ok {
		return nil, fmt.Errorf("未知工具: %s", name)
	}
	mu := m.lockTool(name)
	mu.Lock()
	defer mu.Unlock()

	dest := m.BinaryPath(name)
	prev := dest + ".prev"
	if !fileExists(prev) {
		return nil, fmt.Errorf("%s 没有可回滚的旧版本", name)
	}
	trash := dest + ".trash"
	if fileExists(dest) {
		_ = os.Rename(dest, trash)
	}
	if err := os.Rename(prev, dest); err != nil {
		if fileExists(trash) {
			_ = os.Rename(trash, dest)
		}
		return nil, fmt.Errorf("回滚失败: %w", err)
	}
	_ = os.Remove(trash)

	st := m.loadState(ctx, name)
	cur := st.InstalledVersion
	st.InstalledVersion, st.InstalledSHA256 = st.PrevVersion, st.PrevSHA256
	if sum, err := fileSHA256(dest); err == nil {
		st.InstalledSHA256 = sum
	}
	if v := m.probeVersion(ctx, name, dest); v != "" {
		st.InstalledVersion = v
	}
	st.PrevVersion, st.PrevSHA256 = "", ""
	st.Status, st.StatusNote = statusOK, ""
	m.saveState(ctx, st)
	m.record(ctx, UpdateRecord{
		Tool: name, FromVersion: cur, ToVersion: st.InstalledVersion,
		SHA256: st.InstalledSHA256, OK: true, Note: "rollback",
	})
	return m.oneStatus(ctx, st), nil
}

func (m *Manager) markReview(ctx context.Context, st *ToolState, note string) {
	st.Status, st.StatusNote = statusReview, note
	m.saveState(ctx, st)
}

// ApplySettings 更新一个工具的持久设置（pin / auto_update / 检查间隔）。
func (m *Manager) ApplySettings(ctx context.Context, name string, mutate func(*ToolState)) (*ToolStatus, error) {
	if _, ok := Spec(name); !ok {
		return nil, fmt.Errorf("未知工具: %s", name)
	}
	mu := m.lockTool(name)
	mu.Lock()
	defer mu.Unlock()

	st := m.loadState(ctx, name)
	mutate(st)
	if st.CheckIntervalHours < 1 {
		st.CheckIntervalHours = 1
	}
	st.PinnedVersion = trimV(st.PinnedVersion)
	m.saveState(ctx, st)
	return m.oneStatus(ctx, st), nil
}
