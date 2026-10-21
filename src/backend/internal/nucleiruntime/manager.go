// Package nuclei 管理项目自带的 nuclei 外部二进制、模板目录和扫描执行。
//
// 设计约束（与 4zreark 的部署形态一致）：
//   - 不依赖系统 PATH，也不在镜像里预装 nuclei；二进制与模板全部落在
//     <dataDir>/nuclei/ 下，随项目数据卷迁移/备份。
//   - 首次使用自动下载固定版本的官方 release；之后的扫描前按间隔自动
//     更新二进制与模板，也可以用 nuclei_update 手动触发。
//   - 所有子进程都显式设置 HOME/XDG_* 到项目目录，避免 nuclei 往宿主
//     用户目录写配置或模板。
package nucleiruntime

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultVersion 是首次自动下载的 nuclei 版本；可用设置 nuclei.version 覆盖。
	DefaultVersion = "3.11.1"

	// Setting* 是系统设置键。所有键都通过 Settings 接口读写，未配置时使用默认值。
	SettingEnabled             = "nuclei.enabled"
	SettingAutoUpdate          = "nuclei.auto_update"
	SettingUpdateIntervalHours = "nuclei.update_interval_hours"
	SettingVersion             = "nuclei.version"
	SettingBinaryPath          = "nuclei.binary_path"
	SettingTemplatesDir        = "nuclei.templates_dir"
	SettingCustomTemplatesDir  = "nuclei.custom_templates_dir"
	SettingLastUpdate          = "nuclei.last_update"
	SettingInteractsh          = "nuclei.interactsh"
	SettingMaxScanSeconds      = "nuclei.max_scan_seconds"
	SettingProxy               = "nuclei.proxy"

	defaultUpdateInterval = 24 * time.Hour
	minUpdateInterval     = time.Hour
	defaultMaxScan        = 10 * time.Minute
	maxMaxScan            = 30 * time.Minute
	downloadLimit         = 256 << 20 // 256 MB，远大于 nuclei release 体积
	commandOutputLimit    = 64 << 10  // 子进程 stderr 只保留最后 64KB
)

var (
	ErrDisabled         = errors.New("nuclei 已停用（设置 nuclei.enabled=false）")
	ErrBinaryMissing    = errors.New("nuclei 二进制未安装；启用 nuclei.auto_update 或运行 nuclei_update")
	ErrTemplatesMissing = errors.New("nuclei 模板未安装；运行 nuclei_update 或启用 nuclei.auto_update")
)

// Settings 是管理器需要的最小设置接口；*db.DB 直接满足。
type Settings interface {
	GetSetting(key string) (value string, ok bool, err error)
	SetSetting(key, value string) error
}

// Manager 持有项目内 nuclei 的路径、锁和模板索引。零值不可用，请用 New。
type Manager struct {
	root     string
	settings Settings
	client   *http.Client

	// runMu 串行化「更新」与「扫描」：更新取写锁，扫描取读锁。避免一边替换
	// 二进制/模板、一边跑扫描。
	runMu sync.RWMutex

	// updateMu 用 TryLock 防止两个更新流程并发（例如两个 agent 同时触发）。
	updateMu sync.Mutex

	indexMu sync.Mutex
	index   *Index

	// ctx 是服务器的长生命周期上下文；首次成功使用后启动定时更新循环。
	ctx      context.Context
	loopOnce sync.Once
}

// New 创建管理器。root 通常是 <dataDir>/nuclei；settings 可为 nil（测试/未接库）。
func New(root string, settings Settings) *Manager {
	return &Manager{
		root:     filepath.Clean(root),
		settings: settings,
		client: &http.Client{
			Timeout: 30 * time.Minute,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				ResponseHeaderTimeout: 30 * time.Second,
			},
		},
	}
}

func (m *Manager) Root() string { return m.root }

// VersionSetting 返回当前配置的引导版本（未配置时为默认版本）。
func (m *Manager) VersionSetting() string { return m.version() }

// UpdateIntervalHours 返回自动更新间隔（小时）。
func (m *Manager) UpdateIntervalHours() int { return int(m.UpdateInterval().Hours()) }

// MaxScanSeconds 返回默认扫描时长上限（秒）。
func (m *Manager) MaxScanSeconds() int { return int(m.MaxScanDuration().Seconds()) }

// SetEnabled 设置 nuclei 工具总开关。
func (m *Manager) SetEnabled(v bool) { m.setSetting(SettingEnabled, strconv.FormatBool(v)) }

// SetAutoUpdate 设置扫描前/后台自动更新开关。
func (m *Manager) SetAutoUpdate(v bool) { m.setSetting(SettingAutoUpdate, strconv.FormatBool(v)) }

// SetUpdateIntervalHours 设置自动更新间隔；最小 1 小时。
func (m *Manager) SetUpdateIntervalHours(n int) {
	if n < 1 {
		n = 1
	}
	m.setSetting(SettingUpdateIntervalHours, strconv.Itoa(n))
}

// SetVersion 设置首次下载的引导版本；空串恢复默认。
func (m *Manager) SetVersion(v string) { m.setSetting(SettingVersion, strings.TrimSpace(v)) }

// SetInteractsh 设置 nuclei 是否使用 interactsh 带外验证。
func (m *Manager) SetInteractsh(v bool) { m.setSetting(SettingInteractsh, strconv.FormatBool(v)) }

// SetMaxScanSeconds 设置默认扫描时长上限；限制在 60..1800 秒。
func (m *Manager) SetMaxScanSeconds(n int) {
	if n < 60 {
		n = 60
	}
	if max := int(maxMaxScan.Seconds()); n > max {
		n = max
	}
	m.setSetting(SettingMaxScanSeconds, strconv.Itoa(n))
}

// Proxy 返回 nuclei 下载/更新使用的代理（空=直连，遵循环境变量）。
func (m *Manager) Proxy() string { return m.setting(SettingProxy, "") }

// SetProxy 设置 nuclei 下载/更新代理；支持 http/https/socks5。
func (m *Manager) SetProxy(v string) { m.setSetting(SettingProxy, strings.TrimSpace(v)) }

// httpClient 每次按当前代理设置构造客户端，设置改动无需重启。
func (m *Manager) httpClient() *http.Client {
	c := *m.client
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	if p := m.Proxy(); p != "" {
		if u, err := url.Parse(p); err == nil && u.Host != "" {
			tr.Proxy = func(req *http.Request) (*url.URL, error) {
				// GitHub release 的资产会 302 到 release-assets.githubusercontent.com。
				// 部分代理节点对该 CDN 的 TLS 握手不兼容，直连反而可用；这里只对
				// 资产 CDN 绕过代理，初始 github.com 请求仍走代理。
				switch strings.ToLower(req.URL.Hostname()) {
				case "release-assets.githubusercontent.com", "objects.githubusercontent.com":
					return nil, nil
				}
				return u, nil
			}
		}
	}
	c.Transport = tr
	return &c
}

// Progress 是一次 nuclei 更新的阶段进度，供前端进度条展示。
type Progress struct {
	Phase   string `json:"phase"`
	Percent int    `json:"percent"`
	Message string `json:"message,omitempty"`
}

func reportProgress(progress func(Progress), phase string, percent int, message string) {
	if progress == nil {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	progress(Progress{Phase: phase, Percent: percent, Message: message})
}

// SetContext 注入服务器长生命周期上下文，用于首次使用后的定时自动更新。
// 只应在任何 Ensure/Run 之前调用一次。
func (m *Manager) SetContext(ctx context.Context) { m.ctx = ctx }

// startAutoLoop 在首次成功使用后启动一个低频更新循环：每小时检查一次是否
// 到期，到期才真正更新。这样长驻部署无需人工干预；从未使用 nuclei 的进程
// 不会因为启动就发起网络请求。
func (m *Manager) startAutoLoop() {
	if m == nil || m.ctx == nil {
		return
	}
	m.loopOnce.Do(func() {
		go func() {
			timer := time.NewTimer(time.Hour)
			defer timer.Stop()
			for {
				select {
				case <-m.ctx.Done():
					return
				case <-timer.C:
				}
				if m.Enabled() && m.AutoUpdate() && m.updateDue(time.Now()) {
					if _, err := m.Update(m.ctx, false, false, false); err != nil {
						log.Printf("[nuclei] 定时自动更新失败: %v", err)
					}
				}
				timer.Reset(6 * time.Hour)
			}
		}()
	})
}

// BinaryPath 返回实际使用的二进制路径：设置 nuclei.binary_path 优先，否则
// 使用项目内的 <root>/bin/nuclei[.exe]。
func (m *Manager) BinaryPath() string {
	if p := m.setting(SettingBinaryPath, ""); p != "" {
		return p
	}
	name := "nuclei"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(m.root, "bin", name)
}

// TemplatesDir 返回官方模板目录：设置 nuclei.templates_dir 优先，否则
// 使用项目内的 <root>/templates。该目录由 nuclei -update-templates 维护。
func (m *Manager) TemplatesDir() string {
	if p := m.setting(SettingTemplatesDir, ""); p != "" {
		return p
	}
	return filepath.Join(m.root, "templates")
}

// CustomTemplatesDir 返回自定义模板目录：设置 nuclei.custom_templates_dir
// 优先，否则使用项目内的 <root>/custom-templates。该目录不会被模板更新覆盖。
func (m *Manager) CustomTemplatesDir() string {
	if p := m.setting(SettingCustomTemplatesDir, ""); p != "" {
		return p
	}
	return filepath.Join(m.root, "custom-templates")
}

func (m *Manager) ScansDir() string { return filepath.Join(m.root, "scans") }
func (m *Manager) homeDir() string  { return filepath.Join(m.root, "home") }
func (m *Manager) tmpDir() string   { return filepath.Join(m.root, "tmp") }

func (m *Manager) Enabled() bool {
	v := strings.ToLower(m.setting(SettingEnabled, "true"))
	return v != "false" && v != "0" && v != "off" && v != "no"
}

func (m *Manager) AutoUpdate() bool {
	v := strings.ToLower(m.setting(SettingAutoUpdate, "true"))
	return v != "false" && v != "0" && v != "off" && v != "no"
}

func (m *Manager) Interactsh() bool {
	v := strings.ToLower(m.setting(SettingInteractsh, "false"))
	return v == "true" || v == "1" || v == "on" || v == "yes"
}

func (m *Manager) UpdateInterval() time.Duration {
	v := strings.TrimSpace(m.setting(SettingUpdateIntervalHours, ""))
	if v == "" {
		return defaultUpdateInterval
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return defaultUpdateInterval
	}
	d := time.Duration(n) * time.Hour
	if d < minUpdateInterval {
		return minUpdateInterval
	}
	return d
}

func (m *Manager) MaxScanDuration() time.Duration {
	v := strings.TrimSpace(m.setting(SettingMaxScanSeconds, ""))
	if v == "" {
		return defaultMaxScan
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return defaultMaxScan
	}
	d := time.Duration(n) * time.Second
	if d > maxMaxScan {
		return maxMaxScan
	}
	return d
}

func (m *Manager) version() string {
	v := strings.TrimSpace(m.setting(SettingVersion, ""))
	if v == "" {
		v = DefaultVersion
	}
	v = strings.TrimPrefix(v, "v")
	// 版本号会拼进下载 URL，只允许数字/点/短横线。
	for _, r := range v {
		if (r < '0' || r > '9') && r != '.' && r != '-' {
			return DefaultVersion
		}
	}
	if v == "" || strings.HasPrefix(v, ".") {
		return DefaultVersion
	}
	return v
}

func (m *Manager) setting(key, def string) string {
	if m == nil || m.settings == nil {
		return def
	}
	v, ok, err := m.settings.GetSetting(key)
	if err != nil || !ok {
		return def
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v
}

func (m *Manager) setSetting(key, value string) {
	if m == nil || m.settings == nil {
		return
	}
	if err := m.settings.SetSetting(key, value); err != nil {
		log.Printf("[nuclei] 保存设置 %s 失败: %v", key, err)
	}
}

func (m *Manager) lastUpdate() time.Time {
	v := strings.TrimSpace(m.setting(SettingLastUpdate, ""))
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t
}

func (m *Manager) updateDue(now time.Time) bool {
	last := m.lastUpdate()
	if last.IsZero() {
		return true
	}
	return now.Sub(last) >= m.UpdateInterval()
}

// Ensure 保证扫描可执行：二进制存在、模板存在，并在到期时自动更新。
// auto=false 时只做存在性检查，不下载、不更新（用于离线/测试）。
func (m *Manager) Ensure(ctx context.Context, auto bool) (*EnsureResult, error) {
	if m == nil {
		return nil, errors.New("nuclei 管理器未初始化")
	}
	if !m.Enabled() {
		return nil, ErrDisabled
	}
	res := &EnsureResult{BinaryPath: m.BinaryPath(), TemplatesDir: m.TemplatesDir()}

	if override := m.setting(SettingBinaryPath, ""); override == "" {
		if !fileExists(res.BinaryPath) {
			if !auto {
				return nil, ErrBinaryMissing
			}
			if err := m.installBinary(ctx, m.version(), nil); err != nil {
				return nil, fmt.Errorf("下载 nuclei 二进制失败: %w", err)
			}
			res.Installed = true
		}
	} else if !fileExists(override) {
		return nil, fmt.Errorf("设置 nuclei.binary_path 指向的文件不存在: %s", override)
	}

	if !hasTemplates(res.TemplatesDir) {
		if !auto {
			return nil, ErrTemplatesMissing
		}
		if err := m.updateTemplates(ctx, res.BinaryPath, res.TemplatesDir); err != nil {
			return nil, fmt.Errorf("下载 nuclei 模板失败: %w", err)
		}
		res.Updated = true
	}

	if auto && m.updateDue(time.Now()) {
		ur, err := m.updateLocked(ctx, false, false, false, nil)
		if err != nil {
			// 已有可用二进制/模板时，自动更新失败不应阻断扫描。
			res.Warnings = append(res.Warnings, "自动更新失败: "+err.Error())
			log.Printf("[nuclei] 自动更新失败，继续使用现有版本: %v", err)
		} else {
			res.Updated = true
			res.Warnings = append(res.Warnings, ur.Warnings...)
			res.BinaryVersion = ur.BinaryVersion
			res.TemplateCount = ur.TemplateCount
		}
	}
	if res.BinaryVersion == "" {
		res.BinaryVersion = m.binaryVersion(ctx, res.BinaryPath)
	}
	if res.TemplateCount == 0 {
		res.TemplateCount = countTemplateFiles(res.TemplatesDir)
	}
	if auto {
		m.startAutoLoop()
	}
	return res, nil
}

// Update 手动更新二进制和/或模板。force=false 时仍会执行；保留参数给调用方
// 语义表达（当前更新命令本身幂等）。
func (m *Manager) Update(ctx context.Context, force, binaryOnly, templatesOnly bool) (*UpdateResult, error) {
	return m.UpdateWithProgress(ctx, force, binaryOnly, templatesOnly, nil)
}

// UpdateWithProgress 与 Update 相同，但会通过 progress 回调报告阶段进度。
func (m *Manager) UpdateWithProgress(ctx context.Context, force, binaryOnly, templatesOnly bool, progress func(Progress)) (*UpdateResult, error) {
	if m == nil {
		return nil, errors.New("nuclei 管理器未初始化")
	}
	if !m.Enabled() {
		return nil, ErrDisabled
	}
	if binaryOnly && templatesOnly {
		return nil, errors.New("binary_only 与 templates_only 不能同时为 true")
	}
	return m.updateLocked(ctx, force, binaryOnly, templatesOnly, progress)
}

func (m *Manager) updateLocked(ctx context.Context, force, binaryOnly, templatesOnly bool, progress func(Progress)) (*UpdateResult, error) {
	if !m.updateMu.TryLock() {
		return nil, errors.New("nuclei 更新正在进行中，请稍后再试")
	}
	defer m.updateMu.Unlock()

	m.runMu.Lock()
	defer m.runMu.Unlock()

	res := &UpdateResult{BinaryPath: m.BinaryPath(), TemplatesDir: m.TemplatesDir()}
	reportProgress(progress, "检查 nuclei 二进制", 5, "")
	if err := m.ensureBinaryLocked(ctx, progress); err != nil {
		return nil, err
	}

	if !templatesOnly {
		reportProgress(progress, "更新 nuclei 二进制", 50, "")
		if override := m.setting(SettingBinaryPath, ""); override != "" {
			res.Warnings = append(res.Warnings, "nuclei.binary_path 由用户指定，跳过二进制自更新")
		} else if err := m.updateBinary(ctx, res.BinaryPath); err != nil {
			res.Warnings = append(res.Warnings, "二进制更新失败: "+err.Error())
		} else {
			res.Updated = true
		}
		reportProgress(progress, "二进制就绪", 60, "")
	}
	if !binaryOnly {
		reportProgress(progress, "更新官方模板", 65, "模板较多时可能需要几分钟")
		if err := m.updateTemplates(ctx, res.BinaryPath, res.TemplatesDir); err != nil {
			if !hasTemplates(res.TemplatesDir) {
				return nil, err
			}
			// 已有模板时，更新失败只记警告：继续用现有模板扫描，
			// 同时推进更新时钟，避免每次扫描前都卡在同一个网络错误上。
			res.Warnings = append(res.Warnings, "官方模板更新失败，继续使用现有模板: "+err.Error())
			res.LastUpdate = time.Now()
			m.setSetting(SettingLastUpdate, res.LastUpdate.Format(time.RFC3339))
			reportProgress(progress, "模板更新失败，使用现有模板", 95, err.Error())
		} else {
			res.Updated = true
			// 只有模板更新成功才推进自动更新时钟；binary_only 不应把模板
			// 也标记为“刚更新过”。
			res.LastUpdate = time.Now()
			m.setSetting(SettingLastUpdate, res.LastUpdate.Format(time.RFC3339))
			reportProgress(progress, "模板更新完成", 95, "")
		}
	} else {
		res.LastUpdate = m.lastUpdate()
	}

	m.invalidateIndex()
	res.BinaryVersion = m.binaryVersion(ctx, res.BinaryPath)
	res.TemplateCount = countTemplateFiles(res.TemplatesDir)
	res.CustomTemplateCount = countTemplateFiles(m.CustomTemplatesDir())
	reportProgress(progress, "完成", 100, "")
	return res, nil
}

func (m *Manager) ensureBinaryLocked(ctx context.Context, progress func(Progress)) error {
	p := m.BinaryPath()
	if fileExists(p) {
		reportProgress(progress, "二进制已存在", 45, "")
		return nil
	}
	if override := m.setting(SettingBinaryPath, ""); override != "" {
		return fmt.Errorf("设置 nuclei.binary_path 指向的文件不存在: %s", override)
	}
	if err := m.installBinary(ctx, m.version(), progress); err != nil {
		return err
	}
	reportProgress(progress, "二进制安装完成", 45, "")
	return nil
}

// updateBinary 调用 nuclei 自带的 -update。它会把新版本替换到当前可执行文件；
// 项目内二进制可写，因此不需要重走下载流程。
func (m *Manager) updateBinary(ctx context.Context, binary string) error {
	if !fileExists(binary) {
		return ErrBinaryMissing
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	_, err := m.runCommand(ctx, binary, "-update", "-duc")
	if err != nil {
		return fmt.Errorf("nuclei -update 失败（继续使用当前版本）: %w", err)
	}
	return nil
}

func (m *Manager) updateTemplates(ctx context.Context, binary, templatesDir string) error {
	if !fileExists(binary) {
		return ErrBinaryMissing
	}
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		return fmt.Errorf("创建模板目录失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	// 不带 -duc：该标志会连显式 -update-templates 的版本检查一起跳过，
	// 导致命令退出码 0 但什么都没下载。
	out, err := m.runCommand(ctx, binary, "-update-templates", "-ud", templatesDir)
	if err != nil {
		return fmt.Errorf("%w: %s", err, tail(out))
	}
	if !hasTemplates(templatesDir) {
		return fmt.Errorf("模板更新命令结束但目录内没有可用模板: %s（输出: %s）", templatesDir, tail(out))
	}
	return nil
}

// binaryVersion 读取 nuclei -version 的首行；失败返回空串（状态展示用）。
func (m *Manager) binaryVersion(ctx context.Context, binary string) string {
	if !fileExists(binary) {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := m.runCommand(ctx, binary, "-version")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(ansiEscape.ReplaceAllString(line, ""))
		if line == "" {
			continue
		}
		if len(line) > 240 {
			line = line[:240]
		}
		return line
	}
	return ""
}

// Status 返回项目内 nuclei 的安装/更新状态。不会触发下载或更新。
func (m *Manager) Status(ctx context.Context) *Status {
	if m == nil {
		return &Status{}
	}
	st := &Status{
		Root:                  m.root,
		BinaryPath:            m.BinaryPath(),
		TemplatesDir:          m.TemplatesDir(),
		CustomTemplatesDir:    m.CustomTemplatesDir(),
		BinaryExists:          fileExists(m.BinaryPath()),
		TemplatesExists:       hasTemplates(m.TemplatesDir()),
		CustomTemplatesExists: hasTemplates(m.CustomTemplatesDir()),
		TemplateCount:         countTemplateFiles(m.TemplatesDir()),
		CustomTemplateCount:   countTemplateFiles(m.CustomTemplatesDir()),
		AutoUpdate:            m.AutoUpdate(),
		UpdateIntervalHours:   int(m.UpdateInterval().Hours()),
		Interactsh:            m.Interactsh(),
		VersionSetting:        m.version(),
	}
	if !m.lastUpdate().IsZero() {
		st.LastUpdate = m.lastUpdate().Format(time.RFC3339)
	}
	if st.BinaryExists {
		st.BinaryVersion = m.binaryVersion(ctx, st.BinaryPath)
	}
	if override := m.setting(SettingBinaryPath, ""); override != "" {
		st.Warnings = append(st.Warnings, "nuclei.binary_path 由用户指定；自动更新只会更新模板")
	}
	return st
}

// Index 返回模板索引（官方 + 自定义，首次调用时构建）。更新/写入后自动失效。
func (m *Manager) Index() *Index {
	m.indexMu.Lock()
	defer m.indexMu.Unlock()
	if m.index == nil {
		m.index = NewMultiIndex([]IndexDir{
			{Path: m.TemplatesDir(), Source: SourceOfficial},
			{Path: m.CustomTemplatesDir(), Source: SourceCustom},
		})
	}
	return m.index
}

func (m *Manager) invalidateIndex() {
	m.indexMu.Lock()
	defer m.indexMu.Unlock()
	m.index = nil
}

// env 把 nuclei 的 HOME/XDG/TMPDIR 全部收敛到项目目录，避免写宿主用户目录。
// 设置了 nuclei.proxy 时，同时覆盖 HTTP(S)_PROXY/ALL_PROXY，确保
// nuclei -update / -update-templates 也走同一个代理。
func (m *Manager) env() []string {
	home := m.homeDir()
	_ = os.MkdirAll(home, 0o700)
	_ = os.MkdirAll(m.tmpDir(), 0o700)
	proxy := m.Proxy()
	keep := make([]string, 0, len(os.Environ())+10)
	for _, e := range os.Environ() {
		switch {
		case strings.HasPrefix(e, "HOME="),
			strings.HasPrefix(e, "XDG_CONFIG_HOME="),
			strings.HasPrefix(e, "XDG_CACHE_HOME="),
			strings.HasPrefix(e, "XDG_DATA_HOME="),
			strings.HasPrefix(e, "TMPDIR="):
			continue
		case proxy != "" && isProxyEnv(e):
			continue
		}
		keep = append(keep, e)
	}
	keep = append(keep,
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
		"XDG_DATA_HOME="+filepath.Join(home, ".local", "share"),
		"TMPDIR="+m.tmpDir(),
	)
	if proxy != "" {
		keep = append(keep,
			"HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy, "ALL_PROXY="+proxy,
			"http_proxy="+proxy, "https_proxy="+proxy, "all_proxy="+proxy,
			// GitHub release 资产 CDN 对部分代理节点不兼容，直连更稳。
			"NO_PROXY=release-assets.githubusercontent.com,objects.githubusercontent.com",
			"no_proxy=release-assets.githubusercontent.com,objects.githubusercontent.com",
		)
	}
	return keep
}

func isProxyEnv(e string) bool {
	name := strings.ToUpper(strings.SplitN(e, "=", 2)[0])
	switch name {
	case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
		return true
	}
	return false
}

func (m *Manager) runCommand(ctx context.Context, binary string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = m.root
	cmd.Env = m.env()
	out, err := cmd.CombinedOutput()
	if len(out) > commandOutputLimit {
		out = out[len(out)-commandOutputLimit:]
	}
	return string(out), err
}

func fileExists(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

func tail(s string) string {
	s = strings.TrimSpace(ansiEscape.ReplaceAllString(s, ""))
	if len(s) > 2000 {
		s = s[len(s)-2000:]
	}
	return s
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// EnsureResult 描述 Ensure 的结果。
type EnsureResult struct {
	BinaryPath    string   `json:"binary_path"`
	BinaryVersion string   `json:"binary_version,omitempty"`
	TemplatesDir  string   `json:"templates_dir"`
	TemplateCount int      `json:"template_count,omitempty"`
	Installed     bool     `json:"installed"`
	Updated       bool     `json:"updated"`
	Warnings      []string `json:"warnings,omitempty"`
}

// UpdateResult 描述一次手动更新的结果。
type UpdateResult struct {
	BinaryPath          string    `json:"binary_path"`
	BinaryVersion       string    `json:"binary_version,omitempty"`
	TemplatesDir        string    `json:"templates_dir"`
	TemplateCount       int       `json:"template_count"`
	CustomTemplateCount int       `json:"custom_template_count"`
	Updated             bool      `json:"updated"`
	LastUpdate          time.Time `json:"last_update"`
	Warnings            []string  `json:"warnings,omitempty"`
}

// Status 是 nuclei_status 工具的返回结构。
type Status struct {
	Root                  string   `json:"root"`
	BinaryPath            string   `json:"binary_path"`
	BinaryExists          bool     `json:"binary_exists"`
	BinaryVersion         string   `json:"binary_version,omitempty"`
	TemplatesDir          string   `json:"templates_dir"`
	CustomTemplatesDir    string   `json:"custom_templates_dir"`
	TemplatesExists       bool     `json:"templates_exists"`
	CustomTemplatesExists bool     `json:"custom_templates_exists"`
	TemplateCount         int      `json:"template_count"`
	CustomTemplateCount   int      `json:"custom_template_count"`
	VersionSetting        string   `json:"version_setting"`
	AutoUpdate            bool     `json:"auto_update"`
	UpdateIntervalHours   int      `json:"update_interval_hours"`
	LastUpdate            string   `json:"last_update,omitempty"`
	Interactsh            bool     `json:"interactsh"`
	Warnings              []string `json:"warnings,omitempty"`
}
