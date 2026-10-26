package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/nucleiruntime"
)

// NucleiRuntimeService 管理项目内 nuclei 二进制与模板目录。
// 模板库的事实源仍是 PG；本服务只负责「可执行文件 + 上游模板快照」的
// 下载、更新与状态查询，供 POC/自动验证链路取二进制路径。
type NucleiRuntimeService struct {
	mgr      *nucleiruntime.Manager
	stopOnce sync.Once
	stopCh   chan struct{}
}

var (
	nucleiRuntimeOnce sync.Once
	nucleiRuntimeSvc  *NucleiRuntimeService
)

func GetNucleiRuntimeService() *NucleiRuntimeService {
	nucleiRuntimeOnce.Do(func() {
		root := os.Getenv("ZRE_NUCLEI_DIR")
		if strings.TrimSpace(root) == "" {
			root = filepath.Join("data", "nuclei")
		}
		_ = os.MkdirAll(root, 0o750)
		settings := newFileSettings(filepath.Join(root, "settings.json"))
		mgr := nucleiruntime.New(root, settings)
		mgr.SetContext(context.Background())
		nucleiRuntimeSvc = &NucleiRuntimeService{mgr: mgr, stopCh: make(chan struct{})}
		nucleiRuntimeSvc.Start()
	})
	return nucleiRuntimeSvc
}

// Start 后台同步循环：每小时 Ensure(auto=true)——缺失的二进制/模板补装，
// auto_update 开启且到期时自动同步上游（模板快照 + 二进制），失败不阻断扫描
// （Ensure 内部已把失败降级为警告，继续用现有版本）。
func (s *NucleiRuntimeService) Start() {
	go func() {
		select {
		case <-time.After(5 * time.Minute):
		case <-s.stopCh:
			return
		}
		for {
			if s.mgr == nil || !s.mgr.Enabled() {
				// nuclei 运行时被显式关闭：不跑网络同步，保留补缺语义由扫描路径兜底
				select {
				case <-s.stopCh:
					return
				case <-time.After(time.Hour):
				}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			res, err := s.mgr.Ensure(ctx, true)
			cancel()
			if err != nil {
				log.Printf("[nuclei] 后台同步失败（沿用现有运行时）: %v", err)
			} else if res != nil && (res.Installed || res.Updated) {
				log.Printf("[nuclei] 后台同步完成: installed=%v updated=%v", res.Installed, res.Updated)
			}
			select {
			case <-s.stopCh:
				return
			case <-time.After(time.Hour):
			}
		}
	}()
}

// Stop 停止后台同步循环。
func (s *NucleiRuntimeService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
}

func NewNucleiRuntimeService() *NucleiRuntimeService { return GetNucleiRuntimeService() }

// Status 当前二进制/模板状态。
func (s *NucleiRuntimeService) Status(ctx context.Context) (*nucleiruntime.Status, error) {
	if s == nil || s.mgr == nil {
		return nil, errors.New("nuclei 运行时未初始化")
	}
	return s.mgr.Status(ctx), nil
}

// Ensure 检查（auto=false）或自动补齐（auto=true）二进制与模板。
func (s *NucleiRuntimeService) Ensure(ctx context.Context, auto bool) (*nucleiruntime.EnsureResult, error) {
	if s == nil || s.mgr == nil {
		return nil, errors.New("nuclei 运行时未初始化")
	}
	return s.mgr.Ensure(ctx, auto)
}

// Update 下载/更新二进制或模板。
func (s *NucleiRuntimeService) Update(ctx context.Context, force, binaryOnly, templatesOnly bool, progress func(nucleiruntime.Progress)) (*nucleiruntime.UpdateResult, error) {
	if s == nil || s.mgr == nil {
		return nil, errors.New("nuclei 运行时未初始化")
	}
	return s.mgr.UpdateWithProgress(ctx, force, binaryOnly, templatesOnly, progress)
}

// BinaryPath 返回当前可用二进制路径（配置覆盖或项目内安装）。
func (s *NucleiRuntimeService) BinaryPath() string {
	if s == nil || s.mgr == nil {
		return ""
	}
	return s.mgr.BinaryPath()
}

// TemplatesDir 返回官方模板目录。
func (s *NucleiRuntimeService) TemplatesDir() string {
	if s == nil || s.mgr == nil {
		return ""
	}
	return s.mgr.TemplatesDir()
}

// CustomTemplatesDir 返回自定义模板目录。
func (s *NucleiRuntimeService) CustomTemplatesDir() string {
	if s == nil || s.mgr == nil {
		return ""
	}
	return s.mgr.CustomTemplatesDir()
}

// SetSettings 更新运行时可写设置（白名单）。
func (s *NucleiRuntimeService) SetSettings(in map[string]any) error {
	if s == nil || s.mgr == nil {
		return errors.New("nuclei 运行时未初始化")
	}
	for k, v := range in {
		switch k {
		case "enabled":
			s.mgr.SetEnabled(boolValue(v))
		case "auto_update":
			s.mgr.SetAutoUpdate(boolValue(v))
		case "interval_hours":
			if n, ok := intValue(v); ok {
				s.mgr.SetUpdateIntervalHours(n)
			}
		case "version":
			s.mgr.SetVersion(stringValue(v))
		case "interactsh":
			s.mgr.SetInteractsh(boolValue(v))
		case "max_scan_seconds":
			if n, ok := intValue(v); ok {
				s.mgr.SetMaxScanSeconds(n)
			}
		case "proxy":
			s.mgr.SetProxy(stringValue(v))
		default:
			return fmt.Errorf("不支持的设置项: %s", k)
		}
	}
	return nil
}

func boolValue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "1" || strings.EqualFold(t, "true") || strings.EqualFold(t, "yes")
	case float64:
		return t != 0
	}
	return false
}

func intValue(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), true
	case int:
		return t, true
	case string:
		var n int
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// fileSettings 是 nuclei 运行时的轻量持久化设置（JSON 文件）。
// 只保存白名单键，进程重启后仍生效；密钥类配置不在这里。
type fileSettings struct {
	path string
	mu   sync.Mutex
	m    map[string]string
}

func newFileSettings(path string) *fileSettings {
	fs := &fileSettings{path: path, m: map[string]string{}}
	raw, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(raw, &fs.m)
	}
	if fs.m == nil {
		fs.m = map[string]string{}
	}
	return fs
}

func (f *fileSettings) GetSetting(key string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[key]
	return v, ok, nil
}

func (f *fileSettings) SetSetting(key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[key] = value
	raw, err := json.MarshalIndent(f.m, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}
