package core

import (
	"os"
	"path/filepath"

	"github.com/c1ayooo/4zreark/internal/toolruntime"
)

// getToolsDir 获取工具目录路径
func getToolsDir() string {
	// 获取可执行文件所在目录
	execPath, err := os.Executable()
	if err != nil {
		// 回退到当前工作目录
		return filepath.Join(".", "tools")
	}
	execDir := filepath.Dir(execPath)

	// 尝试多个可能的路径
	possiblePaths := []string{
		filepath.Join(execDir, "tools"),       // 与可执行文件同级的 tools
		filepath.Join(execDir, "..", "tools"), // 上一级的 tools (开发模式)
		filepath.Join(".", "tools"),           // 当前目录的 tools
		filepath.Join("..", "tools"),          // 上级目录的 tools (测试模式)
		"tools",                               // 直接 tools 目录
	}

	for _, p := range possiblePaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return filepath.Join(execDir, "tools")
}

// FileExists 检查文件是否存在
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ToolsManager 工具管理器
type ToolsManager struct {
	ToolsDir string
}

// NewToolsManager 创建工具管理器
func NewToolsManager() *ToolsManager {
	return &ToolsManager{
		ToolsDir: getToolsDir(),
	}
}

// GetToolPath 获取工具路径。委托 toolruntime 统一解析：
// 环境变量覆盖 → data/tools 托管目录（toolruntime 安装/更新落点）→
// tools/<os>/ vendored → PATH。每次调用都重新解析，工具更新即时生效。
func (t *ToolsManager) GetToolPath(toolName string) string {
	return toolruntime.Default().ResolveToolPath(toolName)
}

// IsToolAvailable 检查工具是否可用
func (t *ToolsManager) IsToolAvailable(toolName string) bool {
	return t.GetToolPath(toolName) != ""
}

// ListAvailableTools 列出平台项目内部已安装的工具（托管目录 + vendored 目录）。
// 系统 PATH 上的工具不算平台自身安装，统一走 toolruntime 的发现逻辑。
func (t *ToolsManager) ListAvailableTools() []string {
	res := toolruntime.DiscoverInstalled(toolruntime.DefaultDiscoverOptions())
	tools := make([]string, 0, len(res.Items))
	for _, it := range res.Items {
		tools = append(tools, it.Name)
	}
	return tools
}
