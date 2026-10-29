package pipeline

import (
	"strings"
	"sync"

	"github.com/c1ayooo/4zreark/config"
)

var (
	topNCacheMu sync.Mutex
	topNCache   = map[string]string{}
)

// topNPorts 读取内置端口表（config/dicts/ports/topN.txt，go:embed 内置，
// 部署包无需携带外部数据）。返回 gogo -p 直接可用的逗号串。
// 结果进程内缓存；表缺失返回空串（调用方回退 top1000）。
func topNPorts(mode string) string {
	topNCacheMu.Lock()
	defer topNCacheMu.Unlock()
	if v, ok := topNCache[mode]; ok {
		return v
	}
	var s string
	if data, err := config.ReadDictFile("dicts/ports/" + mode + ".txt"); err == nil {
		s = strings.TrimSpace(string(data))
	}
	topNCache[mode] = s
	return s
}
