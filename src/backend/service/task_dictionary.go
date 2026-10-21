package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/repo"
)

// materializeTaskConfigDictionaries 把任务引用的字典展开成词表写回 config。
// master 创建任务时调用一次，远端 worker 就不需要数据库连接。
func materializeTaskConfigDictionaries(ctx context.Context, task *models.Task) (bool, error) {
	changed := false
	if id := strings.TrimSpace(task.Config.DirDictID); id != "" && len(task.Config.DirWordlist) == 0 {
		values, err := loadTaskDictionary(ctx, id, "directory", 20000)
		if err != nil {
			return false, err
		}
		if len(values) > 0 {
			task.Config.DirWordlist = values
			changed = true
		}
	}
	if id := strings.TrimSpace(task.Config.SubdomainDictID); id != "" && len(task.Config.SubdomainWordlist) == 0 {
		values, err := loadTaskDictionary(ctx, id, "subdomain", 5000)
		if err != nil {
			return false, err
		}
		if len(values) > 0 {
			task.Config.SubdomainWordlist = values
			changed = true
		}
	}
	return changed, nil
}

// 任务级字典：前端在任务配置里选 dictionaries.id，执行器按 id 从 dict_entries
// 读取词表。子域任务直接用 []string；目录扫描的 spray 只接受文件路径，
// 所以这里额外提供临时文件落盘。

const taskDictMax = 50000

func loadTaskDictionary(ctx context.Context, dictID, expectedType string, max int) ([]string, error) {
	id := strings.TrimSpace(dictID)
	if id == "" {
		return nil, nil
	}
	if repo.Default() == nil {
		return nil, errors.New("数据层未初始化")
	}
	if max <= 0 || max > taskDictMax {
		max = 5000
	}
	dict, err := repo.Default().Dictionaries().GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("读取字典失败（id=%s）: %w", id, err)
	}
	if expectedType != "" && dict.Type != expectedType && dict.Type != "custom" {
		return nil, fmt.Errorf("字典 %q 类型是 %s，任务需要 %s 字典", dict.Name, dict.Type, expectedType)
	}
	values, err := repo.Default().Dictionaries().ListEntriesForExpand(ctx, id, max)
	if err != nil {
		return nil, fmt.Errorf("读取字典条目失败: %w", err)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("字典 %q 没有条目", dict.Name)
	}
	return values, nil
}

// writeTempWordlist 把词表写成 spray 能消费的换行文件，调用方负责删除。
func writeTempWordlist(values []string) (string, error) {
	f, err := os.CreateTemp("", "zre-wordlist-*.txt")
	if err != nil {
		return "", err
	}
	path := f.Name()
	w := bufio.NewWriter(f)
	written := 0
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, err := w.WriteString(v + "\n"); err != nil {
			f.Close()
			os.Remove(path)
			return "", err
		}
		written++
	}
	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	if written == 0 {
		os.Remove(path)
		return "", errors.New("词表为空")
	}
	return path, nil
}
