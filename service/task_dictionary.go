package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
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
	// 字典自学习：把达到阈值的热词随任务下发（worker 无库，只能消费任务 config）。
	// 学习是旁路：读取失败只记日志，不阻塞派单。
	if learned, err := materializeLearnedWords(ctx, task); err != nil {
		log.Printf("[TaskExecutor] 学习热词物化失败（任务继续）: %v", err)
	} else if learned {
		changed = true
	}
	return changed, nil
}

// materializeLearnedWords 把 dict_learning 里已晋升的热词写进任务 config。
// 执行端把它们追加在内置/任务级词表之后，绝不替代——内置字典的默认语义不变。
func materializeLearnedWords(ctx context.Context, task *models.Task) (bool, error) {
	if repo.Default() == nil {
		return false, nil
	}
	cfg, err := LoadDictLearningConfig(ctx)
	if err != nil {
		return false, err
	}
	if !cfg.Enabled {
		return false, nil
	}
	lr := repo.Default().DictLearning()
	changed := false
	if subs, err := lr.PromotedValues(ctx, repo.DictKindSubdomain, 300); err != nil {
		return changed, err
	} else if len(subs) > 0 {
		task.Config.LearnedSubdomainWords = subs
		changed = true
	}
	if paths, err := lr.PromotedValues(ctx, repo.DictKindPath, 800); err != nil {
		return changed, err
	} else if len(paths) > 0 {
		task.Config.LearnedPaths = paths
		changed = true
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
