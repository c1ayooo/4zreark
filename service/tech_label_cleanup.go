package service

import (
	"context"
	"log"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
	"gopkg.in/yaml.v3"
)

// 技术栈画像清洗：sensitive.yaml 里的规则名不是技术栈。
//
// 这些词条（Linkfinder、系统绝对路径泄漏、内网IP、各类文档平台泄漏…）是
// 「响应内容里出现了类似泄露的文本」的特征，曾经被扫描器直接并进
// sites.tech，于是技术栈列表里混进了提取器名和告警名。扫描侧已经改为不再
// 写入（FingerprintMatch.Source=sensitive 被丢弃），这里负责把历史数据里的
// 残留剔掉——tech 是只增不减的合并列，不清就永远在。
//
// 词条清单直接取内置 sensitive.yaml 的顶层键，避免在 SQL 里抄一份会漂移的
// 名单。

// SensitiveFeatureNames 返回内置敏感特征规则的名称（sensitive.yaml 顶层键）。
func SensitiveFeatureNames() []string {
	raw, err := config.ReadDictFile("config/dicts/yaml/sensitive.yaml")
	if err != nil {
		return nil
	}
	var parsed map[string]yaml.Node
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	names := make([]string, 0, len(parsed))
	for name := range parsed {
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// CleanupNonTechLabels 把敏感特征名从 sites.tech 里剔除，返回受影响站点数。
// 启动时调用一次即可：幂等，无残留时 UPDATE 命中 0 行。
func CleanupNonTechLabels(ctx context.Context) (int64, error) {
	r := repo.Default()
	if r == nil {
		return 0, nil
	}
	names := SensitiveFeatureNames()
	if len(names) == 0 {
		return 0, nil
	}
	n, err := r.RemoveTechLabels(ctx, names)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		log.Printf("技术栈画像清洗: %d 个站点移除了 %d 类敏感特征词条", n, len(names))
	}
	return n, nil
}
