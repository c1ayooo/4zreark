package githubleak

import (
	"strings"
	"time"
)

// credibility.go — R8 静态闸门之四/五（docs/GitHub敏感信息监控改进建议.md）：
// 来源可信度加权与时效加权。纯静态特征判定，零外呼；处置语义与前三道闸门一致：
// 只降级（likely → suspected，退出高危队列与即时推送优先级），不丢弃——
// "曾泄露"仍是报告素材，结构性判断有例外时不丢真实凭据。

// credRepoNameMarkers 低可信仓库命名特征（合集/搬运/教学仓库）。
// 注：文档 R8-4 还列了 config——与 R9.2-6 相抵（dotfiles/config 类仓库同时是
// .env 高发地），此处不纳入，其价值交由文件特征（.env 加权）表达。
var credRepoNameMarkers = []string{
	"leaked", "leaks", "keys", "passwords", "secrets",
	"collection", "collections", "awesome", "tutorial", "tutorials", "cheatsheet",
}

// credHighValueFileMarkers 高可信文件特征：真实配置/凭据文件（抵扣负分，不使总分转正）。
var credHighValueFileMarkers = []string{
	".env", "application.yml", "application.yaml", "application.properties",
	"config.py", "settings.py", "local.py", ".npmrc", ".netrc",
	"credentials", "secrets.json", "secrets.yml", "secrets.yaml", "id_rsa",
}

// fastExpireSecretTypes 失效快类别：厂商对公开仓库泄露有自动隔离/撤销机制，
// 存活率随时间快速衰减（文档附 B 实证：AWS 两例人工验证全失效）。
var fastExpireSecretTypes = map[string]struct{}{
	"aws_access_key_id": {},
}

// fastExpireStaleDays 失效快类别的时效窗口：命中文件最近提交早于该窗口视为
// 历史线索（大概率已失效），降级不丢弃。其余类别沿用全局 lookback_days。
const fastExpireStaleDays = 30

// credScore 来源可信分（≤0，负值越多越不可信）：
//
//	-2 仓库名命中合集/搬运/教学特征
//	-1 star=0；-1 仓库创建 <7 天；-1 归档仓库；-1 notebook 文件（输出 cell 转录形态）
//	+1 高可信配置/凭据文件（仅抵扣）
//
// 元数据缺失（stars/创建时间为零值）不评分，宁可不降也不误伤。
// 单次提交/组织特征等需要额外 API 的特征不纳入（避免为评分加请求）。
func credScore(item SearchItem, now time.Time) int {
	score := 0
	name := strings.ToLower(item.Repository)
	for _, marker := range credRepoNameMarkers {
		if strings.Contains(name, marker) {
			score -= 2
			break
		}
	}
	if item.RepoStars == 0 {
		score--
	}
	if !item.RepoCreatedAt.IsZero() && now.Sub(item.RepoCreatedAt) < 7*24*time.Hour {
		score--
	}
	if item.RepoArchived {
		score--
	}
	path := strings.ToLower(item.Path)
	if strings.HasSuffix(path, ".ipynb") {
		score--
	}
	for _, marker := range credHighValueFileMarkers {
		if strings.Contains(path, marker) {
			if score < 0 {
				score++
			}
			break
		}
	}
	return score
}

// downgradeLowCredibility R8-4：可信分 ≤ -2 的来源，候选 likely 降级 suspected。
// 返回降级条数（供日志；调用方不改 RunRecord 计数，避免动 schema）。
func downgradeLowCredibility(item SearchItem, candidates []Candidate) int {
	if len(candidates) == 0 {
		return 0
	}
	if score := credScore(item, time.Now().UTC()); score > -2 {
		return 0
	}
	downgraded := 0
	for i := range candidates {
		if candidates[i].Confidence == "likely" {
			candidates[i].Confidence = "suspected"
			downgraded++
		}
	}
	return downgraded
}

// downgradeStaleSecrets R8-5：失效快类别（AWS）命中文件的最近提交超出短时效窗口
// 时降级 suspected。updatedAt 零值（未走时效校验的调用路径）不处理。
func downgradeStaleSecrets(candidates []Candidate, updatedAt time.Time) int {
	if len(candidates) == 0 || updatedAt.IsZero() {
		return 0
	}
	if time.Since(updatedAt) <= fastExpireStaleDays*24*time.Hour {
		return 0
	}
	downgraded := 0
	for i := range candidates {
		if _, fast := fastExpireSecretTypes[candidates[i].SecretType]; fast && candidates[i].Confidence == "likely" {
			candidates[i].Confidence = "suspected"
			downgraded++
		}
	}
	return downgraded
}
