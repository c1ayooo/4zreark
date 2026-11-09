package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/cloudwego/eino/schema"
)

// 高危发现二轮深审（Tier 2）：判定（Tier 1）只读 diff，成本低但上下文窄；
// 命中 high/critical 后，从本地 bare mirror 读命中文件全文做一次 LLM 细查，
// 把「diff 上下文里像漏洞」升级/证伪成「完整文件上下文里的真实漏洞」。
//
// 成本边界：不重新 clone（mirror 采集时就地已有）、不起容器（容器复现仍是
// Tier 3，人工 verified 闸门后由 pocsmith 执行）；每个高危发现多一次 LLM 调用
// + 若干次本地 git show。产物永远落 draft，人工 verified 闸门不变。

const (
	// deepAnalysisTitle 是深审产物的标题标记，前端与 MCP 消费按它识别。
	deepAnalysisTitle = "deep-analysis"
	// deepFileLimit 单文件读取上限；deepMaxFiles 单次深审最多读的变更文件数。
	deepFileLimit = 64 << 10
	deepMaxFiles  = 4
)

// deepSem 限制全局并发深审数：判定 worker 是 8 并发，但 LLM 细查不需要那么多。
var deepSem = make(chan struct{}, 2)

// deepAnalysisEnabled 读配置开关（sentinel.deep_analysis），未配置默认开启。
func deepAnalysisEnabled() bool {
	if cfg := config.Loaded(); cfg != nil && cfg.Sentinel.DeepAnalysis != nil {
		return *cfg.Sentinel.DeepAnalysis
	}
	return true
}

// autoArtifactOn 读 sentinel.auto_artifacts 各项开关，未配置默认开启。
func autoArtifactOn(get func(*config.SentinelAutoArtifactsConfig) *bool) bool {
	if cfg := config.Loaded(); cfg != nil {
		if p := get(&cfg.Sentinel.AutoArtifacts); p != nil {
			return *p
		}
	}
	return true
}

// deepLLMConfig 是产物生成共用的活模型配置（输出预算已放大）。
type deepLLMConfig struct{ cfg config.LLMConfig }

func effectiveDeepLLMConfig(ctx context.Context) deepLLMConfig {
	var fallback config.LLMConfig
	if cfg := config.GetConfig(); cfg != nil {
		fallback = cfg.LLM
	}
	live := EffectiveLLMConfig(ctx, fallback)
	// 深审与产物生成都偏长输出，给足预算（判定默认 2048 只够短 JSON）。
	if live.MaxTokens < 8192 {
		live.MaxTokens = 8192
	}
	return deepLLMConfig{cfg: live}
}

// runHighRiskArtifacts 高危产物流水线（同步执行，river worker 调用）：
// 串行三步，每步独立容错，失败继续下一步；产物幂等（同名 draft 已存在即跳过）：
//  1. 深审 deep-analysis（mirror 文件全文细查）；
//  2. python-poc（仅 web 类）；
//  3. exploit-guide（仅 web 类）。
//
// 内存破坏类没有远程验证面：只深审，验证产物走 Tier 3a 容器差分复现。
// 返回值：三步全部失败时返回最后一个错误（river 据此重试；上游限流 429 等
// 瞬时故障靠退避错峰自愈）。任一产物成功即返回 nil——重试时幂等跳过已有产物。
func runHighRiskArtifacts(ctx context.Context, j *SentinelJudge, findingID, commitID int64, vulnClass string) error {
	deepSem <- struct{}{}
	defer func() { <-deepSem }()

	var lastErr error
	deepReport := ""
	if deepAnalysisEnabled() {
		if a, err := runDeepAnalysis(ctx, j, findingID, commitID); err != nil {
			lastErr = err
			log.Printf("[Sentinel] 深审失败 finding=%d commit=%d: %v", findingID, commitID, err)
		} else {
			deepReport = a.Content
		}
	}

	if !isWebVulnClass(vulnClass) {
		return lastErr
	}

	if autoArtifactOn(func(c *config.SentinelAutoArtifactsConfig) *bool { return c.PythonPOC }) {
		if a, err := GeneratePythonPOC(ctx, findingID, deepReport); err != nil {
			lastErr = err
			log.Printf("[Sentinel] python-poc 生成失败 finding=%d: %v", findingID, err)
		} else if a != nil {
			lastErr = nil
			log.Printf("[Sentinel] python-poc 生成完成 finding=%d artifact=%d", findingID, a.ID)
		}
	}

	if autoArtifactOn(func(c *config.SentinelAutoArtifactsConfig) *bool { return c.ExploitGuide }) {
		if a, err := GenerateExploitGuide(ctx, findingID, deepReport); err != nil {
			log.Printf("[Sentinel] exploit-guide 生成失败 finding=%d: %v", findingID, err)
		} else if a != nil {
			lastErr = nil
			log.Printf("[Sentinel] exploit-guide 生成完成 finding=%d artifact=%d", findingID, a.ID)
		}
	}
	return lastErr
}

// runDeepAnalysis 读 mirror 文件全文 → LLM 细查 → 落 deep-analysis 草稿产物。
// 已有同名产物（重复判定）时跳过。
func runDeepAnalysis(ctx context.Context, j *SentinelJudge, findingID, commitID int64) (*repo.CommitArtifact, error) {
	store := repo.Default().Sentinel()
	f, err := store.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	// 幂等：重复判定/重跑不堆叠同名产物。
	existing, err := store.ListArtifacts(ctx, findingID)
	if err != nil {
		return nil, err
	}
	for _, a := range existing {
		if a.Title == deepAnalysisTitle {
			return a, nil
		}
	}

	commit, err := store.GetCommit(ctx, commitID)
	if err != nil {
		return nil, err
	}
	reasoning := ""
	if judgment, err := store.GetJudgment(ctx, commitID); err == nil && judgment != nil {
		reasoning = judgment.Reasoning
	}

	// 从 diff 解析变更文件，读全文（跳过删除的文件），最多 deepMaxFiles 个。
	src := NewSentinelSource(j.sentCfg)
	var files []string
	for _, fc := range ParseDiff(commit.Diff) {
		if fc.IsDeleted || fc.Path == "" {
			continue
		}
		files = append(files, fc.Path)
		if len(files) >= deepMaxFiles {
			break
		}
	}
	var fileBlocks strings.Builder
	readOK := 0
	for _, p := range files {
		content, err := src.ReadCommitFile(ctx, commit.RepoID, commit.SHA, p, deepFileLimit)
		if err != nil {
			log.Printf("[Sentinel] 深审判读文件失败 commit=%d path=%s: %v", commitID, p, err)
			continue
		}
		readOK++
		fmt.Fprintf(&fileBlocks, "### 文件 %s（提交 %s 时点全文）\n```%s\n%s\n```\n\n", p, commit.SHA[:min(len(commit.SHA), 12)], extOf(p), content)
	}
	if readOK == 0 {
		return nil, errors.New("mirror 中读不到任何变更文件，跳过深审")
	}

	live := effectiveDeepLLMConfig(ctx)
	cm, err := llm.NewChatModel(ctx, live.cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoKey) {
			return nil, errors.New("未配置模型密钥，跳过深审")
		}
		return nil, fmt.Errorf("构建模型失败: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(live.cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	msg, err := cm.Generate(callCtx, []*schema.Message{
		schema.SystemMessage(deepAnalysisSystemPrompt),
		schema.UserMessage(deepAnalysisUserPrompt(f, commit, reasoning, fileBlocks.String())),
	})
	if err != nil {
		return nil, fmt.Errorf("模型调用失败: %w", llm.Classify(err))
	}
	content := strings.TrimSpace(msg.Content)
	if content == "" {
		return nil, errors.New("模型返回空内容")
	}
	return AddFindingArtifact(ctx, findingID, "report", deepAnalysisTitle, content)
}

const deepAnalysisSystemPrompt = `你是资深漏洞审计员。一级判定只看了修复 diff（上下文窄，容易误报/漏报），
现在给你变更文件的完整内容做二轮细查。要求：
1. 先下结论：确认（漏洞在完整上下文里成立）/ 降级（成立但影响小于一级判定）/ 证伪（diff 上下文外已有防护，误报）/ 需更多信息；
2. 给出修正后的攻击路径：从可控输入进入点到漏洞触发点，逐步标注 文件:行号，引用的行必须逐字来自提供的文件内容；
3. 写明前置条件（权限/认证状态/编译选项/版本范围），无则写「无需前置条件」；
4. 说明完整上下文里你已经排除的疑点（例如其他调用方已有参数校验、同文件已有过滤函数）；
5. 给出下一步验证建议（能否用 nuclei 回归、是否值得起容器差分复现）；
6. 用 Markdown 输出，结论放最前，引用代码必须真实存在于提供的文件中，禁止编造。`

func deepAnalysisUserPrompt(f *repo.CommitFinding, commit *repo.GitCommit, reasoning, fileBlocks string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "仓库: %s\n提交: %s\n提交主题: %s\n漏洞类别: %s\n严重度: %s\n发现标题: %s\n",
		commit.RepoFullName, commit.SHA, commit.Subject, f.VulnClass, f.Severity, f.Title)
	if reasoning != "" {
		fmt.Fprintf(&b, "\n一级判定理由（仅基于 diff，供复核）:\n%s\n", reasoning)
	}
	b.WriteString("\n## 变更文件全文\n\n")
	b.WriteString(fileBlocks)
	b.WriteString("\n请按系统要求做二轮深审并输出 Markdown 报告。")
	return b.String()
}

func extOf(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		return path[i+1:]
	}
	return ""
}
