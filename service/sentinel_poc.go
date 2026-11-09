package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/cloudwego/eino/schema"
)

// 高危发现的可验证 PoC 产物（Tier 2 流水线的第 2/3 步）：
//   - python-poc：kind=poc、可独立运行的 Python3 验证脚本（web 类）；
//   - exploit-guide：kind=report、利用文档（前置条件/步骤/影响/检测确认）。
//
// 输入优先用 deep-analysis 深审结论（有完整文件上下文，质量更高），没有则
// 退化为仅 diff。产物永远 draft：人工 verified 才可发布/复现，铁律不自动越过。

// sentinelWebVulnClasses 是可经 HTTP 远程验证的漏洞类别。python-poc 与
// exploit-guide 只对这类生成——内存破坏类（UAF/溢出等）没有远程验证面，
// 细致验证走 Tier 3 容器差分复现。
var sentinelWebVulnClasses = map[string]bool{
	"SQLI":            true,
	"CMDI":            true,
	"RCE":             true,
	"INJECTION":       true,
	"SSRF":            true,
	"XXE":             true,
	"PATH_TRAVERSAL":  true,
	"DESERIALIZATION": true,
	"AUTH_BYPASS":     true,
	"INFO_LEAK":       true,
}

func isWebVulnClass(class string) bool {
	return sentinelWebVulnClasses[strings.ToUpper(strings.TrimSpace(class))]
}

const (
	pythonPocTitle    = "python-poc"
	exploitGuideTitle = "exploit-guide"
)

// findingGenContext 是产物生成共用的取数结果。
type findingGenContext struct {
	finding   *repo.CommitFinding
	commit    *repo.GitCommit
	reasoning string
	diff      string
}

// loadFindingGenContext 取 finding/commit/判定理由/截断 diff，产物生成共用。
func loadFindingGenContext(ctx context.Context, findingID int64) (*findingGenContext, error) {
	store := repo.Default().Sentinel()
	f, err := store.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	commit, err := store.GetCommit(ctx, f.CommitID)
	if err != nil {
		return nil, err
	}
	reasoning := ""
	if judgment, err := store.GetJudgment(ctx, f.CommitID); err == nil && judgment != nil {
		reasoning = judgment.Reasoning
	}
	diff := commit.Diff
	if len(diff) > 12000 {
		diff = diff[:12000] + "\n…（超长截断）"
	}
	return &findingGenContext{finding: f, commit: commit, reasoning: reasoning, diff: diff}, nil
}

// artifactExists 按 title 幂等检查：重复判定/重跑不堆叠同名产物。
func artifactExists(arts []*repo.CommitArtifact, title string) bool {
	for _, a := range arts {
		if a.Title == title {
			return true
		}
	}
	return false
}

// llmArtifactCall 组一次产物 LLM 调用：放大输出预算、拼 prompt、生成消息。
func llmArtifactCall(ctx context.Context, live deepLLMConfig, system, user string) (string, error) {
	cm, err := llm.NewChatModel(ctx, live.cfg)
	if err != nil {
		if errors.Is(err, llm.ErrNoKey) {
			return "", errors.New("未配置模型密钥，跳过产物生成")
		}
		return "", fmt.Errorf("构建模型失败: %w", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(live.cfg.TimeoutSeconds)*time.Second)
	defer cancel()
	msg, err := cm.Generate(callCtx, []*schema.Message{
		schema.SystemMessage(system),
		schema.UserMessage(user),
	})
	if err != nil {
		return "", fmt.Errorf("模型调用失败: %w", llm.Classify(err))
	}
	return strings.TrimSpace(msg.Content), nil
}

// GeneratePythonPOC 草拟 Python 验证脚本，落 kind=poc、title=python-poc 的
// draft 产物。deepReport 非空时作为高置信上下文并入。仅 web 类漏洞有意义，
// 由调用方（高危流水线）保证。
func GeneratePythonPOC(ctx context.Context, findingID int64, deepReport string) (*repo.CommitArtifact, error) {
	store := repo.Default().Sentinel()
	g, err := loadFindingGenContext(ctx, findingID)
	if err != nil {
		return nil, err
	}
	if arts, err := store.ListArtifacts(ctx, findingID); err == nil && artifactExists(arts, pythonPocTitle) {
		return nil, nil
	}

	live := effectiveDeepLLMConfig(ctx)
	content, err := llmArtifactCall(ctx, live, pythonPocSystemPrompt, pythonPocUserPrompt(g, deepReport))
	if err != nil {
		return nil, err
	}
	if content == "" {
		return nil, errors.New("模型返回空内容")
	}
	return AddFindingArtifact(ctx, findingID, "poc", pythonPocTitle, content)
}

// GenerateExploitGuide 草拟利用文档，落 kind=report、title=exploit-guide 的
// draft 产物。与确定性拼装的 repro-guide（复现步骤）互补：这里给的是
// 「怎么利用、影响多大、如何检测确认」的攻防两用文档。
func GenerateExploitGuide(ctx context.Context, findingID int64, deepReport string) (*repo.CommitArtifact, error) {
	store := repo.Default().Sentinel()
	g, err := loadFindingGenContext(ctx, findingID)
	if err != nil {
		return nil, err
	}
	if arts, err := store.ListArtifacts(ctx, findingID); err == nil && artifactExists(arts, exploitGuideTitle) {
		return nil, nil
	}

	live := effectiveDeepLLMConfig(ctx)
	content, err := llmArtifactCall(ctx, live, exploitGuideSystemPrompt, exploitGuideUserPrompt(g, deepReport))
	if err != nil {
		return nil, err
	}
	if content == "" {
		return nil, errors.New("模型返回空内容")
	}
	return AddFindingArtifact(ctx, findingID, "report", exploitGuideTitle, content)
}

const pythonPocSystemPrompt = `你是漏洞验证脚本工程师。写一个可独立运行的 Python3 验证脚本，用于授权环境下确认该漏洞是否真实存在。硬性要求：
1. 单文件，除 requests 外不得依赖第三方库；Python 3.8+ 兼容；
2. 目标地址从命令行参数或环境变量 TARGET 读取，默认值只用 http://example.com 占位，禁止把真实目标硬编码进脚本；
3. 脚本结尾必须输出明确判定：VULNERABLE / NOT VULNERABLE / ERROR（附原因），判定依据要可复核（状态码、响应特征、时间差等）；
4. 验证载荷与一级判定/深审结论中的攻击路径一致，引用的路径、参数必须真实出现在 diff 或文件内容里，禁止编造；
5. 禁止破坏性动作：不做 DoS/压测、不删改数据、不写后门；需要写操作的用无害化探针（如回显类 payload）；
6. 复杂验证逻辑（绕过、编码、拼接）写成独立函数并注释；异常捕获完整，超时可控（requests 显式 timeout）；
7. 文件开头 docstring 写明：漏洞概述、用法示例、前置条件、判定标准。
只输出 Python 代码，不要 Markdown 代码围栏以外的解释。`

func pythonPocUserPrompt(g *findingGenContext, deepReport string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "仓库: %s\n漏洞类别: %s\n严重度: %s\n发现标题: %s\n",
		g.commit.RepoFullName, g.finding.VulnClass, g.finding.Severity, g.finding.Title)
	if g.reasoning != "" {
		b.WriteString("\n一级判定理由:\n")
		b.WriteString(g.reasoning)
		b.WriteString("\n")
	}
	if deepReport != "" {
		b.WriteString("\n## 二轮深审结论（优先采信其中修正后的攻击路径与前置条件）\n")
		b.WriteString(deepReport)
		b.WriteString("\n")
	}
	b.WriteString("\n## 修复 diff\n\n")
	b.WriteString(g.diff)
	b.WriteString("\n\n请生成 Python 验证脚本。")
	return b.String()
}

const exploitGuideSystemPrompt = `你是攻防两用的安全文档工程师。基于修复 diff（以及二轮深审结论，如有）写一份利用文档，供授权安全评估与修复确认使用。Markdown 结构必须包含：
1. 漏洞概述：类别、严重度、一句话影响；
2. 影响范围：受影响版本/组件（从 diff 与提交主题推断，不确定就写「待确认」，禁止编造版本号）；
3. 前置条件：认证状态、网络可达性、配置要求；
4. 利用步骤：从可控输入进入点到漏洞触发点逐步展开，请求示例用 HTTP 原始报文或 curl；引用的路径/参数必须真实出现在 diff 或深审结论里；
5. 影响评估：能拿到什么（读/写/执行/越权），最坏后果；
6. 检测与修复确认：修复后如何验证漏洞已消除（回归方法）；
7. 参考：相关 CVE（仅当提交主题/理由中真实出现，禁止臆造）。
禁止输出超出「验证与评估」目的的内容：不写武器化利用链、不写持久化/横向移动、不写规避检测。`

func exploitGuideUserPrompt(g *findingGenContext, deepReport string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "仓库: %s\n提交主题: %s\n漏洞类别: %s\n严重度: %s\n发现标题: %s\n",
		g.commit.RepoFullName, g.commit.Subject, g.finding.VulnClass, g.finding.Severity, g.finding.Title)
	if g.reasoning != "" {
		b.WriteString("\n一级判定理由:\n")
		b.WriteString(g.reasoning)
		b.WriteString("\n")
	}
	if deepReport != "" {
		b.WriteString("\n## 二轮深审结论（优先采信）\n")
		b.WriteString(deepReport)
		b.WriteString("\n")
	}
	b.WriteString("\n## 修复 diff\n\n")
	b.WriteString(g.diff)
	b.WriteString("\n\n请生成利用文档。")
	return b.String()
}
