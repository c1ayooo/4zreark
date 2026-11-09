package service

// 发现生命周期 + 产物链（v0.3 §11.8 MVP）。
//
// finding：open → confirmed / ignored / resolved；确认时自动把 commit.diff
// 固化成 patch 证据产物（证据定格在确认时刻，后续仓库变化不影响取证）。
// artifact：draft → pending_review → verified / rejected → deprecated；
// 铁律沿用文档：非 verified 产物不可下载、不可发布到 PoC 库。
// nuclei 模板由 LLM 依据修复 diff 草拟，落 draft 待人工审核——生成物是
// 候选而非结论，人工 verified 之前不会进入扫描分发链。

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/internal/llm"
	"github.com/c1ayooo/4zreark/repo"
)

// SentinelFindingStatuses 是 finding 状态枚举（与前端 FINDING_STATUS 对齐）。
var SentinelFindingStatuses = map[string]bool{
	"open": true, "confirmed": true, "ignored": true, "resolved": true,
}

// SentinelArtifactStatuses 是产物状态枚举（§11.8 状态机）。
var SentinelArtifactStatuses = map[string]bool{
	"draft": true, "pending_review": true, "verified": true, "rejected": true, "deprecated": true,
}

// SentinelArtifactKinds 是产物类型枚举。
var SentinelArtifactKinds = map[string]bool{
	"poc": true, "nuclei": true, "report": true, "patch": true, "repro_log": true,
}

// ErrArtifactNotVerified 是下载/发布闸门的守卫错误。
var ErrArtifactNotVerified = errors.New("产物未通过 verified 审核，不可下载/发布（非 verified 产物不可下发）")

// SetFindingStatus 流转发现状态；open→confirmed 时自动固化 patch 证据产物。
func SetFindingStatus(ctx context.Context, id int64, status string) (*repo.CommitFinding, error) {
	if !SentinelFindingStatuses[status] {
		return nil, fmt.Errorf("status 必须是 open/confirmed/ignored/resolved 之一，收到 %q", status)
	}
	store := repo.Default().Sentinel()
	f, err := store.GetFinding(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := store.SetFindingStatus(ctx, id, status); err != nil {
		return nil, err
	}
	f.Status = status
	if status == "confirmed" {
		ensurePatchArtifact(ctx, store, f)
	}
	return f, nil
}

// ensurePatchArtifact 把确认时刻的 commit.diff 快照成 patch 产物（每发现至多一份）。
// patch 是修复证据而非武器化产物，直接落 verified 方便取证下载。
func ensurePatchArtifact(ctx context.Context, store *repo.Sentinel, f *repo.CommitFinding) {
	n, err := store.CountArtifactsByKind(ctx, f.ID, "patch")
	if err != nil || n > 0 {
		return
	}
	commit, err := store.GetCommit(ctx, f.CommitID)
	if err != nil || strings.TrimSpace(commit.Diff) == "" {
		return
	}
	sha := commit.SHA
	if len(sha) > 8 {
		sha = sha[:8]
	}
	_, _ = store.InsertArtifact(ctx, &repo.CommitArtifact{
		FindingID: f.ID,
		Kind:      "patch",
		Title:     "patch: " + sha,
		Status:    "verified",
		Content:   commit.Diff,
	})
}

// AddFindingArtifact 人工新增产物（粘贴 PoC/模板/报告内容），落 draft 待审。
func AddFindingArtifact(ctx context.Context, findingID int64, kind, title, content string) (*repo.CommitArtifact, error) {
	if !SentinelArtifactKinds[kind] {
		return nil, fmt.Errorf("kind 必须是 poc/nuclei/report/patch/repro_log 之一，收到 %q", kind)
	}
	if strings.TrimSpace(content) == "" {
		return nil, errors.New("content 不能为空")
	}
	store := repo.Default().Sentinel()
	if _, err := store.GetFinding(ctx, findingID); err != nil {
		return nil, err
	}
	a := &repo.CommitArtifact{
		FindingID: findingID,
		Kind:      kind,
		Title:     strings.TrimSpace(title),
		Status:    "draft",
		Content:   content,
	}
	if _, err := store.InsertArtifact(ctx, a); err != nil {
		return nil, err
	}
	return a, nil
}

// SetArtifactStatus 流转产物状态（枚举校验 + 越权回退由调用方约束）。
func SetArtifactStatus(ctx context.Context, id int64, status string) (*repo.CommitArtifact, error) {
	if !SentinelArtifactStatuses[status] {
		return nil, fmt.Errorf("status 必须是 draft/pending_review/verified/rejected/deprecated 之一，收到 %q", status)
	}
	store := repo.Default().Sentinel()
	if err := store.SetArtifactStatus(ctx, id, status); err != nil {
		return nil, err
	}
	return store.GetArtifact(ctx, id)
}

// GetArtifactForDownload 是下载闸门：verified 才放行。
func GetArtifactForDownload(ctx context.Context, id int64) (*repo.CommitArtifact, error) {
	a, err := repo.Default().Sentinel().GetArtifact(ctx, id)
	if err != nil {
		return nil, err
	}
	if a.Status != "verified" {
		return nil, ErrArtifactNotVerified
	}
	return a, nil
}

// PublishArtifact 把 verified 的 nuclei 模板发布进既有 PoC 库（pocs 表），
// 复用 parseTemplate 解析与入库规范；站点探活旁路（verify_service）即可召回复测。
func PublishArtifact(ctx context.Context, id int64) (string, error) {
	store := repo.Default().Sentinel()
	a, err := store.GetArtifact(ctx, id)
	if err != nil {
		return "", err
	}
	if a.Kind != "nuclei" {
		return "", fmt.Errorf("仅 nuclei 模板可发布到 PoC 库，该产物是 %s", a.Kind)
	}
	if a.Status != "verified" {
		return "", ErrArtifactNotVerified
	}
	parsed, err := parseTemplate([]byte(a.Content), fmt.Sprintf("sentinel-artifact-%d", a.ID))
	if err != nil {
		return "", fmt.Errorf("模板解析失败，不能发布: %w", err)
	}
	p := parsed.poc
	p.Type = "nuclei"
	p.Source = "custom"
	if p.Origin == "" {
		p.Origin = "manual"
	}
	if err := repo.Default().Pocs().Create(ctx, p); err != nil {
		if errors.Is(err, repo.ErrDuplicate) {
			return p.TemplateID, fmt.Errorf("模板 %s 已存在于 PoC 库", p.TemplateID)
		}
		return "", err
	}
	return p.TemplateID, nil
}

const nucleiGenSystemPrompt = `你是漏洞复现工程师，任务是把「安全修复 diff」转化为一个可用于验证的 nuclei POC 模板。

只输出一个合法的 nuclei YAML 模板，不要 markdown 围栏、不要解释。
要求：
1. 顶层 id 用小写字母数字连字符；info 含 name/author/severity/classification/tags；
2. http 请求依据 diff 暴露的漏洞路径与参数构造，目标不确定时用 {{BaseURL}} 占位；
3. matcher 保守：宁可漏报不误报，优先状态码加固定响应特征；
4. 不得编造 diff 里不存在的接口、参数或版本信息；
5. 模板表达的是「该漏洞的历史形态」，用于授权环境回归验证，不追求绕过。`

// GenerateNucleiTemplate 让 LLM 依据修复 diff 草拟 nuclei 模板，落 draft 待人工审核。
// 无密钥/调用失败返回错误，由 handler 转 400；产物永远不自动 verified。
func GenerateNucleiTemplate(ctx context.Context, findingID int64) (*repo.CommitArtifact, error) {
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

	var fallback config.LLMConfig
	if cfg := config.GetConfig(); cfg != nil {
		fallback = cfg.LLM
	}
	live := EffectiveLLMConfig(ctx, fallback)
	// 判定场景的 MaxTokens（默认 2048）是为短 JSON 输出设的；reasoning 类模型
	// 的思考也计入输出预算，2048 会被思考全吃掉、正文截空（finish=length）。
	// 模板生成长输出，单独放大到安全水位。
	if live.MaxTokens < 16384 {
		live.MaxTokens = 16384
	}
	cm, err := llm.NewChatModel(ctx, live)
	if err != nil {
		if errors.Is(err, llm.ErrNoKey) {
			return nil, errors.New("未配置模型密钥：先在 设置 → 模型接入 配置，再生成模板")
		}
		return nil, fmt.Errorf("构建模型失败: %w", err)
	}

	callCtx, cancel := context.WithTimeout(ctx, time.Duration(live.TimeoutSeconds)*time.Second)
	defer cancel()
	user := fmt.Sprintf(
		"漏洞类别: %s\n严重度: %s\n发现标题: %s\n仓库: %s\n提交: %s\n判定理由: %s\n\n修复 diff:\n%s",
		f.VulnClass, f.Severity, f.Title, commit.RepoFullName, commit.Subject, reasoning, diff)
	msg, err := cm.Generate(callCtx, []*schema.Message{
		schema.SystemMessage(nucleiGenSystemPrompt),
		schema.UserMessage(user),
	})
	if err != nil {
		return nil, fmt.Errorf("模型调用失败: %w", llm.Classify(err))
	}

	content := strings.TrimSpace(msg.Content)
	log.Printf("[Sentinel] nuclei 生成回包: finding=%d content_len=%d finish 提示=%q head=%q",
		findingID, len(content), msg.Role, truncateForLog(content, 120))
	content = stripCodeFence(content)
	parsed, err := parseTemplate([]byte(content), fmt.Sprintf("sentinel-gen-finding-%d", findingID))
	if err != nil {
		return nil, fmt.Errorf("模型输出不是合法 nuclei 模板: %w", err)
	}
	title := parsed.poc.TemplateID
	if title == "" {
		title = parsed.name
	}
	a := &repo.CommitArtifact{
		FindingID: findingID,
		Kind:      "nuclei",
		Title:     title,
		Status:    "draft",
		Content:   content,
	}
	if _, err := store.InsertArtifact(ctx, a); err != nil {
		return nil, err
	}
	return a, nil
}

// stripCodeFence 去掉模型习惯性包裹的 ```yaml 围栏。
func stripCodeFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	s = strings.TrimPrefix(s, "```yaml")
	s = strings.TrimPrefix(s, "```")
	if idx := strings.LastIndex(s, "```"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

// truncateForLog 是日志截断助手，避免长回包刷屏。
func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
