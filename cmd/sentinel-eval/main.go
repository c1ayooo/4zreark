// sentinel-eval 是 M1 的根假设验证入口：AI 能不能读懂 diff。
//
// 用法：
//
//	go run ./cmd/sentinel-eval -samples ./samples/sentinel -limit 100 -out report.json
//
// 样本目录约定（每个样本 = 一个 patch + 可选标签）：
//
//	0001-cve-2024-xxxx.patch      unified diff（git show --patch=1 -U3 的输出即可）
//	0001-cve-2024-xxxx.json       可选标签：{"is_security_fix":true,"vuln_class":"OOB_WRITE"}
//
// 未配置 ZRE_LLM_API_KEY 时自动使用桩模型：链路照跑，报告里明确标注「未接模型」。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
	"github.com/c1ayooo/4zreark/service"
)

// sampleLabel 是样本的人工标注。
type sampleLabel struct {
	IsSecurityFix bool   `json:"is_security_fix"`
	VulnClass     string `json:"vuln_class"`
	Note          string `json:"note"`
}

type sample struct {
	Name     string
	Patch    string
	Label    *sampleLabel
	ClassHit bool
}

// sampleResult 是单样本的评测结果。
type sampleResult struct {
	Name         string  `json:"name"`
	Predicted    bool    `json:"predicted"`
	Labeled      bool    `json:"labeled"`
	LabeledFix   bool    `json:"labeled_fix"`
	VulnClass    string  `json:"vuln_class"`
	ClassMatch   bool    `json:"class_match"`
	Confidence   float64 `json:"confidence"`
	PromptTokens int     `json:"prompt_tokens"`
	Attempts     int     `json:"attempts"`
	Partial      bool    `json:"partial"`
	Skipped      bool    `json:"skipped"`
	SkipReason   string  `json:"skip_reason,omitempty"`
}

// evalReport 是整份评测报告。
type evalReport struct {
	Model             string         `json:"model"`
	Stub              bool           `json:"stub"`
	Note              string         `json:"note,omitempty"`
	Samples           int            `json:"samples"`
	Skipped           int            `json:"skipped"`
	Judged            int            `json:"judged"`
	Labeled           int            `json:"labeled"`
	LabeledFixes      int            `json:"labeled_fixes"`
	PredictedFixes    int            `json:"predicted_fixes"`
	TruePositive      int            `json:"true_positive"`
	FalsePositive     int            `json:"false_positive"`
	FalseNegative     int            `json:"false_negative"`
	Recall            float64        `json:"recall"`
	Precision         float64        `json:"precision"`
	FalsePositiveRate float64        `json:"false_positive_rate"`
	ClassAccuracy     float64        `json:"class_accuracy"`
	AvgPromptTokens   float64        `json:"avg_prompt_tokens"`
	PartialCount      int            `json:"partial_count"`
	Results           []sampleResult `json:"results"`
}

func main() {
	var (
		dir        = flag.String("samples", "", "样本目录（*.patch + 可选同名 *.json 标签）")
		outPath    = flag.String("out", "", "报告输出路径（默认只打印摘要）")
		limit      = flag.Int("limit", 0, "最多评测多少个样本（0 表示全部）")
		configPath = flag.String("config", "config/config.yaml", "配置文件路径，缺失时用内置默认值")
	)
	flag.Parse()

	if strings.TrimSpace(*dir) == "" {
		fmt.Fprintln(os.Stderr, "必须指定 -samples 目录")
		os.Exit(2)
	}

	cfg := loadConfig(*configPath)
	evaluator, err := service.NewSentinelEvaluator(
		cfg.Sentinel, service.EffectiveLLMConfig(context.Background(), cfg.LLM))
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化判定器失败: %v\n", err)
		os.Exit(2)
	}

	samples, err := loadSamples(*dir, *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载样本失败: %v\n", err)
		os.Exit(2)
	}
	if len(samples) == 0 {
		fmt.Fprintln(os.Stderr, "样本目录里没有 *.patch / *.diff 文件")
		os.Exit(2)
	}

	report := runEval(context.Background(), evaluator, samples)
	if *outPath != "" {
		if err := writeReport(*outPath, report); err != nil {
			fmt.Fprintf(os.Stderr, "写报告失败: %v\n", err)
			os.Exit(1)
		}
	}
	printSummary(report, *outPath)
}

func loadConfig(path string) *config.Config {
	raw, err := os.ReadFile(path)
	if err != nil {
		// 评测入口不强依赖配置文件：用最小 YAML 走环境变量覆盖。
		raw = []byte("sentinel:\n  enabled: true\n")
	}
	return config.LoadConfigRaw(raw)
}

func loadSamples(dir string, limit int) ([]sample, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".patch" || ext == ".diff" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if limit > 0 && len(names) > limit {
		names = names[:limit]
	}

	samples := make([]sample, 0, len(names))
	for _, name := range names {
		patch, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		s := sample{Name: name, Patch: string(patch)}
		labelPath := filepath.Join(dir, strings.TrimSuffix(name, filepath.Ext(name))+".json")
		if raw, err := os.ReadFile(labelPath); err == nil {
			var lb sampleLabel
			if json.Unmarshal(raw, &lb) == nil {
				s.Label = &lb
			}
		}
		samples = append(samples, s)
	}
	return samples, nil
}

func runEval(ctx context.Context, evaluator *service.SentinelEvaluator, samples []sample) *evalReport {
	report := &evalReport{
		Model:   evaluator.ModelName(),
		Stub:    evaluator.IsStub(),
		Samples: len(samples),
	}
	if report.Stub {
		report.Note = "未配置 ZRE_LLM_API_KEY，使用桩模型：以下指标只证明链路可跑通，不代表模型能力"
	}

	tokenSum := 0
	for _, s := range samples {
		commit := buildCommit(s)
		outcome, err := evaluator.Evaluate(ctx, commit)
		res := sampleResult{Name: s.Name}
		if s.Label != nil {
			res.Labeled = true
			res.LabeledFix = s.Label.IsSecurityFix
			report.Labeled++
			if s.Label.IsSecurityFix {
				report.LabeledFixes++
			}
		}
		if err != nil {
			res.Partial = true
			report.PartialCount++
			report.Results = append(report.Results, res)
			continue
		}
		if outcome.Skipped {
			res.Skipped = true
			res.SkipReason = outcome.SkipReason
			report.Skipped++
			report.Results = append(report.Results, res)
			continue
		}

		report.Judged++
		res.Predicted = outcome.Verdict.IsSecurityFix
		res.VulnClass = outcome.Verdict.VulnClass
		res.Confidence = outcome.Verdict.Confidence
		if outcome.Run != nil {
			res.PromptTokens = outcome.Run.PromptTokens
			res.Attempts = outcome.Run.Attempts
			tokenSum += outcome.Run.PromptTokens
		}
		res.Partial = outcome.Partial
		if outcome.Partial {
			report.PartialCount++
		}
		if res.Predicted {
			report.PredictedFixes++
		}
		if res.Labeled {
			switch {
			case res.Predicted && res.LabeledFix:
				report.TruePositive++
			case res.Predicted && !res.LabeledFix:
				report.FalsePositive++
			case !res.Predicted && res.LabeledFix:
				report.FalseNegative++
			}
			if res.Predicted && s.Label != nil && s.Label.VulnClass != "" {
				res.ClassMatch = strings.EqualFold(s.Label.VulnClass, res.VulnClass)
			}
		}
		report.Results = append(report.Results, res)
	}

	report.Recall = ratio(report.TruePositive, report.LabeledFixes)
	report.Precision = ratio(report.TruePositive, report.PredictedFixes)
	report.FalsePositiveRate = ratio(report.FalsePositive, report.Labeled-report.LabeledFixes)
	report.ClassAccuracy = ratio(classMatches(report.Results), report.TruePositive)
	if report.Judged > 0 {
		report.AvgPromptTokens = float64(tokenSum) / float64(report.Judged)
	}
	return report
}

func buildCommit(s sample) *repo.GitCommit {
	files := service.ParseDiff(s.Patch)
	commit := &repo.GitCommit{
		SHA:          strings.TrimSuffix(s.Name, filepath.Ext(s.Name)),
		Subject:      s.Name,
		Diff:         s.Patch,
		FilesChanged: len(files),
	}
	for _, f := range files {
		commit.Additions += f.Additions
		commit.Deletions += f.Deletions
	}
	return commit
}

func classMatches(results []sampleResult) int {
	matched := 0
	for _, r := range results {
		if r.ClassMatch {
			matched++
		}
	}
	return matched
}

func ratio(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func writeReport(path string, report *evalReport) error {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func printSummary(report *evalReport, outPath string) {
	fmt.Printf("模型: %s（stub=%v）\n", report.Model, report.Stub)
	if report.Note != "" {
		fmt.Println("注意:", report.Note)
	}
	fmt.Printf("样本: %d  跳过: %d  已判定: %d  partial: %d\n",
		report.Samples, report.Skipped, report.Judged, report.PartialCount)
	fmt.Printf("标注为修复: %d  判定为修复: %d  TP=%d FP=%d FN=%d\n",
		report.LabeledFixes, report.PredictedFixes, report.TruePositive, report.FalsePositive, report.FalseNegative)
	fmt.Printf("召回=%.3f  精确=%.3f  误报率=%.3f  类型命中=%.3f  平均 prompt token=%.0f\n",
		report.Recall, report.Precision, report.FalsePositiveRate, report.ClassAccuracy, report.AvgPromptTokens)
	if outPath != "" {
		fmt.Printf("报告已写入 %s\n", outPath)
	}
}
