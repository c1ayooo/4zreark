package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/config"
	"github.com/c1ayooo/4zreark/repo"
)

// CommitSentinel 采集层：bare mirror + fetch + rev-list + show（v0.3 §7.1）。
//
// 安全约束：
//   - 全程 exec.CommandContext 直传参数，不经过 shell；
//   - clone_url 只接受 https 且 host 在白名单内，查询参数与 userinfo 一律剥离
//     （否则 https://token@host 会把凭据写进 mirror 的 config）；
//   - mirror 目录由 repo_id 生成，不拼接用户输入。

// SentinelSource 负责把远程仓库同步成本地 mirror 并解析提交。
type SentinelSource struct {
	store *repo.Sentinel
	cfg   config.SentinelConfig
}

// NewSentinelSource 构造采集服务。
func NewSentinelSource(cfg config.SentinelConfig) *SentinelSource {
	cfg.Normalize()
	return &SentinelSource{store: repo.Default().Sentinel(), cfg: cfg}
}

// SentinelConfigView 是暴露给 API 层的只读配置快照。
type SentinelConfigView struct {
	Enabled            bool     `json:"enabled"`
	CloneHosts         []string `json:"clone_hosts"`
	CollectIntervalMin int      `json:"collect_interval_minutes"`
	JudgeModel         string   `json:"judge_model"`
}

// SentinelConfig 返回当前哨兵配置（未加载配置时给安全默认值）。
func SentinelConfig() SentinelConfigView {
	loaded := config.Loaded()
	if loaded == nil {
		return SentinelConfigView{CloneHosts: []string{"github.com"}}
	}
	cfg := loaded.Sentinel
	cfg.Normalize()
	return SentinelConfigView{
		Enabled:            cfg.Enabled,
		CloneHosts:         cfg.CloneHosts,
		CollectIntervalMin: cfg.CollectIntervalMin,
		JudgeModel:         cfg.JudgeModel,
	}
}

// CollectResult 是一次采集的统计。
type CollectResult struct {
	RunID     int64  `json:"run_id"`
	RepoID    string `json:"repo_id"`
	Found     int    `json:"found"`
	Inserted  int    `json:"inserted"`
	Skipped   int    `json:"skipped"`
	ElapsedMS int64  `json:"elapsed_ms"`
}

// SentinelGitError 表示 git 命令失败（区分「配置问题」与「网络问题」）。
type SentinelGitError struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *SentinelGitError) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if len(msg) > 400 {
		msg = msg[:400] + "..."
	}
	return fmt.Sprintf("git %s 失败: %v %s", strings.Join(e.Args, " "), e.Err, msg)
}

func (e *SentinelGitError) Unwrap() error { return e.Err }

// ValidateCloneURL 校验并规范化 clone url。
func ValidateCloneURL(raw string, hosts []string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("clone_url 不能为空")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("clone_url 非法: %v", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("clone_url 只支持 https://")
	}
	if u.User != nil {
		return "", errors.New("clone_url 不能内嵌用户名/令牌")
	}
	host := strings.ToLower(u.Hostname())
	allowed := false
	for _, h := range hosts {
		if host == strings.ToLower(strings.TrimSpace(h)) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("clone_url 主机 %s 不在白名单 %v 内", host, hosts)
	}
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

// MirrorPath 返回某仓库的 mirror 路径（由 id 生成，不拼接用户输入）。
func (s *SentinelSource) MirrorPath(repoID string) string {
	return filepath.Join(s.cfg.MirrorDir, repoID+".git")
}

// Collect 同步单个仓库并落库新提交。
func (s *SentinelSource) Collect(ctx context.Context, repoID string) (*CollectResult, error) {
	started := time.Now()
	r, err := s.store.GetRepo(ctx, repoID)
	if err != nil {
		return nil, err
	}

	cloneURL, err := ValidateCloneURL(r.CloneURL, s.cfg.CloneHosts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSentinelConfig, err)
	}

	result := &CollectResult{RepoID: r.ID}
	runID, runErr := s.store.CreateRun(ctx, &repo.SentinelRun{
		RunType: "collect", RepoID: &r.ID, Status: "running",
	})
	if runErr != nil {
		log.Printf("[Sentinel] 创建采集批次失败 repo=%s: %v", r.ID, runErr)
	}
	result.RunID = runID
	now := time.Now()
	_ = s.store.UpdateRun(ctx, runID, map[string]interface{}{"started_at": now})
	s.emit(ctx, runID, "info", "collect_start", "开始采集 "+r.FullName, nil)

	branch := r.EffectiveBranch()
	mirror := s.MirrorPath(r.ID)

	found, inserted, skipped, err := s.syncMirror(ctx, r, cloneURL, mirror, branch, result)
	if err != nil {
		_ = s.store.MarkRepoChecked(ctx, r.ID, "", err.Error())
		s.emit(ctx, runID, "error", "collect_failed", err.Error(), map[string]interface{}{"repo": r.FullName})
		_ = s.store.UpdateRun(ctx, runID, map[string]interface{}{
			"status": "failed", "error": err.Error(), "finished_at": time.Now(),
			"total": found, "processed": found, "failed": 1,
		})
		return result, err
	}

	result.Found = found
	result.Inserted = inserted
	result.Skipped = skipped
	result.ElapsedMS = time.Since(started).Milliseconds()
	_ = s.store.MarkRepoChecked(ctx, r.ID, "", "")
	s.emit(ctx, runID, "info", "collect_done",
		fmt.Sprintf("采集完成：发现 %d 个提交，新增 %d 个", found, inserted), nil)
	_ = s.store.UpdateRun(ctx, runID, map[string]interface{}{
		"status": "completed", "total": found, "processed": found, "finished_at": time.Now(),
	})
	return result, nil
}

// syncMirror 准备 mirror 并逐个提交解析落库。
func (s *SentinelSource) syncMirror(ctx context.Context, r *repo.GitRepo, cloneURL, mirror, branch string, result *CollectResult) (found, inserted, skipped int, err error) {
	if err = os.MkdirAll(s.cfg.MirrorDir, 0o755); err != nil {
		return 0, 0, 0, fmt.Errorf("创建 mirror 目录失败: %w", err)
	}

	if _, statErr := os.Stat(mirror); statErr != nil {
		if _, gitErr := runGit(ctx, "", "clone", "--bare", "--quiet", cloneURL, mirror); gitErr != nil {
			return 0, 0, 0, gitErr
		}
	} else {
		if _, gitErr := runGit(ctx, mirror, "fetch", "--prune", "--quiet", "origin",
			"+refs/heads/*:refs/heads/*"); gitErr != nil {
			return 0, 0, 0, gitErr
		}
	}

	ref := "refs/heads/" + branch
	if _, gitErr := runGit(ctx, mirror, "rev-parse", "--verify", "--quiet", ref); gitErr != nil {
		return 0, 0, 0, fmt.Errorf("%w: 分支 %s 不存在", errSentinelConfig, branch)
	}

	shas, err := s.listShas(ctx, mirror, ref, r.LastCommitSHA)
	if err != nil {
		return 0, 0, 0, err
	}
	found = len(shas)

	for _, sha := range shas {
		commit, perr := s.readCommit(ctx, mirror, r.ID, sha)
		if perr != nil {
			log.Printf("[Sentinel] 解析提交失败 repo=%s sha=%s: %v", r.ID, sha, perr)
			skipped++
			continue
		}
		id, ok, ierr := s.store.InsertCommit(ctx, commit)
		if ierr != nil {
			log.Printf("[Sentinel] 写入提交失败 repo=%s sha=%s: %v", r.ID, sha, ierr)
			skipped++
			continue
		}
		if !ok {
			skipped++
			continue
		}
		inserted++
		s.emit(ctx, result.RunID, "info", "commit_new",
			fmt.Sprintf("%s %s", shortSHA(sha), commit.Subject), map[string]interface{}{"commit_id": id})
	}

	if len(shas) > 0 {
		_ = s.store.MarkRepoChecked(ctx, r.ID, shas[len(shas)-1], "")
	}
	return found, inserted, skipped, nil
}

// listShas 取待处理提交：有 last_sha 时走增量区间，否则只取最近 N 个。
func (s *SentinelSource) listShas(ctx context.Context, mirror, ref, lastSHA string) ([]string, error) {
	limit := strconv.Itoa(s.cfg.MaxCommitsPerRun)
	if lastSHA == "" {
		out, err := runGit(ctx, mirror, "rev-list", "--reverse", "--no-merges",
			"--max-count="+limit, ref)
		if err != nil {
			return nil, err
		}
		return splitLines(out), nil
	}

	// 增量：last..ref；若 last 已被强推丢弃，回退到最近 N 个，避免整仓中断。
	rng := lastSHA + ".." + ref
	out, err := runGit(ctx, mirror, "rev-list", "--reverse", "--no-merges", rng)
	if err != nil {
		out, err = runGit(ctx, mirror, "rev-list", "--reverse", "--no-merges",
			"--max-count="+limit, ref)
		if err != nil {
			return nil, err
		}
	}
	shas := splitLines(out)
	if len(shas) > s.cfg.MaxCommitsPerRun {
		shas = shas[len(shas)-s.cfg.MaxCommitsPerRun:]
	}
	return shas, nil
}

// readCommit 用一条 git show 同时取元信息与 patch。
func (s *SentinelSource) readCommit(ctx context.Context, mirror, repoID, sha string) (*repo.GitCommit, error) {
	format := "%H%x01%an%x01%ae%x01%aI%x01%s%x01%B%x02"
	out, err := runGit(ctx, mirror, "-c", "core.quotepath=false", "show",
		"--format="+format, "-p", "--no-color", "--no-ext-diff", "-U3", sha)
	if err != nil {
		return nil, err
	}

	metaPart := out
	patchPart := ""
	if idx := strings.Index(out, "\x02"); idx >= 0 {
		metaPart = out[:idx]
		patchPart = out[idx+1:]
	}
	fields := strings.Split(metaPart, "\x01")
	if len(fields) < 5 {
		return nil, errors.New("git show 输出格式异常")
	}

	committedAt, _ := time.Parse(time.RFC3339, strings.TrimSpace(fields[3]))
	files := ParseDiff(patchPart)
	c := &repo.GitCommit{
		RepoID:       repoID,
		SHA:          strings.TrimSpace(fields[0]),
		AuthorName:   strings.TrimSpace(fields[1]),
		AuthorEmail:  strings.TrimSpace(fields[2]),
		CommittedAt:  committedAt,
		Subject:      strings.TrimSpace(fields[4]),
		Message:      strings.TrimSpace(fields[5]),
		FilesChanged: len(files),
		Diff:         patchPart,
	}
	for _, f := range files {
		c.Additions += f.Additions
		c.Deletions += f.Deletions
	}
	return c, nil
}

func (s *SentinelSource) emit(ctx context.Context, runID int64, level, kind, message string, payload map[string]interface{}) {
	if runID == 0 {
		return
	}
	ev := &repo.SentinelRunEvent{RunID: runID, Level: level, Kind: kind, Message: message}
	if len(payload) > 0 {
		if raw, err := json.Marshal(payload); err == nil {
			ev.Payload = raw
		}
	}
	if _, err := s.store.AppendRunEvent(ctx, ev); err != nil {
		log.Printf("[Sentinel] 写事件失败 run=%d: %v", runID, err)
	}
	// 采集失败旁路告警（IM + 站内通知）：批次失败只有 run 表状态，不主动发就没人知道。
	if level == "error" && kind == "collect_failed" {
		repoName, _ := payload["repo"].(string)
		notifyCollectFailed(repoName, message)
	}
}

// FileChange 是一个文件的 diff 片段。
type FileChange struct {
	Path      string
	OldPath   string
	Additions int
	Deletions int
	IsNew     bool
	IsDeleted bool
	Hunks     []DiffHunk
}

// DiffHunk 是一个 @@ 块。
type DiffHunk struct {
	Header string
	Lines  []string
}

// ParseDiff 解析 unified diff，供采集落库与 prep 装箱共用。
func ParseDiff(patch string) []FileChange {
	files := make([]FileChange, 0, 8)
	var cur *FileChange
	var hunk *DiffHunk

	flushHunk := func() {
		if cur != nil && hunk != nil {
			cur.Hunks = append(cur.Hunks, *hunk)
			hunk = nil
		}
	}
	flushFile := func() {
		flushHunk()
		if cur != nil {
			files = append(files, *cur)
			cur = nil
		}
	}

	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "diff --git "):
			flushFile()
			cur = &FileChange{Path: parseDiffGitPath(line)}
		case cur == nil:
			continue
		case strings.HasPrefix(line, "@@"):
			flushHunk()
			hunk = &DiffHunk{Header: line}
		case strings.HasPrefix(line, "new file mode"):
			cur.IsNew = true
		case strings.HasPrefix(line, "deleted file mode"):
			cur.IsDeleted = true
		case strings.HasPrefix(line, "+++ "):
			if p := strings.TrimPrefix(line, "+++ b/"); p != line {
				cur.Path = p
			}
		case strings.HasPrefix(line, "--- "):
			if p := strings.TrimPrefix(line, "--- a/"); p != line {
				cur.OldPath = p
			}
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			cur.Additions++
			if hunk != nil {
				hunk.Lines = append(hunk.Lines, line)
			}
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			cur.Deletions++
			if hunk != nil {
				hunk.Lines = append(hunk.Lines, line)
			}
		default:
			if hunk != nil {
				hunk.Lines = append(hunk.Lines, line)
			}
		}
	}
	flushFile()
	return files
}

func parseDiffGitPath(line string) string {
	// diff --git a/foo/bar.go b/foo/bar.go
	parts := strings.SplitN(strings.TrimPrefix(line, "diff --git "), " b/", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return strings.TrimSpace(line)
}

func splitLines(out string) []string {
	lines := strings.Split(out, "\n")
	result := make([]string, 0, len(lines))
	for _, l := range lines {
		if l = strings.TrimSpace(l); l != "" {
			result = append(result, l)
		}
	}
	return result
}

func shortSHA(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

// runGit 执行 git 命令（独立参数，不经 shell）。
func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_LFS_SKIP_SMUDGE=1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", &SentinelGitError{Args: args, Stderr: stderr.String(), Err: err}
	}
	return string(out), nil
}

// errSentinelConfig 用于区分「配置/输入不合法」与「执行失败」。
var errSentinelConfig = errors.New("提交哨兵配置错误")
