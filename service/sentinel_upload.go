package service

// 提交哨兵 · 上传代码包分析（import archive）。
//
// Agent 拿不到 https 白名单内的远端仓库时，把代码打成 zip/tar.gz 传进来：
//  1. 安全解包到临时目录（路径归一化防 zip-slip、符号链接跳过、解包总量上限）；
//  2. 定位 .git：包里自带 → 直接用；纯源码 → git init + 全量合成单条初始提交；
//  3. git clone --bare 进 sentinel mirror 目录（与在线采集共用同一条读取链路）；
//  4. 建仓库记录（clone_url=upload://…、enabled=false：静态快照不做周期采集）；
//  5. 同步采集落库提交并入队判定，后续判定/发现/产物/复现与在线仓库无差别。
//
// 安全约束沿用采集层：全程 exec git 直传参数；mirror 路径由 repo_id 生成。

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/c1ayooo/4zreark/oid"
	"github.com/c1ayooo/4zreark/repo"
)

const (
	// uploadArchiveLimit 是单包字节上限（MCP 请求体 4MiB 之外 REST 侧统一 32MiB，
	// 这里再卡一道服务端兜底）。
	uploadArchiveLimit = 32 << 20
	// uploadExtractLimit 是解包总量上限，防 zip 炸弹。
	uploadExtractLimit = 512 << 20
	// uploadMaxJudge 是导入后自动入队判定的提交数上限（按提交时间倒序取）。
	uploadMaxJudge = 20
)

// SentinelUploadResult 是一次压缩包导入的结果。
type SentinelUploadResult struct {
	RepoID        string `json:"repo_id"`
	FullName      string `json:"full_name"`
	Branch        string `json:"branch"`
	Synthesized   bool   `json:"synthesized_git"` // 包内无 .git，已合成初始提交
	Found         int    `json:"found_commits"`
	Inserted      int    `json:"inserted_commits"`
	EnqueuedJudge int    `json:"enqueued_judge"`
	Error         string `json:"error,omitempty"` // 采集阶段失败原因（仓库仍已注册）
}

// ImportArchive 导入一个代码压缩包：解包 → 建 mirror → 建仓 → 采集 → 判定入队。
func (s *SentinelSource) ImportArchive(ctx context.Context, name, filename string, content []byte) (*SentinelUploadResult, error) {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return nil, errors.New("filename 不能为空")
	}
	lower := strings.ToLower(filename)
	if !strings.HasSuffix(lower, ".zip") && !strings.HasSuffix(lower, ".tar.gz") && !strings.HasSuffix(lower, ".tgz") {
		return nil, errors.New("仅支持 .zip / .tar.gz / .tgz 压缩包")
	}
	if len(content) == 0 {
		return nil, errors.New("压缩包内容为空")
	}
	if len(content) > uploadArchiveLimit {
		return nil, fmt.Errorf("压缩包超过 %dMB 上限", uploadArchiveLimit>>20)
	}
	display := strings.TrimSpace(name)
	if display == "" {
		base := filepath.Base(filename)
		display = strings.TrimSuffix(base, filepath.Ext(base))
	}
	fullName := "upload/" + sanitizeUploadName(display)

	tmp, err := os.MkdirTemp("", "sentinel-upload-")
	if err != nil {
		return nil, fmt.Errorf("创建临时目录失败: %w", err)
	}
	defer os.RemoveAll(tmp)
	extractDir := filepath.Join(tmp, "code")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return nil, err
	}
	if err := extractArchive(lower, content, extractDir); err != nil {
		return nil, err
	}

	gitRoot, synthesized, err := locateGitRoot(ctx, extractDir, filename)
	if err != nil {
		return nil, err
	}

	// 建仓：静态快照不做周期采集，clone_url 仅作来源标记（upload:// 不会被采集校验放行）。
	r := &repo.GitRepo{
		ID:              oid.NewObjectID().Hex(),
		FullName:        fullName,
		CloneURL:        "upload://" + filename,
		DefaultBranch:   "main",
		IntervalMinutes: 0,
		Enabled:         false,
	}
	if err := os.MkdirAll(s.cfg.MirrorDir, 0o755); err != nil {
		return nil, fmt.Errorf("创建 mirror 目录失败: %w", err)
	}
	mirror := s.MirrorPath(r.ID)
	if _, err := os.Stat(mirror); err == nil {
		return nil, errors.New("mirror 路径冲突，请重试")
	}
	if _, err := runGit(ctx, "", "clone", "--bare", "--quiet", gitRoot, mirror); err != nil {
		_ = os.RemoveAll(mirror)
		return nil, fmt.Errorf("导入 git 仓库失败: %w", err)
	}
	branch, berr := mirrorDefaultBranch(ctx, mirror)
	if berr != nil {
		_ = os.RemoveAll(mirror)
		return nil, berr
	}
	r.Branch = branch
	if err := s.store.CreateRepo(ctx, r); err != nil {
		_ = os.RemoveAll(mirror)
		return nil, fmt.Errorf("注册仓库失败: %w", err)
	}

	res := &SentinelUploadResult{RepoID: r.ID, FullName: fullName, Branch: branch, Synthesized: synthesized}

	// 同步采集：mirror 已就绪，Collect 会跳过 https 校验直接增量读取。
	collect, cerr := s.Collect(ctx, r.ID)
	if cerr != nil {
		res.Error = cerr.Error()
		return res, nil
	}
	res.Found = collect.Found
	res.Inserted = collect.Inserted

	// 判定入队：新落库的提交默认 status=pending，调度器 5 分钟内也会捡起；
	// 这里立即入队让 Agent 无需等待调度周期。
	if q := DefaultSentinelQueue(); q != nil {
		pending, perr := s.store.ListPendingCommits(ctx, r.ID, uploadMaxJudge)
		if perr == nil {
			for _, cm := range pending {
				if q.EnqueueJudge(ctx, cm.ID) == nil {
					res.EnqueuedJudge++
				}
			}
		}
	}
	return res, nil
}

// locateGitRoot 在解包结果里定位 git 仓库根：根目录 .git → 解包目录本身；
// 唯一子目录带 .git → 该子目录；都没有 → 合成初始提交（返回 synthesized=true）。
func locateGitRoot(ctx context.Context, extractDir, filename string) (string, bool, error) {
	if _, err := os.Stat(filepath.Join(extractDir, ".git")); err == nil {
		return extractDir, false, nil
	}
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return "", false, err
	}
	var subdirs []string
	for _, e := range entries {
		if e.IsDir() {
			subdirs = append(subdirs, e.Name())
		}
	}
	if len(subdirs) == 1 {
		sub := filepath.Join(extractDir, subdirs[0])
		if _, err := os.Stat(filepath.Join(sub, ".git")); err == nil {
			return sub, false, nil
		}
	}
	if err := synthesizeGitRepo(ctx, extractDir, filename); err != nil {
		return "", false, err
	}
	return extractDir, true, nil
}

// synthesizeGitRepo 把纯源码目录包成单提交 git 仓库，让采集链路可读出 diff。
func synthesizeGitRepo(ctx context.Context, dir, filename string) error {
	if _, err := runGit(ctx, dir, "init", "--quiet"); err != nil {
		return fmt.Errorf("git init 失败: %w", err)
	}
	if _, err := runGit(ctx, dir, "add", "-A"); err != nil {
		return fmt.Errorf("git add 失败: %w", err)
	}
	msg := "import: uploaded code (" + filename + ")"
	if _, err := runGit(ctx, dir,
		"-c", "user.name=4zreark", "-c", "user.email=upload@4zreark.local",
		"commit", "--quiet", "--allow-empty", "-m", msg); err != nil {
		return fmt.Errorf("合成初始提交失败（压缩包可能是空的）: %w", err)
	}
	return nil
}

// mirrorDefaultBranch 取 bare mirror 的默认分支；HEAD 无效时退回第一个分支。
func mirrorDefaultBranch(ctx context.Context, mirror string) (string, error) {
	if out, err := runGit(ctx, mirror, "symbolic-ref", "--short", "HEAD"); err == nil {
		if b := strings.TrimSpace(out); b != "" {
			return b, nil
		}
	}
	out, err := runGit(ctx, mirror, "for-each-ref", "--format=%(refname:short)", "refs/heads")
	if err != nil {
		return "", fmt.Errorf("读取分支失败: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if b := strings.TrimSpace(line); b != "" {
			return b, nil
		}
	}
	return "", errors.New("压缩包里没有任何分支提交")
}

// sanitizeUploadName 把用户输入收敛成安全的 full_name 尾段。
func sanitizeUploadName(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		out = "code"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// extractArchive 按扩展名分发解包。
func extractArchive(lowerFilename string, content []byte, dest string) error {
	switch {
	case strings.HasSuffix(lowerFilename, ".zip"):
		return extractZip(content, dest)
	case strings.HasSuffix(lowerFilename, ".tar.gz"), strings.HasSuffix(lowerFilename, ".tgz"):
		return extractTarGz(content, dest)
	}
	return fmt.Errorf("不支持的压缩包格式: %s", lowerFilename)
}

// countingWriter 统计写入总量，触顶即中断（防 zip 炸弹撑爆磁盘）。
type countingWriter struct {
	w     io.Writer
	n     int64
	limit int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	cw.n += int64(len(p))
	if cw.limit > 0 && cw.n > cw.limit {
		return 0, errors.New("解包总量超过上限（疑似 zip 炸弹）")
	}
	return cw.w.Write(p)
}

// safeJoin 把压缩包内路径归一化到 dest 之下，拒绝任何形式逃逸。
func safeJoin(dest, name string) (string, error) {
	if name == "" || strings.Contains(name, "\x00") {
		return "", errors.New("压缩包内路径非法")
	}
	target := filepath.Join(dest, filepath.Clean("/"+name))
	if target != dest && !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
		return "", errors.New("压缩包内路径非法: " + name)
	}
	return target, nil
}

func extractZip(content []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return fmt.Errorf("打开 zip 失败: %w", err)
	}
	cw := &countingWriter{limit: uploadExtractLimit}
	for _, f := range zr.File {
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			continue // 跳过符号链接条目，防指向包外路径
		}
		target, err := safeJoin(dest, f.Name)
		if err != nil {
			return err
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("读取 %s 失败: %w", f.Name, err)
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode().Perm())
		if err != nil {
			rc.Close()
			return err
		}
		cw.w = out
		_, copyErr := io.Copy(cw, rc)
		out.Close()
		rc.Close()
		if copyErr != nil {
			return copyErr
		}
	}
	return nil
}

func extractTarGz(content []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return fmt.Errorf("打开 gzip 失败: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	cw := &countingWriter{limit: uploadExtractLimit}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("读取 tar 失败: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeDir {
			continue // 跳过符号链接/硬链接/设备等，只保留目录与普通文件
		}
		target, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, hdr.FileInfo().Mode().Perm())
		if err != nil {
			return err
		}
		cw.w = out
		_, copyErr := io.Copy(cw, tr)
		out.Close()
		if copyErr != nil {
			return copyErr
		}
	}
}
