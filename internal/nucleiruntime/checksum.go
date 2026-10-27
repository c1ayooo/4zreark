package nucleiruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// nuclei 下载链完整性校验（审计 M15）：
// 下载 release 的 checksums.txt（上游 HTTPS 分发），取出当前平台 zip 的 SHA256，
// 与实际下载物比对；清单缺失或哈希不匹配一律失败关闭——下载物在通过校验前
// 不解压、不执行、不替换正式二进制。-version 只证明能跑，不证明来源，不算校验。
// 离线/私有镜像环境的兜底：ZRE_NUCLEI_ALLOW_UNCHECKED=1 显式跳过（与
// toolruntime 的 ZRE_TOOL_ALLOW_UNCHECKED 同一约定），仅 TOFU 语义。

const allowUncheckedEnv = "ZRE_NUCLEI_ALLOW_UNCHECKED"

func checksumsURL(version string) string {
	return fmt.Sprintf("https://github.com/projectdiscovery/nuclei/releases/download/v%s/checksums.txt", version)
}

// expectedChecksum 从上游 checksums.txt（格式："<sha256>  <file>" 或 BSD 风格
// "<sha256> *<file>"）里取出目标资产的哈希；找不到返回 false。
func expectedChecksum(content, asset string) (string, bool) {
	asset = strings.TrimSpace(asset)
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == asset {
			sum := strings.ToLower(fields[0])
			if len(sum) == 64 {
				return sum, true
			}
		}
	}
	return "", false
}

// sha256SumFile 计算文件哈希，流式读取不占整块内存。
func sha256SumFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyAgainstChecksums 下载上游清单并校验已下载的 zip。
// 校验不通过时错误在此返回，调用方不会走到解压/执行路径。
func (m *Manager) verifyAgainstChecksums(ctx context.Context, version, zipPath string) error {
	asset, _, err := assetName(version, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	expected, err := m.fetchExpectedChecksum(ctx, version, asset)
	if err != nil {
		if os.Getenv(allowUncheckedEnv) == "1" {
			return nil // 显式兜底：无清单也放行（TOFU），日志由调用方打
		}
		return err
	}
	got, err := sha256SumFile(zipPath)
	if err != nil {
		return fmt.Errorf("计算下载物 SHA256 失败: %w", err)
	}
	if !strings.EqualFold(got, expected) {
		return fmt.Errorf("nuclei 下载物校验失败：期望 SHA256 %s，实际 %s（清单 %s）",
			expected, got, asset)
	}
	return nil
}

// fetchExpectedChecksum 下载上游 checksums.txt 并取目标资产哈希。
func (m *Manager) fetchExpectedChecksum(ctx context.Context, version, asset string) (string, error) {
	tmp, err := os.CreateTemp(m.tmpDir(), "nuclei-checksums-*.txt")
	if err != nil {
		return "", fmt.Errorf("创建清单临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := m.download(ctx, checksumsURL(version), tmp, nil); err != nil {
		tmp.Close()
		return "", fmt.Errorf("上游 checksums.txt 不可用（如需跳过校验设 %s=1）: %w", allowUncheckedEnv, err)
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(tmpName)
	if err != nil {
		return "", err
	}
	sum, ok := expectedChecksum(string(raw), asset)
	if !ok {
		return "", fmt.Errorf("上游 checksums.txt 缺少 %s 的哈希（如需跳过校验设 %s=1）", asset, allowUncheckedEnv)
	}
	return sum, nil
}
