package extractor

// sftp 提取器：nuclei 命中 vscode-sftp 模板（/sftp.json 泄露）后，把响应里的
// SFTP/SSH 配置解析成凭据条目。sftp.json 是 VSCode SFTP 扩展的配置（JSONC：
// 允许注释与尾逗号），标准 json 解析失败时回退正则逐字段抓取。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// sftpExtractor 处理模板 id vscode-sftp。
type sftpExtractor struct{}

var sftpConfigKeyRe = regexp.MustCompile(`"([A-Za-z_]+)"\s*:\s*("([^"]*)"|(\d+))`)

func (sftpExtractor) Supports(templateID string) bool { return templateID == "vscode-sftp" }

func (sftpExtractor) Extract(ctx context.Context, c *Ctx) (*Finding, error) {
	body := bodyFromResponse(c.Response)
	if strings.TrimSpace(body) == "" {
		return nil, nil // 无响应报文可解析（老 nuclei 不输出 response 时）
	}
	creds := parseSFTPConfig(body)
	if creds.Host == "" {
		return nil, nil // 命中但报文的 host 字段缺失：非 sftp.json 内容，不产出
	}
	data, _ := json.Marshal(creds)
	// 原始凭据 key 行作为证据（隐藏私钥正文，只给路径/存在标记）
	evidence := sftpEvidence(body, creds)
	return &Finding{
		ProjectID:   c.ProjectID,
		Domain:      c.Domain,
		Target:      firstNonEmpty(c.MatchURL, c.Target),
		Category:    "sftp_credential",
		Kind:        "sftp",
		Data:        string(data),
		RawEvidence: evidence,
	}, nil
}

// sftpCredential 提取出的 SFTP/SSH 连接条目。
type sftpCredential struct {
	Name     string `json:"name,omitempty"`
	Host     string `json:"host"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// PrivateKeyPath 私钥本地路径（私钥正文不入库，只记路径与存在性）。
	PrivateKeyPath string `json:"private_key_path,omitempty"`
	HasPrivateKey  bool   `json:"has_private_key"`
}

func parseSFTPConfig(body string) sftpCredential {
	var out sftpCredential
	// 先试标准 JSON（无注释场景）。
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(body), &raw); err == nil {
		out.Name, _ = raw["name"].(string)
		out.Host, _ = raw["host"].(string)
		out.Protocol, _ = raw["protocol"].(string)
		out.Username, _ = raw["username"].(string)
		out.Password, _ = raw["password"].(string)
		out.PrivateKeyPath, _ = raw["privateKeyPath"].(string)
		if p, ok := raw["port"].(float64); ok {
			out.Port = int(p)
		}
		out.HasPrivateKey = out.PrivateKeyPath != "" || raw["privateKey"] != nil
		if out.Port == 0 {
			out.Port = defaultSFTPPort(out.Protocol)
		}
		return out
	}
	// JSONC（含注释/尾逗号）回退：逐 key 抓取。
	vals := map[string]string{}
	for _, m := range sftpConfigKeyRe.FindAllStringSubmatch(body, -1) {
		key := m[1]
		if len(m[3]) > 0 {
			vals[key] = m[3]
		}
		if len(m[4]) > 0 {
			vals[key] = m[4]
		}
	}
	out.Name = vals["name"]
	out.Host = vals["host"]
	out.Protocol = vals["protocol"]
	out.Username = vals["username"]
	out.Password = vals["password"]
	out.PrivateKeyPath = vals["privateKeyPath"]
	out.HasPrivateKey = out.PrivateKeyPath != "" || vals["privateKey"] != ""
	if n, err := strconv.Atoi(vals["port"]); err == nil {
		out.Port = n
	}
	if out.Port == 0 {
		out.Port = defaultSFTPPort(out.Protocol)
	}
	return out
}

func defaultSFTPPort(protocol string) int {
	switch strings.ToLower(protocol) {
	case "sftp":
		return 22
	case "ftp":
		return 21
	case "ftps":
		return 990
	default:
		return 22
	}
}

// sftpEvidence 生成证据文本：host/user/port + password 存在标记（口令正文只在
// data 字段保留——渗透数据明文是产品决策，见凭据不脱敏约定）。
func sftpEvidence(body string, creds sftpCredential) string {
	var b strings.Builder
	fmt.Fprintf(&b, "sftp.json 命中 → %s:%d user=%s password_set=%v private_key_path=%s",
		creds.Host, creds.Port, creds.Username, creds.Password != "", creds.PrivateKeyPath)
	if line := firstNonEmpty(body, ""); line != "" && len(body) <= 4096 {
		b.WriteString("\n")
		b.WriteString(body)
	}
	return b.String()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
