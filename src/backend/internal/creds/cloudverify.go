// Package cloudkeys 云主机 AccessKey 凭证池：多云厂商 AK/SK 录入、脱敏回显与有效性验证。
//
// 验证语义为「最小化确认」：只调各云厂商的 STS GetCallerIdentity 类接口（一次签名调用，
// 返回调用者身份），不做权限探查、不产生计费副作用——与 githubleak/APK 扫描里检测到的
// 泄露 AK 形成检测→验证闭环。SecretKey 明文仅服务端持有，API 只回显 Masked。
package creds

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 凭证池支持的云厂商。
const (
	ProviderAliyun  = "aliyun"
	ProviderTencent = "tencent"
	ProviderAWS     = "aws"
	ProviderHuawei  = "huawei"
	ProviderVolc    = "volc" // 火山引擎(字节跳动)
)

// 验证状态（四档语义，与 miniapp/llm 验证器统一）。
const (
	StatusUnverified   = "unverified"
	StatusValid        = "valid"
	StatusInvalid      = "invalid"      // 密钥被厂商明确拒绝（不存在/签名不符/已失效）
	StatusRestricted   = "restricted"   // 密钥真实存在但被策略拦截（SCP/CAM/RAM 拒绝）——不能与 invalid 同级
	StatusUnverifiable = "unverifiable" // 网络/服务端原因，不下结论（原 error 档）
)

// Providers 供前端下拉与后端校验共用。
var Providers = []string{ProviderAliyun, ProviderTencent, ProviderAWS, ProviderHuawei, ProviderVolc}

func ValidProvider(p string) bool {
	for _, v := range Providers {
		if v == p {
			return true
		}
	}
	return false
}

// VerifyResult 一次 STS 验证的结论。
type VerifyResult struct {
	Valid     bool   `json:"valid"`
	Status    string `json:"status"`               // valid / invalid / restricted / unverifiable
	AccountID string `json:"account_id,omitempty"` // 归属账号（云账号 ID）
	Arn       string `json:"arn,omitempty"`        // 调用者身份 ARN
	Code      string `json:"code,omitempty"`       // 厂商错误码（无效/受限/无法判定时）
	Message   string `json:"message,omitempty"`
}

// Verify 用厂商 STS GetCallerIdentity 最小化验证一对 AK/SK。client 可注入（测试）。
// BaseURLOverride 端点覆盖(测试注入;空=各厂商官方 STS/IAM 端点)。
var BaseURLOverride string

func Verify(ctx context.Context, client *http.Client, provider, accessKeyID, secretKey string) (VerifyResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	eps := map[string]string{
		ProviderAliyun:  "https://sts.aliyuncs.com",
		ProviderTencent: "https://sts.tencentcloudapi.com",
		ProviderAWS:     "https://sts.amazonaws.com",
		ProviderHuawei:  "https://iam.myhuaweicloud.com",
		ProviderVolc:    "https://iam.volcengineapi.com",
	}[provider]
	if eps == "" {
		return VerifyResult{}, fmt.Errorf("不支持的云厂商: %s(可选 aliyun/tencent/aws/huawei/volc)", provider)
	}
	if v := strings.TrimSpace(BaseURLOverride); v != "" {
		eps = v
	}
	switch provider {
	case ProviderAliyun:
		return verifyAliyunAt(ctx, client, eps, accessKeyID, secretKey)
	case ProviderTencent:
		return verifyTencentAt(ctx, client, eps, accessKeyID, secretKey)
	case ProviderAWS:
		return verifyAWSAt(ctx, client, eps, accessKeyID, secretKey)
	case ProviderHuawei:
		return verifyHuaweiAt(ctx, client, eps, accessKeyID, secretKey)
	case ProviderVolc:
		return verifyVolcAt(ctx, client, eps, accessKeyID, secretKey)
	}
	return VerifyResult{}, fmt.Errorf("不支持的云厂商: %s", provider)
}

// ────────────────────────── 阿里云（ACS3 签名）──────────────────────────

// verifyAliyunAt POST <base>/，Action/Version 走 x-acs-* 头，ACS3-HMAC-SHA256 签名。
// 无效密钥返回 400 + Code=InvalidAccessKeyId.NotFound / SignatureDoesNotMatch。
// 错误体与成功体同构（顶层平铺 Code/Message），一个结构解析两种响应。
func verifyAliyunAt(ctx context.Context, client *http.Client, base, ak, sk string) (VerifyResult, error) {
	nonce, err := randomHex(16)
	if err != nil {
		return VerifyResult{}, err
	}
	acsDate := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	headers := map[string]string{
		"host":                  strings.TrimPrefix(base, "https://"),
		"x-acs-action":          "GetCallerIdentity",
		"x-acs-version":         "2015-04-01",
		"x-acs-date":            acsDate,
		"x-acs-signature-nonce": nonce,
	}
	signature, signedHeaders := acs3Sign(sk, headers, "")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", nil)
	if err != nil {
		return VerifyResult{}, err
	}
	for k, v := range headers {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("ACS3-HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s",
		ak, signedHeaders, signature))

	var payload struct {
		AccountId string `json:"AccountId"`
		Arn       string `json:"Arn"`
		Code      string `json:"Code"`
		Message   string `json:"Message"`
	}
	ok, err := fetchJSON(ctx, client, req, &payload)
	if err != nil {
		return VerifyResult{}, err
	}
	if ok && payload.Code == "" {
		return VerifyResult{Valid: true, Status: StatusValid, AccountID: payload.AccountId, Arn: payload.Arn}, nil
	}
	res := VerifyResult{Valid: false, Code: payload.Code, Message: payload.Message}
	res.Status = classifyStatus(payload.Code,
		map[string]bool{
			"InvalidAccessKeyId.NotFound": true,
			"SignatureDoesNotMatch":       true,
			"MissingAuthenticationToken":  true,
			"InvalidAccessKeyId":          true,
		},
		map[string]bool{
			// 身份已通过认证、操作被 RAM/策略拒绝：密钥真实存在的关键结论
			"AccessDenied": true, "Forbidden": true, "Forbidden.RAM": true, "SubDenied": true, "NoPermission": true,
		})
	return res, nil
}

// acs3Sign 按阿里云 V3 签名规范计算 Authorization 的 Signature 部分。
// 返回签名与 SignedHeaders（小写、分号连接、按名排序）。
func acs3Sign(secretKey string, headers map[string]string, body string) (signature, signedHeaders string) {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	signedHeaders = strings.Join(names, ";")

	var ch strings.Builder
	for _, name := range names {
		ch.WriteString(name)
		ch.WriteString(":")
		ch.WriteString(strings.TrimSpace(headers[name]))
		ch.WriteString("\n")
	}
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"", // CanonicalQueryString：Action/Version 全走头，query 为空
		ch.String(),
		signedHeaders,
		sha256Hex(body),
	}, "\n")
	stringToSign := "ACS3-HMAC-SHA256\n" + sha256Hex(canonicalRequest)
	return hex.EncodeToString(hmacSHA256([]byte(secretKey), []byte(stringToSign))), signedHeaders
}

// ────────────────────────── 腾讯云（TC3-HMAC-SHA256）──────────────────────────

// verifyTencentAt POST <base>/，body 为空 JSON 对象，
// Action/Version/Timestamp 走 X-TC-* 头。无效密钥返回 AuthFailure.SecretIdNotFound / SignatureFailure。
func verifyTencentAt(ctx context.Context, client *http.Client, base, ak, sk string) (VerifyResult, error) {
	const service = "sts"
	const body = "{}"
	now := time.Now().UTC()
	timestamp := now.Unix()
	date := now.Format("2006-01-02")

	canonicalHeaders := "content-type:application/json; charset=utf-8\n" +
		"host:sts.tencentcloudapi.com\n" +
		"x-tc-action:getcalleridentity\n"
	canonicalRequest := strings.Join([]string{
		http.MethodPost,
		"/",
		"",
		canonicalHeaders,
		"content-type;host;x-tc-action",
		sha256Hex(body),
	}, "\n")
	scope := date + "/" + service + "/tc3_request"
	stringToSign := strings.Join([]string{
		"TC3-HMAC-SHA256",
		fmt.Sprintf("%d", timestamp),
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")
	kDate := hmacSHA256([]byte("TC3"+sk), []byte(date))
	kService := hmacSHA256(kDate, []byte(service))
	kSigning := hmacSHA256(kService, []byte("tc3_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/", strings.NewReader(body))
	if err != nil {
		return VerifyResult{}, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-TC-Action", "GetCallerIdentity")
	req.Header.Set("X-TC-Version", "2018-08-13")
	req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", timestamp))
	req.Header.Set("Authorization", fmt.Sprintf("TC3-HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host;x-tc-action, Signature=%s",
		ak, scope, signature))

	var payload struct {
		Response struct {
			AccountID string `json:"AccountId"`
			UserId    string `json:"UserId"`
			Arn       string `json:"Arn"`
			Error     *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"Response"`
	}
	ok, err := fetchJSON(ctx, client, req, &payload)
	if err != nil {
		return VerifyResult{}, err
	}
	if ok && payload.Response.Error == nil {
		return VerifyResult{Valid: true, Status: StatusValid, AccountID: payload.Response.AccountID, Arn: payload.Response.Arn}, nil
	}
	code, message := "", ""
	if payload.Response.Error != nil {
		code = payload.Response.Error.Code
		message = payload.Response.Error.Message
	}
	res := VerifyResult{Valid: false, Code: code, Message: message}
	res.Status = classifyStatus(code,
		map[string]bool{
			"AuthFailure.SignatureFailure": true,
			"AuthFailure.SecretIdNotFound": true,
			"AuthFailure.InvalidSecretId":  true,
			"AuthFailure.TokenFailure":     true,
		},
		map[string]bool{
			// CAM 已识别身份但拒绝操作：密钥真实存在
			"UnauthorizedOperation": true, "AccessDenied": true,
		})
	return res, nil
}

// ────────────────────────── AWS（SigV4）──────────────────────────

type awsCallerIdentityXML struct {
	Arn     string `xml:"GetCallerIdentityResult>Arn"`
	Account string `xml:"GetCallerIdentityResult>Account"`
	UserId  string `xml:"GetCallerIdentityResult>UserId"`
}

type awsErrorXML struct {
	Code    string `xml:"Error>Code"`
	Message string `xml:"Error>Message"`
}

// verifyAWSAt GET <base>/?Action=GetCallerIdentity&Version=2011-06-15，
// SigV4 全局端点（us-east-1/sts）。无效密钥返回 403 + InvalidClientTokenId / SignatureDoesNotMatch。
func verifyAWSAt(ctx context.Context, client *http.Client, base, ak, sk string) (VerifyResult, error) {
	const region, service = "us-east-1", "sts"
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	query := canonicalQuery(map[string]string{"Action": "GetCallerIdentity", "Version": "2011-06-15"})
	canonicalHeaders := "host:sts.amazonaws.com\nx-amz-date:" + amzDate + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		"/",
		query,
		canonicalHeaders,
		"host;x-amz-date",
		sha256Hex(""),
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")
	kDate := hmacSHA256([]byte("AWS4"+sk), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/?"+query, nil)
	if err != nil {
		return VerifyResult{}, err
	}
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host;x-amz-date, Signature=%s",
		ak, scope, signature))

	resp, err := client.Do(req)
	if err != nil {
		return VerifyResult{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return VerifyResult{}, err
	}
	var identity awsCallerIdentityXML
	var awsErr awsErrorXML
	if err := xml.Unmarshal(data, &identity); err != nil {
		log.Printf("[cloudkeys] 解析云厂商错误响应 identity 失败: %v", err)
	}
	if err := xml.Unmarshal(data, &awsErr); err != nil {
		log.Printf("[cloudkeys] 解析云厂商错误响应错误码失败: %v", err)
	}
	if resp.StatusCode == http.StatusOK && awsErr.Code == "" && identity.Arn != "" {
		return VerifyResult{Valid: true, AccountID: identity.Account, Arn: identity.Arn}, nil
	}
	code, message := awsErr.Code, awsErr.Message
	if code == "" {
		code, message = fmt.Sprintf("HTTP%d", resp.StatusCode), strings.TrimSpace(string(data))
		if len(message) > 200 {
			message = message[:200]
		}
	}
	res := VerifyResult{Valid: false, Code: code, Message: message}
	res.Status = classifyStatus(code,
		map[string]bool{
			"InvalidClientTokenId":  true,
			"InvalidAccessKeyId":    true,
			"SignatureDoesNotMatch": true,
			"ExpiredToken":          true,
			"ExpiredTokenException": true,
		},
		map[string]bool{
			// 签名已通过校验、操作被 SCP/IAM 策略拒绝：密钥真实存在
			"AccessDenied": true, "AccessDeniedException": true,
		})
	return res, nil
}

// ────────────────────────── 华为云（SDK-HMAC-SHA256）──────────────────────────

// verifyHuaweiAt GET /v3/auth/projects（项目列表,列举类只读）,AK/SK 经 SDK-HMAC-SHA256
// 签名直接认证（无密钥派生:StringToSign 不含 scope,签名直接 HMAC(SK, ...)）。
// 无效密钥 401(签名校验失败);有效但无 IAM 权限 403 → restricted(密钥真实存在)。
func verifyHuaweiAt(ctx context.Context, client *http.Client, base, ak, sk string) (VerifyResult, error) {
	const host, path = "iam.myhuaweicloud.com", "/v3/auth/projects"
	now := time.Now().UTC()
	sdkDate := now.Format("20060102T150405Z")

	canonicalHeaders := "host:" + host + "\nx-sdk-date:" + sdkDate + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		path,
		"",
		canonicalHeaders,
		"host;x-sdk-date",
		sha256Hex(""),
	}, "\n")
	stringToSign := "SDK-HMAC-SHA256\n" + sdkDate + "\n" + sha256Hex(canonicalRequest)
	signature := hex.EncodeToString(hmacSHA256([]byte(sk), []byte(stringToSign)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return VerifyResult{}, err
	}
	req.Header.Set("X-Sdk-Date", sdkDate)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("SDK-HMAC-SHA256 Access=%s, SignedHeaders=host;x-sdk-date, Signature=%s", ak, signature))

	resp, err := client.Do(req)
	if err != nil {
		return VerifyResult{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return VerifyResult{}, err
	}
	// 错误体两种形态:{"error_code","error_msg"} 或 {"error":{...}}
	var payload struct {
		Projects  []json.RawMessage `json:"projects"`
		ErrorCode string            `json:"error_code"`
		ErrorMsg  string            `json:"error_msg"`
		Error     *struct {
			Code    any    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		log.Printf("[cloudkeys] 解析错误载荷失败: %v", err)
	}
	code, message := payload.ErrorCode, payload.ErrorMsg
	if payload.Error != nil {
		code = normalizeCode(payload.Error.Code)
		message = payload.Error.Message
	}
	switch {
	case resp.StatusCode == http.StatusOK && code == "":
		return VerifyResult{Valid: true, Status: StatusValid, AccountID: fmt.Sprintf("%d 个项目", len(payload.Projects))}, nil
	case resp.StatusCode == http.StatusUnauthorized:
		// AK/SK 签名校验直接被拒 → invalid
		return VerifyResult{Valid: false, Status: StatusInvalid, Code: code, Message: message}, nil
	case resp.StatusCode == http.StatusForbidden:
		// 签名已通过、IAM 策略拒绝 → 密钥真实存在
		return VerifyResult{Valid: false, Status: StatusRestricted, Code: code, Message: message}, nil
	default:
		if code == "" {
			code, message = fmt.Sprintf("HTTP%d", resp.StatusCode), strings.TrimSpace(string(data))
			if len(message) > 200 {
				message = message[:200]
			}
		}
		return VerifyResult{Valid: false, Status: StatusUnverifiable, Code: code, Message: message}, nil
	}
}

func normalizeCode(raw any) string {
	switch v := raw.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return fmt.Sprintf("%v", int(v))
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ────────────────────────── 火山引擎（签名 V4,HMAC-SHA256/request）──────────────────────────

// verifyVolcAt GET iam ListUsers（列举类只读）。火山签名 V4 与 AWS SigV4 同构但:
// 算法名 HMAC-SHA256(非 AWS4-HMAC-SHA256)、credential 末段 request(非 aws4_request)、
// 必带 X-Content-Sha256 头。无效密钥 InvalidAccessKey/SignatureDoesNotMatch;
// 有效但无 IAM 读权限 AccessDenied → restricted(密钥真实存在)。
func verifyVolcAt(ctx context.Context, client *http.Client, base, ak, sk string) (VerifyResult, error) {
	const host, region, service = "iam.volcengineapi.com", "cn-north-1", "iam"
	now := time.Now().UTC()
	vDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	query := canonicalQuery(map[string]string{"Action": "ListUsers", "Version": "2018-01-01"})
	bodyHash := sha256Hex("")
	canonicalHeaders := "content-type:application/json\nhost:" + host + "\nx-content-sha256:" + bodyHash + "\nx-date:" + vDate + "\n"
	canonicalRequest := strings.Join([]string{
		http.MethodGet,
		"/",
		query,
		canonicalHeaders,
		"content-type;host;x-content-sha256;x-date",
		bodyHash,
	}, "\n")
	scope := date + "/" + region + "/" + service + "/request"
	stringToSign := strings.Join([]string{
		"HMAC-SHA256",
		vDate,
		scope,
		sha256Hex(canonicalRequest),
	}, "\n")
	kDate := hmacSHA256([]byte(sk), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/?"+query, nil)
	if err != nil {
		return VerifyResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Date", vDate)
	req.Header.Set("X-Content-Sha256", bodyHash)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("HMAC-SHA256 Credential=%s/%s, SignedHeaders=content-type;host;x-content-sha256;x-date, Signature=%s",
		ak, scope, signature))

	var payload struct {
		ResponseMetadata struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"ResponseMetadata"`
		Result *struct {
			Details []json.RawMessage `json:"Details"`
		} `json:"Result"`
	}
	ok, err := fetchJSON(ctx, client, req, &payload)
	if err != nil {
		return VerifyResult{}, err
	}
	code, message := "", ""
	if payload.ResponseMetadata.Error != nil {
		code = payload.ResponseMetadata.Error.Code
		message = payload.ResponseMetadata.Error.Message
	}
	if ok && payload.ResponseMetadata.Error == nil {
		return VerifyResult{Valid: true, Status: StatusValid, AccountID: fmt.Sprintf("%d 个 IAM 用户", len(payload.Result.Details))}, nil
	}
	res := VerifyResult{Valid: false, Code: code, Message: message}
	res.Status = classifyStatus(code,
		map[string]bool{
			"InvalidAccessKey":           true,
			"InvalidAccessKeyId":         true,
			"SignatureDoesNotMatch":      true,
			"MissingAuthenticationToken": true,
			"InvalidCredential":          true,
		},
		map[string]bool{
			"AccessDenied":          true,
			"AccessDeniedException": true,
			"PermissionDenied":      true,
			"Forbidden":             true,
		})
	// 401 且错误码未分类 → 也按 invalid(认证层直接拒绝)
	if res.Status == StatusUnverifiable && code == "" && ok {
		res.Status = StatusInvalid
	}
	return res, nil
}

// ────────────────────────── 公共工具 ──────────────────────────

// fetchJSON 发请求并解析 JSON 响应体。返回 HTTP 2xx；解析失败按传输错误处理。
// 各厂商的错误码/错误信息结构不同，由调用方在自己解析的结构里取出。
func fetchJSON(ctx context.Context, client *http.Client, req *http.Request, out any) (ok bool, err error) {
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return false, fmt.Errorf("解析响应失败 (HTTP %d): %w", resp.StatusCode, err)
	}
	return resp.StatusCode >= 200 && resp.StatusCode < 300, nil
}

// classifyStatus 厂商错误码 → 结论状态（四档语义）。
// rejected 集合 = 厂商明确拒绝（invalid，验证的目标结论）；restricted 集合 = 身份认证已通过、
// 操作被策略拒绝（密钥真实存在，是关键结论，不得与 invalid 同级）；其余（限流/服务端异常/
// 参数问题）= unverifiable，不轻易下「无效」结论。
func classifyStatus(code string, rejected, restricted map[string]bool) string {
	switch {
	case rejected[code]:
		return StatusInvalid
	case restricted[code]:
		return StatusRestricted
	default:
		return StatusUnverifiable
	}
}

// canonicalQuery RFC3986 编码并按 key 排序的 query 串（SigV4 规范）。
func canonicalQuery(params map[string]string) string {
	parts := make([]string, 0, len(params))
	for k, v := range params {
		parts = append(parts, awsURIEscape(k)+"="+awsURIEscape(v))
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// awsURIEscape AWS SigV4 要求的 URI 编码：空格 → %20（非 +），保留 unreserved 字符。
func awsURIEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// LooksLikePlaceholder 凭证录入的占位值防线（同 githubtokens 判据的精简版）：
// 明显的 YOUR_/example/占位词直接拒绝，防止 config/文档示例被照单入池。
func LooksLikePlaceholder(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return true
	}
	if strings.ContainsAny(t, "<> \t\n") {
		return true
	}
	compact := strings.ToLower(t)
	compact = strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(compact)
	for _, q := range []string{
		"your", "example", "sample", "placeholder", "replace", "insert", "paste",
		"changeme", "fillme", "dummy", "fake", "redacted", "notconfigured", "notset",
		"todo", "tbd", "xxxx",
	} {
		if strings.Contains(compact, q) {
			return true
		}
	}
	return false
}

// MaskKey 脱敏回显：前 4 位 + … + 后 4 位（与 githubtokens.maskToken 同形）。
func MaskKey(key string) string {
	if len(key) <= 8 {
		return "****"
	}
	return key[:4] + "…" + key[len(key)-4:]
}

// ErrNotFound 单条记录不存在。
var ErrNotFound = errors.New("cloud key 不存在")
