package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/internal/useragent"
	"github.com/c1ayooo/4zreark/repo"
)

// 图标采集与指纹。
//
// 采集顺序：先看 HTML 里的 <link rel="icon" href="...">，没有再退回 /favicon.ico。
// 哈希两套：
//   sha256  内容哈希，做唯一键与聚类（同图必同 hash）
//   mmh3    Shodan 那套 favicon hash，用来对齐外部资产库的 icon_hash 查询

const iconMaxBytes = 256 << 10

var (
	linkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	hrefRe    = regexp.MustCompile(`(?is)\bhref\s*=\s*["']([^"']+)["']`)
	relRe     = regexp.MustCompile(`(?is)\brel\s*=\s*["']?([^"'>]+)["']?`)
)

// IconResult 是一次图标采集的结果。
type IconResult struct {
	SHA256      string `json:"sha256"`
	MMH3        int64  `json:"mmh3"`
	Size        int    `json:"size"`
	ContentType string `json:"content_type"`
	SourceURL   string `json:"source_url"`
	Data        []byte `json:"-"`
}

// IconURLFromHTML 从页面里找 favicon 地址（相对路径按 base 解析）。
func IconURLFromHTML(baseURL, html string) string {
	for _, tag := range linkTagRe.FindAllString(html, -1) {
		rel := ""
		if m := relRe.FindStringSubmatch(tag); len(m) > 1 {
			rel = strings.ToLower(m[1])
		}
		if !strings.Contains(rel, "icon") {
			continue
		}
		if m := hrefRe.FindStringSubmatch(tag); len(m) > 1 {
			href := strings.TrimSpace(m[1])
			if href == "" || strings.HasPrefix(href, "data:") {
				continue
			}
			if u, err := url.Parse(baseURL); err == nil {
				if ref, err := url.Parse(href); err == nil {
					return u.ResolveReference(ref).String()
				}
			}
			return href
		}
	}
	return ""
}

// FetchIcon 抓一个站点的图标。失败返回 nil（图标不是探测的必要条件）。
func FetchIcon(ctx context.Context, baseURL, html string) *IconResult {
	candidates := []string{}
	if u := IconURLFromHTML(baseURL, html); u != "" {
		candidates = append(candidates, u)
	}
	if u, err := url.Parse(baseURL); err == nil {
		root := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/favicon.ico"}
		candidates = append(candidates, root.String())
	}

	for _, candidate := range candidates {
		data, ctype, ok := fetchBinary(ctx, candidate)
		if !ok {
			continue
		}
		sum := sha256.Sum256(data)
		return &IconResult{
			SHA256:      hex.EncodeToString(sum[:]),
			MMH3:        int64(faviconMMH3(data)),
			Size:        len(data),
			ContentType: ctype,
			SourceURL:   candidate,
			Data:        data,
		}
	}
	return nil
}

func fetchBinary(ctx context.Context, rawURL string) ([]byte, string, bool) {
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(cctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", false
	}
	req.Header.Set("User-Agent", useragent.Pick())
	req.Header.Set("Accept", "image/*,*/*;q=0.8")

	resp, err := probeClient.Do(req)
	if err != nil {
		return nil, "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", false
	}

	ctype := strings.ToLower(strings.TrimSpace(strings.Split(resp.Header.Get("Content-Type"), ";")[0]))
	if ctype != "" && !strings.HasPrefix(ctype, "image/") && ctype != "application/octet-stream" {
		return nil, "", false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, iconMaxBytes))
	if err != nil || len(data) < 16 { // 空文件/错误页不算图标
		return nil, "", false
	}
	if ctype == "" || ctype == "application/octet-stream" {
		ctype = http.DetectContentType(data)
	}
	return data, ctype, true
}

// faviconMMH3 是 Shodan 口径的 favicon 哈希：
// 先 base64（每 76 字符插一个换行），再对这段文本取 murmur3_32，取有符号结果。
func faviconMMH3(data []byte) int32 {
	enc := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return int32(murmur3_32([]byte(b.String()), 0))
}

// murmur3_32 是 MurmurHash3 x86 32 位实现。
func murmur3_32(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}

	var k1 uint32
	switch tail := data[nblocks*4:]; len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}

	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// IconService 负责图标的去重入库与读取。
type IconService struct{}

func NewIconService() *IconService { return &IconService{} }

// Save 把一次采集结果入库（按 sha256 去重），并把图标挂到站点上。
func (s *IconService) Save(ctx context.Context, siteID int64, icon *IconResult) error {
	if icon == nil || icon.SHA256 == "" {
		return nil
	}
	r := repo.Default()
	if r == nil {
		return errors.New("数据层未初始化")
	}
	clusters := r.Clusters()
	if err := clusters.UpsertIcon(ctx, repo.IconInput{
		SHA256:      icon.SHA256,
		MMH3:        icon.MMH3,
		ContentType: icon.ContentType,
		Size:        icon.Size,
		Data:        icon.Data,
	}); err != nil {
		return err
	}
	return clusters.AttachIconToSite(ctx, siteID, icon.SHA256, icon.MMH3)
}
