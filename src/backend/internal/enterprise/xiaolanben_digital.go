package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 小蓝本数字资产（APP/小程序/公众号/新媒体）采集。
//
// 数据路径与企业详情一致：浏览器签名通道打开 sou.xiaolanben.com 企业详情页，
// 从 window.__INITIAL_STATE__.companyDetail 提取所有数组型字段，由纯函数
// parseXlbDigitalAssets 按字段名归类到名单 kind。上游字段名未知项安全忽略，
// 不崩不混入；真实字段形状以首次 live 校准为准（fixture 测试锁定解析契约）。

// classifyXlbKey 把 companyDetail 的数组字段名映射到名单 kind；
// 未识别的键返回空串（跳过）。匹配顺序敏感：miniapp 先于 app。
func classifyXlbKey(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	switch {
	case containsAnySub(k, "miniapp", "mini_program", "miniprogram", "miniapplet", "applet", "weapp", "xcx"):
		return "miniapp"
	case containsAnySub(k, "official", "publicaccount", "publicnum", "gzh", "wxpublic", "wechatpublic"):
		return "official_account"
	case containsAnySub(k, "newmedia", "weibo", "douyin", "kuaishou", "xiaohongshu", "tiktok",
		"bilibili", "shortvideo", "video", "media"):
		return "newmedia"
	case containsAnySub(k, "app"):
		return "app"
	}
	return ""
}

func containsAnySub(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// xlbItemString 从对象条目按候选键取第一个非空字符串值（键大小写不敏感）。
func xlbItemString(item map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := item[k]; strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseXlbDigitalAssets 把详情页提取的字段数组解析成数字资产线索。
// detailJSON 形如 {"__entityName":"公司","apps":[...],"miniPrograms":[...]}；
// investments / webSites 等未匹配键被忽略。
func parseXlbDigitalAssets(detailJSON []byte) ([]DigitalHit, error) {
	var detail map[string]json.RawMessage
	if err := json.Unmarshal(detailJSON, &detail); err != nil {
		return nil, fmt.Errorf("小蓝本数字资产解析失败: %w", err)
	}
	entityName := ""
	if raw, ok := detail["__entityName"]; ok {
		_ = json.Unmarshal(raw, &entityName)
	}

	hits := []DigitalHit{}
	seen := map[string]bool{}
	for key, raw := range detail {
		kind := classifyXlbKey(key)
		if kind == "" {
			continue
		}
		var items []any
		if err := json.Unmarshal(raw, &items); err != nil {
			continue
		}
		for _, it := range items {
			name, platform, company := "", "", ""
			switch v := it.(type) {
			case string:
				name = strings.TrimSpace(v)
			case map[string]any:
				m := map[string]string{}
				for ik, iv := range v {
					if s, ok := iv.(string); ok {
						m[strings.ToLower(ik)] = s
					}
				}
				name = xlbItemString(m, "name", "appname", "title", "nickname", "wxname",
					"username", "accountname", "wechatname", "ghname", "alias")
				platform = xlbItemString(m, "platform", "platformname", "typename", "type",
					"source", "channel", "os")
				company = xlbItemString(m, "company", "companyname", "publisher", "developer")
			default:
				continue
			}
			if name == "" {
				continue
			}
			dedupKey := kind + "\x00" + strings.ToLower(name)
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true
			hits = append(hits, DigitalHit{
				Kind:       kind,
				Name:       name,
				Platform:   platform,
				Company:    company,
				EntityName: entityName,
				Evidence:   "小蓝本企业详情 " + key,
			})
		}
	}
	return hits, nil
}

// xlbDigitalExtractJS 页面内提取：companyDetail 的全部数组型字段 + 企业名。
const xlbDigitalExtractJS = `() => {
	const s = window.__INITIAL_STATE__ || {};
	const cd = s.companyDetail || {};
	const bi = cd.basicInfo || {};
	const out = {};
	for (const k of Object.keys(cd)) {
		if (Array.isArray(cd[k]) && cd[k].length) out[k] = cd[k];
	}
	out.__entityName = bi.companyName || bi.name || '';
	return JSON.stringify(out);
}`

// DigitalAssets 实现可选接口 DigitalAssetsProvider。
func (p *xiaolanbenProvider) DigitalAssets(ctx context.Context, extID string, pageNum, size int) ([]DigitalHit, bool, error) {
	if p.xlbChromeBin() == "" {
		return nil, false, p.queryBlocked("数字资产")
	}
	page, err := p.xlbSignPage(ctx)
	if err != nil {
		return nil, false, err
	}
	detailURL := "https://sou.xiaolanben.com/company/" + extID
	if err := page.Navigate(detailURL); err != nil {
		return nil, false, fmt.Errorf("小蓝本详情页导航失败: %w", err)
	}
	_ = page.WaitLoad()
	time.Sleep(2500 * time.Millisecond) // SSR 数据渲染
	res, err := page.Eval(xlbDigitalExtractJS)
	if err != nil {
		return nil, false, fmt.Errorf("小蓝本数字资产提取失败: %w", err)
	}
	hits, err := parseXlbDigitalAssets([]byte(res.Value.String()))
	if err != nil {
		return nil, false, err
	}
	start := (pageNum - 1) * size
	out := []DigitalHit{}
	for i, h := range hits {
		if i < start {
			continue
		}
		if len(out) >= size {
			break
		}
		out = append(out, h)
	}
	return out, start+size < len(hits), nil
}
