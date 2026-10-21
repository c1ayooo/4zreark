package grab

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/imroc/req/v3"

	"github.com/c1ayooo/4zreark/internal/recon/vulnmonitor/util"
)

type VenustechCrawler struct {
	client *req.Client
	log    *log.Logger
}

func (v *VenustechCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "venustech",
		DisplayName: "启明星辰漏洞通告",
		Link:        "https://www.venustech.com.cn/new_type/aqtg/",
	}
}

func (v *VenustechCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

func (v *VenustechCrawler) GetUpdate(ctx context.Context, pageLimit int) ([]*VulnInfo, error) {
	var results []*VulnInfo

	for i := 1; i <= pageLimit; i++ {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		pageResult, err := v.parsePage(ctx, i)
		if err != nil {
			return results, err
		}
		v.log.Printf("got %d vulns from page %d", len(pageResult), i)
		results = append(results, pageResult...)
	}

	return results, nil
}

func (v *VenustechCrawler) parsePage(ctx context.Context, page int) ([]*VulnInfo, error) {
	rawURL := "https://www.venustech.com.cn/new_type/aqtg/"
	if page > 1 {
		rawURL = fmt.Sprintf("%sindex_%d.html", rawURL, page)
	}

	resp, err := v.client.R().SetContext(ctx).Get(rawURL)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}

	// 改版后的列表：ul.safetyList > li.safetyItem > a.safety-tit。
	// 先认新结构，落空再回退旧路径，两边都空才判整页失效。
	itemsSel := doc.Find("ul.safetyList li a.safety-tit")
	if itemsSel.Length() == 0 {
		itemsSel = doc.Find("ul.safetyList li a")
	}
	if itemsSel.Length() == 0 {
		itemsSel = doc.Find("body > div > div.wrapper.clearfloat > div.right.main-content > div > div.main-inner-bt > ul > li > a")
	}
	itemsCnt := itemsSel.Length()
	if itemsCnt == 0 {
		v.log.Printf("invalid response is \n%s", resp.Dump())
		return nil, fmt.Errorf("goquery find zero vulns")
	}

	results := make([]*VulnInfo, 0, itemsCnt)
	itemsSel.Each(func(i int, s *goquery.Selection) {
		// 微软月度、Oracle 季度补丁日漏洞通告不抓取
		if strings.Contains(s.Text(), "多个安全漏洞") {
			return
		}

		if href, ok := s.Attr("href"); ok {
			vulnURL := "https://www.venustech.com.cn" + href
			vulnInfo, err := v.parseSingle(ctx, vulnURL)
			if err != nil {
				v.log.Printf("%s %s", err, vulnURL)
				return
			}
			results = append(results, vulnInfo)
		} else {
			v.log.Printf("failed to get href")
		}
	})

	return results, nil
}

func (v *VenustechCrawler) parseSingle(ctx context.Context, vulnURL string) (*VulnInfo, error) {
	v.log.Printf("parsing vuln %s", vulnURL)
	resp, err := v.client.R().SetContext(ctx).Get(vulnURL)
	if err != nil {
		return nil, err
	}

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Bytes()))
	if err != nil {
		return nil, err
	}
	// 启明星辰在 2026-10 前后改版：详情页从「key/value 表格」换成
	// h3.news-title + span.news-time + div.news_text 的段落结构，旧表选择器
	// 全部落空。新版页面已不再发布「漏洞等级」字段，所以这里只能不设等级
	// （保持零值），由 minSeverity 过滤决定去留——不臆造档位。
	contentSel := doc.Find("div.news-content.ctn")
	if contentSel.Length() == 0 {
		contentSel = doc.Find("div.news-content")
	}

	var vulnInfo VulnInfo

	title := strings.TrimSpace(contentSel.Find("h3.news-title").First().Text())
	if title == "" {
		title = strings.TrimSpace(contentSel.Find("h3").First().Text())
	}
	vulnInfo.Title = strings.TrimPrefix(title, "【漏洞通告】")

	// 新版把发布时间放在标题旁的 span 里
	when := strings.TrimSpace(contentSel.Find("span.news-time").First().Text())
	if _, err := time.Parse("2006-01-02", when); err == nil {
		vulnInfo.Disclosure = when
	}

	// CVE 只在标题里出现，形如（CVE-2026-21589)
	if m := cveRe.FindString(vulnInfo.Title); m != "" {
		vulnInfo.CVE = m
	}

	// 正文取 news_text；新旧版都在，缺它时退回到整个内容区
	bodySel := contentSel.Find("div.news_text")
	if bodySel.Length() == 0 {
		bodySel = contentSel
	}
	vulnInfo.Description = strings.TrimSpace(bodySel.Text())

	// 使用文件名做为 UniqueKey
	filename := path.Base(resp.Request.URL.Path)
	ext := path.Ext(filename)
	vulnInfo.UniqueKey = strings.TrimSuffix(filename, ext) + "_venustech"
	vulnInfo.From = vulnURL
	vulnInfo.Creator = v
	return &vulnInfo, nil
}

// CVE 编号在标题里以（CVE-2026-21589) 形态出现，括号中英文混用，所以
// 只认编号本体、不依赖括号。
var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

func NewVenustechCrawler() Grabber {
	client := util.NewHttpClient()

	return &VenustechCrawler{
		client: client,
		log:    log.New(os.Stderr, "[venustech] ", log.LstdFlags),
	}
}
