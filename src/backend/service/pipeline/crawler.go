package pipeline

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/c1ayooo/4zreark/models"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

// runURLScan 执行URL扫描 (使用 Katana 批量模式)
func (p *ScanPipeline) runURLScan() {
	log.Printf("[Pipeline] Running URL scan with Katana (list mode)")

	// 收集所有需要爬取的 URL
	urls := make([]string, 0)

	// 1. 从子域名扫描结果中收集 URL
	for _, sub := range p.discoveredSubdomains {
		if sub.URL != "" {
			urls = append(urls, sub.URL)
		} else if sub.Host != "" {
			// 根据状态码判断协议
			if sub.StatusCode > 0 {
				urls = append(urls, "https://"+sub.Host)
			}
		}
	}

	// 2. 从资产中收集 URL
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}

	// 3. 如果都没有，使用原始目标
	if len(urls) == 0 {
		for _, target := range p.task.Targets {
			if strings.HasPrefix(target, "http") {
				urls = append(urls, target)
			} else {
				urls = append(urls, "https://"+target)
			}
		}
	}

	// URL 去重
	urlSet := make(map[string]bool)
	uniqueURLs := make([]string, 0)
	for _, url := range urls {
		if !urlSet[url] {
			urlSet[url] = true
			uniqueURLs = append(uniqueURLs, url)
		}
	}

	log.Printf("[Pipeline] Collected %d unique URLs for Katana crawling", len(uniqueURLs))

	if len(uniqueURLs) == 0 {
		return
	}

	// 使用 Katana 批量爬取
	if p.katanaScanner.IsAvailable() {
		ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.katanaScanner.ExecutionTimeout)*time.Minute)
		defer cancel()

		result, err := p.katanaScanner.CrawlList(ctx, uniqueURLs)
		if err != nil {
			log.Printf("[Pipeline] Katana list crawl failed: %v", err)
			return
		}

		for _, crawledURL := range result.URLs {
			urlInfo := URLInfo{
				URL:        crawledURL.URL,
				Method:     crawledURL.Method,
				StatusCode: crawledURL.StatusCode,
				Source:     "katana",
			}
			p.discoveredURLs = append(p.discoveredURLs, urlInfo)
			p.saveURLResult(crawledURL, "list")
		}
	} else {
		log.Printf("[Pipeline] Katana not available, skipping URL scan")
	}

	log.Printf("[Pipeline] Discovered %d URLs", len(p.discoveredURLs))
}

// runWebCrawler 执行Web爬虫 (使用 Rad)
func (p *ScanPipeline) runWebCrawler() {
	log.Printf("[Pipeline] Running web crawler with Rad")

	if !p.radScanner.IsAvailable() {
		log.Printf("[Pipeline] Rad not available, skipping")
		return
	}

	// 获取要爬取的 URL
	urls := make([]string, 0)
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}

	for _, url := range urls {
		ctx, cancel := context.WithTimeout(p.ctx, time.Duration(p.radScanner.ExecutionTimeout)*time.Minute)

		result, err := p.radScanner.Crawl(ctx, url)
		cancel()

		if err != nil {
			log.Printf("[Pipeline] Rad failed for %s: %v", url, err)
			continue
		}

		for _, crawledURL := range result.URLs {
			// 避免重复
			exists := false
			for _, existing := range p.discoveredURLs {
				if existing.URL == crawledURL.URL {
					exists = true
					break
				}
			}

			if !exists {
				urlInfo := URLInfo{
					URL:    crawledURL.URL,
					Method: crawledURL.Method,
					Source: "rad",
				}
				p.discoveredURLs = append(p.discoveredURLs, urlInfo)
			}
		}
	}

	log.Printf("[Pipeline] Total URLs after Rad: %d", len(p.discoveredURLs))
}

// runDirScan 执行目录扫描 (使用 Spray)
func (p *ScanPipeline) runDirScan() {
	log.Printf("[Pipeline] Running directory scan with Spray")

	urls := make([]string, 0)
	for _, asset := range p.discoveredAssets {
		if asset.URL != "" {
			urls = append(urls, asset.URL)
		}
	}

	if len(urls) == 0 {
		log.Printf("[Pipeline] No URLs to scan for directories")
		return
	}

	sprayScanner := webscan.NewSprayScanner()
	if sprayScanner == nil || !sprayScanner.IsAvailable() {
		log.Printf("[Pipeline] Spray scanner not available, skipping directory scan")
		return
	}

	ctx, cancel := context.WithTimeout(p.ctx, 30*time.Minute)
	defer cancel()

	result, err := sprayScanner.ScanBatch(ctx, urls)
	if err != nil {
		log.Printf("[Pipeline] Spray scan error: %v", err)
		return
	}

	if result != nil {
		entries := webscan.FilterSoft404Entries(ctx, result.Results, nil)
		for _, entry := range entries {
			p.saveDirScanResultFromSpray(entry)
		}
	}
}

// saveURLResult 保存URL爬取结果
func (p *ScanPipeline) saveURLResult(url webscan.KatanaCrawledURL, source string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeCrawler,
		Source:      source,
		Data: map[string]interface{}{
			"url":         url.URL,
			"method":      url.Method,
			"status_code": url.StatusCode,
			"crawler":     source,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}

// saveDirScanResultFromSpray 保存 Spray 目录扫描结果
func (p *ScanPipeline) saveDirScanResultFromSpray(entry webscan.SprayEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := models.ScanResult{
		TaskID:      p.task.ID,
		WorkspaceID: p.task.WorkspaceID,
		Type:        models.ResultTypeDirScan,
		Source:      "spray",
		Data: map[string]interface{}{
			"url":          entry.URL,
			"path":         entry.Path,
			"status":       entry.StatusCode,
			"size":         entry.BodyLength,
			"content_type": entry.ContentType,
			"title":        entry.Title,
		},
		CreatedAt: time.Now(),
	}

	p.resultService.CreateResultWithDedup(&result)
	p.totalResults++
}
