package pipeline

// FileLeakModule 备份/敏感文件泄露检测模块。
//
// 消费指纹模块产出的 HTTP 资产（AssetHttp），对每个站点 origin 探测一组
// 固定路径（.git/.env/备份压缩包/actuator/swagger 等）。与目录扫描的区别：
// 这里是强特征判定（魔数/关键字）+ 软 404 基线，不依赖字典，路径固定，
// 请求预算每站点 ≈ 26 次且不随任务规模放大。

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/scanner/scope"
	"github.com/c1ayooo/4zreark/scanner/webscan"
)

type FileLeakModule struct {
	BaseModule
	scanner     *webscan.FileLeakScanner
	resultChan  chan interface{}
	concurrency int
	scope       *scope.Scope
}

func NewFileLeakModule(ctx context.Context, nextModule ModuleRunner, concurrency int) *FileLeakModule {
	if concurrency <= 0 {
		concurrency = 4
	}
	m := &FileLeakModule{
		BaseModule: BaseModule{
			name:       "FileLeak",
			ctx:        ctx,
			nextModule: nextModule,
			dupChecker: NewDuplicateChecker(),
		},
		scanner:     webscan.NewFileLeakScanner(),
		resultChan:  make(chan interface{}, 200),
		concurrency: concurrency,
	}
	return m
}

func (m *FileLeakModule) SetScope(s *scope.Scope) { m.scope = s }

// ModuleRun 运行模块
func (m *FileLeakModule) ModuleRun() error {
	var allWg sync.WaitGroup
	var resultWg sync.WaitGroup
	var nextModuleRun sync.WaitGroup

	sem := make(chan struct{}, m.concurrency)

	if m.nextModule != nil {
		nextModuleRun.Add(1)
		go func() {
			defer nextModuleRun.Done()
			if err := m.nextModule.ModuleRun(); err != nil {
				log.Printf("[%s] Next module error: %v", m.name, err)
			}
		}()
	}

	resultWg.Add(1)
	go func() {
		defer resultWg.Done()
		for result := range m.resultChan {
			if m.nextModule != nil {
				select {
				case <-m.ctx.Done():
					return
				case m.nextModule.GetInput() <- result:
				}
			}
		}
		if m.nextModule != nil {
			m.nextModule.CloseInput()
		}
	}()

	m.ReportModuleStart(0)
	defer m.ReportModuleComplete()
	for {
		select {
		case <-m.ctx.Done():
			allWg.Wait()
			close(m.resultChan)
			resultWg.Wait()
			nextModuleRun.Wait()
			return nil

		case data, ok := <-m.input:
			if ok {
				// 透传原始数据，保持下游链路不断。
				select {
				case <-m.ctx.Done():
				case m.resultChan <- data:
				}
			}
			if !ok {
				allWg.Wait()
				close(m.resultChan)
				resultWg.Wait()
				nextModuleRun.Wait()
				return nil
			}
			m.ReportProgress(1, 0)

			asset, isAsset := data.(AssetHttp)
			if !isAsset || asset.URL == "" {
				continue
			}
			// 真实探测必须卡在授权边界内。
			if m.scope != nil && !m.scope.AllowsURL(asset.URL) {
				continue
			}
			if m.dupChecker.IsURLDuplicate(asset.URL) {
				continue
			}
			allWg.Add(1)
			go func(origin string) {
				defer allWg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				m.scanOrigin(origin)
			}(asset.URL)
		}
	}
}

func (m *FileLeakModule) scanOrigin(origin string) {
	origin = strings.TrimRight(origin, "/")
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Minute)
	defer cancel()

	hits := m.scanner.ScanOrigin(ctx, origin)
	if len(hits) == 0 {
		return
	}
	log.Printf("[%s] %s 发现 %d 个泄露文件", m.name, origin, len(hits))
	for _, h := range hits {
		select {
		case <-m.ctx.Done():
			return
		case m.resultChan <- FileLeakResult{
			Target:     origin,
			URL:        origin + h.Path,
			Kind:       h.Kind,
			Name:       h.Name,
			Evidence:   h.Evidence,
			Severity:   h.Severity,
			StatusCode: h.StatusCode,
			Length:     h.Length,
			Source:     "fileleak",
		}:
		}
	}
}
