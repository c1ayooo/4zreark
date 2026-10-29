package service

import (
	"fmt"
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/c1ayooo/4zreark/internal/icp/miit"
	"github.com/c1ayooo/4zreark/repo"
)

// 工信部 ICP 官方查询：独立 worker + 全局限速，API 只入队。
//
// 官方站风控严格，因此：
//   - 任意两次 HTTP 请求至少间隔 5s（token/验证码/查询共用，见 miit.Client）；
//   - 每个查询单页最多 40 条，翻页间隔 6s，最多 20 页；
//   - 只有一个 worker 串行执行；队列满时直接拒绝，绝不阻塞调用方。
//
// 该 worker 与任务队列、扫描流水线完全隔离，ICP 慢不会拖住其他业务。
const (
	ICPQueueSize    = 50
	ICPMinInterval  = 5 * time.Second
	ICPPagePacing   = 6 * time.Second
	ICPMaxPages     = 20
	ICPQueryTimeout = 15 * time.Minute
)

var ErrICPQueueFull = errors.New("ICP 查询队列已满，请稍后再试")

type ICPService struct {
	client *miit.Client
	queue  chan string

	maxPages   int
	pagePacing time.Duration

	mu      sync.Mutex
	cancels map[string]context.CancelFunc
	started bool
}

var (
	icpDefaultOnce sync.Once
	icpDefault     *ICPService
)

// DefaultICPService 进程级单例：API 与种子展开共用同一个客户端/限速门，
// 避免多处 new 出独立 gate 后并发打官方站。
func DefaultICPService() *ICPService {
	icpDefaultOnce.Do(func() { icpDefault = NewICPService() })
	return icpDefault
}

func NewICPService() *ICPService {
	c := miit.New("", 30*time.Second)
	c.SetMinInterval(ICPMinInterval)
	return &ICPService{
		client:     c,
		queue:      make(chan string, ICPQueueSize),
		maxPages:   ICPMaxPages,
		pagePacing: ICPPagePacing,
		cancels:    map[string]context.CancelFunc{},
	}
}

// SetMaxPages 调整单次查询最大翻页数（运维/测试用，需在入队前调用）。
func (s *ICPService) SetMaxPages(n int) {
	if n > 0 {
		s.maxPages = n
	}
}

// SetPagePacing 调整翻页间隔（运维/测试用；不要低于官方站可承受的频率）。
func (s *ICPService) SetPagePacing(d time.Duration) {
	if d >= 0 {
		s.pagePacing = d
	}
}

// SetMinInterval 调整任意两次上游请求的最小间隔（默认 5s）。
func (s *ICPService) SetMinInterval(d time.Duration) {
	s.client.SetMinInterval(d)
}

func (s *ICPService) repo() (*repo.Repo, error) {
	r := repo.Default()
	if r == nil {
		return nil, errors.New("数据层未初始化")
	}
	return r, nil
}

// Enqueue 创建查询任务并入队；队列满时立即返回错误，不阻塞。
func (s *ICPService) Enqueue(ctx context.Context, projectID int64, query string, serviceType, pageSize int) (*repo.ICPQuery, error) {
	query = strings.TrimSpace(query)
	if query == "" || len([]rune(query)) > 100 {
		return nil, errors.New("查询关键词必填且不超过 100 字")
	}
	if len(s.queue) >= cap(s.queue) {
		return nil, ErrICPQueueFull
	}
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	q, err := r.CreateICPQuery(ctx, projectID, query, serviceType, pageSize)
	if err != nil {
		return nil, err
	}
	// 动作日志：ICP 查询入队（task_id 借用 icp_queries.id，同为 char(24)）
	if aerr := r.Tasks().AddLogCategory(ctx, q.ID, "icp", "info",
		"ICP 查询入队："+query, ""); aerr != nil {
		log.Printf("[icp] 动作日志写入失败: %v", aerr)
	}
	s.ensureWorker()
	select {
	case s.queue <- q.ID:
		return q, nil
	default:
		_ = r.FinishICPQuery(context.Background(), q.ID, "error", "队列已满")
		return nil, ErrICPQueueFull
	}
}

func (s *ICPService) ensureWorker() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return
	}
	s.started = true
	go s.worker()
}

func (s *ICPService) worker() {
	for id := range s.queue {
		s.runQuery(id)
	}
}

// Cancel 取消排队中/运行中的查询；返回是否找到任务。
func (s *ICPService) Cancel(id string) bool {
	s.mu.Lock()
	cancel, ok := s.cancels[id]
	s.mu.Unlock()
	if ok {
		cancel()
		return true
	}
	// 还在队列里时取消：worker 会看到非 queued 状态并跳过。
	r, err := s.repo()
	if err != nil {
		return false
	}
	q, err := r.GetICPQuery(context.Background(), id)
	if err != nil || q.Status != "queued" {
		return false
	}
	return r.FinishICPQuery(context.Background(), id, "canceled", "用户取消") == nil
}

func (s *ICPService) runQuery(id string) {
	r, err := s.repo()
	if err != nil {
		return
	}
	q, err := r.GetICPQuery(context.Background(), id)
	if err != nil {
		return
	}
	if q.Status != "queued" {
		return // 入队后被取消
	}
	if err := r.MarkICPQueryRunning(context.Background(), id); err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), ICPQueryTimeout)
	s.mu.Lock()
	s.cancels[id] = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.cancels, id)
		s.mu.Unlock()
	}()

	status, errMsg := "done", ""
	total, pages, fetched := 0, 0, 0
	for page := 1; page <= s.maxPages; page++ {
		if page > 1 {
			if !icpSleep(ctx, s.pagePacing) {
				break
			}
		}
		data, qerr := s.client.Query(ctx, q.Query, q.ServiceType, page, q.PageSize)
		if qerr != nil {
			if errors.Is(qerr, context.Canceled) {
				status, errMsg = "canceled", "用户取消"
			} else if errors.Is(qerr, context.DeadlineExceeded) {
				status, errMsg = "error", "查询超时"
			} else {
				status, errMsg = "error", qerr.Error()
			}
			break
		}
		total, pages = data.Total, data.Pages
		items := make([]repo.ICPFilingInput, 0, len(data.Items))
		for _, it := range data.Items {
			items = append(items, repo.ICPFilingInput{
				Domain: it.Domain, MainLicence: it.MainLicence, ServiceLicence: it.ServiceLicence,
				UnitName: it.UnitName, NatureName: it.NatureName,
				ContentType: it.ContentTypeName, LeaderName: it.LeaderName,
				UpdateRecordTime: it.UpdateRecordTime,
			})
		}
		n, ierr := r.InsertICPFilings(ctx, id, q.ProjectID, items)
		if ierr != nil {
			status, errMsg = "error", "写入备案记录失败: "+ierr.Error()
			break
		}
		fetched += n
		_ = r.UpdateICPQueryProgress(context.Background(), id, total, pages, fetched)
		if pages <= 0 || page >= pages || len(data.Items) == 0 {
			break
		}
	}
	if status == "done" && pages > s.maxPages {
		errMsg = "结果超过单次上限，已截断"
	}
	if err := r.FinishICPQuery(context.Background(), id, status, errMsg); err != nil {
		log.Printf("[icp] 任务 %s 状态落库失败: %v", id, err)
	}
	// 动作日志：查询完成/失败（含抓取量）
	level, msg := "success", fmt.Sprintf("ICP 查询完成「%s」：抓取 %d 条", q.Query, fetched)
	if status == "error" {
		level, msg = "error", fmt.Sprintf("ICP 查询失败「%s」：%s", q.Query, errMsg)
	} else if status == "canceled" {
		level, msg = "info", fmt.Sprintf("ICP 查询已取消「%s」", q.Query)
	} else if errMsg != "" {
		level, msg = "warn", fmt.Sprintf("ICP 查询完成（截断）「%s」：%s", q.Query, errMsg)
	}
	if aerr := r.Tasks().AddLogCategory(context.Background(), id, "icp", level, msg, ""); aerr != nil {
		log.Printf("[icp] 动作日志写入失败: %v", aerr)
	}
}

func icpSleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *ICPService) List(ctx context.Context, projectID int64, limit int) ([]*repo.ICPQuery, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.ListICPQueries(ctx, projectID, limit)
}

func (s *ICPService) Get(ctx context.Context, id string) (*repo.ICPQuery, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.GetICPQuery(ctx, id)
}

func (s *ICPService) Filings(ctx context.Context, queryID string, limit int) ([]*repo.ICPFiling, error) {
	r, err := s.repo()
	if err != nil {
		return nil, err
	}
	return r.ListICPFilings(ctx, queryID, limit)
}

// QueryDirect 同步查询若干页，不写查询任务/快照，供种子展开等短链路使用。
// 仍然使用同一个 client 与 5 秒请求门，因此不会绕过官方站限速。
func (s *ICPService) QueryDirect(ctx context.Context, keyword string, serviceType, pageSize, maxPages int) ([]repo.ICPFilingInput, int, error) {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return nil, 0, errors.New("查询关键词必填")
	}
	if serviceType <= 0 {
		serviceType = 1
	}
	if pageSize <= 0 || pageSize > 40 {
		pageSize = 40
	}
	if maxPages <= 0 {
		maxPages = 1
	}
	if maxPages > s.maxPages {
		maxPages = s.maxPages
	}
	out := []repo.ICPFilingInput{}
	total := 0
	for page := 1; page <= maxPages; page++ {
		if page > 1 && !icpSleep(ctx, s.pagePacing) {
			break
		}
		data, err := s.client.Query(ctx, keyword, serviceType, page, pageSize)
		if err != nil {
			if len(out) > 0 {
				return out, total, nil // 已有结果时保留，后续页失败不整体报废
			}
			return nil, 0, err
		}
		total = data.Total
		for _, it := range data.Items {
			out = append(out, repo.ICPFilingInput{
				Domain: it.Domain, MainLicence: it.MainLicence, ServiceLicence: it.ServiceLicence,
				UnitName: it.UnitName, NatureName: it.NatureName,
				ContentType: it.ContentTypeName, LeaderName: it.LeaderName,
				UpdateRecordTime: it.UpdateRecordTime,
			})
		}
		if data.Pages <= 0 || page >= data.Pages || len(data.Items) == 0 {
			break
		}
	}
	return out, total, nil
}
