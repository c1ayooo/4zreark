// Package vulnmonitor polls public vulnerability intelligence sources and
// normalizes their output for storage.
//
// The nine bundled sources are the same adapters used by 4zrec's vulnintel
// pipeline: Aliyun AVD, Chaitin, QiAnXin TI, OSCS, ThreatBook, Seebug, CISA KEV,
// Apache Struts2 and VenusTech. The package has no database or LLM dependency:
// callers supply a Store implementation (or use MemoryStore / read PollResult).
package vulnmonitor

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/c1ayooo/reconkit/vulnmonitor/grab"
)

// Intel is one normalized vulnerability record. It mirrors the fields 4zrec
// writes into vuln_intel, without any database types.
type Intel struct {
	UniqueKey   string   `json:"unique_key"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	CVE         string   `json:"cve,omitempty"`
	Disclosure  string   `json:"disclosure,omitempty"`
	Solutions   string   `json:"solutions,omitempty"`
	Source      string   `json:"source"`      // provider display name, e.g. 微步在线研究响应中心-漏洞通告
	SourceName  string   `json:"source_name"` // provider key, e.g. threatbook
	SourceURL   string   `json:"source_url,omitempty"`
	From        string   `json:"from,omitempty"` // provider-specific detail URL
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Store persists normalized intel. Implementations should be idempotent on
// UniqueKey and report whether the row was newly created.
type Store interface {
	UpsertIntel(ctx context.Context, intel Intel) (created bool, err error)
}

// SourceError records a failed source without aborting the poll.
type SourceError struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

// PollResult summarizes one poll.
type PollResult struct {
	New     int           `json:"new"`
	Updated int           `json:"updated"`
	Sources int           `json:"sources"`
	Failed  int           `json:"failed"`
	NewHigh []string      `json:"new_high,omitempty"` // newly created high/critical titles
	Errors  []SourceError `json:"errors,omitempty"`
	Items   []Intel       `json:"items,omitempty"` // every accepted item, regardless of Store
}

// Status is a snapshot for dashboards.
type Status struct {
	Polling    bool
	LastPoll   time.Time
	LastResult PollResult
	Sources    int
}

// Monitor owns the source adapters and the polling loop.
type Monitor struct {
	grabbers      []grab.Grabber
	sourcesSet    bool
	store         Store
	interval      time.Duration
	pageLimit     int
	sourceTimeout time.Duration
	minRank       int
	useValuable   bool
	notify        func(newHigh []string)
	logger        *log.Logger

	refreshCh chan struct{}
	mu        sync.Mutex
	polling   bool
	lastPoll  time.Time
	lastRes   PollResult
}

// Option configures a Monitor.
type Option func(*Monitor)

// WithSources replaces the default nine sources.
func WithSources(sources ...grab.Grabber) Option {
	return func(m *Monitor) {
		m.grabbers = append([]grab.Grabber{}, sources...)
		m.sourcesSet = true
	}
}

// WithInterval sets the polling interval (default 30m).
func WithInterval(d time.Duration) Option {
	return func(m *Monitor) {
		if d > 0 {
			m.interval = d
		}
	}
}

// WithPageLimit sets the per-source page limit (default 3).
func WithPageLimit(n int) Option {
	return func(m *Monitor) {
		if n > 0 {
			m.pageLimit = n
		}
	}
}

// WithSourceTimeout sets the per-source timeout (default 2m).
func WithSourceTimeout(d time.Duration) Option {
	return func(m *Monitor) {
		if d > 0 {
			m.sourceTimeout = d
		}
	}
}

// WithMinSeverity drops records below level. Default is Medium (medium/high/critical).
func WithMinSeverity(level grab.SeverityLevel) Option {
	return func(m *Monitor) {
		if rank, ok := severityRank[string(level)]; ok {
			m.minRank = rank
		}
	}
}

// WithValuableFilter additionally applies each source's IsValuable rule.
// It is off by default, matching 4zrec's polling behavior (severity only).
func WithValuableFilter(enabled bool) Option {
	return func(m *Monitor) { m.useValuable = enabled }
}

// WithNotifyHook receives newly created high/critical titles after each poll.
func WithNotifyHook(fn func(newHigh []string)) Option {
	return func(m *Monitor) { m.notify = fn }
}

// WithLogger overrides the default stderr logger.
func WithLogger(l *log.Logger) Option {
	return func(m *Monitor) {
		if l != nil {
			m.logger = l
		}
	}
}

// New creates a monitor. A nil Store is allowed: accepted items are still
// returned in PollResult.Items and counted as New.
func New(store Store, opts ...Option) *Monitor {
	m := &Monitor{
		store:         store,
		interval:      30 * time.Minute,
		pageLimit:     3,
		sourceTimeout: 2 * time.Minute,
		minRank:       2, // medium and above
		logger:        log.New(os.Stderr, "[vulnmonitor] ", log.LstdFlags),
		refreshCh:     make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(m)
	}
	if !m.sourcesSet {
		m.grabbers = DefaultGrabbers()
	}
	return m
}

// DefaultGrabbers returns the nine bundled source adapters.
func DefaultGrabbers() []grab.Grabber {
	return []grab.Grabber{
		grab.NewAVDCrawler(),        // 阿里云漏洞库
		grab.NewChaitinCrawler(),    // 长亭漏洞库
		grab.NewTiCrawler(),         // 奇安信 TI
		grab.NewOSCSCrawler(),       // OSCS
		grab.NewThreatBookCrawler(), // 微步
		grab.NewSeebugCrawler(),     // Seebug
		grab.NewKEVCrawler(),        // CISA KEV
		grab.NewStruts2Crawler(),    // Apache S2 公告
		grab.NewVenustechCrawler(),  // 启明星辰
	}
}

// Providers lists the configured sources (for a settings/dashboard view).
func (m *Monitor) Providers() []grab.Provider {
	out := make([]grab.Provider, 0, len(m.grabbers))
	for _, g := range m.grabbers {
		if p := g.ProviderInfo(); p != nil {
			out = append(out, *p)
		}
	}
	return out
}

// Poll runs every source concurrently and ingests the results. Single-source
// failures are counted and returned; they never abort the other sources.
// Overlapping polls are ignored (returns an empty result).
func (m *Monitor) Poll(ctx context.Context) PollResult {
	m.mu.Lock()
	if m.polling {
		m.mu.Unlock()
		return PollResult{}
	}
	m.polling = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.polling = false
		m.lastPoll = time.Now()
		m.mu.Unlock()
	}()

	res := PollResult{Sources: len(m.grabbers)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, g := range m.grabbers {
		wg.Add(1)
		go func(g grab.Grabber) {
			defer wg.Done()
			srcCtx, cancel := context.WithTimeout(ctx, m.sourceTimeout)
			defer cancel()
			infos, err := g.GetUpdate(srcCtx, m.pageLimit)
			if err != nil {
				m.logger.Printf("%s: %v", g.ProviderInfo().Name, err)
				mu.Lock()
				res.Failed++
				res.Errors = append(res.Errors, SourceError{Source: g.ProviderInfo().Name, Error: err.Error()})
				mu.Unlock()
				return
			}
			n, u, high, items := m.ingest(ctx, g, infos)
			mu.Lock()
			res.New += n
			res.Updated += u
			res.NewHigh = append(res.NewHigh, high...)
			res.Items = append(res.Items, items...)
			mu.Unlock()
		}(g)
	}
	wg.Wait()

	m.mu.Lock()
	m.lastRes = res
	m.mu.Unlock()

	if len(res.NewHigh) > 0 && m.notify != nil {
		m.notify(res.NewHigh)
	}
	return res
}

func (m *Monitor) ingest(ctx context.Context, g grab.Grabber, infos []*grab.VulnInfo) (newN, updatedN int, newHigh []string, items []Intel) {
	for _, info := range infos {
		if info == nil {
			continue
		}
		if severityRank[string(info.Severity)] < m.minRank {
			continue
		}
		if m.useValuable && !g.IsValuable(info) {
			continue
		}
		intel := toIntel(g, info)
		items = append(items, intel)
		if m.store == nil {
			newN++
			if severityRank[intel.Severity] >= 3 {
				newHigh = append(newHigh, intel.Title)
			}
			continue
		}
		created, err := m.store.UpsertIntel(ctx, intel)
		if err != nil {
			m.logger.Printf("upsert %s: %v", intel.UniqueKey, err)
			continue
		}
		if created {
			newN++
			if severityRank[intel.Severity] >= 3 {
				newHigh = append(newHigh, intel.Title)
			}
		} else {
			updatedN++
		}
	}
	return newN, updatedN, newHigh, items
}

func toIntel(g grab.Grabber, info *grab.VulnInfo) Intel {
	p := g.ProviderInfo()
	source, sourceName := "", ""
	if p != nil {
		source, sourceName = p.DisplayName, p.Name
	}
	sourceURL := ""
	if len(info.References) > 0 {
		sourceURL = info.References[0]
	}
	return Intel{
		UniqueKey:   info.UniqueKey,
		Title:       info.Title,
		Description: truncateRunes(info.Description, 2000),
		Severity:    string(info.Severity),
		CVE:         info.CVE,
		Disclosure:  info.Disclosure,
		Solutions:   truncateRunes(info.Solutions, 2000),
		Source:      source,
		SourceName:  sourceName,
		SourceURL:   sourceURL,
		From:        info.From,
		Tags:        append([]string(nil), info.Tags...),
		References:  append([]string(nil), info.References...),
	}
}

// Start runs Poll immediately, then every interval until ctx is canceled.
// Refresh() can trigger an immediate poll between ticks.
func (m *Monitor) Start(ctx context.Context) {
	go func() {
		for {
			m.Poll(ctx)
			timer := time.NewTimer(m.interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-m.refreshCh:
				timer.Stop()
			case <-timer.C:
			}
		}
	}()
}

// Refresh asks the loop to poll now. It never blocks.
func (m *Monitor) Refresh() {
	select {
	case m.refreshCh <- struct{}{}:
	default:
	}
}

// Status returns a concurrency-safe snapshot.
func (m *Monitor) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Status{
		Polling:    m.polling,
		LastPoll:   m.lastPoll,
		LastResult: m.lastRes,
		Sources:    len(m.grabbers),
	}
}

var severityRank = map[string]int{
	"低危": 1, "中危": 2, "高危": 3, "严重": 4,
	"low": 1, "medium": 2, "high": 3, "critical": 4,
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}
