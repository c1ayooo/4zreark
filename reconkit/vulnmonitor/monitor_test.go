package vulnmonitor

import (
	"context"
	"errors"
	"testing"

	"github.com/c1ayooo/reconkit/vulnmonitor/grab"
)

type fakeGrabber struct {
	name  string
	infos []*grab.VulnInfo
	err   error
}

func (f *fakeGrabber) ProviderInfo() *grab.Provider {
	return &grab.Provider{Name: f.name, DisplayName: f.name, Link: "https://example.test/" + f.name}
}

func (f *fakeGrabber) GetUpdate(context.Context, int) ([]*grab.VulnInfo, error) {
	return f.infos, f.err
}

func (f *fakeGrabber) IsValuable(*grab.VulnInfo) bool { return true }

func TestPollFiltersSeverityAndDedupes(t *testing.T) {
	src := &fakeGrabber{name: "fake", infos: []*grab.VulnInfo{
		{UniqueKey: "low-1", Title: "low", Severity: grab.Low},
		{UniqueKey: "med-1", Title: "medium", Severity: grab.Medium},
		{UniqueKey: "high-1", Title: "high", Severity: grab.High, References: []string{"https://ref.test/1"}},
	}}
	store := NewMemoryStore()
	m := New(store, WithSources(src), WithPageLimit(1))

	res := m.Poll(context.Background())
	if res.New != 2 || res.Updated != 0 {
		t.Fatalf("first poll: new=%d updated=%d", res.New, res.Updated)
	}
	if len(res.NewHigh) != 1 || res.NewHigh[0] != "high" {
		t.Fatalf("new high: %v", res.NewHigh)
	}
	if len(res.Items) != 2 {
		t.Fatalf("items=%d", len(res.Items))
	}
	if store.Len() != 2 {
		t.Fatalf("store len=%d", store.Len())
	}
	if res.Items[1].SourceURL != "https://ref.test/1" {
		t.Fatalf("source url=%q", res.Items[1].SourceURL)
	}

	res = m.Poll(context.Background())
	if res.New != 0 || res.Updated != 2 {
		t.Fatalf("second poll: new=%d updated=%d", res.New, res.Updated)
	}
}

func TestPollSourceFailureDoesNotAbortOthers(t *testing.T) {
	bad := &fakeGrabber{name: "bad", err: errors.New("boom")}
	good := &fakeGrabber{name: "good", infos: []*grab.VulnInfo{
		{UniqueKey: "ok-1", Title: "ok", Severity: grab.Critical},
	}}
	m := New(nil, WithSources(bad, good), WithPageLimit(1))
	res := m.Poll(context.Background())
	if res.Failed != 1 || res.New != 1 {
		t.Fatalf("failed=%d new=%d", res.Failed, res.New)
	}
	if len(res.Errors) != 1 || res.Errors[0].Source != "bad" {
		t.Fatalf("errors=%+v", res.Errors)
	}
	if len(res.Items) != 1 || res.Items[0].UniqueKey != "ok-1" {
		t.Fatalf("items=%+v", res.Items)
	}
}

func TestWithValuableFilter(t *testing.T) {
	src := &valuableFilterGrabber{infos: []*grab.VulnInfo{
		{UniqueKey: "keep", Title: "keep", Severity: grab.High},
		{UniqueKey: "drop", Title: "drop", Severity: grab.High},
	}}
	m := New(nil, WithSources(src), WithValuableFilter(true))
	res := m.Poll(context.Background())
	if res.New != 1 || len(res.Items) != 1 || res.Items[0].UniqueKey != "keep" {
		t.Fatalf("new=%d items=%+v", res.New, res.Items)
	}
}

type valuableFilterGrabber struct {
	infos []*grab.VulnInfo
}

func (v *valuableFilterGrabber) ProviderInfo() *grab.Provider {
	return &grab.Provider{Name: "valuable", DisplayName: "valuable"}
}

func (v *valuableFilterGrabber) GetUpdate(context.Context, int) ([]*grab.VulnInfo, error) {
	return v.infos, nil
}

func (v *valuableFilterGrabber) IsValuable(info *grab.VulnInfo) bool {
	return info.UniqueKey == "keep"
}
