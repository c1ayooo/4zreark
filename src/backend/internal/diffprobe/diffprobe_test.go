package diffprobe

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/c1ayooo/4zreark/internal/httpprobe"
)

type fakeResult struct {
	status   int
	body     string
	duration int64
	err      error
}

// fakeDoer 按 URL 返回预设结果；durations 按调用次数循环，便于验证时间盲注。
func fakeDoer(t *testing.T, byURL map[string]fakeResult, durations map[string][]int64) Doer {
	t.Helper()
	calls := map[string]int{}
	return func(_ context.Context, req httpprobe.Request) (Response, error) {
		r, ok := byURL[req.URL]
		if !ok {
			return Response{}, errors.New("unexpected URL " + req.URL)
		}
		if r.err != nil {
			return Response{}, r.err
		}
		d := r.duration
		if ds := durations[req.URL]; len(ds) > 0 {
			i := calls[req.URL]
			d = ds[i%len(ds)]
			calls[req.URL]++
		}
		return Response{
			Result: &httpprobe.Result{
				StatusCode: r.status,
				RespBody:   r.body,
				DurationMS: d,
			},
		}, nil
	}
}

func baseRequest() Request {
	return Request{Method: "GET", URL: "http://target/api?id=1"}
}

func variant(label, role, u string) Request {
	return Request{Label: label, Role: role, Method: "GET", URL: u}
}

func TestBooleanSeparation(t *testing.T) {
	do := fakeDoer(t, map[string]fakeResult{
		"http://target/api?id=1":       {status: 200, body: "<html><body>hello world user list</body></html>"},
		"http://target/api?id=1%27":    {status: 200, body: "<html><body>hello world user list</body></html>"},
		"http://target/api?id=1%27%27": {status: 200, body: "<html><body>database error occurred</body></html>"},
	}, nil)
	rep, err := Run(context.Background(), baseRequest(),
		[]Request{
			variant("true", "true", "http://target/api?id=1%27"),
			variant("false", "false", "http://target/api?id=1%27%27"),
		},
		Options{SimilarityThreshold: 0.8}, do)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "signal" {
		t.Fatalf("verdict = %s, want signal; signals=%+v", rep.Verdict, rep.Signals)
	}
	if !hasSignal(rep, "boolean_separation") {
		t.Fatalf("missing boolean_separation: %+v", rep.Signals)
	}
}

func TestTimeBased(t *testing.T) {
	do := fakeDoer(t, map[string]fakeResult{
		"http://target/api?id=1":           {status: 200, body: "same"},
		"http://target/api?id=1%3BWAITFOR": {status: 200, body: "same"},
	}, map[string][]int64{
		"http://target/api?id=1":           {100, 110, 105},
		"http://target/api?id=1%3BWAITFOR": {1300, 1280, 1320},
	})
	rep, err := Run(context.Background(), baseRequest(),
		[]Request{variant("sleep", "probe", "http://target/api?id=1%3BWAITFOR")},
		Options{Repeats: 3, TimingDeltaMS: 1000}, do)
	if err != nil {
		t.Fatal(err)
	}
	if !hasSignal(rep, "time_based") {
		t.Fatalf("missing time_based: %+v", rep.Signals)
	}
	if rep.Verdict != "signal" {
		t.Fatalf("verdict = %s, want signal", rep.Verdict)
	}
}

func TestErrorBasedAndDBMS(t *testing.T) {
	do := fakeDoer(t, map[string]fakeResult{
		"http://target/api?id=1": {status: 200, body: "ok"},
		"http://target/api?id=1%27": {
			status: 500,
			body:   `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1'''`,
		},
	}, nil)
	rep, err := Run(context.Background(), baseRequest(),
		[]Request{variant("quote", "probe", "http://target/api?id=1%27")},
		Options{}, do)
	if err != nil {
		t.Fatal(err)
	}
	if !hasSignal(rep, "error_based") {
		t.Fatalf("missing error_based: %+v", rep.Signals)
	}
	if rep.DBMSHint != "MySQL" {
		t.Fatalf("DBMSHint = %q, want MySQL", rep.DBMSHint)
	}
}

func TestNoSignal(t *testing.T) {
	do := fakeDoer(t, map[string]fakeResult{
		"http://target/api?id=1": {status: 200, body: "same page"},
		"http://target/api?id=2": {status: 200, body: "same page"},
	}, nil)
	rep, err := Run(context.Background(), baseRequest(),
		[]Request{variant("control", "control", "http://target/api?id=2")},
		Options{}, do)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "no_signal" {
		t.Fatalf("verdict = %s, want no_signal; signals=%+v", rep.Verdict, rep.Signals)
	}
	if len(rep.Signals) != 0 {
		t.Fatalf("unexpected signals: %+v", rep.Signals)
	}
}

func TestReflectionIsWeakSignal(t *testing.T) {
	do := fakeDoer(t, map[string]fakeResult{
		"http://target/api?q=1":   {status: 200, body: "search results"},
		"http://target/api?q=XYZ": {status: 200, body: "you searched for XYZ"},
	}, nil)
	rep, err := Run(context.Background(), Request{Method: "GET", URL: "http://target/api?q=1"},
		[]Request{{Label: "echo", URL: "http://target/api?q=XYZ", Marker: "XYZ"}},
		Options{}, do)
	if err != nil {
		t.Fatal(err)
	}
	if !hasSignal(rep, "reflection") {
		t.Fatalf("missing reflection: %+v", rep.Signals)
	}
	if rep.Verdict != "inconclusive" {
		t.Fatalf("verdict = %s, want inconclusive", rep.Verdict)
	}
}

func TestVariantFailureMakesInconclusive(t *testing.T) {
	do := fakeDoer(t, map[string]fakeResult{
		"http://target/api?id=1": {status: 200, body: "ok"},
		"http://target/api?id=2": {err: errors.New("connection reset")},
	}, nil)
	rep, err := Run(context.Background(), baseRequest(),
		[]Request{variant("broken", "probe", "http://target/api?id=2")},
		Options{}, do)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "inconclusive" {
		t.Fatalf("verdict = %s, want inconclusive", rep.Verdict)
	}
	if len(rep.Notes) == 0 {
		t.Fatal("expected notes for failed variant")
	}
}

func TestBaselineFailure(t *testing.T) {
	do := fakeDoer(t, map[string]fakeResult{
		"http://target/api?id=1": {err: errors.New("timeout")},
	}, nil)
	_, err := Run(context.Background(), baseRequest(), []Request{
		variant("v", "probe", "http://target/api?id=1"),
	}, Options{}, do)
	if err == nil || !strings.Contains(err.Error(), "基线") {
		t.Fatalf("err = %v, want baseline failure", err)
	}
}

func TestSimilarity(t *testing.T) {
	if got := Similarity("a b c", "a b c"); got != 1 {
		t.Fatalf("same = %v", got)
	}
	if got := Similarity("<b>hello</b> world", "hello world"); got < 0.99 {
		t.Fatalf("normalized = %v, want ~1", got)
	}
	if got := Similarity("hello world", "completely different response"); got > 0.3 {
		t.Fatalf("different = %v, want low", got)
	}
}

func TestNormalizeOptions(t *testing.T) {
	o := normalizeOptions(Options{TimingDeltaMS: 800})
	if o.Repeats != 3 {
		t.Fatalf("repeats = %d, want 3", o.Repeats)
	}
	o = normalizeOptions(Options{})
	if o.Repeats != 1 || o.SimilarityThreshold != DefaultSimilarityThreshold {
		t.Fatalf("defaults = %+v", o)
	}
}

func hasSignal(rep *Report, typ string) bool {
	for _, s := range rep.Signals {
		if s.Type == typ {
			return true
		}
	}
	return false
}
