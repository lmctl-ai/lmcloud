// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

// retryAdapter wraps a fakeadapter.Fake and drives GetObject through a configurable
// hostkit.RetryPolicy sequence of HTTP status codes before returning the object body.
type retryAdapter struct {
	*fakeadapter.Fake
	policy   hostkit.RetryPolicy
	statuses []int
}

func (a *retryAdapter) GetObject(ctx context.Context, b, k string, limit int64) ([]byte, error) {
	p := a.policy
	p.Sleep = func(context.Context, time.Duration) error { return nil }
	p.Jitter = func(time.Duration) time.Duration { return 0 }
	last, _ := p.Do(ctx, true, func(_ context.Context, attempt int) hostkit.Attempt {
		status := 200
		if attempt < len(a.statuses) {
			status = a.statuses[attempt]
		}
		return hostkit.Attempt{Status: status}
	})
	if last.Err != nil {
		return nil, last.Err
	}
	if last.Status >= 400 {
		return nil, hostkit.FinalStatusError(last.Status, "ServiceUnavailable", "simulated retry failure")
	}
	return a.Fake.GetObject(ctx, b, k, limit)
}

func TestCostPerfRetryAndMidRetryExhaustion(t *testing.T) {
	// 1. 429 -> 503 -> 200 on object_get (DefaultRetryPolicy: 3 attempts):
	// calls() == 1, errors() == 0, retries() == 2, throttles() == 1, requests() == 3.
	f1 := fakeadapter.New(fakeadapter.Options{})
	ra1 := &retryAdapter{
		Fake:     f1,
		policy:   hostkit.DefaultRetryPolicy(),
		statuses: []int{429, 503, 200},
	}
	h1 := New(Config{Provider: "aws", Store: ra1, Queue: f1})
	h1.SetAbortOnError(false)
	if _, err := h1.BucketCreate(false, "retry-bkt-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := h1.ObjectPut(false, "retry-bkt-1", "k.txt", "hello-retry", "text/plain", nil); err != nil {
		t.Fatal(err)
	}
	h1.MetricsReset()
	body, err := h1.ObjectGet(false, "retry-bkt-1", "k.txt")
	if err != nil || body != "hello-retry" {
		t.Fatalf("ObjectGet failed: body=%q err=%v", body, err)
	}
	m1 := h1.Metrics().Op("object_get")
	if m1.Calls != 1 || m1.Errors != 0 || m1.Retries != 2 || m1.Throttles != 1 || m1.BytesIn != int64(len("hello-retry")) {
		t.Fatalf("429->503->200 OpMetrics = %+v", m1)
	}
	c1 := h1.CostReport().Item("object_get")
	if c1.Requests != 3 || c1.BillingUnits != 3 || c1.Bytes != int64(len("hello-retry")) {
		t.Fatalf("429->503->200 CostLineItem = %+v", c1)
	}

	// 2. Terminal 4-attempt 429 -> 503 -> 503 -> 503 (RetryPolicy{Attempts: 4}):
	// calls() == 1, errors() == 1, retries() == 3, throttles() == 1, requests() == 4.
	f2 := fakeadapter.New(fakeadapter.Options{})
	p4 := hostkit.DefaultRetryPolicy()
	p4.Attempts = 4
	ra2 := &retryAdapter{
		Fake:     f2,
		policy:   p4,
		statuses: []int{429, 503, 503, 503},
	}
	h2 := New(Config{Provider: "aws", Store: ra2, Queue: f2})
	h2.SetAbortOnError(false)
	if _, err := h2.BucketCreate(false, "retry-bkt-2"); err != nil {
		t.Fatal(err)
	}
	h2.MetricsReset()
	_, _ = h2.ObjectGet(false, "retry-bkt-2", "k.txt")
	if h2.LastError().Code != hostkit.Internal || h2.LastError().HTTPStatus != 503 {
		t.Fatalf("expected terminal 503 INTERNAL, got %+v", h2.LastError())
	}
	m2 := h2.Metrics().Op("object_get")
	if m2.Calls != 1 || m2.Errors != 1 || m2.Retries != 3 || m2.Throttles != 1 {
		t.Fatalf("terminal 4-attempt OpMetrics = %+v", m2)
	}
	c2 := h2.CostReport().Item("object_get")
	if c2.Requests != 4 || c2.BillingUnits != 4 || c2.Bytes != 0 {
		t.Fatalf("terminal 4-attempt CostLineItem = %+v", c2)
	}

	// 3. Mid-retry cap exhaustion:
	// Budget covers 2 attempts of object_get (attempt 0 settled at 400 ns after 429,
	// attempt 1 settled at 400 ns after 503, attempt 2 requires 1,406,650 ns reservation
	// for 16 MiB bound which exceeds narrowed work cap):
	// attempt 3 is refused pre-dispatch with COST_CAP_EXCEEDED, requests() == 2,
	// retries() == 1, throttles() == 1, cap_exceeded_count() == 1.
	f3 := fakeadapter.New(fakeadapter.Options{})
	ra3 := &retryAdapter{
		Fake:     f3,
		policy:   hostkit.DefaultRetryPolicy(),
		statuses: []int{429, 503, 200},
	}
	h3 := New(Config{Provider: "aws", Store: ra3, Queue: f3})
	h3.SetAbortOnError(false)
	if _, err := h3.BucketCreate(false, "retry-bkt-3"); err != nil {
		t.Fatal(err)
	}
	baseSpend := h3.EstimatedCost()
	// Attempt 0 settles 400 ns; attempt 1 settles 400 ns; reserving attempt 2 requires
	// 400 ns + 1,406,250 ns (16 MiB @ $0.09/GiB) = 1,406,650 ns.
	// Allow 800 ns (settled attempt 0 + settled attempt 1 -> Wait: attempt 1 reservation
	// needs 400 settled + 1,406,650 in-flight = 1,407,050 ns, while attempt 2 reservation
	// needs 800 settled + 1,406,650 in-flight = 1,407,450 ns!).
	capForTwoAttempts := baseSpend + 0.001407050
	if err := h3.SetCostCapUSD(capForTwoAttempts); err != nil {
		t.Fatalf("SetCostCapUSD: %v (last=%+v)", err, h3.LastError())
	}
	h3.MetricsReset()
	_, _ = h3.ObjectGet(false, "retry-bkt-3", "k.txt")
	if h3.LastError().Code != hostkit.CostCapExceeded || h3.LastError().ProviderCode != "CostCapExceeded" || h3.LastError().HTTPStatus != 0 {
		t.Fatalf("expected COST_CAP_EXCEEDED on attempt 3, got %+v", h3.LastError())
	}
	m3 := h3.Metrics().Op("object_get")
	rep3 := h3.CostReport()
	c3 := rep3.Item("object_get")
	if c3.Requests != 2 || m3.Calls != 1 || m3.Errors != 1 || m3.Retries != 1 || m3.Throttles != 1 || rep3.CapExceededCount != 1 {
		t.Fatalf("mid-retry cap exhaustion: cost=%+v metrics=%+v capExceeded=%d", c3, m3, rep3.CapExceededCount)
	}
}

func TestLatencySampleRingBufferWraparound10005(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Provider: "ref", Store: f, Queue: f})
	h.MetricsReset()

	// Record 5 extreme outliers in the first 5 calls (1 µs and 900 ms), followed by
	// 10,000 samples of 10 ms .. 20 ms so the 10,000-sample ring buffer wraps around.
	h.RecordSyntheticMetricSample("object_get", 1*time.Microsecond, false, 0, 0, 10, 0)
	h.RecordSyntheticMetricSample("object_get", 900*time.Millisecond, false, 0, 0, 10, 0)
	h.RecordSyntheticMetricSample("object_get", 5*time.Millisecond, false, 0, 0, 10, 0)
	h.RecordSyntheticMetricSample("object_get", 5*time.Millisecond, false, 0, 0, 10, 0)
	h.RecordSyntheticMetricSample("object_get", 5*time.Millisecond, false, 0, 0, 10, 0)
	for i := 0; i < MaxLatencySamplesPerOp; i++ {
		d := 10*time.Millisecond + time.Duration(i%11)*time.Millisecond
		h.RecordSyntheticMetricSample("object_get", d, false, 0, 0, 10, 0)
	}

	opm := h.Metrics().Op("object_get")
	if opm.Calls != 10_005 {
		t.Fatalf("Calls = %d, want 10005", opm.Calls)
	}
	if math.Abs(opm.MinMS-0.001) > 1e-9 {
		t.Fatalf("MinMS = %v, want 0.001 (streaming all-call minimum must survive ring-buffer wraparound)", opm.MinMS)
	}
	if math.Abs(opm.MaxMS-900.0) > 1e-9 {
		t.Fatalf("MaxMS = %v, want 900.0 (streaming all-call maximum must survive ring-buffer wraparound)", opm.MaxMS)
	}
	wantMean := opm.TotalMS / 10005.0
	if math.Abs(opm.MeanMS-wantMean) > 1e-9 {
		t.Fatalf("MeanMS = %v, want %v", opm.MeanMS, wantMean)
	}
	if !(0.0 <= opm.MinMS && opm.MinMS <= opm.P50MS && opm.P50MS <= opm.P95MS && opm.P95MS <= opm.MaxMS && opm.MaxMS <= opm.TotalMS) {
		t.Fatalf("order invariant violated after wraparound: %+v", opm)
	}
	if !(opm.MinMS <= opm.MeanMS && opm.MeanMS <= opm.MaxMS) {
		t.Fatalf("mean invariant violated after wraparound: %+v", opm)
	}
}

func TestSetCostCapUSDValidationAndCampaignPersistence(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "campaign.json")
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: statePath})
	h.SetAbortOnError(false)

	// Tiny positive cap (< 1 nano-USD) rejected with INVALID_ARGUMENT before state change (SolReviewer Notes 4 & 5).
	_ = h.SetCostCapUSD(1e-10)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected INVALID_ARGUMENT for tiny cap, got %+v", h.LastError())
	}
	if math.Abs(h.CostCapUSD()-0.05) > 1e-12 {
		t.Fatalf("CostCapUSD mutated on rejected tiny cap: %v", h.CostCapUSD())
	}

	// Create a bucket and narrow cap to exact settled cost.
	if _, err := h.BucketCreate(false, "persist-bkt"); err != nil {
		t.Fatal(err)
	}
	spent := h.EstimatedCost()
	if err := h.SetCostCapUSD(spent); err != nil {
		t.Fatalf("SetCostCapUSD(spent) failed: %v (last=%+v)", err, h.LastError())
	}

	// Second host sharing CampaignStatePath inherits narrowed work cap and locked cleanup reserve.
	h2 := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: statePath})
	h2.SetAbortOnError(false)
	if math.Abs(h2.CostCapUSD()-spent) > 1e-12 || math.Abs(h2.EstimatedCost()-spent) > 1e-12 {
		t.Fatalf("child host did not restore cap/spend: cap=%v est=%v want=%v", h2.CostCapUSD(), h2.EstimatedCost(), spent)
	}
	_, _ = h2.BucketExists(false, "persist-bkt")
	if h2.LastError().Code != hostkit.CostCapExceeded {
		t.Fatalf("expected child BucketExists to fail with COST_CAP_EXCEEDED, got %+v", h2.LastError())
	}
	deleted, err := h2.BucketDelete(false, "persist-bkt")
	if err != nil || !deleted || h2.LastError().Code != hostkit.OK {
		t.Fatalf("expected child BucketDelete to succeed via cleanup reserve: deleted=%v err=%v last=%+v", deleted, err, h2.LastError())
	}
}
