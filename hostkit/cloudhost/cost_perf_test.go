// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
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

type multiRetryCallStore struct {
	*fakeadapter.Fake
	dispatched int
}

func (s *multiRetryCallStore) HeadBucket(ctx context.Context, _ string) error {
	for i := 0; i < 2; i++ {
		p := hostkit.DefaultRetryPolicy()
		p.Sleep = func(context.Context, time.Duration) error { return nil }
		p.Jitter = func(time.Duration) time.Duration { return 0 }
		_, _ = p.Do(ctx, true, func(_ context.Context, _ int) hostkit.Attempt {
			s.dispatched++
			return hostkit.Attempt{Status: 200}
		})
	}
	return nil
}

func TestSolPhysicalAdmission(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	st := &multiRetryCallStore{Fake: f}
	h := New(Config{Provider: "ref", Store: st, Queue: f})
	h.SetAbortOnError(false)

	// Cap for exactly ONE bucket_exists attempt (400 nano-USD).
	if err := h.SetCostCapUSD(0.00000040); err != nil {
		t.Fatalf("SetCostCapUSD: %v", err)
	}
	_, _ = h.BucketExists(false, "probe-bucket")
	if st.dispatched != 1 {
		t.Fatalf("dispatched = %d, want 1 (second physical attempt must be refused by pre-attempt budget check)", st.dispatched)
	}
	if h.LastError().Code != hostkit.CostCapExceeded {
		t.Fatalf("expected COST_CAP_EXCEEDED on second physical attempt, got %+v", h.LastError())
	}
	if got := h.CostReport().Item("bucket_exists").Requests; got != 1 {
		t.Fatalf("reported bucket_exists requests = %d, want 1", got)
	}

	// Also verify BucketCreate 409 conflict disambiguation meters HeadBucket + BucketCreateToken.
	f2 := fakeadapter.New(fakeadapter.Options{})
	h2 := New(Config{Provider: "ref", Store: f2, Queue: f2})
	h2.SetAbortOnError(false)
	if _, err := f2.CreateBucket(context.Background(), "sol-conflict-bkt"); err != nil {
		t.Fatal(err)
	}
	// Cap for 1 request only (5,000 ns): CreateBucket (5,000 ns) returns 409, then metered HeadBucket (400 ns) must be refused!
	if err := h2.SetCostCapUSD(0.00000500); err != nil {
		t.Fatal(err)
	}
	_, _ = h2.BucketCreate(false, "sol-conflict-bkt")
	if h2.LastError().Code != hostkit.CostCapExceeded {
		t.Fatalf("expected COST_CAP_EXCEEDED on conflict disambiguation probe, got %+v", h2.LastError())
	}
}

type partialStreamStore struct {
	*fakeadapter.Fake
}

func (s *partialStreamStore) GetObject(_ context.Context, _, _ string, _ int64) ([]byte, error) {
	return []byte("partial paid bytes"), io.ErrUnexpectedEOF
}

func TestSolFailedTransferUndercharge(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	st := &partialStreamStore{Fake: f}
	h := New(Config{Provider: "ref", Store: st, Queue: f})
	h.SetAbortOnError(false)

	_, _ = h.ObjectGet(false, "probe-bucket", "key")
	if h.LastError().Code == hostkit.OK {
		t.Fatal("expected error from interrupted stream")
	}
	item := h.CostReport().Item("object_get")
	const wantCost = 0.00140665 // 400 ns request + 1,406,250 ns for 16 MiB bound
	if math.Abs(item.EstimatedUSD-wantCost) > 1e-11 || item.Bytes != hostkit.MaxObjectBytes {
		t.Fatalf("interrupted transfer undercharged: item=%+v wantCost=%v wantBytes=%d", item, wantCost, hostkit.MaxObjectBytes)
	}
}

func TestSolCampaignStaleWriter(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "campaign.json")
	f := fakeadapter.New(fakeadapter.Options{})

	h1 := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: statePath})
	h2 := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: statePath})
	h1.SetAbortOnError(false)
	h2.SetAbortOnError(false)

	if err := h1.SetCostCapUSD(0.00000040); err != nil {
		t.Fatal(err)
	}
	if err := h2.SetCostCapUSD(0.00000040); err != nil {
		t.Fatal(err)
	}
	_, _ = h1.BucketExists(false, "probe-bucket")
	if h1.LastError().Code != hostkit.OK {
		t.Fatalf("expected h1 BucketExists to succeed, got %+v", h1.LastError())
	}
	// h2 was initialized before h1 spent the budget; h2 must synchronize with the journal before admitting.
	_, _ = h2.BucketExists(false, "probe-bucket")
	if h2.LastError().Code != hostkit.CostCapExceeded {
		t.Fatalf("expected stale host h2 to synchronize and refuse with COST_CAP_EXCEEDED, got %+v", h2.LastError())
	}

	h3 := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: statePath})
	rep := h3.CostReport()
	if rep.TotalRequests != 1 || rep.CapExceededCount != 1 || math.Abs(rep.EstimatedUSD-0.00000040) > 1e-12 {
		t.Fatalf("campaign state after h2 = %+v", rep)
	}
}

func TestSolCorruptCampaignFailsOpen(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "campaign.json")
	if err := os.WriteFile(statePath, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: statePath})
	h.SetAbortOnError(false)

	_, _ = h.BucketExists(false, "probe-bucket")
	if h.LastError().Code == hostkit.OK {
		t.Fatalf("corrupt campaign state failed open! last=%+v", h.LastError())
	}
	if h.CostReport().TotalRequests != 0 {
		t.Fatalf("corrupt campaign state dispatched request: %+v", h.CostReport())
	}
}

func TestSolQueueBatchOverspendsTotal(t *testing.T) {
	for _, tc := range []struct {
		cap float64
		fee int64
	}{
		{0.05, 20_000_000},
		{0.25, 100_000_000},
	} {
		f := fakeadapter.New(fakeadapter.Options{})
		if _, err := f.CreateQueue(context.Background(), "probe-queue"); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if _, err := f.Send(context.Background(), "probe-queue", strings.Repeat("x", 48000)); err != nil {
				t.Fatal(err)
			}
		}
		pt := safety.SyntheticSimPriceTable("ref")
		q := pt.Operations["queue_receive"]
		q.RequestNanoUSD = tc.fee
		pt.Operations["queue_receive"] = q

		meter, err := safety.NewCostMeter(safety.CostPolicy{
			CapUSD:            tc.cap,
			CeilingUSD:        0.25,
			CleanupReserveUSD: 0.01,
		}, pt, nil)
		if err != nil {
			t.Fatal(err)
		}
		h := New(Config{Provider: "ref", Queue: f, Meter: meter})
		h.SetAbortOnError(false)

		msgs, _ := h.QueueReceive(false, "probe-queue", 3, 0, 30)
		if len(msgs) != 0 || h.LastError().Code != hostkit.CostCapExceeded {
			t.Fatalf("cap=%g: expected pre-dispatch COST_CAP_EXCEEDED, got len=%d last=%+v", tc.cap, len(msgs), h.LastError())
		}
		r := h.CostReport()
		if r.EstimatedUSD > r.CapUSD || r.EstimatedUSD > r.CeilingUSD {
			t.Fatalf("cap=%g: overspent cap: %+v", tc.cap, r)
		}
	}

	// Also verify AttemptReservation.Commit clamps direct ActualCostNanoUSD overrides above reservation.
	tbl := safety.SyntheticSimPriceTable("ref")
	meter2, err := safety.NewCostMeter(safety.CostPolicy{
		CapUSD:            0.25,
		CeilingUSD:        0.25,
		CleanupReserveUSD: 0.01,
	}, tbl, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := meter2.ReserveAttempt(safety.AttemptPricingInput{Operation: "queue_receive", PayloadSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	committed := res.Commit(1_000_000_000, false) // attempt to settle $1.00 on a 400-ns reservation
	snap2 := meter2.Snapshot()
	if committed != res.Quote().AttemptNanoUSD || snap2.ChargedNanoUSD > res.Quote().AttemptNanoUSD {
		t.Fatalf("Commit failed to clamp to admitted reservation: committed=%d total=%d quote=%d", committed, snap2.ChargedNanoUSD, res.Quote().AttemptNanoUSD)
	}
}

type shortPollQueue struct {
	*fakeadapter.Fake
	polls int
}

func (q *shortPollQueue) Receive(_ context.Context, _ string, _, _, _ int) ([]hostkit.RawMessage, error) {
	q.polls++
	return nil, nil
}

func TestSolShortPollUndercharges(t *testing.T) {
	// 1. Verify all 5 short-poll dispatches in a 1s wait with 250ms interval are billed individually.
	a := &shortPollQueue{Fake: fakeadapter.New(fakeadapter.Options{})}
	now := time.Now()
	h := New(Config{
		Provider:     "ref",
		Queue:        a,
		PollInterval: 250 * time.Millisecond,
		Now:          func() time.Time { return now },
		Sleep: func(_ context.Context, d time.Duration) error {
			now = now.Add(d)
			return nil
		},
	})
	h.SetAbortOnError(false)
	_, err := h.QueueReceive(false, "probe-queue", 1, 1, 30)
	if err != nil || h.LastError().Code != hostkit.OK {
		t.Fatalf("QueueReceive failed: err=%v last=%+v", err, h.LastError())
	}
	r := h.CostReport().Item("queue_receive")
	if a.polls != 5 || r.Requests != int64(a.polls) {
		t.Fatalf("short-poll undercharged: polls=%d report=%+v", a.polls, r)
	}

	// 2. Verify mid-WaitLoop cap exhaustion stops further short-poll dispatches.
	a2 := &shortPollQueue{Fake: fakeadapter.New(fakeadapter.Options{BinaryWire: true})}
	now2 := time.Unix(1_700_000_000, 0)
	h2 := New(Config{
		Provider:     "ref",
		Queue:        a2,
		PollInterval: 250 * time.Millisecond,
		Now:          func() time.Time { return now2 },
		Sleep: func(_ context.Context, d time.Duration) error {
			now2 = now2.Add(d)
			return nil
		},
	})
	h2.SetAbortOnError(false)
	if err := h2.SetCostCapUSD(0.00000080); err != nil {
		t.Fatal(err)
	}
	_, _ = h2.QueueReceive(false, "probe-queue", 1, 2, 30)
	if a2.polls != 2 || h2.LastError().Code != hostkit.CostCapExceeded {
		t.Fatalf("expected 2 polls then COST_CAP_EXCEEDED, got polls=%d last=%+v", a2.polls, h2.LastError())
	}
}

type crashInFlightStore struct {
	*fakeadapter.Fake
	statePath           string
	hadLedgerAtDispatch bool
	check               func()
}

func (s *crashInFlightStore) HeadBucket(_ context.Context, _ string) error {
	raw, err := os.ReadFile(s.statePath)
	s.hadLedgerAtDispatch = err == nil && strings.Contains(string(raw), `"event":"reserve"`)
	return nil
}

func (s *crashInFlightStore) GetObject(_ context.Context, _, _ string, _ int64) ([]byte, error) {
	if s.check != nil {
		s.check()
	}
	return nil, hostkit.ProviderError(hostkit.Internal, 500, "SimulatedCrash", "process interrupted mid-flight")
}

func TestSolNoDurableReservation(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "campaign.json")
	f := fakeadapter.New(fakeadapter.Options{})
	st := &crashInFlightStore{
		Fake:      f,
		statePath: statePath,
	}
	h := New(Config{Provider: "ref", Store: st, Queue: f, CampaignStatePath: statePath})
	h.SetAbortOnError(false)

	_, _ = h.BucketExists(false, "probe-bucket")
	if !st.hadLedgerAtDispatch {
		t.Fatal("expected durable reserve record on disk BEFORE HeadBucket dispatch")
	}

	// Simulate an un-settled pending reservation left behind by a SIGKILL mid-request:
	// panic inside GetObject so finish() never runs, and verify a new Host charges the reserved bound on replay.
	crashPath := filepath.Join(t.TempDir(), "crash-campaign.json")
	f2 := fakeadapter.New(fakeadapter.Options{})
	hCrash := New(Config{Provider: "ref", Store: &crashInFlightStore{
		Fake: f2,
		check: func() {
			panic("simulated-sigkill")
		},
	}, Queue: f2, CampaignStatePath: crashPath})
	hCrash.SetAbortOnError(false)
	func() {
		defer func() { _ = recover() }()
		_, _ = hCrash.ObjectGet(false, "sol-bkt", "sol-key")
	}()

	hReplayed := New(Config{Provider: "ref", Store: f2, Queue: f2, CampaignStatePath: crashPath})
	const wantReserved = 0.00140665
	if got := hReplayed.EstimatedCost(); math.Abs(got-wantReserved) > 1e-11 {
		t.Fatalf("replayed unresolved reservation cost = %v, want %v", got, wantReserved)
	}
	if item := hReplayed.CostReport().Item("object_get"); item.Requests != 1 || item.Bytes != hostkit.MaxObjectBytes {
		t.Fatalf("replayed unresolved reservation line item = %+v", item)
	}
}

func TestSolStateWriteFollowsSymlink(t *testing.T) {
	// 1. Symlink at predictable .PID.tmp path must not be touched.
	dir1 := t.TempDir()
	p1 := filepath.Join(dir1, "campaign.json")
	victim1 := filepath.Join(dir1, "must-not-overwrite")
	if err := os.WriteFile(victim1, []byte("preserve me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim1, p1+"."+strings.TrimSpace(filepath.Base(os.Args[0]))+".tmp"); err != nil {
		t.Fatal(err)
	}
	// Also create the exact "%s.%d.tmp" symlink from Sol's probe:
	tmpLink := filepath.Join(dir1, "campaign.json."+itoaPID(os.Getpid())+".tmp")
	if err := os.Symlink(victim1, tmpLink); err != nil {
		t.Fatal(err)
	}
	h1 := New(Config{Provider: "ref", Store: fakeadapter.New(fakeadapter.Options{}), CampaignStatePath: p1})
	h1.SetAbortOnError(false)
	_, _ = h1.BucketExists(false, "probe-bucket")
	if got, _ := os.ReadFile(victim1); string(got) != "preserve me" {
		t.Fatalf("victim1 overwritten via .PID.tmp symlink: %q", string(got))
	}

	// 2. Symlink at statePath itself must be refused by O_NOFOLLOW.
	dir2 := t.TempDir()
	victim2 := filepath.Join(dir2, "victim.txt")
	if err := os.WriteFile(victim2, []byte("DO-NOT-TOUCH"), 0o600); err != nil {
		t.Fatal(err)
	}
	statePath2 := filepath.Join(dir2, "campaign.json")
	if err := os.Symlink(victim2, statePath2); err != nil {
		t.Fatal(err)
	}

	f := fakeadapter.New(fakeadapter.Options{})
	h2 := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: statePath2})
	h2.SetAbortOnError(false)
	_, _ = h2.BucketCreate(false, "sol-symlink-bkt")
	if h2.LastError().Code == hostkit.OK {
		t.Fatalf("expected symlink state path to be refused, got last=%+v", h2.LastError())
	}
	gotVictim, err := os.ReadFile(victim2)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotVictim) != "DO-NOT-TOUCH" {
		t.Fatalf("victim file was modified through symlink: %q", string(gotVictim))
	}
}

func itoaPID(pid int) string {
	if pid == 0 {
		return "0"
	}
	var buf [32]byte
	i := len(buf)
	for pid > 0 {
		i--
		buf[i] = byte('0' + pid%10)
		pid /= 10
	}
	return string(buf[i:])
}

type cancelDuringSleepStore struct {
	*fakeadapter.Fake
	mode       string // "parent", "child", "sleep_err"
	dispatched int
}

func (s *cancelDuringSleepStore) GetObject(ctx context.Context, _, _ string, _ int64) ([]byte, error) {
	callCtx := ctx
	var cancelChild context.CancelFunc
	if s.mode == "child" {
		callCtx, cancelChild = context.WithCancel(ctx)
		defer cancelChild()
	}

	p := hostkit.DefaultRetryPolicy()
	p.Attempts = 3
	p.Jitter = func(time.Duration) time.Duration { return 0 }
	p.Sleep = func(_ context.Context, _ time.Duration) error {
		switch s.mode {
		case "child":
			cancelChild()
			return callCtx.Err()
		case "sleep_err":
			return context.DeadlineExceeded
		default:
			return nil
		}
	}

	_, _ = p.Do(callCtx, true, func(attemptCtx context.Context, attempt int) hostkit.Attempt {
		if s.mode == "parent" && attempt == 1 {
			cctx, cancel := context.WithCancel(attemptCtx)
			cancel()
			return hostkit.Attempt{Err: cctx.Err(), NotSent: true}
		}
		s.dispatched++
		return hostkit.Attempt{Status: 503}
	})
	return nil, hostkit.ProviderError(hostkit.Internal, 503, "Unavailable", "cancelled during retry sleep")
}

func TestSolCancelledSleepAccounting(t *testing.T) {
	for _, mode := range []string{"child", "parent", "sleep_err"} {
		t.Run(mode, func(t *testing.T) {
			f := fakeadapter.New(fakeadapter.Options{})
			st := &cancelDuringSleepStore{Fake: f, mode: mode}
			h := New(Config{Provider: "ref", Store: st, Queue: f})
			h.SetAbortOnError(false)

			_, _ = h.ObjectGet(false, "probe-bucket", "key")
			if st.dispatched != 1 {
				t.Fatalf("dispatched = %d, want 1", st.dispatched)
			}
			item := h.CostReport().Item("object_get")
			m := h.Metrics().Op("object_get")
			if item.Requests != 1 || m.Retries != 0 {
				t.Fatalf("undispatched retry was billed/counted (%s): cost=%+v metrics=%+v", mode, item, m)
			}
		})
	}
}

func TestSolLiveDefaultsToSynthetic(t *testing.T) {
	t.Setenv("LMCLOUD_LIVE", "1")
	f := fakeadapter.New(fakeadapter.Options{})

	// 1. Default Config with no Meter/Journal in live mode must not report synthetic price table and must fail closed on dispatch.
	h1 := New(Config{Provider: "aws", Store: f, Queue: f})
	h1.SetAbortOnError(false)
	if h1.CostReport().PriceTableVersion == safety.SyntheticSimPriceTableVersion || h1.CostReport().PriceTableVersion != "" {
		t.Fatalf("live mode with default unconfigured meter selected price table %q", h1.CostReport().PriceTableVersion)
	}
	_, _ = h1.BucketCreate(false, "sol-live-bkt")
	if h1.LastError().Code == hostkit.OK {
		t.Fatalf("live mode with default unconfigured meter failed open! last=%+v", h1.LastError())
	}
	if names, _, _ := f.ListBuckets(context.Background(), ""); len(names) != 0 {
		t.Fatalf("live mode dispatched bucket creation without valid meter/journal: %v", names)
	}

	// 2. Explicit synthetic price table in live mode must also fail closed.
	synMeter, err := safety.NewCostMeter(safety.CostPolicy{
		CapUSD:            0.05,
		CleanupReserveUSD: 0.01,
	}, safety.SyntheticSimPriceTable("ref"), nil)
	if err != nil {
		t.Fatal(err)
	}
	jDir1, err := safety.EnsureStateDir(filepath.Join(t.TempDir(), "state1"))
	if err != nil {
		t.Fatal(err)
	}
	j1, err := safety.OpenJournal(jDir1, safety.JournalMeta{
		RunID:      "run-1700000000-0123456789ab",
		PolicyHash: strings.Repeat("a", 64),
		Provider:   "aws",
		Account:    "123456789012",
		Scope:      "arn:aws:iam::123456789012:role/lmcloud-conformance-ci",
		Region:     "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j1.Close() }()

	h2 := New(Config{Provider: "aws", Store: f, Queue: f, Meter: synMeter, Journal: j1})
	h2.SetAbortOnError(false)
	_, _ = h2.BucketCreate(false, "sol-live-bkt-2")
	if h2.LastError().Code == hostkit.OK {
		t.Fatalf("live mode with synthetic price table failed open! last=%+v", h2.LastError())
	}

	// 3. Verified regional AWS us-east-1 price table + safety.Journal in live mode succeeds.
	realTbl, err := safety.LoadEmbeddedPriceTable("aws", "us-east-1", time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	realMeter, err := safety.NewCostMeter(safety.CostPolicy{
		CapUSD:            0.05,
		CleanupReserveUSD: 0.01,
	}, realTbl, nil)
	if err != nil {
		t.Fatal(err)
	}
	jDir2, err := safety.EnsureStateDir(filepath.Join(t.TempDir(), "state2"))
	if err != nil {
		t.Fatal(err)
	}
	j2, err := safety.OpenJournal(jDir2, safety.JournalMeta{
		RunID:      "run-1700000000-0123456789cd",
		PolicyHash: strings.Repeat("b", 64),
		Provider:   "aws",
		Account:    "123456789012",
		Scope:      "arn:aws:iam::123456789012:role/lmcloud-conformance-ci",
		Region:     "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j2.Close() }()

	h3 := New(Config{Provider: "aws", Store: f, Queue: f, Meter: realMeter, Journal: j2})
	h3.SetAbortOnError(false)
	if _, err := h3.BucketCreate(false, "sol-live-ok-bkt"); err != nil || h3.LastError().Code != hostkit.OK {
		t.Fatalf("live mode with verified regional meter + journal failed: %v (last=%+v)", err, h3.LastError())
	}
	if got := h3.CostReport().Item("bucket_create").Requests; got != 1 {
		t.Fatalf("live mode bucket_create requests = %d, want 1", got)
	}
}

func TestSolFailedSetterPersistence(t *testing.T) {
	// 1. Missing parent directory fails SetCostCapUSD and does not report success.
	p1 := filepath.Join(t.TempDir(), "missing-parent", "campaign.json")
	f := fakeadapter.New(fakeadapter.Options{})
	h1 := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: p1})
	h1.SetAbortOnError(false)
	_ = h1.SetCostCapUSD(0.00000040)
	if h1.LastError().Code == hostkit.OK {
		t.Fatalf("expected SetCostCapUSD on missing parent dir to fail, got last=%+v", h1.LastError())
	}

	// 2. Replacing statePath with a directory after initial creation fails SetCostCapUSD and poisons the host.
	dir := t.TempDir()
	statePath := filepath.Join(dir, "campaign.json")
	h2 := New(Config{Provider: "ref", Store: f, Queue: f, CampaignStatePath: statePath})
	h2.SetAbortOnError(false)

	if _, err := h2.BucketCreate(false, "sol-setter-bkt"); err != nil || h2.LastError().Code != hostkit.OK {
		t.Fatalf("BucketCreate: err=%v last=%+v", err, h2.LastError())
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}

	_ = h2.SetCostCapUSD(0.01)
	if h2.LastError().Code == hostkit.OK {
		t.Fatalf("expected SetCostCapUSD to fail when persistence fails, got last=%+v", h2.LastError())
	}
	// Subsequent operations must also fail closed because the ledger is poisoned.
	_, _ = h2.BucketExists(false, "sol-setter-bkt")
	if h2.LastError().Code == hostkit.OK {
		t.Fatalf("expected subsequent operation to fail closed after persistence failure, got last=%+v", h2.LastError())
	}
}

