// SPDX-License-Identifier: MIT

package safety

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

type customQuoter struct {
	extraNano int64
}

func (c customQuoter) QuoteAttempt(_ AttemptPricingInput, base AttemptQuote) (AttemptQuote, error) {
	base.AttemptNanoUSD += c.extraNano
	return base, nil
}

type zeroQuoter struct{}

func (zeroQuoter) QuoteAttempt(in AttemptPricingInput, _ AttemptQuote) (AttemptQuote, error) {
	return AttemptQuote{Operation: in.Operation, AttemptNanoUSD: 0, CleanupReserveNanoUSD: 0}, nil
}

func TestLoadEmbeddedPriceTable_FailClosedAndStaleness(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	pt, err := LoadEmbeddedPriceTable("aws", "us-east-1", now)
	if err != nil {
		t.Fatalf("LoadEmbeddedPriceTable aws/us-east-1: %v", err)
	}
	if pt.Provider != "aws" || pt.Region != "us-east-1" {
		t.Fatalf("unexpected table metadata: %+v", pt)
	}

	// Unknown region fails closed.
	if _, err := LoadEmbeddedPriceTable("aws", "eu-central-1", now); err == nil {
		t.Fatal("expected unknown region to fail closed")
	}

	// Unknown provider fails closed.
	if _, err := LoadEmbeddedPriceTable("gcp", "us-central1", now); err == nil {
		t.Fatal("expected unpopulated provider to fail closed")
	}

	// Stale table (now > effective_date + max_age_days) fails closed.
	staleNow := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := LoadEmbeddedPriceTable("aws", "us-east-1", staleNow); err == nil {
		t.Fatal("expected stale price table to fail closed")
	}

	// Unknown operation fails closed.
	if _, err := pt.Quote(AttemptPricingInput{Operation: "nonexistent_op"}); err == nil {
		t.Fatal("expected unknown operation to fail closed")
	}
}

func TestCostMeter_ReservationsAndCleanupReserve(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pt, err := LoadEmbeddedPriceTable("aws", "us-east-1", now)
	if err != nil {
		t.Fatalf("LoadEmbeddedPriceTable: %v", err)
	}

	meter, err := NewCostMeter(CostPolicy{
		CapUSD:            DefaultCostCapUSD,
		CeilingUSD:        HardCostCeilingUSD,
		CleanupReserveUSD: DefaultCleanupReserveUSD,
	}, pt, customQuoter{extraNano: 100})
	if err != nil {
		t.Fatalf("NewCostMeter: %v", err)
	}

	snap := meter.Snapshot()
	if snap.CapNanoUSD != 50_000_000 || snap.CleanupReserveNanoUSD != 10_000_000 || snap.WorkCeilingNanoUSD != 40_000_000 {
		t.Fatalf("unexpected initial snapshot: %+v", snap)
	}

	// Reserve and commit a bucket_create (5000 + 100 custom = 5100 attempt, 10000 cleanup reserve).
	res, err := meter.ReserveAttempt(AttemptPricingInput{Operation: "bucket_create"})
	if err != nil {
		t.Fatalf("ReserveAttempt bucket_create: %v", err)
	}
	if res.Quote().AttemptNanoUSD != 5100 || res.Quote().CleanupReserveNanoUSD != 10000 {
		t.Fatalf("unexpected quote: %+v", res.Quote())
	}
	charged := res.Commit(-1, true)
	if charged != 5100 {
		t.Fatalf("Commit charged = %d, want 5100", charged)
	}
	snap = meter.Snapshot()
	if snap.ChargedNanoUSD != 5100 || snap.ResourceCleanupNanoUSD != 10000 || snap.InFlightNanoUSD != 0 {
		t.Fatalf("snapshot after commit: %+v", snap)
	}

	// Exhaust the $0.04 work ceiling: restore charged up to 39,990,000 nano-USD
	// (with 10,000 resource cleanup = 40,000,000 total committed).
	meter.RestoreCharged(39_990_000, 10_000)

	// Any further ordinary work must fail closed with ErrCostCapExceeded.
	if _, err := meter.ReserveAttempt(AttemptPricingInput{Operation: "bucket_list"}); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected ErrCostCapExceeded on ordinary work at $0.04 work ceiling, got %v", err)
	}

	// Cleanup operation (`IsCleanup: true`) CAN still draw from the $0.01 cleanup reserve!
	cleanRes, err := meter.ReserveAttempt(AttemptPricingInput{
		Operation: "queue_delete",
		IsCleanup: true,
	})
	if err != nil {
		t.Fatalf("expected cleanup attempt to succeed using cleanup reserve, got %v", err)
	}
	cleanRes.Commit(-1, false)
	meter.ReleaseResourceCleanup(10_000)

	// SetCapUSD rejects > $0.25 ceiling.
	if err := meter.SetCapUSD(0.30); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected SetCapUSD(0.30) to fail with ErrCostCapExceeded, got %v", err)
	}

	// AttemptQuoter returning 0 is clamped to max(base, q) so adapters cannot make operations free.
	zeroMeter, err := NewCostMeter(CostPolicy{
		CapUSD:            DefaultCostCapUSD,
		CeilingUSD:        HardCostCeilingUSD,
		CleanupReserveUSD: DefaultCleanupReserveUSD,
	}, pt, zeroQuoter{})
	if err != nil {
		t.Fatalf("NewCostMeter zeroQuoter: %v", err)
	}
	zq, err := zeroMeter.QuoteAttempt(AttemptPricingInput{Operation: "bucket_create"})
	if err != nil {
		t.Fatalf("QuoteAttempt zeroQuoter: %v", err)
	}
	if zq.AttemptNanoUSD != 5000 || zq.CleanupReserveNanoUSD != 10000 {
		t.Fatalf("expected zeroQuoter to be clamped to base (5000, 10000), got %+v", zq)
	}
}

func TestCostMeter_ScriptWorkSubCapAndCleanupHeadroom(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pt, err := LoadEmbeddedPriceTable("aws", "us-east-1", now)
	if err != nil {
		t.Fatalf("LoadEmbeddedPriceTable: %v", err)
	}

	// 1. Even if the operator sets TotalCapUSD to the $0.25 hard ceiling, the $0.01
	// cleanup reserve is held INSIDE $0.25, so a script work sub-cap of $0.25
	// ($0.25 work + $0.01 cleanup = $0.26 > $0.25) is rejected with ErrCostCapExceeded.
	maxMeter, err := NewCostMeter(CostPolicy{
		CapUSD:            HardCostCeilingUSD,
		CeilingUSD:        HardCostCeilingUSD,
		CleanupReserveUSD: DefaultCleanupReserveUSD,
	}, pt, nil)
	if err != nil {
		t.Fatalf("NewCostMeter max: %v", err)
	}
	if err := maxMeter.SetWorkCapUSD(0.25); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected SetWorkCapUSD(0.25) under $0.25 total cap to fail with ErrCostCapExceeded, got %v", err)
	}
	if err := maxMeter.SetWorkCapUSD(0.24); err != nil {
		t.Fatalf("expected SetWorkCapUSD(0.24) under $0.25 total cap to succeed, got %v", err)
	}

	// 2. Default $0.05 total cap ($0.01 cleanup reserve inside):
	// Create a bucket (5,000 ns work + 10,000 ns locked resource cleanup reserve),
	// then narrow the script work sub-cap down to exact settled work spend ($0.000005).
	meter, err := NewCostMeter(CostPolicy{
		CapUSD:            DefaultCostCapUSD,
		CeilingUSD:        HardCostCeilingUSD,
		CleanupReserveUSD: DefaultCleanupReserveUSD,
	}, pt, nil)
	if err != nil {
		t.Fatalf("NewCostMeter default: %v", err)
	}
	res, err := meter.ReserveAttempt(AttemptPricingInput{Operation: "bucket_create"})
	if err != nil {
		t.Fatalf("ReserveAttempt bucket_create: %v", err)
	}
	res.Commit(-1, true)

	// Narrowing work cap to > $0.04 minus locked resource cleanup fails.
	if err := meter.SetWorkCapUSD(0.04); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected SetWorkCapUSD(0.04) with locked resource cleanup to fail, got %v", err)
	}
	// Narrowing work cap below settled work spend (5,000 ns = $0.000005) fails.
	if err := meter.SetWorkCapUSD(0.000004); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected SetWorkCapUSD(0.000004) below settled work spend to fail, got %v", err)
	}
	// Narrowing work cap to exact settled work spend (5,000 ns = $0.000005) succeeds
	// even though ResourceCleanupNanoUSD (10,000 ns) is locked!
	if err := meter.SetWorkCapUSD(0.000005); err != nil {
		t.Fatalf("SetWorkCapUSD(0.000005) failed: %v", err)
	}
	snap := meter.Snapshot()
	if !snap.HasScriptWorkCap || snap.ActiveCapNanoUSD != 5000 || snap.WorkCeilingNanoUSD != 5000 || snap.CapNanoUSD != 50_000_000 {
		t.Fatalf("unexpected snapshot after SetWorkCapUSD: %+v", snap)
	}

	// Monotone non-increasing: attempting to raise work cap back to $0.01 fails.
	if err := meter.SetWorkCapUSD(0.01); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected non-monotone SetWorkCapUSD(0.01) to fail, got %v", err)
	}

	// Ordinary non-cleanup work (including queue_ack or bucket_exists) is now refused.
	if _, err := meter.ReserveAttempt(AttemptPricingInput{Operation: "bucket_exists", IsCleanup: false}); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected bucket_exists to fail after work cap narrowed to settled spend, got %v", err)
	}
	if _, err := meter.ReserveAttempt(AttemptPricingInput{Operation: "queue_ack", IsCleanup: false}); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected queue_ack (ordinary work) to fail after work cap narrowed, got %v", err)
	}

	// Cleanup operation (IsCleanup: true) succeeds using reserved cleanup headroom inside the $0.05 total cap!
	delRes, err := meter.ReserveAttempt(AttemptPricingInput{Operation: "bucket_delete", IsCleanup: true})
	if err != nil {
		t.Fatalf("expected bucket_delete (IsCleanup: true) to succeed under narrowed work cap, got %v", err)
	}
	delRes.Commit(-1, false)
	meter.ReleaseResourceCleanup(10_000)

	// 3. Journal persistence across compaction and reopen.
	dir := filepath.Join(t.TempDir(), "journals")
	pol := DefaultAWSLivePolicy(dir, true)
	runID := "run-1710000000-0123456789ab"
	j, err := OpenJournal(dir, JournalMeta{
		RunID:      runID,
		PolicyHash: pol.Hash(),
		Provider:   "aws",
		Account:    "123456789012",
		Scope:      "123456789012",
		Region:     "us-east-1",
	})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	if err := j.RecordCost(KindBucket, "", "lmcloud-conf-0123456789ab-b1", "bucket_create", 5000); err != nil {
		t.Fatalf("RecordCost: %v", err)
	}
	if err := j.RecordWorkCap(5000); err != nil {
		t.Fatalf("RecordWorkCap: %v", err)
	}
	if err := j.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	st := j.State()
	_ = j.Close()
	if st.WorkCapNanoUSD != 5000 {
		t.Fatalf("expected WorkCapNanoUSD=5000 after Compact, got %d", st.WorkCapNanoUSD)
	}

	childMeter, err := NewCostMeter(pol.Cost, pt, nil)
	if err != nil {
		t.Fatalf("NewCostMeter child: %v", err)
	}
	RestoreMeterFromState(childMeter, pt, st)
	childSnap := childMeter.Snapshot()
	if !childSnap.HasScriptWorkCap || childSnap.ActiveCapNanoUSD != 5000 || childSnap.ChargedNanoUSD != 5000 {
		t.Fatalf("unexpected child meter snapshot after RestoreMeterFromState: %+v", childSnap)
	}
	if _, err := childMeter.ReserveAttempt(AttemptPricingInput{Operation: "bucket_exists", IsCleanup: false}); !errors.Is(err, ErrCostCapExceeded) {
		t.Fatalf("expected child invocation ordinary work to fail under inherited narrowed work cap, got %v", err)
	}
}

func TestSetWorkCapUSD_TinyAndSetterErrorMapping(t *testing.T) {
	pt := SyntheticSimPriceTable("aws")
	m, err := NewCostMeter(CostPolicy{CapUSD: 0.25, CeilingUSD: 0.25, CleanupReserveUSD: 0.01}, pt, nil)
	if err != nil {
		t.Fatalf("NewCostMeter: %v", err)
	}

	// Note 5: tiny positive cap < 1 nano-USD rounds to zero and must be rejected before mutating state.
	if err := m.SetWorkCapUSD(1e-10); err == nil {
		t.Fatalf("expected error for 1e-10, got nil")
	}
	if m.Snapshot().HasScriptWorkCap {
		t.Fatalf("expected HasScriptWorkCap to remain false after rejected tiny cap")
	}

	// Exact 1 nano-USD ($0.000000001) succeeds.
	if err := m.SetWorkCapUSD(1e-9); err != nil {
		t.Fatalf("expected 1e-9 to succeed, got %v", err)
	}
	if m.Snapshot().ActiveCapNanoUSD != 1 {
		t.Fatalf("expected ActiveCapNanoUSD=1, got %d", m.Snapshot().ActiveCapNanoUSD)
	}

	// Note 4: LiveGuard.SetWorkCapUSD maps setter validation errors to hostkit.InvalidArgument (HTTPStatus 0).
	jDir := filepath.Join(t.TempDir(), "journals")
	jPol := DefaultAWSLivePolicy(jDir, true)
	j, err := OpenJournal(jDir, JournalMeta{
		RunID:      "run-1710000000-0123456789ab",
		PolicyHash: jPol.Hash(),
		Provider:   "aws",
		Account:    "123456789012",
		Scope:      "123456789012",
		Region:     "us-east-1",
	})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer func() { _ = j.Close() }()
	g := &LiveGuard{meter: m, journal: j, now: time.Now}
	cerr := g.SetWorkCapUSD(0.10) // widens above 1e-9
	if cerr == nil || cerr.Code != hostkit.InvalidArgument || cerr.HTTPStatus != 0 {
		t.Fatalf("expected hostkit.InvalidArgument with HTTPStatus=0, got %#v", cerr)
	}
}

