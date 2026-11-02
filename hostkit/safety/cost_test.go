// SPDX-License-Identifier: MIT

package safety

import (
	"errors"
	"testing"
	"time"
)

type customQuoter struct {
	extraNano int64
}

func (c customQuoter) QuoteAttempt(_ AttemptPricingInput, base AttemptQuote) (AttemptQuote, error) {
	base.AttemptNanoUSD += c.extraNano
	return base, nil
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
}
