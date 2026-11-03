// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func solDispatch(c context.Context) error {
	last, _ := hostkit.DefaultRetryPolicy().Do(c, true, func(context.Context, int) hostkit.Attempt {
		return hostkit.Attempt{Status: 200}
	})
	return last.Err
}

func TestSolSubopDirectCallback(t *testing.T) {
	h := New(Config{Provider: "aws", Tables: fakeadapter.New(fakeadapter.Options{}), CampaignStatePath: t.TempDir() + "/campaign"})
	ctx, s, e := h.beginAttemptScope(context.Background(), "table_delete", safety.AttemptPricingInput{Operation: "table_delete", IsCleanup: true}, safety.KindTable, "orders")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_put", PayloadBytes: 1024}, func(context.Context) error {
		calls++
		return nil
	})
	_, _, ae := s.finish(0, 0, true, true)
	line := h.CostReport().Item("table_delete")
	t.Logf("direct callback calls=%d err=%v finish=%v report=%+v", calls, err, ae, line)
	if calls > 0 && line.EstimatedUSD == 0 {
		t.Error("callback executed without admitted or settled sub-operation")
	}
}

func TestSolSubopNestedTariff(t *testing.T) {
	h := New(Config{Provider: "aws", Tables: fakeadapter.New(fakeadapter.Options{})})
	ctx, s, e := h.beginAttemptScope(context.Background(), "table_delete", safety.AttemptPricingInput{Operation: "table_delete", IsCleanup: true}, safety.KindTable, "orders")
	if e != nil {
		t.Fatal(e)
	}
	err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_delete", PayloadBytes: 1024}, func(outer context.Context) error {
		if err := solDispatch(outer); err != nil {
			return err
		}
		if err := hostkit.RunSubOperation(outer, hostkit.SubOperationSpec{Operation: "object_delete"}, solDispatch); err != nil {
			return err
		}
		return solDispatch(outer)
	})
	_, _, ae := s.finish(0, 0, true, true)
	line := h.CostReport().Item("table_delete")
	t.Logf("nested err=%v finish=%v report=%+v", err, ae, line)
	if line.EstimatedUSD < 0.0000025 {
		t.Error("nested sub-operation overwrote outer tariff; second outer write not charged")
	}
}

func TestSolSubopCleanupEscalation(t *testing.T) {
	h := New(Config{Provider: "aws", Tables: fakeadapter.New(fakeadapter.Options{})})
	h.SetAbortOnError(false)
	if e := h.SetCostCapUSD(0.000001); e != nil {
		t.Fatal(e)
	}
	ctx, s, e := h.beginAttemptScope(context.Background(), "table_exists", safety.AttemptPricingInput{Operation: "table_exists"}, safety.KindTable, "orders")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_put", PayloadBytes: 1024, IsCleanup: true}, func(c context.Context) error {
		last, _ := hostkit.DefaultRetryPolicy().Do(c, true, func(context.Context, int) hostkit.Attempt {
			calls++
			return hostkit.Attempt{Status: 200}
		})
		return last.Err
	})
	_, _, ae := s.finish(0, 0, true, false)
	t.Logf("work cap=$0.000001 write dispatched=%d err=%v finish=%v cost=%g", calls, err, ae, h.EstimatedCost())
	if calls > 0 {
		t.Error("non-cleanup parent promoted a write into cleanup ceiling")
	}
}

func TestSolSubopRetryCapAndPersistence(t *testing.T) {
	path := t.TempDir() + "/campaign"
	h := New(Config{Provider: "aws", Tables: fakeadapter.New(fakeadapter.Options{}), CampaignStatePath: path})
	h.SetAbortOnError(false)
	if e := h.SetCostCapUSD(0.000002); e != nil {
		t.Fatal(e)
	}
	ctx, scope, e := h.beginAttemptScope(context.Background(), "table_delete", safety.AttemptPricingInput{Operation: "table_delete"}, safety.KindTable, "orders")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_delete", PayloadBytes: 1024}, func(c context.Context) error {
		last, _ := hostkit.DefaultRetryPolicy().Do(c, true, func(context.Context, int) hostkit.Attempt {
			calls++
			return hostkit.Attempt{Status: 500}
		})
		return last.Err
	})
	_, _, finishErr := scope.finish(0, 0, false, false)
	if calls != 1 || err == nil || finishErr == nil {
		t.Fatalf("retry limit calls=%d err=%v finish=%v", calls, err, finishErr)
	}
	h2 := New(Config{Provider: "aws", Tables: fakeadapter.New(fakeadapter.Options{}), CampaignStatePath: path})
	_, s2, e2 := h2.beginAttemptScope(context.Background(), "table_delete", safety.AttemptPricingInput{Operation: "table_delete"}, safety.KindTable, "orders")
	if e2 != nil {
		t.Fatal(e2)
	}
	s2.finish(0, 0, true, false)
	t.Logf("retry dispatches=%d restart cost=%g", calls, h2.EstimatedCost())
	if h2.EstimatedCost() < 0.00000125 {
		t.Fatal("lost settled spend on restart")
	}
}

func TestSolSubopFailedJournalNoDispatch(t *testing.T) {
	path := t.TempDir() + "/campaign"
	h := New(Config{Provider: "aws", Tables: fakeadapter.New(fakeadapter.Options{}), CampaignStatePath: path})
	ctx, s, e := h.beginAttemptScope(context.Background(), "table_delete", safety.AttemptPricingInput{Operation: "table_delete"}, safety.KindTable, "orders")
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_delete", PayloadBytes: 1024}, func(c context.Context) error {
		if e := os.Rename(path, path+".saved"); e != nil {
			t.Fatal(e)
		}
		if e := os.Mkdir(path, 0700); e != nil {
			t.Fatal(e)
		}
		last, _ := hostkit.DefaultRetryPolicy().Do(c, true, func(context.Context, int) hostkit.Attempt {
			calls++
			return hostkit.Attempt{Status: 200}
		})
		return last.Err
	})
	_, _, finishErr := s.finish(0, 0, false, false)
	t.Logf("journal failure calls=%d err=%v finish=%v", calls, err, finishErr)
	if calls != 0 || err == nil {
		t.Fatal("dispatch despite missing durable journal")
	}
}

func TestSolSubopValidationLifetimeAndConcurrency(t *testing.T) {
	h := New(Config{Provider: "aws", Tables: fakeadapter.New(fakeadapter.Options{})})
	ctx, s, e := h.beginAttemptScope(context.Background(), "table_delete", safety.AttemptPricingInput{Operation: "table_delete", IsCleanup: true}, safety.KindTable, "orders")
	if e != nil {
		t.Fatal(e)
	}

	// Invalid specs rejected before callback executes.
	if err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_delete"}, nil); err == nil {
		t.Fatal("expected nil callback to fail")
	}
	if err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: ""}, solDispatch); err == nil {
		t.Fatal("expected empty operation to fail")
	}
	if err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_delete", PayloadBytes: -1}, solDispatch); err == nil {
		t.Fatal("expected negative payload bytes to fail")
	}

	// Concurrent sub-operations on the same parent scope are race-free and accounted.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_delete", PayloadBytes: 1024}, solDispatch); err != nil {
				t.Errorf("concurrent RunSubOperation: %v", err)
			}
		}()
	}
	wg.Wait()

	_, _, ae := s.finish(0, 0, true, true)
	if ae != nil {
		t.Fatalf("finish: %v", ae)
	}
	line := h.CostReport().Item("table_delete")
	if line.Requests != 4 || line.EstimatedUSD < 4*0.00000125-1e-12 {
		t.Fatalf("unexpected concurrent line item: %+v", line)
	}

	// Sub-operation after parent finish is rejected.
	if err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "item_delete", PayloadBytes: 1024}, solDispatch); err == nil {
		t.Fatal("expected sub-operation after finish to fail")
	}
}
