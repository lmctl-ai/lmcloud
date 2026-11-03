// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func solTabHost(f hostkit.Tables) *Host {
	h := New(Config{
		Provider:  "ref",
		Tables:    f,
		Endpoints: &hostkit.EndpointResolver{Getenv: func(string) string { return "" }},
	})
	h.SetAbortOnError(false)
	return h
}

func solFullAttrs() map[string]hostkit.Attr {
	m := map[string]hostkit.Attr{}
	for i := 0; i < 8; i++ {
		n := 32768
		if i == 7 {
			n = 32688
		}
		m[fmt.Sprintf("a%d", i)] = hostkit.StringAttr(strings.Repeat("x", n))
	}
	return m
}

func TestSolTablesValues(t *testing.T) {
	for _, s := range []string{strings.Repeat("雪", 32768), strings.Repeat("😀", 16384)} {
		if e := hostkit.AttrStringValue(s); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{strings.Repeat("雪", 32769), strings.Repeat("😀", 16385), "\xff"} {
		if e := hostkit.AttrStringValue(s); e == nil {
			t.Fatal("accepted invalid string")
		}
	}
	attrs := solFullAttrs()
	if n, e := hostkit.CanonicalItemBytes(attrs); e != nil || n != 262144 {
		t.Fatalf("n=%d err=%v", n, e)
	}
	attrs["a7"] = hostkit.StringAttr(strings.Repeat("x", 32689))
	if _, e := hostkit.CanonicalItemBytes(attrs); e == nil {
		t.Fatal("accepted +1 byte")
	}
	attrs = map[string]hostkit.Attr{}
	for i := 0; i < 240; i++ {
		attrs[fmt.Sprintf("a%d", i)] = hostkit.BoolAttr(true)
	}
	if _, e := hostkit.CanonicalItemBytes(attrs); e != nil {
		t.Fatal(e)
	}
	attrs["extra"] = hostkit.BoolAttr(true)
	if _, e := hostkit.CanonicalItemBytes(attrs); e == nil {
		t.Fatal("accepted 241 attrs")
	}
	for _, x := range []float64{0, 1e-130, 9.999e125} {
		if e := hostkit.AttrNumberValue(x); e != nil {
			t.Fatal(e)
		}
	}
	for _, x := range []float64{math.NaN(), math.Inf(1), 1e126, 1e-131} {
		if e := hostkit.AttrNumberValue(x); e == nil {
			t.Fatal("invalid number accepted")
		}
	}
}

func TestSolTablesTokenMaxReplay(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := solTabHost(f)
	_, _ = h.TableCreate(false, "tab", true)
	for _, sk := range []string{"a", "b", "c"} {
		it, _ := h.ItemNew("pk", sk, true)
		_, _ = h.ItemPut(false, "tab", it, hostkit.PutUnconditional, "")
	}
	p, _ := h.ItemQuery(false, "tab", "pk", "", "", 1, "")
	if p.NextToken == "" {
		t.Fatal(h.LastError())
	}
	calls := f.Calls()["Query"]
	_, _ = h.ItemQuery(false, "tab", "pk", "", "", 2, p.NextToken)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 || f.Calls()["Query"] != calls {
		t.Fatalf("expected preflight INVALID_ARGUMENT without backend Query call; got last=%+v calls=%d->%d", h.LastError(), calls, f.Calls()["Query"])
	}
}

func TestSolTablesDryOverlayLostFromPages(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := solTabHost(f)
	_, _ = h.TableCreate(true, "tab", true)
	it, _ := h.ItemNew("pk", "a", true)
	stored, _ := h.ItemPut(true, "tab", it, hostkit.PutUnconditional, "")
	got, _ := h.ItemGet(true, "tab", "pk", "a", true)
	q, _ := h.ItemQuery(true, "tab", "pk", "", "", 1, "")
	s, _ := h.ItemScan(true, "tab", 1, "")
	if !stored.Exists() || !got.Exists() || len(q.Items) != 1 || len(s.Items) != 1 || f.MutatorCalls() != 0 {
		t.Fatalf("expected dry overlay items in query and scan with 0 mutator calls; got stored=%v got=%v q=%d s=%d mut=%d",
			stored.Exists(), got.Exists(), len(q.Items), len(s.Items), f.MutatorCalls())
	}
}

func TestSolTablesDryConditionsIgnoreBackend(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	_, _ = f.CreateTable(context.Background(), "tab", false)
	_, _ = f.PutItem(context.Background(), "tab", hostkit.Item{PK: "pk", Attrs: map[string]hostkit.Attr{}}, hostkit.PutUnconditional, "")
	mutBefore := f.MutatorCalls()

	h := solTabHost(f)
	it, _ := h.ItemNew("pk", "", false)
	_, _ = h.ItemPut(true, "tab", it, hostkit.PutIfAbsent, "")
	if h.LastError().Code != hostkit.Conflict {
		t.Fatalf("expected dry PutIfAbsent on existing backend item to return CONFLICT, got %+v", h.LastError())
	}
	it2, _ := h.ItemNew("absent", "", false)
	_, _ = h.ItemPut(true, "tab", it2, hostkit.PutIfVersion, "stale")
	if h.LastError().Code != hostkit.NotFound {
		t.Fatalf("expected dry PutIfVersion on missing backend item to return NOT_FOUND, got %+v", h.LastError())
	}
	if f.MutatorCalls() != mutBefore {
		t.Fatalf("dry-run mutated backend: mutator calls %d -> %d", mutBefore, f.MutatorCalls())
	}
}

type solTwoTableWrites struct {
	*fakeadapter.Fake
	calls int
}

func (a *solTwoTableWrites) PutItem(ctx context.Context, t string, it hostkit.Item, m hostkit.PutMode, v string) (hostkit.Item, error) {
	var out hostkit.Item
	for i := 0; i < 2; i++ {
		last, _ := hostkit.DefaultRetryPolicy().Do(ctx, false, func(c context.Context, _ int) hostkit.Attempt {
			a.calls++
			var e error
			out, e = a.Fake.PutItem(c, t, it, m, v)
			return hostkit.Attempt{Status: 200, Err: e}
		})
		if last.Err != nil {
			return hostkit.Item{}, last.Err
		}
	}
	return out, nil
}

func TestSolTablesPerPhysicalWriteUndercharge(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	_, _ = f.CreateTable(context.Background(), "tab", false)
	a := &solTwoTableWrites{Fake: f}
	h := solTabHost(a)
	it := newTableItemFromHostkit(h, hostkit.Item{PK: "pk", Attrs: solFullAttrs()})
	quote, _ := h.cost.meter.QuoteAttempt(safety.AttemptPricingInput{Operation: "item_put", PayloadSize: 262144})
	base := h.cost.meter.Table().Operations["item_put"].RequestNanoUSD
	capNano := quote.AttemptNanoUSD + base
	if e := h.SetCostCapUSD(safety.NanoToUSD(capNano)); e != nil {
		t.Fatal(e)
	}
	_, _ = h.ItemPut(false, "tab", it, hostkit.PutUnconditional, "")
	if a.calls != 1 || h.LastError().Code != hostkit.CostCapExceeded {
		t.Fatalf("expected 2nd physical write to be rejected by COST_CAP_EXCEEDED after 1st write settled; calls=%d last=%+v", a.calls, h.LastError())
	}

	// With enough budget for both physical writes on a fresh host, both must be billed at full payload units.
	a2 := &solTwoTableWrites{Fake: f}
	h2 := solTabHost(a2)
	it2 := newTableItemFromHostkit(h2, hostkit.Item{PK: "pk", Attrs: solFullAttrs()})
	_, _ = h2.ItemPut(false, "tab", it2, hostkit.PutUnconditional, "")
	r := h2.CostReport().Item("item_put")
	if a2.calls != 2 || h2.LastError().Code != hostkit.OK || r.BillingUnits < 2*256 {
		t.Fatalf("expected both physical writes billed at >=512 units; calls=%d report=%+v last=%+v", a2.calls, r, h2.LastError())
	}
}

func solJournal(t *testing.T) (*safety.CostMeter, *safety.Journal, safety.Policy) {
	t.Helper()
	dir, e := safety.EnsureStateDir(filepath.Join(t.TempDir(), "journals"))
	if e != nil {
		t.Fatal(e)
	}
	pol := safety.DefaultAWSLivePolicy(dir, true)
	pt, e := safety.LoadEmbeddedPriceTable("aws", "us-east-1", time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	m, e := safety.NewCostMeter(pol.Cost, pt, nil)
	if e != nil {
		t.Fatal(e)
	}
	j, e := safety.OpenJournal(dir, safety.JournalMeta{
		RunID:      "run-1700000000-abcdef012345",
		Provider:   "aws",
		Account:    "254332045686",
		Scope:      "scope",
		Region:     "us-east-1",
		PolicyHash: pol.Hash(),
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { j.Close() })
	return m, j, pol
}

type solUnusedRecovery struct{ safety.RecoveryAdapter }

func TestSolTablesDelegatedBypass(t *testing.T) {
	m, j, p := solJournal(t)
	g, e := safety.NewLiveGuard(safety.GuardConfig{Policy: p, Meter: m, Journal: j, Recovery: &solUnusedRecovery{}})
	if e != nil {
		t.Fatal(e)
	}
	f := fakeadapter.New(fakeadapter.Options{})
	_, _ = f.CreateTable(context.Background(), "foreign", false)
	mutBefore := f.MutatorCalls()
	h := New(Config{Provider: "aws", Store: g.WrapStore(fakeadapter.New(fakeadapter.Options{})), Tables: f})
	h.SetAbortOnError(false)
	if e := h.SetCostCapUSD(0.000000001); e != nil {
		t.Fatal(e)
	}
	deleted, _ := h.TableDelete(false, "foreign")
	if deleted || h.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected unguarded live TableDelete to fail closed with PERMISSION_DENIED; deleted=%v last=%+v", deleted, h.LastError())
	}
	made, _ := h.TableCreate(false, "tab", false)
	if made || h.LastError().Code != hostkit.CostCapExceeded {
		t.Fatalf("expected TableCreate under 1-nano cap to fail with COST_CAP_EXCEEDED; made=%v last=%+v", made, h.LastError())
	}

	// Even with sufficient work cap on a fresh host, unguarded live tables must fail closed until tables ownership/recovery exists.
	m2, j2, p2 := solJournal(t)
	g2, e := safety.NewLiveGuard(safety.GuardConfig{Policy: p2, Meter: m2, Journal: j2, Recovery: &solUnusedRecovery{}})
	if e != nil {
		t.Fatal(e)
	}
	h2 := New(Config{Provider: "aws", Store: g2.WrapStore(fakeadapter.New(fakeadapter.Options{})), Tables: f})
	h2.SetAbortOnError(false)
	deleted, _ = h2.TableDelete(false, "foreign")
	if deleted || h2.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected unguarded live TableDelete to fail closed with PERMISSION_DENIED; deleted=%v last=%+v", deleted, h2.LastError())
	}
	made, _ = h2.TableCreate(false, "tab", false)
	if made || h2.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected unguarded live TableCreate to fail closed with PERMISSION_DENIED; made=%v last=%+v", made, h2.LastError())
	}
	if f.MutatorCalls() != mutBefore {
		t.Fatalf("expected 0 backend table mutations, got %d -> %d", mutBefore, f.MutatorCalls())
	}
}

func TestSolTablesJournalRoundTrip(t *testing.T) {
	m, j, _ := solJournal(t)
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Provider: "aws", Tables: f, Meter: m, Journal: j})
	h.SetAbortOnError(false)
	made, _ := h.TableCreate(false, "tab", false)
	if !made || h.LastError().Code != hostkit.OK {
		t.Fatal(h.LastError())
	}
	meta := j.Meta()
	dir := filepath.Dir(j.Path())
	if e := j.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := safety.OpenJournal(dir, meta)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if reopened.State().ChargedNanoUSD != 5000 || len(reopened.State().ActiveCleanup) != 1 {
		t.Fatalf("state %+v", reopened.State())
	}
}

func TestSolTablesCleanupAfterNonemptyDelete(t *testing.T) {
	for _, mode := range []string{"memory", "campaign", "journal"} {
		t.Run(mode, func(t *testing.T) {
			f := fakeadapter.New(fakeadapter.Options{})
			cfg := Config{Provider: "ref", Tables: f}
			switch mode {
			case "campaign":
				cfg.CampaignStatePath = filepath.Join(t.TempDir(), "campaign.jsonl")
			case "journal":
				m, j, _ := solJournal(t)
				cfg.Provider = "aws"
				cfg.Meter = m
				cfg.Journal = j
			}
			h := New(cfg)
			h.SetAbortOnError(false)
			_, _ = h.TableCreate(false, "tab", false)
			it, _ := h.ItemNew("pk", "", false)
			_, _ = h.ItemPut(false, "tab", it, hostkit.PutUnconditional, "")
			_, _ = h.TableDelete(false, "tab")
			if h.LastError().Code != hostkit.OK {
				t.Fatal(h.LastError())
			}
			got := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
			if got != 0 {
				t.Fatalf("%s: expected 0 cleanup nanos after nonempty table delete, got %d", mode, got)
			}
			if mode != "memory" {
				child := New(cfg)
				_ = child.CostReport()
				if got := child.cost.meter.Snapshot().ResourceCleanupNanoUSD; got != 0 {
					t.Fatalf("%s child reopen: expected 0 cleanup nanos, got %d", mode, got)
				}
			}
		})
	}
}

func TestSolTablesOverwriteAndDeleteCosts(t *testing.T) {
	for _, op := range []string{"put", "update", "delete"} {
		t.Run(op, func(t *testing.T) {
			f := fakeadapter.New(fakeadapter.Options{})
			_, _ = f.CreateTable(context.Background(), "tab", false)
			old := hostkit.Item{PK: "pk", Attrs: map[string]hostkit.Attr{"value": hostkit.StringAttr(strings.Repeat("x", 32768))}}
			_, _ = f.PutItem(context.Background(), "tab", old, hostkit.PutUnconditional, "")
			h := solTabHost(f)
			small, _ := h.ItemNew("pk", "", false)
			_, _ = small.SetBool("value", true)
			if op == "put" {
				hTight := solTabHost(f)
				if e := hTight.SetCostCapUSD(0.00000125); e != nil {
					t.Fatal(e)
				}
				smallTight, _ := hTight.ItemNew("pk", "", false)
				_, _ = smallTight.SetBool("value", true)
				mutBefore := f.MutatorCalls()
				_, _ = hTight.ItemPut(false, "tab", smallTight, hostkit.PutUnconditional, "")
				if hTight.LastError().Code != hostkit.CostCapExceeded || f.MutatorCalls() != mutBefore {
					t.Fatalf("expected 1-unit-capped overwrite to fail closed with COST_CAP_EXCEEDED before mutation; last=%+v mut=%d->%d",
						hTight.LastError(), mutBefore, f.MutatorCalls())
				}
			}
			switch op {
			case "put":
				_, _ = h.ItemPut(false, "tab", small, hostkit.PutUnconditional, "")
			case "update":
				_, _ = h.ItemUpdate(false, "tab", "pk", "", false, small)
			case "delete":
				_ = h.ItemDelete(false, "tab", "pk", "", false)
			}
			if h.LastError().Code != hostkit.OK {
				t.Fatal(h.LastError())
			}
			r := h.CostReport().Item("item_" + op)
			if r.BillingUnits < 33 {
				t.Fatalf("%s on existing >32KiB item must bill >=33 units, got %+v", op, r)
			}
		})
	}
}

func TestSolTablesFloatExactBoundary(t *testing.T) {
	belowMin := math.Nextafter(1e-130, 0)
	belowMax := math.Nextafter(1e126, 0)
	if hostkit.AttrNumberValue(belowMin) == nil {
		t.Fatalf("expected illegal below-min %g to be rejected", belowMin)
	}
	if err := hostkit.AttrNumberValue(belowMax); err != nil {
		t.Fatalf("expected legal below-max %g to be accepted, got %v", belowMax, err)
	}
}

func TestSolTablesTokenLayoutReplay(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := solTabHost(f)
	_, _ = h.TableCreate(false, "tab", true)
	for _, sk := range []string{"a", "b"} {
		it, _ := h.ItemNew("pk", sk, true)
		_, _ = h.ItemPut(false, "tab", it, hostkit.PutUnconditional, "")
	}
	page, _ := h.ItemQuery(false, "tab", "pk", "", "", 1, "")
	if page.NextToken == "" {
		t.Fatal("no token")
	}
	_, _ = h.TableDelete(false, "tab")
	_, _ = h.TableCreate(false, "tab", false)
	it, _ := h.ItemNew("pk", "", false)
	_, _ = h.ItemPut(false, "tab", it, hostkit.PutUnconditional, "")
	before := f.Calls()["Query"]
	_, _ = h.ItemQuery(false, "tab", "pk", "", "", 1, page.NextToken)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 || f.Calls()["Query"] != before {
		t.Fatalf("expected sorted-table token reused after recreate as key-only to fail preflight with INVALID_ARGUMENT; last=%+v calls=%d->%d",
			h.LastError(), before, f.Calls()["Query"])
	}
}

func TestSolTablesConditionalPutSemantics(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := solTabHost(f)
	_, _ = h.TableCreate(false, "tab", false)
	it, _ := h.ItemNew("pk", "", false)
	_, _ = it.SetInt("integer", math.MaxInt64)
	_, _ = it.SetNumber("float", 5)
	stored, _ := h.ItemPut(false, "tab", it, hostkit.PutIfAbsent, "")
	if !stored.Exists() || stored.Version() == "" {
		t.Fatal(h.LastError())
	}
	v := stored.Version()
	_, _ = h.ItemPut(false, "tab", it, hostkit.PutIfAbsent, "")
	if h.LastError().Code != hostkit.Conflict {
		t.Fatal(h.LastError())
	}
	_, _ = h.ItemPut(false, "tab", it, hostkit.PutIfVersion, "wrong")
	if h.LastError().Code != hostkit.PreconditionFailed {
		t.Fatal(h.LastError())
	}
	stored, _ = h.ItemPut(false, "tab", it, hostkit.PutIfVersion, v)
	if h.LastError().Code != hostkit.OK || stored.Version() == v {
		t.Fatal(h.LastError())
	}
	if n, _ := stored.GetInt("integer"); n != math.MaxInt64 || stored.TypeOf("float") != "number" {
		t.Fatal("type/int loss")
	}
	_ = h.ItemDelete(false, "tab", "pk", "", false)
	_, _ = h.ItemPut(false, "tab", it, hostkit.PutIfVersion, stored.Version())
	if h.LastError().Code != hostkit.NotFound {
		t.Fatal(h.LastError())
	}
	recreated, _ := h.ItemPut(false, "tab", it, hostkit.PutUnconditional, "")
	if recreated.Version() == v || recreated.Version() == stored.Version() {
		t.Fatal("ABA")
	}
}

func TestSolTablesReservedNamesAndKeysFailBeforeAdapter(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := solTabHost(f)
	for _, name := range []string{"lmcloudmeta", "tables", "ab", "Table", "abc-def"} {
		_, _ = h.TableCreate(false, name, false)
		if h.LastError().Code != hostkit.InvalidArgument {
			t.Fatal(h.LastError())
		}
	}
	for _, pk := range []string{".", "..", "__x__", "雪", "a/b", ""} {
		_, _ = h.ItemGet(false, "tab", pk, "", false)
		if h.LastError().Code != hostkit.InvalidArgument {
			t.Fatal(h.LastError())
		}
	}
	if len(f.Calls()) != 0 {
		t.Fatalf("invalid args reached adapter: %v", f.Calls())
	}
}
