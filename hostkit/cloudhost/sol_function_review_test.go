// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func solFnConfig(t *testing.T, h *Host, code string) *FunctionConfig {
	t.Helper()
	c, e := h.FunctionConfig(hostkit.RuntimePython312, "index.handler")
	if e != nil {
		t.Fatal(e)
	}
	c, e = c.SetInlineCode(code)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

type solFnForeign struct {
	*fakeadapter.Fake
	op   string
	snap hostkit.FunctionSnapshot
}

func (a *solFnForeign) replace(tgt string) error {
	return a.InjectUnmarkedFunctionForTesting(tgt, strings.Repeat("f", 32), a.snap)
}

func (a *solFnForeign) PublishFunctionVersion(ctx context.Context, n, r string) (string, error) {
	if a.op == "publish" {
		if e := a.replace(n); e != nil {
			return "", e
		}
	}
	return a.Fake.PublishFunctionVersion(ctx, n, r)
}

func (a *solFnForeign) SetFunctionAlias(ctx context.Context, n, alias, v string) (bool, error) {
	if a.op == "alias" {
		if e := a.replace(n); e != nil {
			return false, e
		}
		fctx := hostkit.WithCreateToken(ctx, strings.Repeat("f", 32))
		if _, e := a.Fake.PublishFunctionVersion(fctx, n, ""); e != nil {
			return false, e
		}
	}
	return a.Fake.SetFunctionAlias(ctx, n, alias, v)
}

func (a *solFnForeign) DeleteFunctionAlias(ctx context.Context, n, alias string) (bool, error) {
	if a.op == "delete-alias" {
		if e := a.replace(n); e != nil {
			return false, e
		}
		fctx := hostkit.WithCreateToken(ctx, strings.Repeat("f", 32))
		_, _ = a.Fake.PublishFunctionVersion(fctx, n, "")
		_, _ = a.Fake.SetFunctionAlias(fctx, n, alias, "1")
	}
	return a.Fake.DeleteFunctionAlias(ctx, n, alias)
}

func TestSolFnForeignChildMutation(t *testing.T) {
	for _, op := range []string{"publish", "alias", "delete-alias"} {
		t.Run(op, func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			cfg := solFnConfig(t, h, "def handler(e,c): return {}\n")
			_, _ = h.FunctionCreate(false, "solfn", cfg)
			_, _ = h.FunctionPublishVersion(false, "solfn", "", false)
			_ = h.FunctionAliasSet(false, "solfn", "prod", "1")
			snap, _ := f.GetFunction(context.Background(), "solfn", "$LATEST")
			a := &solFnForeign{Fake: f, op: op, snap: snap}
			h = New(Config{Provider: "aws", Functions: a, CampaignStatePath: campaign})
			h.SetAbortOnError(false)
			switch op {
			case "publish":
				_, _ = h.FunctionPublishVersion(false, "solfn", "", false)
			case "alias":
				_ = h.FunctionAliasSet(false, "solfn", "prod", "1")
			case "delete-alias":
				_, _ = h.FunctionAliasDelete(false, "solfn", "prod")
			}
			t.Logf("operation=%s last_error=%+v", op, h.LastError())
			if h.LastError().Code == hostkit.OK {
				t.Fatal("mutated foreign replacement after ownership read")
			}
		})
	}
}

type solFnPublishPause struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *solFnPublishPause) PublishFunctionVersion(ctx context.Context, n, r string) (string, error) {
	close(a.entered)
	<-a.release
	return a.Fake.PublishFunctionVersion(ctx, n, r)
}

func TestSolFnConcurrentPublishReserve(t *testing.T) {
	for _, journalMode := range []bool{false, true} {
		name := "campaign"
		if journalMode {
			name = "journal"
		}
		t.Run(name, func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			base := Config{Provider: "aws", Functions: f, CampaignStatePath: campaign}
			if journalMode {
				_, j, _ := solJournal(t)
				base.Journal = j
				base.CampaignStatePath = ""
				h = New(base)
				h.SetAbortOnError(false)
			}
			cfg := solFnConfig(t, h, "def handler(e,c): return {}\n")
			_, _ = h.FunctionCreate(false, "solfn", cfg)
			a := &solFnPublishPause{Fake: f, entered: make(chan struct{}), release: make(chan struct{})}
			cfgA := base
			cfgA.Functions = a
			ha := New(cfgA)
			ha.SetAbortOnError(false)
			done := make(chan string, 1)
			go func() {
				v, _ := ha.FunctionPublishVersion(false, "solfn", "", false)
				done <- v
			}()
			<-a.entered
			hb := New(base)
			hb.SetAbortOnError(false)
			v1, _ := hb.FunctionPublishVersion(false, "solfn", "", false)
			close(a.release)
			v2 := <-done
			hc := New(base)
			got := hc.cost.meter.Snapshot().ResourceCleanupNanoUSD
			t.Logf("versions=%s,%s cleanup=%d", v1, v2, got)
			if got != 210000 {
				t.Fatalf("two published versions require base150000+2*30000; got %d", got)
			}
		})
	}
}

func TestSolFnSandboxLimits(t *testing.T) {
	h, _, _, _ := newFuncHost(t)
	cfg := solFnConfig(t, h, `import os,resource
def handler(e,c):
 p=os.path.join(os.environ['TMPDIR'],'bounded-probe')
 with open(p,'wb') as f:
  for i in range(17): f.write(b'x'*1048576)
 return {'disk_bytes':os.stat(p).st_size,'nproc':list(resource.getrlimit(resource.RLIMIT_NPROC)),'fsize':list(resource.getrlimit(resource.RLIMIT_FSIZE)),'etc_readable':os.path.isfile('/etc/machine-id') and bool(open('/etc/machine-id').read())}
`)
	_, _ = h.FunctionCreate(false, "solfn", cfg)
	out, _ := h.FunctionInvoke(false, "solfn", "", "{}", false)
	t.Logf("last=%+v result=%s", h.LastError(), out.Payload())
	if h.LastError().Code != hostkit.OK {
		t.Fatal("sandbox unavailable", h.LastError())
	}
	var v map[string]any
	if e := json.Unmarshal([]byte(out.Payload()), &v); e != nil {
		t.Fatal(e)
	}
	if n, ok := v["disk_bytes"].(float64); ok && n > 16*1024*1024 {
		t.Fatal("sandbox can write beyond specified 16 MiB tmpfs bound")
	}
	if etcRead, ok := v["etc_readable"].(bool); ok && etcRead {
		t.Fatal("sandbox exposed /etc/machine-id")
	}
}

func TestSolFnLogTail(t *testing.T) {
	h, _, _, _ := newFuncHost(t)
	cfg := solFnConfig(t, h, "def handler(e,c):\n print('x'*70000)\n print('FINAL-TAIL-MARKER')\n return {}\n")
	_, _ = h.FunctionCreate(false, "solfn", cfg)
	out, _ := h.FunctionInvoke(false, "solfn", "", "{}", false)
	if h.LastError().Code != hostkit.OK {
		t.Fatal(h.LastError())
	}
	if !strings.Contains(out.Logs(), "FINAL-TAIL-MARKER") {
		t.Fatal("returned log tail excludes actual final output after 64 KiB")
	}
}

type solFnShapeRace struct {
	*fakeadapter.Fake
	change     func()
	dispatched bool
	lost       bool
}

func (a *solFnShapeRace) InvokeFunction(ctx context.Context, in hostkit.FunctionInvokeInput) (hostkit.FunctionInvokeOutput, error) {
	a.change()
	a.dispatched = true
	if a.lost {
		return hostkit.FunctionInvokeOutput{}, hostkit.ProviderError(hostkit.Internal, 0, "LostReply", "synthetic execution lost reply")
	}
	return hostkit.FunctionInvokeOutput{
		StatusCode:      200,
		Payload:         `{"errorType":"Timeout"}`,
		FunctionError:   "Timeout",
		TimeoutSeconds:  230,
		MemoryMB:        2048,
		BilledMS:        230000,
		ExecutedVersion: "$LATEST",
	}, nil
}

func TestSolFnShapeAdmissionRace(t *testing.T) {
	for _, lost := range []bool{false, true} {
		name := "complete"
		if lost {
			name = "lost-reply"
		}
		t.Run(name, func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			cfg := solFnConfig(t, h, "def handler(e,c): return {}\n")
			_, _ = cfg.SetTimeoutSeconds(1)
			_, _ = h.FunctionCreate(false, "solfn", cfg)
			b := New(Config{Provider: "aws", Functions: f, CampaignStatePath: campaign})
			b.SetAbortOnError(false)
			a := &solFnShapeRace{Fake: f, lost: lost}
			a.change = func() {
				c := solFnConfig(t, b, "def handler(e,c): return {}\n")
				_, _ = c.SetTimeoutSeconds(230)
				_, _ = c.SetMemoryMB(2048)
				_, _ = b.FunctionUpdate(false, "solfn", c, "", false)
				if b.LastError().Code != hostkit.OK {
					t.Fatal(b.LastError())
				}
			}
			caller := New(Config{Provider: "aws", Functions: a, CampaignStatePath: campaign})
			caller.SetAbortOnError(false)
			_ = caller.SetCostCapUSD(0.0005)
			_, _ = caller.FunctionInvoke(false, "solfn", "", "{}", false)
			t.Logf("dispatched=%v last=%+v estimated_usd=%.9f new_shape_worst_nano=7360200 work_cap_nano=500000",
				a.dispatched, caller.LastError(), caller.EstimatedCost())
			if a.dispatched {
				t.Fatal("un-pinned old quota admitted execution of a new shape beyond the work cap")
			}
		})
	}
}

func TestSolFnNodeLargePayload(t *testing.T) {
	h, _, _, _ := newFuncHost(t)
	c, _ := h.FunctionConfig(hostkit.RuntimeNodeJS20x, "index.handler")
	c, _ = c.SetInlineCode("exports.handler = async (event) => ({n:event.s.length});\n")
	_, _ = h.FunctionCreate(false, "solfn", c)
	payload := `{"s":"` + strings.Repeat("x", 200000) + `"}`
	out, _ := h.FunctionInvoke(false, "solfn", "", payload, false)
	t.Logf("last=%+v function_error=%s payload=%s", h.LastError(), out.FunctionError(), out.Payload())
	if h.LastError().Code != hostkit.OK || out.IsError() || !strings.Contains(out.Payload(), "200000") {
		t.Fatal("valid sub-1MiB Node payload did not execute")
	}
}

func TestSolFnDryExistingAlias(t *testing.T) {
	h, f, _, campaign := newFuncHost(t)
	c := solFnConfig(t, h, "def handler(e,c): return {}\n")
	_, _ = h.FunctionCreate(false, "solfn", c)
	_, _ = h.FunctionPublishVersion(false, "solfn", "", false)
	_ = h.FunctionAliasSet(false, "solfn", "prod", "1")
	h = New(Config{Provider: "aws", Functions: f, CampaignStatePath: campaign})
	h.SetAbortOnError(false)
	before := f.Calls()
	alias, _ := h.FunctionAliasGet(true, "solfn", "prod")
	out, _ := h.FunctionInvoke(true, "solfn", "prod", "{}", true)
	t.Logf("alias=%q invoke_error=%+v version=%q GetFunction_delta=%d",
		alias, h.LastError(), out.ExecutedVersion(), f.Calls()["GetFunction"]-before["GetFunction"])
	if alias != "1" || h.LastError().Code != hostkit.OK || out.ExecutedVersion() != "1" {
		t.Fatal("existing alias missing from dry preview")
	}
}

func TestSolFnLivePreflightAll(t *testing.T) {
	live := fakeadapter.New(fakeadapter.Options{})
	routes := hostkit.EndpointRoutes{Live: live}
	router := &hostkit.Router{Pick: routes.Pick}
	h := New(Config{Provider: "aws", Store: router, Functions: router})
	h.SetAbortOnError(false)
	c := solFnConfig(t, h, "def handler(e,c): return {}\n")
	calls := []func(){
		func() { _, _ = h.FunctionCreate(false, "solfn", c) },
		func() { _, _ = h.FunctionUpdate(false, "solfn", c, "", false) },
		func() { _, _ = h.FunctionDelete(false, "solfn") },
		func() { _, _ = h.FunctionExists(false, "solfn") },
		func() { _, _ = h.FunctionGet(false, "solfn", "", false) },
		func() { _, _ = h.FunctionList(false) },
		func() { _, _ = h.FunctionPublishVersion(false, "solfn", "", false) },
		func() { _, _ = h.FunctionVersions(false, "solfn") },
		func() { _ = h.FunctionAliasSet(false, "solfn", "prod", "1") },
		func() { _, _ = h.FunctionAliasGet(false, "solfn", "prod") },
		func() { _, _ = h.FunctionAliasDelete(false, "solfn", "prod") },
		func() { _, _ = h.FunctionInvoke(false, "solfn", "", "{}", false) },
	}
	for i, call := range calls {
		call()
		if h.LastError().Code != hostkit.PermissionDenied {
			t.Fatalf("op %d not refused: %+v", i, h.LastError())
		}
	}
	if len(live.Calls()) != 0 {
		t.Fatal("live adapter touched", live.Calls())
	}
	offline := fakeadapter.New(fakeadapter.Options{})
	h = New(Config{Provider: "aws", Store: router, Functions: offline})
	h.SetAbortOnError(false)
	c, _ = h.FunctionConfig(hostkit.RuntimePython312, "index.handler")
	c, _ = c.SetPackageObject("sol-bucket", "index.py")
	_, _ = h.FunctionCreate(false, "solfn", c)
	if h.LastError().Code != hostkit.PermissionDenied || len(live.Calls()) != 0 || offline.Calls()["CreateFunction"] != 0 {
		t.Fatal("package staging touched live route", h.LastError(), live.Calls(), offline.Calls())
	}
}

// TestSolFnInvokePinnedTargetRace verifies that when an unwrapped Fake adapter resolves
// and pins an execution target (either $LATEST or an alias) for cost admission, any concurrent
// update to $LATEST or retargeting of the alias before InvokeFunction acquires the atomic
// state lock is rejected with 409 CONFLICT (ConcurrentTargetModification) before execution.
func TestSolFnInvokePinnedTargetRace(t *testing.T) {
	for _, targetKind := range []string{"latest", "alias"} {
		t.Run(targetKind, func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			cfg1 := solFnConfig(t, h, "def handler(e,c): return {'v':1}\n")
			_, _ = cfg1.SetTimeoutSeconds(1)
			_, _ = cfg1.SetMemoryMB(128)
			_, _ = h.FunctionCreate(false, "pinracefn", cfg1)
			v1, _ := h.FunctionPublishVersion(false, "pinracefn", "", false)

			cfg2 := solFnConfig(t, h, "def handler(e,c): return {'v':2}\n")
			_, _ = cfg2.SetTimeoutSeconds(230)
			_, _ = cfg2.SetMemoryMB(2048)
			if targetKind == "alias" {
				_, _ = h.FunctionUpdate(false, "pinracefn", cfg2, "", false)
				v2, _ := h.FunctionPublishVersion(false, "pinracefn", "", false)
				_ = h.FunctionAliasSet(false, "pinracefn", "prod", v1)
				peer := New(Config{Provider: "aws", Functions: f, CampaignStatePath: campaign})
				peer.SetAbortOnError(false)
				f.SetBeforeInvokeLockForTesting(func() {
					_ = peer.FunctionAliasSet(false, "pinracefn", "prod", v2)
				})
				defer f.SetBeforeInvokeLockForTesting(nil)
				_, _ = h.FunctionInvoke(false, "pinracefn", "prod", "{}", true)
			} else {
				peer := New(Config{Provider: "aws", Functions: f, CampaignStatePath: campaign})
				peer.SetAbortOnError(false)
				f.SetBeforeInvokeLockForTesting(func() {
					_, _ = peer.FunctionUpdate(false, "pinracefn", cfg2, "", false)
				})
				defer f.SetBeforeInvokeLockForTesting(nil)
				_, _ = h.FunctionInvoke(false, "pinracefn", "", "{}", false)
			}
			if h.LastError().Code != hostkit.Conflict || h.LastError().HTTPStatus != 409 {
				t.Fatalf("expected 409 CONFLICT on concurrent target modification before lock, got %+v", h.LastError())
			}
		})
	}
}

// TestSolFnChildMutationFenceAcrossRecreate verifies that delayed child mutations
// (publish, alias, delete-alias) paused after checkOwnershipInScope cannot mutate a
// subsequently deleted and recreated incarnation of the same function in either
// campaign_journal or safety_journal.
func TestSolFnChildMutationFenceAcrossRecreate(t *testing.T) {
	for _, journalMode := range []bool{false, true} {
		mode := "campaign_journal"
		if journalMode {
			mode = "safety_journal"
		}
		t.Run(mode, func(t *testing.T) {
			for _, op := range []string{"publish", "alias", "delete-alias"} {
				t.Run(op, func(t *testing.T) {
					dir := t.TempDir()
					statePath := filepath.Join(dir, "fake.json")
					campaignPath := filepath.Join(dir, "campaign.jsonl")
					f := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
					base := Config{Provider: "aws", Functions: f, CampaignStatePath: campaignPath}
					if journalMode {
						_, j, _ := solJournal(t)
						base.Journal = j
						base.CampaignStatePath = ""
					}
					h := New(base)
					h.SetAbortOnError(false)
					cfg := solFnConfig(t, h, "def handler(e,c): return {'gen':1}\n")
					_, _ = h.FunctionCreate(false, "fencefn", cfg)
					_, _ = h.FunctionPublishVersion(false, "fencefn", "", false)
					_ = h.FunctionAliasSet(false, "fencefn", "prod", "1")

					entered := make(chan struct{})
					release := make(chan struct{})
					pauseAdapter := &solFnChildFencePause{
						Fake:    f,
						op:      op,
						entered: entered,
						release: release,
					}
					cfgSlow := base
					cfgSlow.Functions = pauseAdapter
					hSlow := New(cfgSlow)
					hSlow.SetAbortOnError(false)

					done := make(chan struct{})
					go func() {
						defer close(done)
						switch op {
						case "publish":
							_, _ = hSlow.FunctionPublishVersion(false, "fencefn", "", false)
						case "alias":
							_ = hSlow.FunctionAliasSet(false, "fencefn", "prod", "1")
						case "delete-alias":
							_, _ = hSlow.FunctionAliasDelete(false, "fencefn", "prod")
						}
					}()
					<-entered

					// Delete and recreate fencefn on a peer host before releasing the delayed child mutation.
					hPeer := New(base)
					hPeer.SetAbortOnError(false)
					if deleted, err := hPeer.FunctionDelete(false, "fencefn"); !deleted || err != nil {
						t.Fatalf("FunctionDelete: deleted=%v err=%v (%+v)", deleted, err, hPeer.LastError())
					}
					cfg2 := solFnConfig(t, hPeer, "def handler(e,c): return {'gen':2}\n")
					if created, err := hPeer.FunctionCreate(false, "fencefn", cfg2); !created || err != nil {
						t.Fatalf("FunctionCreate recreate: created=%v err=%v (%+v)", created, err, hPeer.LastError())
					}
					_, _ = hPeer.FunctionPublishVersion(false, "fencefn", "", false)
					_ = hPeer.FunctionAliasSet(false, "fencefn", "prod", "1")

					close(release)
					<-done

					if hSlow.LastError().Code == hostkit.OK {
						t.Fatalf("delayed %sfrom old incarnation succeeded against recreated function", op)
					}
				})
			}
		})
	}
}

type solFnChildFencePause struct {
	*fakeadapter.Fake
	op               string
	entered, release chan struct{}
}

func (a *solFnChildFencePause) PublishFunctionVersion(ctx context.Context, n, r string) (string, error) {
	if a.op == "publish" {
		close(a.entered)
		<-a.release
	}
	return a.Fake.PublishFunctionVersion(ctx, n, r)
}

func (a *solFnChildFencePause) SetFunctionAlias(ctx context.Context, n, alias, v string) (bool, error) {
	if a.op == "alias" {
		close(a.entered)
		<-a.release
	}
	return a.Fake.SetFunctionAlias(ctx, n, alias, v)
}

func (a *solFnChildFencePause) DeleteFunctionAlias(ctx context.Context, n, alias string) (bool, error) {
	if a.op == "delete-alias" {
		close(a.entered)
		<-a.release
	}
	return a.Fake.DeleteFunctionAlias(ctx, n, alias)
}

// TestSolFnConcurrentPublishCrashReopenAndDelete verifies that concurrent version publishes
// preserve 150,000 + 2*30,000 = 210,000 nano-USD cleanup reserve across crash/reopen and
// journal compaction in both campaign_journal and safety_journal, and that FunctionDelete
// releases all 210,000 nano-USD back to 0.
func TestSolFnConcurrentPublishCrashReopenAndDelete(t *testing.T) {
	for _, useSafetyJournal := range []bool{false, true} {
		mode := "campaign_journal"
		if useSafetyJournal {
			mode = "safety_journal"
		}
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			statePath := filepath.Join(dir, "fake.json")
			campaignPath := filepath.Join(dir, "campaign.jsonl")
			journalDir := filepath.Join(dir, "sj")
			f := fakeadapter.New(fakeadapter.Options{StatePath: statePath})

			var j *safety.Journal
			var err error
			if useSafetyJournal {
				j, err = safety.OpenJournal(journalDir, safety.JournalMeta{
					RunID:      "run-1700000000-abcdef012345",
					Provider:   "aws",
					Account:    "000000000000",
					Scope:      "000000000000",
					Region:     "us-east-1",
					Endpoint:   "http://127.0.0.1:4566",
					PolicyHash: strings.Repeat("a", 64),
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			base := Config{
				Provider:          "aws",
				Functions:         f,
				CampaignStatePath: campaignPath,
				Journal:           j,
			}
			if useSafetyJournal {
				base.CampaignStatePath = ""
			}

			h := New(base)
			h.SetAbortOnError(false)
			cfg := solFnConfig(t, h, "def handler(e,c): return {}\n")
			_, _ = h.FunctionCreate(false, "solfn", cfg)

			a := &solFnPublishPause{Fake: f, entered: make(chan struct{}), release: make(chan struct{})}
			cfgA := base
			cfgA.Functions = a
			ha := New(cfgA)
			ha.SetAbortOnError(false)
			done := make(chan string, 1)
			go func() {
				v, _ := ha.FunctionPublishVersion(false, "solfn", "", false)
				done <- v
			}()
			<-a.entered
			hb := New(base)
			hb.SetAbortOnError(false)
			_, _ = hb.FunctionPublishVersion(false, "solfn", "", false)
			close(a.release)
			<-done

			if useSafetyJournal {
				if err := j.Compact(); err != nil {
					t.Fatal(err)
				}
				_ = j.Close()
				j, err = safety.OpenJournal(journalDir, safety.JournalMeta{
					RunID:      "run-1700000000-abcdef012345",
					Provider:   "aws",
					Account:    "000000000000",
					Scope:      "000000000000",
					Region:     "us-east-1",
					Endpoint:   "http://127.0.0.1:4566",
					PolicyHash: strings.Repeat("a", 64),
				})
				if err != nil {
					t.Fatal(err)
				}
				defer j.Close()
				base.Journal = j
			}

			hReopen := New(base)
			hReopen.SetAbortOnError(false)
			if got := hReopen.cost.meter.Snapshot().ResourceCleanupNanoUSD; got != 210000 {
				t.Fatalf("after crash/reopen expected cleanup reserve 210000, got %d", got)
			}
			_ = hReopen.SetCostCapUSD(hReopen.EstimatedCost())
			if deleted, err := hReopen.FunctionDelete(false, "solfn"); !deleted || err != nil || hReopen.LastError().Code != hostkit.OK {
				t.Fatalf("FunctionDelete under exhausted work cap after reopen failed: deleted=%v err=%v (%+v)", deleted, err, hReopen.LastError())
			}
			if gotAfter := hReopen.cost.meter.Snapshot().ResourceCleanupNanoUSD; gotAfter != 0 {
				t.Fatalf("after FunctionDelete expected cleanup reserve 0, got %d", gotAfter)
			}
		})
	}
}
