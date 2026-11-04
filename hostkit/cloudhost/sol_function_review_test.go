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

func TestSolR2FnUnlinkedScratchQuota(t *testing.T) {
	h, _, _, _ := newFuncHost(t)
	cfg := solFnConfig(t, h, `import os
def handler(e,c):
 files=[]
 try:
  for i in range(2):
   p=os.path.join(os.environ['TMPDIR'],'bounded'+str(i))
   fd=os.open(p,os.O_RDWR|os.O_CREAT,0o600)
   os.unlink(p)
   files.append(fd)
   for j in range(12): os.write(fd,b'x'*1048576)
   os.fsync(fd)
  return {'open_bytes':sum(os.fstat(fd).st_size for fd in files),'visible_names':os.listdir(os.environ['TMPDIR'])}
 finally:
  for fd in files: os.close(fd)
`)
	_, _ = h.FunctionCreate(false, "quotaunlinked", cfg)
	out, _ := h.FunctionInvoke(false, "quotaunlinked", "", "{}", false)
	t.Logf("last=%+v function_error=%s payload=%s", h.LastError(), out.FunctionError(), out.Payload())
	if h.LastError().Code != hostkit.OK {
		t.Fatal(h.LastError())
	}
	var v map[string]any
	_ = json.Unmarshal([]byte(out.Payload()), &v)
	if n, ok := v["open_bytes"].(float64); ok && n > 16*1024*1024 {
		t.Fatal("unlinked open files bypass aggregate 16 MiB sandbox quota")
	}
	if out.FunctionError() == "" {
		t.Fatalf("expected non-empty FunctionError when writing 24 MiB to unlinked open files, got payload=%s", out.Payload())
	}
}

func TestSolR2FnUnlinkedScratchQuotaNodeJS(t *testing.T) {
	h, _, _, _ := newFuncHost(t)
	cfg, err := h.FunctionConfig("nodejs20.x", "index.handler")
	if err != nil {
		t.Fatal(err)
	}
	jsCode := `const fs = require("fs");
const path = require("path");
exports.handler = async () => {
  const td = process.env.TMPDIR || "/tmp";
  const chunk = Buffer.alloc(1024 * 1024, 0x78);
  const fds = [];
  try {
    for (let idx = 0; idx < 2; idx++) {
      const p = path.join(td, "unlinked-js-" + idx + ".bin");
      const fd = fs.openSync(p, "w+");
      fs.unlinkSync(p);
      fds.push(fd);
      for (let i = 0; i < 12; i++) {
        fs.writeSync(fd, chunk);
      }
      fs.fsyncSync(fd);
    }
    return { open_bytes: 24 * 1024 * 1024 };
  } finally {
    for (const fd of fds) {
      try { fs.closeSync(fd); } catch (_) {}
    }
  }
};
`
	if _, err := cfg.SetInlineCode(jsCode); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.SetTimeoutSeconds(5); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.SetMemoryMB(128); err != nil {
		t.Fatal(err)
	}
	_, _ = h.FunctionCreate(false, "quotaunlinkedjs", cfg)
	out, _ := h.FunctionInvoke(false, "quotaunlinkedjs", "", "{}", false)
	t.Logf("last=%+v function_error=%s payload=%s", h.LastError(), out.FunctionError(), out.Payload())
	if h.LastError().Code != hostkit.OK {
		t.Fatal(h.LastError())
	}
	if out.FunctionError() == "" {
		t.Fatalf("expected non-empty FunctionError for nodejs20.x writing 24 MiB to unlinked open files, got payload=%s", out.Payload())
	}
}

func TestSolR2FnRefusedUpdatePoisonsChildren(t *testing.T) {
	for _, journalMode := range []bool{false, true} {
		mode := "campaign"
		if journalMode {
			mode = "journal"
		}
		t.Run(mode, func(t *testing.T) {
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
			_, _ = h.FunctionCreate(false, "refusedfn", cfg)
			_, _ = h.FunctionPublishVersion(false, "refusedfn", "", false)
			_ = h.FunctionAliasSet(false, "refusedfn", "prod", "1")
			_, _ = h.FunctionUpdate(false, "refusedfn", cfg, strings.Repeat("0", 32), true)
			if h.LastError().Code != hostkit.PreconditionFailed {
				t.Fatal("wrong revision was not refused", h.LastError())
			}
			h = New(base)
			h.SetAbortOnError(false)
			for _, op := range []string{"publish", "alias", "delete-alias"} {
				switch op {
				case "publish":
					_, _ = h.FunctionPublishVersion(false, "refusedfn", "", false)
				case "alias":
					_ = h.FunctionAliasSet(false, "refusedfn", "prod", "1")
				case "delete-alias":
					_, _ = h.FunctionAliasDelete(false, "refusedfn", "prod")
				}
				t.Logf("%s last=%+v", op, h.LastError())
				if h.LastError().Code != hostkit.OK {
					t.Errorf("refused update permanently fenced normal %s", op)
				}
			}
		})
	}
}

type solR2Foreign struct {
	*fakeadapter.Fake
	snap hostkit.FunctionSnapshot
	op   string
}

func (a *solR2Foreign) swap(n string) error {
	if e := a.InjectUnmarkedFunctionForTesting(n, strings.Repeat("f", 32), a.snap); e != nil {
		return e
	}
	ctx := hostkit.WithCreateToken(context.Background(), strings.Repeat("f", 32))
	if _, e := a.Fake.PublishFunctionVersion(ctx, n, ""); e != nil {
		return e
	}
	_, e := a.Fake.SetFunctionAlias(ctx, n, "prod", "1")
	return e
}

func (a *solR2Foreign) SetFunctionAlias(ctx context.Context, n, k, v string) (bool, error) {
	if a.op == "alias" {
		if e := a.swap(n); e != nil {
			return false, e
		}
	}
	return a.Fake.SetFunctionAlias(ctx, n, k, v)
}

func (a *solR2Foreign) DeleteFunctionAlias(ctx context.Context, n, k string) (bool, error) {
	if a.op == "delete-alias" {
		if e := a.swap(n); e != nil {
			return false, e
		}
	}
	return a.Fake.DeleteFunctionAlias(ctx, n, k)
}

func TestSolR2FnForeignWriteFixture(t *testing.T) {
	for _, op := range []string{"alias", "delete-alias"} {
		t.Run(op, func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			cfg := solFnConfig(t, h, "def handler(e,c): return {}\n")
			_, _ = h.FunctionCreate(false, "foreignfn", cfg)
			_, _ = h.FunctionPublishVersion(false, "foreignfn", "", false)
			_ = h.FunctionAliasSet(false, "foreignfn", "prod", "1")
			snap, _ := f.GetFunction(context.Background(), "foreignfn", "$LATEST")
			h = New(Config{Provider: "aws", Functions: &solR2Foreign{Fake: f, snap: snap, op: op}, CampaignStatePath: campaign})
			h.SetAbortOnError(false)
			if op == "alias" {
				_ = h.FunctionAliasSet(false, "foreignfn", "prod", "1")
			} else {
				_, _ = h.FunctionAliasDelete(false, "foreignfn", "prod")
			}
			if h.LastError().Code != hostkit.PermissionDenied {
				t.Fatal("expected adapter lock owner refusal", h.LastError())
			}
			ctx := context.Background()
			alias, e := f.GetFunctionAlias(ctx, "foreignfn", "prod")
			if e != nil || alias != "1" {
				t.Fatal("foreign alias changed", alias, e)
			}
		})
	}
}

func TestSolR2FnPinnedSameShapeAndAppearance(t *testing.T) {
	for _, mode := range []string{"alias-same-quota", "appearing-target"} {
		t.Run(mode, func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			cfg := solFnConfig(t, h, "def handler(e,c): return {'v':1}\n")
			peer := New(Config{Provider: "aws", Functions: f, CampaignStatePath: campaign})
			peer.SetAbortOnError(false)
			qualifier := ""
			qualified := false
			if mode == "alias-same-quota" {
				_, _ = h.FunctionCreate(false, "pinnewfn", cfg)
				_, _ = h.FunctionPublishVersion(false, "pinnewfn", "", false)
				other := solFnConfig(t, h, "def handler(e,c): return {'v':2}\n")
				_, _ = h.FunctionUpdate(false, "pinnewfn", other, "", false)
				_, _ = h.FunctionPublishVersion(false, "pinnewfn", "", false)
				_ = h.FunctionAliasSet(false, "pinnewfn", "prod", "1")
				qualifier = "prod"
				qualified = true
			}
			dispatched := false
			f.SetFaultInvokeAfterDispatchForTesting(func() error {
				dispatched = true
				return nil
			})
			f.SetBeforeInvokeLockForTesting(func() {
				if mode == "alias-same-quota" {
					_ = peer.FunctionAliasSet(false, "pinnewfn", "prod", "2")
				} else {
					_, _ = peer.FunctionCreate(false, "pinnewfn", cfg)
				}
				if peer.LastError().Code != hostkit.OK {
					t.Fatal(peer.LastError())
				}
			})
			defer f.SetBeforeInvokeLockForTesting(nil)
			_, _ = h.FunctionInvoke(false, "pinnewfn", qualifier, "{}", qualified)
			t.Logf("mode=%s last=%+v dispatched=%v", mode, h.LastError(), dispatched)
			if h.LastError().Code != hostkit.Conflict || h.LastError().ProviderCode != "ConcurrentTargetModification" || dispatched {
				t.Fatal("pin race was not refused before execution", h.LastError())
			}
		})
	}
}

type solR2FunctionsOnly struct {
	hostkit.Functions
}

func TestSolR2FnDryNoPinnerIO(t *testing.T) {
	h, f, _, campaign := newFuncHost(t)
	c := solFnConfig(t, h, "def handler(e,c): return {}\n")
	_, _ = h.FunctionCreate(false, "drynopin", c)
	_, _ = h.FunctionPublishVersion(false, "drynopin", "", false)
	_ = h.FunctionAliasSet(false, "drynopin", "prod", "1")
	h = New(Config{Provider: "aws", Functions: solR2FunctionsOnly{Functions: f}, CampaignStatePath: campaign})
	h.SetAbortOnError(false)
	before := f.Calls()
	out, _ := h.FunctionInvoke(true, "drynopin", "prod", "{}", true)
	after := f.Calls()
	reads := after["GetFunction"] - before["GetFunction"] + after["ListFunctionVersions"] - before["ListFunctionVersions"] + after["GetFunctionAlias"] - before["GetFunctionAlias"]
	t.Logf("last=%+v adapter_reads=%d mutators=%d", h.LastError(), reads, f.MutatorCalls())
	if h.LastError().Code != hostkit.OK || out.ExecutedVersion() != "1" {
		t.Fatalf("dry invoke failed: last=%+v ver=%q", h.LastError(), out.ExecutedVersion())
	}
	if reads != 0 {
		t.Fatal("dry invocation made adapter reads without optional pinner")
	}
}

func TestSolR2FnDryNoPinnerIOSafetyJournal(t *testing.T) {
	_, f, _, _ := newFuncHost(t)
	journalDir := filepath.Join(t.TempDir(), "sj")
	j, err := safety.OpenJournal(journalDir, safety.JournalMeta{
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
	h := New(Config{Provider: "aws", Functions: solR2FunctionsOnly{Functions: f}, Journal: j})
	h.SetAbortOnError(false)
	c := solFnConfig(t, h, "def handler(e,c): return {}\n")
	_, _ = h.FunctionCreate(false, "drynopinsj", c)
	_, _ = h.FunctionPublishVersion(false, "drynopinsj", "", false)
	_ = h.FunctionAliasSet(false, "drynopinsj", "prod", "1")
	if err := j.Compact(); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	j2, err := safety.OpenJournal(journalDir, safety.JournalMeta{
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
	defer j2.Close()
	h2 := New(Config{Provider: "aws", Functions: solR2FunctionsOnly{Functions: f}, Journal: j2})
	h2.SetAbortOnError(false)
	before := f.Calls()
	out, _ := h2.FunctionInvoke(true, "drynopinsj", "prod", "{}", true)
	after := f.Calls()
	reads := after["GetFunction"] - before["GetFunction"] + after["ListFunctionVersions"] - before["ListFunctionVersions"] + after["GetFunctionAlias"] - before["GetFunctionAlias"]
	if h2.LastError().Code != hostkit.OK || out.ExecutedVersion() != "1" {
		t.Fatalf("dry invoke failed: last=%+v ver=%q", h2.LastError(), out.ExecutedVersion())
	}
	if reads != 0 {
		t.Fatalf("dry invocation made %d adapter reads without optional pinner", reads)
	}
}

func TestSolR3FnMappedUnlinkedQuota(t *testing.T) {
	h, _, _, _ := newFuncHost(t)
	cfg := solFnConfig(t, h, `import os,ctypes
def handler(e,c):
 lib=ctypes.CDLL(None,use_errno=True)
 lib.mmap.restype=ctypes.c_void_p
 lib.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
 lib.munmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t]
 n=12*1024*1024
 maps=[]
 try:
  for i in range(2):
   p=os.path.join(os.environ['TMPDIR'],'mapped'+str(i))
   fd=os.open(p,os.O_RDWR|os.O_CREAT,0o600)
   os.unlink(p)
   try:
    os.ftruncate(fd,n)
    addr=lib.mmap(None,n,3,1,fd,0)
    if addr==ctypes.c_void_p(-1).value: raise OSError(ctypes.get_errno(),'mmap')
    maps.append(addr)
   finally: os.close(fd)
   ctypes.memset(addr,120,n)
  return {'mapped_bytes':n*len(maps),'visible_names':os.listdir(os.environ['TMPDIR'])}
 finally:
  for addr in maps: lib.munmap(addr,n)
`)
	h.FunctionCreate(false, "mappedquota", cfg)
	out, _ := h.FunctionInvoke(false, "mappedquota", "", "{}", false)
	t.Logf("last=%+v function_error=%s payload=%s", h.LastError(), out.FunctionError(), out.Payload())
	if h.LastError().Code != hostkit.OK {
		t.Fatal(h.LastError())
	}
	var v map[string]any
	_ = json.Unmarshal([]byte(out.Payload()), &v)
	if n, ok := v["mapped_bytes"].(float64); ok && n > 16*1024*1024 {
		t.Fatal("mmap retains 24 MiB of unlinked scratch inodes after all descriptors close; aggregate quota bypassed")
	}
}

type solR3LatePublish struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *solR3LatePublish) PublishFunctionVersion(ctx context.Context, n, r string) (string, error) {
	v, e := a.Fake.PublishFunctionVersion(ctx, n, r)
	if e == nil {
		close(a.entered)
		<-a.release
	}
	return v, e
}

type solR3LateAlias struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *solR3LateAlias) SetFunctionAlias(ctx context.Context, n, alias, ver string) (bool, error) {
	c, e := a.Fake.SetFunctionAlias(ctx, n, alias, ver)
	if e == nil {
		close(a.entered)
		<-a.release
	}
	return c, e
}

func TestSolR3FnDryCacheMustNotConfirmAmbiguity(t *testing.T) {
	for _, journalMode := range []bool{false, true} {
		mode := "campaign"
		if journalMode {
			mode = "journal"
		}
		t.Run(mode, func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			base := Config{Provider: "aws", Functions: f, CampaignStatePath: campaign}
			var j *safety.Journal
			if journalMode {
				_, j, _ = solJournal(t)
				base.Journal = j
				base.CampaignStatePath = ""
				h = New(base)
				h.SetAbortOnError(false)
			}
			c := solFnConfig(t, h, "def handler(e,c): return {'v':1}\n")
			h.FunctionCreate(false, "cacheambfn", c)
			slow := &solR3LatePublish{Fake: f, entered: make(chan struct{}), release: make(chan struct{})}
			aCfg := base
			aCfg.Functions = slow
			a := New(aCfg)
			a.SetAbortOnError(false)
			done := make(chan struct{})
			go func() {
				defer close(done)
				a.FunctionPublishVersion(false, "cacheambfn", "", false)
			}()
			<-slow.entered

			b := New(base)
			b.SetAbortOnError(false)
			f.SetFaultMutatorAfterCommitForTesting(func(op string) error {
				if op == "UpdateFunction" {
					return hostkit.ProviderError(hostkit.Internal, 0, "LostReply", "synthetic update applied but reply lost")
				}
				return nil
			})
			c2 := solFnConfig(t, b, "def handler(e,c): return {'v':2}\n")
			b.FunctionUpdate(false, "cacheambfn", c2, "", false)
			f.SetFaultMutatorAfterCommitForTesting(nil)

			_, _, before, beforeHas, e := b.cost.lookupFunctionEntry("", "cacheambfn")
			if e != nil || !beforeHas || before.IntentOp != "update" {
				close(slow.release)
				<-done
				t.Fatal("fixture must retain uncertain update", b.LastError(), beforeHas, before, e)
			}
			close(slow.release)
			<-done

			if journalMode {
				jDir := filepath.Dir(j.Path())
				jMeta := j.State().Meta
				if err := j.Compact(); err != nil {
					t.Fatalf("Compact: %v", err)
				}
				if err := j.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				reopened, err := safety.OpenJournal(jDir, jMeta)
				if err != nil {
					t.Fatalf("Reopen: %v", err)
				}
				t.Cleanup(func() { _ = reopened.Close() })
				base.Journal = reopened
			}

			replay := New(base)
			_, _, after, afterHas, e := replay.cost.lookupFunctionEntry("", "cacheambfn")
			t.Logf("publish_last=%+v update_last=%+v ambiguity_before=%v ambiguity_after=%v remaining=%+v", a.LastError(), b.LastError(), beforeHas, afterHas, after)
			if e != nil {
				t.Fatal(e)
			}
			if !afterHas || after.IntentOp != "update" {
				t.Fatal("older publish's dry-cache write confirmed the unrelated uncertain update")
			}
		})
	}
}

func TestSolR3FnDryCacheDelayedAliasAcrossUncertainDeleteAndRecreate(t *testing.T) {
	for _, journalMode := range []bool{false, true} {
		mode := "campaign"
		if journalMode {
			mode = "journal"
		}
		t.Run(mode, func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			base := Config{Provider: "aws", Functions: f, CampaignStatePath: campaign}
			var j *safety.Journal
			if journalMode {
				_, j, _ = solJournal(t)
				base.Journal = j
				base.CampaignStatePath = ""
				h = New(base)
				h.SetAbortOnError(false)
			}
			c := solFnConfig(t, h, "def handler(e,c): return {'v':1}\n")
			h.FunctionCreate(false, "cachealiasfn", c)
			ver, _ := h.FunctionPublishVersion(false, "cachealiasfn", "", false)
			if ver != "1" {
				t.Fatalf("publish ver=%q err=%+v", ver, h.LastError())
			}

			// Start delayed alias_set on generation 1, then trigger an uncertain delete.
			slow := &solR3LateAlias{Fake: f, entered: make(chan struct{}), release: make(chan struct{})}
			aCfg := base
			aCfg.Functions = slow
			a := New(aCfg)
			a.SetAbortOnError(false)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = a.FunctionAliasSet(false, "cachealiasfn", "prod", "1")
			}()
			<-slow.entered

			b := New(base)
			b.SetAbortOnError(false)
			f.SetFaultMutatorAfterCommitForTesting(func(op string) error {
				if op == "DeleteFunction" {
					return hostkit.ProviderError(hostkit.Internal, 0, "LostReply", "synthetic delete applied but reply lost")
				}
				return nil
			})
			_, _ = b.FunctionDelete(false, "cachealiasfn")
			f.SetFaultMutatorAfterCommitForTesting(nil)

			close(slow.release)
			<-done

			if journalMode {
				jDir := filepath.Dir(j.Path())
				jMeta := j.State().Meta
				if err := j.Compact(); err != nil {
					t.Fatalf("Compact: %v", err)
				}
				if err := j.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				reopened, err := safety.OpenJournal(jDir, jMeta)
				if err != nil {
					t.Fatalf("Reopen: %v", err)
				}
				t.Cleanup(func() { _ = reopened.Close() })
				base.Journal = reopened
			}

			replay := New(base)
			_, _, after, afterHas, e := replay.cost.lookupFunctionEntry("", "cachealiasfn")
			if e != nil || !afterHas || after.IntentOp != "delete" {
				t.Fatalf("delayed alias_set cleared uncertain delete: err=%v afterHas=%v after=%+v", e, afterHas, after)
			}
		})
		t.Run(mode+"_delete_recreate", func(t *testing.T) {
			h, f, _, campaign := newFuncHost(t)
			base := Config{Provider: "aws", Functions: f, CampaignStatePath: campaign}
			var j *safety.Journal
			if journalMode {
				_, j, _ = solJournal(t)
				base.Journal = j
				base.CampaignStatePath = ""
				h = New(base)
				h.SetAbortOnError(false)
			}
			c1 := solFnConfig(t, h, "def handler(e,c): return {'v':1}\n")
			c1.SetTimeoutSeconds(3)
			c1.SetMemoryMB(128)
			h.FunctionCreate(false, "cacherecreatefn", c1)

			slow := &solR3LatePublish{Fake: f, entered: make(chan struct{}), release: make(chan struct{})}
			aCfg := base
			aCfg.Functions = slow
			a := New(aCfg)
			a.SetAbortOnError(false)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, _ = a.FunctionPublishVersion(false, "cacherecreatefn", "", false)
			}()
			<-slow.entered

			b := New(base)
			b.SetAbortOnError(false)
			_, _ = b.FunctionDelete(false, "cacherecreatefn")
			c2 := solFnConfig(t, b, "def handler(e,c): return {'v':2}\n")
			c2.SetTimeoutSeconds(9)
			c2.SetMemoryMB(256)
			b.FunctionCreate(false, "cacherecreatefn", c2)
			if b.LastError().Code != hostkit.OK {
				close(slow.release)
				<-done
				t.Fatalf("delete+recreate failed: %+v", b.LastError())
			}

			close(slow.release)
			<-done

			if journalMode {
				jDir := filepath.Dir(j.Path())
				jMeta := j.State().Meta
				if err := j.Compact(); err != nil {
					t.Fatalf("Compact: %v", err)
				}
				if err := j.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				reopened, err := safety.OpenJournal(jDir, jMeta)
				if err != nil {
					t.Fatalf("Reopen: %v", err)
				}
				t.Cleanup(func() { _ = reopened.Close() })
				base.Journal = reopened
			}

			roCfg := base
			roCfg.Functions = solR2FunctionsOnly{Functions: f}
			replay := New(roCfg)
			replay.SetAbortOnError(false)
			before := f.Calls()
			out, _ := replay.FunctionInvoke(true, "cacherecreatefn", "", "{}", false)
			afterCalls := f.Calls()
			reads := afterCalls["GetFunction"] - before["GetFunction"] + afterCalls["ListFunctionVersions"] - before["ListFunctionVersions"] + afterCalls["GetFunctionAlias"] - before["GetFunctionAlias"]
			if replay.LastError().Code != hostkit.OK || reads != 0 {
				t.Fatalf("dry invoke after recreate failed: last=%+v reads=%d", replay.LastError(), reads)
			}
			// Also verify dry preview did not inherit incarnation 1's published version "1".
			_, _ = replay.FunctionInvoke(true, "cacherecreatefn", "1", "{}", true)
			if replay.LastError().Code != hostkit.NotFound {
				t.Fatalf("expected version 1 from stale incarnation to be absent in incarnation 2 preview; got %+v (out=%+v)", replay.LastError(), out)
			}
		})
	}
}

func TestSolR3FnSanitizedCacheIsNotReadback(t *testing.T) {
	for _, journalMode := range []bool{false, true} {
		mode := "campaign"
		if journalMode {
			mode = "journal"
		}
		t.Run(mode, func(t *testing.T) {
			_, f, _, campaign := newFuncHost(t)
			base := Config{Provider: "aws", Functions: solR2FunctionsOnly{Functions: f}, CampaignStatePath: campaign}
			if journalMode {
				_, j, _ := solJournal(t)
				base.Journal = j
				base.CampaignStatePath = ""
			}
			h := New(base)
			h.SetAbortOnError(false)
			cfg := solFnConfig(t, h, "def handler(e,c): return {}\n")
			cfg.SetEnv("APP_ENV", "test-fixture-value")
			h.FunctionCreate(false, "readcachefn", cfg)

			h2 := New(base)
			h2.SetAbortOnError(false)
			got, _ := h2.FunctionGet(true, "readcachefn", "", false)
			t.Logf("last=%+v inline_bytes=%d has_env=%v", h2.LastError(), len(got.InlineCode()), got.HasEnv("APP_ENV"))
			if got.InlineCode() == "" || !got.HasEnv("APP_ENV") {
				t.Fatal("sanitized journal preview replaced complete readback configuration")
			}
		})
	}
}

func TestSolR3FnManyDescriptorsAndSparseQuota(t *testing.T) {
	for _, mode := range []string{"manyfds", "sparse"} {
		t.Run(mode, func(t *testing.T) {
			h, _, _, _ := newFuncHost(t)
			cfg := solFnConfig(t, h, `import os
def handler(e,c):
 fds=[]
 blocked=0
 n=1048576 if e['mode']=='manyfds' else 8*1048576
 try:
  for i in range(20 if e['mode']=='manyfds' else 3):
   p=os.path.join(os.environ['TMPDIR'],'fd'+str(i))
   fd=os.open(p,os.O_RDWR|os.O_CREAT,0o600)
   os.unlink(p)
   fds.append(fd)
   try:
    if e['mode']=='manyfds': os.write(fd,b'x'*n)
    else: os.ftruncate(fd,n)
   except OSError as ex:
    blocked=ex.errno
    break
  return {'held_bytes':sum(os.fstat(fd).st_size for fd in fds),'fds':len(fds),'blocked':blocked}
 finally:
  for fd in fds: os.close(fd)
`)
			h.FunctionCreate(false, "manyquota", cfg)
			out, _ := h.FunctionInvoke(false, "manyquota", "", `{"mode":"`+mode+`"}`, false)
			t.Logf("last=%+v function_error=%s payload=%s", h.LastError(), out.FunctionError(), out.Payload())
			var v map[string]any
			_ = json.Unmarshal([]byte(out.Payload()), &v)
			n, ok := v["held_bytes"].(float64)
			b, bok := v["blocked"].(float64)
			if h.LastError().Code != hostkit.OK || !ok || !bok || n > 16*1048576 || b == 0 {
				t.Fatal("aggregate fd/sparse bound not enforced", out.Payload())
			}
		})
	}
}

