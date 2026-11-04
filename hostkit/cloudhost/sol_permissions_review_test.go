// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

type solPermLost struct {
	*fakeadapter.Fake
	path                     string
	durableDoc, durableToken bool
	token                    string
}

func (a *solPermLost) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	raw, _ := os.ReadFile(a.path)
	a.durableDoc = strings.Contains(string(raw), `\"effect\"`)
	a.durableToken = strings.Contains(string(raw), att.OwnerToken)
	a.token = att.OwnerToken
	if e := a.Fake.AttachPolicy(ctx, att); e != nil {
		return e
	}
	return hostkit.ProviderError(hostkit.Internal, 0, "LostReply", "reply lost after apply")
}

func TestSolPermLostReply(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "campaign.jsonl")
	f := fakeadapter.New(fakeadapter.Options{StatePath: filepath.Join(d, "fake.json")})
	a := &solPermLost{Fake: f, path: path}
	h := New(Config{Provider: "ref", Store: f, Permissions: a, CampaignStatePath: path})
	h.SetAbortOnError(false)
	_, _ = h.BucketCreate(false, "sol-bucket")
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	_ = h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	t.Logf("before native dispatch: durable document=%v durable ownership token=%v", a.durableDoc, a.durableToken)
	if !a.durableDoc || !a.durableToken {
		t.Error("native attach dispatched without recoverable full-document/token intent")
	}
	h2 := New(Config{Provider: "ref", Store: f, Permissions: f, CampaignStatePath: path})
	h2.SetAbortOnError(false)
	allowed, _ := h2.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	raw, _ := os.ReadFile(filepath.Join(d, "fake.json"))
	var st struct {
		Policies map[string]hostkit.PolicyAttachment
	}
	_ = json.Unmarshal(raw, &st)
	t.Logf("after lost reply/reopen: native attachments=%d portable allowed=%v last=%s", len(st.Policies), allowed, h2.LastError().Code)
	if h2.LastError().Code == hostkit.OK {
		t.Error("ambiguous applied attachment silently replayed as absent instead of retained/fail-closed")
	}
}

type solPermPause struct {
	*fakeadapter.Fake
	applied, release chan struct{}
}

func (a *solPermPause) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	if e := a.Fake.AttachPolicy(ctx, att); e != nil {
		return e
	}
	close(a.applied)
	<-a.release
	return nil
}

func TestSolPermConcurrentReplacement(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "campaign.jsonl")
	state := filepath.Join(d, "fake.json")
	f := fakeadapter.New(fakeadapter.Options{StatePath: state})
	a := &solPermPause{Fake: f, applied: make(chan struct{}), release: make(chan struct{})}
	h1 := New(Config{Provider: "ref", Store: f, Permissions: a, CampaignStatePath: path})
	h1.SetAbortOnError(false)
	_, _ = h1.BucketCreate(false, "sol-bucket")
	h2 := New(Config{Provider: "ref", Store: f, Permissions: f, CampaignStatePath: path})
	h2.SetAbortOnError(false)
	p1, _ := h1.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	p2, _ := h2.PolicyNew().Statement("Deny", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	done := make(chan struct{})
	go func() {
		_ = h1.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p1)
		close(done)
	}()
	<-a.applied
	_ = h2.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p2)
	close(a.release)
	<-done
	allowed, _ := h2.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	raw, _ := os.ReadFile(state)
	var st struct {
		Policies map[string]hostkit.PolicyAttachment
	}
	_ = json.Unmarshal(raw, &st)
	var native []hostkit.PolicyAttachment
	for _, v := range st.Policies {
		native = append(native, v)
	}
	nativeAllow := hostkit.EvaluatePolicies(native, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	t.Logf("overlapping same-key attaches: native allowed=%v journal evaluator allowed=%v", nativeAllow, allowed)
	if allowed != nativeAllow {
		t.Error("late unfenced completion overwrote authoritative attachment after newer native replacement")
	}
}

type solPermEcho struct {
	*fakeadapter.Fake
	secret string
}

func (a *solPermEcho) DetachPolicy(context.Context, hostkit.AttachmentKind, string, string) error {
	return hostkit.ProviderError(hostkit.Internal, 0, "EchoOwner", "native error: "+a.secret)
}

func TestSolPermReplayTokenRedaction(t *testing.T) {
	h, f, path := newPermsHost(t)
	_, _ = h.BucketCreate(false, "sol-bucket")
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	_ = h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	attachments, ce := h.cost.listPolicyAttachments()
	if ce != nil || len(attachments) != 1 {
		t.Fatal("setup failed")
	}
	token := attachments[0].OwnerToken
	a := &solPermEcho{Fake: f, secret: token}
	h2 := New(Config{Provider: "aws", Store: f, Permissions: a, CampaignStatePath: path})
	h2.SetAbortOnError(false)
	_ = h2.PolicyDetach(false, "storage:bucket:sol-bucket", "principal:alice")
	if strings.Contains(h2.LastError().Message, token) {
		t.Error("replayed attachment ownership token leaked through last_error")
	}
}

func TestSolPermActionResourceMatrix(t *testing.T) {
	h, _, _ := newPermsHost(t)
	_, _ = h.BucketCreate(false, "sol-bucket")
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:bucket:sol-bucket"})
	lint, _ := h.PolicyLint(p)
	_ = h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	allowed, _ := h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:bucket:sol-bucket")
	t.Logf("object.read against bucket resource: lint OK=%v allowed=%v last=%s", lint.OK(), allowed, h.LastError().Code)
	if lint.OK() || allowed {
		t.Error("Appendix A action/resource type incompatibility accepted as executable")
	}
}

func TestSolPermUnknownProvider(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Provider: "unknown-cloud", Store: f, Permissions: f})
	h.SetAbortOnError(false)
	_, _ = h.BucketCreate(false, "sol-bucket")
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	_ = h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	if f.Calls()["AttachPolicy"] > 0 {
		t.Error("unknown provider reached mutation adapter")
	}
}

func TestSolPermDelegatedLiveCheck(t *testing.T) {
	m, j, p := solJournal(t)
	g, e := safety.NewLiveGuard(safety.GuardConfig{Policy: p, Meter: m, Journal: j, Recovery: &solUnusedRecovery{}})
	if e != nil {
		t.Fatal(e)
	}
	f := fakeadapter.New(fakeadapter.Options{})
	_, _ = f.CreateBucket(context.Background(), "sol-bucket")
	h := New(Config{Provider: "aws", Store: g.WrapStore(f), Permissions: f})
	h.SetAbortOnError(false)
	if err := h.SetCostCapUSD(0.0000004); err != nil {
		t.Fatal(err)
	}
	_, _ = h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	t.Logf("live guarded store + unguarded permissions: CheckPolicy calls=%d last=%s report=%+v", f.Calls()["CheckPolicy"], h.LastError().Code, h.CostReport().Item("policy_check"))
	if f.Calls()["CheckPolicy"] > 0 {
		t.Error("unguarded permissions check bypassed live refusal/admission via bucket resource delegation")
	}
}

func TestSolPermSafetyJournalMissingAuthority(t *testing.T) {
	_, j, _ := solJournal(t)
	document := `{"v":1,"statements":[{"effect":"Allow","actions":["storage.object.read"],"resources":["storage:object:sol-bucket/*"]}]}`
	if err := j.RecordPolicyAttach("resource", "storage:bucket:sol-bucket", "principal:alice", document, "", ""); err != nil {
		t.Logf("rejected missing authority: %v", err)
		return
	}
	f := fakeadapter.New(fakeadapter.Options{})
	_, _ = f.CreateBucket(context.Background(), "sol-bucket")
	h := New(Config{Provider: "aws", Store: f, Permissions: f, Journal: j})
	h.SetAbortOnError(false)
	allowed, _ := h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	t.Logf("missing owner token/generation: allowed=%v last=%s", allowed, h.LastError().Code)
	if allowed || h.LastError().Code == hostkit.OK {
		t.Error("incomplete safety-journal attachment authority accepted instead of fail-closed")
	}
}

func TestSolPermForeignDetach(t *testing.T) {
	h, f, path := newPermsHost(t)
	_, _ = h.BucketCreate(false, "sol-bucket")
	stmts := []hostkit.PolicyStatement{{Effect: "Allow", Actions: []string{"storage.object.read"}, Resources: []string{"storage:object:sol-bucket/*"}}}
	doc, ce := hostkit.SerializeCanonicalPolicy(stmts)
	if ce != nil {
		t.Fatal(ce)
	}
	// An operator/native writer has an entry for the same target/principal;
	// this run never journaled or owned it.
	foreign := hostkit.PolicyAttachment{Kind: hostkit.AttachmentResource, Target: "storage:bucket:sol-bucket", Principal: "principal:alice", Statements: stmts, Document: doc, OwnerToken: strings.Repeat("a", 32), Generation: "1"}
	if err := f.AttachPolicy(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	before := f.Calls()["DetachPolicy"]
	_ = h.PolicyDetach(false, "storage:bucket:sol-bucket", "principal:alice")
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "fake.json"))
	var st struct {
		Policies map[string]hostkit.PolicyAttachment
	}
	_ = json.Unmarshal(raw, &st)
	t.Logf("never-journaled pair: native detach calls=%d surviving foreign policies=%d last=%s", f.Calls()["DetachPolicy"]-before, len(st.Policies), h.LastError().Code)
	if f.Calls()["DetachPolicy"] > before || len(st.Policies) != 1 {
		t.Error("detach touched/deleted unjournaled foreign native policy")
	}
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	_ = h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	// Replace our native entry with a foreign owner after the journaled attach.
	if err := f.AttachPolicy(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	_ = h.PolicyDetach(false, "storage:bucket:sol-bucket", "principal:alice")
	raw, _ = os.ReadFile(filepath.Join(filepath.Dir(path), "fake.json"))
	_ = json.Unmarshal(raw, &st)
	if len(st.Policies) != 1 {
		t.Error("detach also deleted foreign replacement of a formerly-owned attachment")
	}
}

func TestSolPermEndpointScope(t *testing.T) {
	a := fakeadapter.New(fakeadapter.Options{})
	b := fakeadapter.New(fakeadapter.Options{})
	_, _ = b.CreateBucket(context.Background(), "sol-bucket") // pre-existing in other scope
	router := hostkit.Router{Pick: func(ctx context.Context) (hostkit.Backend, error) {
		if hostkit.EndpointFrom(ctx) == "http://127.0.0.1:19002" {
			return b, nil
		}
		return a, nil
	}}
	h := New(Config{Provider: "ref", Store: router, Permissions: router, CampaignStatePath: filepath.Join(t.TempDir(), "campaign.jsonl")})
	h.SetAbortOnError(false)
	_ = h.SetEndpoint("all", "http://127.0.0.1:19001")
	_, _ = h.BucketCreate(false, "sol-bucket")
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	_ = h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	_ = h.SetEndpoint("all", "http://127.0.0.1:19002")
	allowed, _ := h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	_ = h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	t.Logf("after endpoint scope switch: old grant allowed=%v foreign AttachPolicy calls=%d last=%s", allowed, b.Calls()["AttachPolicy"], h.LastError().Code)
	if allowed || b.Calls()["AttachPolicy"] > 0 {
		t.Error("name-only ownership/attachment key authorized a different endpoint's foreign resource")
	}
}

type solPermPauseBeforeAttach struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *solPermPauseBeforeAttach) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	close(a.entered)
	<-a.release
	return a.Fake.AttachPolicy(ctx, att)
}

type solPermPauseBeforeDetach struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *solPermPauseBeforeDetach) DetachPolicy(ctx context.Context, kind hostkit.AttachmentKind, target, principal string) error {
	close(a.entered)
	<-a.release
	return a.Fake.DetachPolicy(ctx, kind, target, principal)
}

func TestSolPermConcurrentAttachAndDetachBothOrders(t *testing.T) {
	// Order 1: Slow Attach (gen 2) vs fast Detach (gen 3) -> Detach wins on both native and journal.
	t.Run("slow_attach_fenced_by_newer_detach", func(t *testing.T) {
		d := t.TempDir()
		path := filepath.Join(d, "campaign.jsonl")
		state := filepath.Join(d, "fake.json")
		f := fakeadapter.New(fakeadapter.Options{StatePath: state})
		pauseAttach := &solPermPauseBeforeAttach{Fake: f, entered: make(chan struct{}), release: make(chan struct{})}

		hSeed := New(Config{Provider: "ref", Store: f, Permissions: f, CampaignStatePath: path})
		hSeed.SetAbortOnError(false)
		_, _ = hSeed.BucketCreate(false, "sol-bucket")
		pAllow, _ := hSeed.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
		if err := hSeed.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", pAllow); err != nil {
			t.Fatal(err)
		}

		hSlowAttach := New(Config{Provider: "ref", Store: f, Permissions: pauseAttach, CampaignStatePath: path})
		hSlowAttach.SetAbortOnError(false)
		done := make(chan struct{})
		go func() {
			_ = hSlowAttach.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", pAllow)
			close(done)
		}()
		<-pauseAttach.entered

		// While hSlowAttach is paused before native dispatch, hSeed detaches (gen 3).
		if err := hSeed.PolicyDetach(false, "storage:bucket:sol-bucket", "principal:alice"); err != nil {
			t.Fatalf("PolicyDetach failed: %v (%+v)", err, hSeed.LastError())
		}
		close(pauseAttach.release)
		<-done

		allowed, _ := hSeed.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
		if hSeed.LastError().Code != hostkit.OK || allowed {
			t.Fatalf("expected detach to win over stale slow attach, got allowed=%v last=%+v", allowed, hSeed.LastError())
		}
	})

	// Order 2: Slow Detach (gen 2) vs fast re-Attach (gen 3) -> re-Attach wins on both native and journal.
	t.Run("slow_detach_fenced_by_newer_attach", func(t *testing.T) {
		d := t.TempDir()
		path := filepath.Join(d, "campaign.jsonl")
		state := filepath.Join(d, "fake.json")
		f := fakeadapter.New(fakeadapter.Options{StatePath: state})
		pauseDetach := &solPermPauseBeforeDetach{Fake: f, entered: make(chan struct{}), release: make(chan struct{})}

		hSeed := New(Config{Provider: "ref", Store: f, Permissions: f, CampaignStatePath: path})
		hSeed.SetAbortOnError(false)
		_, _ = hSeed.BucketCreate(false, "sol-bucket")
		pAllow, _ := hSeed.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
		if err := hSeed.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", pAllow); err != nil {
			t.Fatal(err)
		}

		hSlowDetach := New(Config{Provider: "ref", Store: f, Permissions: pauseDetach, CampaignStatePath: path})
		hSlowDetach.SetAbortOnError(false)
		done := make(chan struct{})
		go func() {
			_ = hSlowDetach.PolicyDetach(false, "storage:bucket:sol-bucket", "principal:alice")
			close(done)
		}()
		<-pauseDetach.entered

		// While hSlowDetach is paused before native dispatch, hSeed attaches a new generation (gen 3).
		if err := hSeed.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", pAllow); err != nil {
			t.Fatalf("PolicyAttach failed: %v (%+v)", err, hSeed.LastError())
		}
		close(pauseDetach.release)
		<-done

		allowed, _ := hSeed.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
		raw, _ := os.ReadFile(state)
		var st struct {
			Policies map[string]hostkit.PolicyAttachment
		}
		_ = json.Unmarshal(raw, &st)
		if hSeed.LastError().Code != hostkit.OK || !allowed || len(st.Policies) != 1 {
			t.Fatalf("expected newer attach to win over stale slow detach, got allowed=%v native=%d last=%+v", allowed, len(st.Policies), hSeed.LastError())
		}
	})
}

func TestSolPermForeignBucketCreateConflictDoesNotAdoptOwnership(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	_, _ = f.CreateBucket(context.Background(), "foreign-bucket") // created without this run's token

	h := New(Config{Provider: "ref", Store: f, Permissions: f, CampaignStatePath: filepath.Join(t.TempDir(), "campaign.jsonl")})
	h.SetAbortOnError(false)

	created, err := h.BucketCreate(false, "foreign-bucket")
	if err != nil || created {
		t.Fatalf("expected BucketCreate on pre-existing foreign bucket to return (false, nil), got (%v, %v)", created, err)
	}

	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:foreign-bucket/*"})
	_ = h.PolicyAttach(false, "storage:bucket:foreign-bucket", "principal:alice", p)
	if h.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected PolicyAttach on unowned 409 bucket to fail PERMISSION_DENIED, got %+v", h.LastError())
	}
}

type solR2AmbThenDeny struct {
	*fakeadapter.Fake
	calls int
}

func (a *solR2AmbThenDeny) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	a.calls++
	if a.calls == 1 {
		if err := a.Fake.AttachPolicy(ctx, att); err != nil {
			return err
		}
		return hostkit.ProviderError(hostkit.Internal, 0, "LostReply", "synthetic lost reply after apply")
	}
	return hostkit.ProviderError(hostkit.PermissionDenied, 403, "AccessDenied", "synthetic refusal before apply")
}

func TestSolR2PriorAmbiguitySurvivesNewRefusal(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "campaign.jsonl")
	state := filepath.Join(d, "fake.json")
	f := fakeadapter.New(fakeadapter.Options{StatePath: state})
	a := &solR2AmbThenDeny{Fake: f}
	seed := New(Config{Provider: "ref", Store: f, Permissions: f, CampaignStatePath: path})
	seed.SetAbortOnError(false)
	seed.BucketCreate(false, "sol-bucket")
	initial, _ := seed.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	seed.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", initial)
	h := New(Config{Provider: "ref", Store: f, Permissions: a, CampaignStatePath: path})
	h.SetAbortOnError(false)
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	deny, _ := h.PolicyNew().Statement("Deny", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", deny)
	h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	if h.LastError().Code != hostkit.Conflict {
		t.Fatal("setup did not retain first lost reply")
	}
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	h2 := New(Config{Provider: "ref", Store: f, Permissions: f, CampaignStatePath: path})
	h2.SetAbortOnError(false)
	allowed, _ := h2.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	raw, _ := os.ReadFile(state)
	var st struct {
		Policies map[string]hostkit.PolicyAttachment
	}
	json.Unmarshal(raw, &st)
	var native []hostkit.PolicyAttachment
	for _, v := range st.Policies {
		native = append(native, v)
	}
	nativeAllowed := hostkit.EvaluatePolicies(native, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	t.Logf("lost Deny reply, then new refusal, then reopen: native allowed=%v portable allowed=%v last=%s", nativeAllowed, allowed, h2.LastError().Code)
	if h2.LastError().Code != hostkit.Conflict {
		t.Error("new definitive refusal erased earlier unresolved applied intent")
	}
}

func TestSolR2PriorAmbiguitySurvivesNewRefusalSafetyJournal(t *testing.T) {
	_, j, _ := solJournal(t)
	state := filepath.Join(t.TempDir(), "fake.json")
	f := fakeadapter.New(fakeadapter.Options{StatePath: state})
	a := &solR2AmbThenDeny{Fake: f}
	seed := New(Config{Provider: "aws", Store: f, Permissions: f, Journal: j})
	seed.SetAbortOnError(false)
	seed.BucketCreate(false, "sol-bucket")
	initial, _ := seed.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	seed.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", initial)

	h := New(Config{Provider: "aws", Store: f, Permissions: a, Journal: j})
	h.SetAbortOnError(false)
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	deny, _ := h.PolicyNew().Statement("Deny", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", deny)
	h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	if h.LastError().Code != hostkit.Conflict {
		t.Fatal("setup did not retain first lost reply")
	}
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	if err := j.Compact(); err != nil {
		t.Fatal(err)
	}
	journalDir := filepath.Dir(j.Path())
	meta := j.State().Meta
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := safety.OpenJournal(journalDir, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	h2 := New(Config{Provider: "aws", Store: f, Permissions: f, Journal: reopened})
	h2.SetAbortOnError(false)
	_, _ = h2.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	if h2.LastError().Code != hostkit.Conflict {
		t.Errorf("new definitive refusal erased earlier unresolved applied intent in safety journal after compaction+reopen: got %s", h2.LastError().Code)
	}
}

func TestSolR2SafetyJournalAttachWorkflow(t *testing.T) {
	_, j, _ := solJournal(t)
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Provider: "aws", Store: f, Permissions: f, Journal: j})
	h.SetAbortOnError(false)
	h.BucketCreate(false, "sol-bucket")
	if h.LastError().Code != hostkit.OK {
		t.Fatal("bucket setup failed", h.LastError())
	}
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	t.Logf("Journal-backed attach: code=%s message=%s calls=%d", h.LastError().Code, h.LastError().Message, f.Calls()["AttachPolicy"])
	if h.LastError().Code != hostkit.OK || f.Calls()["AttachPolicy"] != 1 {
		t.Error("valid journal-backed policy attach failed")
	}
}

func TestSolR2SafetyJournalDirectIntent(t *testing.T) {
	_, j, _ := solJournal(t)
	f := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{Provider: "aws", Store: f, Permissions: f, Journal: j})
	h.SetAbortOnError(false)
	scope, _ := h.permissionsScope()
	stmts := []hostkit.PolicyStatement{{Effect: "Allow", Actions: []string{"storage.object.read"}, Resources: []string{"storage:object:sol-bucket/*"}}}
	doc, _ := hostkit.SerializeCanonicalPolicy(stmts)
	_, ce := h.cost.beginPolicyAttachIntent(scope, hostkit.AttachmentResource, "storage:bucket:sol-bucket", "principal:alice", stmts, doc)
	if ce != nil {
		t.Errorf("direct valid intent rejected after bypassing reservation key issue: %s", ce.Message)
	}
}

func TestSolR2CompactionPreservesDetachFence(t *testing.T) {
	_, j, _ := solJournal(t)
	f := fakeadapter.New(fakeadapter.Options{})
	f.CreateBucket(context.Background(), "sol-bucket")
	h := New(Config{Provider: "aws", Store: f, Permissions: f, Journal: j})
	h.SetAbortOnError(false)
	scope, _ := h.permissionsScope()
	target := "storage:bucket:sol-bucket"
	principal := "principal:alice"
	stmts := []hostkit.PolicyStatement{{Effect: "Allow", Actions: []string{"storage.object.read"}, Resources: []string{"storage:object:sol-bucket/*"}}}
	doc, _ := hostkit.SerializeCanonicalPolicy(stmts)
	owner := strings.Repeat("a", 32)
	i1 := strings.Repeat("b", 32)
	i2 := strings.Repeat("c", 32)
	if e := j.RecordPolicyIntent(scope, "resource", target, principal, "attach", doc, owner, "1", i1, "", "", 0); e != nil {
		t.Fatal(e)
	}
	if e := j.RecordPolicyAttachScoped(scope, "resource", target, principal, doc, owner, "1", i1, 0); e != nil {
		t.Fatal(e)
	}
	if e := j.RecordPolicyIntent(scope, "resource", target, principal, "detach", "", owner, "2", i2, owner, "1", 0); e != nil {
		t.Fatal(e)
	}
	if e := j.RecordPolicyDetachScoped(scope, "resource", target, principal, owner, "2", i2); e != nil {
		t.Fatal(e)
	}
	key := hostkit.ScopedAttachmentKey(scope, hostkit.AttachmentResource, target, principal)
	before := j.State().MaxPolicyGen[key]
	if e := j.Compact(); e != nil {
		t.Fatal(e)
	}
	journalDir := filepath.Dir(j.Path())
	meta := j.State().Meta
	if e := j.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := safety.OpenJournal(journalDir, meta)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	after := reopened.State().MaxPolicyGen[key]
	h = New(Config{Provider: "aws", Store: f, Permissions: f, Journal: reopened})
	h.SetAbortOnError(false)
	stale := hostkit.PolicyAttachment{Key: key, Scope: scope, Kind: hostkit.AttachmentResource, Target: target, Principal: principal, Document: doc, Statements: stmts, OwnerToken: owner, Generation: "1", IntentID: i1}
	ce := h.cost.confirmPolicyAttach(stale)
	allowed, _ := h.PolicyCheck(false, principal, "storage.object.read", "storage:object:sol-bucket/k")
	t.Logf("detach fence across compaction: max before=%d after=%d stale completion error=%v allowed=%v last=%s", before, after, ce, allowed, h.LastError().Code)
	if after != before || allowed {
		t.Error("compaction dropped tombstone/high-water mark and resurrected stale grant")
	}
}

func TestSolR2ForeignAttachPreserved(t *testing.T) {
	h, f, path := newPermsHost(t)
	h.BucketCreate(false, "sol-bucket")
	stmts := []hostkit.PolicyStatement{{Effect: "Deny", Actions: []string{"storage.object.read"}, Resources: []string{"storage:object:sol-bucket/*"}}}
	doc, _ := hostkit.SerializeCanonicalPolicy(stmts)
	foreign := hostkit.PolicyAttachment{Kind: hostkit.AttachmentResource, Target: "storage:bucket:sol-bucket", Principal: "principal:alice", Document: doc, Statements: stmts, OwnerToken: strings.Repeat("f", 32), Generation: "1"}
	if err := f.AttachPolicy(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "fake.json"))
	var st struct {
		Policies map[string]hostkit.PolicyAttachment
	}
	json.Unmarshal(raw, &st)
	surviving := false
	for _, v := range st.Policies {
		if v.OwnerToken == foreign.OwnerToken && v.Document == doc {
			surviving = true
		}
	}
	t.Logf("foreign same-key Deny survives host attach=%v last=%s", surviving, h.LastError().Code)
	if !surviving {
		t.Error("host attach overwrote foreign native contribution/owner")
	}
}

func TestSolR2PolicyCleanupHeadroom(t *testing.T) {
	h, f, _ := newPermsHost(t)
	h.BucketCreate(false, "sol-bucket")
	before := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	if h.LastError().Code != hostkit.OK {
		t.Fatal(h.LastError())
	}
	after := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
	t.Logf("attachment cleanup lock delta=%d, quoted cleanup=%d", after-before, h.cost.meter.Table().Operations["policy_attach"].CleanupReserveNanoUSD)
	if after-before < 1000 {
		t.Error("successful attach released rather than durably locking its quoted cleanup headroom")
	}
	if err := h.SetCostCapUSD(h.EstimatedCost()); err != nil {
		t.Fatal(err)
	}
	calls := f.Calls()["DetachPolicy"]
	h.PolicyDetach(false, "storage:bucket:sol-bucket", "principal:alice")
	t.Logf("owned detach with exhausted work budget: code=%s native detach calls=%d", h.LastError().Code, f.Calls()["DetachPolicy"]-calls)
	if h.LastError().Code != hostkit.OK || f.Calls()["DetachPolicy"] == calls {
		t.Error("owned cleanup cannot use reserved cleanup ceiling after work exhaustion")
	}
}

func TestSolR2PolicyCleanupHeadroomCrashReopen(t *testing.T) {
	h, f, path := newPermsHost(t)
	h.BucketCreate(false, "sol-bucket")
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	if h.LastError().Code != hostkit.OK {
		t.Fatal(h.LastError())
	}
	if err := h.SetCostCapUSD(h.EstimatedCost()); err != nil {
		t.Fatal(err)
	}
	hReopen := New(Config{Provider: "aws", Store: f, Permissions: f, CampaignStatePath: path})
	hReopen.SetAbortOnError(false)
	callsBeforeReopenDetach := f.Calls()["DetachPolicy"]
	hReopen.PolicyDetach(false, "storage:bucket:sol-bucket", "principal:alice")
	if hReopen.LastError().Code != hostkit.OK || f.Calls()["DetachPolicy"] == callsBeforeReopenDetach {
		t.Errorf("reopened host owned detach failed under exhausted work cap: %+v", hReopen.LastError())
	}
}

func TestSolR2LiveRouteWithoutGlobalFlag(t *testing.T) {
	offline := fakeadapter.New(fakeadapter.Options{})
	live := fakeadapter.New(fakeadapter.Options{})
	routes := hostkit.EndpointRoutes{Offline: offline, Live: live}
	router := hostkit.Router{Pick: routes.Pick}
	h := New(Config{Provider: "aws", Store: router, Permissions: router})
	h.SetAbortOnError(false)
	if err := h.SetEndpoint("all", "https://live.invalid"); err != nil {
		t.Fatal(err)
	}
	// Native-route resource setup is synthetic; neither router backend uses networking.
	h.BucketCreate(false, "sol-bucket")
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	t.Logf("EndpointRoutes.Live with no global LIVE flag: live policy writes=%d last=%s", live.Calls()["AttachPolicy"], h.LastError().Code)
	if live.Calls()["AttachPolicy"] > 0 {
		t.Error("uncertified live-routed permission mutation escaped flag-only refusal")
	}
}

func TestSolR3UnmarkedForeignPolicy(t *testing.T) {
	h, f, path := newPermsHost(t)
	h.BucketCreate(false, "sol-bucket")
	stmts := []hostkit.PolicyStatement{{Effect: "Deny", Actions: []string{"storage.object.read"}, Resources: []string{"storage:object:sol-bucket/*"}}}
	doc, _ := hostkit.SerializeCanonicalPolicy(stmts)
	foreign := hostkit.PolicyAttachment{Kind: hostkit.AttachmentResource, Target: "storage:bucket:sol-bucket", Principal: "principal:alice", Document: doc, Statements: stmts}
	if err := f.AttachPolicy(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "fake.json"))
	var st struct {
		Policies map[string]hostkit.PolicyAttachment
	}
	json.Unmarshal(raw, &st)
	preserved := false
	for _, att := range st.Policies {
		if att.Document == doc && att.OwnerToken == "" {
			preserved = true
		}
	}
	t.Logf("unmarked foreign Deny preserved=%v last=%s", preserved, h.LastError().Code)
	if !preserved {
		t.Error("attach adopted/replaced pre-existing policy with no ownership marker")
	}
}

func TestSolR3UnmarkedForeignPolicyVariants(t *testing.T) {
	h, f, path := newPermsHost(t)
	h.BucketCreate(false, "sol-bucket")
	stmts := []hostkit.PolicyStatement{{Effect: "Deny", Actions: []string{"storage.object.read"}, Resources: []string{"storage:object:sol-bucket/*"}}}
	doc, _ := hostkit.SerializeCanonicalPolicy(stmts)
	foreignPrincipal := hostkit.PolicyAttachment{Kind: hostkit.AttachmentPrincipal, Target: "", Principal: "principal:alice", Document: doc, Statements: stmts}
	if err := f.AttachPolicy(context.Background(), foreignPrincipal); err != nil {
		t.Fatal(err)
	}
	malformedResource := hostkit.PolicyAttachment{Kind: hostkit.AttachmentResource, Target: "storage:bucket:sol-bucket", Principal: "principal:bob", Document: doc, Statements: stmts, OwnerToken: "not-a-valid-32-hex-token"}
	if err := f.AttachPolicy(context.Background(), malformedResource); err != nil {
		t.Fatal(err)
	}
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttachPrincipal(false, "principal:alice", p)
	if h.LastError().Code != hostkit.PreconditionFailed {
		t.Errorf("expected PRECONDITION_FAILED on unmarked foreign principal policy, got %+v", h.LastError())
	}
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:bob", p)
	if h.LastError().Code != hostkit.PreconditionFailed {
		t.Errorf("expected PRECONDITION_FAILED on malformed-marker foreign resource policy, got %+v", h.LastError())
	}
	raw, _ := os.ReadFile(filepath.Join(filepath.Dir(path), "fake.json"))
	var st struct {
		Policies map[string]hostkit.PolicyAttachment
	}
	json.Unmarshal(raw, &st)
	if len(st.Policies) != 2 {
		t.Fatalf("expected 2 preserved foreign policies, got %d", len(st.Policies))
	}
}

func TestSolR3CrossEndpointDeletionPreservesDeny(t *testing.T) {
	d := t.TempDir()
	ap := filepath.Join(d, "a.json")
	bp := filepath.Join(d, "b.json")
	a := fakeadapter.New(fakeadapter.Options{StatePath: ap})
	b := fakeadapter.New(fakeadapter.Options{StatePath: bp})
	router := hostkit.Router{Pick: func(ctx context.Context) (hostkit.Backend, error) {
		if hostkit.EndpointFrom(ctx) == "http://127.0.0.1:19002" {
			return b, nil
		}
		return a, nil
	}}
	h := New(Config{Provider: "ref", Store: router, Permissions: router, CampaignStatePath: filepath.Join(d, "campaign.jsonl")})
	h.SetAbortOnError(false)
	h.SetEndpoint("all", "http://127.0.0.1:19001")
	h.BucketCreate(false, "sol-bucket")
	h.SetEndpoint("all", "http://127.0.0.1:19002")
	h.BucketCreate(false, "sol-bucket")
	allow, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	deny, _ := h.PolicyNew().Statement("Deny", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/secret/*"})
	h.PolicyAttachPrincipal(false, "principal:alice", allow)
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", deny)
	before, _ := h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/secret/k")
	if h.LastError().Code != hostkit.OK || before {
		t.Fatal("setup Deny did not override", h.LastError())
	}
	h.SetEndpoint("all", "http://127.0.0.1:19001")
	h.BucketDelete(false, "sol-bucket")
	if h.LastError().Code != hostkit.OK {
		t.Fatal("delete setup failed", h.LastError())
	}
	h.SetEndpoint("all", "http://127.0.0.1:19002")
	after, _ := h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/secret/k")
	raw, _ := os.ReadFile(bp)
	var st struct {
		Policies map[string]hostkit.PolicyAttachment
	}
	json.Unmarshal(raw, &st)
	var native []hostkit.PolicyAttachment
	for _, v := range st.Policies {
		native = append(native, v)
	}
	nativeAllow := hostkit.EvaluatePolicies(native, "principal:alice", "storage.object.read", "storage:object:sol-bucket/secret/k")
	t.Logf("delete same-name A bucket: B allowed before=%v after=%v native=%v last=%s", before, after, nativeAllow, h.LastError().Code)
	if after {
		t.Error("deleting A removed B's scoped resource Deny while leaving B's identity Allow")
	}
}

func TestSolR3CrossEndpointDeletionVariants(t *testing.T) {
	// Test queues, tables, pending Deny intents, safety.Journal, and crash/reopen across endpoints.
	_, j, _ := solJournal(t)
	d := t.TempDir()
	a := fakeadapter.New(fakeadapter.Options{StatePath: filepath.Join(d, "a.json")})
	b := fakeadapter.New(fakeadapter.Options{StatePath: filepath.Join(d, "b.json")})
	router := hostkit.Router{Pick: func(ctx context.Context) (hostkit.Backend, error) {
		if hostkit.EndpointFrom(ctx) == "http://127.0.0.1:19002" {
			return b, nil
		}
		return a, nil
	}}
	h := New(Config{Provider: "aws", Store: router, Queue: router, Tables: router, Permissions: router, Journal: j})
	h.SetAbortOnError(false)

	h.SetEndpoint("all", "http://127.0.0.1:19001")
	h.QueueCreate(false, "sol-queue")
	h.TableCreate(false, "soltable", false)

	h.SetEndpoint("all", "http://127.0.0.1:19002")
	h.QueueCreate(false, "sol-queue")
	h.TableCreate(false, "soltable", false)

	qAllow, _ := h.PolicyNew().Statement("Allow", []string{"queue.queue.send", "queue.queue.receive"}, []string{"queue:queue:sol-queue"})
	qDeny, _ := h.PolicyNew().Statement("Deny", []string{"queue.queue.send"}, []string{"queue:queue:sol-queue"})
	h.PolicyAttachPrincipal(false, "principal:alice", qAllow)
	h.PolicyAttach(false, "queue:queue:sol-queue", "principal:alice", qDeny)

	tAllow, _ := h.PolicyNew().Statement("Allow", []string{"tables.table.read", "tables.table.write"}, []string{"tables:table:soltable"})
	tDeny, _ := h.PolicyNew().Statement("Deny", []string{"tables.table.write"}, []string{"tables:table:soltable"})
	h.PolicyAttachPrincipal(false, "principal:bob", tAllow)
	h.PolicyAttach(false, "tables:table:soltable", "principal:bob", tDeny)

	// Delete queue and table in scope A; scope B's Denys must survive (including across compact/reopen).
	h.SetEndpoint("all", "http://127.0.0.1:19001")
	h.QueueDelete(false, "sol-queue")
	h.TableDelete(false, "soltable")

	if err := j.Compact(); err != nil {
		t.Fatal(err)
	}
	jDir := filepath.Dir(j.Path())
	meta := j.State().Meta
	_ = j.Close()
	reopened, err := safety.OpenJournal(jDir, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	h2 := New(Config{Provider: "aws", Store: router, Queue: router, Tables: router, Permissions: router, Journal: reopened})
	h2.SetAbortOnError(false)
	h2.SetEndpoint("all", "http://127.0.0.1:19002")
	qAllowed, _ := h2.PolicyCheck(false, "principal:alice", "queue.queue.send", "queue:queue:sol-queue")
	if h2.LastError().Code != hostkit.OK || qAllowed {
		t.Errorf("deleting A queue removed B queue Deny: allowed=%v err=%+v", qAllowed, h2.LastError())
	}
	tAllowed, _ := h2.PolicyCheck(false, "principal:bob", "tables.table.write", "tables:table:soltable")
	if h2.LastError().Code != hostkit.OK || tAllowed {
		t.Errorf("deleting A table removed B table Deny: allowed=%v err=%+v", tAllowed, h2.LastError())
	}

	// Also verify pending Deny intent in B survives deleting same-name bucket in A.
	h2.SetEndpoint("all", "http://127.0.0.1:19001")
	h2.BucketCreate(false, "pend-bkt")
	h2.SetEndpoint("all", "http://127.0.0.1:19002")
	h2.BucketCreate(false, "pend-bkt")
	bScope, _ := h2.permissionsScope()
	bDenyDoc := `{"v":1,"statements":[{"effect":"Deny","actions":["storage.object.read"],"resources":["storage:object:pend-bkt/*"]}]}`
	if err := reopened.RecordPolicyIntent(bScope, "resource", "storage:bucket:pend-bkt", "principal:carol", "attach", bDenyDoc, safety.NewToken128(), "1", safety.NewToken128(), "", "", 1000); err != nil {
		t.Fatal(err)
	}
	h2.SetEndpoint("all", "http://127.0.0.1:19001")
	h2.BucketDelete(false, "pend-bkt")
	h2.SetEndpoint("all", "http://127.0.0.1:19002")
	_, _ = h2.PolicyCheck(false, "principal:carol", "storage.object.read", "storage:object:pend-bkt/k")
	if h2.LastError().Code != hostkit.Conflict {
		t.Errorf("deleting A bucket erased B's pending Deny intent: got %+v", h2.LastError())
	}
}

type solR3LostAttach struct{ *fakeadapter.Fake }

func (a *solR3LostAttach) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	if err := a.Fake.AttachPolicy(ctx, att); err != nil {
		return err
	}
	return hostkit.ProviderError(hostkit.Internal, 0, "LostReply", "synthetic reply loss")
}

func TestSolR3AmbiguousCleanupReserve(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "campaign.jsonl")
	f := fakeadapter.New(fakeadapter.Options{StatePath: filepath.Join(d, "fake.json")})
	h := New(Config{Provider: "ref", Store: f, Permissions: &solR3LostAttach{f}, CampaignStatePath: path})
	h.SetAbortOnError(false)
	h.BucketCreate(false, "sol-bucket")
	before := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	h2 := New(Config{Provider: "ref", Store: f, Permissions: f, CampaignStatePath: path})
	h2.SetAbortOnError(false)
	after := h2.cost.meter.Snapshot().ResourceCleanupNanoUSD
	t.Logf("applied lost-reply attachment: cleanup delta after reopen=%d", after-before)
	if after-before < 1000 {
		t.Error("ambiguously applied attachment lost its reserved cleanup headroom")
	}
}

func TestSolR3AmbiguousCleanupReserveSafetyJournal(t *testing.T) {
	_, j, _ := solJournal(t)
	f := fakeadapter.New(fakeadapter.Options{StatePath: filepath.Join(t.TempDir(), "fake.json")})
	h := New(Config{Provider: "aws", Store: f, Permissions: &solR3LostAttach{f}, Journal: j})
	h.SetAbortOnError(false)
	h.BucketCreate(false, "sol-bucket")
	before := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	if err := j.Compact(); err != nil {
		t.Fatal(err)
	}
	jDir := filepath.Dir(j.Path())
	meta := j.State().Meta
	_ = j.Close()
	reopened, err := safety.OpenJournal(jDir, meta)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	h2 := New(Config{Provider: "aws", Store: f, Permissions: f, Journal: reopened})
	h2.SetAbortOnError(false)
	after := h2.cost.meter.Snapshot().ResourceCleanupNanoUSD
	if after-before < 1000 {
		t.Errorf("safety journal ambiguously applied attachment lost reserved cleanup headroom: delta=%d", after-before)
	}
	// Verify owned detach can reconcile and release the ambiguous attachment under exhausted work cap.
	if err := h2.SetCostCapUSD(h2.EstimatedCost()); err != nil {
		t.Fatal(err)
	}
	h2.PolicyDetach(false, "storage:bucket:sol-bucket", "principal:alice")
	if h2.LastError().Code != hostkit.OK {
		t.Errorf("expected owned detach of ambiguous attachment to succeed under cleanup reserve, got %+v", h2.LastError())
	}
}

func TestSolR3DefaultLiveRoutePreflight(t *testing.T) {
	live := fakeadapter.New(fakeadapter.Options{})
	live.CreateBucket(context.Background(), "sol-bucket")
	routes := hostkit.EndpointRoutes{Live: live}
	router := hostkit.Router{Pick: routes.Pick}
	h := New(Config{Provider: "aws", Store: router, Permissions: router})
	h.SetAbortOnError(false)
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	t.Logf("default live route: ownership HeadBucket calls=%d permission writes=%d code=%s", live.Calls()["HeadBucket"], live.Calls()["AttachPolicy"], h.LastError().Code)
	if live.Calls()["HeadBucket"] > 0 {
		t.Error("default live route reached ownership I/O before refusal")
	}
}

func TestSolR3DefaultLiveRoutePreflightVariants(t *testing.T) {
	offlinePerms := fakeadapter.New(fakeadapter.Options{})
	live := fakeadapter.New(fakeadapter.Options{})
	live.CreateBucket(context.Background(), "sol-bucket")
	live.CreateQueue(context.Background(), "sol-queue")
	live.CreateTable(context.Background(), "soltable", false)
	routes := hostkit.EndpointRoutes{Live: live}
	liveRouter := hostkit.Router{Pick: routes.Pick}

	// Even when Permissions itself is offline, if Store/Queue/Tables resolve to a default Live route,
	// prerequisite target reads must be refused before any Live HeadBucket/LookupQueue/HeadTable call.
	h := New(Config{Provider: "aws", Store: liveRouter, Queue: liveRouter, Tables: liveRouter, Permissions: offlinePerms})
	h.SetAbortOnError(false)
	pBkt, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", pBkt)
	if h.LastError().Code != hostkit.PermissionDenied || live.Calls()["HeadBucket"] > 0 {
		t.Errorf("live Store route reached HeadBucket=%d code=%s", live.Calls()["HeadBucket"], h.LastError().Code)
	}
	pQ, _ := h.PolicyNew().Statement("Allow", []string{"queue.queue.send"}, []string{"queue:queue:sol-queue"})
	h.PolicyAttach(false, "queue:queue:sol-queue", "principal:alice", pQ)
	if h.LastError().Code != hostkit.PermissionDenied || live.Calls()["LookupQueue"] > 0 {
		t.Errorf("live Queue route reached LookupQueue=%d code=%s", live.Calls()["LookupQueue"], h.LastError().Code)
	}
	pTbl, _ := h.PolicyNew().Statement("Allow", []string{"tables.table.read"}, []string{"tables:table:soltable"})
	h.PolicyAttach(false, "tables:table:soltable", "principal:alice", pTbl)
	if h.LastError().Code != hostkit.PermissionDenied || live.Calls()["HeadTable"] > 0 {
		t.Errorf("live Tables route reached HeadTable=%d code=%s", live.Calls()["HeadTable"], h.LastError().Code)
	}
	_, _ = h.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:sol-bucket/k")
	if h.LastError().Code != hostkit.PermissionDenied || live.Calls()["HeadBucket"] > 0 {
		t.Errorf("live PolicyCheck reached HeadBucket=%d code=%s", live.Calls()["HeadBucket"], h.LastError().Code)
	}
}

func TestSolR3IntentStackCompactionAndAbort(t *testing.T) {
	_, j, _ := solJournal(t)
	scope := "synthetic-scope"
	target := "storage:bucket:sol-bucket"
	pr := "principal:alice"
	doc := `{"v":1,"statements":[{"effect":"Deny","actions":["storage.object.read"],"resources":["storage:object:sol-bucket/*"]}]}`
	owner := safety.NewToken128()
	i1 := safety.NewToken128()
	i2 := safety.NewToken128()
	if e := j.RecordPolicyIntent(scope, "resource", target, pr, "attach", doc, owner, "1", i1, "", "", 0); e != nil {
		t.Fatal(e)
	}
	if e := j.RecordPolicyIntent(scope, "resource", target, pr, "attach", doc, owner, "2", i2, owner, "1", 0); e != nil {
		t.Fatal(e)
	}
	if e := j.RecordPolicyIntent(scope, "resource", target, pr, "abort", "", owner, "2", i2, "", "", 0); e != nil {
		t.Fatal(e)
	}
	if e := j.Compact(); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Dir(j.Path())
	meta := j.State().Meta
	j.Close()
	reopened, e := safety.OpenJournal(dir, meta)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	key := hostkit.ScopedAttachmentKey(scope, hostkit.AttachmentResource, target, pr)
	s := reopened.State()
	if len(s.AmbiguousStack[key]) != 1 || s.AmbiguousStack[key][0].IntentID != i1 || s.MaxPolicyGen[key] != 2 || s.LatestPolicyIntent[key] != i2 {
		t.Fatal("compaction/reopen changed pending predecessor or high-water marks")
	}
	if e := reopened.RecordPolicyIntent(scope, "resource", target, pr, "abort", "", owner, "1", i1, "", "", 0); e != nil {
		t.Fatal(e)
	}
	if e := reopened.Compact(); e != nil {
		t.Fatal(e)
	}
	if s := reopened.State(); len(s.AmbiguousStack[key]) != 0 || s.MaxPolicyGen[key] != 2 {
		t.Fatal("final abort lost tombstone or left pending intent")
	}
}

type solR3SubopBudget struct {
	*fakeadapter.Fake
	physical int
}

func (a *solR3SubopBudget) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	for i := 0; i < 3; i++ {
		if err := hostkit.RunSubOperation(ctx, hostkit.SubOperationSpec{Operation: "object_head"}, func(sub context.Context) error {
			last, _ := hostkit.DefaultRetryPolicy().Do(sub, true, func(context.Context, int) hostkit.Attempt {
				a.physical++
				return hostkit.Attempt{Status: 200}
			})
			return last.Err
		}); err != nil {
			return err
		}
	}
	return a.Fake.AttachPolicy(ctx, att)
}

func TestSolR3PhysicalSuboperationBudget(t *testing.T) {
	f := fakeadapter.New(fakeadapter.Options{})
	a := &solR3SubopBudget{Fake: f}
	h := New(Config{Provider: "ref", Store: f, Permissions: a, CampaignStatePath: filepath.Join(t.TempDir(), "campaign.jsonl")})
	h.SetAbortOnError(false)
	h.BucketCreate(false, "sol-bucket")
	if e := h.SetCostCapUSD(h.EstimatedCost() + 0.0000014); e != nil {
		t.Fatal(e)
	}
	p, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:sol-bucket/*"})
	h.PolicyAttach(false, "storage:bucket:sol-bucket", "principal:alice", p)
	t.Logf("budgeted physical suboperations=%d actual grant writes=%d last=%s", a.physical, f.Calls()["AttachPolicy"], h.LastError().Code)
	if a.physical != 2 || f.Calls()["AttachPolicy"] != 0 || h.LastError().Code != hostkit.CostCapExceeded {
		t.Fatal("physical admission did not stop at budget")
	}
}
