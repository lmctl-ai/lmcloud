// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

func newPermsHost(t *testing.T) (*Host, *fakeadapter.Fake, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "fake.json")
	campaignPath := filepath.Join(dir, "campaign.jsonl")
	fake := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
	h := New(Config{
		Provider:          "aws",
		Store:             fake,
		Queue:             fake,
		Tables:            fake,
		Permissions:       fake,
		CampaignStatePath: campaignPath,
	})
	h.SetAbortOnError(false)
	return h, fake, campaignPath
}

func TestPermissionsTier1AndTier2Validation(t *testing.T) {
	h, _, _ := newPermsHost(t)

	// Tier-1 syntax rejections
	p := h.PolicyNew()
	_, _ = p.Statement("Maybe", []string{"storage.object.read"}, []string{"storage:object:bkt/k"})
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected pre-flight INVALID_ARGUMENT on bad effect, got %+v", h.LastError())
	}

	p = h.PolicyNew()
	_, _ = p.Statement("Allow", []string{"storage.*"}, []string{"storage:object:bkt/k"})
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected pre-flight INVALID_ARGUMENT on wildcard action, got %+v", h.LastError())
	}

	// Duplicate JSON keys and unknown fields rejected in PolicyParse
	_, _ = h.PolicyParse(`{"v":1,"v":1,"statements":[]}`)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected duplicate JSON key to fail PolicyParse, got %+v", h.LastError())
	}
	_, _ = h.PolicyParse(`{"v":1,"statements":[],"extra":true}`)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected unknown field to fail PolicyParse, got %+v", h.LastError())
	}

	// Tier-2 semantic lint deterministic ordering & attach refusal
	lintPol := h.PolicyNew()
	lintPol, _ = lintPol.Statement("Allow", []string{"storage.object.bogusverb"}, []string{"storage:object:mybkt/k"})
	if h.LastError().Code != hostkit.OK {
		t.Fatalf("Tier-1 should accept well-formed unknown action for lint: %+v", h.LastError())
	}
	lintPol, _ = lintPol.Statement("Allow", []string{"permissions.policy.write"}, []string{"storage:bucket:mybkt"})
	if h.LastError().Code != hostkit.OK {
		t.Fatalf("Tier-1 should accept well-formed escalation action for lint: %+v", h.LastError())
	}
	lintPol, _ = lintPol.Statement("Allow", []string{"storage.object.write", "storage.object.delete"}, []string{"storage:bucket:*"})
	if h.LastError().Code != hostkit.OK {
		t.Fatalf("Tier-1 should accept wildcard bucket resource for lint: %+v", h.LastError())
	}

	rep, err := h.PolicyLint(lintPol)
	if err != nil || h.LastError().Code != hostkit.OK {
		t.Fatalf("PolicyLint failed: %v / %+v", err, h.LastError())
	}
	if rep.OK() {
		t.Fatal("expected lint report with error findings to have OK()==false")
	}
	wantCodes := []string{"UNKNOWN_ACTION", "ESCALATION_NAMESPACE", "OVERBROAD_COMBINATION", "WILDCARD_SCOPE"}
	if rep.Len() != int64(len(wantCodes)) {
		t.Fatalf("want %d findings, got %d", len(wantCodes), rep.Len())
	}
	for i, want := range wantCodes {
		f, err := rep.At(int64(i))
		if err != nil {
			t.Fatal(err)
		}
		if f.Code() != want {
			t.Fatalf("finding[%d]: want code %q, got %q", i, want, f.Code())
		}
	}

	// Non-executable policy refused pre-flight at attach
	if _, err := h.BucketCreate(false, "mybkt"); err != nil || h.LastError().Code != hostkit.OK {
		t.Fatalf("BucketCreate: %v / %+v", err, h.LastError())
	}
	_ = h.PolicyAttach(false, "storage:bucket:mybkt", "principal:alice", lintPol)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected pre-flight INVALID_ARGUMENT on lint error attach, got %+v", h.LastError())
	}
}

func TestPermissionsOwnershipFencingAndResourceDeletionCleanup(t *testing.T) {
	dir := t.TempDir()
	fakeState := filepath.Join(dir, "fake.json")
	campaignA := filepath.Join(dir, "campaign-a.jsonl")
	campaignB := filepath.Join(dir, "campaign-b.jsonl")

	fakeA := fakeadapter.New(fakeadapter.Options{StatePath: fakeState})
	hostA := New(Config{
		Provider:          "aws",
		Store:             fakeA,
		Queue:             fakeA,
		Tables:            fakeA,
		Permissions:       fakeA,
		CampaignStatePath: campaignA,
	})
	hostA.SetAbortOnError(false)

	_, _ = hostA.BucketCreate(false, "foreign-bkt")
	_, _ = hostA.QueueCreate(false, "foreign-q")
	_, _ = hostA.TableCreate(false, "foreigntbl", false)

	// Host B shares the underlying cloud state (fakeState) but has its own run journal (campaignB).
	fakeB := fakeadapter.New(fakeadapter.Options{StatePath: fakeState})
	hostB := New(Config{
		Provider:          "aws",
		Store:             fakeB,
		Queue:             fakeB,
		Tables:            fakeB,
		Permissions:       fakeB,
		CampaignStatePath: campaignB,
	})
	hostB.SetAbortOnError(false)

	polBkt, _ := hostB.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:foreign-bkt/*"})
	_ = hostB.PolicyAttach(false, "storage:bucket:foreign-bkt", "principal:bob", polBkt)
	if hostB.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED on foreign bucket attach, got %+v", hostB.LastError())
	}
	_ = hostB.PolicyAttachPrincipal(false, "principal:bob", polBkt)
	if hostB.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED on foreign bucket principal attach, got %+v", hostB.LastError())
	}

	polQ, _ := hostB.PolicyNew().Statement("Allow", []string{"queue.queue.send"}, []string{"queue:queue:foreign-q"})
	_ = hostB.PolicyAttach(false, "queue:queue:foreign-q", "principal:bob", polQ)
	if hostB.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED on foreign queue attach, got %+v", hostB.LastError())
	}

	polTbl, _ := hostB.PolicyNew().Statement("Allow", []string{"tables.table.read"}, []string{"tables:table:foreigntbl"})
	_ = hostB.PolicyAttach(false, "tables:table:foreigntbl", "principal:bob", polTbl)
	if hostB.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED on foreign table attach, got %+v", hostB.LastError())
	}

	// PolicyCheck on an existing foreign resource succeeds with false (default deny).
	allowed, err := hostB.PolicyCheck(false, "principal:bob", "storage.object.read", "storage:object:foreign-bkt/k")
	if err != nil || hostB.LastError().Code != hostkit.OK || allowed {
		t.Fatalf("expected PolicyCheck on existing foreign bucket to return (false, OK), got (%v, %+v)", allowed, hostB.LastError())
	}

	// Deleting a run-owned resource automatically removes its resource-scoped policy attachments.
	_, _ = hostA.BucketCreate(false, "owned-bkt")
	polOwned, _ := hostA.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:owned-bkt/*"})
	_ = hostA.PolicyAttach(false, "storage:bucket:owned-bkt", "principal:alice", polOwned)
	if hostA.LastError().Code != hostkit.OK {
		t.Fatalf("PolicyAttach failed: %+v", hostA.LastError())
	}
	if ok, _ := hostA.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:owned-bkt/k"); hostA.LastError().Code != hostkit.OK || !ok {
		t.Fatalf("expected PolicyCheck true before delete, got (%v, %+v)", ok, hostA.LastError())
	}
	_, _ = hostA.BucketDelete(false, "owned-bkt")
	_, _ = hostA.BucketCreate(false, "owned-bkt")
	if ok, _ := hostA.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:owned-bkt/k"); hostA.LastError().Code != hostkit.OK || ok {
		t.Fatalf("expected PolicyCheck false after bucket delete+recreate, got (%v, %+v)", ok, hostA.LastError())
	}
}

func TestPermissionsJournalReplayAndCorruptFailClosed(t *testing.T) {
	dir := t.TempDir()
	fakeState := filepath.Join(dir, "fake.json")
	campaignPath := filepath.Join(dir, "campaign.jsonl")

	fake1 := fakeadapter.New(fakeadapter.Options{StatePath: fakeState})
	h1 := New(Config{
		Provider:          "aws",
		Store:             fake1,
		Queue:             fake1,
		Tables:            fake1,
		Permissions:       fake1,
		CampaignStatePath: campaignPath,
	})
	h1.SetAbortOnError(false)

	_, _ = h1.BucketCreate(false, "replay-bkt")
	allowPol, _ := h1.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:replay-bkt/*"})
	_ = h1.PolicyAttach(false, "storage:bucket:replay-bkt", "principal:alice", allowPol)
	if h1.LastError().Code != hostkit.OK {
		t.Fatalf("PolicyAttach failed: %+v", h1.LastError())
	}
	denyPol, _ := h1.PolicyNew().Statement("Deny", []string{"storage.object.read"}, []string{"storage:object:replay-bkt/secret/*"})
	_ = h1.PolicyAttachPrincipal(false, "principal:alice", denyPol)
	if h1.LastError().Code != hostkit.OK {
		t.Fatalf("PolicyAttachPrincipal failed: %+v", h1.LastError())
	}

	// Second host instance replays solely from CampaignStatePath.
	fake2 := fakeadapter.New(fakeadapter.Options{StatePath: fakeState})
	h2 := New(Config{
		Provider:          "aws",
		Store:             fake2,
		Queue:             fake2,
		Tables:            fake2,
		Permissions:       fake2,
		CampaignStatePath: campaignPath,
	})
	h2.SetAbortOnError(false)

	if ok, _ := h2.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:replay-bkt/public/a"); h2.LastError().Code != hostkit.OK || !ok {
		t.Fatalf("expected replayed PolicyCheck true on public path, got (%v, %+v)", ok, h2.LastError())
	}
	if ok, _ := h2.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:replay-bkt/secret/a"); h2.LastError().Code != hostkit.OK || ok {
		t.Fatalf("expected replayed cross-attachment Deny to override Allow on secret path, got (%v, %+v)", ok, h2.LastError())
	}

	// Corrupting the campaign journal must fail closed with INTERNAL.
	f, err := os.OpenFile(campaignPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{\"corrupt_json\"\n")
	_ = f.Close()

	h3 := New(Config{
		Provider:          "aws",
		Store:             fake2,
		Queue:             fake2,
		Tables:            fake2,
		Permissions:       fake2,
		CampaignStatePath: campaignPath,
	})
	h3.SetAbortOnError(false)
	_, _ = h3.PolicyCheck(false, "principal:alice", "storage.object.read", "storage:object:replay-bkt/public/a")
	if h3.LastError().Code != hostkit.Internal {
		t.Fatalf("expected INTERNAL on corrupt campaign journal, got %+v", h3.LastError())
	}
}

func TestPermissionsAttachmentCap128(t *testing.T) {
	// Use in-memory tracker (no disk fsync per attach) for fast 128-cap test.
	fake := fakeadapter.New(fakeadapter.Options{})
	h := New(Config{
		Provider:    "aws",
		Store:       fake,
		Permissions: fake,
	})
	h.SetAbortOnError(false)

	_, _ = h.BucketCreate(false, "cap-bkt")
	pol, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:cap-bkt/*"})

	for i := 0; i < hostkit.MaxAttachmentsPerRun; i++ {
		pr := fmt.Sprintf("principal:user-%03d", i)
		_ = h.PolicyAttach(false, "storage:bucket:cap-bkt", pr, pol)
		if h.LastError().Code != hostkit.OK {
			t.Fatalf("attach %d failed: %+v", i, h.LastError())
		}
	}

	// 129th distinct attachment key must fail pre-flight with INVALID_ARGUMENT.
	_ = h.PolicyAttach(false, "storage:bucket:cap-bkt", "principal:user-overflow", pol)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().ProviderCode != "AttachmentLimitExceeded" {
		t.Fatalf("expected INVALID_ARGUMENT/AttachmentLimitExceeded, got %+v", h.LastError())
	}

	// Replacing an existing attachment key at the 128 cap must still succeed.
	pol2, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.write"}, []string{"storage:object:cap-bkt/*"})
	_ = h.PolicyAttach(false, "storage:bucket:cap-bkt", "principal:user-000", pol2)
	if h.LastError().Code != hostkit.OK {
		t.Fatalf("expected replace on existing attachment key at 128 cap to succeed, got %+v", h.LastError())
	}
}

func TestPermissionsDryRunZeroMutatorCallsAndTokenRedaction(t *testing.T) {
	h, fake, campaignPath := newPermsHost(t)
	_, _ = h.BucketCreate(false, "dry-bkt")
	beforeMutators := fake.MutatorCalls()

	pol, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:dry-bkt/*"})
	_ = h.PolicyAttach(true, "storage:bucket:dry-bkt", "principal:dry-user", pol)
	if h.LastError().Code != hostkit.OK {
		t.Fatalf("dry PolicyAttach failed: %+v", h.LastError())
	}
	if ok, _ := h.PolicyCheck(true, "principal:dry-user", "storage.object.read", "storage:object:dry-bkt/k"); h.LastError().Code != hostkit.OK || !ok {
		t.Fatalf("expected dry PolicyCheck true after dry attach, got (%v, %+v)", ok, h.LastError())
	}
	_ = h.PolicyDetach(true, "storage:bucket:dry-bkt", "principal:dry-user")
	if h.LastError().Code != hostkit.OK {
		t.Fatalf("dry PolicyDetach failed: %+v", h.LastError())
	}
	if ok, _ := h.PolicyCheck(true, "principal:dry-user", "storage.object.read", "storage:object:dry-bkt/k"); h.LastError().Code != hostkit.OK || ok {
		t.Fatalf("expected dry PolicyCheck false after dry detach, got (%v, %+v)", ok, h.LastError())
	}
	if fake.MutatorCalls() != beforeMutators {
		t.Fatalf("expected zero adapter mutator calls during dry permissions ops, got delta %d", fake.MutatorCalls()-beforeMutators)
	}

	// Real state was untouched by dry run.
	if ok, _ := h.PolicyCheck(false, "principal:dry-user", "storage.object.read", "storage:object:dry-bkt/k"); h.LastError().Code != hostkit.OK || ok {
		t.Fatalf("expected real PolicyCheck false, got (%v, %+v)", ok, h.LastError())
	}

	// Create-token redaction on AttachPolicy error (using same CampaignStatePath so dry-bkt is owned).
	echoFake := fakeadapter.New(fakeadapter.Options{EchoCreateToken: true})
	echoHost := New(Config{
		Provider:          "aws",
		Store:             fake,
		Permissions:       echoFake,
		CampaignStatePath: campaignPath,
	})
	echoHost.SetAbortOnError(false)
	_ = echoHost.PolicyAttach(false, "storage:bucket:dry-bkt", "principal:dry-user", pol)
	le := echoHost.LastError()
	if le.Code != hostkit.PermissionDenied || !strings.Contains(le.Message, "[create-token]") {
		t.Fatalf("expected redacted token in AttachPolicy error, got %+v", le)
	}
}

type subOpPermsAdapter struct {
	*fakeadapter.Fake
}

func (a *subOpPermsAdapter) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	// Simulate a multi-step native attach (e.g. GET existing bucket policy + PUT merged bucket policy).
	steps := []hostkit.SubOperationSpec{
		{Operation: "object_head", PayloadBytes: 0},
		{Operation: "object_put", PayloadBytes: int64(len(att.Document))},
	}
	for _, spec := range steps {
		if err := hostkit.RunSubOperation(ctx, spec, func(subCtx context.Context) error {
			last, _ := hostkit.DefaultRetryPolicy().Do(subCtx, true, func(context.Context, int) hostkit.Attempt {
				return hostkit.Attempt{Status: 200}
			})
			return last.Err
		}); err != nil {
			return err
		}
	}
	return a.Fake.AttachPolicy(ctx, att)
}

func TestPermissionsSubOperationCostAdmissionAndLiveRefusal(t *testing.T) {
	dir := t.TempDir()
	base := fakeadapter.New(fakeadapter.Options{StatePath: filepath.Join(dir, "fake.json")})
	perms := &subOpPermsAdapter{Fake: base}
	h := New(Config{
		Provider:          "aws",
		Store:             base,
		Permissions:       perms,
		CampaignStatePath: filepath.Join(dir, "campaign.jsonl"),
	})
	h.SetAbortOnError(false)

	_, _ = h.BucketCreate(false, "subop-bkt")
	pol, _ := h.PolicyNew().Statement("Allow", []string{"storage.object.read"}, []string{"storage:object:subop-bkt/*"})
	_ = h.PolicyAttach(false, "storage:bucket:subop-bkt", "principal:alice", pol)
	if h.LastError().Code != hostkit.OK {
		t.Fatalf("PolicyAttach failed: %+v", h.LastError())
	}
	line := h.CostReport().Item("policy_attach")
	if line.Requests != 2 || line.EstimatedUSD < 0.0000054 {
		t.Fatalf("expected 2 sub-op requests ($0.0000004 + $0.0000050 = $0.0000054) under policy_attach, got %+v", line)
	}

	// Unconfigured live mode refuses all permissions operations fail-closed with PERMISSION_DENIED.
	t.Setenv("LMCLOUD_LIVE", "1")
	liveHost := New(Config{
		Provider:    "aws",
		Store:       base,
		Permissions: base,
	})
	liveHost.SetAbortOnError(false)
	_, _ = liveHost.PrincipalCurrent(false)
	if liveHost.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected live PrincipalCurrent to fail with PERMISSION_DENIED, got %+v", liveHost.LastError())
	}
	_ = liveHost.PolicyAttach(false, "storage:bucket:subop-bkt", "principal:alice", pol)
	if liveHost.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected live PolicyAttach to fail with PERMISSION_DENIED, got %+v", liveHost.LastError())
	}
}
