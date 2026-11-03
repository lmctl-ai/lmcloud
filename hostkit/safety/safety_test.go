// SPDX-License-Identifier: MIT

package safety

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

func newTestSetup(t *testing.T) (Policy, string, *FakeRecoveryBackend) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journals")
	pol := DefaultAWSLivePolicy(dir, true)
	runID := NewRunID(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))
	backend := NewFakeRecoveryBackend(
		"aws",
		"254332045686",
		"arn:aws:iam::254332045686:role/awsspot-admin",
		"us-east-1",
	)
	return pol, runID, backend
}

func TestSafety_GuardStoreAndQueueLifecycle(t *testing.T) {
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)
	errState := hostkit.NewErrorState()

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Errors:   errState,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()

	store := sess.WrapStore(backend)
	queue := sess.WrapQueue(backend)

	// 1. Unprefixed bucket/queue names are refused before touching the backend.
	if _, err := store.CreateBucket(ctx, "prod-customer-bucket"); err == nil {
		t.Fatal("expected unprefixed bucket create to be refused")
	}
	if _, err := queue.CreateQueue(ctx, "prod-orders-queue"); err == nil {
		t.Fatal("expected unprefixed queue create to be refused")
	}

	bktName, _ := FormatLiveResourceName(runID, "bkt", 1)
	qName, _ := FormatLiveResourceName(runID, "que", 1)

	// 2. Object/message operations on a non-existent parent report NOT_FOUND
	// without mutating.
	if _, err := store.PutObject(ctx, bktName, "k1", []byte("hello"), "text/plain", nil); err == nil {
		t.Fatal("expected PutObject on missing bucket to fail")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.NotFound {
		t.Fatalf("expected NOT_FOUND for missing parent bucket, got %+v", ce)
	}

	// 3. Create bucket, put/get object, create queue, send/receive/ack message.
	created, err := store.CreateBucket(ctx, bktName)
	if err != nil || !created {
		t.Fatalf("CreateBucket: created=%v err=%v", created, err)
	}
	if _, err := store.PutObject(ctx, bktName, "k1", []byte("payload-1"), "text/plain", nil); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	got, err := store.GetObject(ctx, bktName, "k1", 1024)
	if err != nil || string(got) != "payload-1" {
		t.Fatalf("GetObject: got=%q err=%v", got, err)
	}

	qCreated, err := queue.CreateQueue(ctx, qName)
	if err != nil || !qCreated {
		t.Fatalf("CreateQueue: created=%v err=%v", qCreated, err)
	}
	msgID, err := queue.Send(ctx, qName, "hello-queue")
	if err != nil || msgID == "" {
		t.Fatalf("Send: id=%q err=%v", msgID, err)
	}
	msgs, err := queue.Receive(ctx, qName, 1, 0, 30)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("Receive: msgs=%+v err=%v", msgs, err)
	}
	if err := queue.Ack(ctx, qName, msgs[0].Receipt); err != nil {
		t.Fatalf("Ack: %v", err)
	}

	// 4. FinishAndSweep deletes object before bucket and deletes queue.
	rep, err := sess.FinishAndSweep(ctx)
	if err != nil {
		t.Fatalf("FinishAndSweep: %v", err)
	}
	if !rep.Clean() || len(rep.Deleted) != 3 {
		t.Fatalf("expected 3 deleted items (object, bucket, queue) and clean report, got %+v", rep)
	}
	if backend.HasBucket(bktName) || backend.HasQueue(qName) {
		t.Fatal("expected bucket and queue to be deleted after FinishAndSweep")
	}
}

func TestSafety_UnrelatedSamePrefixResourceNeverAdoptedOrDeleted(t *testing.T) {
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)

	foreignBkt, _ := FormatLiveResourceName(runID, "foreign", 1)
	ownedBkt, _ := FormatLiveResourceName(runID, "owned", 2)
	unownedSibling, _ := FormatLiveResourceName(runID, "sibling", 3)

	// Pre-seed two buckets that share this run's `lmcloud-conf-<run12>-` prefix
	// but were created by another run/principal (different owner_nonce / run_id).
	for _, b := range []string{foreignBkt, unownedSibling} {
		backend.SeedBucket(b, map[string]string{
			TagKeyRunID:       NewRunID(time.Unix(1712000000, 0)),
			TagKeyOwnerNonce:  NewToken128(),
			TagKeyCreateToken: NewToken128(),
		}, "254332045686", "arn:aws:iam::254332045686:role/awsspot-admin")
	}

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()
	store := sess.WrapStore(backend)

	// Attempting to CreateBucket on the colliding same-prefix bucket must fail
	// closed with CONFLICT (ForeignResourceCollision), mark it Retained, and NOT adopt it.
	if _, err := store.CreateBucket(ctx, foreignBkt); err == nil {
		t.Fatal("expected CreateBucket on foreign same-prefix bucket to fail closed")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.Conflict || ce.ProviderCode != "ForeignResourceCollision" {
		t.Fatalf("expected ForeignResourceCollision, got %+v", ce)
	}

	// Attempting PutObject or DeleteBucket on the foreign same-prefix bucket must
	// also be refused.
	if _, err := store.PutObject(ctx, foreignBkt, "k1", []byte("x"), "text/plain", nil); err == nil {
		t.Fatal("expected PutObject on foreign same-prefix bucket to be refused")
	}
	if err := store.DeleteBucket(ctx, foreignBkt); err == nil {
		t.Fatal("expected DeleteBucket on foreign same-prefix bucket to be refused")
	}

	// Create a genuinely owned bucket and sweep everything.
	if _, err := store.CreateBucket(ctx, ownedBkt); err != nil {
		t.Fatalf("CreateBucket ownedBkt: %v", err)
	}
	rep, err := sess.FinishAndSweep(ctx)
	if err != nil {
		t.Fatalf("FinishAndSweep: %v", err)
	}
	if len(rep.Deleted) != 1 || rep.Deleted[0].Name != ownedBkt {
		t.Fatalf("expected only ownedBkt deleted, got %+v", rep.Deleted)
	}
	if len(rep.Retained) != 1 || rep.Retained[0].Name != foreignBkt {
		t.Fatalf("expected foreignBkt in Retained, got %+v", rep.Retained)
	}
	if len(rep.UnownedSkipped) != 1 || rep.UnownedSkipped[0].Name != unownedSibling {
		t.Fatalf("expected unownedSibling in UnownedSkipped, got %+v", rep.UnownedSkipped)
	}
	if !backend.HasBucket(foreignBkt) || !backend.HasBucket(unownedSibling) {
		t.Fatal("foreign same-prefix bucket was deleted!")
	}
}

func TestSafety_FailedDuplicateAfterConfirmPreservesOwnershipAndSweeps(t *testing.T) {
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()
	store := sess.WrapStore(backend)

	bkt, _ := FormatLiveResourceName(runID, "dup", 1)
	created1, err := store.CreateBucket(ctx, bkt)
	if err != nil || !created1 {
		t.Fatalf("first CreateBucket: created=%v err=%v", created1, err)
	}
	entry1, ok := sess.Journal().Lookup(KindBucket, "", bkt)
	if !ok || entry1.State != StateConfirmed {
		t.Fatalf("expected confirmed entry after first create, got %+v", entry1)
	}

	// Duplicate CreateBucket in the same run returns (false, nil) and preserves tokens.
	created2, err := store.CreateBucket(ctx, bkt)
	if err != nil || created2 {
		t.Fatalf("second CreateBucket: created=%v err=%v (want false, nil)", created2, err)
	}
	// Explicitly call Failed on the journal after confirm: must NOT cancel the confirmed entry.
	if err := sess.Journal().Failed(KindBucket, "", bkt, "simulated duplicate failure", 400); err != nil {
		t.Fatalf("Journal.Failed: %v", err)
	}
	entry2, ok := sess.Journal().Lookup(KindBucket, "", bkt)
	if !ok || entry2.State != StateConfirmed || entry2.OwnerNonce != entry1.OwnerNonce || entry2.CreateToken != entry1.CreateToken {
		t.Fatalf("confirmed entry corrupted after duplicate/failed: %+v", entry2)
	}

	rep, err := sess.FinishAndSweep(ctx)
	if err != nil {
		t.Fatalf("FinishAndSweep: %v", err)
	}
	if len(rep.Deleted) != 1 || rep.Deleted[0].Name != bkt || backend.HasBucket(bkt) {
		t.Fatalf("expected confirmed bucket to be swept, got %+v", rep)
	}
}

func TestSafety_TokenEchoRedactionInErrorState(t *testing.T) {
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)
	errState := hostkit.NewErrorState()

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Errors:   errState,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()
	store := sess.WrapStore(backend)

	backend.SetEchoTokenOnOp("bucket_create", true)
	bkt, _ := FormatLiveResourceName(runID, "echo", 1)

	_, callErr := store.CreateBucket(ctx, bkt)
	if callErr == nil {
		t.Fatal("expected CreateBucket to fail when echoTokenOnOp is set")
	}

	// Read the raw journal file to find the generated OwnerNonce and CreateToken.
	rawBytes, err := os.ReadFile(sess.Journal().Path())
	if err != nil {
		t.Fatalf("ReadFile journal: %v", err)
	}
	records, _, err := parseJournalBytes(rawBytes, false)
	if err != nil {
		t.Fatalf("parseJournalBytes: %v", err)
	}
	var intentRec JournalRecord
	for _, r := range records {
		if r.Event == EventIntent && r.Name == bkt {
			intentRec = r
			break
		}
	}
	if intentRec.OwnerNonce == "" || intentRec.CreateToken == "" {
		t.Fatalf("expected intent record with tokens, got %+v", intentRec)
	}

	abortErr := errState.Fail("bucket_create", bkt, hostkit.AsCloudError(callErr))
	if abortErr == nil {
		t.Fatal("expected AbortError from errState.Fail")
	}
	last := errState.Last()
	for _, text := range []string{abortErr.Error(), last.Message, last.ProviderCode} {
		if strings.Contains(text, intentRec.CreateToken) {
			t.Fatalf("CreateToken %s leaked in diagnostic text %q", intentRec.CreateToken, text)
		}
		if strings.Contains(text, intentRec.OwnerNonce) {
			t.Fatalf("OwnerNonce %s leaked in diagnostic text %q", intentRec.OwnerNonce, text)
		}
		if !strings.Contains(text, hostkit.CreateTokenMarker) {
			t.Fatalf("expected %s marker in scrubbed text %q", hostkit.CreateTokenMarker, text)
		}
	}
}

func TestSafety_ScopeMismatchAmbiguousAndUnexpectedChildRetention(t *testing.T) {
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	store := sess.WrapStore(backend)

	bktAmb, _ := FormatLiveResourceName(runID, "amb", 1)
	bktChild, _ := FormatLiveResourceName(runID, "child", 2)

	if _, err := store.CreateBucket(ctx, bktAmb); err != nil {
		t.Fatalf("CreateBucket bktAmb: %v", err)
	}
	if _, err := store.CreateBucket(ctx, bktChild); err != nil {
		t.Fatalf("CreateBucket bktChild: %v", err)
	}
	if _, err := store.PutObject(ctx, bktChild, "owned-obj", []byte("ok"), "text/plain", nil); err != nil {
		t.Fatalf("PutObject owned-obj: %v", err)
	}
	// Seed an unexpected unjournaled child object inside bktChild.
	backend.SeedObject(bktChild, "unexpected-foreign-obj", []byte("foreign"), map[string]string{})
	// Mark bktAmb as returning an ambiguous 404 NotAuthorizedOrNotFound.
	backend.SetAmbiguous(KindBucket, "", bktAmb, true)

	_ = sess.Close()

	// 1. Scope mismatch during Sweep is refused before touching any resource.
	backend.SetIdentity("999999999999", "arn:aws:iam::999999999999:role/other", "us-east-1")
	if _, err := Sweep(ctx, backend, SweepOptions{
		JournalDir: pol.JournalDir,
		RunID:      runID,
		Policy:     &pol,
		Apply:      true,
	}); err == nil {
		t.Fatal("expected Sweep to refuse mismatched caller identity/account")
	}

	// Restore valid identity.
	backend.SetIdentity("254332045686", "arn:aws:iam::254332045686:role/awsspot-admin", "us-east-1")

	// 2. Active sweep deletes owned-obj, retains bktChild (due to unexpected-foreign-obj),
	// and retains bktAmb (due to AbsenceAmbiguous).
	rep, err := Sweep(ctx, backend, SweepOptions{
		JournalDir: pol.JournalDir,
		RunID:      runID,
		Policy:     &pol,
		Apply:      true,
	})
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if len(rep.Deleted) != 1 || rep.Deleted[0].Name != "owned-obj" {
		t.Fatalf("expected only owned-obj deleted, got %+v", rep.Deleted)
	}
	if len(rep.Retained) != 2 {
		t.Fatalf("expected 2 retained buckets (bktAmb and bktChild), got %+v", rep.Retained)
	}
	if !backend.HasBucket(bktAmb) || !backend.HasBucket(bktChild) || !backend.HasObject(bktChild, "unexpected-foreign-obj") {
		t.Fatal("expected retained buckets and unexpected child object to remain untouched")
	}
}

func TestSafety_DryRunDefaultAsyncPollingAndIdempotentSecondSweep(t *testing.T) {
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)
	backend.SetAsyncDeletePolls(3)

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	store := sess.WrapStore(backend)
	bkt, _ := FormatLiveResourceName(runID, "async", 1)
	if _, err := store.CreateBucket(ctx, bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	_ = sess.Close()

	// 1. Default SweepOptions (Apply: false) runs in dry-run mode and makes zero deletes.
	dryRep, err := Sweep(ctx, backend, SweepOptions{
		JournalDir: pol.JournalDir,
		RunID:      runID,
		Policy:     &pol,
	})
	if err != nil {
		t.Fatalf("dry-run Sweep: %v", err)
	}
	if !dryRep.DryRun || len(dryRep.WouldDelete) != 1 || len(dryRep.Deleted) != 0 {
		t.Fatalf("unexpected dry-run report: %+v", dryRep)
	}
	if !backend.HasBucket(bkt) || len(backend.DeleteLog()) != 0 {
		t.Fatal("dry-run Sweep mutated backend state")
	}

	// 2. Apply mode polls PollDelete 3 times before writing the deleted tombstone.
	applyRep, err := Sweep(ctx, backend, SweepOptions{
		JournalDir:   pol.JournalDir,
		RunID:        runID,
		Policy:       &pol,
		Apply:        true,
		PollAttempts: 5,
		PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatalf("apply Sweep: %v", err)
	}
	if len(applyRep.Deleted) != 1 || backend.HasBucket(bkt) {
		t.Fatalf("expected bucket deleted after async poll convergence, got %+v", applyRep)
	}

	// 3. Second sweep on the already-swept journal is a clean idempotent no-op.
	rep2, err := Sweep(ctx, backend, SweepOptions{
		JournalDir: pol.JournalDir,
		RunID:      runID,
		Policy:     &pol,
		Apply:      true,
	})
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if len(rep2.Deleted) != 0 || len(rep2.Failed) != 0 {
		t.Fatalf("expected idempotent empty second sweep, got %+v", rep2)
	}
}

func TestSafety_SubprocessKill9CrashAndCrossProcessSweep(t *testing.T) {
	ctx := context.Background()
	tmp := t.TempDir()
	journalDir := filepath.Join(tmp, "journals")
	statePath := filepath.Join(tmp, "fake-cloud.json")
	pol := DefaultAWSLivePolicy(journalDir, true)
	runID := NewRunID(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))

	// Seed an unowned sibling bucket in the persistent fake cloud before spawning the child.
	backend, err := NewPersistentFakeRecoveryBackend(
		statePath,
		"aws",
		"254332045686",
		"arn:aws:iam::254332045686:role/awsspot-admin",
		"us-east-1",
	)
	if err != nil {
		t.Fatalf("NewPersistentFakeRecoveryBackend: %v", err)
	}
	unownedSibling, _ := FormatLiveResourceName(runID, "sibling", 99)
	backend.SeedBucket(unownedSibling, map[string]string{
		TagKeyRunID:       NewRunID(time.Unix(1711111111, 0)),
		TagKeyOwnerNonce:  NewToken128(),
		TagKeyCreateToken: NewToken128(),
	}, "254332045686", "arn:aws:iam::254332045686:role/awsspot-admin")

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_Kill9Child$")
	cmd.Env = append(os.Environ(),
		"LMCLOUD_SAFETY_HELPER=kill9",
		"LMCLOUD_SAFETY_JOURNAL_DIR="+journalDir,
		"LMCLOUD_SAFETY_STATE_PATH="+statePath,
		"LMCLOUD_SAFETY_RUN_ID="+runID,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected child process to exit via SIGKILL, but it exited 0: %s", out)
	}

	// Verify child created bkt1, obj1, and q1 before SIGKILL.
	bkt1, _ := FormatLiveResourceName(runID, "bkt", 1)
	bkt2, _ := FormatLiveResourceName(runID, "bkt", 2)
	q1, _ := FormatLiveResourceName(runID, "que", 1)

	if !backend.HasBucket(bkt1) || !backend.HasObject(bkt1, "obj1") || !backend.HasQueue(q1) {
		t.Fatalf("expected bkt1, obj1, q1 to exist after child SIGKILL (child output: %s)", out)
	}

	// Now sweep from the parent process (simulating recovery after SIGKILL released the flock lease).
	rep, err := Sweep(ctx, backend, SweepOptions{
		JournalDir: journalDir,
		RunID:      runID,
		Policy:     &pol,
		Apply:      true,
		ScanPrefix: true,
	})
	if err != nil {
		t.Fatalf("parent recovery Sweep after child SIGKILL: %v", err)
	}
	if !rep.Clean() {
		t.Fatalf("expected clean sweep report, got Failed=%+v", rep.Failed)
	}
	if len(rep.Deleted) != 3 {
		t.Fatalf("expected 3 deleted items (obj1, bkt1, q1), got %+v", rep.Deleted)
	}
	// Verify LIFO order: obj1 was deleted before bkt1.
	if rep.Deleted[0].Kind != KindObject || rep.Deleted[0].Name != "obj1" {
		t.Fatalf("expected first deleted item to be obj1 (LIFO), got %+v", rep.Deleted)
	}
	// Verify bkt2 (which had only a pending intent and was never created) was classified Absent.
	if len(rep.Absent) != 1 || rep.Absent[0].Name != bkt2 {
		t.Fatalf("expected pending uncreated bkt2 in Absent, got %+v", rep.Absent)
	}
	// Verify unowned sibling was reported in UnownedSkipped and NEVER deleted.
	if len(rep.UnownedSkipped) != 1 || rep.UnownedSkipped[0].Name != unownedSibling {
		t.Fatalf("expected unownedSibling in UnownedSkipped, got %+v", rep.UnownedSkipped)
	}
	if !backend.HasBucket(unownedSibling) {
		t.Fatal("unowned sibling bucket was deleted during recovery sweep!")
	}
	if backend.HasBucket(bkt1) || backend.HasQueue(q1) {
		t.Fatal("owned resources still exist after recovery sweep")
	}
}

func TestHelperProcess_Kill9Child(t *testing.T) {
	if os.Getenv("LMCLOUD_SAFETY_HELPER") != "kill9" {
		return
	}
	ctx := context.Background()
	journalDir := os.Getenv("LMCLOUD_SAFETY_JOURNAL_DIR")
	statePath := os.Getenv("LMCLOUD_SAFETY_STATE_PATH")
	runID := os.Getenv("LMCLOUD_SAFETY_RUN_ID")

	pol := DefaultAWSLivePolicy(journalDir, true)
	backend, err := NewPersistentFakeRecoveryBackend(
		statePath,
		"aws",
		"254332045686",
		"arn:aws:iam::254332045686:role/awsspot-admin",
		"us-east-1",
	)
	if err != nil {
		t.Fatalf("NewPersistentFakeRecoveryBackend: %v", err)
	}
	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	store := sess.WrapStore(backend)
	queue := sess.WrapQueue(backend)

	bkt1, _ := FormatLiveResourceName(runID, "bkt", 1)
	bkt2, _ := FormatLiveResourceName(runID, "bkt", 2)
	q1, _ := FormatLiveResourceName(runID, "que", 1)

	if _, err := store.CreateBucket(ctx, bkt1); err != nil {
		t.Fatalf("CreateBucket bkt1: %v", err)
	}
	if _, err := store.PutObject(ctx, bkt1, "obj1", []byte("crash-data"), "text/plain", nil); err != nil {
		t.Fatalf("PutObject obj1: %v", err)
	}
	if _, err := queue.CreateQueue(ctx, q1); err != nil {
		t.Fatalf("CreateQueue q1: %v", err)
	}
	// Write a pending intent for bkt2 right before crashing with SIGKILL.
	if _, err := sess.Journal().BeginCreate(KindBucket, "", "us-east-1", bkt2, 5000); err != nil {
		t.Fatalf("BeginCreate bkt2: %v", err)
	}

	_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
}

func TestSafety_SubprocessDiskFullRlimitFailsClosedBeforeCloudCreate(t *testing.T) {
	tmp := t.TempDir()
	journalDir := filepath.Join(tmp, "journals")
	statePath := filepath.Join(tmp, "fake-cloud.json")
	runID := NewRunID(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess_DiskFullChild$")
	cmd.Env = append(os.Environ(),
		"LMCLOUD_SAFETY_HELPER=diskfull",
		"LMCLOUD_SAFETY_JOURNAL_DIR="+journalDir,
		"LMCLOUD_SAFETY_STATE_PATH="+statePath,
		"LMCLOUD_SAFETY_RUN_ID="+runID,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("diskfull helper subprocess failed: %v\noutput: %s", err, out)
	}

	// Verify zero cloud resources were created when the journal write failed under RLIMIT_FSIZE.
	backend, err := NewPersistentFakeRecoveryBackend(
		statePath,
		"aws",
		"254332045686",
		"arn:aws:iam::254332045686:role/awsspot-admin",
		"us-east-1",
	)
	if err != nil {
		t.Fatalf("NewPersistentFakeRecoveryBackend: %v", err)
	}
	bkt1, _ := FormatLiveResourceName(runID, "bkt", 1)
	if backend.HasBucket(bkt1) {
		t.Fatal("cloud bucket was created despite journal write failure under RLIMIT_FSIZE!")
	}

	// Verify parent can cleanly load and reopen the journal (truncating any partial tail).
	jPath, err := JournalPath(journalDir, runID)
	if err != nil {
		t.Fatalf("JournalPath: %v", err)
	}
	st, err := LoadJournal(jPath)
	if err != nil {
		t.Fatalf("LoadJournal after diskfull child: %v", err)
	}
	if len(st.Entries) != 0 {
		t.Fatalf("expected 0 committed entries after diskfull write refusal, got %+v", st.Entries)
	}
}

func TestHelperProcess_DiskFullChild(t *testing.T) {
	if os.Getenv("LMCLOUD_SAFETY_HELPER") != "diskfull" {
		return
	}
	// Ignore SIGXFSZ so exceeding RLIMIT_FSIZE returns EFBIG from Write()
	// instead of terminating the process with a signal.
	ignoreSIGXFSZ()

	ctx := context.Background()
	journalDir := os.Getenv("LMCLOUD_SAFETY_JOURNAL_DIR")
	statePath := os.Getenv("LMCLOUD_SAFETY_STATE_PATH")
	runID := os.Getenv("LMCLOUD_SAFETY_RUN_ID")

	pol := DefaultAWSLivePolicy(journalDir, true)
	backend, err := NewPersistentFakeRecoveryBackend(
		statePath,
		"aws",
		"254332045686",
		"arn:aws:iam::254332045686:role/awsspot-admin",
		"us-east-1",
	)
	if err != nil {
		t.Fatalf("NewPersistentFakeRecoveryBackend: %v", err)
	}
	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()
	store := sess.WrapStore(backend)

	// Clamp RLIMIT_FSIZE to the current journal header size + 32 bytes so the
	// very next `intent` record write fails with EFBIG / short write mid-line.
	fi, err := os.Stat(sess.Journal().Path())
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	limit := uint64(fi.Size() + 32)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: limit, Max: limit}); err != nil {
		t.Fatalf("Setrlimit RLIMIT_FSIZE: %v", err)
	}

	bkt1, _ := FormatLiveResourceName(runID, "bkt", 1)
	if _, err := store.CreateBucket(ctx, bkt1); err == nil {
		t.Fatal("expected CreateBucket to fail when journal write hits RLIMIT_FSIZE")
	} else if ce := hostkit.AsCloudError(err); ce.ProviderCode != "JournalWriteFailed" {
		t.Fatalf("expected JournalWriteFailed, got %+v", ce)
	}
}

func TestSafety_SupervisorMultiInvocationCampaign(t *testing.T) {
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)

	sup, err := NewSupervisor(SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	bkt, _ := FormatLiveResourceName(runID, "camp", 1)
	que, _ := FormatLiveResourceName(runID, "campq", 1)

	// Invocation 1: create bucket and put object.
	if err := sup.RunInvocation(ctx, func(ctx context.Context, sess *Session) error {
		s := sess.WrapStore(backend)
		if _, err := s.CreateBucket(ctx, bkt); err != nil {
			return err
		}
		_, err := s.PutObject(ctx, bkt, "step1", []byte("from-inv-1"), "text/plain", nil)
		return err
	}); err != nil {
		t.Fatalf("RunInvocation 1: %v", err)
	}

	// Invocation 2: re-opens the same journal, sees bkt as owned, reads object, creates queue.
	if err := sup.RunInvocation(ctx, func(ctx context.Context, sess *Session) error {
		s := sess.WrapStore(backend)
		q := sess.WrapQueue(backend)
		got, err := s.GetObject(ctx, bkt, "step1", 1024)
		if err != nil || string(got) != "from-inv-1" {
			return errors.New("failed to read step1 from invocation 1")
		}
		_, err = q.CreateQueue(ctx, que)
		return err
	}); err != nil {
		t.Fatalf("RunInvocation 2: %v", err)
	}

	// FinishCampaign sweeps everything in LIFO order.
	rep, err := sup.FinishCampaign(ctx)
	if err != nil {
		t.Fatalf("FinishCampaign: %v", err)
	}
	if !rep.Clean() || len(rep.Deleted) != 3 {
		t.Fatalf("expected 3 deleted items in campaign sweep, got %+v", rep)
	}
	if backend.HasBucket(bkt) || backend.HasQueue(que) {
		t.Fatal("expected all campaign resources deleted")
	}
}

func TestSafety_RetainedResourceNeverReAdoptedAndSurvivesCompaction(t *testing.T) {
	// HIGH 3 & MEDIUM 4 regression test:
	// Simulates an S3 us-east-1 adapter that runs PutBucketTagging after a duplicate
	// CreateBucket. Once a resource is marked Retained (either via Sweep/Retain or
	// post-create collision), subsequent CreateBucket/CreateQueue must NEVER dispatch
	// to the adapter, Retain must survive Journal.Confirm and Journal.Compact, and
	// Guard DeleteBucket/DeleteQueue/DeleteObject must refuse deletion.
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)
	backend.SetOverwriteTagsOnDuplicateCreate(true)

	foreignBkt, _ := FormatLiveResourceName(runID, "retbkt", 1)
	foreignQue, _ := FormatLiveResourceName(runID, "retque", 1)
	foreignNonce := NewToken128()
	foreignToken := NewToken128()

	backend.SeedBucket(foreignBkt, map[string]string{
		TagKeyRunID:       NewRunID(time.Unix(1712000000, 0)),
		TagKeyOwnerNonce:  foreignNonce,
		TagKeyCreateToken: foreignToken,
	}, "254332045686", "arn:aws:iam::254332045686:role/awsspot-admin")
	backend.SeedQueue(foreignQue, map[string]string{
		TagKeyRunID:       NewRunID(time.Unix(1712000000, 0)),
		TagKeyOwnerNonce:  foreignNonce,
		TagKeyCreateToken: foreignToken,
	}, "254332045686", "arn:aws:iam::254332045686:role/awsspot-admin")

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()
	store := sess.WrapStore(backend)
	queue := sess.WrapQueue(backend)

	// Pre-retain foreignBkt (as if an earlier sweep retained an ambiguous/foreign bucket).
	if err := sess.Journal().Retain(KindBucket, "", foreignBkt, "ambiguous foreign bucket"); err != nil {
		t.Fatalf("Journal.Retain: %v", err)
	}

	// 1. Calling CreateBucket on a retained bucket must be refused BEFORE calling the
	// backend (which would otherwise overwrite its tags because OverwriteTagsOnDuplicateCreate=true).
	if _, err := store.CreateBucket(ctx, foreignBkt); err == nil {
		t.Fatal("expected CreateBucket on retained bucket to fail closed")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.Conflict || ce.ProviderCode != "ForeignResourceCollision" {
		t.Fatalf("expected ForeignResourceCollision on retained bucket, got %+v", ce)
	}

	// Verify foreignBkt's tags in the backend were NOT overwritten.
	ro, err := backend.ReadOwnership(ctx, ResourceRef{Kind: KindBucket, Name: foreignBkt})
	if err != nil || ro.OwnerNonce != foreignNonce {
		t.Fatalf("retained bucket tags were overwritten! ro=%+v err=%v", ro, err)
	}

	// 2. First CreateQueue on foreignQue collides and records Retain in the journal (MEDIUM 4).
	backend.SetOverwriteTagsOnDuplicateCreate(false)
	if _, err := queue.CreateQueue(ctx, foreignQue); err == nil {
		t.Fatal("expected first CreateQueue on foreign queue to fail")
	}
	qEntry, ok := sess.Journal().Lookup(KindQueue, "", foreignQue)
	if !ok || qEntry.State != StateRetained || !qEntry.Retain {
		t.Fatalf("expected foreignQue to be marked StateRetained after collision, got %+v", qEntry)
	}
	// Even if we now enable OverwriteTagsOnDuplicateCreate, a second CreateQueue is blocked
	// at the journal check before reaching the adapter.
	backend.SetOverwriteTagsOnDuplicateCreate(true)
	if _, err := queue.CreateQueue(ctx, foreignQue); err == nil {
		t.Fatal("expected second CreateQueue on retained queue to fail")
	}

	// 3. Direct Journal.Confirm on a retained entry must fail and keep Retain sticky.
	if err := sess.Journal().Confirm(KindBucket, "", foreignBkt, ConfirmDetails{ProviderID: "id"}); err == nil {
		t.Fatal("expected Journal.Confirm on retained entry to be refused")
	}
	// Compact the journal and verify StateRetained and Retain:true survive compaction.
	if err := sess.Journal().Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	bEntry, ok := sess.Journal().Lookup(KindBucket, "", foreignBkt)
	if !ok || bEntry.State != StateRetained || !bEntry.Retain {
		t.Fatalf("expected StateRetained and Retain:true to survive compaction, got %+v", bEntry)
	}

	// 4. Guard deletes must refuse retained buckets, queues, and objects.
	if err := store.DeleteBucket(ctx, foreignBkt); err == nil {
		t.Fatal("expected DeleteBucket on retained bucket to be refused")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.PermissionDenied || ce.ProviderCode != "RetainedResourceDeleteRefused" {
		t.Fatalf("expected RetainedResourceDeleteRefused, got %+v", ce)
	}
	if err := queue.DeleteQueue(ctx, foreignQue); err == nil {
		t.Fatal("expected DeleteQueue on retained queue to be refused")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.PermissionDenied || ce.ProviderCode != "RetainedResourceDeleteRefused" {
		t.Fatalf("expected RetainedResourceDeleteRefused, got %+v", ce)
	}

	// Also test an owned object that becomes retained: DeleteObject must refuse it.
	ownedBkt, _ := FormatLiveResourceName(runID, "owned", 2)
	if _, err := store.CreateBucket(ctx, ownedBkt); err != nil {
		t.Fatalf("CreateBucket ownedBkt: %v", err)
	}
	if _, err := store.PutObject(ctx, ownedBkt, "ret-obj", []byte("data"), "text/plain", nil); err != nil {
		t.Fatalf("PutObject ret-obj: %v", err)
	}
	if err := sess.Journal().Retain(KindObject, ownedBkt, "ret-obj", "manual quarantine"); err != nil {
		t.Fatalf("Retain ret-obj: %v", err)
	}
	if err := store.DeleteObject(ctx, ownedBkt, "ret-obj"); err == nil {
		t.Fatal("expected DeleteObject on retained object to be refused")
	} else if ce := hostkit.AsCloudError(err); ce.ProviderCode != "RetainedResourceDeleteRefused" {
		t.Fatalf("expected RetainedResourceDeleteRefused for object, got %+v", ce)
	}

	// 5. FinishAndSweep retains foreignBkt, foreignQue, ret-obj, and ownedBkt (since ret-obj is inside it).
	rep, err := sess.FinishAndSweep(ctx)
	if err != nil {
		t.Fatalf("FinishAndSweep: %v", err)
	}
	if !backend.HasBucket(foreignBkt) || !backend.HasQueue(foreignQue) || !backend.HasObject(ownedBkt, "ret-obj") {
		t.Fatalf("retained resources were deleted during sweep! rep=%+v", rep)
	}
}

func TestSafety_QueueAckIsOrdinaryWorkAndGetObjectClampsLimit(t *testing.T) {
	// MEDIUM 5 & MEDIUM 7 regression test.
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)
	pol.Limits.MaxObjectBytes = 16

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()
	store := sess.WrapStore(backend)
	queue := sess.WrapQueue(backend)

	bkt, _ := FormatLiveResourceName(runID, "bkt", 1)
	que, _ := FormatLiveResourceName(runID, "que", 1)
	if _, err := store.CreateBucket(ctx, bkt); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if _, err := queue.CreateQueue(ctx, que); err != nil {
		t.Fatalf("CreateQueue: %v", err)
	}
	if _, err := queue.Send(ctx, que, "msg"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	msgs, err := queue.Receive(ctx, que, 1, 0, 30)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("Receive: %v", err)
	}

	// Seed a 32-byte object directly in the backend (exceeding MaxObjectBytes = 16)
	// with valid ownership metadata so GetObject reaches the size guard.
	bEntry, _ := sess.Journal().Lookup(KindBucket, "", bkt)
	_, _ = sess.Journal().BeginCreate(KindObject, bkt, "us-east-1", "big-obj", 1000)
	_ = sess.Journal().Confirm(KindObject, bkt, "big-obj", ConfirmDetails{ProviderID: "etag"})
	objEntry, _ := sess.Journal().Lookup(KindObject, bkt, "big-obj")
	backend.SeedObject(bkt, "big-obj", []byte("0123456789abcdef0123456789abcdef"), map[string]string{
		TagKeyRunID:       runID,
		TagKeyOwnerNonce:  objEntry.OwnerNonce,
		TagKeyCreateToken: objEntry.CreateToken,
	})
	_ = bEntry

	// MEDIUM 7: GetObject with limit=0 or limit=1024 must clamp to MaxObjectBytes (16)
	// and fail closed because the object is 32 bytes.
	for _, reqLimit := range []int64{0, 1024} {
		if _, err := store.GetObject(ctx, bkt, "big-obj", reqLimit); err == nil {
			t.Fatalf("expected GetObject(limit=%d) on oversized object to fail", reqLimit)
		}
	}

	// MEDIUM 5: Exhaust the $0.04 work budget (leaving only the $0.01 cleanup reserve).
	// Queue.Ack must be rejected with LiveCostCapExceeded because it is ordinary work,
	// NOT cleanup reserve.
	sess.Meter().RestoreCharged(39_999_900, 2_000)
	if err := queue.Ack(ctx, que, msgs[0].Receipt); err == nil {
		t.Fatal("expected Queue.Ack to be refused when work budget is exhausted")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.PermissionDenied || ce.ProviderCode != "LiveCostCapExceeded" {
		t.Fatalf("expected LiveCostCapExceeded from Queue.Ack, got %+v", ce)
	}
}

func TestSafety_MandatoryChildListingFailClosed(t *testing.T) {
	// MEDIUM 8 regression test:
	// Both GuardStore.DeleteBucket and Sweep must fail closed (refuse delete / retain)
	// when RemoteOwnership.ChildrenVerified is false or when ChildKeys is non-empty.
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer sess.Close()
	store := sess.WrapStore(backend)

	bktUnverified, _ := FormatLiveResourceName(runID, "unver", 1)
	bktNonEmpty, _ := FormatLiveResourceName(runID, "nonemp", 2)
	if _, err := store.CreateBucket(ctx, bktUnverified); err != nil {
		t.Fatalf("CreateBucket bktUnverified: %v", err)
	}
	if _, err := store.CreateBucket(ctx, bktNonEmpty); err != nil {
		t.Fatalf("CreateBucket bktNonEmpty: %v", err)
	}
	if _, err := store.PutObject(ctx, bktNonEmpty, "child1", []byte("hi"), "text/plain", nil); err != nil {
		t.Fatalf("PutObject child1: %v", err)
	}

	// 1. DeleteBucket on non-empty bucket is refused before calling adapter.
	if err := store.DeleteBucket(ctx, bktNonEmpty); err == nil {
		t.Fatal("expected DeleteBucket on non-empty bucket to fail")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.Conflict || ce.ProviderCode != "BucketNotEmpty" {
		t.Fatalf("expected BucketNotEmpty, got %+v", ce)
	}

	// 2. Mark bktUnverified as having unverified children (ChildrenVerified=false).
	backend.SetUnverifiedChildren(bktUnverified, true)
	if err := store.DeleteBucket(ctx, bktUnverified); err == nil {
		t.Fatal("expected DeleteBucket with ChildrenVerified=false to fail closed")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.PermissionDenied || ce.ProviderCode != "ChildListingRequired" {
		t.Fatalf("expected ChildListingRequired, got %+v", ce)
	}

	// 3. FinishAndSweep deletes child1 and bktNonEmpty, but RETAINS bktUnverified.
	rep, err := sess.FinishAndSweep(ctx)
	if err != nil {
		t.Fatalf("FinishAndSweep: %v", err)
	}
	if len(rep.Retained) != 1 || rep.Retained[0].Name != bktUnverified {
		t.Fatalf("expected bktUnverified in Retained, got %+v", rep.Retained)
	}
	if !backend.HasBucket(bktUnverified) {
		t.Fatal("bktUnverified was deleted despite ChildrenVerified=false!")
	}
	if backend.HasBucket(bktNonEmpty) {
		t.Fatal("expected bktNonEmpty to be swept after its owned child1 was deleted")
	}
}

func TestSafety_PersistedCampaignLimitsAcrossInvocationsAndCompaction(t *testing.T) {
	// MEDIUM 9 regression test:
	// Campaign limits (MaxRunSeconds, MaxBuckets, MaxMessages, MaxTotalBytes) must
	// persist in the journal across Supervisor.RunInvocation calls and Compact().
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)
	pol.Limits.MaxBuckets = 2
	pol.Limits.MaxMessages = 2
	pol.Limits.MaxTotalBytes = 20
	pol.Limits.MaxRunSeconds = 60

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	sup, err := NewSupervisor(SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewSupervisor: %v", err)
	}

	bkt1, _ := FormatLiveResourceName(runID, "bkt", 1)
	bkt2, _ := FormatLiveResourceName(runID, "bkt", 2)
	bkt3, _ := FormatLiveResourceName(runID, "bkt", 3)
	que1, _ := FormatLiveResourceName(runID, "que", 1)

	// Invocation 1: create bkt1, delete bkt1 (cumulative BucketsCreated is still 1!),
	// create que1, send 2 messages of 8 bytes each (total 16 bytes), and compact.
	if err := sup.RunInvocation(ctx, func(ctx context.Context, sess *Session) error {
		s := sess.WrapStore(backend)
		q := sess.WrapQueue(backend)
		if _, err := s.CreateBucket(ctx, bkt1); err != nil {
			return err
		}
		if err := s.DeleteBucket(ctx, bkt1); err != nil {
			return err
		}
		if _, err := q.CreateQueue(ctx, que1); err != nil {
			return err
		}
		if _, err := q.Send(ctx, que1, "12345678"); err != nil {
			return err
		}
		if _, err := q.Send(ctx, que1, "87654321"); err != nil {
			return err
		}
		return sess.Journal().Compact()
	}); err != nil {
		t.Fatalf("Invocation 1: %v", err)
	}

	// Invocation 2 (10s later):
	// - Creating bkt2 succeeds (cumulative BucketsCreated = 2 == MaxBuckets).
	// - Creating bkt3 fails (BucketsCreated would be 3 > MaxBuckets).
	// - Sending a 3rd message fails (MessagesSent = 2 == MaxMessages).
	// - Putting a 10-byte object fails (TotalPayloadBytes 16 + 10 > MaxTotalBytes 20).
	now = now.Add(10 * time.Second)
	if err := sup.RunInvocation(ctx, func(ctx context.Context, sess *Session) error {
		s := sess.WrapStore(backend)
		q := sess.WrapQueue(backend)
		if _, err := s.CreateBucket(ctx, bkt2); err != nil {
			return err
		}
		if _, err := s.CreateBucket(ctx, bkt3); err == nil {
			t.Fatal("expected 3rd bucket create across invocations to fail MaxBuckets=2")
		}
		if _, err := q.Send(ctx, que1, "x"); err == nil {
			t.Fatal("expected 3rd message send across invocations to fail MaxMessages=2")
		}
		if _, err := s.PutObject(ctx, bkt2, "k", []byte("0123456789"), "text/plain", nil); err == nil {
			t.Fatal("expected PutObject exceeding cumulative MaxTotalBytes=20 across invocations to fail")
		}
		return nil
	}); err != nil {
		t.Fatalf("Invocation 2: %v", err)
	}

	// Invocation 3 (65s after Invocation 1 start, exceeding MaxRunSeconds=60):
	// Any guarded operation must fail with LiveRunDeadlineExceeded.
	now = now.Add(55 * time.Second)
	if err := sup.RunInvocation(ctx, func(ctx context.Context, sess *Session) error {
		s := sess.WrapStore(backend)
		if _, err := s.ListObjects(ctx, bkt2, "", 10, ""); err == nil {
			t.Fatal("expected operation after cumulative MaxRunSeconds=60 to fail")
		} else if ce := hostkit.AsCloudError(err); ce.ProviderCode != "LiveRunDeadlineExceeded" {
			t.Fatalf("expected LiveRunDeadlineExceeded, got %+v", ce)
		}
		return nil
	}); err != nil {
		t.Fatalf("Invocation 3: %v", err)
	}

	if _, err := sup.FinishCampaign(ctx); err != nil {
		t.Fatalf("FinishCampaign: %v", err)
	}
}

func TestSafety_PendingGracePeriodFindOwnedErrorAndCrashReservationRestore(t *testing.T) {
	// LOW 10, LOW 11, LOW 12 regression test.
	ctx := context.Background()
	pol, runID, backend := newTestSetup(t)
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	sess, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	bktPending, _ := FormatLiveResourceName(runID, "pend", 1)
	if _, err := sess.Journal().BeginCreate(KindBucket, "", "us-east-1", bktPending, 12_345_000); err != nil {
		t.Fatalf("BeginCreate: %v", err)
	}
	_ = sess.Close()

	// LOW 12: Re-opening the session with an unresolved StatePending entry must
	// include its 12_345_000 nano-USD reservation in the restored CostMeter.
	sess2, err := OpenSession(ctx, SessionConfig{
		Policy:   pol,
		RunID:    runID,
		Recovery: backend,
		Now:      func() time.Time { return now.Add(2 * time.Second) },
	})
	if err != nil {
		t.Fatalf("OpenSession 2: %v", err)
	}
	if got := sess2.Meter().Snapshot().ChargedNanoUSD; got < 12_345_000 {
		t.Fatalf("expected restored CostMeter to include pending reservation 12_345_000, got %d", got)
	}
	_ = sess2.Close()

	// LOW 10: Sweeping 2 seconds after IntentAtUnix (within the 10s MaxRequestTimeout grace window)
	// reports bktPending in Absent but keeps it in StatePending in the journal.
	repGrace, err := Sweep(ctx, backend, SweepOptions{
		JournalDir: pol.JournalDir,
		RunID:      runID,
		Policy:     &pol,
		Apply:      true,
		Now:        func() time.Time { return now.Add(2 * time.Second) },
	})
	if err != nil {
		t.Fatalf("Sweep within grace period: %v", err)
	}
	if len(repGrace.Absent) != 1 || repGrace.Absent[0].Name != bktPending {
		t.Fatalf("expected bktPending in Absent during grace window, got %+v", repGrace)
	}
	stGrace, err := LoadJournal(filepath.Join(pol.JournalDir, runID+".jsonl"))
	if err != nil {
		t.Fatalf("LoadJournal after grace sweep: %v", err)
	}
	if e, ok := stGrace.Lookup(KindBucket, "", bktPending); !ok || e.State != StatePending {
		t.Fatalf("expected bktPending to remain StatePending during grace window, got %+v", e)
	}

	// LOW 11: If FindOwned fails during prefix discovery, Sweep records it in rep.Failed (Clean() == false).
	backend.SetFindOwnedError(errors.New("simulated list-buckets failure"))
	repFail, err := Sweep(ctx, backend, SweepOptions{
		JournalDir: pol.JournalDir,
		RunID:      runID,
		Policy:     &pol,
		Apply:      true,
		ScanPrefix: true,
		Now:        func() time.Time { return now.Add(2 * time.Second) },
	})
	if err != nil {
		t.Fatalf("Sweep with FindOwnedError: %v", err)
	}
	if repFail.Clean() || len(repFail.Failed) == 0 {
		t.Fatalf("expected FindOwned error in rep.Failed, got %+v", repFail)
	}
	backend.SetFindOwnedError(nil)

	// Once Now advances past the 10s grace window (+15s), Sweep tombstones bktPending as StateDeleted
	// and compacts the journal (removing the deleted entry).
	repAfter, err := Sweep(ctx, backend, SweepOptions{
		JournalDir: pol.JournalDir,
		RunID:      runID,
		Policy:     &pol,
		Apply:      true,
		Now:        func() time.Time { return now.Add(15 * time.Second) },
	})
	if err != nil {
		t.Fatalf("Sweep after grace period: %v", err)
	}
	if !repAfter.Clean() || len(repAfter.Absent) != 1 {
		t.Fatalf("unexpected report after grace window: %+v", repAfter)
	}
	stAfter, err := LoadJournal(filepath.Join(pol.JournalDir, runID+".jsonl"))
	if err != nil {
		t.Fatalf("LoadJournal after post-grace sweep: %v", err)
	}
	if e, ok := stAfter.Lookup(KindBucket, "", bktPending); ok && e.State != StateDeleted {
		t.Fatalf("expected bktPending to be tombstoned/compacted after grace window, got %+v", e)
	}
}
