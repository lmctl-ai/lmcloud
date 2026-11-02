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

	// Pre-seed a bucket that shares this run's `lmcloud-conf-<run12>-` prefix
	// but was created by another run/principal (different owner_nonce / run_id).
	backend.SeedBucket(foreignBkt, map[string]string{
		TagKeyRunID:       NewRunID(time.Unix(1712000000, 0)),
		TagKeyOwnerNonce:  NewToken128(),
		TagKeyCreateToken: NewToken128(),
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

	// Attempting to CreateBucket on the colliding same-prefix bucket must fail
	// closed with CONFLICT (ForeignResourceCollision) and NOT adopt it.
	if _, err := store.CreateBucket(ctx, foreignBkt); err == nil {
		t.Fatal("expected CreateBucket on foreign same-prefix bucket to fail closed")
	} else if ce := hostkit.AsCloudError(err); ce.Code != hostkit.Conflict || ce.ProviderCode != "ForeignResourceCollision" {
		t.Fatalf("expected ForeignResourceCollision, got %+v", ce)
	}

	// Attempting PutObject or DeleteBucket on the foreign same-prefix bucket must
	// also be refused with PERMISSION_DENIED.
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
	if len(rep.UnownedSkipped) != 1 || rep.UnownedSkipped[0].Name != foreignBkt {
		t.Fatalf("expected foreignBkt in UnownedSkipped, got %+v", rep.UnownedSkipped)
	}
	if !backend.HasBucket(foreignBkt) {
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
