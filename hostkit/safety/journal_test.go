// SPDX-License-Identifier: MIT

package safety

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func sampleMeta(t *testing.T, dir string) (JournalMeta, string) {
	t.Helper()
	pol := DefaultAWSLivePolicy(dir, true)
	runID := NewRunID(time.Unix(1712880000, 0))
	meta := JournalMeta{
		RunID:      runID,
		SessionID:  "sess-1",
		PolicyHash: pol.Hash(),
		Provider:   "aws",
		Account:    "254332045686",
		Scope:      "arn:aws:iam::254332045686:role/awsspot-admin",
		Region:     "us-east-1",
		Endpoint:   "https://s3.us-east-1.amazonaws.com",
	}
	bkt, err := FormatLiveResourceName(runID, "bkt", 1)
	if err != nil {
		t.Fatalf("FormatLiveResourceName: %v", err)
	}
	return meta, bkt
}

func TestJournal_IntentConfirmDuplicateFailedAndCompaction(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journals")
	meta, bkt := sampleMeta(t, dir)

	j, err := OpenJournal(dir, meta)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()

	// 1. BeginCreate persists random 128-bit OwnerNonce and CreateToken.
	intent1, err := j.BeginCreate(KindBucket, "", "us-east-1", bkt, 5000)
	if err != nil {
		t.Fatalf("BeginCreate: %v", err)
	}
	if err := ValidateToken128(intent1.OwnerNonce); err != nil {
		t.Fatalf("OwnerNonce: %v", err)
	}
	if err := ValidateToken128(intent1.CreateToken); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if intent1.OwnerNonce == intent1.CreateToken {
		t.Fatal("expected distinct OwnerNonce and CreateToken")
	}

	// 2. Retry while still pending reuses persisted OwnerNonce and CreateToken.
	intentRetry, err := j.BeginCreate(KindBucket, "", "us-east-1", bkt, 0)
	if err != nil {
		t.Fatalf("BeginCreate retry: %v", err)
	}
	if intentRetry.OwnerNonce != intent1.OwnerNonce || intentRetry.CreateToken != intent1.CreateToken {
		t.Fatalf("retry tokens changed: got (%s, %s), want (%s, %s)",
			intentRetry.OwnerNonce, intentRetry.CreateToken, intent1.OwnerNonce, intent1.CreateToken)
	}

	// 3. Confirm transitions to StateConfirmed.
	if err := j.Confirm(KindBucket, "", bkt, ConfirmDetails{
		ProviderID:          "arn:aws:s3:::" + bkt,
		ConfirmedAtUnix:     1712880010,
		ServerCreatedAtUnix: 1712880009,
		ChargedNanoUSD:      5000,
	}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	// 4. Duplicate BeginCreate on an already-confirmed resource NEVER overwrites
	// OwnerNonce or CreateToken and sets AlreadyConfirmed=true.
	dupIntent, err := j.BeginCreate(KindBucket, "", "us-east-1", bkt, 0)
	if err != nil {
		t.Fatalf("duplicate BeginCreate: %v", err)
	}
	if !dupIntent.AlreadyConfirmed {
		t.Fatal("expected AlreadyConfirmed=true on duplicate BeginCreate")
	}
	if dupIntent.OwnerNonce != intent1.OwnerNonce || dupIntent.CreateToken != intent1.CreateToken {
		t.Fatal("duplicate BeginCreate altered tokens")
	}

	// 5. Failed after Confirm NEVER cancels the confirmed entry.
	if err := j.Failed(KindBucket, "", bkt, "BucketAlreadyOwnedByYou", 1000); err != nil {
		t.Fatalf("Failed after confirm: %v", err)
	}
	entry, ok := j.Lookup(KindBucket, "", bkt)
	if !ok || entry.State != StateConfirmed {
		t.Fatalf("confirmed entry lost after Failed: ok=%v entry=%+v", ok, entry)
	}

	// 6. Pending child object that fails is removed from active entries.
	if _, err := j.BeginCreate(KindObject, bkt, "us-east-1", "k1", 1000); err != nil {
		t.Fatalf("BeginCreate object: %v", err)
	}
	if err := j.Failed(KindObject, bkt, "k1", "InternalError", 1000); err != nil {
		t.Fatalf("Failed object: %v", err)
	}
	if _, ok := j.Lookup(KindObject, bkt, "k1"); ok {
		t.Fatal("expected pending object to be removed after Failed")
	}

	// 7. Compact preserves confirmed bucket and accumulated cost.
	if err := j.Compact(); err != nil {
		t.Fatalf("Compact: %v", err)
	}
	st, err := LoadJournal(j.Path())
	if err != nil {
		t.Fatalf("LoadJournal after Compact: %v", err)
	}
	if len(st.Entries) != 1 || st.Entries[0].Name != bkt || st.Entries[0].OwnerNonce != intent1.OwnerNonce {
		t.Fatalf("unexpected state after Compact: %+v", st.Entries)
	}
	if st.ChargedNanoUSD != 7000 {
		t.Fatalf("charged nano usd: got %d, want 7000", st.ChargedNanoUSD)
	}
}

func TestJournal_LeaseContention(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journals")
	meta, _ := sampleMeta(t, dir)

	j1, err := OpenJournal(dir, meta)
	if err != nil {
		t.Fatalf("OpenJournal 1: %v", err)
	}
	defer j1.Close()

	if _, err := OpenJournal(dir, meta); !errors.Is(err, ErrJournalLeaseBusy) {
		t.Fatalf("expected ErrJournalLeaseBusy on second OpenJournal, got %v", err)
	}
}

func TestJournal_TornTailTruncateAndMiddleCorruptionFatal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journals")
	meta, bkt := sampleMeta(t, dir)

	j, err := OpenJournal(dir, meta)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	intent, err := j.BeginCreate(KindBucket, "", "us-east-1", bkt, 5000)
	if err != nil {
		t.Fatalf("BeginCreate: %v", err)
	}
	path := j.Path()
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Append a torn final line (no trailing '\n').
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	if _, err := f.WriteString(`{"v":1,"seq":3,"event":"confirmed"`); err != nil {
		t.Fatalf("write torn tail: %v", err)
	}
	_ = f.Close()

	// LoadJournal tolerates the torn final line.
	st, err := LoadJournal(path)
	if err != nil {
		t.Fatalf("LoadJournal with torn tail: %v", err)
	}
	if len(st.Entries) != 1 || st.Entries[0].OwnerNonce != intent.OwnerNonce {
		t.Fatalf("unexpected entries after torn tail LoadJournal: %+v", st.Entries)
	}

	// OpenJournal truncates the torn final line and allows clean appends.
	j2, err := OpenJournal(dir, meta)
	if err != nil {
		t.Fatalf("OpenJournal with torn tail: %v", err)
	}
	if err := j2.Confirm(KindBucket, "", bkt, ConfirmDetails{ConfirmedAtUnix: 1712880020}); err != nil {
		t.Fatalf("Confirm after torn tail recovery: %v", err)
	}
	_ = j2.Close()

	// Corrupt a line in the middle (followed by '\n' and another valid line): must be fatal.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	lines[1] = `{"v":1,"seq":2,"corrupt":`
	corrupted := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(corrupted), 0o600); err != nil {
		t.Fatalf("WriteFile corrupted: %v", err)
	}
	if _, err := LoadJournal(path); err == nil {
		t.Fatal("expected middle line corruption to fail LoadJournal")
	}
}

func TestJournal_ForgedRecordsRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journals")
	meta, bkt := sampleMeta(t, dir)

	baseHeader := JournalRecord{
		Version:    JournalVersion,
		Seq:        1,
		Time:       "2026-04-12T00:00:00Z",
		Event:      EventMeta,
		RunID:      meta.RunID,
		PolicyHash: meta.PolicyHash,
		Provider:   meta.Provider,
		Account:    meta.Account,
		Scope:      meta.Scope,
		Region:     meta.Region,
	}
	validIntent := JournalRecord{
		Version:     JournalVersion,
		Seq:         2,
		Time:        "2026-04-12T00:00:01Z",
		Event:       EventIntent,
		RunID:       meta.RunID,
		PolicyHash:  meta.PolicyHash,
		Provider:    meta.Provider,
		Account:     meta.Account,
		Scope:       meta.Scope,
		Region:      meta.Region,
		Kind:        KindBucket,
		Name:        bkt,
		OwnerNonce:  NewToken128(),
		CreateToken: NewToken128(),
	}

	// 1. Unprefixed bucket name ("prod-data") in journal is rejected.
	forgedName := validIntent
	forgedName.Name = "prod-data"
	if _, err := ReplayJournal([]JournalRecord{baseHeader, forgedName}); err == nil {
		t.Fatal("expected unprefixed bucket in journal to be rejected")
	}

	// 2. Scope/account mismatch on record 2 is rejected.
	forgedAcct := validIntent
	forgedAcct.Account = "999999999999"
	if _, err := ReplayJournal([]JournalRecord{baseHeader, forgedAcct}); err == nil {
		t.Fatal("expected account mismatch in journal to be rejected")
	}

	// 3. Missing/invalid OwnerNonce is rejected.
	forgedNonce := validIntent
	forgedNonce.OwnerNonce = "short"
	if _, err := ReplayJournal([]JournalRecord{baseHeader, forgedNonce}); err == nil {
		t.Fatal("expected invalid owner_nonce in journal to be rejected")
	}

	// 4. Non-monotonic sequence number is rejected.
	forgedSeq := validIntent
	forgedSeq.Seq = 99
	if _, err := ReplayJournal([]JournalRecord{baseHeader, forgedSeq}); err == nil {
		t.Fatal("expected non-monotonic seq in journal to be rejected")
	}

	// 5. Raw `failed` record appended after `confirmed` never cancels `confirmed`.
	confirmedRec := validIntent
	confirmedRec.Seq = 3
	confirmedRec.Event = EventConfirmed
	failedRec := validIntent
	failedRec.Seq = 4
	failedRec.Event = EventFailed
	st, err := ReplayJournal([]JournalRecord{baseHeader, validIntent, confirmedRec, failedRec})
	if err != nil {
		t.Fatalf("ReplayJournal confirmed+failed: %v", err)
	}
	if len(st.Entries) != 1 || st.Entries[0].State != StateConfirmed {
		t.Fatalf("expected confirmed resource to survive subsequent failed record, got %+v", st.Entries)
	}
	_ = json.Marshal
}

func TestJournal_CompactionLeaseRace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journals")
	meta, bkt := sampleMeta(t, dir)

	j, err := OpenJournal(dir, meta)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()

	if _, err := j.BeginCreate(KindBucket, "", "us-east-1", bkt, 5000); err != nil {
		t.Fatalf("BeginCreate: %v", err)
	}
	if err := j.Confirm(KindBucket, "", bkt, ConfirmDetails{ConfirmedAtUnix: 1712880010, ChargedNanoUSD: 5000}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var stolenLeases int
	var unexpectedErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			j2, oerr := OpenJournal(dir, meta)
			if oerr == nil {
				stolenLeases++
				_ = j2.Close()
				return
			}
			if !errors.Is(oerr, ErrJournalLeaseBusy) {
				unexpectedErr = oerr
				return
			}
		}
	}()

	for i := 0; i < 350; i++ {
		if err := j.Compact(); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Compact iteration %d failed: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	if stolenLeases > 0 {
		t.Fatalf("concurrent OpenJournal stole lease %d time(s) during Compact", stolenLeases)
	}
	if unexpectedErr != nil {
		t.Fatalf("concurrent OpenJournal returned unexpected error: %v", unexpectedErr)
	}

	// Verify appends after 350 compactions land in the live journal file on disk.
	bkt2, _ := FormatLiveResourceName(meta.RunID, "bkt", 2)
	if _, err := j.BeginCreate(KindBucket, "", "us-east-1", bkt2, 5000); err != nil {
		t.Fatalf("BeginCreate bkt2 after compactions: %v", err)
	}
	st, err := LoadJournal(j.Path())
	if err != nil {
		t.Fatalf("LoadJournal after compactions: %v", err)
	}
	if _, ok := st.Lookup(KindBucket, "", bkt2); !ok {
		t.Fatalf("expected bkt2 in journal on disk after compactions, got %+v", st.Entries)
	}
}

func TestJournal_WriteFailurePoisonsAndPreservesIntegrity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journals")
	meta, bkt1 := sampleMeta(t, dir)
	bkt2, _ := FormatLiveResourceName(meta.RunID, "bkt", 2)

	j, err := OpenJournal(dir, meta)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	defer j.Close()

	var origLim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &origLim); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	defer func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &origLim)
	}()

	fi, err := os.Stat(j.Path())
	if err != nil {
		t.Fatalf("stat journal: %v", err)
	}
	// Clamp RLIMIT_FSIZE to header + 32 bytes so the next append fails mid-line with EFBIG.
	small := uint64(fi.Size() + 32)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: small, Max: origLim.Max}); err != nil {
		t.Fatalf("Setrlimit small: %v", err)
	}

	_, err1 := j.BeginCreate(KindBucket, "", "us-east-1", bkt1, 5000)
	if err1 == nil {
		t.Fatal("expected first BeginCreate under RLIMIT_FSIZE to fail")
	}

	// Restore RLIMIT_FSIZE and try a second append on the same Journal instance.
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &origLim); err != nil {
		t.Fatalf("restore RLIMIT_FSIZE: %v", err)
	}

	if _, err2 := j.BeginCreate(KindBucket, "", "us-east-1", bkt2, 5000); err2 == nil {
		t.Fatal("expected second BeginCreate on poisoned journal to fail")
	}

	// The on-disk journal must have rolled back the partial write and remain 100% valid JSONL.
	st, err := LoadJournal(j.Path())
	if err != nil {
		t.Fatalf("LoadJournal after failed write: %v", err)
	}
	if len(st.Entries) != 0 {
		t.Fatalf("expected 0 entries after failed write rollback, got %+v", st.Entries)
	}

	// Closing and reopening the journal must succeed and allow clean appends.
	if err := j.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	j2, err := OpenJournal(dir, meta)
	if err != nil {
		t.Fatalf("OpenJournal reopen: %v", err)
	}
	defer j2.Close()
	if _, err := j2.BeginCreate(KindBucket, "", "us-east-1", bkt2, 5000); err != nil {
		t.Fatalf("BeginCreate on reopened journal: %v", err)
	}
}

func TestJournal_EndpointRedactionAndValidation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "journals")
	meta, _ := sampleMeta(t, dir)
	meta.Endpoint = "https://akid:secretpass@s3.us-east-1.amazonaws.com/bucket?X-Amz-Signature=deadbeef#frag"

	j, err := OpenJournal(dir, meta)
	if err != nil {
		t.Fatalf("OpenJournal with userinfo/query endpoint: %v", err)
	}
	defer j.Close()

	if j.Meta().Endpoint != "https://s3.us-east-1.amazonaws.com/bucket" {
		t.Fatalf("unexpected redacted endpoint: got %q", j.Meta().Endpoint)
	}
	raw, err := os.ReadFile(j.Path())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	for _, secret := range []string{"akid", "secretpass", "X-Amz-Signature", "deadbeef", "frag"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret %q leaked into journal file: %s", secret, raw)
		}
	}

	// Forged record with unredacted query string in Endpoint is rejected by ReplayJournal.
	forgedHeader := JournalRecord{
		Version:    JournalVersion,
		Seq:        1,
		Time:       "2026-04-12T00:00:00Z",
		Event:      EventMeta,
		RunID:      meta.RunID,
		PolicyHash: meta.PolicyHash,
		Provider:   meta.Provider,
		Account:    meta.Account,
		Scope:      meta.Scope,
		Region:     meta.Region,
		Endpoint:   "https://s3.us-east-1.amazonaws.com/?X-Amz-Security-Token=secret",
	}
	if _, err := ReplayJournal([]JournalRecord{forgedHeader}); err == nil {
		t.Fatal("expected unredacted endpoint query in ReplayJournal to be rejected")
	}
}
