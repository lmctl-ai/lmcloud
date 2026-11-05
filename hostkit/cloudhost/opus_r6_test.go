package cloudhost

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func r6Pad(t *testing.T, h *Host, e *opusEnv, spares int, leave int64) {
	for i := 0; i < spares; i++ {
		left := int64(safety.MaxJournalFileBytes) - e.size() - leave
		if left < 2048 {
			return
		}
		tg := int(left) - 700
		if tg > 7<<20 {
			tg = 7 << 20
		}
		pool := fmt.Sprintf("spare%d", i)
		act, _, _, _, cerr := h.cost.lookupUserpoolEntry("", pool)
		if cerr != nil {
			t.Fatal(cerr)
		}
		if cerr := h.cost.updateUserpoolStateOpts("", pool, act.OwnerToken, act.Incarnation, act.Generation, true, false, func(cur string) string {
			st, _ := decodePersistedUserpoolState(cur)
			base := len(encodePersistedUserpoolState(st))
			n := tg - base - 12
			if n < 1 {
				n = 1
			}
			st.Memberships["pad"] = []string{strings.Repeat("p", n)}
			return encodePersistedUserpoolState(st)
		}); cerr != nil {
			t.Fatalf("seed %s: %v", pool, cerr)
		}
	}
}

// compaction folding near the hard limit must not change replayed authority
func TestR6FoldEquivalence(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "realpool")
	for _, u := range []string{"alice", "bob", "carol"} {
		h.UserCreate(false, "realpool", u, nil)
	}
	h.GroupCreate(false, "realpool", "ops")
	h.GroupCreate(false, "realpool", "dev")
	h.GroupAddUser(false, "realpool", "ops", "alice")
	h.GroupAddUser(false, "realpool", "ops", "bob")
	h.GroupAddUser(false, "realpool", "dev", "carol")
	for i := 0; i < 400; i++ {
		h.UserGet(false, "realpool", "alice")
	}
	h.UserDelete(false, "realpool", "alice") // implicit membership release
	h.GroupDelete(false, "realpool", "dev")  // implicit membership release
	for i := 0; i < 8; i++ {
		h.UserpoolCreate(false, fmt.Sprintf("spare%d", i))
	}
	opusPadJournal(t, h, 50<<20, e.size)
	r6Pad(t, h, e, 8, 900)
	a := e.host(e.f)
	before := a.cost.meter.Snapshot()
	br, _ := json.Marshal(a.CostReport())
	sz := e.size()
	h2 := e.host(e.f)
	h2.GroupDelete(false, "realpool", "ghostgroup") // cleanup op: triggers folding
	c := h2.LastError()
	after := e.size()
	b := e.host(e.f)
	s := b.cost.meter.Snapshot()
	ar, _ := json.Marshal(b.CostReport())
	t.Logf("size %d -> %d op=%s/%s charged %d -> %d cleanup %d -> %d", sz, after, c.Code, c.ProviderCode, before.ChargedNanoUSD, s.ChargedNanoUSD, before.ResourceCleanupNanoUSD, s.ResourceCleanupNanoUSD)
	t.Logf("before=%.600s", br)
	t.Logf("after =%.600s", ar)
	if after >= sz {
		t.Fatal("folding did not run")
	}
	if s.ResourceCleanupNanoUSD != before.ResourceCleanupNanoUSD {
		t.Errorf("fold changed cleanup reserve: %d -> %d", before.ResourceCleanupNanoUSD, s.ResourceCleanupNanoUSD)
	}
	if s.ChargedNanoUSD < before.ChargedNanoUSD {
		t.Errorf("fold lost charged spend")
	}
	b.UserGet(false, "realpool", "bob")
	t.Logf("read after fold=%s", opCode(b))
}

func r6Copy(t *testing.T, src, dst string) {
	if out, err := exec.Command("cp", "-a", src+"/.", dst).CombinedOutput(); err != nil {
		t.Fatal(string(out))
	}
}

// records have no margin: reserve at limit-513 plus settle can cross the read limit
func TestR6HardLimitGapSweep(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			base := t.TempDir()
			sb := &opusEnv{t: t, state: filepath.Join(base, "fake.json"), campaign: filepath.Join(base, "campaign.jsonl"), jdir: filepath.Join(base, "journal"), jm: jm}
			sb.f = fakeadapter.New(fakeadapter.Options{StatePath: sb.state})
			if jm {
				sb.j = openUserpoolSafetyJournal(t, sb.jdir)
			}
			h := sb.host(sb.f)
			h.UserpoolCreate(false, "realpool")
			h.UserCreate(false, "realpool", "alice", nil)
			h.UserCreate(false, "realpool", "bob", nil)
			for i := 0; i < 8; i++ {
				h.UserpoolCreate(false, fmt.Sprintf("spare%d", i))
			}
			opusPadJournal(t, h, 50<<20, sb.size)
			r6Pad(t, h, sb, 8, 6000)
			if jm {
				_ = sb.j.Close()
			}
			var bad []string
			for _, gap := range []int64{1500, 900, 640, 300} {
				d := t.TempDir()
				r6Copy(t, base, d)
				e := &opusEnv{t: t, state: filepath.Join(d, "fake.json"), campaign: filepath.Join(d, "campaign.jsonl"), jdir: filepath.Join(d, "journal"), jm: jm}
				e.f = fakeadapter.New(fakeadapter.Options{StatePath: e.state})
				if jm {
					e.j = openUserpoolSafetyJournal(t, e.jdir)
				}
				x := e.host(e.f)
				left := int64(safety.MaxJournalFileBytes) - e.size() - gap
				act, _, _, _, _ := x.cost.lookupUserpoolEntry("", "spare7")
				if cerr := x.cost.updateUserpoolStateOpts("", "spare7", act.OwnerToken, act.Incarnation, act.Generation, true, false, func(cur string) string {
					st, _ := decodePersistedUserpoolState(cur)
					st.Memberships["pad2"] = []string{strings.Repeat("q", int(left)-1200-len(cur)+len(cur)-0)}
					return encodePersistedUserpoolState(st)
				}); cerr != nil {
					t.Logf("gap %d seed: %v", gap, cerr)
					continue
				}
				got := int64(safety.MaxJournalFileBytes) - e.size()
				x.UserDelete(false, "realpool", "alice")
				ud := x.LastError()
				x.UserpoolDelete(false, "realpool")
				pd := x.LastError()
				end := e.size()
				if !jm {
					fi, _ := os.Stat(e.campaign)
					end = fi.Size()
				}
				var readErr string
				if jm {
					_ = e.j.Close()
					if j, err := safety.OpenJournal(e.jdir, safety.JournalMeta{RunID: "run-1700000000-abcdef012345", Provider: "aws", Account: "000000000000", Scope: "000000000000", Region: "us-east-1", Endpoint: "http://127.0.0.1:4566", PolicyHash: strings.Repeat("a", 64)}); err != nil {
						readErr = err.Error()
					} else {
						_ = j.Close()
					}
				} else {
					r := e.host(e.f)
					if _, _, _, _, ce := r.cost.lookupUserpoolEntry("", "realpool"); ce != nil {
						readErr = ce.Error()
					}
				}
				t.Logf("headroom=%d userDelete=%s/%s poolDelete=%s/%s end=%d over=%d read=%q", got, ud.Code, ud.ProviderCode, pd.Code, pd.ProviderCode, end, end-int64(safety.MaxJournalFileBytes), readErr)
				if readErr != "" || end > int64(safety.MaxJournalFileBytes) {
					bad = append(bad, fmt.Sprintf("headroom=%d", got))
				}
			}
			if len(bad) > 0 {
				t.Fatalf("journal became unreadable: %v", bad)
			}
		})
	}
}

func r6Child(t *testing.T, e *opusEnv) (*exec.Cmd, chan string, string, string) {
	ent, g := e.campaign+".entered", e.campaign+".go"
	c := exec.Command(os.Args[0], "-test.run=^TestR5HelperChildReset$", "-test.v")
	c.Env = append(os.Environ(), "R5_STATE="+e.state, "R5_CAMPAIGN="+e.campaign, "R5_ENTERED="+ent, "R5_GO="+g)
	outc := make(chan string, 1)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = c.Wait(); outc <- "done" }()
	for i := 0; i < 3000; i++ {
		if _, err := os.Stat(ent); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c, outc, ent, g
}

// lock cannot be created: the fence must not silently degrade
func TestR6RevokeLockUnavailableFailsClosed(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "xpool")
	h.UserCreate(false, "xpool", "alice", nil)
	h.UserSetPassword(false, "xpool", "alice", "Original123")
	_ = os.RemoveAll(e.campaign + ".profiles.revokes")
	if err := os.WriteFile(e.campaign+".profiles.revokes", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, outc, _, g := r6Child(t, e)
	h.UserSetEnabled(false, "xpool", "alice", true)
	s, _ := h.UserSignIn(false, "xpool", "alice", "Original123")
	sc := opCode(h)
	_ = os.WriteFile(g, []byte("x"), 0o600)
	<-outc
	r := e.host(e.f)
	r.UserVerifyToken(false, "xpool", s.AccessToken())
	t.Logf("signin(old pw)=%s verify=%s", sc, opCode(r))
	if sc == hostkit.OK && opCode(r) == hostkit.OK {
		t.Fatal("revoke lock unavailable: fence silently fails open across processes")
	}
}

// crashed owner: intent becomes reconcilable, nothing stuck
func TestR6KilledOwnerReconciles(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "xpool")
	h.UserCreate(false, "xpool", "alice", nil)
	h.UserSetPassword(false, "xpool", "alice", "Original123")
	old, _ := h.UserSignIn(false, "xpool", "alice", "Original123")
	c, outc, _, _ := r6Child(t, e)
	_ = c.Process.Kill()
	<-outc
	h.UserVerifyToken(false, "xpool", old.AccessToken())
	v1 := opCode(h)
	h.UserSignIn(false, "xpool", "alice", "Original123")
	s1 := opCode(h)
	h.UserSetEnabled(false, "xpool", "alice", true)
	s, _ := h.UserSignIn(false, "xpool", "alice", "Original123")
	s2 := opCode(h)
	h.UserVerifyToken(false, "xpool", s.AccessToken())
	v2 := opCode(h)
	h.UserVerifyToken(false, "xpool", old.AccessToken())
	v3 := opCode(h)
	ents, _ := os.ReadDir(e.campaign + ".profiles.revokes")
	t.Logf("old verify=%s signin pending=%s after enable signin=%s newverify=%s old=%s lockfiles=%d", v1, s1, s2, v2, v3, len(ents))
	if v1 == hostkit.OK || v3 == hostkit.OK || s2 != hostkit.OK || v2 != hostkit.OK {
		t.Fatal("killed owner path wrong")
	}
}

// refused delete alone still restores the session; overlapping refused deletes never lower below a completed op
func TestR6RollbackCompareAndRestore(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "rbpool")
	h.UserCreate(false, "rbpool", "alice", nil)
	h.UserSetPassword(false, "rbpool", "alice", "Original123")
	s, _ := h.UserSignIn(false, "rbpool", "alice", "Original123")
	a := &opusHoldDeleteRefuse{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
	b := &opusHoldDeleteRefuse{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
	h1, h2 := e.host(a), e.host(b)
	d1, d2 := make(chan struct{}), make(chan struct{})
	go func() { defer close(d1); h1.UserDelete(false, "rbpool", "alice") }()
	<-a.entered
	go func() { defer close(d2); h2.UserDelete(false, "rbpool", "alice") }()
	<-b.entered
	close(a.release)
	<-d1
	close(b.release)
	<-d2
	r := e.host(e.f)
	act, _, _, _, _ := r.cost.lookupUserpoolEntry("", "rbpool")
	st, _ := decodePersistedUserpoolState(act.StateJSON)
	r.UserVerifyToken(false, "rbpool", s.AccessToken())
	t.Logf("two refused deletes: gen=%d pending=%v verify=%s", st.RevokedSessionGen["alice"], st.PendingUserRevokeSet, opCode(r))
	if len(st.PendingUserRevokeSet) != 0 {
		t.Fatal("pending stuck")
	}
	var _ context.Context
}

// direct record append reaches the last bytes the admission checks allow
func TestR6TightGapCampaign(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	sb := &opusEnv{t: t, state: filepath.Join(base, "fake.json"), campaign: filepath.Join(base, "campaign.jsonl"), jdir: filepath.Join(base, "journal")}
	sb.f = fakeadapter.New(fakeadapter.Options{StatePath: sb.state})
	h := sb.host(sb.f)
	h.UserpoolCreate(false, "realpool")
	h.UserCreate(false, "realpool", "alice", nil)
	for i := 0; i < 8; i++ {
		h.UserpoolCreate(false, fmt.Sprintf("spare%d", i))
	}
	opusPadJournal(t, h, 50<<20, sb.size)
	r6Pad(t, h, sb, 7, 6000)
	var bad []string
	for _, gap := range []int64{1000, 700, 300} {
		d := t.TempDir()
		r6Copy(t, base, d)
		e := &opusEnv{t: t, state: filepath.Join(d, "fake.json"), campaign: filepath.Join(d, "campaign.jsonl"), jdir: filepath.Join(d, "journal")}
		e.f = fakeadapter.New(fakeadapter.Options{StatePath: e.state})
		x := e.host(e.f)
		act, _, _, _, _ := x.cost.lookupUserpoolEntry("", "spare7")
		left := int(int64(safety.MaxJournalFileBytes) - e.size() - gap)
		st, _ := decodePersistedUserpoolState(act.StateJSON)
		st.Memberships["pad3"] = []string{strings.Repeat("r", left-len(act.StateJSON)-420)}
		enc := encodePersistedUserpoolState(st)
		if err := x.cost.withLockedCampaignJournal(true, func(_ *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			return appendRec(campaignJournalRecord{Event: safety.EventUserpoolState, ResKey: "spare7", OwnerToken: act.OwnerToken, UserpoolIncarnation: act.Incarnation, Generation: act.Generation, UserpoolState: enc})
		}); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Stat(e.campaign)
		room := int64(safety.MaxJournalFileBytes) - fi.Size()
		y := e.host(e.f)
		y.UserDelete(false, "realpool", "alice")
		ud := y.LastError()
		y.UserpoolDelete(false, "realpool")
		pd := y.LastError()
		fi2, _ := os.Stat(e.campaign)
		r := e.host(e.f)
		_, _, _, _, ce := r.cost.lookupUserpoolEntry("", "realpool")
		t.Logf("room=%d userDelete=%s/%s poolDelete=%s/%s over=%d read=%v", room, ud.Code, ud.ProviderCode, pd.Code, pd.ProviderCode, fi2.Size()-int64(safety.MaxJournalFileBytes), ce)
		if ce != nil || fi2.Size() > int64(safety.MaxJournalFileBytes) {
			bad = append(bad, fmt.Sprintf("room=%d", room))
		}
	}
	if len(bad) > 0 {
		t.Fatalf("journal unreadable after cleanup: %v", bad)
	}
}
