package cloudhost

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

// delete refused AFTER another revocation completed: rollback restores a stale generation
type opusHoldDeleteRefuse struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *opusHoldDeleteRefuse) DeleteUser(context.Context, string, string) error {
	close(a.entered)
	<-a.release
	return hostkit.ProviderError(hostkit.PermissionDenied, 403, "AccessDenied", "denied")
}
func TestR5RefusedDeleteRollbackResurrectsToken(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		for _, second := range []string{"reset", "disable_enable"} {
			second := second
			t.Run(modeName(jm)+"/"+second, func(t *testing.T) {
				t.Parallel()
				e := newOpusEnv(t, jm)
				h := e.host(e.f)
				h.UserpoolCreate(false, "rbpool")
				h.UserCreate(false, "rbpool", "alice", nil)
				h.UserSetPassword(false, "rbpool", "alice", "Original123")
				s, _ := h.UserSignIn(false, "rbpool", "alice", "Original123")
				a := &opusHoldDeleteRefuse{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
				slow := e.host(a)
				done := make(chan struct{})
				go func() { defer close(done); slow.UserDelete(false, "rbpool", "alice") }()
				<-a.entered
				if second == "reset" {
					h.UserSetPassword(false, "rbpool", "alice", "Changed456")
				} else {
					h.UserSetEnabled(false, "rbpool", "alice", false)
					h.UserSetEnabled(false, "rbpool", "alice", true)
				}
				res := opCode(h)
				close(a.release)
				<-done
				e.reopen()
				r := e.host(e.f)
				act, _, _, _, _ := r.cost.lookupUserpoolEntry("", "rbpool")
				st, _ := decodePersistedUserpoolState(act.StateJSON)
				r.UserVerifyToken(false, "rbpool", s.AccessToken())
				t.Logf("delete=%s second=%s gen=%d pending=%v verify(old)=%s", opCode(slow), res, st.RevokedSessionGen["alice"], st.PendingUserRevokeSet, opCode(r))
				if opCode(r) == hostkit.OK {
					t.Fatal("old token verifies after a successful revocation: refused delete's rollback lowered the generation")
				}
			})
		}
	}
}

// real second process: in-flight tracking is process-local
type opusFilePause struct {
	*fakeadapter.Fake
	entered, gofile string
}

func (a *opusFilePause) SetUserPassword(ctx context.Context, p, u, pw string) (hostkit.UserSnapshot, error) {
	_ = os.WriteFile(a.entered, []byte("x"), 0o600)
	for i := 0; i < 6000; i++ {
		if _, err := os.Stat(a.gofile); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return a.Fake.SetUserPassword(ctx, p, u, pw)
}
func TestR5HelperChildReset(t *testing.T) {
	st := os.Getenv("R5_STATE")
	if st == "" {
		t.Skip("helper")
	}
	f := fakeadapter.New(fakeadapter.Options{StatePath: st})
	a := &opusFilePause{Fake: f, entered: os.Getenv("R5_ENTERED"), gofile: os.Getenv("R5_GO")}
	h := New(Config{Provider: "aws", Store: f, Userpools: a, CampaignStatePath: os.Getenv("R5_CAMPAIGN")})
	h.SetAbortOnError(false)
	h.UserSetPassword(false, "xpool", "alice", "Changed456")
	fmt.Printf("CHILD reset=%s\n", h.LastError().Code)
}
func TestR5ProcessLocalInFlight(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "xpool")
	h.UserCreate(false, "xpool", "alice", nil)
	h.UserSetPassword(false, "xpool", "alice", "Original123")
	ent, g := e.campaign+".entered", e.campaign+".go"
	c := exec.Command(os.Args[0], "-test.run=^TestR5HelperChildReset$", "-test.v")
	c.Env = append(os.Environ(), "R5_STATE="+e.state, "R5_CAMPAIGN="+e.campaign, "R5_ENTERED="+ent, "R5_GO="+g)
	outc := make(chan string, 1)
	go func() { b, _ := c.CombinedOutput(); outc <- string(b) }()
	for i := 0; i < 3000; i++ {
		if _, err := os.Stat(ent); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.UserSetEnabled(false, "xpool", "alice", true)
	en := opCode(h)
	s, _ := h.UserSignIn(false, "xpool", "alice", "Original123")
	sc := opCode(h)
	_ = os.WriteFile(g, []byte("x"), 0o600)
	out := <-outc
	r := e.host(e.f)
	r.UserVerifyToken(false, "xpool", s.AccessToken())
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "CHILD") {
			line = l
		}
	}
	t.Logf("enable=%s signin(old pw)=%s %s verify=%s", en, sc, line, opCode(r))
	if !strings.Contains(line, "reset=OK") {
		t.Fatalf("child: %s", out[:min(len(out), 800)])
	}
	if sc == hostkit.OK && opCode(r) == hostkit.OK {
		t.Fatal("second process cleared the first's in-flight revocation; old-password token survives the reset")
	}
}

// cleanup-class records have no check against the hard 64 MiB read limit
func TestR5CleanupOverrunsHardLimit(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "realpool")
			for i := 0; i < 60; i++ {
				h.UserCreate(false, "realpool", fmt.Sprintf("user%03d", i), nil)
			}
			for i := 0; i < 3; i++ {
				h.UserpoolCreate(false, fmt.Sprintf("spare%d", i))
			}
			opusPadJournal(t, h, 58<<20, e.size)
			for i := 0; i < 3; i++ {
				left := int64(safety.MaxJournalFileBytes) - e.size() - 2500
				if left < 4096 {
					break
				}
				tg := int(left)
				if tg > 7<<20 {
					tg = 7 << 20
				}
				pool := fmt.Sprintf("spare%d", i)
				act, _, _, _, _ := h.cost.lookupUserpoolEntry("", pool)
				if cerr := h.cost.updateUserpoolStateOpts("", pool, act.OwnerToken, act.Incarnation, act.Generation, true, false, func(cur string) string {
					st, _ := decodePersistedUserpoolState(cur)
					st.Memberships["pad"] = []string{strings.Repeat("p", tg)}
					return encodePersistedUserpoolState(st)
				}); cerr != nil {
					t.Fatalf("seed: %v", cerr)
				}
			}
			start := e.size()
			var firstErr *hostkit.CloudError
			n := 0
			for i := 0; i < 60; i++ {
				h.UserDelete(false, "realpool", fmt.Sprintf("user%03d", i))
				if opCode(h) != hostkit.OK {
					le := h.LastError()
					firstErr = &le
					break
				}
				n++
			}
			end := e.size()
			if fi, err := os.Stat(e.campaign); err == nil && !jm {
				end = fi.Size()
			}
			t.Logf("start=%d deleted=%d end=%d firstErr=%+v", start, n, end, firstErr)
			var openErr any
			func() {
				defer func() { openErr = recover() }()
				e.reopenNoFail()
			}()
			r := e.host(e.f)
			r.UserpoolDelete(false, "realpool")
			pd := r.LastError()
			t.Logf("reopenErr=%v poolDelete=%s/%s %s", openErr, pd.Code, pd.ProviderCode, pd.Message)
			if pd.Code != hostkit.OK {
				t.Fatalf("cleanup-class work pushed the journal past its read limit and bricked cleanup: %+v", pd)
			}
		})
	}
}
func (e *opusEnv) reopenNoFail() {
	if e.jm {
		_ = e.j.Close()
		j, err := safety.OpenJournal(e.jdir, safety.JournalMeta{RunID: "run-1700000000-abcdef012345", Provider: "aws", Account: "000000000000", Scope: "000000000000", Region: "us-east-1", Endpoint: "http://127.0.0.1:4566", PolicyHash: strings.Repeat("a", 64)})
		if err != nil {
			panic(err.Error())
		}
		e.j = j
	}
}

// evicted bindings fail closed; revocation at limit of a state dominated by non-bindings
func TestR5EnableAfterRevocationHeadroom(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "hrpool")
	h.UserCreate(false, "hrpool", "alice", nil)
	h.UserSetPassword(false, "hrpool", "alice", "Original123")
	act, _, _, _, _ := h.cost.lookupUserpoolEntry("", "hrpool")
	if cerr := h.cost.updateUserpoolStateOpts("", "hrpool", act.OwnerToken, act.Incarnation, act.Generation, true, false, func(cur string) string {
		st, _ := decodePersistedUserpoolState(cur)
		st.Memberships["pad"] = []string{strings.Repeat("p", 8*1024*1024-30)}
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		t.Logf("seed: %v", cerr)
	}
	h.UserSetEnabled(false, "hrpool", "alice", false)
	d := h.LastError()
	h.UserSetEnabled(false, "hrpool", "alice", true)
	en := h.LastError()
	nat, _ := e.f.GetUser(context.Background(), "hrpool", "alice")
	t.Logf("disable=%s enable=%s/%s nativeEnabled=%v", d.Code, en.Code, en.ProviderCode, nat.Enabled)
	if nat.Enabled && en.Code != hostkit.OK {
		t.Fatalf("enable committed natively then refused by the state limit: %+v", en)
	}
}
