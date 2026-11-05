package cloudhost

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

// enable(true) clears a pending revocation that belongs to a reset still in flight
type opusPreCommitPw struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *opusPreCommitPw) SetUserPassword(ctx context.Context, p, u, pw string) (hostkit.UserSnapshot, error) {
	close(a.entered)
	<-a.release
	return a.Fake.SetUserPassword(ctx, p, u, pw)
}

func TestR4EnableClearsInFlightRevocation(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "racepool")
			h.UserCreate(false, "racepool", "alice", nil)
			h.UserSetPassword(false, "racepool", "alice", "Original123")
			a := &opusPreCommitPw{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
			slow := e.host(a)
			done := make(chan struct{})
			go func() { defer close(done); slow.UserSetPassword(false, "racepool", "alice", "Changed456") }()
			<-a.entered
			h.UserSetEnabled(false, "racepool", "alice", true) // no-op enable, must not clear in-flight pending
			en := opCode(h)
			s, _ := h.UserSignIn(false, "racepool", "alice", "Original123") // old password still valid natively
			sc := opCode(h)
			close(a.release)
			<-done
			e.reopen()
			r := e.host(e.f)
			r.UserVerifyToken(false, "racepool", s.AccessToken())
			t.Logf("enable=%s signin(old pw)=%s reset=%s verify=%s", en, sc, opCode(slow), opCode(r))
			if sc == hostkit.OK && opCode(slow) == hostkit.OK && opCode(r) == hostkit.OK {
				t.Fatal("token authenticated with the old password verifies after the reset succeeded")
			}
		})
	}
}

func TestR4SecondResetClearsFirstInFlight(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "racepool")
			h.UserCreate(false, "racepool", "alice", nil)
			h.UserSetPassword(false, "racepool", "alice", "Original123")
			a := &opusPreCommitPw{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
			slow := e.host(a)
			done := make(chan struct{})
			go func() { defer close(done); slow.UserSetPassword(false, "racepool", "alice", "FinalPass789") }()
			<-a.entered
			h.UserSetPassword(false, "racepool", "alice", "Interim4567")
			s, _ := h.UserSignIn(false, "racepool", "alice", "Interim4567")
			sc := opCode(h)
			close(a.release)
			<-done
			e.reopen()
			r := e.host(e.f)
			r.UserVerifyToken(false, "racepool", s.AccessToken())
			t.Logf("signin(interim)=%s final reset=%s verify=%s", sc, opCode(slow), opCode(r))
			if sc == hostkit.OK && opCode(slow) == hostkit.OK && opCode(r) == hostkit.OK {
				t.Fatal("token from a superseded password survives the last reset to commit")
			}
		})
	}
}

func TestR4GhostRevocationGrowsAuthority(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "ghostpool")
			for i := 0; i < 150; i++ {
				h.UserSetPassword(false, "ghostpool", fmt.Sprintf("ghost%05d", i), "Passw0rd123")
				h.UserSetEnabled(false, "ghostpool", fmt.Sprintf("spook%05d", i), false)
				if opCode(h) != hostkit.NotFound {
					t.Fatal(h.LastError())
				}
			}
			act, _, _, _, _ := h.cost.lookupUserpoolEntry("", "ghostpool")
			st, _ := decodePersistedUserpoolState(act.StateJSON)
			t.Logf("users=%d revokedGen=%d pending=%d state=%d", len(st.Users), len(st.RevokedSessionGen), len(st.PendingUserRevoke), len(act.StateJSON))
			if len(st.RevokedSessionGen) > 0 {
				t.Fatal("NOT_FOUND set_password/set_enabled on never-existing users leaves permanent per-user authority (rollback keeps the bump)")
			}
		})
	}
}

func opusSeedState(t *testing.T, h *Host, pool string, target int) {
	act, _, _, _, _ := h.cost.lookupUserpoolEntry("", pool)
	if cerr := h.cost.updateUserpoolState("", pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
		st, _ := decodePersistedUserpoolState(cur)
		base := len(encodePersistedUserpoolState(st))
		n := (target - base) / 361
		for u := 0; u < 2 && n > 0; u++ {
			name := fmt.Sprintf("phantom%04d", u)
			st.Users[name] = hostkit.UserSnapshot{Exists: true, Username: name, Enabled: true, Status: hostkit.UserStatusConfirmed, SessionGen: 2}
			c := 128
			if n < c {
				c = n
			}
			b := make([]tokenBindingRecord, 0, c)
			for j := 0; j < c; j++ {
				b = append(b, tokenBindingRecord{TokenSHA256: strings.Repeat("a", 64), Sub: strings.Repeat("0", 32), Username: name, PoolID: "pool-" + pool, IncarnationID: act.Incarnation, SessionGen: 2, IssuedAt: 1, ExpiresAt: 4102444800, Scope: strings.Repeat("c", 64)})
			}
			st.TokenBindings[name] = b
			n -= c
		}
		curLen := len(encodePersistedUserpoolState(st))
		for {
			gap := target - curLen
			if gap < 8 {
				break
			}
			l := gap - 3
			addedOverhead := 3
			if len(st.Memberships["padgroup"]) == 0 {
				l = gap - 15
				addedOverhead = 15
			}
			if l > 1<<20 {
				l = 1 << 20
			}
			if l < 1 {
				l = 1
			}
			st.Memberships["padgroup"] = append(st.Memberships["padgroup"], strings.Repeat("p", l))
			curLen += l + addedOverhead
		}
		return encodePersistedUserpoolState(st)
	}); cerr != nil {
		t.Fatalf("seed: %v", cerr)
	}
}

// a pool whose bindings filled the 8 MiB state limit
func TestR4RevocationAtStateLimit(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "fullpool")
			h.UserCreate(false, "fullpool", "alice", nil)
			h.UserSetPassword(false, "fullpool", "alice", "Original123")
			s, _ := h.UserSignIn(false, "fullpool", "alice", "Original123")
			opusSeedState(t, h, "fullpool", 8*1024*1024-30)
			act, _, _, _, _ := h.cost.lookupUserpoolEntry("", "fullpool")
			h.UserSetEnabled(false, "fullpool", "alice", false)
			dis := h.LastError()
			nat, _ := e.f.GetUser(context.Background(), "fullpool", "alice")
			h.UserVerifyToken(false, "fullpool", s.AccessToken())
			vc := opCode(h)
			h.UserDelete(false, "fullpool", "alice")
			ud := h.LastError()
			h.UserpoolDelete(false, "fullpool")
			pd := h.LastError()
			t.Logf("state=%d disable=%s/%s nativeEnabled=%v verify=%s userDelete=%s/%s poolDelete=%s/%s", len(act.StateJSON), dis.Code, dis.ProviderCode, nat.Enabled, vc, ud.Code, ud.ProviderCode, pd.Code, pd.ProviderCode)
			if vc == hostkit.OK {
				t.Error("a pool at the state limit cannot revoke: disable refused and the token still verifies")
			}
			if ud.Code != hostkit.OK {
				t.Error("user_delete refused at the state limit")
			}
			if pd.Code != hostkit.OK {
				t.Error("pool delete refused at the state limit")
			}
		})
	}
}

func opusPadJournal(t *testing.T, h *Host, target int64, size func() int64) int {
	n := 0
	for size() < target {
		pool := fmt.Sprintf("pad%03d", n)
		h.UserpoolCreate(false, pool)
		if opCode(h) != hostkit.OK {
			t.Fatalf("pad create: %+v (size %d)", h.LastError(), size())
		}
		left := target - size()
		tg := 7 << 20
		if left < int64(tg) {
			tg = int(left) - 2048
		}
		if tg < 4096 {
			break
		}
		opusSeedState(t, h, pool, tg)
		n++
	}
	return n
}

func (e *opusEnv) size() int64 {
	if e.jm {
		return e.j.FileSize()
	}
	fi, err := os.Stat(e.campaign)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func TestR4CleanupAndRevocationAtJournalLimit(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "realpool")
			h.UserCreate(false, "realpool", "alice", nil)
			h.UserCreate(false, "realpool", "bob", nil)
			h.GroupCreate(false, "realpool", "ops")
			h.GroupAddUser(false, "realpool", "ops", "bob")
			h.UserSetPassword(false, "realpool", "alice", "Original123")
			s, _ := h.UserSignIn(false, "realpool", "alice", "Original123")
			opusPadJournal(t, h, maxNonCleanupJournalBytes-3000, e.size)
			h.UserCreate(false, "realpool", "trigger", nil) // non-cleanup near limit
			tc := h.LastError()
			nt, _ := e.f.GetUser(context.Background(), "realpool", "trigger")
			sz := e.size()
			h.UserSetEnabled(false, "realpool", "alice", false)
			dis := h.LastError()
			h.UserVerifyToken(false, "realpool", s.AccessToken())
			v := h.LastError()
			h.UserDelete(false, "realpool", "alice")
			ud := h.LastError()
			h.GroupRemoveUser(false, "realpool", "ops", "bob")
			gr := h.LastError()
			h.UserpoolDelete(false, "realpool")
			pd := h.LastError()
			info, _ := e.f.UserPoolExists(context.Background(), "realpool")
			sz2 := e.size()
			t.Logf("size=%d create=%s/%s nativeTrigger=%v disable=%s/%s verify=%s/%s userDelete=%s/%s groupRemove=%s/%s poolDelete=%s/%s nativePool=%v endSize=%d", sz, tc.Code, tc.ProviderCode, nt.Exists, dis.Code, dis.ProviderCode, v.Code, v.ProviderCode, ud.Code, ud.ProviderCode, gr.Code, gr.ProviderCode, pd.Code, pd.ProviderCode, info, sz2)
			e.reopen()
			r := e.host(e.f)
			if pd.Code != hostkit.OK {
				t.Fatalf("cleanup near the journal limit failed: %+v", pd)
			}
			if ud.Code != hostkit.OK {
				t.Errorf("user_delete (cleanup class) refused at the journal limit: %+v", ud)
			}
			r.UserSignIn(false, "pad000", "nobody", "Passw0rd123")
			t.Logf("after reopen readable: %+v", r.LastError())
			if nt.Exists && tc.Code != hostkit.OK {
				t.Errorf("user_create committed natively then refused by file limit: %+v", tc)
			}
			if dis.Code != hostkit.OK && v.Code == hostkit.OK {
				t.Errorf("revocation refused at journal limit while the token still verifies: %+v", dis)
			}
		})
	}
}

// safety mode: repeated big-state appends must compact, not hit the limit
func TestR4SafetyBigStateChurn(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, true)
	h := e.host(e.f)
	h.UserpoolCreate(false, "churnpool")
	opusSeedState(t, h, "churnpool", 6<<20)
	var maxSz int64
	for i := 0; i < 16; i++ {
		h.UserCreate(false, "churnpool", fmt.Sprintf("c%04d", i), nil)
		if opCode(h) != hostkit.OK {
			t.Fatalf("iter %d size %d: %+v", i, e.size(), h.LastError())
		}
		if s := e.size(); s > maxSz {
			maxSz = s
		}
	}
	t.Logf("max journal=%d end=%d", maxSz, e.size())
	if maxSz > 64<<20 {
		t.Fatal("over limit")
	}
	e.reopen()
	r := e.host(e.f)
	r.UserGet(false, "churnpool", "c0015")
	if opCode(r) != hostkit.OK {
		t.Fatal(r.LastError())
	}
}

// nothing preflight accepts may fail journal validation: attribute values, names, usernames, groups, passwords
func TestR4PropertySweepPreflightVsJournal(t *testing.T) {
	t.Parallel()
	var vals []string
	for b := 1; b < 0x80; b++ {
		vals = append(vals, "x"+string(rune(b))+"y", string(rune(b)))
	}
	vals = append(vals, "", " ", "password", "access_token", "private_key", `"password"`, `{"password":"x"}`, `"access_token":"eyJ"`, "\u0080", "\u0085", "\u009f", " ", "\u2028", "\u2029", string(rune(0xfeff)), "\ufffd", "\U0010ffff", "\u200b", "null", `\u0000`, `\x7f`, "</script>", strings.Repeat("\x7f", 2048), strings.Repeat("\x01", 2048), strings.Repeat(`"`, 2048), strings.Repeat("é", 1024), "eyJhbGciOiJSUzI1NiJ9.e30.sig")
	big := map[string]string{}
	for i := 0; i < 32; i++ {
		big[fmt.Sprintf("a%d", i)] = strings.Repeat("\x7f\x01", 1024)
	}
	for _, jm := range []bool{true, false} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "sweep")
			okN, refused := 0, 0
			try := func(u string, attrs map[string]string) {
				if ce := hostkit.ValidatePoolAttributes(attrs); ce != nil {
					refused++
					return
				}
				h.UserCreate(false, "sweep", u, attrs)
				c := h.LastError()
				if c.Code != hostkit.OK {
					t.Fatalf("accepted input failed: attrs=%q %+v", attrs, c)
				}
				got, _ := h.UserGet(false, "sweep", u)
				for k, v := range attrs {
					if got.Attribute(k) != v {
						t.Fatalf("readback mismatch %q", v)
					}
				}
				h.UserDelete(false, "sweep", u)
				if opCode(h) != hostkit.OK {
					t.Fatalf("delete failed %+v", h.LastError())
				}
				okN++
			}
			for i, v := range vals {
				try(fmt.Sprintf("u%04d", i), map[string]string{"note": v})
			}
			try("bigctl", big)
			for _, n := range []string{"password", "password_hash", "password_salt", "private_key", "private_key_pem", "access_token", "token_bindings", "users", "pool", "user_profile_dir", "attributes", "owner_token", "aaa", strings.Repeat("a", 64), "a_" + strings.Repeat("9", 62)} {
				if ce := hostkit.ValidatePoolUsername(n); ce != nil {
					t.Logf("username %q refused", n)
					continue
				}
				h.UserCreate(false, "sweep", n, map[string]string{"password": "literal", "access_token": "x", "private_key": "y"})
				if opCode(h) != hostkit.OK {
					t.Fatalf("user %q: %+v", n, h.LastError())
				}
				h.GroupCreate(false, "sweep", n)
				h.GroupAddUser(false, "sweep", n, n)
				if opCode(h) != hostkit.OK {
					t.Fatalf("group %q: %+v", n, h.LastError())
				}
				h.UserSetPassword(false, "sweep", n, "Pw\"\\%<>'&;1a")
				if opCode(h) != hostkit.OK {
					t.Fatalf("password %q: %+v", n, h.LastError())
				}
				okN++
			}
			e.reopen()
			r := e.host(e.f)
			r.UserGet(false, "sweep", "password")
			if opCode(r) != hostkit.OK {
				t.Fatalf("reopen: %+v", r.LastError())
			}
			r.UserpoolDelete(false, "sweep")
			t.Logf("accepted=%d refused=%d delete=%s", okN, refused, opCode(r))
			if opCode(r) != hostkit.OK {
				t.Fatal(r.LastError())
			}
		})
	}
}

// provider text with control bytes must not reach a validated journal field
type opusCtlErr struct{ *fakeadapter.Fake }

func (a *opusCtlErr) SetUserPassword(context.Context, string, string, string) (hostkit.UserSnapshot, error) {
	return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.Internal, 500, "Bad\x7f\nCode", "boom\x7f\x01\n")
}
func (a *opusCtlErr) CreateUser(context.Context, hostkit.UserCreateInput) (hostkit.UserSnapshot, error) {
	return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.Internal, 500, "Bad\x7f\nCode", "boom\x7f\x01\n")
}
func TestR4ProviderControlCharsDoNotPoison(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, true)
	h := e.host(e.f)
	h.UserpoolCreate(false, "ctlpool")
	h.UserCreate(false, "ctlpool", "alice", nil)
	b := e.host(&opusCtlErr{Fake: e.f})
	b.UserSetPassword(false, "ctlpool", "alice", "Passw0rd123")
	b.UserCreate(false, "ctlpool", "bob", nil)
	t.Logf("%+v", b.LastError())
	h.UserGet(false, "ctlpool", "alice")
	if opCode(h) != hostkit.OK {
		t.Fatal(h.LastError())
	}
}

// reserve only released on proven outcomes
func TestR4CleanupReserveOnProvenOutcomes(t *testing.T) {
	t.Parallel()
	type step struct {
		name string
		op   string
		run  func(h *Host)
		c    hostkit.Code
		st   int
	}
	for _, s := range []step{
		{"user_delete_lost", "DeleteUser", func(h *Host) { h.UserDelete(false, "respool", "alice") }, hostkit.Internal, 503},
		{"user_delete_403", "DeleteUser", func(h *Host) { h.UserDelete(false, "respool", "alice") }, hostkit.PermissionDenied, 403},
		{"group_delete_lost", "DeleteGroup", func(h *Host) { h.GroupDelete(false, "respool", "ops") }, hostkit.Internal, 503},
		{"membership_remove_lost", "RemoveUserFromGroup", func(h *Host) { h.GroupRemoveUser(false, "respool", "ops", "alice") }, hostkit.Internal, 503},
		{"pool_delete_lost", "DeleteUserPool", func(h *Host) { h.UserpoolDelete(false, "respool") }, hostkit.Internal, 503},
	} {
		t.Run(s.name, func(t *testing.T) {
			e := newOpusEnv(t, false)
			h := e.host(e.f)
			h.UserpoolCreate(false, "respool")
			h.UserCreate(false, "respool", "alice", nil)
			h.GroupCreate(false, "respool", "ops")
			h.GroupAddUser(false, "respool", "ops", "alice")
			base := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
			hit := false
			e.f.SetFaultUserpoolMutatorAfterCommitForTesting(func(got string) error {
				if got == s.op {
					hit = true
					return hostkit.ProviderError(s.c, s.st, "Fault", "after commit")
				}
				return nil
			})
			s.run(h)
			e.f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
			after := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
			r := e.host(e.f)
			re := r.cost.meter.Snapshot().ResourceCleanupNanoUSD
			act, _, amb, hasAmb, _ := r.cost.lookupUserpoolEntry("", "respool")
			t.Logf("hit=%v op=%s reserve base=%d after=%d replay=%d amb=%v(%s) statelen=%d", hit, opCode(h), base, after, re, hasAmb, amb.IntentOp, len(act.StateJSON))
			if !hit {
				t.Skip("fault op not exercised on this path")
			}
			want := base
			if s.name == "pool_delete_lost" {
				want = 50000 // children were deleted and proven; the pool reserve must stay
			}
			if after != want || re != after {
				t.Fatalf("reserve released without a proven outcome or diverges on replay: base=%d want=%d after=%d replay=%d", base, want, after, re)
			}
		})
	}
}

func TestR4GhostDeleteDoesNotReleaseOthers(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "respool")
	h.UserCreate(false, "respool", "alice", nil)
	base := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
	h.UserDelete(false, "respool", "ghost")
	h.GroupDelete(false, "respool", "ghostgrp")
	after := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
	r := e.host(e.f)
	t.Logf("base=%d after=%d replay=%d", base, after, r.cost.meter.Snapshot().ResourceCleanupNanoUSD)
	if after != base || r.cost.meter.Snapshot().ResourceCleanupNanoUSD != base {
		t.Fatal("reserve changed by ghost delete")
	}
}

// no-native-gen adapter through the whole revocation matrix
func TestR4NoGenMatrix(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		for _, op := range []string{"reset", "disable", "delete"} {
			for _, mode := range []string{"ok", "lost_committed"} {
				jm, op, mode := jm, op, mode
				t.Run(modeName(jm)+"/"+op+"/"+mode, func(t *testing.T) {
					t.Parallel()
					e := newOpusEnv(t, jm)
					a := &opusNoGen{Fake: e.f}
					h := e.host(a)
					h.UserpoolCreate(false, "gpool")
					h.UserCreate(false, "gpool", "alice", nil)
					h.UserSetPassword(false, "gpool", "alice", "Original123")
					s, _ := h.UserSignIn(false, "gpool", "alice", "Original123")
					if mode != "ok" {
						e.f.SetFaultUserpoolMutatorAfterCommitForTesting(func(string) error {
							return hostkit.ProviderError(hostkit.Internal, 503, "Lost", "x")
						})
					}
					switch op {
					case "reset":
						h.UserSetPassword(false, "gpool", "alice", "Changed456")
					case "disable":
						h.UserSetEnabled(false, "gpool", "alice", false)
					case "delete":
						h.UserDelete(false, "gpool", "alice")
					}
					e.f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
					e.reopen()
					r := e.host(a)
					r.UserVerifyToken(false, "gpool", s.AccessToken())
					oldv := opCode(r)
					// recovery
					switch op {
					case "reset":
						r.UserSetPassword(false, "gpool", "alice", "Changed456")
						ns, _ := r.UserSignIn(false, "gpool", "alice", "Changed456")
						r.UserVerifyToken(false, "gpool", ns.AccessToken())
					case "disable":
						r.UserSetEnabled(false, "gpool", "alice", true)
						ns, _ := r.UserSignIn(false, "gpool", "alice", "Original123")
						r.UserVerifyToken(false, "gpool", ns.AccessToken())
					case "delete":
						r.UserDelete(false, "gpool", "alice")
						r.UserCreate(false, "gpool", "alice", nil)
						r.UserSetPassword(false, "gpool", "alice", "Again12345")
						r.UserVerifyToken(false, "gpool", s.AccessToken())
						if opCode(r) == hostkit.OK {
							t.Fatal("pre-delete token verifies on recreated user")
						}
						ns, _ := r.UserSignIn(false, "gpool", "alice", "Again12345")
						r.UserVerifyToken(false, "gpool", ns.AccessToken())
					}
					t.Logf("old=%s recovered=%s", oldv, opCode(r))
					if oldv == hostkit.OK || opCode(r) != hostkit.OK {
						t.Fatalf("old=%s recovered=%+v", oldv, r.LastError())
					}
				})
			}
		}
	}
}

// out-of-order replies leave a pending intent behind
type opusHoldReply struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *opusHoldReply) SetUserPassword(ctx context.Context, p, u, pw string) (hostkit.UserSnapshot, error) {
	o, e := a.Fake.SetUserPassword(ctx, p, u, pw)
	close(a.entered)
	<-a.release
	return o, e
}

func TestR4LateReplyLeavesPendingStuck(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "lrpool")
			h.UserCreate(false, "lrpool", "alice", nil)
			h.UserSetPassword(false, "lrpool", "alice", "Original123")
			a := &opusHoldReply{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
			slow := e.host(a)
			done := make(chan struct{})
			go func() { defer close(done); slow.UserSetPassword(false, "lrpool", "alice", "Second1234") }()
			<-a.entered // native committed (lower child seq); its reply is delayed
			h.UserCreate(false, "lrpool", "other", nil)
			h.GroupCreate(false, "lrpool", "ops")
			h.UserSetEnabled(false, "lrpool", "alice", false) // higher child seq, journal first
			h.UserSetEnabled(false, "lrpool", "alice", true)
			close(a.release)
			<-done
			act, _, _, _, _ := h.cost.lookupUserpoolEntry("", "lrpool")
			st, _ := decodePersistedUserpoolState(act.StateJSON)
			s, _ := h.UserSignIn(false, "lrpool", "alice", "Second1234")
			sc := opCode(h)
			h.UserVerifyToken(false, "lrpool", s.AccessToken())
			t.Logf("reset=%s pending=%v signin=%s verify=%s", opCode(slow), st.PendingUserRevoke, sc, opCode(h))
			if sc != hostkit.OK || opCode(h) != hostkit.OK {
				t.Fatal("user stuck after out-of-order replies")
			}
		})
	}
}

func TestR4RefusedRevocationKeepsSessions(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "rfpool")
	h.UserCreate(false, "rfpool", "alice", nil)
	h.UserSetPassword(false, "rfpool", "alice", "Original123")
	s, _ := h.UserSignIn(false, "rfpool", "alice", "Original123")
	b := e.host(&opusRefuse{Fake: e.f})
	b.UserSetPassword(false, "rfpool", "alice", "Changed456")
	r := e.host(e.f)
	r.UserVerifyToken(false, "rfpool", s.AccessToken())
	t.Logf("reset=%s verify=%s", opCode(b), opCode(r))
	if opCode(b) == hostkit.PermissionDenied && opCode(r) != hostkit.OK {
		t.Log("accepted fail-closed tradeoff: generation stays monotonic after a refused reset")
	}
}

type opusRefuse struct{ *fakeadapter.Fake }

func (a *opusRefuse) SetUserPassword(context.Context, string, string, string) (hostkit.UserSnapshot, error) {
	return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.PermissionDenied, 403, "AccessDenied", "denied")
}
