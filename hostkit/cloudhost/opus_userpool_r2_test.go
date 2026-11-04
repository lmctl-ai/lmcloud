package cloudhost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

type opusEnv struct {
	t        *testing.T
	f        *fakeadapter.Fake
	state    string
	campaign string
	jdir     string
	j        *safety.Journal
	jm       bool
}

func newOpusEnv(t *testing.T, jm bool) *opusEnv {
	dir := t.TempDir()
	e := &opusEnv{t: t, state: filepath.Join(dir, "fake.json"), campaign: filepath.Join(dir, "campaign.jsonl"), jdir: filepath.Join(dir, "journal"), jm: jm}
	e.f = fakeadapter.New(fakeadapter.Options{StatePath: e.state})
	if jm {
		e.j = openUserpoolSafetyJournal(t, e.jdir)
		t.Cleanup(func() { _ = e.j.Close() })
	}
	return e
}
func (e *opusEnv) host(a hostkit.Userpools) *Host {
	c := Config{Provider: "aws", Store: e.f, Userpools: a}
	if e.jm {
		c.Journal = e.j
	} else {
		c.CampaignStatePath = e.campaign
	}
	h := New(c)
	h.SetAbortOnError(false)
	return h
}
func (e *opusEnv) reopen() {
	if e.jm {
		if err := e.j.Compact(); err != nil {
			e.t.Fatal(err)
		}
		_ = e.j.Close()
		e.j = openUserpoolSafetyJournal(e.t, e.jdir)
	}
}
func opCode(h *Host) hostkit.Code { return h.LastError().Code }
func modeName(jm bool) string {
	if jm {
		return "safety"
	}
	return "campaign"
}

// ---- fenced revocation vs in-flight sign-in
type opusPauseSignIn struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *opusPauseSignIn) SignIn(ctx context.Context, in hostkit.UserSignInInput) (hostkit.SessionSnapshot, error) {
	out, err := a.Fake.SignIn(ctx, in)
	close(a.entered)
	<-a.release
	return out, err
}

func TestOpusUPSignInRacesRevocation(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		for _, c := range []struct {
			name, op string
			lost     bool
		}{{"disable_lost", "SetUserEnabled", true}, {"delete_lost", "DeleteUser", true}, {"reset_lost", "SetUserPassword", true},
			{"disable_ok", "SetUserEnabled", false}, {"delete_ok", "DeleteUser", false}, {"reset_ok", "SetUserPassword", false}} {
			jm, c := jm, c
			t.Run(modeName(jm)+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				e := newOpusEnv(t, jm)
				h := e.host(e.f)
				h.UserpoolCreate(false, "racepool")
				h.UserCreate(false, "racepool", "alice", nil)
				h.UserSetPassword(false, "racepool", "alice", "Original123")
				a := &opusPauseSignIn{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
				slow := e.host(a)
				var sess *Session
				done := make(chan struct{})
				go func() { defer close(done); sess, _ = slow.UserSignIn(false, "racepool", "alice", "Original123") }()
				<-a.entered
				if c.lost {
					op := c.op
					e.f.SetFaultUserpoolMutatorAfterCommitForTesting(func(got string) error {
						if got == op {
							return hostkit.ProviderError(hostkit.Internal, 503, "LostReply", "synthetic")
						}
						return nil
					})
				}
				switch c.op {
				case "SetUserPassword":
					h.UserSetPassword(false, "racepool", "alice", "Changed456")
				case "SetUserEnabled":
					h.UserSetEnabled(false, "racepool", "alice", false)
				case "DeleteUser":
					h.UserDelete(false, "racepool", "alice")
				}
				opResult := opCode(h)
				e.f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
				close(a.release)
				<-done
				e.reopen()
				v := e.host(e.f)
				v.UserVerifyToken(false, "racepool", sess.AccessToken())
				native, _ := e.f.GetUser(context.Background(), "racepool", "alice")
				t.Logf("revocation=%s signin=%s tokenlen=%d native exists=%v enabled=%v verify=%s", opResult, opCode(slow), len(sess.AccessToken()), native.Exists, native.Enabled, opCode(v))
				if opCode(slow) == hostkit.OK && opCode(v) == hostkit.OK {
					t.Fatalf("token verifies after committed %s (native exists=%v enabled=%v)", c.op, native.Exists, native.Enabled)
				}
			})
		}
	}
}

// ---- legal names hitting the journal's forbidden-substring filter
func TestOpusUPLegalNamesVsForbiddenFilter(t *testing.T) {
	for _, jm := range []bool{false, true} {
		for _, c := range []struct {
			name  string
			setup func(h *Host)
		}{
			{"user_password", func(h *Host) { h.UserCreate(false, "namepool", "password", nil) }},
			{"user_access_token", func(h *Host) { h.UserCreate(false, "namepool", "access_token", nil) }},
			{"user_private_key", func(h *Host) { h.UserCreate(false, "namepool", "private_key", nil) }},
			{"group_password", func(h *Host) { h.GroupCreate(false, "namepool", "password") }},
			{"attr_value_password", func(h *Host) {
				h.UserCreate(false, "namepool", "alice", map[string]string{"role": "password"})
			}},
		} {
			t.Run(modeName(jm)+"/"+c.name, func(t *testing.T) {
				e := newOpusEnv(t, jm)
				h := e.host(e.f)
				h.UserpoolCreate(false, "namepool")
				c.setup(h)
				first := h.LastError()
				h.UserCreate(false, "namepool", "bob", nil)
				nextOp := h.LastError()
				e.reopen()
				r := e.host(e.f)
				_, _ = r.UserpoolDelete(false, "namepool")
				del := r.LastError()
				info, _ := e.f.DescribeUserPool(context.Background(), "namepool")
				t.Logf("setup=%s/%s next=%s/%s poolDelete=%s/%s native pool remaining=%v", first.Code, first.ProviderCode, nextOp.Code, nextOp.ProviderCode, del.Code, del.ProviderCode, info.Name != "")
				if first.Code != hostkit.OK || nextOp.Code != hostkit.OK || del.Code != hostkit.OK {
					t.Fatalf("legal name breaks authority: %v | %v | %v", first.Message, nextOp.Message, del.Message)
				}
			})
		}
	}
}

// ---- compaction atomicity (scratch fault point right after Truncate(0))
func opusFill(t *testing.T, h *Host, pool string, min int64, path string) {
	for i := 0; ; i++ {
		h.UserCreate(false, pool, fmt.Sprintf("fill%04d", i), map[string]string{"a": "b"})
		if opCode(h) != hostkit.OK {
			t.Fatal(h.LastError())
		}
		st, err := os.Stat(path)
		if err == nil && st.Size() > min {
			return
		}
		if i > 900 {
			t.Fatal("no growth")
		}
	}
}
func TestOpusUPCompactionCrashWindow(t *testing.T) {
	for _, mode := range []string{"after_truncate", "mid_write"} {
		t.Run(mode, func(t *testing.T) {
			e := newOpusEnv(t, false)
			h := e.host(e.f)
			h.UserpoolCreate(false, "crashpool")
			h.UserCreate(false, "crashpool", "alice", nil)
			h.UserSetPassword(false, "crashpool", "alice", "Original123")
			sess, _ := h.UserSignIn(false, "crashpool", "alice", "Original123")
			h.UserSetPassword(false, "crashpool", "alice", "Changed456") // revoke
			opusFill(t, h, "crashpool", 200<<10, e.campaign)
			before, _ := os.Stat(e.campaign)
			opusCrashHook = func(f *os.File, raw []byte) {
				if mode == "mid_write" {
					_, _ = f.Write(raw[:len(raw)/2+37])
					_ = f.Sync()
				}
				panic("simulated process death")
			}
			defer func() { opusCrashHook = nil }()
			func() {
				defer func() { _ = recover() }()
				for i := 0; i < 40; i++ {
					h.UserCreate(false, "crashpool", fmt.Sprintf("more%03d", i), nil)
				}
			}()
			opusCrashHook = nil
			after, _ := os.Stat(e.campaign)
			r := e.host(e.f)
			r.UserVerifyToken(false, "crashpool", sess.AccessToken())
			vcode := r.LastError()
			r.UserGet(false, "crashpool", "alice")
			gcode := r.LastError()
			_, _ = r.UserpoolDelete(false, "crashpool")
			dcode := r.LastError()
			spent := r.cost.meter.Snapshot().ChargedNanoUSD
			t.Logf("journal before=%d after=%d verify=%s/%s get=%s/%s delete=%s/%s restoredCharged=%d", before.Size(), after.Size(), vcode.Code, vcode.ProviderCode, gcode.Code, gcode.ProviderCode, dcode.Code, dcode.ProviderCode, spent)
			if after.Size() < before.Size()/4 {
				t.Fatalf("crash inside compaction destroyed the authority journal: %d -> %d bytes", before.Size(), after.Size())
			}
			if gcode.Code != hostkit.OK && dcode.Code != hostkit.OK {
				t.Fatalf("crash inside compaction lost ownership: get=%v delete=%v", gcode, dcode)
			}
		})
	}
}

// ---- pending intent survives compaction / replay; rollback fidelity
func TestOpusUPPendingSurvivesCampaignCompaction(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		for _, op := range []string{"SetUserPassword", "SetUserEnabled", "DeleteUser"} {
			jm, op := jm, op
			t.Run(modeName(jm)+"/"+op, func(t *testing.T) {
				t.Parallel()
				e := newOpusEnv(t, jm)
				h := e.host(e.f)
				h.UserpoolCreate(false, "comppool")
				h.UserCreate(false, "comppool", "alice", nil)
				h.UserSetPassword(false, "comppool", "alice", "Original123")
				sess, _ := h.UserSignIn(false, "comppool", "alice", "Original123")
				if !jm {
					opusFill(t, h, "comppool", 300<<10, e.campaign)
				}
				o := op
				e.f.SetFaultUserpoolMutatorAfterCommitForTesting(func(got string) error {
					if got == o {
						return hostkit.ProviderError(hostkit.Internal, 503, "LostReply", "x")
					}
					return nil
				})
				switch op {
				case "SetUserPassword":
					h.UserSetPassword(false, "comppool", "alice", "Changed456")
				case "SetUserEnabled":
					h.UserSetEnabled(false, "comppool", "alice", false)
				case "DeleteUser":
					h.UserDelete(false, "comppool", "alice")
				}
				e.f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
				for i := 0; i < 5; i++ {
					h.UserCreate(false, "comppool", fmt.Sprintf("post%02d", i), nil)
				}
				e.reopen()
				r := e.host(e.f)
				act, _, _, _, _ := r.cost.lookupUserpoolEntry("", "comppool")
				st, _ := decodePersistedUserpoolState(act.StateJSON)
				r.UserVerifyToken(false, "comppool", sess.AccessToken())
				t.Logf("pending=%v verify=%s", st.PendingUserRevoke, opCode(r))
				if opCode(r) == hostkit.OK || st.PendingUserRevoke["alice"] == "" {
					t.Fatal("pending revocation lost across compaction/replay")
				}
			})
		}
	}
}

// A retry after a committed first attempt surfaces a 4xx: the "definitive refusal" rollback resurrects old tokens.
func TestOpusUPDefinitiveAfterCommitRollsBackRevocation(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		for _, cc := range []struct {
			name string
			c    hostkit.Code
			st   int
		}{{"retry401", hostkit.Unauthenticated, 401}, {"retry403", hostkit.PermissionDenied, 403}, {"retry409", hostkit.Conflict, 409}} {
			for _, op := range []string{"SetUserPassword", "SetUserEnabled"} {
				jm, cc, op := jm, cc, op
				t.Run(modeName(jm)+"/"+cc.name+"/"+op, func(t *testing.T) {
					t.Parallel()
					e := newOpusEnv(t, jm)
					h := e.host(e.f)
					h.UserpoolCreate(false, "rbpool")
					h.UserCreate(false, "rbpool", "alice", nil)
					h.UserSetPassword(false, "rbpool", "alice", "Original123")
					sess, _ := h.UserSignIn(false, "rbpool", "alice", "Original123")
					o := op
					e.f.SetFaultUserpoolMutatorAfterCommitForTesting(func(got string) error {
						if got == o {
							return hostkit.ProviderError(cc.c, cc.st, "RetryRefused", "first attempt committed, reply lost, SDK retry refused")
						}
						return nil
					})
					if op == "SetUserPassword" {
						h.UserSetPassword(false, "rbpool", "alice", "Changed456")
					} else {
						h.UserSetEnabled(false, "rbpool", "alice", false)
					}
					e.f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
					e.reopen()
					r := e.host(e.f)
					r.UserVerifyToken(false, "rbpool", sess.AccessToken())
					t.Logf("mutator=%s verify=%s", opCode(h), opCode(r))
					if opCode(r) == hostkit.OK {
						t.Fatal("old token verifies after a natively committed revocation")
					}
				})
			}
		}
	}
}

func TestOpusUPDeleteRefusedDropsLiveBindings(t *testing.T) {
	for _, jm := range []bool{false, true} {
		t.Run(modeName(jm), func(t *testing.T) {
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "refpool")
			h.UserCreate(false, "refpool", "alice", nil)
			h.UserSetPassword(false, "refpool", "alice", "Original123")
			sess, _ := h.UserSignIn(false, "refpool", "alice", "Original123")
			a := &opusRefuseDelete{Fake: e.f}
			d := e.host(a)
			d.UserDelete(false, "refpool", "alice")
			e.reopen()
			r := e.host(e.f)
			r.UserVerifyToken(false, "refpool", sess.AccessToken())
			t.Logf("delete=%s verify=%s", opCode(d), opCode(r))
			if opCode(d) == hostkit.PermissionDenied && opCode(r) != hostkit.OK {
				t.Fatal("definitive pre-dispatch-class refusal: session for a still-existing user lost (rollback does not restore bindings)")
			}
		})
	}
}

type opusRefuseDelete struct{ *fakeadapter.Fake }

func (a *opusRefuseDelete) DeleteUser(context.Context, string, string) error {
	return hostkit.ProviderError(hostkit.PermissionDenied, 403, "AccessDenied", "denied")
}

// ---- child owner under native lock on non-mutator paths
func opusSetChildOwner(t *testing.T, state, pool, user, owner string) {
	raw, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["Userpools"].(map[string]any)[pool].(map[string]any)["users"].(map[string]any)[user].(map[string]any)["owner_token"] = owner
	raw, _ = json.Marshal(doc)
	if err = os.WriteFile(state, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
func TestOpusUPForeignChildReadsAndAuth(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		for _, owner := range []string{"", strings.Repeat("f", 32)} {
			jm, owner := jm, owner
			t.Run(modeName(jm)+"/owner="+owner, func(t *testing.T) {
				t.Parallel()
				e := newOpusEnv(t, jm)
				h := e.host(e.f)
				h.UserpoolCreate(false, "ownpool")
				h.UserCreate(false, "ownpool", "alice", map[string]string{"email": "alice@example.com"})
				h.UserSetPassword(false, "ownpool", "alice", "Original123")
				pre, _ := h.UserSignIn(false, "ownpool", "alice", "Original123")
				h.GroupCreate(false, "ownpool", "admins")
				h.GroupAddUser(false, "ownpool", "admins", "alice")
				opusSetChildOwner(t, e.state, "ownpool", "alice", owner)
				e.reopen()
				h = e.host(e.f)
				var fails []string
				u, _ := h.UserGet(false, "ownpool", "alice")
				t.Logf("user_get exists=%v code=%s", u.Exists(), opCode(h))
				if opCode(h) == hostkit.OK && u.Exists() {
					fails = append(fails, "user_get")
				}
				s, _ := h.UserSignIn(false, "ownpool", "alice", "Original123")
				t.Logf("sign_in tok=%v code=%s", s.AccessToken() != "", opCode(h))
				if s.AccessToken() != "" {
					fails = append(fails, "sign_in")
					h.UserVerifyToken(false, "ownpool", s.AccessToken())
					t.Logf("verify fresh token on foreign child=%s", opCode(h))
					if opCode(h) == hostkit.OK {
						fails = append(fails, "verify_new")
					}
				}
				h.UserVerifyToken(false, "ownpool", pre.AccessToken())
				t.Logf("verify pre-existing token=%s", opCode(h))
				if opCode(h) == hostkit.OK {
					fails = append(fails, "verify_old")
				}
				g, _ := h.UserGroups(false, "ownpool", "alice")
				t.Logf("user_groups=%v code=%s", g, opCode(h))
				if opCode(h) == hostkit.OK && len(g) > 0 {
					fails = append(fails, "user_groups")
				}
				if len(fails) > 0 {
					t.Fatalf("foreign-owned child accepted on: %v", fails)
				}
			})
		}
	}
}

// ---- incarnation
type opusDescribeFail struct{ *fakeadapter.Fake }

func (a *opusDescribeFail) DescribeUserPool(context.Context, string) (hostkit.UserpoolInfo, error) {
	return hostkit.UserpoolInfo{}, hostkit.ProviderError(hostkit.Internal, 503, "ServiceUnavailable", "describe down")
}
func TestOpusUPIncarnationFailClosed(t *testing.T) {
	for _, jm := range []bool{false, true} {
		for _, down := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/describe_down=%v", modeName(jm), down), func(t *testing.T) {
				e := newOpusEnv(t, jm)
				h := e.host(e.f)
				h.UserpoolCreate(false, "incpool")
				h.UserCreate(false, "incpool", "alice", nil)
				h.GroupCreate(false, "incpool", "ops")
				old, _ := e.f.DescribeUserPool(context.Background(), "incpool")
				if err := e.f.InjectUnmarkedUserpoolForTesting("incpool", old.OwnerToken); err != nil {
					t.Fatal(err)
				}
				e.reopen()
				var a hostkit.Userpools = e.f
				if down {
					a = &opusDescribeFail{Fake: e.f}
				}
				r := e.host(a)
				var ok []string
				r.UserGet(false, "incpool", "alice")
				t.Logf("user_get=%s", opCode(r))
				if opCode(r) == hostkit.OK {
					ok = append(ok, "user_get")
				}
				r.GroupList(false, "incpool")
				t.Logf("group_list=%s", opCode(r))
				if opCode(r) == hostkit.OK {
					ok = append(ok, "group_list")
				}
				r.UserList(false, "incpool", 10, "")
				t.Logf("user_list=%s", opCode(r))
				if opCode(r) == hostkit.OK {
					ok = append(ok, "user_list")
				}
				r.UserSignIn(false, "incpool", "alice", "Original123")
				t.Logf("sign_in=%s", opCode(r))
				if len(ok) > 0 {
					t.Fatalf("read path served a replaced physical incarnation: %v", ok)
				}
			})
		}
	}
}

// ---- duplicate create vs concurrent child ops
type opusPauseCreate struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *opusPauseCreate) CreateUserPool(ctx context.Context, in hostkit.UserpoolCreateInput) (bool, hostkit.UserpoolInfo, error) {
	c, i, err := a.Fake.CreateUserPool(ctx, in)
	close(a.entered)
	<-a.release
	return c, i, err
}

type opusPausePw struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *opusPausePw) SetUserPassword(ctx context.Context, p, u, pw string) (hostkit.UserSnapshot, error) {
	o, e := a.Fake.SetUserPassword(ctx, p, u, pw)
	close(a.entered)
	<-a.release
	return o, e
}

type opusPauseUserCreate struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *opusPauseUserCreate) CreateUser(ctx context.Context, in hostkit.UserCreateInput) (hostkit.UserSnapshot, error) {
	o, e := a.Fake.CreateUser(ctx, in)
	close(a.entered)
	<-a.release
	return o, e
}

func TestOpusUPDuplicateCreateSerial(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "duppool")
			h.UserCreate(false, "duppool", "alice", nil)
			h.UserSetPassword(false, "duppool", "alice", "FirstPass123")
			sess, _ := h.UserSignIn(false, "duppool", "alice", "FirstPass123")
			a := &opusPausePw{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
			slow := e.host(a)
			done := make(chan struct{})
			go func() { defer close(done); slow.UserSetPassword(false, "duppool", "alice", "SecondPass456") }()
			<-a.entered
			created, _ := h.UserpoolCreate(false, "duppool")
			dup := opCode(h)
			close(a.release)
			<-done
			e.reopen()
			r := e.host(e.f)
			r.UserVerifyToken(false, "duppool", sess.AccessToken())
			t.Logf("dup=%s created=%v reset=%s oldverify=%s", dup, created, opCode(slow), opCode(r))
			if opCode(r) == hostkit.OK {
				t.Fatal("old token survives")
			}
			if opCode(slow) == hostkit.OK {
				s2, _ := r.UserSignIn(false, "duppool", "alice", "SecondPass456")
				r.UserVerifyToken(false, "duppool", s2.AccessToken())
				if opCode(r) != hostkit.OK {
					t.Fatal("new session broken", r.LastError())
				}
			}
		})
	}
}

func TestOpusUPCreateInFlightDuringChild(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm)+"/reset_finishes_during_dup_create", func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "dup2pool")
			h.UserCreate(false, "dup2pool", "alice", nil)
			h.UserSetPassword(false, "dup2pool", "alice", "FirstPass123")
			sess, _ := h.UserSignIn(false, "dup2pool", "alice", "FirstPass123")
			pw := &opusPausePw{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
			slow := e.host(pw)
			d1 := make(chan struct{})
			go func() { defer close(d1); slow.UserSetPassword(false, "dup2pool", "alice", "SecondPass456") }()
			<-pw.entered
			pc := &opusPauseCreate{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
			dh := e.host(pc)
			d2 := make(chan struct{})
			go func() { defer close(d2); dh.UserpoolCreate(false, "dup2pool") }()
			<-pc.entered
			close(pw.release)
			<-d1
			close(pc.release)
			<-d2
			e.reopen()
			r := e.host(e.f)
			r.UserVerifyToken(false, "dup2pool", sess.AccessToken())
			oldv := opCode(r)
			s2, _ := r.UserSignIn(false, "dup2pool", "alice", "SecondPass456")
			sc := opCode(r)
			r.UserVerifyToken(false, "dup2pool", s2.AccessToken())
			t.Logf("reset=%s(%s) dup=%s oldverify=%s newsignin=%s newverify=%s", opCode(slow), slow.LastError().ProviderCode, opCode(dh), oldv, sc, opCode(r))
			if oldv == hostkit.OK {
				t.Fatal("old token verifies")
			}
			if sc != hostkit.OK || opCode(r) != hostkit.OK {
				t.Fatal("user not recoverable after reset raced duplicate create")
			}
		})
		t.Run(modeName(jm)+"/user_create_finishes_during_dup_create", func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "dup3pool")
			uc := &opusPauseUserCreate{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
			slow := e.host(uc)
			d1 := make(chan struct{})
			go func() { defer close(d1); slow.UserCreate(false, "dup3pool", "carol", nil) }()
			<-uc.entered
			pc := &opusPauseCreate{Fake: e.f, entered: make(chan struct{}), release: make(chan struct{})}
			dh := e.host(pc)
			d2 := make(chan struct{})
			go func() { defer close(d2); dh.UserpoolCreate(false, "dup3pool") }()
			<-pc.entered
			close(uc.release)
			<-d1
			close(pc.release)
			<-d2
			e.reopen()
			r := e.host(e.f)
			nat, _ := e.f.GetUser(context.Background(), "dup3pool", "carol")
			act, _, _, _, _ := r.cost.lookupUserpoolEntry("", "dup3pool")
			st, _ := decodePersistedUserpoolState(act.StateJSON)
			_, inJ := st.Users["carol"]
			r.UserSetPassword(false, "dup3pool", "carol", "CarolPass123")
			pc2 := opCode(r)
			s, _ := r.UserSignIn(false, "dup3pool", "carol", "CarolPass123")
			r.UserVerifyToken(false, "dup3pool", s.AccessToken())
			v := opCode(r)
			r.UserpoolDelete(false, "dup3pool")
			t.Logf("user_create=%s dup=%s native=%v journal=%v setpw=%s verify=%s delete=%s cleanupLocked=%d", opCode(slow), opCode(dh), nat.Exists, inJ, pc2, v, opCode(r), r.cost.meter.Snapshot().ResourceCleanupNanoUSD)
			if nat.Exists && !inJ && opCode(slow) == hostkit.OK {
				t.Fatal("native child committed, reported OK, not journaled")
			}
			if nat.Exists && !inJ {
				t.Fatal("native child committed but authority lost it; user cannot be used for tokens")
			}
		})
	}
}

// ---- token kind / client binding
type opusBadTok struct {
	*fakeadapter.Fake
	claims func(in hostkit.UserSignInInput, out hostkit.SessionSnapshot, iss, client string) map[string]any
}

func (a *opusBadTok) SignIn(ctx context.Context, in hostkit.UserSignInInput) (hostkit.SessionSnapshot, error) {
	out, e := a.Fake.SignIn(ctx, in)
	if e != nil {
		return out, e
	}
	priv, _, kid, issuer, client, _, _, _ := a.Fake.UserpoolSigningKeyMaterialForTesting(in.Pool)
	out.AccessToken, e = hostkit.MintRS256JWT(priv, kid, a.claims(in, out, issuer, client))
	return out, e
}
func TestOpusUPTokenBinding(t *testing.T) {
	t.Parallel()
	base := func(in hostkit.UserSignInInput, out hostkit.SessionSnapshot, iss string) map[string]any {
		return map[string]any{"sub": out.Claims["sub"], "username": in.Username, "iss": iss, "iat": out.IssuedAt, "exp": out.ExpiresAt, "token_use": "access"}
	}
	for name, fn := range map[string]func(hostkit.UserSignInInput, hostkit.SessionSnapshot, string, string) map[string]any{
		"wrong_client": func(in hostkit.UserSignInInput, o hostkit.SessionSnapshot, iss, c string) map[string]any {
			m := base(in, o, iss)
			m["client_id"] = "otherclient"
			return m
		},
		"no_client": func(in hostkit.UserSignInInput, o hostkit.SessionSnapshot, iss, c string) map[string]any {
			return base(in, o, iss)
		},
		"id_token": func(in hostkit.UserSignInInput, o hostkit.SessionSnapshot, iss, c string) map[string]any {
			m := base(in, o, iss)
			m["client_id"] = c
			m["token_use"] = "id"
			return m
		},
		"wrong_username": func(in hostkit.UserSignInInput, o hostkit.SessionSnapshot, iss, c string) map[string]any {
			m := base(in, o, iss)
			m["client_id"] = c
			m["username"] = "mallory"
			return m
		},
		"wrong_sub": func(in hostkit.UserSignInInput, o hostkit.SessionSnapshot, iss, c string) map[string]any {
			m := base(in, o, iss)
			m["client_id"] = c
			m["sub"] = "different-sub"
			return m
		},
	} {
		name, fn := name, fn
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, false)
			h := e.host(e.f)
			h.UserpoolCreate(false, "tokpool")
			h.UserCreate(false, "tokpool", "alice", nil)
			h.UserCreate(false, "tokpool", "mallory", nil)
			h.UserSetPassword(false, "tokpool", "alice", "Original123")
			b := e.host(&opusBadTok{Fake: e.f, claims: fn})
			s, _ := b.UserSignIn(false, "tokpool", "alice", "Original123")
			sc := opCode(b)
			b.UserVerifyToken(false, "tokpool", s.AccessToken())
			t.Logf("sign_in=%s returned_token=%v verify=%s", sc, s.AccessToken() != "", opCode(b))
			if opCode(b) == hostkit.OK {
				t.Fatal("verified bad token")
			}
			if sc == hostkit.OK && s.AccessToken() != "" {
				t.Fatal("sign-in reported success and returned a token that can never verify")
			}
		})
	}
}

// ---- timing
func med(xs []time.Duration) time.Duration {
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	return xs[len(xs)/2]
}
func TestOpusUPSignInTimingAllPaths(t *testing.T) {
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "timepool")
	h.UserCreate(false, "timepool", "pwless", nil)
	h.UserCreate(false, "timepool", "active", nil)
	h.UserSetPassword(false, "timepool", "active", "Actual12345")
	h.UserCreate(false, "timepool", "disabled", nil)
	h.UserSetPassword(false, "timepool", "disabled", "Actual12345")
	h.UserSetEnabled(false, "timepool", "disabled", false)
	paths := []struct{ n, u, p string }{{"missing", "nobody", "Guess12345"}, {"passwordless", "pwless", "Guess12345"}, {"wrong", "active", "Guess12345"}, {"disabled_wrong", "disabled", "Guess12345"}, {"disabled_right", "disabled", "Actual12345"}}
	res := map[string]time.Duration{}
	for round := 0; round < 7; round++ {
		for _, p := range paths {
			st := time.Now()
			h.UserSignIn(false, "timepool", p.u, p.p)
			d := time.Since(st)
			if opCode(h) != hostkit.Unauthenticated {
				t.Fatal(p.n, h.LastError())
			}
			res[p.n+fmt.Sprint(round)] = d
		}
	}
	var lo, hi time.Duration
	for _, p := range paths {
		var xs []time.Duration
		for r := 1; r < 7; r++ {
			xs = append(xs, res[p.n+fmt.Sprint(r)])
		}
		m := med(xs)
		t.Logf("%s median %s", p.n, m)
		if lo == 0 || m < lo {
			lo = m
		}
		if m > hi {
			hi = m
		}
	}
	msgs := map[string]bool{}
	for _, p := range paths {
		h.UserSignIn(false, "timepool", p.u, p.p)
		le := h.LastError()
		msgs[fmt.Sprintf("%s|%d|%s|%s", le.Code, le.HTTPStatus, le.ProviderCode, le.Message)] = true
	}
	t.Logf("distinct error shapes: %v", msgs)
	if float64(hi) > 1.5*float64(lo) || len(msgs) != 1 {
		t.Fatalf("sign-in timing/shape differ lo=%s hi=%s", lo, hi)
	}
}

// ---- secrets
type opusEchoAdapter struct{ *fakeadapter.Fake }

func (a *opusEchoAdapter) SignIn(_ context.Context, in hostkit.UserSignInInput) (hostkit.SessionSnapshot, error) {
	return hostkit.SessionSnapshot{}, hostkit.ProviderError(hostkit.Internal, 500, "Echo", "backend said password="+in.Password+" bad, raw "+in.Password)
}
func (a *opusEchoAdapter) SetUserPassword(_ context.Context, p, u, pw string) (hostkit.UserSnapshot, error) {
	return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.Internal, 500, "Echo", "rejected "+pw+" json \""+pw+"\"")
}
func TestOpusUPSecretCanaries(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			pw1, pw2, wrong := "CanaryPassA1x9", "CanaryPassB2y8", "CanaryWrongC3z7"
			h.UserpoolCreate(false, "secpool")
			attrs := map[string]string{"bio": strings.Repeat("profile ", 40)}
			h.UserCreate(false, "secpool", "alice", attrs)
			h.UserSetPassword(false, "secpool", "alice", pw1)
			s1, _ := h.UserSignIn(false, "secpool", "alice", pw1)
			h.UserSignIn(false, "secpool", "alice", wrong)
			h.UserVerifyToken(false, "secpool", s1.AccessToken())
			h.UserSetPassword(false, "secpool", "alice", pw2)
			s2, _ := h.UserSignIn(false, "secpool", "alice", pw2)
			var msgs []string
			ea := e.host(&opusEchoAdapter{Fake: e.f})
			ea.UserSignIn(false, "secpool", "alice", wrong)
			msgs = append(msgs, fmt.Sprintf("%+v", ea.LastError()))
			ea.UserSetPassword(false, "secpool", "alice", "CanaryEchoD4w6")
			msgs = append(msgs, fmt.Sprintf("%+v", ea.LastError()))
			ea.SetAbortOnError(true)
			_, ab := ea.UserSignIn(false, "secpool", "alice", wrong)
			msgs = append(msgs, fmt.Sprint(ab))
			salt, hash, _, _ := e.f.UserpoolRawPasswordEntryForTesting("secpool", "alice")
			needles := []string{pw1, pw2, wrong, "CanaryEchoD4w6", s1.AccessToken(), s2.AccessToken(), hash, salt}
			for _, seg := range strings.Split(s1.AccessToken(), ".") {
				needles = append(needles, seg)
			}
			var blobs []string
			root := filepath.Dir(e.campaign)
			_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
				if err == nil && !fi.IsDir() && p != e.state && !strings.HasPrefix(filepath.Base(p), "fake.json") {
					b, _ := os.ReadFile(p)
					blobs = append(blobs, p+"\x00"+string(b))
					if fi.Mode().Perm()&0o077 != 0 {
						t.Errorf("file perms %o %s", fi.Mode().Perm(), p)
					}
				}
				return nil
			})
			t.Logf("scanned files=%d", len(blobs))
			for _, n := range needles {
				if n == "" {
					continue
				}
				for _, b := range blobs {
					if strings.Contains(b, n) {
						t.Errorf("secret %.12s… found in %s", n, strings.SplitN(b, "\x00", 2)[0])
					}
				}
				for _, m := range msgs {
					if strings.Contains(m, n) {
						t.Errorf("secret %.12s… in error %s", n, m)
					}
				}
			}
			_ = hex.EncodeToString
		})
	}
}

// ---- churn
func TestOpusUPIdempotentDeleteGrowsAuthority(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "churnpool")
			tStart := time.Now()
			for i := 0; i < 400; i++ {
				h.UserDelete(false, "churnpool", fmt.Sprintf("ghost%05d", i))
				if opCode(h) != hostkit.OK {
					t.Fatal(i, h.LastError())
				}
			}
			e.reopen()
			r := e.host(e.f)
			act, _, _, _, _ := r.cost.lookupUserpoolEntry("", "churnpool")
			st, _ := decodePersistedUserpoolState(act.StateJSON)
			tEnd := time.Since(tStart)
			t.Logf("elapsed=%s users=%d revokedGen=%d userSeq=%d statebytes=%d", tEnd, len(st.Users), len(st.RevokedSessionGen), len(st.UserSeq), len(act.StateJSON))
			if len(st.RevokedSessionGen) > 0 {
				t.Fatal("per-user revocation/sequence maps grow without bound for users that never existed")
			}
		})
	}
}
func TestOpusUPProfileBlobsAfterDelete(t *testing.T) {
	for _, jm := range []bool{false, true} {
		t.Run(modeName(jm), func(t *testing.T) {
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "blobpool")
			for i := 0; i < 50; i++ {
				u := fmt.Sprintf("user%03d", i)
				h.UserCreate(false, "blobpool", u, map[string]string{"ssn": fmt.Sprintf("%0300d", i)})
				h.UserDelete(false, "blobpool", u)
			}
			h.UserpoolDelete(false, "blobpool")
			dir := h.userpoolProfileDir()
			ents, _ := os.ReadDir(dir)
			t.Logf("pool deleted (%s); profile blobs remaining=%d", opCode(h), len(ents))
			if len(ents) != 0 {
				t.Fatal("deleted users' profile attributes stay on disk unbounded after user and pool delete")
			}
		})
	}
}
func TestOpusUPProfileLossOnBlobWriteFailure(t *testing.T) {
	for _, jm := range []bool{false, true} {
		t.Run(modeName(jm), func(t *testing.T) {
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			if err := os.WriteFile(h.userpoolProfileDir(), []byte("x"), 0o600); err != nil { // dir creation fails
				t.Fatal(err)
			}
			h.UserpoolCreate(false, "lostpool")
			h.UserCreate(false, "lostpool", "alice", map[string]string{"bio": strings.Repeat("z", 400)})
			c := opCode(h)
			userpoolProfileCacheMu.Lock()
			userpoolProfileCache = make(map[string]map[string]string, 64)
			userpoolProfileCacheBytes = 0
			userpoolProfileCacheMu.Unlock()
			e.reopen()
			r := e.host(e.f)
			act, _, _, _, _ := r.cost.lookupUserpoolEntry("", "lostpool")
			st, _ := decodePersistedUserpoolState(act.StateJSON)
			t.Logf("create=%s journal attrs=%d hash=%q", c, len(st.Users["alice"].Attributes), st.UserProfileHashes["alice"])
			if c == hostkit.OK && len(st.Users["alice"].Attributes) == 0 {
				t.Fatal("profile silently lost: blob write failure ignored and journal keeps only the hash")
			}
		})
	}
}
func TestOpusUPProfileCacheHeap(t *testing.T) {
	attrs := map[string]string{}
	for i := 0; i < 32; i++ {
		attrs[fmt.Sprintf("attr%d", i)] = strings.Repeat("x", 2048)
	}
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	for i := 0; i < 4000; i++ {
		c := map[string]string{}
		for k, v := range attrs {
			c[k] = string(append([]byte(nil), v...))
		}
		cacheUserProfileAttrs(fmt.Sprintf("%064d", i), c)
	}
	runtime.GC()
	runtime.ReadMemStats(&b)
	t.Logf("process-global profile cache retained %d MiB after 4000 distinct legal profiles", (b.HeapAlloc-a.HeapAlloc)>>20)
	if (b.HeapAlloc-a.HeapAlloc)>>20 > 64 {
		t.Fatal("global profile cache bound is entries only; retained bytes are not bounded for legal profiles")
	}
}

// ---- journal size admission with legal state (injected authoritative state, 2000 users + bindings)
func TestOpusUPLegalCatalogExceedsJournalCaps(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "bigpool")
			h.UserCreate(false, "bigpool", "alice", nil)
			act, _, _, _, _ := h.cost.lookupUserpoolEntry("", "bigpool")
			// a pool at its documented caps: 2000 users, 128 live bindings/user
			if cerr := h.cost.updateUserpoolState("", "bigpool", act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
				st, _ := decodePersistedUserpoolState(cur)
				for i := 0; i < 2000; i++ {
					u := fmt.Sprintf("user%04d", i)
					st.Users[u] = hostkit.UserSnapshot{Exists: true, Username: u, Sub: fmt.Sprintf("%032d", i), Enabled: true, Status: hostkit.UserStatusConfirmed, SessionGen: 2}
					b := make([]tokenBindingRecord, 0, 128)
					for j := 0; j < 128; j++ {
						b = append(b, tokenBindingRecord{TokenSHA256: strings.Repeat("a", 64), Sub: fmt.Sprintf("%032d", i), Username: u, PoolID: "pool-bigpool", IncarnationID: act.Incarnation, SessionGen: 2, IssuedAt: 1, ExpiresAt: 4102444800, Scope: strings.Repeat("c", 64)})
					}
					st.TokenBindings[u] = b
				}
				return encodePersistedUserpoolState(st)
			}); cerr != nil {
				t.Logf("legal capped state refused: %v", cerr)
			}
			h.UserSetPassword(false, "bigpool", "alice", "Original123")
			a := h.LastError()
			h.UserCreate(false, "bigpool", "bob", nil)
			b := h.LastError()
			_, _ = h.UserpoolDelete(false, "bigpool")
			d := h.LastError()
			t.Logf("reset=%s/%s create=%s/%s delete=%s/%s", a.Code, a.ProviderCode, b.Code, b.ProviderCode, d.Code, d.ProviderCode)
			if d.Code != hostkit.OK {
				t.Fatalf("pool at documented caps cannot be cleaned up: %+v", d)
			}
		})
	}
}

var _ sync.Mutex
