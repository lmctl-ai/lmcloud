package cloudhost

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
)

func clearProfileCaches() {
	userpoolProfileCacheMu.Lock()
	userpoolProfileCache = make(map[string]map[string]string, 64)
	userpoolProfileCacheBytes = 0
	userpoolProfileCacheMu.Unlock()
}

func TestR3CompactionKillEachStep(t *testing.T) {
	baseE := newOpusEnv(t, false)
	baseH := baseE.host(baseE.f)
	baseH.UserpoolCreate(false, "crashpool")
	baseH.UserCreate(false, "crashpool", "alice", nil)
	baseH.UserSetPassword(false, "crashpool", "alice", "Original123")
	old, _ := baseH.UserSignIn(false, "crashpool", "alice", "Original123")
	baseH.UserSetPassword(false, "crashpool", "alice", "Changed456")
	live, _ := baseH.UserSignIn(false, "crashpool", "alice", "Changed456")
	opusFill(t, baseH, "crashpool", 305<<10, baseE.campaign)
	spentBefore := baseH.cost.meter.Snapshot()
	baseStateBytes, err := os.ReadFile(baseE.state)
	if err != nil {
		t.Fatal(err)
	}
	baseCampaignBytes, err := os.ReadFile(baseE.campaign)
	if err != nil {
		t.Fatal(err)
	}

	for _, step := range []string{"tmp_open", "tmp_written", "tmp_synced", "renamed", "dir_synced"} {
		t.Run(step, func(t *testing.T) {
			e := newOpusEnv(t, false)
			if err := os.WriteFile(e.state, baseStateBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(e.campaign, baseCampaignBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			e.reopen()
			h := e.host(e.f)
			hit := false
			opusStepHook = func(s string) {
				if s == step {
					hit = true
					panic("kill")
				}
			}
			defer func() { opusStepHook = nil }()
			func() {
				defer func() { _ = recover() }()
				for i := 0; i < 80 && !hit; i++ {
					h.UserCreate(false, "crashpool", fmt.Sprintf("more%03d", i), nil)
				}
			}()
			opusStepHook = nil
			if !hit {
				t.Fatal("step not reached")
			}
			r := e.host(e.f)
			r.UserVerifyToken(false, "crashpool", old.AccessToken())
			vOld := opCode(r)
			r.UserVerifyToken(false, "crashpool", live.AccessToken())
			vLive := opCode(r)
			r.UserCreate(false, "crashpool", "afterkill", nil)
			next := opCode(r)
			_, tmpErr := os.Stat(e.campaign + ".compact.tmp")
			s := r.cost.meter.Snapshot()
			t.Logf("revoked=%s live=%s next=%s tmpLeft=%v charged %d->%d cleanup %d->%d", vOld, vLive, next, tmpErr == nil, spentBefore.ChargedNanoUSD, s.ChargedNanoUSD, spentBefore.ResourceCleanupNanoUSD, s.ResourceCleanupNanoUSD)
			if vOld == hostkit.OK || vLive != hostkit.OK || next != hostkit.OK || tmpErr == nil || s.ChargedNanoUSD < spentBefore.ChargedNanoUSD {
				t.Fatal("authority changed by crash in compaction")
			}
			r.UserpoolDelete(false, "crashpool")
			if opCode(r) != hostkit.OK {
				t.Fatal(r.LastError())
			}
		})
	}
}

func TestR3CompactionDirSyncFailureLosesAppends(t *testing.T) {
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "dspool")
	h.UserCreate(false, "dspool", "alice", nil)
	for i := 0; ; i++ {
		h.UserCreate(false, "dspool", fmt.Sprintf("fill%04d", i), nil)
		fi, _ := os.Stat(e.campaign)
		if fi.Size() > 311<<10 {
			break
		}
	}
	fired := 0
	opusDirSyncFail = func() bool { fired++; return fired == 1 }
	defer func() { opusDirSyncFail = nil }()
	h.UserCreate(false, "dspool", "bobafter", nil)
	c1 := h.LastError()
	opusDirSyncFail = nil
	r := e.host(e.f)
	act, _, _, _, cerr := r.cost.lookupUserpoolEntry("", "dspool")
	st, _ := decodePersistedUserpoolState(act.StateJSON)
	_, in := st.Users["bobafter"]
	r.UserGet(false, "dspool", "bobafter")
	g := r.LastError()
	h2 := r.cost.meter.Snapshot()
	t.Logf("fired=%d create=%s/%s journaled=%v lookup=%v get=%s/%s charged=%d", fired, c1.Code, c1.ProviderCode, in, cerr, g.Code, g.ProviderCode, h2.ChargedNanoUSD)
	if fired == 0 {
		t.Fatal("fault not reached")
	}
	if cerr != nil || g.Code != hostkit.OK || (c1.Code == hostkit.OK && !in) {
		t.Fatal("append after failed dir fsync went to the unlinked inode")
	}
}

func TestR3ConcurrentHostsDuringCompaction(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "chpool")
	opusFill(t, h, "chpool", 300<<10, e.campaign)
	var wg sync.WaitGroup
	errs := make(chan string, 400)
	for w := 0; w < 4; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := e.host(e.f)
			for i := 0; i < 25; i++ {
				c.UserCreate(false, "chpool", fmt.Sprintf("w%dx%03d", w, i), nil)
				if opCode(c) != hostkit.OK {
					errs <- fmt.Sprintf("%+v", c.LastError())
				}
				c.UserGet(false, "chpool", "fill0001")
				if opCode(c) != hostkit.OK {
					errs <- fmt.Sprintf("%+v", c.LastError())
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	n := 0
	for m := range errs {
		if n < 3 {
			t.Log(m)
		}
		n++
	}
	r := e.host(e.f)
	act, _, _, _, cerr := r.cost.lookupUserpoolEntry("", "chpool")
	st, _ := decodePersistedUserpoolState(act.StateJSON)
	cnt := 0
	for u := range st.Users {
		if strings.HasPrefix(u, "w") {
			cnt++
		}
	}
	fi, _ := os.Stat(e.campaign)
	t.Logf("errs=%d journaled=%d/100 size=%d cerr=%v", n, cnt, fi.Size(), cerr)
	if n > 0 || cnt != 100 {
		t.Fatal("concurrent compaction lost or failed mutations")
	}
}

// request never reached the provider: the journal generation is ahead of native
type opusReqLost struct {
	*fakeadapter.Fake
	lost bool
}

func (a *opusReqLost) SetUserPassword(ctx context.Context, p, u, pw string) (hostkit.UserSnapshot, error) {
	if a.lost {
		return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.Internal, 503, "ConnReset", "request not delivered")
	}
	return a.Fake.SetUserPassword(ctx, p, u, pw)
}
func (a *opusReqLost) SetUserEnabled(ctx context.Context, p, u string, en bool) (hostkit.UserSnapshot, error) {
	if a.lost {
		return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.Internal, 503, "ConnReset", "request not delivered")
	}
	return a.Fake.SetUserEnabled(ctx, p, u, en)
}
func TestR3UndeliveredRevocationThenRecovery(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm)+"/reset_retry", func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			a := &opusReqLost{Fake: e.f}
			h := e.host(a)
			h.UserpoolCreate(false, "rlpool")
			h.UserCreate(false, "rlpool", "alice", nil)
			h.UserSetPassword(false, "rlpool", "alice", "Original123")
			a.lost = true
			h.UserSetPassword(false, "rlpool", "alice", "Changed456")
			first := opCode(h)
			a.lost = false
			h.UserSetPassword(false, "rlpool", "alice", "Changed456")
			second := opCode(h)
			s, _ := h.UserSignIn(false, "rlpool", "alice", "Changed456")
			sc := opCode(h)
			h.UserVerifyToken(false, "rlpool", s.AccessToken())
			t.Logf("first=%s retry=%s signin=%s verify=%s", first, second, sc, opCode(h))
			if second != hostkit.OK || sc != hostkit.OK || opCode(h) != hostkit.OK {
				t.Fatal("user locked out after a transient undelivered reset followed by a successful retry")
			}
		})
		t.Run(modeName(jm)+"/disable_then_enable", func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			a := &opusReqLost{Fake: e.f}
			h := e.host(a)
			h.UserpoolCreate(false, "rlpool")
			h.UserCreate(false, "rlpool", "alice", nil)
			h.UserSetPassword(false, "rlpool", "alice", "Original123")
			a.lost = true
			h.UserSetEnabled(false, "rlpool", "alice", false)
			a.lost = false
			h.UserSetEnabled(false, "rlpool", "alice", true)
			en := opCode(h)
			s, _ := h.UserSignIn(false, "rlpool", "alice", "Original123")
			sc := opCode(h)
			h.UserVerifyToken(false, "rlpool", s.AccessToken())
			t.Logf("enable=%s signin=%s verify=%s", en, sc, opCode(h))
			if sc != hostkit.OK || opCode(h) != hostkit.OK {
				t.Fatal("enabled user cannot sign in after an undelivered disable")
			}
		})
	}
}

// adapter without a native session generation (Cognito-like) and without child sequences
type opusNoGen struct {
	*fakeadapter.Fake
	reject bool
}

func stripGen(s hostkit.UserSnapshot) hostkit.UserSnapshot { s.SessionGen = 0; s.ChildSeq = 0; return s }
func noSeq(ctx context.Context) context.Context {
	var x uint64
	return hostkit.WithUserpoolChildMutationSeqOut(ctx, &x)
}
func (a *opusNoGen) GetUser(ctx context.Context, p, u string) (hostkit.UserSnapshot, error) {
	s, e := a.Fake.GetUser(ctx, p, u)
	return stripGen(s), e
}
func (a *opusNoGen) CreateUser(ctx context.Context, in hostkit.UserCreateInput) (hostkit.UserSnapshot, error) {
	s, e := a.Fake.CreateUser(noSeq(ctx), in)
	return stripGen(s), e
}
func (a *opusNoGen) SetUserPassword(ctx context.Context, p, u, pw string) (hostkit.UserSnapshot, error) {
	s, e := a.Fake.SetUserPassword(noSeq(ctx), p, u, pw)
	if a.reject {
		return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.Unauthenticated, 401, "ExpiredToken", "retry refused after committed first attempt")
	}
	return stripGen(s), e
}
func (a *opusNoGen) SetUserEnabled(ctx context.Context, p, u string, en bool) (hostkit.UserSnapshot, error) {
	s, e := a.Fake.SetUserEnabled(noSeq(ctx), p, u, en)
	if a.reject {
		return hostkit.UserSnapshot{}, hostkit.ProviderError(hostkit.Unauthenticated, 401, "ExpiredToken", "retry refused after committed first attempt")
	}
	return stripGen(s), e
}
func (a *opusNoGen) SignIn(ctx context.Context, in hostkit.UserSignInInput) (hostkit.SessionSnapshot, error) {
	s, e := a.Fake.SignIn(ctx, in)
	s.SessionGen = 0
	return s, e
}
func TestR3AdapterWithoutNativeSessionGen(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			a := &opusNoGen{Fake: e.f}
			h := e.host(a)
			h.UserpoolCreate(false, "nopool")
			h.UserCreate(false, "nopool", "alice", nil)
			h.UserSetPassword(false, "nopool", "alice", "Original123")
			s, _ := h.UserSignIn(false, "nopool", "alice", "Original123")
			sc := opCode(h)
			h.UserVerifyToken(false, "nopool", s.AccessToken())
			t.Logf("signin=%s verify=%s", sc, opCode(h))
			if sc != hostkit.OK || opCode(h) != hostkit.OK {
				t.Fatalf("host's own generation model requires a native SessionGen: verify=%v", h.LastError())
			}
		})
	}
}
func TestR3NoSeqRefusalAfterCommitRollback(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "rbpool")
			h.UserCreate(false, "rbpool", "alice", nil)
			h.UserSetPassword(false, "rbpool", "alice", "Original123")
			_, _ = h.UserSignIn(false, "rbpool", "alice", "Original123")
			a := &opusNoGen{Fake: e.f, reject: true}
			x := e.host(a)
			x.UserSetPassword(false, "rbpool", "alice", "Changed456")
			act, _, _, _, _ := x.cost.lookupUserpoolEntry("", "rbpool")
			st, _ := decodePersistedUserpoolState(act.StateJSON)
			nat, _ := e.f.GetUser(context.Background(), "rbpool", "alice")
			b := getUserTokenBindings(&st, "alice")
			t.Logf("reset=%s journalGen=%d rev=%d nativeGen=%d binding gen=%d pending=%v", opCode(x), st.Users["alice"].SessionGen, st.RevokedSessionGen["alice"], nat.SessionGen, b[0].SessionGen, st.PendingUserRevoke)
			if st.RevokedSessionGen["alice"] <= b[0].SessionGen {
				t.Fatal("no-seq adapter: revocation generation rolled back after a 4xx that followed a native commit (only the native gen compare still rejects)")
			}
		})
	}
}

func TestR3ForeignChildEveryPath(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "ownpool")
			h.UserCreate(false, "ownpool", "alice", map[string]string{"email": "a@example.com"})
			h.UserCreate(false, "ownpool", "bob", nil)
			h.UserSetPassword(false, "ownpool", "alice", "Original123")
			pre, _ := h.UserSignIn(false, "ownpool", "alice", "Original123")
			opusSetChildOwner(t, e.state, "ownpool", "alice", strings.Repeat("f", 32))
			h.UserVerifyToken(false, "ownpool", pre.AccessToken())
			t.Logf("verify=%s", opCode(h))
			if opCode(h) == hostkit.OK {
				t.Error("verify accepts foreign child")
			}
			u, _ := h.UserGet(true, "ownpool", "alice")
			t.Logf("dry get exists=%v attrs=%v code=%s", u.Exists(), u.Attributes(), opCode(h))
			if u.Exists() && opCode(h) == hostkit.OK {
				t.Error("dry user_get exposes foreign child")
			}
			p, _ := h.UserList(true, "ownpool", 10, "")
			t.Logf("dry list code=%s page=%+v", opCode(h), p)
			h.UserList(false, "ownpool", 10, "")
			lc := opCode(h)
			h.UserGet(false, "ownpool", "bob")
			t.Logf("live list with one foreign child=%s; own bob get=%s", lc, opCode(h))
		})
	}
}

func TestR3SharedProfileBlobAcrossPools(t *testing.T) {
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			attrs := map[string]string{"bio": strings.Repeat("z", 400)}
			h.UserpoolCreate(false, "poola")
			h.UserpoolCreate(false, "poolb")
			h.UserCreate(false, "poola", "alice", attrs)
			h.UserCreate(false, "poolb", "bob", attrs)
			h.UserDelete(false, "poola", "alice")
			clearProfileCaches()
			r := e.host(e.f)
			act, _, _, _, _ := r.cost.lookupUserpoolEntry("", "poolb")
			st, _ := decodePersistedUserpoolState(act.StateJSON)
			t.Logf("poolb bob journal attrs=%d hash=%q exists=%v", len(st.Users["bob"].Attributes), st.UserProfileHashes["bob"], profileBlobExists(st.UserProfileDir, st.UserProfileHashes["bob"]))
			if len(st.Users["bob"].Attributes) == 0 {
				t.Fatal("deleting a user in pool A destroyed the profile of an identical user in pool B")
			}
		})
	}
}

func TestR3BindingsReconstructFromJournalAlone(t *testing.T) {
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "jrpool")
			h.UserCreate(false, "jrpool", "alice", nil)
			h.UserSetPassword(false, "jrpool", "alice", "Original123")
			s, _ := h.UserSignIn(false, "jrpool", "alice", "Original123")
			if err := os.RemoveAll(e.campaign + ".profiles"); err != nil {
				t.Fatal(err)
			}
			_ = os.RemoveAll(filepath.Join(filepath.Dir(e.campaign), "journal.profiles"))
			clearProfileCaches()
			r := e.host(e.f)
			r.UserVerifyToken(false, "jrpool", s.AccessToken())
			t.Logf("verify after losing unsynced side dir=%s", opCode(r))
			if opCode(r) != hostkit.OK {
				t.Fatal("design 17 2.6: registry must reconstruct from the journal alone; bindings now live only in unsynced side files")
			}
		})
	}
}

func TestR3BlobCountAfterChurn(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "chpool")
	for i := 0; i < 4; i++ {
		h.UserCreate(false, "chpool", "alice", map[string]string{"bio": fmt.Sprintf("%0400d", i)})
		h.UserSetPassword(false, "chpool", "alice", "Original123")
		h.UserSignIn(false, "chpool", "alice", "Original123")
		h.UserSignIn(false, "chpool", "alice", "Original123")
		h.UserDelete(false, "chpool", "alice")
	}
	ents, _ := os.ReadDir(e.campaign + ".profiles")
	t.Logf("after user churn blobs=%d", len(ents))
	h.UserCreate(false, "chpool", "keep", map[string]string{"bio": strings.Repeat("k", 400)})
	h.UserSetPassword(false, "chpool", "keep", "Original123")
	h.UserSignIn(false, "chpool", "keep", "Original123")
	h.UserpoolDelete(false, "chpool")
	ents2, _ := os.ReadDir(e.campaign + ".profiles")
	t.Logf("after pool delete blobs=%d", len(ents2))
	if len(ents) != 0 || len(ents2) != 0 {
		t.Fatal("blobs remain after delete")
	}
}

func TestR3NativeOnlyUserDeleteReleasesCleanup(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "lrpool")
			base := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
			e.f.SetFaultUserpoolMutatorAfterCommitForTesting(func(op string) error {
				if op == "CreateUser" {
					return hostkit.ProviderError(hostkit.Internal, 503, "Lost", "x")
				}
				return nil
			})
			h.UserCreate(false, "lrpool", "ghost", nil)
			c1 := opCode(h)
			e.f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
			mid := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
			h.UserDelete(false, "lrpool", "ghost")
			c2 := opCode(h)
			after := h.cost.meter.Snapshot().ResourceCleanupNanoUSD
			nat, _ := e.f.GetUser(context.Background(), "lrpool", "ghost")
			t.Logf("create=%s delete=%s native=%v cleanup base=%d mid=%d after=%d", c1, c2, nat.Exists, base, mid, after)
			if !nat.Exists && after > base {
				t.Fatal("cleanup reserve for a native-only user not released by user_delete")
			}
		})
	}
}

func TestR3AttributeValueBytesSafetyMode(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"a\x7fb", "tab\tin", "nl\nin", "uni x", "\u0085next"} {
		v := v
		t.Run(fmt.Sprintf("%q", v), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, true)
			h := e.host(e.f)
			h.UserpoolCreate(false, "attrpool")
			h.UserCreate(false, "attrpool", "alice", map[string]string{"note": v})
			c := h.LastError()
			h.UserpoolDelete(false, "attrpool")
			t.Logf("create=%s/%s delete=%s", c.Code, c.ProviderCode, opCode(h))
			if opCode(h) != hostkit.OK {
				t.Fatalf("legal attribute value poisons host: %v", h.LastError())
			}
		})
	}
}

func TestR3StateLimitAfterNativeCommit(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "limpool")
			act, _, _, _, _ := h.cost.lookupUserpoolEntry("", "limpool")
			// 64 groups x 2000 usernames of 60 bytes: memberships inside documented caps (8.1 MB)
			if cerr := h.cost.updateUserpoolState("", "limpool", act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
				st, _ := decodePersistedUserpoolState(cur)
				for g := 0; g < 62; g++ {
					m := make([]string, 0, 2000)
					for i := 0; i < 2000; i++ {
						m = append(m, fmt.Sprintf("u%063d", i))
					}
					st.Memberships[fmt.Sprintf("group%03d", g)] = m
				}
				base := len(encodePersistedUserpoolState(st))
				extra := []string{}
				for i := 0; base+(i+1)*67 < 8*1024*1024-120; i++ {
					extra = append(extra, fmt.Sprintf("u%063d", i))
				}
				st.Memberships["group999"] = extra
				return encodePersistedUserpoolState(st)
			}); cerr != nil {
				t.Logf("seed: %v", cerr)
			}
			a2, _, _, _, _ := h.cost.lookupUserpoolEntry("", "limpool")
			h.UserCreate(false, "limpool", "bobbob", nil)
			c := h.LastError()
			nat, _ := e.f.GetUser(context.Background(), "limpool", "bobbob")
			h.UserDelete(false, "limpool", "bobbob")
			d := h.LastError()
			t.Logf("state=%d create=%s/%s msg=%q native=%v userDelete=%s/%s", len(a2.StateJSON), c.Code, c.ProviderCode, c.Message, nat.Exists, d.Code, d.ProviderCode)
			if nat.Exists && c.Code != hostkit.OK {
				t.Fatalf("native commit refused by state limit after dispatch: %+v", c)
			}
		})
	}
}

func TestR3JournalBytesPerReadOp(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	h.UserpoolCreate(false, "bytepool")
	h.UserCreate(false, "bytepool", "alice", nil)
	a, _ := os.Stat(e.campaign)
	for i := 0; i < 50; i++ {
		h.UserGet(false, "bytepool", "alice")
	}
	b, _ := os.Stat(e.campaign)
	per := (b.Size() - a.Size()) / 50
	t.Logf("journal bytes per user_get=%d; default cap reaches %d MiB of append-only records", per, per*(50_000_000/400)>>20)
	_ = filepath.Base
}

func TestR3LockoutPersistsAcrossResets(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	a := &opusReqLost{Fake: e.f}
	h := e.host(a)
	h.UserpoolCreate(false, "lkpool")
	h.UserCreate(false, "lkpool", "alice", nil)
	h.UserSetPassword(false, "lkpool", "alice", "Original123")
	a.lost = true
	h.UserSetPassword(false, "lkpool", "alice", "Changed456")
	a.lost = false
	var seq []string
	for i, pw := range []string{"Changed456", "Third78901", "Fourth2345"} {
		h.UserSetPassword(false, "lkpool", "alice", pw)
		h.UserSignIn(false, "lkpool", "alice", pw)
		seq = append(seq, fmt.Sprintf("reset%d signin=%s", i, opCode(h)))
	}
	nat, _ := e.f.GetUser(context.Background(), "lkpool", "alice")
	act, _, _, _, _ := h.cost.lookupUserpoolEntry("", "lkpool")
	st, _ := decodePersistedUserpoolState(act.StateJSON)
	t.Logf("%v native gen=%d journal gen=%d", seq, nat.SessionGen, st.RevokedSessionGen["alice"])
	h.UserDelete(false, "lkpool", "alice")
	h.UserCreate(false, "lkpool", "alice", nil)
	h.UserSetPassword(false, "lkpool", "alice", "Fifth67890")
	h.UserSignIn(false, "lkpool", "alice", "Fifth67890")
	t.Logf("after delete+recreate signin=%s", opCode(h))
	if !strings.Contains(seq[2], "OK") {
		t.Fatal("no number of successful resets recovers the account")
	}
}

func TestR3LostReplyCommittedThenRetryRecovers(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(modeName(jm), func(t *testing.T) {
			t.Parallel()
			e := newOpusEnv(t, jm)
			h := e.host(e.f)
			h.UserpoolCreate(false, "okpool")
			h.UserCreate(false, "okpool", "alice", nil)
			h.UserSetPassword(false, "okpool", "alice", "Original123")
			e.f.SetFaultUserpoolMutatorAfterCommitForTesting(func(op string) error {
				if op == "SetUserPassword" {
					return hostkit.ProviderError(hostkit.Internal, 503, "Lost", "x")
				}
				return nil
			})
			h.UserSetPassword(false, "okpool", "alice", "Changed456")
			e.f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
			h.UserSignIn(false, "okpool", "alice", "Changed456")
			beforeRetry := opCode(h)
			h.UserSetPassword(false, "okpool", "alice", "Changed456")
			h.UserSignIn(false, "okpool", "alice", "Changed456")
			t.Logf("signin before retry=%s after retry=%s", beforeRetry, opCode(h))
			if opCode(h) != hostkit.OK {
				t.Fatal("not recoverable")
			}
		})
	}
}

func TestR3AggregateJournalFileLimit(t *testing.T) {
	t.Parallel()
	e := newOpusEnv(t, false)
	h := e.host(e.f)
	blob := strings.Repeat("g", 60)
	var last error
	for p := 0; p < 11; p++ {
		pool := fmt.Sprintf("agg%03d", p)
		h.UserpoolCreate(false, pool)
		act, _, _, _, cerr := h.cost.lookupUserpoolEntry("", pool)
		if cerr != nil {
			last = cerr
			break
		}
		// each state stays under the new 8 MiB per-state check
		if cerr := h.cost.updateUserpoolState("", pool, act.OwnerToken, act.Incarnation, act.Generation, func(cur string) string {
			st, _ := decodePersistedUserpoolState(cur)
			for g := 0; g < 62; g++ {
				m := make([]string, 0, 2000)
				for i := 0; i < 2000; i++ {
					m = append(m, fmt.Sprintf("%s%04d", blob, i))
				}
				st.Memberships[fmt.Sprintf("group%03d", g)] = m
			}
			return encodePersistedUserpoolState(st)
		}); cerr != nil {
			last = cerr
			t.Logf("pool %d seed: %v", p, cerr)
			break
		}
	}
	fi, _ := os.Stat(e.campaign)
	h.UserpoolDelete(false, "agg000")
	d := h.LastError()
	t.Logf("file=%d last=%v delete=%s/%s", fi.Size(), last, d.Code, d.ProviderCode)
	if d.Code != hostkit.OK {
		t.Fatalf("aggregate journal size has no admission check and bricks cleanup: %+v", d)
	}
}
