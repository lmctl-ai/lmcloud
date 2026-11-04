// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func newUserpoolHost(t *testing.T) (*Host, *fakeadapter.Fake, string, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "fake.json")
	campaignPath := filepath.Join(dir, "campaign.jsonl")
	f := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
	h := New(Config{
		Provider:          "aws",
		Store:             f,
		Userpools:         f,
		CampaignStatePath: campaignPath,
	})
	h.SetAbortOnError(false)
	return h, f, statePath, campaignPath
}

func openUserpoolSafetyJournal(t *testing.T, dir string) *safety.Journal {
	t.Helper()
	j, err := safety.OpenJournal(dir, safety.JournalMeta{
		RunID:      "run-1700000000-abcdef012345",
		Provider:   "aws",
		Account:    "000000000000",
		Scope:      "000000000000",
		Region:     "us-east-1",
		Endpoint:   "http://127.0.0.1:4566",
		PolicyHash: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	return j
}

func TestUserpoolLifecycleAndNotFoundPrecedence(t *testing.T) {
	h, _, _, _ := newUserpoolHost(t)

	// Missing pool probes vs NOT_FOUND errors.
	ex, err := h.UserpoolExists(false, "missingpool")
	if err != nil || ex || h.LastError().Code != hostkit.OK {
		t.Fatalf("UserpoolExists on missing pool: ex=%v err=%v last=%+v", ex, err, h.LastError())
	}
	del, err := h.UserpoolDelete(false, "missingpool")
	if err != nil || del || h.LastError().Code != hostkit.OK {
		t.Fatalf("UserpoolDelete on missing pool: del=%v err=%v last=%+v", del, err, h.LastError())
	}

	// Token verify precedence: structural garbage fails with INVALID_ARGUMENT (http_status == 0)
	// BEFORE checking pool existence; syntactically valid JWT fails with NOT_FOUND on missing pool.
	_, _ = h.UserVerifyToken(false, "missingpool", "garbage.token.value")
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected INVALID_ARGUMENT (status 0) for malformed JWT on missing pool, got %+v", h.LastError())
	}
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1","iat":1000,"exp":2000}`))
	validShape := hdr + "." + pay + ".c2ln"
	_, _ = h.UserVerifyToken(false, "missingpool", validShape)
	if h.LastError().Code != hostkit.NotFound {
		t.Fatalf("expected NOT_FOUND for syntactically valid JWT on missing pool, got %+v", h.LastError())
	}

	// Create and idempotent re-create.
	created, err := h.UserpoolCreate(false, "poolalpha")
	if err != nil || !created || h.LastError().Code != hostkit.OK {
		t.Fatalf("UserpoolCreate first: created=%v err=%v last=%+v", created, err, h.LastError())
	}
	created2, err := h.UserpoolCreate(false, "poolalpha")
	if err != nil || created2 || h.LastError().Code != hostkit.OK {
		t.Fatalf("UserpoolCreate second: created=%v err=%v last=%+v", created2, err, h.LastError())
	}
	pools, err := h.UserpoolList(false)
	if err != nil || len(pools) != 1 || pools[0] != "poolalpha" {
		t.Fatalf("UserpoolList: pools=%v err=%v", pools, err)
	}
	deleted, err := h.UserpoolDelete(false, "poolalpha")
	if err != nil || !deleted || h.LastError().Code != hostkit.OK {
		t.Fatalf("UserpoolDelete: deleted=%v err=%v last=%+v", deleted, err, h.LastError())
	}
}

func TestUserpoolRecreationIncarnationAndPageTokenQuarantine(t *testing.T) {
	h, _, _, _ := newUserpoolHost(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	h.cfg.Now = func() time.Time { return now }

	_, _ = h.UserpoolCreate(false, "poolrecreate")
	_, _ = h.UserCreate(false, "poolrecreate", "alice", map[string]string{"email": "alice@example.com"})
	_, _ = h.UserCreate(false, "poolrecreate", "bob", nil)
	_ = h.UserSetPassword(false, "poolrecreate", "alice", "ValidPass1")

	sess1, err := h.UserSignIn(false, "poolrecreate", "alice", "ValidPass1")
	if err != nil || sess1.AccessToken() == "" {
		t.Fatalf("UserSignIn 1: err=%v last=%+v", err, h.LastError())
	}
	page1, err := h.UserList(false, "poolrecreate", 1, "")
	if err != nil || page1.NextToken == "" {
		t.Fatalf("UserList 1: next=%q err=%v last=%+v", page1.NextToken, err, h.LastError())
	}

	// Delete and recreate pool with the same name and same username/password.
	if deleted, err := h.UserpoolDelete(false, "poolrecreate"); !deleted || err != nil {
		t.Fatalf("UserpoolDelete: deleted=%v err=%v", deleted, err)
	}
	if created, err := h.UserpoolCreate(false, "poolrecreate"); !created || err != nil {
		t.Fatalf("UserpoolCreate recreate: created=%v err=%v", created, err)
	}
	_, _ = h.UserCreate(false, "poolrecreate", "alice", nil)
	_, _ = h.UserCreate(false, "poolrecreate", "bob", nil)
	_ = h.UserSetPassword(false, "poolrecreate", "alice", "ValidPass1")

	// Token from prior incarnation must fail with UNAUTHENTICATED.
	_, _ = h.UserVerifyToken(false, "poolrecreate", sess1.AccessToken())
	if h.LastError().Code != hostkit.Unauthenticated {
		t.Fatalf("expected UNAUTHENTICATED for prior-incarnation JWT, got %+v", h.LastError())
	}

	// Page token from prior incarnation must fail with INVALID_ARGUMENT (http_status == 0).
	_, _ = h.UserList(false, "poolrecreate", 1, page1.NextToken)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected INVALID_ARGUMENT for prior-incarnation page token, got %+v", h.LastError())
	}
}

func TestUserpoolTokenSecurityExpiryRevocationRotationAndEviction(t *testing.T) {
	for _, useSafetyJournal := range []bool{false, true} {
		mode := "campaign_journal"
		if useSafetyJournal {
			mode = "safety_journal"
		}
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			campaignPath := filepath.Join(dir, "campaign.jsonl")
			journalDir := filepath.Join(dir, "sj")
			f := fakeadapter.New(fakeadapter.Options{})

			now := time.Unix(1_700_000_000, 0).UTC()
			var j *safety.Journal
			if useSafetyJournal {
				j = openUserpoolSafetyJournal(t, journalDir)
				defer func() {
					if j != nil {
						_ = j.Close()
					}
				}()
			}

			makeHost := func() *Host {
				cfg := Config{
					Provider:          "aws",
					Store:             f,
					Userpools:         f,
					CampaignStatePath: campaignPath,
					Journal:           j,
					Now:               func() time.Time { return now },
				}
				if useSafetyJournal {
					cfg.CampaignStatePath = ""
				}
				h := New(cfg)
				h.SetAbortOnError(false)
				return h
			}

			h := makeHost()
			_, _ = h.UserpoolCreate(false, "secpool")
			_, _ = h.UserCreate(false, "secpool", "alice", map[string]string{"role": "admin"})
			_ = h.UserSetPassword(false, "secpool", "alice", "SecretPass1")

			// 1. Exact expiry boundary: token issued at t=1700000000 has exp=1700003600.
			sess, err := h.UserSignIn(false, "secpool", "alice", "SecretPass1")
			if err != nil || sess.ExpiresIn() != 3600 {
				t.Fatalf("UserSignIn: expiresIn=%d err=%v last=%+v", sess.ExpiresIn(), err, h.LastError())
			}
			tok1 := sess.AccessToken()

			// At exp - 1 (t = 1700003599), token is valid with ExpiresIn() == 1.
			now = time.Unix(1_700_003_599, 0).UTC()
			vSess, err := h.UserVerifyToken(false, "secpool", tok1)
			if err != nil || vSess.ExpiresIn() != 1 || vSess.Claims()["username"] != "alice" {
				t.Fatalf("verify at exp-1 failed: expiresIn=%d err=%v last=%+v", vSess.ExpiresIn(), err, h.LastError())
			}

			// At exact exp (t = 1700003600), strict now < exp rejects the token.
			now = time.Unix(1_700_003_600, 0).UTC()
			_, _ = h.UserVerifyToken(false, "secpool", tok1)
			if h.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("expected UNAUTHENTICATED at exact exp == now, got %+v", h.LastError())
			}

			// Clock skew leeway for iat: token issued at t = 1700003600 verified at t = 1700003540 (iat == now+60) -> valid;
			// verified at t = 1700003539 (iat == now+61) -> UNAUTHENTICATED.
			sessSkew, _ := h.UserSignIn(false, "secpool", "alice", "SecretPass1")
			tokSkew := sessSkew.AccessToken()
			now = time.Unix(1_700_003_540, 0).UTC()
			if _, err := h.UserVerifyToken(false, "secpool", tokSkew); err != nil || h.LastError().Code != hostkit.OK {
				t.Fatalf("expected valid at iat == now+60, got %+v", h.LastError())
			}
			now = time.Unix(1_700_003_539, 0).UTC()
			_, _ = h.UserVerifyToken(false, "secpool", tokSkew)
			if h.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("expected UNAUTHENTICATED at iat == now+61, got %+v", h.LastError())
			}
			now = time.Unix(1_700_003_600, 0).UTC()

			// 2. Same-second password change revokes tokSkew immediately, while same-second new sign-in works.
			_ = h.UserSetPassword(false, "secpool", "alice", "SecretPass2")
			_, _ = h.UserVerifyToken(false, "secpool", tokSkew)
			if h.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("expected same-second password change to revoke prior token, got %+v", h.LastError())
			}
			sessAfterPw, err := h.UserSignIn(false, "secpool", "alice", "SecretPass2")
			if err != nil || h.LastError().Code != hostkit.OK {
				t.Fatalf("same-second sign-in after password change failed: %+v", h.LastError())
			}
			if _, err := h.UserVerifyToken(false, "secpool", sessAfterPw.AccessToken()); err != nil || h.LastError().Code != hostkit.OK {
				t.Fatalf("verify of new token after same-second password change failed: %+v", h.LastError())
			}

			// 3. Same-second user_set_enabled(false) revokes token, and re-enabling does NOT un-revoke it.
			_ = h.UserSetEnabled(false, "secpool", "alice", false)
			_, _ = h.UserVerifyToken(false, "secpool", sessAfterPw.AccessToken())
			if h.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("expected disabled user token to be revoked, got %+v", h.LastError())
			}
			_ = h.UserSetEnabled(false, "secpool", "alice", true)
			_, _ = h.UserVerifyToken(false, "secpool", sessAfterPw.AccessToken())
			if h.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("re-enabling user must not un-revoke pre-disable token, got %+v", h.LastError())
			}

			// 4. Key rotation: mint token under key 1, rotate key, verify old token still works and new token works.
			sessKey1, err := h.UserSignIn(false, "secpool", "alice", "SecretPass2")
			if err != nil {
				t.Fatalf("UserSignIn before key rotation: %v", err)
			}
			if _, err := f.RotateUserpoolSigningKeyForTesting("secpool"); err != nil {
				t.Fatalf("RotateUserpoolSigningKeyForTesting: %v", err)
			}
			sessKey2, err := h.UserSignIn(false, "secpool", "alice", "SecretPass2")
			if err != nil {
				t.Fatalf("UserSignIn after key rotation: %v", err)
			}
			if _, err := h.UserVerifyToken(false, "secpool", sessKey1.AccessToken()); err != nil {
				t.Fatalf("token under rotated-out key should still verify: %+v", h.LastError())
			}
			if _, err := h.UserVerifyToken(false, "secpool", sessKey2.AccessToken()); err != nil {
				t.Fatalf("token under active rotated key failed: %+v", h.LastError())
			}

			// 5. Never-issued token signed with the pool's real RSA private key must be rejected (not in journaled binding registry).
			privPEM, _, kid, issuer, clientID, _, _, ok := f.UserpoolSigningKeyMaterialForTesting("secpool")
			if !ok {
				t.Fatal("missing signing key material")
			}
			unissuedTok, err := hostkit.MintRS256JWT(privPEM, kid, map[string]any{
				"sub":       "forged-sub",
				"username":  "alice",
				"iss":       issuer,
				"aud":       clientID,
				"client_id": clientID,
				"token_use": "access",
				"iat":       now.Unix(),
				"exp":       now.Unix() + 3600,
			})
			if err != nil {
				t.Fatalf("MintRS256JWT: %v", err)
			}
			_, _ = h.UserVerifyToken(false, "secpool", unissuedTok)
			if h.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("expected UNAUTHENTICATED for never-issued token, got %+v", h.LastError())
			}

			// 6. Duplicate JSON keys in JWT payload and oversize JWT (> 8192 bytes) fail with INVALID_ARGUMENT (status 0).
			hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
			dupPay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1","sub":"u2","iat":1000,"exp":2000}`))
			_, _ = h.UserVerifyToken(false, "secpool", hdr+"."+dupPay+".c2ln")
			if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
				t.Fatalf("expected INVALID_ARGUMENT for duplicate JSON claim key, got %+v", h.LastError())
			}
			oversize := hdr + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"`+strings.Repeat("x", 9000)+`"}`)) + ".c2ln"
			_, _ = h.UserVerifyToken(false, "secpool", oversize)
			if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
				t.Fatalf("expected INVALID_ARGUMENT for >8192B JWT, got %+v", h.LastError())
			}

			// 7. >128 live session bindings per user deterministically evicts oldest.
			_, _ = h.UserCreate(false, "secpool", "bob", nil)
			_ = h.UserSetPassword(false, "secpool", "bob", "BobPass123")
			fastCfg := Config{
				Provider:          "aws",
				Store:             f,
				Userpools:         &fastMintSignInAdapter{Fake: f},
				CampaignStatePath: campaignPath,
				Journal:           j,
				Now:               func() time.Time { return now },
			}
			if useSafetyJournal {
				fastCfg.CampaignStatePath = ""
			}
			hFast := New(fastCfg)
			hFast.SetAbortOnError(false)
			var bobTokens []string
			for i := 0; i < hostkit.MaxSessionBindingsPerUser+1; i++ {
				s, err := hFast.UserSignIn(false, "secpool", "bob", "BobPass123")
				if err != nil {
					t.Fatalf("bob sign-in %d: %v (%+v)", i, err, hFast.LastError())
				}
				bobTokens = append(bobTokens, s.AccessToken())
			}
			// Token 0 must have been evicted; tokens 1..128 must verify.
			_, _ = h.UserVerifyToken(false, "secpool", bobTokens[0])
			if h.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("expected evicted oldest token[0] to fail with UNAUTHENTICATED, got %+v", h.LastError())
			}
			if _, err := h.UserVerifyToken(false, "secpool", bobTokens[1]); err != nil || h.LastError().Code != hostkit.OK {
				t.Fatalf("expected token[1] to remain valid, got %+v", h.LastError())
			}
			if _, err := h.UserVerifyToken(false, "secpool", bobTokens[len(bobTokens)-1]); err != nil || h.LastError().Code != hostkit.OK {
				t.Fatalf("expected newest token to remain valid, got %+v", h.LastError())
			}

			// 8. Crash/reopen (and journal compaction) preserves token-binding registry and revocation state.
			if useSafetyJournal {
				if err := j.Compact(); err != nil {
					t.Fatalf("Compact: %v", err)
				}
				_ = j.Close()
				j = openUserpoolSafetyJournal(t, journalDir)
			}
			hReopen := makeHost()
			_, _ = hReopen.UserVerifyToken(false, "secpool", bobTokens[0])
			if hReopen.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("after reopen, evicted token[0] verified: %+v", hReopen.LastError())
			}
			if _, err := hReopen.UserVerifyToken(false, "secpool", bobTokens[len(bobTokens)-1]); err != nil || hReopen.LastError().Code != hostkit.OK {
				t.Fatalf("after reopen, newest token failed verification: %+v", hReopen.LastError())
			}
		})
	}
}

func TestUserpoolPBKDF2AndSecretRedactionCanaries(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "fake.json")
	journalDir := filepath.Join(dir, "sj")
	f := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
	j := openUserpoolSafetyJournal(t, journalDir)
	defer j.Close()

	h := New(Config{
		Provider:  "aws",
		Store:     f,
		Userpools: f,
		Journal:   j,
	})
	h.SetAbortOnError(false)

	canaryPw := `CanaryPass1!"#$%&'()*+,/:;<=>?@[\]^_` + "`{|}~"
	badPw := "WrongCanary99!Secret"

	_, _ = h.UserpoolCreate(false, "redactpool")
	_, _ = h.UserCreate(false, "redactpool", "user1", nil)
	if err := h.UserSetPassword(false, "redactpool", "user1", canaryPw); err != nil {
		t.Fatalf("UserSetPassword: %v (%+v)", err, h.LastError())
	}

	// Verify PBKDF2-HMAC-SHA256 600,000 iterations in fakeadapter.
	salt, hash, iterations, ok := f.UserpoolRawPasswordEntryForTesting("redactpool", "user1")
	if !ok || iterations != hostkit.PBKDF2Iterations || len(salt) != hostkit.PBKDF2SaltBytes*2 || len(hash) != hostkit.PBKDF2KeyBytes*2 {
		t.Fatalf("expected PBKDF2 600,000 iterations with 16B salt (32 hex) and 32B key (64 hex), got ok=%v iter=%d salt=%d hash=%d",
			ok, iterations, len(salt), len(hash))
	}

	sess, err := h.UserSignIn(false, "redactpool", "user1", canaryPw)
	if err != nil || sess.AccessToken() == "" {
		t.Fatalf("UserSignIn: %v (%+v)", err, h.LastError())
	}
	jwtTok := sess.AccessToken()

	// Wrong password and missing user must never echo password and must return identical messages.
	_, _ = h.UserSignIn(false, "redactpool", "user1", badPw)
	eBad := h.LastError()
	_, _ = h.UserSignIn(false, "redactpool", "ghost_user", badPw)
	eGhost := h.LastError()
	if eBad.Code != hostkit.Unauthenticated || eGhost.Code != hostkit.Unauthenticated {
		t.Fatalf("expected UNAUTHENTICATED, got bad=%+v ghost=%+v", eBad, eGhost)
	}
	if eBad.Message != eGhost.Message {
		t.Fatalf("user enumeration leak: %q != %q", eBad.Message, eGhost.Message)
	}
	if strings.Contains(eBad.Message, badPw) || strings.Contains(eBad.Message, canaryPw) {
		t.Fatalf("password echoed in error message: %q", eBad.Message)
	}

	// Register > 300 additional secrets to verify early secrets remain redacted past 256 operations.
	for i := 0; i < 320; i++ {
		pw := fmt.Sprintf("RotationSecretPass%04d!Z", i)
		_, _ = h.UserSignIn(true, "redactpool", "user1", pw)
	}
	// If an error message contains canaryPw (or its JSON-escaped / URL-escaped form) or jwtTok, h.fail must scrub it.
	jsonEscapedByte, _ := json.Marshal(canaryPw)
	jsonEscaped := string(jsonEscapedByte[1 : len(jsonEscapedByte)-1])
	leakedMsg := "provider failed with raw=" + canaryPw + " json=" + jsonEscaped + " tok=" + jwtTok
	_ = h.fail("user_sign_in", "redactpool", hostkit.ProviderError(hostkit.Internal, 500, "Fault", leakedMsg))
	scrubbed := h.LastError().Message
	if strings.Contains(scrubbed, canaryPw) || strings.Contains(scrubbed, jsonEscaped) || strings.Contains(scrubbed, jwtTok) {
		t.Fatalf("expected early secrets and escaped variants to remain redacted after >300 ops, got: %s", scrubbed)
	}

	// Verify safety journal file on disk contains zero occurrences of passwords, raw JWT, or password hash/salt.
	rawJournal, err := os.ReadFile(j.Path())
	if err != nil {
		t.Fatalf("ReadFile journal: %v", err)
	}
	jStr := string(rawJournal)
	for _, secret := range []string{canaryPw, badPw, jwtTok, salt, hash} {
		if secret != "" && strings.Contains(jStr, secret) {
			t.Fatalf("safety journal leaked secret %q", secret)
		}
	}
}

func TestUserpoolPaginationPageTokenFileAndBounds(t *testing.T) {
	h, f, _, campaignPath := newUserpoolHost(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	h.cfg.Now = func() time.Time { return now }

	// Verify page token HMAC key file is created with mode 0600 and never written to campaign journal.
	keyPath := h.PageTokenKeyPath()
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat page token key file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions on page token key file, got %o", info.Mode().Perm())
	}

	_, _ = h.UserpoolCreate(false, "pagepool")
	_, _ = h.UserpoolCreate(false, "otherpool")
	for _, u := range []string{"u_delta", "u_alpha", "u_charlie", "u_bravo"} {
		_, _ = h.UserCreate(false, "pagepool", u, map[string]string{"name": u})
	}
	// Force reverse order from native adapter to verify host-side global lexicographical sorting.
	if err := f.SetUserpoolReverseListOrderForTesting("pagepool", true); err != nil {
		t.Fatal(err)
	}

	p1, err := h.UserList(false, "pagepool", 2, "")
	if err != nil || len(p1.Items) != 2 || p1.Items[0].Username() != "u_alpha" || p1.Items[1].Username() != "u_bravo" || p1.NextToken == "" {
		t.Fatalf("page 1: items=%v next=%q err=%v", p1.Items, p1.NextToken, err)
	}

	// Cross-pool reuse of page token must fail with INVALID_ARGUMENT (http_status == 0).
	_, _ = h.UserList(false, "otherpool", 2, p1.NextToken)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected cross-pool page token to fail with INVALID_ARGUMENT, got %+v", h.LastError())
	}

	// Different max_items with same page token must fail with INVALID_ARGUMENT (http_status == 0).
	_, _ = h.UserList(false, "pagepool", 3, p1.NextToken)
	if h.LastError().Code != hostkit.InvalidArgument || h.LastError().HTTPStatus != 0 {
		t.Fatalf("expected max_items mismatch on page token to fail with INVALID_ARGUMENT, got %+v", h.LastError())
	}

	p2, err := h.UserList(false, "pagepool", 2, p1.NextToken)
	if err != nil || len(p2.Items) != 2 || p2.Items[0].Username() != "u_charlie" || p2.Items[1].Username() != "u_delta" || p2.NextToken != "" {
		t.Fatalf("page 2: items=%v next=%q err=%v", p2.Items, p2.NextToken, err)
	}

	// Reopening host rotates page-token HMAC key so pre-reopen page tokens are rejected.
	hReopen := New(Config{
		Provider:          "aws",
		Store:             f,
		Userpools:         f,
		CampaignStatePath: campaignPath,
		Now:               func() time.Time { return now },
	})
	hReopen.SetAbortOnError(false)
	_, _ = hReopen.UserList(false, "pagepool", 2, p1.NextToken)
	if hReopen.LastError().Code != hostkit.InvalidArgument || hReopen.LastError().HTTPStatus != 0 {
		t.Fatalf("expected pre-reopen page token to fail after reopen key rotation, got %+v", hReopen.LastError())
	}
}

func TestSolUserpoolLostReplyAmbiguityAndCleanupReserves(t *testing.T) {
	for _, useSafetyJournal := range []bool{false, true} {
		mode := "campaign_journal"
		if useSafetyJournal {
			mode = "safety_journal"
		}
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			campaignPath := filepath.Join(dir, "campaign.jsonl")
			journalDir := filepath.Join(dir, "sj")
			f := fakeadapter.New(fakeadapter.Options{})

			var j *safety.Journal
			if useSafetyJournal {
				j = openUserpoolSafetyJournal(t, journalDir)
				defer func() {
					if j != nil {
						_ = j.Close()
					}
				}()
			}

			makeHost := func() *Host {
				cfg := Config{
					Provider:          "aws",
					Store:             f,
					Userpools:         f,
					CampaignStatePath: campaignPath,
					Journal:           j,
				}
				if useSafetyJournal {
					cfg.CampaignStatePath = ""
				}
				h := New(cfg)
				h.SetAbortOnError(false)
				return h
			}

			h := makeHost()
			// 1. Inject lost reply after CreateUserPool mutates the adapter.
			f.SetFaultUserpoolMutatorAfterCommitForTesting(func(op string) error {
				if op == "CreateUserPool" {
					return hostkit.ProviderError(hostkit.Internal, 503, "ServiceUnavailable", "lost reply")
				}
				return nil
			})
			_, _ = h.UserpoolCreate(false, "ambpool")
			f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
			if h.LastError().Code != hostkit.Internal {
				t.Fatalf("expected 503 on lost reply, got %+v", h.LastError())
			}

			// Cleanup reserve for ambpool (50,000 nano-USD) must be locked despite lost reply.
			if got := h.cost.meter.Snapshot().ResourceCleanupNanoUSD; got != 50000 {
				t.Fatalf("expected 50000 cleanup reserve locked on ambiguous create, got %d", got)
			}

			// All mutations and reads on ambpool (and UserpoolList) must fail closed with CONFLICT until reconciled.
			_, _ = h.UserpoolExists(false, "ambpool")
			if h.LastError().Code != hostkit.Conflict {
				t.Fatalf("expected CONFLICT on UserpoolExists during ambiguity, got %+v", h.LastError())
			}
			_, _ = h.UserpoolList(false)
			if h.LastError().Code != hostkit.Conflict {
				t.Fatalf("expected CONFLICT on UserpoolList during ambiguity, got %+v", h.LastError())
			}
			_, _ = h.UserCreate(false, "ambpool", "alice", nil)
			if h.LastError().Code != hostkit.Conflict {
				t.Fatalf("expected CONFLICT on UserCreate during ambiguity, got %+v", h.LastError())
			}

			// Reconcile by re-running UserpoolCreate (same OwnerToken matches).
			if _, err := h.UserpoolCreate(false, "ambpool"); err != nil || h.LastError().Code != hostkit.OK {
				t.Fatalf("reconciling UserpoolCreate failed: err=%v last=%+v", err, h.LastError())
			}

			// Create user (locks 5000), group (locks 5000), and membership (locks 1000).
			// Total locked = 50000 + 5000 + 5000 + 1000 = 61000 nano-USD.
			_, _ = h.UserCreate(false, "ambpool", "alice", nil)
			_, _ = h.GroupCreate(false, "ambpool", "admins")
			_ = h.GroupAddUser(false, "ambpool", "admins", "alice")
			if got := h.cost.meter.Snapshot().ResourceCleanupNanoUSD; got != 61000 {
				t.Fatalf("expected 61000 cleanup reserve, got %d", got)
			}

			// Crash/reopen and compact journal, then exhaust script work cap and verify UserpoolDelete cascades and succeeds.
			if useSafetyJournal {
				if err := j.Compact(); err != nil {
					t.Fatal(err)
				}
				_ = j.Close()
				j = openUserpoolSafetyJournal(t, journalDir)
			}
			hReopen := makeHost()
			if got := hReopen.cost.meter.Snapshot().ResourceCleanupNanoUSD; got != 61000 {
				t.Fatalf("after reopen expected 61000 cleanup reserve, got %d", got)
			}
			if err := hReopen.SetCostCapUSD(hReopen.EstimatedCost()); err != nil {
				t.Fatal(err)
			}
			deleted, err := hReopen.UserpoolDelete(false, "ambpool")
			if err != nil || !deleted || hReopen.LastError().Code != hostkit.OK {
				t.Fatalf("UserpoolDelete under exhausted work cap failed: deleted=%v err=%v last=%+v", deleted, err, hReopen.LastError())
			}
			if got := hReopen.cost.meter.Snapshot().ResourceCleanupNanoUSD; got != 0 {
				t.Fatalf("after UserpoolDelete expected 0 cleanup reserve, got %d", got)
			}
		})
	}
}

type solUserpoolLateChild struct {
	*fakeadapter.Fake
	op               string
	entered, release chan struct{}
}

func (a *solUserpoolLateChild) SetUserEnabled(ctx context.Context, pool, username string, enabled bool) (hostkit.UserSnapshot, error) {
	u, err := a.Fake.SetUserEnabled(ctx, pool, username, enabled)
	if err == nil && a.op == "set_enabled" {
		close(a.entered)
		<-a.release
	}
	return u, err
}

type solUserpoolNoSeqAdapter struct {
	hostkit.Userpools
	entered, release chan struct{}
	reads            int
	unmetered        bool
}

func (a *solUserpoolNoSeqAdapter) SetUserEnabled(ctx context.Context, pool, username string, enabled bool) (hostkit.UserSnapshot, error) {
	u, err := a.Userpools.SetUserEnabled(hostkit.WithUserpoolChildMutationSeqOut(ctx, nil), pool, username, enabled)
	if err == nil {
		close(a.entered)
		<-a.release
	}
	return u, err
}

func (a *solUserpoolNoSeqAdapter) GetUser(ctx context.Context, pool, username string) (hostkit.UserSnapshot, error) {
	a.reads++
	a.unmetered = hostkit.RetryHooksFrom(ctx).BeforeAttempt == nil
	return a.Userpools.GetUser(ctx, pool, username)
}

func TestSolUserpoolOutOfOrderChildReplyAndFallbackAdmission(t *testing.T) {
	for _, useSafetyJournal := range []bool{false, true} {
		mode := "campaign_journal"
		if useSafetyJournal {
			mode = "safety_journal"
		}
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			campaignPath := filepath.Join(dir, "campaign.jsonl")
			journalDir := filepath.Join(dir, "sj")
			f := fakeadapter.New(fakeadapter.Options{})

			var j *safety.Journal
			if useSafetyJournal {
				j = openUserpoolSafetyJournal(t, journalDir)
				defer func() {
					if j != nil {
						_ = j.Close()
					}
				}()
			}

			base := Config{
				Provider:          "aws",
				Store:             f,
				Userpools:         f,
				CampaignStatePath: campaignPath,
				Journal:           j,
			}
			if useSafetyJournal {
				base.CampaignStatePath = ""
			}

			h := New(base)
			h.SetAbortOnError(false)
			_, _ = h.UserpoolCreate(false, "orderpool")
			_, _ = h.UserCreate(false, "orderpool", "alice", nil)
			_ = h.UserSetPassword(false, "orderpool", "alice", "OrderPass1")
			sess, _ := h.UserSignIn(false, "orderpool", "alice", "OrderPass1")

			// Slow goroutine calls UserSetEnabled(true) first in the adapter, then pauses before updating journal state.
			// Peer calls UserSetEnabled(false) (revoking alice's token) and compacts journal before slow resumes.
			late := &solUserpoolLateChild{
				Fake:    f,
				op:      "set_enabled",
				entered: make(chan struct{}),
				release: make(chan struct{}),
			}
			slowCfg := base
			slowCfg.Userpools = late
			slow := New(slowCfg)
			slow.SetAbortOnError(false)

			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = slow.UserSetEnabled(false, "orderpool", "alice", true)
			}()
			<-late.entered

			peer := New(base)
			peer.SetAbortOnError(false)
			if err := peer.UserSetEnabled(false, "orderpool", "alice", false); err != nil {
				t.Fatal(err)
			}
			if useSafetyJournal {
				if err := j.Compact(); err != nil {
					t.Fatal(err)
				}
			}
			close(late.release)
			<-done

			// Verify alice remains disabled and her token stays revoked!
			_, _ = peer.UserVerifyToken(false, "orderpool", sess.AccessToken())
			if peer.LastError().Code != hostkit.Unauthenticated {
				t.Fatalf("delayed older SetUserEnabled(true) un-revoked disabled user's token: %+v", peer.LastError())
			}

			// Also test fallback reconciliation read admission when adapter does not report ChildSeq.
			noSeq := &solUserpoolNoSeqAdapter{
				Userpools: f,
				entered:   make(chan struct{}),
				release:   make(chan struct{}),
			}
			noSeqCfg := base
			noSeqCfg.Userpools = noSeq
			slowNoSeq := New(noSeqCfg)
			slowNoSeq.SetAbortOnError(false)
			done2 := make(chan struct{})
			go func() {
				defer close(done2)
				_ = slowNoSeq.UserSetEnabled(false, "orderpool", "alice", true)
			}()
			<-noSeq.entered
			_ = peer.UserSetEnabled(false, "orderpool", "alice", false)
			close(noSeq.release)
			<-done2
			if noSeq.reads != 1 || noSeq.unmetered {
				t.Fatalf("expected 1 metered fallback GetUser read, got reads=%d unmetered=%v", noSeq.reads, noSeq.unmetered)
			}
		})
	}
}

func TestSolUserpoolForeignPoolAndForeignChildProtection(t *testing.T) {
	h, f, _, _ := newUserpoolHost(t)

	// 1. Foreign pool (both marked with foreign token and unmarked with empty token) must be refused.
	for _, tok := range []string{strings.Repeat("f", 32), ""} {
		poolName := "foreignpool"
		if tok == "" {
			poolName = "unmarkedpool"
		}
		if err := f.InjectUnmarkedUserpoolForTesting(poolName, tok); err != nil {
			t.Fatal(err)
		}
		_, _ = h.UserpoolCreate(false, poolName)
		if h.LastError().Code != hostkit.Conflict {
			t.Fatalf("expected CONFLICT on UserpoolCreate(%s), got %+v", poolName, h.LastError())
		}
		_, _ = h.UserpoolDelete(false, poolName)
		if h.LastError().Code != hostkit.PermissionDenied {
			t.Fatalf("expected PERMISSION_DENIED on UserpoolDelete(%s), got %+v", poolName, h.LastError())
		}
		_, _ = h.UserCreate(false, poolName, "alice", nil)
		if h.LastError().Code != hostkit.PermissionDenied {
			t.Fatalf("expected PERMISSION_DENIED on UserCreate(%s), got %+v", poolName, h.LastError())
		}
	}

	// 2. Owned pool with injected foreign child user must preserve foreign child and refuse UserpoolDelete with PERMISSION_DENIED.
	_, _ = h.UserpoolCreate(false, "ownedforeignchild")
	_, _ = h.UserCreate(false, "ownedforeignchild", "owned_user", nil)
	if err := f.InjectForeignPoolChildForTesting("ownedforeignchild", "user", "foreign_user", strings.Repeat("b", 32)); err != nil {
		t.Fatal(err)
	}
	_ = h.UserDelete(false, "ownedforeignchild", "foreign_user")
	if h.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED deleting foreign child user, got %+v", h.LastError())
	}
	_, _ = h.UserpoolDelete(false, "ownedforeignchild")
	if h.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected PERMISSION_DENIED on UserpoolDelete when foreign child user is present, got %+v", h.LastError())
	}
}

type solUserpoolsOnly struct {
	hostkit.Userpools
}

func TestSolUserpoolDryRunAndLiveRoutePreflightAll(t *testing.T) {
	// 1. Live route preflight refuses all 18 userpool operations before any adapter I/O.
	live := fakeadapter.New(fakeadapter.Options{})
	routes := hostkit.EndpointRoutes{Live: live}
	router := &hostkit.Router{Pick: routes.Pick}
	h := New(Config{Provider: "aws", Store: router, Userpools: router})
	h.SetAbortOnError(false)

	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pay := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1","iat":1000,"exp":2000}`))
	validShape := hdr + "." + pay + ".c2ln"

	calls := []func(){
		func() { _, _ = h.UserpoolCreate(false, "solpool") },
		func() { _, _ = h.UserpoolDelete(false, "solpool") },
		func() { _, _ = h.UserpoolExists(false, "solpool") },
		func() { _, _ = h.UserpoolList(false) },
		func() { _, _ = h.UserCreate(false, "solpool", "alice", nil) },
		func() { _, _ = h.UserGet(false, "solpool", "alice") },
		func() { _ = h.UserDelete(false, "solpool", "alice") },
		func() { _ = h.UserSetEnabled(false, "solpool", "alice", false) },
		func() { _ = h.UserSetPassword(false, "solpool", "alice", "ValidPass1") },
		func() { _, _ = h.UserList(false, "solpool", 10, "") },
		func() { _, _ = h.UserSignIn(false, "solpool", "alice", "ValidPass1") },
		func() { _, _ = h.UserVerifyToken(false, "solpool", validShape) },
		func() { _, _ = h.GroupCreate(false, "solpool", "grp1") },
		func() { _, _ = h.GroupDelete(false, "solpool", "grp1") },
		func() { _, _ = h.GroupList(false, "solpool") },
		func() { _ = h.GroupAddUser(false, "solpool", "grp1", "alice") },
		func() { _ = h.GroupRemoveUser(false, "solpool", "grp1", "alice") },
		func() { _, _ = h.UserGroups(false, "solpool", "alice") },
	}
	for i, fn := range calls {
		fn()
		if h.LastError().Code != hostkit.PermissionDenied {
			t.Fatalf("live route op %d not refused with PERMISSION_DENIED: %+v", i, h.LastError())
		}
	}
	if len(live.Calls()) != 0 {
		t.Fatalf("live adapter was touched: %v", live.Calls())
	}

	// 2. Dry-run mode refuses user_sign_in and user_verify_token with INVALID_ARGUMENT (http_status == 0) and zero adapter calls,
	// and serves dry reads from persisted journal state withoutUserpoolDryStatePeeker.
	hSim, fSim, _, campaign := newUserpoolHost(t)
	_, _ = hSim.UserpoolCreate(false, "drypool")
	_, _ = hSim.UserCreate(false, "drypool", "alice", map[string]string{"dept": "eng"})
	_, _ = hSim.GroupCreate(false, "drypool", "devs")
	_ = hSim.GroupAddUser(false, "drypool", "devs", "alice")

	hDry := New(Config{
		Provider:          "aws",
		Store:             fSim,
		Userpools:         solUserpoolsOnly{Userpools: fSim},
		CampaignStatePath: campaign,
	})
	hDry.SetAbortOnError(false)
	beforeCalls := fSim.Calls()

	_, _ = hDry.UserSignIn(true, "drypool", "alice", "ValidPass1")
	if hDry.LastError().Code != hostkit.InvalidArgument || hDry.LastError().HTTPStatus != 0 {
		t.Fatalf("expected dry UserSignIn to fail with INVALID_ARGUMENT (status 0), got %+v", hDry.LastError())
	}
	_, _ = hDry.UserVerifyToken(true, "drypool", validShape)
	if hDry.LastError().Code != hostkit.InvalidArgument || hDry.LastError().HTTPStatus != 0 {
		t.Fatalf("expected dry UserVerifyToken to fail with INVALID_ARGUMENT (status 0), got %+v", hDry.LastError())
	}

	uDry, err := hDry.UserGet(true, "drypool", "alice")
	if err != nil || !uDry.Exists() || uDry.Attribute("dept") != "eng" {
		t.Fatalf("dry UserGet without peeker failed: exists=%v dept=%q err=%v", uDry.Exists(), uDry.Attribute("dept"), err)
	}
	grpsDry, err := hDry.UserGroups(true, "drypool", "alice")
	if err != nil || len(grpsDry) != 1 || grpsDry[0] != "devs" {
		t.Fatalf("dry UserGroups without peeker failed: grps=%v err=%v", grpsDry, err)
	}
	afterCalls := fSim.Calls()
	if len(afterCalls) != len(beforeCalls) {
		t.Fatalf("expected zero adapter calls in dry mode without peeker, before=%v after=%v", beforeCalls, afterCalls)
	}
}

type fastMintSignInAdapter struct {
	*fakeadapter.Fake
}

func (a *fastMintSignInAdapter) SignIn(_ context.Context, in hostkit.UserSignInInput) (hostkit.SessionSnapshot, error) {
	return a.Fake.MintSessionWithoutKDFForTesting(in)
}

func TestSolUPLostRevocationReply(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		for _, op := range []string{"SetUserPassword", "SetUserEnabled", "DeleteUser"} {
			jm, op := jm, op
			t.Run(fmt.Sprintf("journal=%v/%s", jm, op), func(t *testing.T) {
				t.Parallel()
				h, f, _, campaign := newUserpoolHost(t)
				cfg := Config{Provider: "aws", Store: f, Userpools: f, CampaignStatePath: campaign}
				var j *safety.Journal
				dir := filepath.Join(t.TempDir(), "journal")
				if jm {
					j = openUserpoolSafetyJournal(t, dir)
					cfg.Journal = j
					cfg.CampaignStatePath = ""
					defer func() { _ = j.Close() }()
				}
				h = New(cfg)
				h.SetAbortOnError(false)
				_, _ = h.UserpoolCreate(false, "proofpool")
				_, _ = h.UserCreate(false, "proofpool", "alice", nil)
				_ = h.UserSetPassword(false, "proofpool", "alice", "Original123")
				sess, _ := h.UserSignIn(false, "proofpool", "alice", "Original123")
				if sess.AccessToken() == "" {
					t.Fatal("fixture", h.LastError())
				}
				f.SetFaultUserpoolMutatorAfterCommitForTesting(func(got string) error {
					if got == op {
						return hostkit.ProviderError(hostkit.Internal, 503, "LostReply", "synthetic lost reply")
					}
					return nil
				})
				switch op {
				case "SetUserPassword":
					_ = h.UserSetPassword(false, "proofpool", "alice", "Changed456")
				case "SetUserEnabled":
					_ = h.UserSetEnabled(false, "proofpool", "alice", false)
				case "DeleteUser":
					_ = h.UserDelete(false, "proofpool", "alice")
				}
				if h.LastError().Code != hostkit.Internal {
					t.Fatal("fault not reached", h.LastError())
				}
				f.SetFaultUserpoolMutatorAfterCommitForTesting(nil)
				_, _ = h.UserVerifyToken(false, "proofpool", sess.AccessToken())
				if h.LastError().Code == hostkit.OK {
					t.Fatal("old token remains authorized immediately after committed revoke with lost reply")
				}
				if jm {
					if e := j.Compact(); e != nil {
						t.Fatal(e)
					}
					_ = j.Close()
					j = openUserpoolSafetyJournal(t, dir)
					cfg.Journal = j
				}
				h = New(cfg)
				h.SetAbortOnError(false)
				_, _ = h.UserVerifyToken(false, "proofpool", sess.AccessToken())
				t.Logf("old token after native %s and reopen: %s", op, h.LastError().Code)
				if h.LastError().Code == hostkit.OK {
					t.Fatal("old token remains authorized after committed revoke with lost reply")
				}
			})
		}
	}
}

func TestSolUPPBKDF2TimingOracle(t *testing.T) {
	h, f, _, _ := newUserpoolHost(t)
	_, _ = h.UserpoolCreate(false, "timingpool")
	_, _ = h.UserCreate(false, "timingpool", "alice", nil)
	_ = h.UserSetPassword(false, "timingpool", "alice", "ActualPass123")
	guess := "WrongGuess987"
	_, _ = f.SignIn(context.Background(), hostkit.UserSignInInput{Pool: "timingpool", Username: "primeghost", Password: guess})
	start := time.Now()
	_, missing := f.SignIn(context.Background(), hostkit.UserSignInInput{Pool: "timingpool", Username: "nobody", Password: guess})
	fast := time.Since(start)
	start = time.Now()
	_, existing := f.SignIn(context.Background(), hostkit.UserSignInInput{Pool: "timingpool", Username: "alice", Password: guess})
	slow := time.Since(start)
	if hostkit.AsCloudError(missing).Code != hostkit.Unauthenticated || hostkit.AsCloudError(existing).Code != hostkit.Unauthenticated {
		t.Fatal("fixture")
	}
	t.Logf("primed unknown-user check=%s; existing-user cold-salt check=%s; ratio=%.1f", fast, slow, float64(slow)/float64(fast))
	if slow > 20*time.Millisecond && slow > fast*10 {
		t.Fatal("global dummy memo gives a clear username enumeration oracle")
	}
}

func TestSolUPSanitizedProfilesAreReadback(t *testing.T) {
	for _, jm := range []bool{false, true} {
		t.Run(fmt.Sprintf("journal=%v", jm), func(t *testing.T) {
			h, f, _, campaign := newUserpoolHost(t)
			cfg := Config{Provider: "aws", Store: f, Userpools: f, CampaignStatePath: campaign}
			var j *safety.Journal
			dir := filepath.Join(t.TempDir(), "journal")
			if jm {
				j = openUserpoolSafetyJournal(t, dir)
				cfg.Journal = j
				cfg.CampaignStatePath = ""
				defer func() { _ = j.Close() }()
			}
			h = New(cfg)
			h.SetAbortOnError(false)
			_, _ = h.UserpoolCreate(false, "profilepool")
			_, _ = h.UserCreate(false, "profilepool", "alice", map[string]string{
				"note": "a perfectly valid eyJ profile",
				"bio":  strings.Repeat("x", 300),
			})
			act, ok, _, _, e := h.cost.lookupUserpoolEntry("", "profilepool")
			if e != nil || !ok {
				t.Fatal("fixture", e)
			}
			st, _ := decodePersistedUserpoolState(act.StateJSON)
			t.Logf("persisted attrs=%v campaign=%s", st.Users["alice"].Attributes, filepath.Base(campaign))
			if !strings.Contains(st.Users["alice"].Attributes["note"], "eyJ") || len(st.Users["alice"].Attributes["bio"]) != 300 {
				t.Fatalf("persisted user snapshot lost valid attributes: %+v", st.Users["alice"].Attributes)
			}
			u, _ := h.UserGet(false, "profilepool", "alice")
			if !strings.Contains(u.Attribute("note"), "eyJ") || len(u.Attribute("bio")) != 300 {
				t.Fatal("live readback lost value")
			}
			// Also verify dry readback without Peeker after reopen/compact.
			if jm {
				if err := j.Compact(); err != nil {
					t.Fatal(err)
				}
				_ = j.Close()
				j = openUserpoolSafetyJournal(t, dir)
				cfg.Journal = j
			}
			cfg.Userpools = solUserpoolsOnly{Userpools: f}
			hDry := New(cfg)
			hDry.SetAbortOnError(false)
			uDry, err := hDry.UserGet(true, "profilepool", "alice")
			if err != nil || !strings.Contains(uDry.Attribute("note"), "eyJ") || len(uDry.Attribute("bio")) != 300 {
				t.Fatalf("dry readback without peeker lost value: note=%q len(bio)=%d err=%v", uDry.Attribute("note"), len(uDry.Attribute("bio")), err)
			}
		})
	}
}

func TestSolUPForeignReadsAndUnmarkedChildDelete(t *testing.T) {
	t.Run("foreign_pool_read", func(t *testing.T) {
		h, f, _, _ := newUserpoolHost(t)
		if e := f.InjectUnmarkedUserpoolForTesting("foreignpool", strings.Repeat("f", 32)); e != nil {
			t.Fatal(e)
		}
		if e := f.InjectForeignPoolChildForTesting("foreignpool", "user", "alice", strings.Repeat("f", 32)); e != nil {
			t.Fatal(e)
		}
		u, _ := h.UserGet(false, "foreignpool", "alice")
		t.Logf("foreign pool user_get exists=%v attrs=%v code=%s", u.Exists(), u.Attributes(), h.LastError().Code)
		if h.LastError().Code == hostkit.OK && u.Exists() {
			t.Fatal("read foreign pool user without journal ownership")
		}
		if h.LastError().Code != hostkit.PermissionDenied {
			t.Fatalf("expected PERMISSION_DENIED on foreign UserGet, got %+v", h.LastError())
		}
		_, _ = h.GroupList(false, "foreignpool")
		if h.LastError().Code != hostkit.PermissionDenied {
			t.Fatalf("expected PERMISSION_DENIED on foreign GroupList, got %+v", h.LastError())
		}
		_, _ = h.UserGroups(false, "foreignpool", "alice")
		if h.LastError().Code != hostkit.PermissionDenied {
			t.Fatalf("expected PERMISSION_DENIED on foreign UserGroups, got %+v", h.LastError())
		}
	})
	for _, owner := range []string{"", strings.Repeat("f", 32)} {
		t.Run("unmarked_child_owner="+owner, func(t *testing.T) {
			h, f, state, _ := newUserpoolHost(t)
			_, _ = h.UserpoolCreate(false, "ownedpool")
			_, _ = h.UserCreate(false, "ownedpool", "alice", nil)
			raw, e := os.ReadFile(state)
			if e != nil {
				t.Fatal(e)
			}
			var doc map[string]any
			if e = json.Unmarshal(raw, &doc); e != nil {
				t.Fatal(e)
			}
			doc["Userpools"].(map[string]any)["ownedpool"].(map[string]any)["users"].(map[string]any)["alice"].(map[string]any)["owner_token"] = owner
			raw, _ = json.Marshal(doc)
			if e = os.WriteFile(state, raw, 0600); e != nil {
				t.Fatal(e)
			}
			_ = h.UserDelete(false, "ownedpool", "alice")
			u, e := f.GetUser(context.Background(), "ownedpool", "alice")
			t.Logf("delete unmarked/foreign child: exists=%v err=%v code=%s", u.Exists, e, h.LastError().Code)
			if !u.Exists {
				t.Fatal("deleted child whose own owner token does not match")
			}
		})
	}
}

type solUPLatePassword struct {
	*fakeadapter.Fake
	entered, release chan struct{}
}

func (a *solUPLatePassword) SetUserPassword(ctx context.Context, p, u, pw string) (hostkit.UserSnapshot, error) {
	out, e := a.Fake.SetUserPassword(ctx, p, u, pw)
	if e == nil {
		close(a.entered)
		<-a.release
	}
	return out, e
}

func TestSolUPDuplicateCreateErasesRevocation(t *testing.T) {
	t.Parallel()
	for _, jm := range []bool{false, true} {
		jm := jm
		t.Run(fmt.Sprintf("journal=%v", jm), func(t *testing.T) {
			t.Parallel()
			h, f, _, campaign := newUserpoolHost(t)
			cfg := Config{Provider: "aws", Store: f, Userpools: f, CampaignStatePath: campaign}
			var j *safety.Journal
			dir := filepath.Join(t.TempDir(), "journal")
			if jm {
				j = openUserpoolSafetyJournal(t, dir)
				cfg.Journal = j
				cfg.CampaignStatePath = ""
				defer func() { _ = j.Close() }()
			}
			h = New(cfg)
			h.SetAbortOnError(false)
			_, _ = h.UserpoolCreate(false, "duplicatepool")
			_, _ = h.UserCreate(false, "duplicatepool", "alice", nil)
			_ = h.UserSetPassword(false, "duplicatepool", "alice", "FirstPass123")
			sess, _ := h.UserSignIn(false, "duplicatepool", "alice", "FirstPass123")
			a := &solUPLatePassword{Fake: f, entered: make(chan struct{}), release: make(chan struct{})}
			slowCfg := cfg
			slowCfg.Userpools = a
			slow := New(slowCfg)
			slow.SetAbortOnError(false)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_ = slow.UserSetPassword(false, "duplicatepool", "alice", "SecondPass456")
			}()
			<-a.entered
			_, _ = h.UserpoolCreate(false, "duplicatepool")
			if h.LastError().Code != hostkit.OK {
				t.Fatal(h.LastError())
			}
			close(a.release)
			<-done
			_, _ = h.UserVerifyToken(false, "duplicatepool", sess.AccessToken())
			t.Logf("password-reset result=%s old-token verify=%s", slow.LastError().Code, h.LastError().Code)
			if h.LastError().Code == hostkit.OK {
				t.Fatal("successful password reset lost revocation after duplicate pool create")
			}
		})
	}
}

func TestSolUPActiveSecretEvicted(t *testing.T) {
	h, _, _, _ := newUserpoolHost(t)
	active := "ActiveSecret987Example"
	_, _ = h.UserpoolCreate(false, "activepool")
	_, _ = h.UserCreate(false, "activepool", "alice", nil)
	_ = h.UserSetPassword(false, "activepool", "alice", active)
	for i := 0; i < 33000; i++ {
		h.errs.AddRedaction(fmt.Sprintf("UnusedSecret%08d", i))
	}
	_ = h.fail("user_sign_in", "poolname", hostkit.ProviderError(hostkit.Internal, 500, "Failure", "upstream echoed "+active))
	if strings.Contains(h.LastError().Message, active) {
		t.Fatal("still-active secret leaked after fixed-size registration FIFO evicted it")
	}
}

func TestSolUPLegalProfilesExceedJournal(t *testing.T) {
	for _, jm := range []bool{false, true} {
		t.Run(fmt.Sprintf("journal=%v", jm), func(t *testing.T) {
			h, f, _, campaign := newUserpoolHost(t)
			cfg := Config{Provider: "aws", Store: f, Userpools: f, CampaignStatePath: campaign}
			var j *safety.Journal
			dir := filepath.Join(t.TempDir(), "journal")
			if jm {
				j = openUserpoolSafetyJournal(t, dir)
				cfg.Journal = j
				cfg.CampaignStatePath = ""
				defer func() { _ = j.Close() }()
			}
			h = New(cfg)
			h.SetAbortOnError(false)
			_, _ = h.UserpoolCreate(false, "largeprofiles")
			attrs := map[string]string{}
			for i := 0; i < 32; i++ {
				attrs[fmt.Sprintf("attr%d", i)] = strings.Repeat("x", 2048)
			}
			for i := 0; i < 60; i++ {
				_, _ = h.UserCreate(false, "largeprofiles", fmt.Sprintf("user%03d", i), attrs)
				if h.LastError().Code != hostkit.OK {
					if !jm {
						info, _ := os.Stat(campaign)
						t.Logf("legal user count before failure=%d campaign-bytes=%d error=%+v", i, info.Size(), h.LastError())
					}
					_, _ = h.UserpoolDelete(false, "largeprofiles")
					t.Logf("cleanup after journal growth error=%+v", h.LastError())
					t.Fatal("within-contract profiles exhaust authority journal and block cleanup")
				}
			}
			if _, err := h.UserpoolDelete(false, "largeprofiles"); err != nil || h.LastError().Code != hostkit.OK {
				t.Fatalf("UserpoolDelete after 60 legal large-profile users failed: err=%v last=%+v", err, h.LastError())
			}
		})
	}
}

func TestSolUPSameOwnerDifferentIncarnationAdopted(t *testing.T) {
	h, f, _, _ := newUserpoolHost(t)
	_, _ = h.UserpoolCreate(false, "incarnationpool")
	old, _ := f.DescribeUserPool(context.Background(), "incarnationpool")
	if e := f.InjectUnmarkedUserpoolForTesting("incarnationpool", old.OwnerToken); e != nil {
		t.Fatal(e)
	}
	fresh, _ := f.DescribeUserPool(context.Background(), "incarnationpool")
	if fresh.IncarnationID == old.IncarnationID {
		t.Fatal("fixture")
	}
	_, _ = h.UserpoolCreate(false, "incarnationpool")
	act, _, _, _, _ := h.cost.lookupUserpoolEntry("", "incarnationpool")
	t.Logf("different physical incarnation adopted=%v result=%s", act.Incarnation == fresh.IncarnationID, h.LastError().Code)
	if h.LastError().Code == hostkit.OK {
		t.Fatal("same owner token bypassed physical-incarnation fence")
	}
}

func TestSolUPExactEndpointCascade(t *testing.T) {
	a, b := fakeadapter.New(fakeadapter.Options{}), fakeadapter.New(fakeadapter.Options{})
	ea, eb := "http://127.0.0.1:40171", "http://127.0.0.1:40172"
	router := hostkit.Router{Pick: func(ctx context.Context) (hostkit.Backend, error) {
		if hostkit.EndpointFrom(ctx) == ea {
			return a, nil
		}
		return b, nil
	}}
	h := New(Config{Provider: "aws", Store: router, Userpools: router, CampaignStatePath: filepath.Join(t.TempDir(), "journal")})
	h.SetAbortOnError(false)
	for _, ep := range []string{ea, eb} {
		_ = h.SetEndpoint("userpool", ep)
		_, _ = h.UserpoolCreate(false, "samepool")
		_, _ = h.UserCreate(false, "samepool", "alice", nil)
		if h.LastError().Code != hostkit.OK {
			t.Fatal(h.LastError())
		}
	}
	_ = h.SetEndpoint("userpool", ea)
	_, _ = h.UserpoolDelete(false, "samepool")
	if h.LastError().Code != hostkit.OK {
		t.Fatal(h.LastError())
	}
	_ = h.SetEndpoint("userpool", eb)
	u, _ := h.UserGet(false, "samepool", "alice")
	if !u.Exists() || h.LastError().Code != hostkit.OK {
		t.Fatal("other endpoint child deleted", h.LastError())
	}
	if got := h.cost.meter.Snapshot().ResourceCleanupNanoUSD; got != 55000 {
		t.Fatal("other endpoint cleanup reservation released", got)
	}
	t.Log("exact endpoint cascade preserves other endpoint child and 55000 cleanup reserve")
}

type solUPWrongTokenKind struct {
	*fakeadapter.Fake
}

func (a solUPWrongTokenKind) SignIn(ctx context.Context, in hostkit.UserSignInInput) (hostkit.SessionSnapshot, error) {
	out, e := a.Fake.SignIn(ctx, in)
	if e != nil {
		return out, e
	}
	priv, _, kid, issuer, _, _, _, _ := a.Fake.UserpoolSigningKeyMaterialForTesting(in.Pool)
	out.AccessToken, e = hostkit.MintRS256JWT(priv, kid, map[string]any{
		"sub":       out.Claims["sub"],
		"username":  in.Username,
		"iss":       issuer,
		"iat":       out.IssuedAt,
		"exp":       out.ExpiresAt,
		"token_use": "id",
	})
	return out, e
}

func TestSolUPWrongTokenUseAndMissingClient(t *testing.T) {
	h, f, _, _ := newUserpoolHost(t)
	_, _ = h.UserpoolCreate(false, "tokenkindpool")
	_, _ = h.UserCreate(false, "tokenkindpool", "alice", nil)
	_ = h.UserSetPassword(false, "tokenkindpool", "alice", "CorrectPass123")
	goodSess, _ := h.UserSignIn(false, "tokenkindpool", "alice", "CorrectPass123")
	if goodSess.AccessToken() == "" {
		t.Fatal("fixture", h.LastError())
	}
	h.cfg.Userpools = solUPWrongTokenKind{f}
	sess, _ := h.UserSignIn(false, "tokenkindpool", "alice", "CorrectPass123")
	if h.LastError().Code == hostkit.OK || sess.AccessToken() != "" {
		t.Fatal("sign-in accepted ID token without required pool app-client binding")
	}
	priv, _, kid, issuer, _, _, _, _ := f.UserpoolSigningKeyMaterialForTesting("tokenkindpool")
	badTok, err := hostkit.MintRS256JWT(priv, kid, map[string]any{
		"sub":       goodSess.Claims()["sub"],
		"username":  "alice",
		"iss":       issuer,
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Unix() + 3600,
		"token_use": "id",
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, _ := h.UserVerifyToken(false, "tokenkindpool", badTok)
	t.Logf("verified token_use=%s client_id=%q result=%s", verified.Claims()["token_use"], verified.Claims()["client_id"], h.LastError().Code)
	if h.LastError().Code == hostkit.OK {
		t.Fatal("accepted signed ID token without required pool app-client binding as an access token")
	}
}
