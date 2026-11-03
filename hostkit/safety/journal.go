// SPDX-License-Identifier: MIT

package safety

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// JournalVersion is the current append-only JSONL journal format version.
	JournalVersion = 1

	// Resource kinds tracked in the recovery journal.
	KindBucket       = "bucket"
	KindObject       = "object"
	KindQueue        = "queue"
	KindQueueMessage = "queue_message"

	// Journal event types.
	EventMeta      = "meta"
	EventIntent    = "intent"
	EventConfirmed = "confirmed"
	EventFailed    = "failed"
	EventRetained  = "retained"
	EventDeleted   = "deleted"
	EventCost      = "cost"

	// Resource lifecycle states after journal replay.
	StatePending   = "pending"
	StateConfirmed = "confirmed"
	StateRetained  = "retained"
	StateDeleted   = "deleted"
)

var (
	// ErrJournalLeaseBusy is returned when another live host or sweeper holds the flock lease.
	ErrJournalLeaseBusy = errors.New("journal lease busy")

	hex32Pattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NewToken128 generates a random 128-bit lowercase hex token (32 hex chars).
func NewToken128() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// ValidateToken128 verifies that tok is a 32-char lowercase hex string.
func ValidateToken128(tok string) error {
	if !hex32Pattern.MatchString(tok) {
		return fmt.Errorf("invalid 128-bit hex token %q (want 32 lowercase hex chars)", tok)
	}
	return nil
}

// RedactEndpoint strips any userinfo, query string, or fragment from an
// endpoint URL so credentials or signed query parameters never reach the
// on-disk journal.
func RedactEndpoint(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if hasControlChars(raw) {
		return "", errors.New("journal endpoint contains control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid journal endpoint %q: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid journal endpoint %q: scheme and host are required", raw)
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), nil
}

// JournalMeta pins the run identity, policy hash, and attested provider scope
// for a single journal file. Every record in the file must match this header.
type JournalMeta struct {
	RunID         string `json:"run_id"`
	SessionID     string `json:"session_id,omitempty"`
	PolicyHash    string `json:"policy_hash"`
	Provider      string `json:"provider"`
	Account       string `json:"account"`
	Tenant        string `json:"tenant,omitempty"`
	Scope         string `json:"scope"`
	Region        string `json:"region"`
	Endpoint      string `json:"endpoint,omitempty"`
	StartedAtUnix int64  `json:"started_at_unix,omitempty"`
}

// Validate checks that m contains a valid run ID, policy hash, and attested scope.
func (m JournalMeta) Validate() error {
	if err := ValidateRunID(m.RunID); err != nil {
		return err
	}
	if !hex64Pattern.MatchString(m.PolicyHash) {
		return fmt.Errorf("invalid journal policy_hash %q (want 64 lowercase hex chars)", m.PolicyHash)
	}
	if !validProviders[m.Provider] {
		return fmt.Errorf("invalid journal provider %q", m.Provider)
	}
	if strings.TrimSpace(m.Account) == "" || hasControlChars(m.Account) {
		return fmt.Errorf("invalid journal account %q", m.Account)
	}
	if hasControlChars(m.Tenant) {
		return fmt.Errorf("invalid journal tenant %q", m.Tenant)
	}
	if strings.TrimSpace(m.Scope) == "" || hasControlChars(m.Scope) {
		return fmt.Errorf("invalid journal scope %q", m.Scope)
	}
	if strings.TrimSpace(m.Region) == "" || hasControlChars(m.Region) {
		return fmt.Errorf("invalid journal region %q", m.Region)
	}
	if hasControlChars(m.SessionID) || hasControlChars(m.Endpoint) {
		return errors.New("journal meta contains control characters")
	}
	if m.Endpoint != "" {
		cleanEP, err := RedactEndpoint(m.Endpoint)
		if err != nil {
			return err
		}
		if cleanEP != m.Endpoint {
			return fmt.Errorf("journal endpoint %q contains unredacted userinfo, query, or fragment", m.Endpoint)
		}
	}
	return nil
}

func (m JournalMeta) sameIdentity(o JournalMeta) bool {
	return m.RunID == o.RunID &&
		m.PolicyHash == o.PolicyHash &&
		m.Provider == o.Provider &&
		m.Account == o.Account &&
		m.Tenant == o.Tenant &&
		m.Scope == o.Scope &&
		m.Region == o.Region
}

// JournalRecord is a single line in the append-only JSONL journal.
type JournalRecord struct {
	Version             int    `json:"v"`
	Seq                 uint64 `json:"seq"`
	Time                string `json:"ts"`
	Event               string `json:"event"`
	RunID               string `json:"run_id"`
	SessionID           string `json:"session_id,omitempty"`
	PolicyHash          string `json:"policy_hash"`
	Provider            string `json:"provider"`
	Account             string `json:"account"`
	Tenant              string `json:"tenant,omitempty"`
	Scope               string `json:"scope"`
	Region              string `json:"region"`
	Endpoint            string `json:"endpoint,omitempty"`
	StartedAtUnix       int64  `json:"started_at_unix,omitempty"`
	Kind                string `json:"kind,omitempty"`
	Parent              string `json:"parent,omitempty"`
	Location            string `json:"location,omitempty"`
	Name                string `json:"name,omitempty"`
	ProviderID          string `json:"provider_id,omitempty"`
	OwnerNonce          string `json:"owner_nonce,omitempty"`
	CreateToken         string `json:"create_token,omitempty"`
	ETag                string `json:"etag,omitempty"`
	Generation          string `json:"generation,omitempty"`
	IntentAtUnix        int64  `json:"intent_at_unix,omitempty"`
	ConfirmedAtUnix     int64  `json:"confirmed_at_unix,omitempty"`
	ServerCreatedAtUnix int64  `json:"server_created_at_unix,omitempty"`
	ReservedNanoUSD     int64  `json:"reserved_nano_usd,omitempty"`
	ChargedNanoUSD      int64  `json:"charged_nano_usd,omitempty"`
	PayloadBytes        int64  `json:"payload_bytes,omitempty"`
	BucketsCreated      int    `json:"buckets_created,omitempty"`
	QueuesCreated       int    `json:"queues_created,omitempty"`
	ObjectsCreated      int    `json:"objects_created,omitempty"`
	MessagesSent        int    `json:"messages_sent,omitempty"`
	Reason              string `json:"reason,omitempty"`
	Retain              bool   `json:"retain,omitempty"`
}

func (r JournalRecord) meta() JournalMeta {
	return JournalMeta{
		RunID:         r.RunID,
		SessionID:     r.SessionID,
		PolicyHash:    r.PolicyHash,
		Provider:      r.Provider,
		Account:       r.Account,
		Tenant:        r.Tenant,
		Scope:         r.Scope,
		Region:        r.Region,
		Endpoint:      r.Endpoint,
		StartedAtUnix: r.StartedAtUnix,
	}
}

// LedgerEntry is the replayed state of a tracked cloud resource.
type LedgerEntry struct {
	Kind                string
	Parent              string
	Location            string
	Name                string
	ProviderID          string
	OwnerNonce          string
	CreateToken         string
	ETag                string
	Generation          string
	IntentAtUnix        int64
	ConfirmedAtUnix     int64
	ServerCreatedAtUnix int64
	ReservedNanoUSD     int64
	State               string // StatePending, StateConfirmed, StateRetained
	Retain              bool
	Reason              string
	Seq                 uint64
}

func resourceKey(kind, parent, name string) string {
	return kind + "\x00" + parent + "\x00" + name
}

// LedgerState represents the validated, replayed state of a run journal.
type LedgerState struct {
	Meta              JournalMeta
	StartedAtUnix     int64
	LastSeq           uint64
	Entries           []LedgerEntry
	ReservedNanoUSD   int64
	ChargedNanoUSD    int64
	BucketsCreated    int
	QueuesCreated     int
	ObjectsCreated    int
	MessagesSent      int
	TotalPayloadBytes int64

	byKey map[string]int
}

// Lookup returns the current LedgerEntry for (kind, parent, name), if active.
func (s *LedgerState) Lookup(kind, parent, name string) (LedgerEntry, bool) {
	if s == nil || s.byKey == nil {
		return LedgerEntry{}, false
	}
	idx, ok := s.byKey[resourceKey(kind, parent, name)]
	if !ok || idx < 0 || idx >= len(s.Entries) {
		return LedgerEntry{}, false
	}
	return s.Entries[idx], true
}

// CreateIntent holds the durably journaled tokens for a resource creation attempt.
type CreateIntent struct {
	Kind             string
	Parent           string
	Location         string
	Name             string
	OwnerNonce       string
	CreateToken      string
	IntentAtUnix     int64
	AlreadyConfirmed bool
}

// ConfirmDetails carries the provider's post-create identifiers and timestamps.
type ConfirmDetails struct {
	ProviderID          string
	Location            string
	ETag                string
	Generation          string
	ConfirmedAtUnix     int64
	ServerCreatedAtUnix int64
	ChargedNanoUSD      int64
	PayloadBytes        int64
}

// EnsureStateDir creates dir (if missing) with mode 0700 and verifies that the
// leaf directory is a real directory (not a symlink), owned by the current UID,
// with zero group/other permission bits.
func EnsureStateDir(dir string) (string, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return "", errors.New("state directory path must not be empty")
	}
	parent := filepath.Dir(dir)
	if parent != "." && parent != "/" {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", fmt.Errorf("mkdir parent %s: %w", parent, err)
		}
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if mkErr := os.Mkdir(dir, 0o700); mkErr != nil && !errors.Is(mkErr, os.ErrExist) {
			return "", fmt.Errorf("mkdir %s: %w", dir, mkErr)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("lstat %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("state directory %q must be a real directory, not a symlink", dir)
	}
	if err := verifyFileOwnerUID(info, dir); err != nil {
		return "", err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("state directory %q has permissions %04o; must not be group/world accessible (want 0700)", dir, perm)
	}
	return filepath.Clean(dir), nil
}

// JournalPath returns the canonical path `<dir>/<run_id>.jsonl` after validating runID.
func JournalPath(dir, runID string) (string, error) {
	if err := ValidateRunID(runID); err != nil {
		return "", err
	}
	cleanDir, err := EnsureStateDir(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(cleanDir, runID+".jsonl"), nil
}

// Journal is an append-only, fsync-backed per-run recovery journal with an
// exclusive POSIX flock lease held on a dedicated `<run_id>.lock` file that is
// never renamed or unlinked during compaction.
type Journal struct {
	mu         sync.Mutex
	path       string
	lockPath   string
	dir        string
	f          *os.File
	lockFile   *os.File
	goodOffset int64
	poisoned   error
	meta       JournalMeta
	state      *LedgerState
	now        func() time.Time
}

// SetClock configures the clock used for timestamps on subsequent journal writes.
func (j *Journal) SetClock(now func() time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.now = now
}

func (j *Journal) nowTime() time.Time {
	if j.now != nil {
		return j.now()
	}
	return time.Now()
}

// OpenJournal opens or creates `<dir>/<meta.RunID>.jsonl`, acquires an exclusive
// non-blocking flock lease on `<dir>/<meta.RunID>.lock`, truncates any
// incomplete torn final line, replays and validates existing records (or writes
// the initial `meta` header), and returns the active Journal.
func OpenJournal(dir string, meta JournalMeta) (*Journal, error) {
	if meta.Endpoint != "" {
		cleanEP, err := RedactEndpoint(meta.Endpoint)
		if err != nil {
			return nil, err
		}
		meta.Endpoint = cleanEP
	}
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	path, err := JournalPath(dir, meta.RunID)
	if err != nil {
		return nil, err
	}
	cleanDir := filepath.Dir(path)
	lockPath := strings.TrimSuffix(path, ".jsonl") + ".lock"

	lockFile, lockCreated, err := openJournalFileNoFollow(lockPath)
	if err != nil {
		return nil, err
	}
	if err := lockJournalFile(lockFile); err != nil {
		_ = lockFile.Close()
		return nil, err
	}

	f, created, err := openJournalFileNoFollow(path)
	if err != nil {
		_ = unlockJournalFile(lockFile)
		_ = lockFile.Close()
		return nil, err
	}

	j := &Journal{
		path:     path,
		lockPath: lockPath,
		dir:      cleanDir,
		f:        f,
		lockFile: lockFile,
		meta:     meta,
	}

	raw, err := io.ReadAll(f)
	if err != nil {
		_ = j.Close()
		return nil, fmt.Errorf("read journal %s: %w", path, err)
	}

	// If the file ends with an incomplete line (no trailing '\n'), truncate the
	// torn tail before replaying or appending.
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		lastNL := bytes.LastIndexByte(raw, '\n')
		truncLen := int64(0)
		if lastNL >= 0 {
			truncLen = int64(lastNL + 1)
		}
		if err := f.Truncate(truncLen); err != nil {
			_ = j.Close()
			return nil, fmt.Errorf("truncate torn journal tail %s: %w", path, err)
		}
		if err := f.Sync(); err != nil {
			_ = j.Close()
			return nil, fmt.Errorf("sync truncated journal %s: %w", path, err)
		}
		raw = raw[:truncLen]
	}

	if len(raw) == 0 {
		startedUnix := meta.StartedAtUnix
		if startedUnix <= 0 {
			startedUnix = time.Now().UTC().Unix()
		}
		j.meta.StartedAtUnix = startedUnix
		j.state = &LedgerState{
			Meta:          j.meta,
			StartedAtUnix: startedUnix,
			byKey:         make(map[string]int),
		}
		if err := j.appendLocked(JournalRecord{
			Event:         EventMeta,
			Endpoint:      j.meta.Endpoint,
			StartedAtUnix: startedUnix,
		}); err != nil {
			_ = j.Close()
			return nil, err
		}
		if created || lockCreated {
			if err := syncDir(cleanDir); err != nil {
				_ = j.Close()
				return nil, err
			}
		}
		return j, nil
	}

	records, _, err := parseJournalBytes(raw, false)
	if err != nil {
		_ = j.Close()
		return nil, fmt.Errorf("journal %s: %w", path, err)
	}
	state, err := ReplayJournal(records)
	if err != nil {
		_ = j.Close()
		return nil, fmt.Errorf("journal %s: %w", path, err)
	}
	if !state.Meta.sameIdentity(meta) {
		_ = j.Close()
		return nil, fmt.Errorf("journal %s scope mismatch: file has (%s/%s/%s/%s policy=%s), caller has (%s/%s/%s/%s policy=%s)",
			path,
			state.Meta.Provider, state.Meta.Account, state.Meta.Scope, state.Meta.Region, state.Meta.PolicyHash,
			meta.Provider, meta.Account, meta.Scope, meta.Region, meta.PolicyHash,
		)
	}
	endOff, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		_ = j.Close()
		return nil, fmt.Errorf("seek journal end %s: %w", path, err)
	}
	j.goodOffset = endOff
	if state.StartedAtUnix > 0 {
		j.meta.StartedAtUnix = state.StartedAtUnix
	}
	j.state = state
	return j, nil
}

func openJournalFileNoFollow(path string) (*os.File, bool, error) {
	created := false
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		created = true
	}
	flags := os.O_RDWR | os.O_CREATE | syscall.O_NOFOLLOW
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open journal %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, false, fmt.Errorf("fstat journal %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, false, fmt.Errorf("journal %q must be a regular file", path)
	}
	if err := verifyFileOwnerUID(info, path); err != nil {
		_ = f.Close()
		return nil, false, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		_ = f.Close()
		return nil, false, fmt.Errorf("journal %q has permissions %04o; must not be group/world accessible (want 0600)", path, perm)
	}
	return f, created, nil
}

// Path returns the filesystem path of the open journal.
func (j *Journal) Path() string {
	return j.path
}

// Meta returns the immutable JournalMeta header for this journal.
func (j *Journal) Meta() JournalMeta {
	return j.meta
}

// State returns a snapshot of the current replayed LedgerState.
func (j *Journal) State() LedgerState {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := *j.state
	cp.Entries = append([]LedgerEntry(nil), j.state.Entries...)
	cp.byKey = make(map[string]int, len(j.state.byKey))
	for k, v := range j.state.byKey {
		cp.byKey[k] = v
	}
	return cp
}

// Lookup returns the current LedgerEntry for (kind, parent, name), if active.
func (j *Journal) Lookup(kind, parent, name string) (LedgerEntry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state.Lookup(kind, parent, name)
}

// BeginCreate durably records an `intent` entry (with fsync) BEFORE a cloud
// create call is dispatched.
//
// Invariants:
//   - If the resource is already `confirmed` or `retained` in this journal,
//     BeginCreate returns the existing tokens with AlreadyConfirmed=true and
//     does NOT overwrite the resource's OwnerNonce or CreateToken.
//   - If the resource is currently `pending` (e.g. a retry after an ambiguous
//     transport failure), BeginCreate reuses the persisted OwnerNonce and
//     CreateToken so the provider can deduplicate the retry.
//   - Otherwise, BeginCreate generates fresh 128-bit OwnerNonce and CreateToken
//     values, appends an `intent` record, and fsyncs the journal before returning.
func (j *Journal) BeginCreate(kind, parent, location, name string, reservedNanoUSD int64) (CreateIntent, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return CreateIntent{}, j.poisoned
	}

	if existing, ok := j.state.Lookup(kind, parent, name); ok {
		if existing.State == StateConfirmed || existing.State == StateRetained || existing.Retain {
			return CreateIntent{
				Kind:             existing.Kind,
				Parent:           existing.Parent,
				Location:         existing.Location,
				Name:             existing.Name,
				OwnerNonce:       existing.OwnerNonce,
				CreateToken:      existing.CreateToken,
				IntentAtUnix:     existing.IntentAtUnix,
				AlreadyConfirmed: true,
			}, nil
		}
		if existing.State == StatePending {
			return CreateIntent{
				Kind:         existing.Kind,
				Parent:       existing.Parent,
				Location:     existing.Location,
				Name:         existing.Name,
				OwnerNonce:   existing.OwnerNonce,
				CreateToken:  existing.CreateToken,
				IntentAtUnix: existing.IntentAtUnix,
			}, nil
		}
	}

	nowUnix := j.nowTime().UTC().Unix()
	intent := CreateIntent{
		Kind:         kind,
		Parent:       parent,
		Location:     location,
		Name:         name,
		OwnerNonce:   NewToken128(),
		CreateToken:  NewToken128(),
		IntentAtUnix: nowUnix,
	}
	rec := JournalRecord{
		Event:           EventIntent,
		Kind:            kind,
		Parent:          parent,
		Location:        location,
		Name:            name,
		OwnerNonce:      intent.OwnerNonce,
		CreateToken:     intent.CreateToken,
		IntentAtUnix:    intent.IntentAtUnix,
		ReservedNanoUSD: reservedNanoUSD,
	}
	if err := j.appendLocked(rec); err != nil {
		return CreateIntent{}, err
	}
	return intent, nil
}

// Confirm durably records that a resource creation succeeded and its ownership
// metadata was verified.
func (j *Journal) Confirm(kind, parent, name string, details ConfirmDetails) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	existing, ok := j.state.Lookup(kind, parent, name)
	if !ok {
		return fmt.Errorf("cannot confirm %s %s/%s without prior intent", kind, parent, name)
	}
	if existing.State == StateRetained || existing.Retain {
		return fmt.Errorf("cannot confirm retained %s %s/%s (%s)", kind, parent, name, existing.Reason)
	}
	loc := details.Location
	if loc == "" {
		loc = existing.Location
	}
	confAt := details.ConfirmedAtUnix
	if confAt == 0 {
		confAt = j.nowTime().UTC().Unix()
	}
	rec := JournalRecord{
		Event:               EventConfirmed,
		Kind:                kind,
		Parent:              parent,
		Location:            loc,
		Name:                name,
		ProviderID:          details.ProviderID,
		OwnerNonce:          existing.OwnerNonce,
		CreateToken:         existing.CreateToken,
		ETag:                details.ETag,
		Generation:          details.Generation,
		IntentAtUnix:        existing.IntentAtUnix,
		ConfirmedAtUnix:     confAt,
		ServerCreatedAtUnix: details.ServerCreatedAtUnix,
		ChargedNanoUSD:      details.ChargedNanoUSD,
		PayloadBytes:        details.PayloadBytes,
		Retain:              existing.Retain,
		Reason:              existing.Reason,
	}
	return j.appendLocked(rec)
}

// Failed records that a pending create attempt definitively failed before any
// resource was created.
//
// CRITICAL INVARIANT: If the resource is already `confirmed` or `retained`
// (for example, a duplicate create call that returned 409 Conflict), Failed is
// a no-op on the resource state and NEVER cancels the confirmed entry.
func (j *Journal) Failed(kind, parent, name, reason string, chargedNanoUSD int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	existing, ok := j.state.Lookup(kind, parent, name)
	if !ok {
		return nil
	}
	if existing.State == StateConfirmed || existing.State == StateRetained || existing.Retain {
		if chargedNanoUSD > 0 {
			return j.appendLocked(JournalRecord{
				Event:          EventCost,
				Kind:           kind,
				Parent:         parent,
				Name:           name,
				ChargedNanoUSD: chargedNanoUSD,
				Reason:         reason,
			})
		}
		return nil
	}
	return j.appendLocked(JournalRecord{
		Event:          EventFailed,
		Kind:           kind,
		Parent:         parent,
		Location:       existing.Location,
		Name:           name,
		Reason:         reason,
		ChargedNanoUSD: chargedNanoUSD,
	})
}

// Retain marks a resource as retained (either by policy or because cleanup/probe
// encountered an ambiguous or mismatched state that forbids blind deletion).
func (j *Journal) Retain(kind, parent, name, reason string) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	existing, ok := j.state.Lookup(kind, parent, name)
	rec := JournalRecord{
		Event:  EventRetained,
		Kind:   kind,
		Parent: parent,
		Name:   name,
		Reason: reason,
		Retain: true,
	}
	if ok {
		rec.Location = existing.Location
		rec.ProviderID = existing.ProviderID
		rec.OwnerNonce = existing.OwnerNonce
		rec.CreateToken = existing.CreateToken
		rec.ETag = existing.ETag
		rec.Generation = existing.Generation
		rec.IntentAtUnix = existing.IntentAtUnix
		rec.ConfirmedAtUnix = existing.ConfirmedAtUnix
		rec.ServerCreatedAtUnix = existing.ServerCreatedAtUnix
	}
	return j.appendLocked(rec)
}

// Deleted durably records that a tracked resource has been verified deleted/absent.
func (j *Journal) Deleted(kind, parent, name string, chargedNanoUSD int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	loc := ""
	if existing, ok := j.state.Lookup(kind, parent, name); ok {
		loc = existing.Location
	}
	return j.appendLocked(JournalRecord{
		Event:          EventDeleted,
		Kind:           kind,
		Parent:         parent,
		Location:       loc,
		Name:           name,
		ChargedNanoUSD: chargedNanoUSD,
	})
}

// RecordCost records an operation's charged cost in nano-USD.
func (j *Journal) RecordCost(kind, parent, name, reason string, chargedNanoUSD int64) error {
	return j.RecordCostWithBytes(kind, parent, name, reason, chargedNanoUSD, 0)
}

// RecordCostWithBytes records an operation's charged cost in nano-USD and payload bytes.
func (j *Journal) RecordCostWithBytes(kind, parent, name, reason string, chargedNanoUSD, payloadBytes int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	return j.appendLocked(JournalRecord{
		Event:          EventCost,
		Kind:           kind,
		Parent:         parent,
		Name:           name,
		ChargedNanoUSD: chargedNanoUSD,
		PayloadBytes:   payloadBytes,
		Reason:         reason,
	})
}

func (j *Journal) rollbackAndPoisonLocked(prevOffset int64, cause error) {
	if j.f != nil {
		_ = j.f.Truncate(prevOffset)
		_, _ = j.f.Seek(prevOffset, io.SeekStart)
		_ = j.f.Sync()
	}
	if j.poisoned == nil {
		j.poisoned = cause
	}
}

func (j *Journal) appendLocked(rec JournalRecord) error {
	if j.f == nil {
		return errors.New("journal is closed")
	}
	if j.poisoned != nil {
		return j.poisoned
	}
	rec.Version = JournalVersion
	rec.Seq = j.state.LastSeq + 1
	if rec.Time == "" {
		rec.Time = j.nowTime().UTC().Format(time.RFC3339Nano)
	}
	rec.RunID = j.meta.RunID
	rec.SessionID = j.meta.SessionID
	rec.PolicyHash = j.meta.PolicyHash
	rec.Provider = j.meta.Provider
	rec.Account = j.meta.Account
	rec.Tenant = j.meta.Tenant
	rec.Scope = j.meta.Scope
	rec.Region = j.meta.Region
	if rec.Endpoint == "" {
		rec.Endpoint = j.meta.Endpoint
	} else {
		cleanEP, err := RedactEndpoint(rec.Endpoint)
		if err != nil {
			return err
		}
		rec.Endpoint = cleanEP
	}

	if err := validateRecord(rec, j.meta, rec.Seq); err != nil {
		return err
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal journal record: %w", err)
	}
	line = append(line, '\n')

	prevOffset := j.goodOffset
	n, err := j.f.Write(line)
	if err != nil {
		j.rollbackAndPoisonLocked(prevOffset, fmt.Errorf("write journal %s: %w", j.path, err))
		return j.poisoned
	}
	if n != len(line) {
		j.rollbackAndPoisonLocked(prevOffset, fmt.Errorf("short write on journal %s (%d/%d bytes)", j.path, n, len(line)))
		return j.poisoned
	}
	if err := j.f.Sync(); err != nil {
		j.rollbackAndPoisonLocked(prevOffset, fmt.Errorf("fsync journal %s: %w", j.path, err))
		return j.poisoned
	}
	j.goodOffset = prevOffset + int64(len(line))

	return applyRecordToState(j.state, rec)
}

// Compact rewrites the journal atomically via a temporary file (fsync temp ->
// atomic rename -> fsync parent dir) containing only the `meta` header, active
// (`pending`, `confirmed`, `retained`) entries, and accumulated cost/counters,
// while holding the dedicated `<run_id>.lock` flock lease continuously.
func (j *Journal) Compact() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return errors.New("journal is closed")
	}
	if j.poisoned != nil {
		return j.poisoned
	}

	var (
		activeBuckets int
		activeQueues  int
		activeObjects int
	)
	for _, e := range j.state.Entries {
		if e.State == StateConfirmed && !e.Retain {
			switch e.Kind {
			case KindBucket:
				activeBuckets++
			case KindQueue:
				activeQueues++
			case KindObject:
				activeObjects++
			}
		}
	}
	baseBuckets := j.state.BucketsCreated - activeBuckets
	if baseBuckets < 0 {
		baseBuckets = 0
	}
	baseQueues := j.state.QueuesCreated - activeQueues
	if baseQueues < 0 {
		baseQueues = 0
	}
	baseObjects := j.state.ObjectsCreated - activeObjects
	if baseObjects < 0 {
		baseObjects = 0
	}

	var compacted []JournalRecord
	seq := uint64(1)
	nowStr := time.Now().UTC().Format(time.RFC3339Nano)

	compacted = append(compacted, JournalRecord{
		Version:         JournalVersion,
		Seq:             seq,
		Time:            nowStr,
		Event:           EventMeta,
		RunID:           j.meta.RunID,
		SessionID:       j.meta.SessionID,
		PolicyHash:      j.meta.PolicyHash,
		Provider:        j.meta.Provider,
		Account:         j.meta.Account,
		Tenant:          j.meta.Tenant,
		Scope:           j.meta.Scope,
		Region:          j.meta.Region,
		Endpoint:        j.meta.Endpoint,
		StartedAtUnix:   j.state.StartedAtUnix,
		ReservedNanoUSD: j.state.ReservedNanoUSD,
		ChargedNanoUSD:  j.state.ChargedNanoUSD,
		PayloadBytes:    j.state.TotalPayloadBytes,
		BucketsCreated:  baseBuckets,
		QueuesCreated:   baseQueues,
		ObjectsCreated:  baseObjects,
		MessagesSent:    j.state.MessagesSent,
	})

	for _, e := range j.state.Entries {
		seq++
		ev := EventIntent
		retainFlag := e.Retain
		switch {
		case e.Retain || e.State == StateRetained:
			ev = EventRetained
			retainFlag = true
		case e.State == StateConfirmed:
			ev = EventConfirmed
		case e.State == StatePending:
			ev = EventIntent
		default:
			continue
		}
		compacted = append(compacted, JournalRecord{
			Version:             JournalVersion,
			Seq:                 seq,
			Time:                nowStr,
			Event:               ev,
			RunID:               j.meta.RunID,
			SessionID:           j.meta.SessionID,
			PolicyHash:          j.meta.PolicyHash,
			Provider:            j.meta.Provider,
			Account:             j.meta.Account,
			Tenant:              j.meta.Tenant,
			Scope:               j.meta.Scope,
			Region:              j.meta.Region,
			Endpoint:            j.meta.Endpoint,
			Kind:                e.Kind,
			Parent:              e.Parent,
			Location:            e.Location,
			Name:                e.Name,
			ProviderID:          e.ProviderID,
			OwnerNonce:          e.OwnerNonce,
			CreateToken:         e.CreateToken,
			ETag:                e.ETag,
			Generation:          e.Generation,
			IntentAtUnix:        e.IntentAtUnix,
			ConfirmedAtUnix:     e.ConfirmedAtUnix,
			ServerCreatedAtUnix: e.ServerCreatedAtUnix,
			Reason:              e.Reason,
			Retain:              retainFlag,
		})
	}

	newState, err := ReplayJournal(compacted)
	if err != nil {
		return fmt.Errorf("validate compacted journal: %w", err)
	}
	// Preserve per-entry pending reservations in memory.
	for i := range newState.Entries {
		ne := &newState.Entries[i]
		if old, ok := j.state.Lookup(ne.Kind, ne.Parent, ne.Name); ok {
			ne.ReservedNanoUSD = old.ReservedNanoUSD
		}
	}

	tmpPath := j.path + ".tmp"
	_ = os.Remove(tmpPath)
	tf, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("open temp journal %s: %w", tmpPath, err)
	}
	for _, rec := range compacted {
		line, err := json.Marshal(rec)
		if err != nil {
			_ = tf.Close()
			_ = os.Remove(tmpPath)
			return err
		}
		line = append(line, '\n')
		if _, err := tf.Write(line); err != nil {
			_ = tf.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("write temp journal %s: %w", tmpPath, err)
		}
	}
	if err := tf.Sync(); err != nil {
		_ = tf.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("fsync temp journal %s: %w", tmpPath, err)
	}
	if err := tf.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp journal %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, j.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename compacted journal %s -> %s: %w", tmpPath, j.path, err)
	}
	if err := syncDir(j.dir); err != nil {
		j.poisoned = fmt.Errorf("journal poisoned after compaction dir sync failure: %w", err)
		return j.poisoned
	}

	newF, _, err := openJournalFileNoFollow(j.path)
	if err != nil {
		j.poisoned = fmt.Errorf("journal poisoned after compaction reopen failure: %w", err)
		return j.poisoned
	}
	endOff, err := newF.Seek(0, io.SeekEnd)
	if err != nil {
		_ = newF.Close()
		j.poisoned = fmt.Errorf("journal poisoned after compaction seek failure: %w", err)
		return j.poisoned
	}
	oldF := j.f
	j.f = newF
	j.goodOffset = endOff
	j.state = newState
	_ = oldF.Close()
	return nil
}

// Close releases the flock lease and closes the underlying journal and lock files.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	var firstErr error
	if j.f != nil {
		f := j.f
		j.f = nil
		if err := f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if j.lockFile != nil {
		lf := j.lockFile
		j.lockFile = nil
		_ = unlockJournalFile(lf)
		if err := lf.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// LoadJournal reads, validates, and replays a journal file from disk without
// modifying it. If the final line is torn (missing trailing '\n'), LoadJournal
// tolerates and ignores that incomplete tail line; any corrupt line in the
// middle is fatal.
func LoadJournal(path string) (*LedgerState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("lstat journal %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("journal %q must be a regular file", path)
	}
	if err := verifyFileOwnerUID(info, path); err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("journal %q has permissions %04o; must not be group/world accessible (want 0600)", path, perm)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read journal %s: %w", path, err)
	}
	records, _, err := parseJournalBytes(raw, true)
	if err != nil {
		return nil, fmt.Errorf("journal %s: %w", path, err)
	}
	state, err := ReplayJournal(records)
	if err != nil {
		return nil, fmt.Errorf("journal %s: %w", path, err)
	}
	base := filepath.Base(path)
	if strings.HasSuffix(base, ".jsonl") {
		wantRun := strings.TrimSuffix(base, ".jsonl")
		if state.Meta.RunID != wantRun {
			return nil, fmt.Errorf("journal %s run_id mismatch: header has %q, filename has %q", path, state.Meta.RunID, wantRun)
		}
	}
	return state, nil
}

func parseJournalBytes(raw []byte, tolerateTornTail bool) ([]JournalRecord, bool, error) {
	tornTail := false
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		if !tolerateTornTail {
			return nil, true, errors.New("unexpected incomplete trailing line")
		}
		tornTail = true
		lastNL := bytes.LastIndexByte(raw, '\n')
		if lastNL < 0 {
			return nil, true, errors.New("journal contains only an incomplete torn first line")
		}
		raw = raw[:lastNL+1]
	}
	lines := bytes.Split(raw, []byte{'\n'})
	var records []JournalRecord
	for i, line := range lines {
		if i == len(lines)-1 && len(line) == 0 {
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, tornTail, fmt.Errorf("line %d: empty line in middle of journal", i+1)
		}
		var rec JournalRecord
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return nil, tornTail, fmt.Errorf("line %d: invalid JSON record: %w", i+1, err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return nil, tornTail, fmt.Errorf("line %d: trailing data on JSONL line", i+1)
		}
		records = append(records, rec)
	}
	return records, tornTail, nil
}

// ReplayJournal validates a sequence of JournalRecords and folds them into a LedgerState.
func ReplayJournal(records []JournalRecord) (*LedgerState, error) {
	if len(records) == 0 {
		return nil, errors.New("empty journal (missing meta record)")
	}
	first := records[0]
	if first.Event != EventMeta {
		return nil, fmt.Errorf("first journal record must be %q, got %q", EventMeta, first.Event)
	}
	meta := first.meta()
	if err := meta.Validate(); err != nil {
		return nil, fmt.Errorf("meta record: %w", err)
	}
	state := &LedgerState{
		Meta:          meta,
		StartedAtUnix: meta.StartedAtUnix,
		byKey:         make(map[string]int),
	}
	for i, rec := range records {
		wantSeq := uint64(i + 1)
		if err := validateRecord(rec, meta, wantSeq); err != nil {
			return nil, fmt.Errorf("record %d (seq=%d): %w", i+1, rec.Seq, err)
		}
		if err := applyRecordToState(state, rec); err != nil {
			return nil, fmt.Errorf("record %d (seq=%d): %w", i+1, rec.Seq, err)
		}
	}
	return state, nil
}

func validateRecord(rec JournalRecord, meta JournalMeta, wantSeq uint64) error {
	if rec.Version != JournalVersion {
		return fmt.Errorf("unsupported journal version %d (want %d)", rec.Version, JournalVersion)
	}
	if rec.Seq != wantSeq {
		return fmt.Errorf("non-monotonic journal seq %d (want %d)", rec.Seq, wantSeq)
	}
	if !meta.sameIdentity(rec.meta()) {
		return fmt.Errorf("record scope/policy mismatch against journal meta (got run=%q provider=%q account=%q scope=%q region=%q policy=%q)",
			rec.RunID, rec.Provider, rec.Account, rec.Scope, rec.Region, rec.PolicyHash)
	}
	if rec.Endpoint != "" {
		cleanEP, err := RedactEndpoint(rec.Endpoint)
		if err != nil {
			return err
		}
		if cleanEP != rec.Endpoint {
			return fmt.Errorf("record endpoint %q contains unredacted userinfo, query, or fragment", rec.Endpoint)
		}
	}
	if rec.ReservedNanoUSD < 0 || rec.ChargedNanoUSD < 0 || rec.PayloadBytes < 0 ||
		rec.BucketsCreated < 0 || rec.QueuesCreated < 0 || rec.ObjectsCreated < 0 || rec.MessagesSent < 0 {
		return errors.New("negative cost or counter amount in journal record")
	}

	switch rec.Event {
	case EventMeta:
		if wantSeq != 1 {
			return errors.New("duplicate meta record after seq 1")
		}
		return nil
	case EventCost:
		return nil
	case EventIntent, EventConfirmed, EventFailed, EventRetained, EventDeleted:
		if err := validateResourceIdentity(rec.RunID, rec.Kind, rec.Parent, rec.Name); err != nil {
			return err
		}
		if rec.Event == EventIntent || rec.Event == EventConfirmed {
			if err := ValidateToken128(rec.OwnerNonce); err != nil {
				return fmt.Errorf("owner_nonce: %w", err)
			}
			if err := ValidateToken128(rec.CreateToken); err != nil {
				return fmt.Errorf("create_token: %w", err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown journal event %q", rec.Event)
	}
}

func validateResourceIdentity(runID, kind, parent, name string) error {
	if hasControlChars(parent) || hasControlChars(name) {
		return errors.New("resource parent/name contains control characters")
	}
	switch kind {
	case KindBucket, KindQueue:
		if parent != "" {
			return fmt.Errorf("%s record must have empty parent (got %q)", kind, parent)
		}
		if err := ValidateLiveResourceName(runID, name); err != nil {
			return fmt.Errorf("forged or unprefixed %s name in journal: %w", kind, err)
		}
		return nil
	case KindObject, KindQueueMessage:
		if err := ValidateLiveResourceName(runID, parent); err != nil {
			return fmt.Errorf("forged or unprefixed parent %q for %s in journal: %w", parent, kind, err)
		}
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s record must have non-empty name", kind)
		}
		return nil
	default:
		return fmt.Errorf("invalid resource kind %q", kind)
	}
}

func incrementKindCreated(state *LedgerState, kind string) {
	switch kind {
	case KindBucket:
		state.BucketsCreated++
	case KindQueue:
		state.QueuesCreated++
	case KindObject:
		state.ObjectsCreated++
	}
}

func applyRecordToState(state *LedgerState, rec JournalRecord) error {
	state.LastSeq = rec.Seq
	state.ReservedNanoUSD += rec.ReservedNanoUSD
	state.ChargedNanoUSD += rec.ChargedNanoUSD
	state.TotalPayloadBytes += rec.PayloadBytes

	if rec.Event == EventMeta {
		if rec.StartedAtUnix > 0 {
			state.StartedAtUnix = rec.StartedAtUnix
		} else if state.StartedAtUnix == 0 && rec.Time != "" {
			if t, err := time.Parse(time.RFC3339Nano, rec.Time); err == nil {
				state.StartedAtUnix = t.UTC().Unix()
			}
		}
		state.BucketsCreated += rec.BucketsCreated
		state.QueuesCreated += rec.QueuesCreated
		state.ObjectsCreated += rec.ObjectsCreated
		state.MessagesSent += rec.MessagesSent
		return nil
	}
	if rec.Event == EventCost {
		if rec.Kind == KindQueueMessage && rec.Reason == "queue_send" {
			state.MessagesSent++
		}
		return nil
	}

	key := resourceKey(rec.Kind, rec.Parent, rec.Name)
	idx, exists := state.byKey[key]

	switch rec.Event {
	case EventIntent:
		if exists {
			cur := state.Entries[idx]
			// Duplicate intent on an already confirmed/retained resource never
			// overwrites its OwnerNonce, CreateToken, or state.
			if cur.State == StateConfirmed || cur.State == StateRetained || cur.Retain {
				return nil
			}
			// Pending retry: preserve existing OwnerNonce if already set.
			if cur.OwnerNonce != "" && cur.OwnerNonce != rec.OwnerNonce {
				return fmt.Errorf("conflicting owner_nonce on pending %s %s/%s", rec.Kind, rec.Parent, rec.Name)
			}
			cur.CreateToken = rec.CreateToken
			if rec.ReservedNanoUSD > 0 {
				cur.ReservedNanoUSD += rec.ReservedNanoUSD
			}
			cur.Seq = rec.Seq
			state.Entries[idx] = cur
			return nil
		}
		entry := LedgerEntry{
			Kind:            rec.Kind,
			Parent:          rec.Parent,
			Location:        rec.Location,
			Name:            rec.Name,
			OwnerNonce:      rec.OwnerNonce,
			CreateToken:     rec.CreateToken,
			IntentAtUnix:    rec.IntentAtUnix,
			ReservedNanoUSD: rec.ReservedNanoUSD,
			State:           StatePending,
			Seq:             rec.Seq,
		}
		state.byKey[key] = len(state.Entries)
		state.Entries = append(state.Entries, entry)
		return nil

	case EventConfirmed:
		if exists {
			cur := state.Entries[idx]
			if cur.OwnerNonce != "" && cur.OwnerNonce != rec.OwnerNonce {
				return fmt.Errorf("confirmed owner_nonce mismatch for %s %s/%s", rec.Kind, rec.Parent, rec.Name)
			}
			wasConfirmed := cur.State == StateConfirmed
			if cur.Retain || cur.State == StateRetained || rec.Retain {
				cur.State = StateRetained
				cur.Retain = true
				if rec.Reason != "" {
					cur.Reason = rec.Reason
				}
			} else {
				cur.State = StateConfirmed
				if !wasConfirmed {
					incrementKindCreated(state, rec.Kind)
				}
			}
			cur.ReservedNanoUSD = 0
			if rec.Location != "" {
				cur.Location = rec.Location
			}
			if rec.ProviderID != "" {
				cur.ProviderID = rec.ProviderID
			}
			cur.OwnerNonce = rec.OwnerNonce
			cur.CreateToken = rec.CreateToken
			if rec.ETag != "" {
				cur.ETag = rec.ETag
			}
			if rec.Generation != "" {
				cur.Generation = rec.Generation
			}
			if rec.IntentAtUnix != 0 {
				cur.IntentAtUnix = rec.IntentAtUnix
			}
			if rec.ConfirmedAtUnix != 0 {
				cur.ConfirmedAtUnix = rec.ConfirmedAtUnix
			}
			if rec.ServerCreatedAtUnix != 0 {
				cur.ServerCreatedAtUnix = rec.ServerCreatedAtUnix
			}
			cur.Seq = rec.Seq
			state.Entries[idx] = cur
			return nil
		}
		st := StateConfirmed
		if rec.Retain {
			st = StateRetained
		} else {
			incrementKindCreated(state, rec.Kind)
		}
		entry := LedgerEntry{
			Kind:                rec.Kind,
			Parent:              rec.Parent,
			Location:            rec.Location,
			Name:                rec.Name,
			ProviderID:          rec.ProviderID,
			OwnerNonce:          rec.OwnerNonce,
			CreateToken:         rec.CreateToken,
			ETag:                rec.ETag,
			Generation:          rec.Generation,
			IntentAtUnix:        rec.IntentAtUnix,
			ConfirmedAtUnix:     rec.ConfirmedAtUnix,
			ServerCreatedAtUnix: rec.ServerCreatedAtUnix,
			State:               st,
			Retain:              rec.Retain,
			Reason:              rec.Reason,
			Seq:                 rec.Seq,
		}
		state.byKey[key] = len(state.Entries)
		state.Entries = append(state.Entries, entry)
		return nil

	case EventFailed:
		if !exists {
			return nil
		}
		cur := state.Entries[idx]
		// CRITICAL: Failed NEVER cancels an already-confirmed or retained entry!
		if cur.State == StateConfirmed || cur.State == StateRetained || cur.Retain {
			return nil
		}
		removeEntryAt(state, idx)
		return nil

	case EventRetained:
		if exists {
			cur := state.Entries[idx]
			cur.State = StateRetained
			cur.Retain = true
			if rec.Location != "" {
				cur.Location = rec.Location
			}
			if rec.ProviderID != "" {
				cur.ProviderID = rec.ProviderID
			}
			if rec.OwnerNonce != "" {
				cur.OwnerNonce = rec.OwnerNonce
			}
			if rec.CreateToken != "" {
				cur.CreateToken = rec.CreateToken
			}
			if rec.ETag != "" {
				cur.ETag = rec.ETag
			}
			if rec.Generation != "" {
				cur.Generation = rec.Generation
			}
			if rec.IntentAtUnix != 0 {
				cur.IntentAtUnix = rec.IntentAtUnix
			}
			if rec.ConfirmedAtUnix != 0 {
				cur.ConfirmedAtUnix = rec.ConfirmedAtUnix
			}
			if rec.ServerCreatedAtUnix != 0 {
				cur.ServerCreatedAtUnix = rec.ServerCreatedAtUnix
			}
			if rec.Reason != "" {
				cur.Reason = rec.Reason
			}
			cur.Seq = rec.Seq
			state.Entries[idx] = cur
			return nil
		}
		entry := LedgerEntry{
			Kind:                rec.Kind,
			Parent:              rec.Parent,
			Location:            rec.Location,
			Name:                rec.Name,
			ProviderID:          rec.ProviderID,
			OwnerNonce:          rec.OwnerNonce,
			CreateToken:         rec.CreateToken,
			ETag:                rec.ETag,
			Generation:          rec.Generation,
			IntentAtUnix:        rec.IntentAtUnix,
			ConfirmedAtUnix:     rec.ConfirmedAtUnix,
			ServerCreatedAtUnix: rec.ServerCreatedAtUnix,
			State:               StateRetained,
			Retain:              true,
			Reason:              rec.Reason,
			Seq:                 rec.Seq,
		}
		state.byKey[key] = len(state.Entries)
		state.Entries = append(state.Entries, entry)
		return nil

	case EventDeleted:
		if !exists {
			return nil
		}
		removeEntryAt(state, idx)
		return nil
	}
	return nil
}

func removeEntryAt(state *LedgerState, idx int) {
	removed := state.Entries[idx]
	delete(state.byKey, resourceKey(removed.Kind, removed.Parent, removed.Name))
	state.Entries = append(state.Entries[:idx], state.Entries[idx+1:]...)
	for i := idx; i < len(state.Entries); i++ {
		e := state.Entries[i]
		state.byKey[resourceKey(e.Kind, e.Parent, e.Name)] = i
	}
}

func syncDir(dir string) error {
	df, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %s for sync: %w", dir, err)
	}
	defer df.Close()
	if err := df.Sync(); err != nil {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return nil
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
