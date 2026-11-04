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
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// JournalVersion is the current append-only JSONL journal format version.
	JournalVersion = 1

	// MaxJournalFileBytes bounds on-disk journal reads (64 MiB).
	MaxJournalFileBytes = 64 << 20

	// Resource kinds tracked in the recovery journal.
	KindBucket           = "bucket"
	KindObject           = "object"
	KindQueue            = "queue"
	KindQueueMessage     = "queue_message"
	KindTable            = "table"
	KindTableItem        = "table_item"
	KindPolicyAttachment = "policy_attachment"
	KindFunction         = "function"
	KindFunctionVersion  = "function_version"
	KindFunctionAlias    = "function_alias"

	// Journal event types.
	EventMeta            = "meta"
	EventIntent          = "intent"
	EventConfirmed       = "confirmed"
	EventFailed          = "failed"
	EventRetained        = "retained"
	EventDeleted         = "deleted"
	EventCost            = "cost"
	EventReserve         = "reserve"
	EventSettle          = "settle"
	EventWorkCap         = "work_cap"
	EventCapExceeded     = "cap_exceeded"
	EventPolicyIntent    = "policy_intent"
	EventPolicyAttach    = "policy_attach"
	EventPolicyDetach    = "policy_detach"
	EventFunctionIntent       = "function_intent"
	EventFunctionConfirm      = "function_confirm"
	EventFunctionPreviewState = "function_preview_state"
	EventFunctionDelete       = "function_delete"

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
		return "", errors.New("invalid journal endpoint URL")
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("invalid journal endpoint URL: scheme and host are required")
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
			return errors.New("journal endpoint contains unredacted userinfo, query, or fragment")
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
	Version               int                     `json:"v"`
	Seq                   uint64                  `json:"seq"`
	Time                  string                  `json:"ts"`
	Event                 string                  `json:"event"`
	RunID                 string                  `json:"run_id"`
	SessionID             string                  `json:"session_id,omitempty"`
	PolicyHash            string                  `json:"policy_hash"`
	Provider              string                  `json:"provider"`
	Account               string                  `json:"account"`
	Tenant                string                  `json:"tenant,omitempty"`
	Scope                 string                  `json:"scope"`
	Region                string                  `json:"region"`
	Endpoint              string                  `json:"endpoint,omitempty"`
	StartedAtUnix         int64                   `json:"started_at_unix,omitempty"`
	Kind                  string                  `json:"kind,omitempty"`
	Parent                string                  `json:"parent,omitempty"`
	Location              string                  `json:"location,omitempty"`
	Name                  string                  `json:"name,omitempty"`
	ProviderID            string                  `json:"provider_id,omitempty"`
	OwnerNonce            string                  `json:"owner_nonce,omitempty"`
	CreateToken           string                  `json:"create_token,omitempty"`
	ETag                  string                  `json:"etag,omitempty"`
	Generation            string                  `json:"generation,omitempty"`
	IntentAtUnix          int64                   `json:"intent_at_unix,omitempty"`
	ConfirmedAtUnix       int64                   `json:"confirmed_at_unix,omitempty"`
	ServerCreatedAtUnix   int64                   `json:"server_created_at_unix,omitempty"`
	AttemptID             string                  `json:"attempt_id,omitempty"`
	ReservedNanoUSD       int64                   `json:"reserved_nano_usd,omitempty"`
	ChargedNanoUSD        int64                   `json:"charged_nano_usd,omitempty"`
	CleanupReserveNanoUSD int64                   `json:"cleanup_reserve_nano_usd,omitempty"`
	ReleaseCleanup        bool                    `json:"release_cleanup,omitempty"`
	ActiveCleanup         map[string]int64        `json:"active_cleanup,omitempty"`
	WorkCapNanoUSD        int64                   `json:"work_cap_nano_usd,omitempty"`
	PayloadBytes          int64                   `json:"payload_bytes,omitempty"`
	Operation             string                  `json:"operation,omitempty"`
	BillingUnits          int64                   `json:"billing_units,omitempty"`
	SettledBytes          int64                   `json:"settled_bytes,omitempty"`
	CapExceededCount      int64                   `json:"cap_exceeded_count,omitempty"`
	OpStats               map[string]OpLedgerStat `json:"op_stats,omitempty"`
	BucketsCreated        int                     `json:"buckets_created,omitempty"`
	QueuesCreated         int                     `json:"queues_created,omitempty"`
	ObjectsCreated        int                     `json:"objects_created,omitempty"`
	MessagesSent          int                     `json:"messages_sent,omitempty"`
	Reason                string                  `json:"reason,omitempty"`
	Retain                bool                    `json:"retain,omitempty"`
	PolicyScope           string                  `json:"policy_scope,omitempty"`
	PolicyKind            string                  `json:"policy_kind,omitempty"`
	PolicyTarget          string                  `json:"policy_target,omitempty"`
	PolicyPrincipal       string                  `json:"policy_principal,omitempty"`
	PolicyDocument        string                  `json:"policy_document,omitempty"`
	PolicyIntentOp        string                  `json:"policy_intent_op,omitempty"`
	ExpectedOwnerToken    string                  `json:"expected_owner_token,omitempty"`
	ExpectedGeneration    string                  `json:"expected_generation,omitempty"`
	FunctionState         string                  `json:"function_state,omitempty"`
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
	PayloadBytes        int64
	State               string // StatePending, StateConfirmed, StateRetained
	Retain              bool
	Reason              string
	Seq                 uint64
}

// AttemptLedgerEntry is an unresolved durable per-attempt cost/byte reservation.
type AttemptLedgerEntry struct {
	AttemptID       string
	Operation       string
	Kind            string
	Parent          string
	Name            string
	Reason          string
	ReservedNanoUSD int64
	PayloadBytes    int64
	Seq             uint64
}

// OpLedgerStat records cumulative per-operation cost and request counters in LedgerState.
type OpLedgerStat struct {
	Requests       int64 `json:"requests"`
	BillingUnits   int64 `json:"billing_units"`
	Bytes          int64 `json:"bytes"`
	ChargedNanoUSD int64 `json:"charged_nano_usd"`
}

// JournalPolicyAttachment is a durable replace-per-key policy attachment entry
// replayed from EventPolicyIntent / EventPolicyAttach / EventPolicyDetach records.
type JournalPolicyAttachment struct {
	Key        string `json:"key"`
	Scope      string `json:"scope,omitempty"`
	Kind       string `json:"kind"`
	Target     string `json:"target,omitempty"`
	Principal  string `json:"principal"`
	Document   string `json:"document"`
	OwnerToken string `json:"owner_token,omitempty"`
	Generation string `json:"generation,omitempty"`
	IntentID   string `json:"intent_id,omitempty"`
	Ambiguous  bool   `json:"ambiguous,omitempty"`
	IntentOp   string `json:"intent_op,omitempty"`
}

// JournalFunctionEntry is a durable function authority entry replayed from
// EventFunctionIntent / EventFunctionConfirm / EventFunctionDelete records.
type JournalFunctionEntry struct {
	Key        string `json:"key"`
	Scope      string `json:"scope,omitempty"`
	Name       string `json:"name"`
	Digest     string `json:"digest,omitempty"`
	OwnerToken string `json:"owner_token,omitempty"`
	Generation string `json:"generation,omitempty"`
	IntentID   string `json:"intent_id,omitempty"`
	Ambiguous  bool   `json:"ambiguous,omitempty"`
	IntentOp   string `json:"intent_op,omitempty"`
	StateJSON  string `json:"state_json,omitempty"`
}

func scopedFunctionKey(scope, name string) string {
	if scope == "" {
		return name
	}
	return scope + "\x00" + name
}

func scopedPolicyKey(scope, kind, target, principal string) string {
	if kind == "principal" {
		target = ""
	}
	if scope == "" {
		return kind + "\x00" + target + "\x00" + principal
	}
	return scope + "\x00" + kind + "\x00" + target + "\x00" + principal
}

func resourceKey(kind, parent, name string) string {
	return kind + "\x00" + parent + "\x00" + name
}

// LedgerState represents the validated, replayed state of a run journal.
type LedgerState struct {
	Meta                   JournalMeta
	StartedAtUnix          int64
	LastSeq                uint64
	Entries                []LedgerEntry
	PendingAttempts        []AttemptLedgerEntry
	ReservedNanoUSD        int64
	ChargedNanoUSD         int64
	WorkCapNanoUSD         int64
	CapExceededCount       int64
	OpStats                map[string]OpLedgerStat
	ActiveCleanup          map[string]int64
	PolicyAttachments      map[string]JournalPolicyAttachment
	AmbiguousPolicies      map[string]JournalPolicyAttachment
	AmbiguousStack         map[string][]JournalPolicyAttachment
	PolicyTombstones       map[string]JournalPolicyAttachment
	MaxPolicyGen           map[string]uint64
	LatestPolicyIntent     map[string]string
	ActiveFunctions        map[string]JournalFunctionEntry
	AmbiguousFunctions     map[string]JournalFunctionEntry
	AmbiguousFunctionStack map[string][]JournalFunctionEntry
	FunctionTombstones     map[string]JournalFunctionEntry
	MaxFunctionGen         map[string]uint64
	LatestFunctionIntent   map[string]string
	BucketsCreated         int
	QueuesCreated          int
	ObjectsCreated         int
	MessagesSent           int
	TotalPayloadBytes      int64

	byKey       map[string]int
	byAttemptID map[string]int
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

// LookupAttempt returns the unresolved AttemptLedgerEntry for attemptID, if active.
func (s *LedgerState) LookupAttempt(attemptID string) (AttemptLedgerEntry, bool) {
	if s == nil || s.byAttemptID == nil {
		return AttemptLedgerEntry{}, false
	}
	idx, ok := s.byAttemptID[attemptID]
	if !ok || idx < 0 || idx >= len(s.PendingAttempts) {
		return AttemptLedgerEntry{}, false
	}
	return s.PendingAttempts[idx], true
}

// CreateIntent holds the durably journaled tokens for a resource creation attempt.
type CreateIntent struct {
	Kind             string
	Parent           string
	Location         string
	Name             string
	OwnerNonce       string
	CreateToken      string
	AttemptID        string
	IntentAtUnix     int64
	AlreadyConfirmed bool
}

// ConfirmDetails carries the provider's post-create identifiers and timestamps.
type ConfirmDetails struct {
	ProviderID          string
	Location            string
	ETag                string
	Generation          string
	AttemptID           string
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

// CheckHealth verifies that the journal is open, writable, and not poisoned by
// an earlier write, short-write, or fsync error.
func (j *Journal) CheckHealth() error {
	if j == nil {
		return errors.New("journal is nil")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.f == nil {
		return errors.New("journal is closed")
	}
	if j.poisoned != nil {
		return j.poisoned
	}
	return nil
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

	raw, err := io.ReadAll(io.LimitReader(f, MaxJournalFileBytes+1))
	if err != nil {
		_ = j.Close()
		return nil, fmt.Errorf("read journal %s: %w", path, err)
	}
	if len(raw) > MaxJournalFileBytes {
		_ = j.Close()
		return nil, fmt.Errorf("journal %s exceeds maximum size of %d bytes", path, MaxJournalFileBytes)
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
			Meta:                   j.meta,
			StartedAtUnix:          startedUnix,
			OpStats:                make(map[string]OpLedgerStat),
			ActiveCleanup:          make(map[string]int64),
			PolicyAttachments:      make(map[string]JournalPolicyAttachment),
			AmbiguousPolicies:      make(map[string]JournalPolicyAttachment),
			AmbiguousStack:         make(map[string][]JournalPolicyAttachment),
			PolicyTombstones:       make(map[string]JournalPolicyAttachment),
			MaxPolicyGen:           make(map[string]uint64),
			LatestPolicyIntent:     make(map[string]string),
			ActiveFunctions:        make(map[string]JournalFunctionEntry),
			AmbiguousFunctions:     make(map[string]JournalFunctionEntry),
			AmbiguousFunctionStack: make(map[string][]JournalFunctionEntry),
			FunctionTombstones:     make(map[string]JournalFunctionEntry),
			MaxFunctionGen:         make(map[string]uint64),
			LatestFunctionIntent:   make(map[string]string),
			byKey:                  make(map[string]int),
			byAttemptID:            make(map[string]int),
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
	cp.PendingAttempts = append([]AttemptLedgerEntry(nil), j.state.PendingAttempts...)
	cp.OpStats = make(map[string]OpLedgerStat, len(j.state.OpStats))
	for k, v := range j.state.OpStats {
		cp.OpStats[k] = v
	}
	cp.ActiveCleanup = make(map[string]int64, len(j.state.ActiveCleanup))
	for k, v := range j.state.ActiveCleanup {
		cp.ActiveCleanup[k] = v
	}
	cp.PolicyAttachments = make(map[string]JournalPolicyAttachment, len(j.state.PolicyAttachments))
	for k, v := range j.state.PolicyAttachments {
		cp.PolicyAttachments[k] = v
	}
	cp.AmbiguousPolicies = make(map[string]JournalPolicyAttachment, len(j.state.AmbiguousPolicies))
	for k, v := range j.state.AmbiguousPolicies {
		cp.AmbiguousPolicies[k] = v
	}
	cp.AmbiguousStack = make(map[string][]JournalPolicyAttachment, len(j.state.AmbiguousStack))
	for k, v := range j.state.AmbiguousStack {
		cp.AmbiguousStack[k] = append([]JournalPolicyAttachment(nil), v...)
	}
	cp.PolicyTombstones = make(map[string]JournalPolicyAttachment, len(j.state.PolicyTombstones))
	for k, v := range j.state.PolicyTombstones {
		cp.PolicyTombstones[k] = v
	}
	cp.MaxPolicyGen = make(map[string]uint64, len(j.state.MaxPolicyGen))
	for k, v := range j.state.MaxPolicyGen {
		cp.MaxPolicyGen[k] = v
	}
	cp.LatestPolicyIntent = make(map[string]string, len(j.state.LatestPolicyIntent))
	for k, v := range j.state.LatestPolicyIntent {
		cp.LatestPolicyIntent[k] = v
	}
	cp.ActiveFunctions = make(map[string]JournalFunctionEntry, len(j.state.ActiveFunctions))
	for k, v := range j.state.ActiveFunctions {
		cp.ActiveFunctions[k] = v
	}
	cp.AmbiguousFunctions = make(map[string]JournalFunctionEntry, len(j.state.AmbiguousFunctions))
	for k, v := range j.state.AmbiguousFunctions {
		cp.AmbiguousFunctions[k] = v
	}
	cp.AmbiguousFunctionStack = make(map[string][]JournalFunctionEntry, len(j.state.AmbiguousFunctionStack))
	for k, v := range j.state.AmbiguousFunctionStack {
		cp.AmbiguousFunctionStack[k] = append([]JournalFunctionEntry(nil), v...)
	}
	cp.FunctionTombstones = make(map[string]JournalFunctionEntry, len(j.state.FunctionTombstones))
	for k, v := range j.state.FunctionTombstones {
		cp.FunctionTombstones[k] = v
	}
	cp.MaxFunctionGen = make(map[string]uint64, len(j.state.MaxFunctionGen))
	for k, v := range j.state.MaxFunctionGen {
		cp.MaxFunctionGen[k] = v
	}
	cp.LatestFunctionIntent = make(map[string]string, len(j.state.LatestFunctionIntent))
	for k, v := range j.state.LatestFunctionIntent {
		cp.LatestFunctionIntent[k] = v
	}
	cp.byKey = make(map[string]int, len(j.state.byKey))
	for k, v := range j.state.byKey {
		cp.byKey[k] = v
	}
	cp.byAttemptID = make(map[string]int, len(j.state.byAttemptID))
	for k, v := range j.state.byAttemptID {
		cp.byAttemptID[k] = v
	}
	return cp
}

// Lookup returns the current LedgerEntry for (kind, parent, name), if active.
func (j *Journal) Lookup(kind, parent, name string) (LedgerEntry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state.Lookup(kind, parent, name)
}

// LookupAttempt returns the unresolved AttemptLedgerEntry for attemptID, if active.
func (j *Journal) LookupAttempt(attemptID string) (AttemptLedgerEntry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state.LookupAttempt(attemptID)
}

// BeginAttempt durably appends an `EventReserve` record for a single operation
// attempt BEFORE provider dispatch, reserving its worst-case cost and payload
// bytes (and incrementing MessagesSent if reason == "queue_send").
func (j *Journal) BeginAttempt(kind, parent, name, reason string, reservedNanoUSD, payloadBytes int64) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return "", j.poisoned
	}
	attemptID := NewToken128()
	rec := JournalRecord{
		Event:           EventReserve,
		Kind:            kind,
		Parent:          parent,
		Name:            name,
		AttemptID:       attemptID,
		ReservedNanoUSD: reservedNanoUSD,
		PayloadBytes:    payloadBytes,
		Reason:          reason,
	}
	if err := j.appendLocked(rec); err != nil {
		return "", err
	}
	return attemptID, nil
}

// SettleAttempt durably settles an unresolved attempt by attemptID, clearing
// its pending reservation and recording actual chargedNanoUSD. If refundBytes
// is true, any payloadBytes reserved by this attempt are refunded from
// TotalPayloadBytes. Settling an already-settled or unknown attemptID is an
// idempotent no-op.
func (j *Journal) SettleAttempt(attemptID string, chargedNanoUSD int64, refundBytes bool) error {
	units := int64(0)
	if chargedNanoUSD > 0 {
		units = 1
	}
	return j.SettleAttemptWithDetails(attemptID, chargedNanoUSD, 0, units, refundBytes)
}

// SettleAttemptWithDetails durably settles an unresolved attempt by attemptID,
// recording actual chargedNanoUSD, settledBytes, and billingUnits.
func (j *Journal) SettleAttemptWithDetails(attemptID string, chargedNanoUSD, settledBytes, billingUnits int64, refundBytes bool) error {
	return j.SettleAttemptWithCleanup(attemptID, chargedNanoUSD, settledBytes, billingUnits, 0, false, refundBytes)
}

// SettleAttemptWithCleanup durably settles an unresolved attempt by attemptID,
// recording actual chargedNanoUSD, settledBytes, billingUnits, and any
// resource-level cleanup reserve lock or release.
func (j *Journal) SettleAttemptWithCleanup(attemptID string, chargedNanoUSD, settledBytes, billingUnits, cleanupReserveNanoUSD int64, releaseCleanup, refundBytes bool) error {
	if strings.TrimSpace(attemptID) == "" {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	att, ok := j.state.LookupAttempt(attemptID)
	if !ok {
		return nil
	}
	var refund int64
	if refundBytes && att.PayloadBytes > 0 {
		refund = att.PayloadBytes
	}
	return j.appendLocked(JournalRecord{
		Event:                 EventSettle,
		Operation:             att.Operation,
		Kind:                  att.Kind,
		Parent:                att.Parent,
		Name:                  att.Name,
		AttemptID:             attemptID,
		ChargedNanoUSD:        chargedNanoUSD,
		CleanupReserveNanoUSD: cleanupReserveNanoUSD,
		ReleaseCleanup:        releaseCleanup,
		PayloadBytes:          refund,
		SettledBytes:          settledBytes,
		BillingUnits:          billingUnits,
		Reason:                att.Reason,
	})
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
//     CreateToken so the provider can deduplicate the retry, while allocating
//     a fresh accounting AttemptID and independent reservation for the new
//     physical dispatch.
//   - Otherwise, BeginCreate generates fresh 128-bit OwnerNonce, CreateToken,
//     and AttemptID values, appends an `intent` record, and fsyncs the journal
//     before returning.
func (j *Journal) BeginCreate(kind, parent, location, name string, reservedNanoUSD int64) (CreateIntent, error) {
	return j.BeginCreateWithBytes(kind, parent, location, name, reservedNanoUSD, 0)
}

// BeginCreateWithBytes is like BeginCreate and also records payloadBytes on the
// durable intent record before provider dispatch.
func (j *Journal) BeginCreateWithBytes(kind, parent, location, name string, reservedNanoUSD, payloadBytes int64) (CreateIntent, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return CreateIntent{}, j.poisoned
	}

	if existing, ok := j.state.Lookup(kind, parent, name); ok {
		if existing.State == StateConfirmed {
			var attemptID string
			if reservedNanoUSD > 0 || payloadBytes > 0 {
				attemptID = NewToken128()
				if err := j.appendLocked(JournalRecord{
					Event:           EventReserve,
					Kind:            kind,
					Parent:          parent,
					Location:        location,
					Name:            name,
					AttemptID:       attemptID,
					ReservedNanoUSD: reservedNanoUSD,
					PayloadBytes:    payloadBytes,
					Reason:          kind + "_overwrite",
				}); err != nil {
					return CreateIntent{}, err
				}
			}
			return CreateIntent{
				Kind:             existing.Kind,
				Parent:           existing.Parent,
				Location:         existing.Location,
				Name:             existing.Name,
				OwnerNonce:       existing.OwnerNonce,
				CreateToken:      existing.CreateToken,
				AttemptID:        attemptID,
				IntentAtUnix:     existing.IntentAtUnix,
				AlreadyConfirmed: true,
			}, nil
		}
		if existing.State == StateRetained || existing.Retain {
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
			nowUnix := j.nowTime().UTC().Unix()
			attemptID := NewToken128()
			intent := CreateIntent{
				Kind:         existing.Kind,
				Parent:       existing.Parent,
				Location:     existing.Location,
				Name:         existing.Name,
				OwnerNonce:   existing.OwnerNonce,
				CreateToken:  existing.CreateToken,
				AttemptID:    attemptID,
				IntentAtUnix: nowUnix,
			}
			rec := JournalRecord{
				Event:           EventIntent,
				Kind:            intent.Kind,
				Parent:          intent.Parent,
				Location:        intent.Location,
				Name:            intent.Name,
				OwnerNonce:      intent.OwnerNonce,
				CreateToken:     intent.CreateToken,
				AttemptID:       intent.AttemptID,
				IntentAtUnix:    intent.IntentAtUnix,
				ReservedNanoUSD: reservedNanoUSD,
				PayloadBytes:    payloadBytes,
			}
			if err := j.appendLocked(rec); err != nil {
				return CreateIntent{}, err
			}
			return intent, nil
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
		AttemptID:    NewToken128(),
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
		AttemptID:       intent.AttemptID,
		IntentAtUnix:    intent.IntentAtUnix,
		ReservedNanoUSD: reservedNanoUSD,
		PayloadBytes:    payloadBytes,
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
	attID := details.AttemptID
	if attID == "" {
		attID = latestAttemptIDFor(j.state, kind, parent, name)
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
		AttemptID:           attID,
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
	attID := latestAttemptIDFor(j.state, kind, parent, name)
	if existing.State == StateConfirmed || existing.State == StateRetained || existing.Retain {
		if chargedNanoUSD > 0 || attID != "" {
			return j.appendLocked(JournalRecord{
				Event:          EventCost,
				Kind:           kind,
				Parent:         parent,
				Name:           name,
				AttemptID:      attID,
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
		AttemptID:      attID,
		Reason:         reason,
		ChargedNanoUSD: chargedNanoUSD,
	})
}

// Retain marks a resource as retained (either by policy or because cleanup/probe
// encountered an ambiguous or mismatched state that forbids blind deletion).
func (j *Journal) Retain(kind, parent, name, reason string) error {
	return j.RetainWithCost(kind, parent, name, reason, 0)
}

// RetainWithCost marks a resource as retained and settles any pending create
// reservation with chargedNanoUSD.
func (j *Journal) RetainWithCost(kind, parent, name, reason string, chargedNanoUSD int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	existing, ok := j.state.Lookup(kind, parent, name)
	var attID string
	if chargedNanoUSD > 0 {
		attID = latestAttemptIDFor(j.state, kind, parent, name)
	}
	rec := JournalRecord{
		Event:          EventRetained,
		Kind:           kind,
		Parent:         parent,
		Name:           name,
		AttemptID:      attID,
		Reason:         reason,
		Retain:         true,
		ChargedNanoUSD: chargedNanoUSD,
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

// RecordWorkCap durably records a narrowed script work sub-cap (in nano-USD)
// in the campaign journal so subsequent invocations inherit the narrowed cap.
func (j *Journal) RecordWorkCap(workCapNanoUSD int64) error {
	if workCapNanoUSD <= 0 {
		return fmt.Errorf("work_cap_nano_usd must be > 0, got %d", workCapNanoUSD)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	if j.state.WorkCapNanoUSD > 0 && workCapNanoUSD > j.state.WorkCapNanoUSD {
		return fmt.Errorf("work_cap_nano_usd must be monotone non-increasing (got %d > %d)", workCapNanoUSD, j.state.WorkCapNanoUSD)
	}
	return j.appendLocked(JournalRecord{
		Event:          EventWorkCap,
		WorkCapNanoUSD: workCapNanoUSD,
	})
}

// RecordCapExceeded durably records a pre-attempt cost-cap refusal in the journal.
func (j *Journal) RecordCapExceeded(operation string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	return j.appendLocked(JournalRecord{
		Event:            EventCapExceeded,
		Operation:        operation,
		CapExceededCount: 1,
	})
}

// RecordPolicyIntent durably appends an EventPolicyIntent record (with ownerToken,
// generation, intentID, and reserved cleanup headroom) BEFORE dispatching a policy
// attach or detach operation.
func (j *Journal) RecordPolicyIntent(scope, kind, target, principal, intentOp, document, ownerToken, generation, intentID, expOwner, expGen string, cleanupReserveNanoUSD int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	return j.appendLocked(JournalRecord{
		Event:                 EventPolicyIntent,
		Kind:                  KindPolicyAttachment,
		PolicyScope:           scope,
		PolicyKind:            kind,
		PolicyTarget:          target,
		PolicyPrincipal:       principal,
		PolicyIntentOp:        intentOp,
		PolicyDocument:        document,
		CreateToken:           ownerToken,
		Generation:            generation,
		AttemptID:             intentID,
		ExpectedOwnerToken:    expOwner,
		ExpectedGeneration:    expGen,
		CleanupReserveNanoUSD: cleanupReserveNanoUSD,
	})
}

// RecordPolicyAttach durably appends an EventPolicyAttach record (replace-per-key)
// with the full canonical policy document before returning.
func (j *Journal) RecordPolicyAttach(kind, target, principal, document, ownerToken, generation string) error {
	return j.RecordPolicyAttachScoped("", kind, target, principal, document, ownerToken, generation, "", 0)
}

// RecordPolicyAttachScoped durably appends a scoped EventPolicyAttach record confirming an attachment.
func (j *Journal) RecordPolicyAttachScoped(scope, kind, target, principal, document, ownerToken, generation, intentID string, cleanupReserveNanoUSD int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	return j.appendLocked(JournalRecord{
		Event:                 EventPolicyAttach,
		Kind:                  KindPolicyAttachment,
		PolicyScope:           scope,
		PolicyKind:            kind,
		PolicyTarget:          target,
		PolicyPrincipal:       principal,
		PolicyDocument:        document,
		CreateToken:           ownerToken,
		Generation:            generation,
		AttemptID:             intentID,
		CleanupReserveNanoUSD: cleanupReserveNanoUSD,
	})
}

// RecordPolicyDetach durably appends an EventPolicyDetach record removing the
// attachment key's contribution.
func (j *Journal) RecordPolicyDetach(kind, target, principal string) error {
	return j.RecordPolicyDetachScoped("", kind, target, principal, "", "", "")
}

// RecordPolicyDetachScoped durably appends a scoped EventPolicyDetach record confirming removal.
func (j *Journal) RecordPolicyDetachScoped(scope, kind, target, principal, ownerToken, generation, intentID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	return j.appendLocked(JournalRecord{
		Event:           EventPolicyDetach,
		Kind:            KindPolicyAttachment,
		PolicyScope:     scope,
		PolicyKind:      kind,
		PolicyTarget:    target,
		PolicyPrincipal: principal,
		CreateToken:     ownerToken,
		Generation:      generation,
		AttemptID:       intentID,
	})
}

// RecordFunctionIntent durably appends an EventFunctionIntent record (with ownerToken,
// generation, intentID, and optional cleanup reserve) BEFORE dispatching a function
// create, update, or delete operation.
func (j *Journal) RecordFunctionIntent(scope, name, intentOp, digest, ownerToken, generation, intentID, expOwner, expGen string, cleanupReserveNanoUSD int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	return j.appendLocked(JournalRecord{
		Event:                 EventFunctionIntent,
		Kind:                  KindFunction,
		PolicyScope:           scope,
		Name:                  name,
		PolicyIntentOp:        intentOp,
		ETag:                  digest,
		CreateToken:           ownerToken,
		Generation:            generation,
		AttemptID:             intentID,
		ExpectedOwnerToken:    expOwner,
		ExpectedGeneration:    expGen,
		CleanupReserveNanoUSD: cleanupReserveNanoUSD,
	})
}

// RecordFunctionConfirm durably appends an EventFunctionConfirm record confirming a function create or update.
func (j *Journal) RecordFunctionConfirm(scope, name, digest, ownerToken, generation, intentID string, cleanupReserveNanoUSD int64) error {
	return j.RecordFunctionConfirmWithState(scope, name, digest, ownerToken, generation, intentID, "", cleanupReserveNanoUSD)
}

// RecordFunctionConfirmWithState durably appends an EventFunctionConfirm record with optional serialized dry-preview state.
func (j *Journal) RecordFunctionConfirmWithState(scope, name, digest, ownerToken, generation, intentID, stateJSON string, cleanupReserveNanoUSD int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	return j.appendLocked(JournalRecord{
		Event:                 EventFunctionConfirm,
		Kind:                  KindFunction,
		PolicyScope:           scope,
		Name:                  name,
		ETag:                  digest,
		CreateToken:           ownerToken,
		Generation:            generation,
		AttemptID:             intentID,
		FunctionState:         stateJSON,
		CleanupReserveNanoUSD: cleanupReserveNanoUSD,
	})
}

// RecordFunctionPreviewState durably appends a non-authoritative EventFunctionPreviewState record
// updating the cached dry-invocation preview descriptor for a function only when the active
// committed entry still matches (expOwnerToken, expDigest, expGeneration) and has no pending ambiguity.
func (j *Journal) RecordFunctionPreviewState(scope, name, expOwnerToken, expDigest, expGeneration, stateJSON string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	return j.appendLocked(JournalRecord{
		Event:         EventFunctionPreviewState,
		Kind:          KindFunction,
		PolicyScope:   scope,
		Name:          name,
		ETag:          expDigest,
		CreateToken:   expOwnerToken,
		Generation:    expGeneration,
		FunctionState: stateJSON,
	})
}

// RecordFunctionDelete durably appends an EventFunctionDelete record confirming function removal.
func (j *Journal) RecordFunctionDelete(scope, name, ownerToken, generation, intentID string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.poisoned != nil {
		return j.poisoned
	}
	return j.appendLocked(JournalRecord{
		Event:       EventFunctionDelete,
		Kind:        KindFunction,
		PolicyScope: scope,
		Name:        name,
		CreateToken: ownerToken,
		Generation:  generation,
		AttemptID:   intentID,
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
		if (e.State == StateConfirmed || e.State == StatePending) && !e.Retain {
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

	var BasePayloadBytes int64
	BasePayloadBytes = j.state.TotalPayloadBytes
	for _, a := range j.state.PendingAttempts {
		if a.PayloadBytes > 0 {
			BasePayloadBytes -= a.PayloadBytes
		}
	}
	if BasePayloadBytes < 0 {
		BasePayloadBytes = 0
	}

	baseOpStats := make(map[string]OpLedgerStat, len(j.state.OpStats))
	for k, v := range j.state.OpStats {
		baseOpStats[k] = v
	}
	baseActiveCleanup := make(map[string]int64, len(j.state.ActiveCleanup))
	for k, v := range j.state.ActiveCleanup {
		if v > 0 {
			baseActiveCleanup[k] = v
		}
	}

	compacted = append(compacted, JournalRecord{
		Version:          JournalVersion,
		Seq:              seq,
		Time:             nowStr,
		Event:            EventMeta,
		RunID:            j.meta.RunID,
		SessionID:        j.meta.SessionID,
		PolicyHash:       j.meta.PolicyHash,
		Provider:         j.meta.Provider,
		Account:          j.meta.Account,
		Tenant:           j.meta.Tenant,
		Scope:            j.meta.Scope,
		Region:           j.meta.Region,
		Endpoint:         j.meta.Endpoint,
		StartedAtUnix:    j.state.StartedAtUnix,
		ChargedNanoUSD:   j.state.ChargedNanoUSD,
		WorkCapNanoUSD:   j.state.WorkCapNanoUSD,
		CapExceededCount: j.state.CapExceededCount,
		OpStats:          baseOpStats,
		ActiveCleanup:    baseActiveCleanup,
		PayloadBytes:     BasePayloadBytes,
		BucketsCreated:   baseBuckets,
		QueuesCreated:    baseQueues,
		ObjectsCreated:   baseObjects,
		MessagesSent:     j.state.MessagesSent,
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

	for _, a := range j.state.PendingAttempts {
		seq++
		reason := a.Reason
		if reason == "queue_send" {
			// MessagesSent is already included in EventMeta.MessagesSent above.
			reason = "queue_send_compacted"
		}
		compacted = append(compacted, JournalRecord{
			Version:         JournalVersion,
			Seq:             seq,
			Time:            nowStr,
			Event:           EventReserve,
			RunID:           j.meta.RunID,
			SessionID:       j.meta.SessionID,
			PolicyHash:      j.meta.PolicyHash,
			Provider:        j.meta.Provider,
			Account:         j.meta.Account,
			Tenant:          j.meta.Tenant,
			Scope:           j.meta.Scope,
			Region:          j.meta.Region,
			Endpoint:        j.meta.Endpoint,
			Kind:            a.Kind,
			Parent:          a.Parent,
			Name:            a.Name,
			AttemptID:       a.AttemptID,
			ReservedNanoUSD: a.ReservedNanoUSD,
			PayloadBytes:    a.PayloadBytes,
			Reason:          reason,
		})
	}

	if len(j.state.PolicyAttachments) > 0 {
		attKeys := make([]string, 0, len(j.state.PolicyAttachments))
		for k := range j.state.PolicyAttachments {
			attKeys = append(attKeys, k)
		}
		sort.Strings(attKeys)
		for _, k := range attKeys {
			pa := j.state.PolicyAttachments[k]
			seq++
			compacted = append(compacted, JournalRecord{
				Version:         JournalVersion,
				Seq:             seq,
				Time:            nowStr,
				Event:           EventPolicyAttach,
				RunID:           j.meta.RunID,
				SessionID:       j.meta.SessionID,
				PolicyHash:      j.meta.PolicyHash,
				Provider:        j.meta.Provider,
				Account:         j.meta.Account,
				Tenant:          j.meta.Tenant,
				Scope:           j.meta.Scope,
				Region:          j.meta.Region,
				Endpoint:        j.meta.Endpoint,
				Kind:            KindPolicyAttachment,
				PolicyScope:     pa.Scope,
				PolicyKind:      pa.Kind,
				PolicyTarget:    pa.Target,
				PolicyPrincipal: pa.Principal,
				PolicyDocument:  pa.Document,
				CreateToken:     pa.OwnerToken,
				Generation:      pa.Generation,
				AttemptID:       pa.IntentID,
			})
		}
	}
	if len(j.state.AmbiguousStack) > 0 {
		ambKeys := make([]string, 0, len(j.state.AmbiguousStack))
		for k, stack := range j.state.AmbiguousStack {
			if len(stack) > 0 {
				ambKeys = append(ambKeys, k)
			}
		}
		sort.Strings(ambKeys)
		for _, k := range ambKeys {
			for _, pa := range j.state.AmbiguousStack[k] {
				seq++
				intentID := pa.IntentID
				if intentID == "" {
					intentID = pa.OwnerToken
				}
				compacted = append(compacted, JournalRecord{
					Version:         JournalVersion,
					Seq:             seq,
					Time:            nowStr,
					Event:           EventPolicyIntent,
					RunID:           j.meta.RunID,
					SessionID:       j.meta.SessionID,
					PolicyHash:      j.meta.PolicyHash,
					Provider:        j.meta.Provider,
					Account:         j.meta.Account,
					Tenant:          j.meta.Tenant,
					Scope:           j.meta.Scope,
					Region:          j.meta.Region,
					Endpoint:        j.meta.Endpoint,
					Kind:            KindPolicyAttachment,
					PolicyScope:     pa.Scope,
					PolicyKind:      pa.Kind,
					PolicyTarget:    pa.Target,
					PolicyPrincipal: pa.Principal,
					PolicyIntentOp:  pa.IntentOp,
					PolicyDocument:  pa.Document,
					CreateToken:     pa.OwnerToken,
					Generation:      pa.Generation,
					AttemptID:       intentID,
				})
			}
		}
	}
	if len(j.state.PolicyTombstones) > 0 {
		tbKeys := make([]string, 0, len(j.state.PolicyTombstones))
		for k := range j.state.PolicyTombstones {
			tbKeys = append(tbKeys, k)
		}
		sort.Strings(tbKeys)
		for _, k := range tbKeys {
			tb := j.state.PolicyTombstones[k]
			maxGen := j.state.MaxPolicyGen[k]
			if maxGen == 0 {
				continue
			}
			latestIntent := j.state.LatestPolicyIntent[k]
			if latestIntent == "" {
				latestIntent = tb.IntentID
			}
			_, inActive := j.state.PolicyAttachments[k]
			_, inAmb := j.state.AmbiguousPolicies[k]
			if !inActive && !inAmb {
				seq++
				compacted = append(compacted, JournalRecord{
					Version:         JournalVersion,
					Seq:             seq,
					Time:            nowStr,
					Event:           EventPolicyDetach,
					RunID:           j.meta.RunID,
					SessionID:       j.meta.SessionID,
					PolicyHash:      j.meta.PolicyHash,
					Provider:        j.meta.Provider,
					Account:         j.meta.Account,
					Tenant:          j.meta.Tenant,
					Scope:           j.meta.Scope,
					Region:          j.meta.Region,
					Endpoint:        j.meta.Endpoint,
					Kind:            KindPolicyAttachment,
					PolicyScope:     tb.Scope,
					PolicyKind:      tb.Kind,
					PolicyTarget:    tb.Target,
					PolicyPrincipal: tb.Principal,
					CreateToken:     tb.OwnerToken,
					Generation:      strconv.FormatUint(maxGen, 10),
					AttemptID:       latestIntent,
				})
				continue
			}
			var emittedGen uint64
			if pa, ok := j.state.PolicyAttachments[k]; ok {
				if g, err := strconv.ParseUint(pa.Generation, 10, 64); err == nil && g > emittedGen {
					emittedGen = g
				}
			}
			if pa, ok := j.state.AmbiguousPolicies[k]; ok {
				if g, err := strconv.ParseUint(pa.Generation, 10, 64); err == nil && g > emittedGen {
					emittedGen = g
				}
			}
			if maxGen > emittedGen && tb.OwnerToken != "" && latestIntent != "" {
				genStr := strconv.FormatUint(maxGen, 10)
				seq++
				compacted = append(compacted, JournalRecord{
					Version:         JournalVersion,
					Seq:             seq,
					Time:            nowStr,
					Event:           EventPolicyIntent,
					RunID:           j.meta.RunID,
					SessionID:       j.meta.SessionID,
					PolicyHash:      j.meta.PolicyHash,
					Provider:        j.meta.Provider,
					Account:         j.meta.Account,
					Tenant:          j.meta.Tenant,
					Scope:           j.meta.Scope,
					Region:          j.meta.Region,
					Endpoint:        j.meta.Endpoint,
					Kind:            KindPolicyAttachment,
					PolicyScope:     tb.Scope,
					PolicyKind:      tb.Kind,
					PolicyTarget:    tb.Target,
					PolicyPrincipal: tb.Principal,
					PolicyIntentOp:  "detach",
					CreateToken:     tb.OwnerToken,
					Generation:      genStr,
					AttemptID:       latestIntent,
				})
				seq++
				compacted = append(compacted, JournalRecord{
					Version:         JournalVersion,
					Seq:             seq,
					Time:            nowStr,
					Event:           EventPolicyIntent,
					RunID:           j.meta.RunID,
					SessionID:       j.meta.SessionID,
					PolicyHash:      j.meta.PolicyHash,
					Provider:        j.meta.Provider,
					Account:         j.meta.Account,
					Tenant:          j.meta.Tenant,
					Scope:           j.meta.Scope,
					Region:          j.meta.Region,
					Endpoint:        j.meta.Endpoint,
					Kind:            KindPolicyAttachment,
					PolicyScope:     tb.Scope,
					PolicyKind:      tb.Kind,
					PolicyTarget:    tb.Target,
					PolicyPrincipal: tb.Principal,
					PolicyIntentOp:  "abort",
					CreateToken:     tb.OwnerToken,
					Generation:      genStr,
					AttemptID:       latestIntent,
				})
			}
		}
	}

	if len(j.state.ActiveFunctions) > 0 {
		fnKeys := make([]string, 0, len(j.state.ActiveFunctions))
		for k := range j.state.ActiveFunctions {
			fnKeys = append(fnKeys, k)
		}
		sort.Strings(fnKeys)
		for _, k := range fnKeys {
			fe := j.state.ActiveFunctions[k]
			seq++
			compacted = append(compacted, JournalRecord{
				Version:     JournalVersion,
				Seq:         seq,
				Time:        nowStr,
				Event:       EventFunctionConfirm,
				RunID:       j.meta.RunID,
				SessionID:   j.meta.SessionID,
				PolicyHash:  j.meta.PolicyHash,
				Provider:    j.meta.Provider,
				Account:     j.meta.Account,
				Tenant:      j.meta.Tenant,
				Scope:       j.meta.Scope,
				Region:      j.meta.Region,
				Endpoint:    j.meta.Endpoint,
				Kind:          KindFunction,
				PolicyScope:   fe.Scope,
				Name:          fe.Name,
				ETag:          fe.Digest,
				CreateToken:   fe.OwnerToken,
				Generation:    fe.Generation,
				AttemptID:     fe.IntentID,
				FunctionState: fe.StateJSON,
			})
		}
	}
	if len(j.state.AmbiguousFunctionStack) > 0 {
		ambKeys := make([]string, 0, len(j.state.AmbiguousFunctionStack))
		for k, stack := range j.state.AmbiguousFunctionStack {
			if len(stack) > 0 {
				ambKeys = append(ambKeys, k)
			}
		}
		sort.Strings(ambKeys)
		for _, k := range ambKeys {
			for _, fe := range j.state.AmbiguousFunctionStack[k] {
				seq++
				intentID := fe.IntentID
				if intentID == "" {
					intentID = fe.OwnerToken
				}
				compacted = append(compacted, JournalRecord{
					Version:        JournalVersion,
					Seq:            seq,
					Time:           nowStr,
					Event:          EventFunctionIntent,
					RunID:          j.meta.RunID,
					SessionID:      j.meta.SessionID,
					PolicyHash:     j.meta.PolicyHash,
					Provider:       j.meta.Provider,
					Account:        j.meta.Account,
					Tenant:         j.meta.Tenant,
					Scope:          j.meta.Scope,
					Region:         j.meta.Region,
					Endpoint:       j.meta.Endpoint,
					Kind:           KindFunction,
					PolicyScope:    fe.Scope,
					Name:           fe.Name,
					PolicyIntentOp: fe.IntentOp,
					ETag:           fe.Digest,
					CreateToken:    fe.OwnerToken,
					Generation:     fe.Generation,
					AttemptID:      intentID,
				})
			}
		}
	}
	if len(j.state.FunctionTombstones) > 0 {
		tbKeys := make([]string, 0, len(j.state.FunctionTombstones))
		for k := range j.state.FunctionTombstones {
			tbKeys = append(tbKeys, k)
		}
		sort.Strings(tbKeys)
		for _, k := range tbKeys {
			tb := j.state.FunctionTombstones[k]
			maxGen := j.state.MaxFunctionGen[k]
			if maxGen == 0 {
				continue
			}
			latestIntent := j.state.LatestFunctionIntent[k]
			if latestIntent == "" {
				latestIntent = tb.IntentID
			}
			_, inActive := j.state.ActiveFunctions[k]
			_, inAmb := j.state.AmbiguousFunctions[k]
			if !inActive && !inAmb {
				seq++
				compacted = append(compacted, JournalRecord{
					Version:     JournalVersion,
					Seq:         seq,
					Time:        nowStr,
					Event:       EventFunctionDelete,
					RunID:       j.meta.RunID,
					SessionID:   j.meta.SessionID,
					PolicyHash:  j.meta.PolicyHash,
					Provider:    j.meta.Provider,
					Account:     j.meta.Account,
					Tenant:      j.meta.Tenant,
					Scope:       j.meta.Scope,
					Region:      j.meta.Region,
					Endpoint:    j.meta.Endpoint,
					Kind:        KindFunction,
					PolicyScope: tb.Scope,
					Name:        tb.Name,
					CreateToken: tb.OwnerToken,
					Generation:  strconv.FormatUint(maxGen, 10),
					AttemptID:   latestIntent,
				})
				continue
			}
			var emittedGen uint64
			if fe, ok := j.state.ActiveFunctions[k]; ok {
				if g, err := strconv.ParseUint(fe.Generation, 10, 64); err == nil && g > emittedGen {
					emittedGen = g
				}
			}
			if fe, ok := j.state.AmbiguousFunctions[k]; ok {
				if g, err := strconv.ParseUint(fe.Generation, 10, 64); err == nil && g > emittedGen {
					emittedGen = g
				}
			}
			if maxGen > emittedGen && tb.OwnerToken != "" && latestIntent != "" {
				genStr := strconv.FormatUint(maxGen, 10)
				seq++
				compacted = append(compacted, JournalRecord{
					Version:        JournalVersion,
					Seq:            seq,
					Time:           nowStr,
					Event:          EventFunctionIntent,
					RunID:          j.meta.RunID,
					SessionID:      j.meta.SessionID,
					PolicyHash:     j.meta.PolicyHash,
					Provider:       j.meta.Provider,
					Account:        j.meta.Account,
					Tenant:         j.meta.Tenant,
					Scope:          j.meta.Scope,
					Region:         j.meta.Region,
					Endpoint:       j.meta.Endpoint,
					Kind:           KindFunction,
					PolicyScope:    tb.Scope,
					Name:           tb.Name,
					PolicyIntentOp: "delete",
					CreateToken:    tb.OwnerToken,
					Generation:     genStr,
					AttemptID:      latestIntent,
				})
				seq++
				compacted = append(compacted, JournalRecord{
					Version:        JournalVersion,
					Seq:            seq,
					Time:           nowStr,
					Event:          EventFunctionIntent,
					RunID:          j.meta.RunID,
					SessionID:      j.meta.SessionID,
					PolicyHash:     j.meta.PolicyHash,
					Provider:       j.meta.Provider,
					Account:        j.meta.Account,
					Tenant:         j.meta.Tenant,
					Scope:          j.meta.Scope,
					Region:         j.meta.Region,
					Endpoint:       j.meta.Endpoint,
					Kind:           KindFunction,
					PolicyScope:    tb.Scope,
					Name:           tb.Name,
					PolicyIntentOp: "abort",
					CreateToken:    tb.OwnerToken,
					Generation:     genStr,
					AttemptID:      latestIntent,
				})
			}
		}
	}

	newState, err := ReplayJournal(compacted)
	if err != nil {
		return fmt.Errorf("validate compacted journal: %w", err)
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
	if info.Size() > MaxJournalFileBytes {
		return nil, fmt.Errorf("journal %s size %d exceeds maximum size of %d bytes", path, info.Size(), MaxJournalFileBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read journal %s: %w", path, err)
	}
	if len(raw) > MaxJournalFileBytes {
		return nil, fmt.Errorf("journal %s size %d exceeds maximum size of %d bytes", path, len(raw), MaxJournalFileBytes)
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
		Meta:                   meta,
		StartedAtUnix:          meta.StartedAtUnix,
		OpStats:                make(map[string]OpLedgerStat),
		ActiveCleanup:          make(map[string]int64),
		PolicyAttachments:      make(map[string]JournalPolicyAttachment),
		AmbiguousPolicies:      make(map[string]JournalPolicyAttachment),
		AmbiguousStack:         make(map[string][]JournalPolicyAttachment),
		PolicyTombstones:       make(map[string]JournalPolicyAttachment),
		MaxPolicyGen:           make(map[string]uint64),
		LatestPolicyIntent:     make(map[string]string),
		ActiveFunctions:        make(map[string]JournalFunctionEntry),
		AmbiguousFunctions:     make(map[string]JournalFunctionEntry),
		AmbiguousFunctionStack: make(map[string][]JournalFunctionEntry),
		FunctionTombstones:     make(map[string]JournalFunctionEntry),
		MaxFunctionGen:         make(map[string]uint64),
		LatestFunctionIntent:   make(map[string]string),
		byKey:                  make(map[string]int),
		byAttemptID:            make(map[string]int),
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
			return errors.New("record endpoint contains unredacted userinfo, query, or fragment")
		}
	}
	if rec.ReservedNanoUSD < 0 || rec.ChargedNanoUSD < 0 || rec.CleanupReserveNanoUSD < 0 || rec.WorkCapNanoUSD < 0 || rec.PayloadBytes < 0 ||
		rec.BillingUnits < 0 || rec.SettledBytes < 0 || rec.CapExceededCount < 0 ||
		rec.BucketsCreated < 0 || rec.QueuesCreated < 0 || rec.ObjectsCreated < 0 || rec.MessagesSent < 0 {
		return errors.New("negative cost or counter amount in journal record")
	}

	switch rec.Event {
	case EventMeta:
		if wantSeq != 1 {
			return errors.New("duplicate meta record after seq 1")
		}
		return nil
	case EventCost, EventCapExceeded:
		return nil
	case EventWorkCap:
		if rec.WorkCapNanoUSD <= 0 {
			return errors.New("work_cap record requires work_cap_nano_usd > 0")
		}
		return nil
	case EventReserve, EventSettle:
		if err := ValidateToken128(rec.AttemptID); err != nil {
			return fmt.Errorf("attempt_id: %w", err)
		}
		if hasControlChars(rec.Parent) || hasControlChars(rec.Name) || hasControlChars(rec.Reason) {
			return errors.New("attempt record contains control characters")
		}
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
	case EventPolicyIntent:
		if rec.Kind != KindPolicyAttachment {
			return fmt.Errorf("policy_intent record must have kind %q (got %q)", KindPolicyAttachment, rec.Kind)
		}
		if hasControlChars(rec.PolicyScope) {
			return fmt.Errorf("invalid policy_scope %q", rec.PolicyScope)
		}
		if rec.PolicyKind != "resource" && rec.PolicyKind != "principal" {
			return fmt.Errorf("invalid policy_kind %q", rec.PolicyKind)
		}
		if rec.PolicyKind == "resource" && (rec.PolicyTarget == "" || len(rec.PolicyTarget) > 512 || hasControlChars(rec.PolicyTarget)) {
			return fmt.Errorf("invalid policy_target %q for resource attachment intent", rec.PolicyTarget)
		}
		if rec.PolicyKind == "principal" && rec.PolicyTarget != "" {
			return fmt.Errorf("principal attachment intent must have empty policy_target (got %q)", rec.PolicyTarget)
		}
		if rec.PolicyPrincipal == "" || len(rec.PolicyPrincipal) > 256 || hasControlChars(rec.PolicyPrincipal) {
			return fmt.Errorf("invalid policy_principal %q", rec.PolicyPrincipal)
		}
		if rec.PolicyIntentOp != "attach" && rec.PolicyIntentOp != "detach" && rec.PolicyIntentOp != "abort" {
			return fmt.Errorf("invalid policy_intent_op %q (want attach, detach, or abort)", rec.PolicyIntentOp)
		}
		if err := ValidateToken128(rec.CreateToken); err != nil {
			return fmt.Errorf("policy_intent owner_token (create_token): %w", err)
		}
		if err := ValidateToken128(rec.AttemptID); err != nil {
			return fmt.Errorf("policy_intent intent_id (attempt_id): %w", err)
		}
		genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
		if err != nil || genNum == 0 {
			return fmt.Errorf("policy_intent requires positive uint64 generation (got %q)", rec.Generation)
		}
		if rec.PolicyIntentOp == "attach" || rec.PolicyDocument != "" {
			if err := validateJournalPolicyDocument(rec.PolicyDocument); err != nil {
				return err
			}
		}
		return nil
	case EventPolicyAttach:
		if rec.Kind != KindPolicyAttachment {
			return fmt.Errorf("policy_attach record must have kind %q (got %q)", KindPolicyAttachment, rec.Kind)
		}
		if hasControlChars(rec.PolicyScope) {
			return fmt.Errorf("invalid policy_scope %q", rec.PolicyScope)
		}
		if rec.PolicyKind != "resource" && rec.PolicyKind != "principal" {
			return fmt.Errorf("invalid policy_kind %q", rec.PolicyKind)
		}
		if rec.PolicyKind == "resource" && (rec.PolicyTarget == "" || len(rec.PolicyTarget) > 512 || hasControlChars(rec.PolicyTarget)) {
			return fmt.Errorf("invalid policy_target %q for resource attachment", rec.PolicyTarget)
		}
		if rec.PolicyKind == "principal" && rec.PolicyTarget != "" {
			return fmt.Errorf("principal attachment must have empty policy_target (got %q)", rec.PolicyTarget)
		}
		if rec.PolicyPrincipal == "" || len(rec.PolicyPrincipal) > 256 || hasControlChars(rec.PolicyPrincipal) {
			return fmt.Errorf("invalid policy_principal %q", rec.PolicyPrincipal)
		}
		if err := ValidateToken128(rec.CreateToken); err != nil {
			return fmt.Errorf("policy_attach missing or invalid owner_token (create_token): %w", err)
		}
		genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
		if err != nil || genNum == 0 {
			return fmt.Errorf("policy_attach requires positive uint64 generation (got %q)", rec.Generation)
		}
		if rec.AttemptID != "" {
			if err := ValidateToken128(rec.AttemptID); err != nil {
				return fmt.Errorf("policy_attach attempt_id: %w", err)
			}
		}
		if err := validateJournalPolicyDocument(rec.PolicyDocument); err != nil {
			return err
		}
		return nil
	case EventPolicyDetach:
		if rec.Kind != KindPolicyAttachment {
			return fmt.Errorf("policy_detach record must have kind %q (got %q)", KindPolicyAttachment, rec.Kind)
		}
		if hasControlChars(rec.PolicyScope) {
			return fmt.Errorf("invalid policy_scope %q", rec.PolicyScope)
		}
		if rec.PolicyKind != "resource" && rec.PolicyKind != "principal" {
			return fmt.Errorf("invalid policy_kind %q", rec.PolicyKind)
		}
		if rec.PolicyKind == "resource" && (rec.PolicyTarget == "" || len(rec.PolicyTarget) > 512 || hasControlChars(rec.PolicyTarget)) {
			return fmt.Errorf("invalid policy_target %q for resource detach", rec.PolicyTarget)
		}
		if rec.PolicyKind == "principal" && rec.PolicyTarget != "" {
			return fmt.Errorf("principal detach must have empty policy_target (got %q)", rec.PolicyTarget)
		}
		if rec.PolicyPrincipal == "" || len(rec.PolicyPrincipal) > 256 || hasControlChars(rec.PolicyPrincipal) {
			return fmt.Errorf("invalid policy_principal %q", rec.PolicyPrincipal)
		}
		if rec.CreateToken != "" {
			if err := ValidateToken128(rec.CreateToken); err != nil {
				return fmt.Errorf("policy_detach owner_token (create_token): %w", err)
			}
		}
		if rec.Generation != "" {
			if genNum, err := strconv.ParseUint(rec.Generation, 10, 64); err != nil || genNum == 0 {
				return fmt.Errorf("policy_detach invalid generation %q", rec.Generation)
			}
		}
		if rec.AttemptID != "" {
			if err := ValidateToken128(rec.AttemptID); err != nil {
				return fmt.Errorf("policy_detach attempt_id: %w", err)
			}
		}
		return nil
	case EventFunctionIntent:
		if rec.Kind != KindFunction {
			return fmt.Errorf("function_intent record must have kind %q (got %q)", KindFunction, rec.Kind)
		}
		if hasControlChars(rec.PolicyScope) || rec.Name == "" || len(rec.Name) > 64 || hasControlChars(rec.Name) {
			return fmt.Errorf("invalid function_intent scope/name %q/%q", rec.PolicyScope, rec.Name)
		}
		if rec.PolicyIntentOp != "create" && rec.PolicyIntentOp != "update" && rec.PolicyIntentOp != "delete" && rec.PolicyIntentOp != "abort" {
			return fmt.Errorf("invalid function_intent_op %q", rec.PolicyIntentOp)
		}
		if err := ValidateToken128(rec.CreateToken); err != nil {
			return fmt.Errorf("function_intent owner_token (create_token): %w", err)
		}
		if err := ValidateToken128(rec.AttemptID); err != nil {
			return fmt.Errorf("function_intent intent_id (attempt_id): %w", err)
		}
		genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
		if err != nil || genNum == 0 {
			return fmt.Errorf("function_intent requires positive uint64 generation (got %q)", rec.Generation)
		}
		if hasControlChars(rec.ETag) || len(rec.ETag) > 512 {
			return fmt.Errorf("invalid function_intent digest %q", rec.ETag)
		}
		return nil
	case EventFunctionConfirm:
		if rec.Kind != KindFunction {
			return fmt.Errorf("function_confirm record must have kind %q (got %q)", KindFunction, rec.Kind)
		}
		if hasControlChars(rec.PolicyScope) || rec.Name == "" || len(rec.Name) > 64 || hasControlChars(rec.Name) {
			return fmt.Errorf("invalid function_confirm scope/name %q/%q", rec.PolicyScope, rec.Name)
		}
		if err := ValidateToken128(rec.CreateToken); err != nil {
			return fmt.Errorf("function_confirm owner_token (create_token): %w", err)
		}
		genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
		if err != nil || genNum == 0 {
			return fmt.Errorf("function_confirm requires positive uint64 generation (got %q)", rec.Generation)
		}
		if rec.AttemptID != "" {
			if err := ValidateToken128(rec.AttemptID); err != nil {
				return fmt.Errorf("function_confirm attempt_id: %w", err)
			}
		}
		if hasControlChars(rec.ETag) || len(rec.ETag) > 512 {
			return fmt.Errorf("invalid function_confirm digest %q", rec.ETag)
		}
		if len(rec.FunctionState) > 256*1024 {
			return errors.New("function_confirm function_state exceeds maximum size")
		}
		return nil
	case EventFunctionPreviewState:
		if rec.Kind != KindFunction {
			return fmt.Errorf("function_preview_state record must have kind %q (got %q)", KindFunction, rec.Kind)
		}
		if hasControlChars(rec.PolicyScope) || rec.Name == "" || len(rec.Name) > 64 || hasControlChars(rec.Name) {
			return fmt.Errorf("invalid function_preview_state scope/name %q/%q", rec.PolicyScope, rec.Name)
		}
		if err := ValidateToken128(rec.CreateToken); err != nil {
			return fmt.Errorf("function_preview_state owner_token (create_token): %w", err)
		}
		genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
		if err != nil || genNum == 0 {
			return fmt.Errorf("function_preview_state requires positive uint64 generation (got %q)", rec.Generation)
		}
		if hasControlChars(rec.ETag) || len(rec.ETag) > 512 {
			return fmt.Errorf("invalid function_preview_state digest %q", rec.ETag)
		}
		if len(rec.FunctionState) > 256*1024 {
			return errors.New("function_preview_state function_state exceeds maximum size")
		}
		return nil
	case EventFunctionDelete:
		if rec.Kind != KindFunction {
			return fmt.Errorf("function_delete record must have kind %q (got %q)", KindFunction, rec.Kind)
		}
		if hasControlChars(rec.PolicyScope) || rec.Name == "" || len(rec.Name) > 64 || hasControlChars(rec.Name) {
			return fmt.Errorf("invalid function_delete scope/name %q/%q", rec.PolicyScope, rec.Name)
		}
		if rec.CreateToken != "" {
			if err := ValidateToken128(rec.CreateToken); err != nil {
				return fmt.Errorf("function_delete owner_token (create_token): %w", err)
			}
		}
		if rec.Generation != "" {
			if genNum, err := strconv.ParseUint(rec.Generation, 10, 64); err != nil || genNum == 0 {
				return fmt.Errorf("function_delete invalid generation %q", rec.Generation)
			}
		}
		if rec.AttemptID != "" {
			if err := ValidateToken128(rec.AttemptID); err != nil {
				return fmt.Errorf("function_delete attempt_id: %w", err)
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
	case KindBucket, KindQueue, KindTable, KindFunction:
		if parent != "" {
			return fmt.Errorf("%s record must have empty parent (got %q)", kind, parent)
		}
		if err := ValidateLiveResourceName(runID, name); err != nil {
			return fmt.Errorf("forged or unprefixed %s name in journal: %w", kind, err)
		}
		return nil
	case KindObject, KindQueueMessage, KindTableItem, KindFunctionVersion, KindFunctionAlias:
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

func decrementKindCreated(state *LedgerState, kind string) {
	switch kind {
	case KindBucket:
		if state.BucketsCreated > 0 {
			state.BucketsCreated--
		}
	case KindQueue:
		if state.QueuesCreated > 0 {
			state.QueuesCreated--
		}
	case KindObject:
		if state.ObjectsCreated > 0 {
			state.ObjectsCreated--
		}
	}
}

func recomputeReservedNanoUSD(state *LedgerState) {
	for i := range state.Entries {
		state.Entries[i].ReservedNanoUSD = 0
		state.Entries[i].PayloadBytes = 0
	}
	var total int64
	for _, a := range state.PendingAttempts {
		if a.ReservedNanoUSD > 0 {
			total += a.ReservedNanoUSD
		}
		if idx, ok := state.byKey[resourceKey(a.Kind, a.Parent, a.Name)]; ok {
			state.Entries[idx].ReservedNanoUSD += a.ReservedNanoUSD
			state.Entries[idx].PayloadBytes += a.PayloadBytes
		}
	}
	state.ReservedNanoUSD = total
}

func latestAttemptIDFor(state *LedgerState, kind, parent, name string) string {
	if state == nil {
		return ""
	}
	for i := len(state.PendingAttempts) - 1; i >= 0; i-- {
		a := state.PendingAttempts[i]
		if a.Kind == kind && a.Parent == parent && a.Name == name {
			return a.AttemptID
		}
	}
	return ""
}

func upsertPendingAttempt(state *LedgerState, att AttemptLedgerEntry) {
	if state.byAttemptID == nil {
		state.byAttemptID = make(map[string]int)
	}
	if aIdx, ok := state.byAttemptID[att.AttemptID]; ok {
		cur := state.PendingAttempts[aIdx]
		if att.ReservedNanoUSD > cur.ReservedNanoUSD {
			cur.ReservedNanoUSD = att.ReservedNanoUSD
		}
		cur.PayloadBytes += att.PayloadBytes
		cur.Seq = att.Seq
		state.PendingAttempts[aIdx] = cur
		return
	}
	state.byAttemptID[att.AttemptID] = len(state.PendingAttempts)
	state.PendingAttempts = append(state.PendingAttempts, att)
}

func removeAttemptAt(state *LedgerState, idx int) {
	removed := state.PendingAttempts[idx]
	delete(state.byAttemptID, removed.AttemptID)
	state.PendingAttempts = append(state.PendingAttempts[:idx], state.PendingAttempts[idx+1:]...)
	for i := idx; i < len(state.PendingAttempts); i++ {
		a := state.PendingAttempts[i]
		state.byAttemptID[a.AttemptID] = i
	}
}

func inferJournalOp(rec JournalRecord, att AttemptLedgerEntry) string {
	if rec.Operation != "" {
		return rec.Operation
	}
	if att.Operation != "" {
		return att.Operation
	}
	reason := rec.Reason
	if reason == "" {
		reason = att.Reason
	}
	switch reason {
	case "bucket_create", "bucket_overwrite":
		return "bucket_create"
	case "bucket_delete":
		return "bucket_delete"
	case "bucket_exists":
		return "bucket_exists"
	case "bucket_list":
		return "bucket_list"
	case "bucket_read_ownership", "pre_create_bucket_check", "post_create_bucket_check", "duplicate_bucket_create_check", "pre_delete_bucket_check", "bucket_create_token":
		return "bucket_read_ownership"
	case "object_put", "object_overwrite":
		return "object_put"
	case "object_get":
		return "object_get"
	case "object_head", "post_failed_object_put_check", "pre_delete_object_check":
		return "object_head"
	case "object_delete":
		return "object_delete"
	case "object_list", "pre_delete_bucket_list_children":
		return "object_list"
	case "object_list_all":
		return "object_list_all"
	case "queue_create", "queue_overwrite":
		return "queue_create"
	case "queue_delete":
		return "queue_delete"
	case "queue_exists":
		return "queue_exists"
	case "queue_list":
		return "queue_list"
	case "queue_read_ownership", "pre_create_queue_check", "post_create_queue_check", "duplicate_queue_create_check", "pre_delete_queue_check", "queue_create_token":
		return "queue_read_ownership"
	case "queue_send", "queue_send_compacted":
		return "queue_send"
	case "queue_receive":
		return "queue_receive"
	case "queue_ack":
		return "queue_ack"
	case "queue_nack":
		return "queue_nack"
	case "table_create", "table_overwrite":
		return "table_create"
	case "table_delete":
		return "table_delete"
	case "table_exists":
		return "table_exists"
	case "table_list":
		return "table_list"
	case "table_read_ownership", "table_create_token":
		return "table_read_ownership"
	case "item_put", "item_overwrite":
		return "item_put"
	case "item_get":
		return "item_get"
	case "item_delete":
		return "item_delete"
	case "item_update":
		return "item_update"
	case "item_query":
		return "item_query"
	case "item_scan":
		return "item_scan"
	case "principal_current":
		return "principal_current"
	case "policy_attach":
		return "policy_attach"
	case "policy_attach_principal":
		return "policy_attach_principal"
	case "policy_detach":
		return "policy_detach"
	case "policy_detach_principal":
		return "policy_detach_principal"
	case "policy_check":
		return "policy_check"
	case "function_create", "function_overwrite":
		return "function_create"
	case "function_update":
		return "function_update"
	case "function_delete":
		return "function_delete"
	case "function_exists":
		return "function_exists"
	case "function_get":
		return "function_get"
	case "function_list":
		return "function_list"
	case "function_publish_version":
		return "function_publish_version"
	case "function_versions":
		return "function_versions"
	case "function_alias_set":
		return "function_alias_set"
	case "function_alias_get":
		return "function_alias_get"
	case "function_alias_delete":
		return "function_alias_delete"
	case "function_read_ownership", "function_create_token":
		return "function_read_ownership"
	case "function_invoke":
		return "function_invoke"
	case "verify_parent_ownership":
		if rec.Kind == KindQueue || att.Kind == KindQueue {
			return "queue_read_ownership"
		}
		if rec.Kind == KindTable || att.Kind == KindTable {
			return "table_read_ownership"
		}
		if rec.Kind == KindFunction || att.Kind == KindFunction {
			return "function_read_ownership"
		}
		return "bucket_read_ownership"
	}
	switch rec.Event {
	case EventConfirmed, EventFailed, EventRetained:
		switch rec.Kind {
		case KindBucket:
			return "bucket_create"
		case KindQueue:
			return "queue_create"
		case KindObject:
			return "object_put"
		case KindTable:
			return "table_create"
		case KindTableItem:
			return "item_put"
		case KindFunction:
			return "function_create"
		case KindFunctionVersion:
			return "function_publish_version"
		case KindFunctionAlias:
			return "function_alias_set"
		}
	}
	return ""
}

func recordOpStat(state *LedgerState, op string, units, bytes, chargedNano int64) {
	if op == "" {
		return
	}
	if state.OpStats == nil {
		state.OpStats = make(map[string]OpLedgerStat)
	}
	if units <= 0 {
		units = 1
		switch op {
		case "queue_send", "queue_receive":
			if bytes > 65536 {
				units = (bytes + 65535) / 65536
			}
		case "item_put", "item_update", "item_delete":
			if bytes > 1024 {
				units = (bytes + 1023) / 1024
			}
		case "item_get", "item_query", "item_scan":
			if bytes > 4096 {
				units = (bytes + 4095) / 4096
			}
		}
	}
	if bytes < 0 {
		bytes = 0
	}
	cur := state.OpStats[op]
	cur.Requests++
	cur.BillingUnits += units
	cur.Bytes += bytes
	cur.ChargedNanoUSD += chargedNano
	state.OpStats[op] = cur
}

func applyRecordToState(state *LedgerState, rec JournalRecord) error {
	defer recomputeReservedNanoUSD(state)
	if state.OpStats == nil {
		state.OpStats = make(map[string]OpLedgerStat)
	}
	if state.ActiveCleanup == nil {
		state.ActiveCleanup = make(map[string]int64)
	}
	if state.PolicyAttachments == nil {
		state.PolicyAttachments = make(map[string]JournalPolicyAttachment)
	}
	if state.AmbiguousPolicies == nil {
		state.AmbiguousPolicies = make(map[string]JournalPolicyAttachment)
	}
	if state.AmbiguousStack == nil {
		state.AmbiguousStack = make(map[string][]JournalPolicyAttachment)
	}
	if state.PolicyTombstones == nil {
		state.PolicyTombstones = make(map[string]JournalPolicyAttachment)
	}
	if state.MaxPolicyGen == nil {
		state.MaxPolicyGen = make(map[string]uint64)
	}
	if state.LatestPolicyIntent == nil {
		state.LatestPolicyIntent = make(map[string]string)
	}
	if state.ActiveFunctions == nil {
		state.ActiveFunctions = make(map[string]JournalFunctionEntry)
	}
	if state.AmbiguousFunctions == nil {
		state.AmbiguousFunctions = make(map[string]JournalFunctionEntry)
	}
	if state.AmbiguousFunctionStack == nil {
		state.AmbiguousFunctionStack = make(map[string][]JournalFunctionEntry)
	}
	if state.FunctionTombstones == nil {
		state.FunctionTombstones = make(map[string]JournalFunctionEntry)
	}
	if state.MaxFunctionGen == nil {
		state.MaxFunctionGen = make(map[string]uint64)
	}
	if state.LatestFunctionIntent == nil {
		state.LatestFunctionIntent = make(map[string]string)
	}
	state.LastSeq = rec.Seq
	if rec.Event != EventSettle {
		state.ChargedNanoUSD += rec.ChargedNanoUSD
		state.TotalPayloadBytes += rec.PayloadBytes
	}

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
		state.CapExceededCount += rec.CapExceededCount
		for k, v := range rec.OpStats {
			cur := state.OpStats[k]
			cur.Requests += v.Requests
			cur.BillingUnits += v.BillingUnits
			cur.Bytes += v.Bytes
			cur.ChargedNanoUSD += v.ChargedNanoUSD
			state.OpStats[k] = cur
		}
		for k, v := range rec.ActiveCleanup {
			if v > 0 {
				state.ActiveCleanup[k] = v
			}
		}
		if rec.WorkCapNanoUSD > 0 && (state.WorkCapNanoUSD == 0 || rec.WorkCapNanoUSD < state.WorkCapNanoUSD) {
			state.WorkCapNanoUSD = rec.WorkCapNanoUSD
		}
		return nil
	}
	if rec.Event == EventCapExceeded {
		n := rec.CapExceededCount
		if n <= 0 {
			n = 1
		}
		state.CapExceededCount += n
		return nil
	}
	if rec.Event == EventWorkCap {
		if rec.WorkCapNanoUSD > 0 && (state.WorkCapNanoUSD == 0 || rec.WorkCapNanoUSD < state.WorkCapNanoUSD) {
			state.WorkCapNanoUSD = rec.WorkCapNanoUSD
		}
		return nil
	}
	if rec.Event == EventPolicyIntent {
		pKey := scopedPolicyKey(rec.PolicyScope, rec.PolicyKind, rec.PolicyTarget, rec.PolicyPrincipal)
		genNum, _ := strconv.ParseUint(rec.Generation, 10, 64)
		if rec.PolicyIntentOp == "abort" {
			stack := state.AmbiguousStack[pKey]
			if len(stack) > 0 {
				filtered := stack[:0]
				for _, item := range stack {
					if item.IntentID != rec.AttemptID {
						filtered = append(filtered, item)
					}
				}
				if len(filtered) > 0 {
					state.AmbiguousStack[pKey] = filtered
					state.AmbiguousPolicies[pKey] = filtered[len(filtered)-1]
				} else {
					delete(state.AmbiguousStack, pKey)
					delete(state.AmbiguousPolicies, pKey)
					if _, inActive := state.PolicyAttachments[pKey]; !inActive {
						deletePolicyActiveCleanup(state, pKey)
					}
				}
			} else if state.LatestPolicyIntent[pKey] == "" || state.LatestPolicyIntent[pKey] == rec.AttemptID {
				delete(state.AmbiguousPolicies, pKey)
				if _, inActive := state.PolicyAttachments[pKey]; !inActive {
					deletePolicyActiveCleanup(state, pKey)
				}
			}
			return nil
		}
		if genNum <= state.MaxPolicyGen[pKey] {
			return fmt.Errorf("non-monotonic policy_intent generation %d for key %q (max=%d)", genNum, pKey, state.MaxPolicyGen[pKey])
		}
		if rec.PolicyIntentOp == "attach" {
			if _, inActive := state.PolicyAttachments[pKey]; !inActive {
				if _, inAmb := state.AmbiguousPolicies[pKey]; !inAmb {
					if countPolicyAttachmentKeys(state) >= 128 {
						return errors.New("policy attachment count in journal exceeds maximum of 128 per run")
					}
				}
			}
		}
		state.MaxPolicyGen[pKey] = genNum
		state.LatestPolicyIntent[pKey] = rec.AttemptID
		jpa := JournalPolicyAttachment{
			Key:        pKey,
			Scope:      rec.PolicyScope,
			Kind:       rec.PolicyKind,
			Target:     rec.PolicyTarget,
			Principal:  rec.PolicyPrincipal,
			Document:   rec.PolicyDocument,
			OwnerToken: rec.CreateToken,
			Generation: rec.Generation,
			IntentID:   rec.AttemptID,
			Ambiguous:  true,
			IntentOp:   rec.PolicyIntentOp,
		}
		state.AmbiguousStack[pKey] = append(state.AmbiguousStack[pKey], jpa)
		state.AmbiguousPolicies[pKey] = jpa
		state.PolicyTombstones[pKey] = jpa
		if rec.CleanupReserveNanoUSD > 0 {
			state.ActiveCleanup["policy\x00"+pKey] = rec.CleanupReserveNanoUSD
		}
		return nil
	}
	if rec.Event == EventPolicyAttach {
		pKey := scopedPolicyKey(rec.PolicyScope, rec.PolicyKind, rec.PolicyTarget, rec.PolicyPrincipal)
		genNum, _ := strconv.ParseUint(rec.Generation, 10, 64)
		if genNum < state.MaxPolicyGen[pKey] {
			return fmt.Errorf("stale policy_attach generation %d for key %q (max=%d)", genNum, pKey, state.MaxPolicyGen[pKey])
		}
		if rec.AttemptID != "" && state.LatestPolicyIntent[pKey] != "" && rec.AttemptID != state.LatestPolicyIntent[pKey] {
			return fmt.Errorf("stale policy_attach intent_id %q for key %q (latest=%q)", rec.AttemptID, pKey, state.LatestPolicyIntent[pKey])
		}
		if _, inActive := state.PolicyAttachments[pKey]; !inActive {
			if _, inAmb := state.AmbiguousPolicies[pKey]; !inAmb {
				if countPolicyAttachmentKeys(state) >= 128 {
					return errors.New("policy attachment count in journal exceeds maximum of 128 per run")
				}
			}
		}
		state.MaxPolicyGen[pKey] = genNum
		if rec.AttemptID != "" {
			state.LatestPolicyIntent[pKey] = rec.AttemptID
		}
		delete(state.AmbiguousStack, pKey)
		delete(state.AmbiguousPolicies, pKey)
		jpa := JournalPolicyAttachment{
			Key:        pKey,
			Scope:      rec.PolicyScope,
			Kind:       rec.PolicyKind,
			Target:     rec.PolicyTarget,
			Principal:  rec.PolicyPrincipal,
			Document:   rec.PolicyDocument,
			OwnerToken: rec.CreateToken,
			Generation: rec.Generation,
			IntentID:   rec.AttemptID,
		}
		state.PolicyAttachments[pKey] = jpa
		state.PolicyTombstones[pKey] = jpa
		if rec.CleanupReserveNanoUSD > 0 {
			state.ActiveCleanup["policy\x00"+pKey] = rec.CleanupReserveNanoUSD
		}
		return nil
	}
	if rec.Event == EventPolicyDetach {
		pKey := scopedPolicyKey(rec.PolicyScope, rec.PolicyKind, rec.PolicyTarget, rec.PolicyPrincipal)
		if rec.Generation != "" {
			genNum, _ := strconv.ParseUint(rec.Generation, 10, 64)
			if genNum < state.MaxPolicyGen[pKey] {
				return fmt.Errorf("stale policy_detach generation %d for key %q (max=%d)", genNum, pKey, state.MaxPolicyGen[pKey])
			}
			state.MaxPolicyGen[pKey] = genNum
		}
		if rec.AttemptID != "" && state.LatestPolicyIntent[pKey] != "" && rec.AttemptID != state.LatestPolicyIntent[pKey] {
			return fmt.Errorf("stale policy_detach intent_id %q for key %q (latest=%q)", rec.AttemptID, pKey, state.LatestPolicyIntent[pKey])
		}
		if rec.AttemptID != "" {
			state.LatestPolicyIntent[pKey] = rec.AttemptID
		}
		ownerTok := rec.CreateToken
		if ownerTok == "" {
			ownerTok = state.PolicyTombstones[pKey].OwnerToken
		}
		state.PolicyTombstones[pKey] = JournalPolicyAttachment{
			Key:        pKey,
			Scope:      rec.PolicyScope,
			Kind:       rec.PolicyKind,
			Target:     rec.PolicyTarget,
			Principal:  rec.PolicyPrincipal,
			OwnerToken: ownerTok,
			Generation: rec.Generation,
			IntentID:   state.LatestPolicyIntent[pKey],
		}
		delete(state.AmbiguousStack, pKey)
		delete(state.AmbiguousPolicies, pKey)
		delete(state.PolicyAttachments, pKey)
		deletePolicyActiveCleanup(state, pKey)
		return nil
	}
	if rec.Event == EventFunctionIntent {
		fKey := scopedFunctionKey(rec.PolicyScope, rec.Name)
		genNum, _ := strconv.ParseUint(rec.Generation, 10, 64)
		if rec.PolicyIntentOp == "abort" {
			stack := state.AmbiguousFunctionStack[fKey]
			if len(stack) > 0 {
				filtered := stack[:0]
				for _, item := range stack {
					if item.IntentID != rec.AttemptID {
						filtered = append(filtered, item)
					}
				}
				if len(filtered) > 0 {
					state.AmbiguousFunctionStack[fKey] = filtered
					state.AmbiguousFunctions[fKey] = filtered[len(filtered)-1]
				} else {
					delete(state.AmbiguousFunctionStack, fKey)
					delete(state.AmbiguousFunctions, fKey)
					if _, inActive := state.ActiveFunctions[fKey]; !inActive {
						deleteFunctionActiveCleanup(state, rec.PolicyScope, rec.Name, fKey)
					}
				}
			} else if state.LatestFunctionIntent[fKey] == "" || state.LatestFunctionIntent[fKey] == rec.AttemptID {
				delete(state.AmbiguousFunctions, fKey)
				if _, inActive := state.ActiveFunctions[fKey]; !inActive {
					deleteFunctionActiveCleanup(state, rec.PolicyScope, rec.Name, fKey)
				}
			}
			return nil
		}
		if genNum <= state.MaxFunctionGen[fKey] {
			return fmt.Errorf("non-monotonic function_intent generation %d for key %q (max=%d)", genNum, fKey, state.MaxFunctionGen[fKey])
		}
		if rec.PolicyIntentOp == "create" {
			if _, inActive := state.ActiveFunctions[fKey]; !inActive {
				if _, inAmb := state.AmbiguousFunctions[fKey]; !inAmb {
					if countFunctionKeys(state) >= 64 {
						return errors.New("function count in journal exceeds maximum of 64 per run")
					}
				}
			}
		}
		state.MaxFunctionGen[fKey] = genNum
		state.LatestFunctionIntent[fKey] = rec.AttemptID
		jfe := JournalFunctionEntry{
			Key:        fKey,
			Scope:      rec.PolicyScope,
			Name:       rec.Name,
			Digest:     rec.ETag,
			OwnerToken: rec.CreateToken,
			Generation: rec.Generation,
			IntentID:   rec.AttemptID,
			Ambiguous:  true,
			IntentOp:   rec.PolicyIntentOp,
		}
		state.AmbiguousFunctionStack[fKey] = append(state.AmbiguousFunctionStack[fKey], jfe)
		state.AmbiguousFunctions[fKey] = jfe
		state.FunctionTombstones[fKey] = jfe
		if rec.CleanupReserveNanoUSD > 0 {
			state.ActiveCleanup[resourceKey(KindFunction, rec.PolicyScope, rec.Name)] = rec.CleanupReserveNanoUSD
		}
		return nil
	}
	if rec.Event == EventFunctionConfirm {
		fKey := scopedFunctionKey(rec.PolicyScope, rec.Name)
		genNum, _ := strconv.ParseUint(rec.Generation, 10, 64)
		if genNum < state.MaxFunctionGen[fKey] {
			return fmt.Errorf("stale function_confirm generation %d for key %q (max=%d)", genNum, fKey, state.MaxFunctionGen[fKey])
		}
		if rec.AttemptID != "" && state.LatestFunctionIntent[fKey] != "" && rec.AttemptID != state.LatestFunctionIntent[fKey] {
			return fmt.Errorf("stale function_confirm intent_id %q for key %q (latest=%q)", rec.AttemptID, fKey, state.LatestFunctionIntent[fKey])
		}
		if _, inActive := state.ActiveFunctions[fKey]; !inActive {
			if _, inAmb := state.AmbiguousFunctions[fKey]; !inAmb {
				if countFunctionKeys(state) >= 64 {
					return errors.New("function count in journal exceeds maximum of 64 per run")
				}
			}
		}
		state.MaxFunctionGen[fKey] = genNum
		if rec.AttemptID != "" {
			state.LatestFunctionIntent[fKey] = rec.AttemptID
		}
		delete(state.AmbiguousFunctionStack, fKey)
		delete(state.AmbiguousFunctions, fKey)
		stateJSON := rec.FunctionState
		if stateJSON == "" {
			stateJSON = state.ActiveFunctions[fKey].StateJSON
		}
		jfe := JournalFunctionEntry{
			Key:        fKey,
			Scope:      rec.PolicyScope,
			Name:       rec.Name,
			Digest:     rec.ETag,
			OwnerToken: rec.CreateToken,
			Generation: rec.Generation,
			IntentID:   rec.AttemptID,
			StateJSON:  stateJSON,
		}
		state.ActiveFunctions[fKey] = jfe
		state.FunctionTombstones[fKey] = jfe
		if rec.CleanupReserveNanoUSD > 0 {
			state.ActiveCleanup[resourceKey(KindFunction, rec.PolicyScope, rec.Name)] = rec.CleanupReserveNanoUSD
		}
		return nil
	}
	if rec.Event == EventFunctionPreviewState {
		fKey := scopedFunctionKey(rec.PolicyScope, rec.Name)
		act, hasAct := state.ActiveFunctions[fKey]
		_, hasAmb := state.AmbiguousFunctions[fKey]
		if !hasAct || hasAmb || len(state.AmbiguousFunctionStack[fKey]) > 0 {
			return nil
		}
		if act.OwnerToken != rec.CreateToken || act.Digest != rec.ETag || act.Generation != rec.Generation {
			return nil
		}
		act.StateJSON = rec.FunctionState
		state.ActiveFunctions[fKey] = act
		if tb, hasTb := state.FunctionTombstones[fKey]; hasTb && tb.OwnerToken == act.OwnerToken && tb.Generation == act.Generation {
			tb.StateJSON = rec.FunctionState
			state.FunctionTombstones[fKey] = tb
		}
		return nil
	}
	if rec.Event == EventFunctionDelete {
		fKey := scopedFunctionKey(rec.PolicyScope, rec.Name)
		if rec.Generation != "" {
			genNum, _ := strconv.ParseUint(rec.Generation, 10, 64)
			if genNum < state.MaxFunctionGen[fKey] {
				return fmt.Errorf("stale function_delete generation %d for key %q (max=%d)", genNum, fKey, state.MaxFunctionGen[fKey])
			}
			state.MaxFunctionGen[fKey] = genNum
		}
		if rec.AttemptID != "" && state.LatestFunctionIntent[fKey] != "" && rec.AttemptID != state.LatestFunctionIntent[fKey] {
			return fmt.Errorf("stale function_delete intent_id %q for key %q (latest=%q)", rec.AttemptID, fKey, state.LatestFunctionIntent[fKey])
		}
		if rec.AttemptID != "" {
			state.LatestFunctionIntent[fKey] = rec.AttemptID
		}
		ownerTok := rec.CreateToken
		if ownerTok == "" {
			ownerTok = state.FunctionTombstones[fKey].OwnerToken
		}
		state.FunctionTombstones[fKey] = JournalFunctionEntry{
			Key:        fKey,
			Scope:      rec.PolicyScope,
			Name:       rec.Name,
			OwnerToken: ownerTok,
			Generation: rec.Generation,
			IntentID:   state.LatestFunctionIntent[fKey],
		}
		delete(state.AmbiguousFunctionStack, fKey)
		delete(state.AmbiguousFunctions, fKey)
		delete(state.ActiveFunctions, fKey)
		deleteFunctionActiveCleanup(state, rec.PolicyScope, rec.Name, fKey)
		removeResourcePolicyAttachments(state, KindFunction, rec.PolicyScope, rec.Name)
		return nil
	}
	if rec.Event == EventCost {
		if rec.Kind == KindQueueMessage && rec.Reason == "queue_send" {
			state.MessagesSent++
		}
		var att AttemptLedgerEntry
		// Settle by explicit AttemptID only; unrelated ownership/read EventCost
		// records for the same resource must NEVER clear a pending create reservation.
		if rec.AttemptID != "" {
			if aIdx, ok := state.byAttemptID[rec.AttemptID]; ok {
				att = state.PendingAttempts[aIdx]
				removeAttemptAt(state, aIdx)
			}
		}
		b := rec.SettledBytes
		if b == 0 {
			b = rec.PayloadBytes
		}
		if b == 0 {
			b = att.PayloadBytes
		}
		recordOpStat(state, inferJournalOp(rec, att), rec.BillingUnits, b, rec.ChargedNanoUSD)
		return nil
	}
	if rec.Event == EventReserve {
		if rec.Kind == KindQueueMessage && rec.Reason == "queue_send" {
			state.MessagesSent++
		}
		upsertPendingAttempt(state, AttemptLedgerEntry{
			AttemptID:       rec.AttemptID,
			Operation:       rec.Operation,
			Kind:            rec.Kind,
			Parent:          rec.Parent,
			Name:            rec.Name,
			Reason:          rec.Reason,
			ReservedNanoUSD: rec.ReservedNanoUSD,
			PayloadBytes:    rec.PayloadBytes,
			Seq:             rec.Seq,
		})
		return nil
	}
	if rec.Event == EventSettle {
		aIdx, ok := state.byAttemptID[rec.AttemptID]
		if !ok {
			// Already settled: idempotent no-op on replay.
			return nil
		}
		att := state.PendingAttempts[aIdx]
		state.ChargedNanoUSD += rec.ChargedNanoUSD
		if rec.PayloadBytes > 0 {
			state.TotalPayloadBytes -= rec.PayloadBytes
			if state.TotalPayloadBytes < 0 {
				state.TotalPayloadBytes = 0
			}
		}
		rKey := resourceKey(att.Kind, att.Parent, att.Name)
		if rec.CleanupReserveNanoUSD > 0 && att.Name != "" {
			if _, inEntries := state.byKey[rKey]; !inEntries {
				state.ActiveCleanup[rKey] = rec.CleanupReserveNanoUSD
			}
		}
		if rec.ReleaseCleanup && att.Name != "" {
			delete(state.ActiveCleanup, rKey)
			removeResourcePolicyAttachments(state, att.Kind, att.Parent, att.Name)
			if att.Kind == KindTable {
				itemPrefix := resourceKey(KindTableItem, att.Parent, att.Name+"/")
				itemPrefixUnscoped := resourceKey(KindTableItem, "", att.Name+"/")
				parentPrefix := resourceKey(KindTableItem, att.Name, "")
				for k := range state.ActiveCleanup {
					if strings.HasPrefix(k, itemPrefix) || strings.HasPrefix(k, itemPrefixUnscoped) || strings.HasPrefix(k, parentPrefix) {
						delete(state.ActiveCleanup, k)
					}
				}
			}
			if att.Kind == KindFunction {
				deleteFunctionActiveCleanup(state, att.Parent, att.Name, scopedFunctionKey(att.Parent, att.Name))
			}
		}
		if rec.BillingUnits == 0 && rec.ChargedNanoUSD == 0 && rec.CleanupReserveNanoUSD == 0 && !rec.ReleaseCleanup {
			if att.Kind == KindQueueMessage && att.Reason == "queue_send" && state.MessagesSent > 0 {
				state.MessagesSent--
			}
			removeAttemptAt(state, aIdx)
			return nil
		}
		settledBytes := rec.SettledBytes
		if settledBytes == 0 && att.PayloadBytes > 0 && rec.PayloadBytes < att.PayloadBytes {
			settledBytes = att.PayloadBytes - rec.PayloadBytes
		}
		recordOpStat(state, inferJournalOp(rec, att), rec.BillingUnits, settledBytes, rec.ChargedNanoUSD)
		removeAttemptAt(state, aIdx)
		return nil
	}

	key := resourceKey(rec.Kind, rec.Parent, rec.Name)
	delete(state.ActiveCleanup, key)
	idx, exists := state.byKey[key]

	switch rec.Event {
	case EventIntent:
		attID := rec.AttemptID
		if attID == "" && (rec.ReservedNanoUSD > 0 || rec.PayloadBytes > 0) {
			attID = rec.CreateToken
		}
		if attID != "" {
			upsertPendingAttempt(state, AttemptLedgerEntry{
				AttemptID:       attID,
				Kind:            rec.Kind,
				Parent:          rec.Parent,
				Name:            rec.Name,
				Reason:          rec.Kind + "_create",
				ReservedNanoUSD: rec.ReservedNanoUSD,
				PayloadBytes:    rec.PayloadBytes,
				Seq:             rec.Seq,
			})
		}
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
			if rec.IntentAtUnix != 0 {
				cur.IntentAtUnix = rec.IntentAtUnix
			}
			cur.Seq = rec.Seq
			state.Entries[idx] = cur
			return nil
		}
		if !rec.Retain {
			incrementKindCreated(state, rec.Kind)
		}
		entry := LedgerEntry{
			Kind:         rec.Kind,
			Parent:       rec.Parent,
			Location:     rec.Location,
			Name:         rec.Name,
			OwnerNonce:   rec.OwnerNonce,
			CreateToken:  rec.CreateToken,
			IntentAtUnix: rec.IntentAtUnix,
			State:        StatePending,
			Seq:          rec.Seq,
		}
		state.byKey[key] = len(state.Entries)
		state.Entries = append(state.Entries, entry)
		return nil

	case EventConfirmed:
		var settledAtt AttemptLedgerEntry
		var hadSettledAtt bool
		attID := rec.AttemptID
		if attID == "" && rec.ChargedNanoUSD > 0 {
			attID = latestAttemptIDFor(state, rec.Kind, rec.Parent, rec.Name)
		}
		if attID != "" {
			if aIdx, ok := state.byAttemptID[attID]; ok {
				settledAtt = state.PendingAttempts[aIdx]
				hadSettledAtt = true
				removeAttemptAt(state, aIdx)
			}
		}
		if hadSettledAtt || rec.ChargedNanoUSD > 0 {
			b := rec.SettledBytes
			if b == 0 {
				b = settledAtt.PayloadBytes
			}
			recordOpStat(state, inferJournalOp(rec, settledAtt), rec.BillingUnits, b, rec.ChargedNanoUSD)
		}
		if exists {
			cur := state.Entries[idx]
			if cur.OwnerNonce != "" && cur.OwnerNonce != rec.OwnerNonce {
				return fmt.Errorf("confirmed owner_nonce mismatch for %s %s/%s", rec.Kind, rec.Parent, rec.Name)
			}
			wasCounted := (cur.State == StateConfirmed || cur.State == StatePending) && !cur.Retain
			if cur.Retain || cur.State == StateRetained || rec.Retain {
				cur.State = StateRetained
				cur.Retain = true
				if rec.Reason != "" {
					cur.Reason = rec.Reason
				}
				if wasCounted {
					decrementKindCreated(state, rec.Kind)
				}
			} else {
				cur.State = StateConfirmed
				if !wasCounted {
					incrementKindCreated(state, rec.Kind)
				}
			}
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
		var settledAtt AttemptLedgerEntry
		var hadSettledAtt bool
		attID := rec.AttemptID
		if attID == "" {
			attID = latestAttemptIDFor(state, rec.Kind, rec.Parent, rec.Name)
		}
		if attID != "" {
			if aIdx, ok := state.byAttemptID[attID]; ok {
				settledAtt = state.PendingAttempts[aIdx]
				hadSettledAtt = true
				removeAttemptAt(state, aIdx)
			}
		}
		if hadSettledAtt || rec.ChargedNanoUSD > 0 {
			b := rec.SettledBytes
			if b == 0 {
				b = settledAtt.PayloadBytes
			}
			recordOpStat(state, inferJournalOp(rec, settledAtt), rec.BillingUnits, b, rec.ChargedNanoUSD)
		}
		if !exists {
			return nil
		}
		cur := state.Entries[idx]
		// CRITICAL: Failed NEVER cancels an already-confirmed or retained entry!
		if cur.State == StateConfirmed || cur.State == StateRetained || cur.Retain {
			return nil
		}
		if cur.State == StatePending {
			decrementKindCreated(state, cur.Kind)
		}
		removeEntryAt(state, idx)
		return nil

	case EventRetained:
		if rec.ChargedNanoUSD > 0 {
			var settledAtt AttemptLedgerEntry
			attID := rec.AttemptID
			if attID == "" {
				attID = latestAttemptIDFor(state, rec.Kind, rec.Parent, rec.Name)
			}
			if attID != "" {
				if aIdx, ok := state.byAttemptID[attID]; ok {
					settledAtt = state.PendingAttempts[aIdx]
					removeAttemptAt(state, aIdx)
				}
			}
			b := rec.SettledBytes
			if b == 0 {
				b = settledAtt.PayloadBytes
			}
			recordOpStat(state, inferJournalOp(rec, settledAtt), rec.BillingUnits, b, rec.ChargedNanoUSD)
		} else if rec.ReservedNanoUSD > 0 && latestAttemptIDFor(state, rec.Kind, rec.Parent, rec.Name) == "" {
			attID := rec.AttemptID
			if attID == "" {
				attID = rec.CreateToken
			}
			if attID == "" {
				attID = NewToken128()
			}
			upsertPendingAttempt(state, AttemptLedgerEntry{
				AttemptID:       attID,
				Kind:            rec.Kind,
				Parent:          rec.Parent,
				Name:            rec.Name,
				Reason:          "retained_reserve",
				ReservedNanoUSD: rec.ReservedNanoUSD,
				Seq:             rec.Seq,
			})
		}
		if exists {
			cur := state.Entries[idx]
			if cur.State == StatePending && !cur.Retain {
				decrementKindCreated(state, cur.Kind)
			}
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
		resEP := rec.Location
		if resEP == "" {
			resEP = rec.Parent
		}
		if resEP == "" && exists {
			resEP = state.Entries[idx].Location
		}
		removeResourcePolicyAttachments(state, rec.Kind, resEP, rec.Name)
		if !exists {
			return nil
		}
		for {
			attID := latestAttemptIDFor(state, rec.Kind, rec.Parent, rec.Name)
			if attID == "" {
				break
			}
			aIdx := state.byAttemptID[attID]
			if rec.ChargedNanoUSD == 0 && state.PendingAttempts[aIdx].ReservedNanoUSD > 0 {
				state.ChargedNanoUSD += state.PendingAttempts[aIdx].ReservedNanoUSD
			}
			removeAttemptAt(state, aIdx)
		}
		removeEntryAt(state, idx)
		return nil
	}
	return nil
}

func validateJournalPolicyDocument(raw string) error {
	if len(raw) == 0 || len(raw) > 8192 || !strings.HasPrefix(raw, `{"v":1,"statements":[`) {
		return errors.New("corrupt or oversized policy_document in journal")
	}
	type stmtDoc struct {
		Effect    string   `json:"effect"`
		Actions   []string `json:"actions"`
		Resources []string `json:"resources"`
	}
	type polDoc struct {
		V          int       `json:"v"`
		Statements []stmtDoc `json:"statements"`
	}
	var doc polDoc
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("corrupt policy_document JSON in journal: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data in journal policy_document")
	}
	if doc.V != 1 || len(doc.Statements) == 0 || len(doc.Statements) > 32 {
		return errors.New("invalid policy_document version or statement count in journal")
	}
	for _, s := range doc.Statements {
		if (s.Effect != "Allow" && s.Effect != "Deny") || len(s.Actions) == 0 || len(s.Actions) > 64 || len(s.Resources) == 0 || len(s.Resources) > 64 {
			return errors.New("invalid statement in journal policy_document")
		}
	}
	return nil
}

func countPolicyAttachmentKeys(state *LedgerState) int {
	if state == nil {
		return 0
	}
	seen := make(map[string]struct{}, len(state.PolicyAttachments)+len(state.AmbiguousPolicies))
	for k := range state.PolicyAttachments {
		seen[k] = struct{}{}
	}
	for k := range state.AmbiguousPolicies {
		seen[k] = struct{}{}
	}
	return len(seen)
}

func deletePolicyActiveCleanup(state *LedgerState, pKey string) {
	if state == nil {
		return
	}
	delete(state.ActiveCleanup, "policy\x00"+pKey)
	suffix := "\x00" + strings.ReplaceAll(pKey, "\x00", "|")
	for ck := range state.ActiveCleanup {
		if strings.HasPrefix(ck, KindPolicyAttachment+"\x00") && strings.HasSuffix(ck, suffix) {
			delete(state.ActiveCleanup, ck)
		}
	}
}

func countFunctionKeys(state *LedgerState) int {
	if state == nil {
		return 0
	}
	seen := make(map[string]struct{}, len(state.ActiveFunctions)+len(state.AmbiguousFunctions))
	for k := range state.ActiveFunctions {
		seen[k] = struct{}{}
	}
	for k := range state.AmbiguousFunctions {
		seen[k] = struct{}{}
	}
	return len(seen)
}

func deleteFunctionActiveCleanup(state *LedgerState, scope, name, fKey string) {
	if state == nil || name == "" {
		return
	}
	delete(state.ActiveCleanup, "function\x00"+fKey)
	delete(state.ActiveCleanup, resourceKey(KindFunction, scope, name))
	verPrefix := resourceKey(KindFunctionVersion, scope, name+"/")
	aliasPrefix := resourceKey(KindFunctionAlias, scope, name+"/")
	for ck := range state.ActiveCleanup {
		if strings.HasPrefix(ck, verPrefix) || strings.HasPrefix(ck, aliasPrefix) {
			delete(state.ActiveCleanup, ck)
		}
	}
}

func policyScopeMatchesResourceEndpoint(policyScope, resKind, resEndpoint string) bool {
	if strings.HasPrefix(policyScope, "perm=") && strings.Contains(policyScope, "|storage=") {
		var wantPrefix string
		switch resKind {
		case KindBucket:
			wantPrefix = "storage="
		case KindQueue:
			wantPrefix = "queue="
		case KindTable:
			wantPrefix = "tables="
		case KindFunction:
			wantPrefix = "function="
		default:
			return false
		}
		for _, part := range strings.Split(policyScope, "|") {
			if strings.HasPrefix(part, wantPrefix) {
				return strings.TrimPrefix(part, wantPrefix) == resEndpoint
			}
		}
		return false
	}
	return policyScope == resEndpoint
}

func removeResourcePolicyAttachments(state *LedgerState, kind, resEndpoint, name string) {
	if state == nil || (len(state.PolicyAttachments) == 0 && len(state.AmbiguousPolicies) == 0) || name == "" {
		return
	}
	var target string
	switch kind {
	case KindBucket:
		target = "storage:bucket:" + name
	case KindQueue:
		target = "queue:queue:" + name
	case KindTable:
		target = "tables:table:" + name
	case KindFunction:
		target = "function:function:" + name
	default:
		return
	}
	for k, pa := range state.PolicyAttachments {
		if pa.Kind == "resource" && pa.Target == target && policyScopeMatchesResourceEndpoint(pa.Scope, kind, resEndpoint) {
			delete(state.PolicyAttachments, k)
			deletePolicyActiveCleanup(state, k)
		}
	}
	for k, pa := range state.AmbiguousPolicies {
		if pa.Kind == "resource" && pa.Target == target && policyScopeMatchesResourceEndpoint(pa.Scope, kind, resEndpoint) {
			delete(state.AmbiguousPolicies, k)
			delete(state.AmbiguousStack, k)
			deletePolicyActiveCleanup(state, k)
		}
	}
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
