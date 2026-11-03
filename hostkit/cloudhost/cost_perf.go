// SPDX-License-Identifier: MIT

package cloudhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

const (
	// MaxLatencySamplesPerOp bounds the per-operation sliding sample ring buffer
	// used for p50_ms and p95_ms quantiles while min/max/mean/total stream over all calls.
	MaxLatencySamplesPerOp = 10_000

	secondsPerMonth = 30 * 24 * 3600
	bytesPerGiB     = 1024 * 1024 * 1024

	campaignJournalVersion = 1
)

// CostLineItem is the immutable snapshot for a single operation in CostReport.
type CostLineItem struct {
	Operation          string
	Service            string
	Requests           int64
	BillingUnits       int64
	Bytes              int64
	UnitPriceUSD       float64
	BytePriceUSDPerGiB float64
	EstimatedUSD       float64
}

// CostReport is the immutable snapshot returned by cloud.cost_report().
type CostReport struct {
	Provider          string
	PriceTableVersion string
	CapUSD            float64
	CeilingUSD        float64
	EstimatedUSD      float64
	TotalRequests     int64
	TotalUnits        int64
	TotalBytes        int64
	CapExceededCount  int64
	Items             []CostLineItem
	byOp              map[string]CostLineItem
	table             *safety.PriceTable
}

// Item returns the CostLineItem for op, or a zero-valued CostLineItem populated
// with the active price table's unit/byte prices if op has 0 calls.
func (r CostReport) Item(op string) CostLineItem {
	if it, ok := r.byOp[op]; ok {
		return it
	}
	return buildCostLineItem(r.table, op, persistedOpCost{})
}

// Summary returns the canonical single-line summary for CostReport.summary().
func (r CostReport) Summary() string {
	if r.TotalRequests == 0 && r.EstimatedUSD == 0 {
		return fmt.Sprintf("estimated cost: $0.00 (read-only; provider=%s, requests=0, cap=$%.2f)", r.Provider, r.CapUSD)
	}
	return fmt.Sprintf("estimated cost: $%.8f (provider=%s, requests=%d, units=%d, bytes=%d, cap=$%.6f)",
		r.EstimatedUSD, r.Provider, r.TotalRequests, r.TotalUnits, r.TotalBytes, r.CapUSD)
}

// OpMetrics is the immutable per-operation performance snapshot inside MetricsReport.
type OpMetrics struct {
	Operation string
	Calls     int64
	Errors    int64
	Retries   int64
	Throttles int64
	BytesIn   int64
	BytesOut  int64
	MinMS     float64
	P50MS     float64
	P95MS     float64
	MaxMS     float64
	MeanMS    float64
	TotalMS   float64
}

// MetricsReport is the immutable snapshot returned by cloud.metrics().
type MetricsReport struct {
	ElapsedMS      float64
	TotalCalls     int64
	TotalErrors    int64
	TotalRetries   int64
	TotalThrottles int64
	TotalBytesIn   int64
	TotalBytesOut  int64
	Ops            []OpMetrics
	byOp           map[string]OpMetrics
}

// Op returns the OpMetrics for op, or a zero-valued OpMetrics if op was not called.
func (r MetricsReport) Op(op string) OpMetrics {
	if m, ok := r.byOp[op]; ok {
		return m
	}
	return OpMetrics{Operation: op}
}

// Summary returns the canonical single-line summary for MetricsReport.summary().
func (r MetricsReport) Summary() string {
	return fmt.Sprintf("metrics: calls=%d, errors=%d, retries=%d, throttles=%d, bytes_out=%d, bytes_in=%d",
		r.TotalCalls, r.TotalErrors, r.TotalRetries, r.TotalThrottles, r.TotalBytesOut, r.TotalBytesIn)
}

func serviceForOp(op string) string {
	switch {
	case strings.HasPrefix(op, "bucket_"), strings.HasPrefix(op, "object_"):
		return "storage"
	case strings.HasPrefix(op, "queue_"):
		return "queue"
	case strings.HasPrefix(op, "table_"), strings.HasPrefix(op, "item_"):
		return "tables"
	default:
		return "cloud"
	}
}

func buildCostLineItem(pt *safety.PriceTable, op string, st persistedOpCost) CostLineItem {
	var unitPrice float64
	var bytePrice float64
	if pt != nil {
		t, ok := pt.Operations[op]
		if !ok && op == "object_list_all" {
			t, ok = pt.Operations["object_list"]
		}
		if ok {
			unitPrice = safety.NanoToUSD(t.RequestNanoUSD)
			if t.StorageGiBMonthNanoUSD > 0 {
				dur := t.MinDurationSeconds
				if dur <= 0 {
					dur = 3600
				}
				effNanoPerGiB := float64(t.StorageGiBMonthNanoUSD) * float64(dur) / float64(secondsPerMonth)
				bytePrice = effNanoPerGiB / float64(safety.NanoUSDPerUSD)
			} else if t.EgressGiBNanoUSD > 0 {
				bytePrice = safety.NanoToUSD(t.EgressGiBNanoUSD)
			}
		}
	}
	return CostLineItem{
		Operation:          op,
		Service:            serviceForOp(op),
		Requests:           st.Requests,
		BillingUnits:       st.BillingUnits,
		Bytes:              st.Bytes,
		UnitPriceUSD:       unitPrice,
		BytePriceUSDPerGiB: bytePrice,
		EstimatedUSD:       safety.NanoToUSD(st.ChargedNanoUSD),
	}
}

type persistedOpCost struct {
	Requests       int64 `json:"requests"`
	BillingUnits   int64 `json:"billing_units"`
	Bytes          int64 `json:"bytes"`
	ChargedNanoUSD int64 `json:"charged_nano_usd"`
}

type campaignJournalRecord struct {
	Version               int    `json:"v"`
	Seq                   uint64 `json:"seq"`
	Event                 string `json:"event"`
	Provider              string `json:"provider,omitempty"`
	AttemptID             string `json:"attempt_id,omitempty"`
	Operation             string `json:"operation,omitempty"`
	ResKind               string `json:"res_kind,omitempty"`
	ResKey                string `json:"res_key,omitempty"`
	IsCleanup             bool   `json:"is_cleanup,omitempty"`
	AttemptNanoUSD        int64  `json:"attempt_nano_usd,omitempty"`
	CleanupReserveNanoUSD int64  `json:"cleanup_reserve_nano_usd,omitempty"`
	ReservedBytes         int64  `json:"reserved_bytes,omitempty"`
	ChargedNanoUSD        int64  `json:"charged_nano_usd,omitempty"`
	SettledBytes          int64  `json:"settled_bytes,omitempty"`
	BillingUnits          int64  `json:"billing_units,omitempty"`
	LockCleanup           bool   `json:"lock_cleanup,omitempty"`
	ReleaseCleanup        bool   `json:"release_cleanup,omitempty"`
	WorkCapNanoUSD        int64  `json:"work_cap_nano_usd,omitempty"`
}

type replayedCampaignState struct {
	lastSeq                uint64
	chargedNanoUSD         int64
	resourceCleanupNanoUSD int64
	workCapNanoUSD         int64
	hasWorkCap             bool
	capExceededCount       int64
	ops                    map[string]persistedOpCost
	activeBuckets          map[string]int64
	activeObjects          map[string]int64
	activeQueues           map[string]int64
	pending                map[string]campaignJournalRecord
}

var (
	campaignLocksMu sync.Mutex
	campaignLocks   = map[string]*sync.Mutex{}
)

func campaignPathMutex(path string) *sync.Mutex {
	clean := filepath.Clean(path)
	campaignLocksMu.Lock()
	defer campaignLocksMu.Unlock()
	m := campaignLocks[clean]
	if m == nil {
		m = &sync.Mutex{}
		campaignLocks[clean] = m
	}
	return m
}

func isLiveModeEnv() bool {
	for _, k := range []string{"LMCLOUD_LIVE", "LMAWS_LIVE", "LMAZURE_LIVE", "LMGCP_LIVE", "LMOCI_LIVE"} {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "1" || strings.EqualFold(v, "true") {
			return true
		}
	}
	return false
}

type liveGuardProvider interface {
	LiveGuard() *safety.LiveGuard
}

func extractLiveGuard(store hostkit.ObjectStore, queue hostkit.Queue) *safety.LiveGuard {
	if gs, ok := store.(guardStore); ok {
		store = gs.s
	}
	if lp, ok := store.(liveGuardProvider); ok && lp.LiveGuard() != nil {
		return lp.LiveGuard()
	}
	if gq, ok := queue.(guardQueue); ok {
		queue = gq.q
	}
	if lp, ok := queue.(liveGuardProvider); ok && lp.LiveGuard() != nil {
		return lp.LiveGuard()
	}
	return nil
}

type costTracker struct {
	mu                   sync.Mutex
	provider             string
	meter                *safety.CostMeter
	journal              *safety.Journal
	liveGuard            *safety.LiveGuard
	delegatedToLiveGuard bool
	unconfiguredLive     bool
	poisoned             *hostkit.CloudError
	statePath            string
	onSetWorkCap         func(workCapNanoUSD int64) error
	capExceededCount     int64
	ops                  map[string]persistedOpCost
	activeBuckets        map[string]int64
	activeObjects        map[string]int64
	activeQueues         map[string]int64
}

func newCostTracker(cfg Config) *costTracker {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = "ref"
	}

	lg := extractLiveGuard(cfg.Store, cfg.Queue)
	liveMode := isLiveModeEnv() || lg != nil

	ct := &costTracker{
		provider:      provider,
		journal:       cfg.Journal,
		liveGuard:     lg,
		statePath:     strings.TrimSpace(cfg.CampaignStatePath),
		onSetWorkCap:  cfg.OnSetWorkCap,
		ops:           map[string]persistedOpCost{},
		activeBuckets: map[string]int64{},
		activeObjects: map[string]int64{},
		activeQueues:  map[string]int64{},
	}

	if lg != nil {
		ct.delegatedToLiveGuard = true
		ct.meter = lg.Meter()
		ct.journal = lg.Journal()
		if ct.meter == nil || ct.journal == nil || ct.meter.Table() == nil || ct.meter.Table().IsSynthetic() {
			ct.unconfiguredLive = true
			ct.poisoned = hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveCostMeterRequired",
				"live guard requires a non-synthetic regional price table and safety journal")
			return ct
		}
		if err := ct.meter.Table().Validate(ct.meter.Table().Provider, ct.meter.Table().Region, cfg.Now()); err != nil {
			ct.unconfiguredLive = true
			ct.poisoned = hostkit.ProviderError(hostkit.PermissionDenied, 0, "LivePriceTableInvalid", err.Error())
		}
		return ct
	}

	if liveMode {
		meter := cfg.Meter
		if meter == nil || meter.Table() == nil || meter.Table().IsSynthetic() {
			ct.unconfiguredLive = true
			ct.poisoned = hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveCostMeterRequired",
				"live mode refuses synthetic or default simulator price table; a verified regional CostMeter and safety Journal are required")
			return ct
		}
		pt := meter.Table()
		if cfg.PriceTable != nil && cfg.PriceTable.IsSynthetic() {
			ct.unconfiguredLive = true
			ct.poisoned = hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveCostMeterRequired",
				"synthetic price table is forbidden in live mode")
			return ct
		}
		if err := pt.Validate(provider, pt.Region, cfg.Now()); err != nil {
			ct.unconfiguredLive = true
			ct.poisoned = hostkit.ProviderError(hostkit.PermissionDenied, 0, "LivePriceTableInvalid", err.Error())
			return ct
		}
		if ct.journal == nil && ct.statePath == "" {
			ct.unconfiguredLive = true
			ct.poisoned = hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveJournalRequired",
				"live mode requires an authoritative safety journal or campaign state path")
			return ct
		}
		ct.meter = meter
	} else {
		meter := cfg.Meter
		if meter == nil {
			pt := cfg.PriceTable
			if pt == nil {
				pt = safety.SyntheticSimPriceTable(provider)
			} else if !pt.IsSynthetic() {
				if err := pt.Validate(pt.Provider, pt.Region, cfg.Now()); err != nil {
					ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "InvalidPriceTable", err.Error())
				}
			}
			var err error
			meter, err = safety.NewCostMeter(safety.CostPolicy{
				CapUSD:            safety.DefaultCostCapUSD,
				CeilingUSD:        safety.HardCostCeilingUSD,
				CleanupReserveUSD: safety.DefaultCleanupReserveUSD,
			}, pt, nil)
			if err != nil {
				panic(fmt.Sprintf("cloudhost: failed to initialize default CostMeter: %v", err))
			}
		} else if pt := meter.Table(); pt != nil && !pt.IsSynthetic() {
			if err := pt.Validate(pt.Provider, pt.Region, cfg.Now()); err != nil {
				ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "InvalidPriceTable", err.Error())
			}
		}
		ct.meter = meter
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct
		}
		ct.syncFromSafetyJournalLocked()
		return ct
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(false, nil); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalCorrupt", err.Error())
		}
	}
	return ct
}

func ppidStartToken() string {
	ppid := os.Getppid()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", ppid))
	if err == nil {
		if rp := bytes.LastIndexByte(raw, ')'); rp >= 0 && rp+2 < len(raw) {
			fields := strings.Fields(string(raw[rp+2:]))
			if len(fields) > 19 {
				return fmt.Sprintf("ppid-%d-%s", ppid, fields[19])
			}
		}
	}
	return fmt.Sprintf("ppid-%d", ppid)
}

func defaultCampaignStatePath(provider string) (string, error) {
	stateDir := strings.TrimSpace(os.Getenv("LMCLOUD_STATE_DIR"))
	if stateDir == "" {
		stateDir = filepath.Join(os.TempDir(), fmt.Sprintf("lmcloud-state-%d", os.Getuid()))
	}
	cleanDir, err := safety.EnsureStateDir(stateDir)
	if err != nil {
		return "", err
	}

	var rawID string
	for _, k := range []string{"LMCLOUD_CAMPAIGN_ID", "LMCLOUD_RUN_ID", "LMAWS_RUN_ID", "LMCLOUD_SESSION_ID"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			rawID = k + "=" + v
			break
		}
	}
	if rawID == "" {
		rawID = ppidStartToken()
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		provider = "ref"
	}
	sum := sha256.Sum256([]byte(rawID + "\x00" + provider))
	hashHex := hex.EncodeToString(sum[:16])
	return filepath.Join(cleanDir, fmt.Sprintf("campaign-%s-%s.jsonl", provider, hashHex)), nil
}

func verifyCampaignParentDir(path string) error {
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("stat campaign parent dir %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("campaign parent %q must be a real directory, not a symlink", dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != os.Getuid() {
			return fmt.Errorf("campaign parent %q is owned by uid %d (want %d)", dir, st.Uid, os.Getuid())
		}
	}
	return nil
}

func openCampaignFileNoFollow(path string) (*os.File, bool, error) {
	created := false
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		created = true
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open campaign file %s: %w", path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, false, fmt.Errorf("fstat campaign file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, false, fmt.Errorf("campaign file %q must be a regular file", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != os.Getuid() {
			_ = f.Close()
			return nil, false, fmt.Errorf("campaign file %q owned by uid %d (want %d)", path, st.Uid, os.Getuid())
		}
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		_ = f.Close()
		return nil, false, fmt.Errorf("campaign file %q has permissions %04o; must not be group/world accessible (want 0600)", path, perm)
	}
	return f, created, nil
}

func syncCampaignDir(dir string) error {
	df, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open campaign dir %s: %w", dir, err)
	}
	defer df.Close()
	if err := df.Sync(); err != nil {
		return fmt.Errorf("fsync campaign dir %s: %w", dir, err)
	}
	return nil
}

func (ct *costTracker) defaultBillingUnits(op string, bytes int64) int64 {
	var units int64 = 1
	if pt := ct.meter.Table(); pt != nil {
		if t, ok := pt.Operations[op]; ok && t.ChunkBytes > 0 && bytes > t.ChunkBytes {
			units = (bytes + t.ChunkBytes - 1) / t.ChunkBytes
		}
	}
	return units
}

func (ct *costTracker) replayCampaignBytes(raw []byte) (*replayedCampaignState, error) {
	st := &replayedCampaignState{
		ops:           map[string]persistedOpCost{},
		activeBuckets: map[string]int64{},
		activeObjects: map[string]int64{},
		activeQueues:  map[string]int64{},
		pending:       map[string]campaignJournalRecord{},
	}
	if len(raw) == 0 {
		return st, nil
	}
	if raw[len(raw)-1] != '\n' {
		return nil, errors.New("corrupt campaign journal: incomplete trailing line")
	}
	lines := bytes.Split(raw, []byte{'\n'})
	for i, line := range lines {
		if i == len(lines)-1 && len(line) == 0 {
			continue
		}
		if len(bytes.TrimSpace(line)) == 0 {
			return nil, fmt.Errorf("corrupt campaign journal line %d: empty line", i+1)
		}
		var rec campaignJournalRecord
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("corrupt campaign journal line %d: %w", i+1, err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return nil, fmt.Errorf("corrupt campaign journal line %d: trailing data", i+1)
		}
		wantSeq := uint64(i + 1)
		if rec.Version != campaignJournalVersion || rec.Seq != wantSeq {
			return nil, fmt.Errorf("corrupt campaign journal line %d: version=%d seq=%d (want v=%d seq=%d)",
				i+1, rec.Version, rec.Seq, campaignJournalVersion, wantSeq)
		}
		if i == 0 && rec.Event != safety.EventMeta {
			return nil, fmt.Errorf("corrupt campaign journal: first record must be %q, got %q", safety.EventMeta, rec.Event)
		}
		st.lastSeq = rec.Seq
		switch rec.Event {
		case safety.EventMeta:
			if i != 0 {
				return nil, errors.New("corrupt campaign journal: duplicate meta record")
			}
		case safety.EventWorkCap:
			if rec.WorkCapNanoUSD <= 0 {
				return nil, errors.New("corrupt campaign journal: invalid work_cap_nano_usd")
			}
			if !st.hasWorkCap || rec.WorkCapNanoUSD < st.workCapNanoUSD {
				st.workCapNanoUSD = rec.WorkCapNanoUSD
				st.hasWorkCap = true
			}
		case safety.EventCapExceeded:
			st.capExceededCount++
		case safety.EventReserve:
			if err := safety.ValidateToken128(rec.AttemptID); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal reserve attempt_id: %w", err)
			}
			if rec.Operation == "" || rec.AttemptNanoUSD < 0 || rec.CleanupReserveNanoUSD < 0 || rec.ReservedBytes < 0 {
				return nil, errors.New("corrupt campaign journal reserve fields")
			}
			st.pending[rec.AttemptID] = rec
		case safety.EventSettle:
			if err := safety.ValidateToken128(rec.AttemptID); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal settle attempt_id: %w", err)
			}
			p, ok := st.pending[rec.AttemptID]
			if !ok {
				continue
			}
			delete(st.pending, rec.AttemptID)
			if rec.ChargedNanoUSD < 0 || rec.SettledBytes < 0 || rec.BillingUnits < 0 {
				return nil, errors.New("corrupt campaign journal negative settle fields")
			}
			if rec.BillingUnits == 0 && rec.ChargedNanoUSD == 0 && !rec.LockCleanup && !rec.ReleaseCleanup {
				// Released undispatched reservation (NotSent).
				continue
			}
			charge := rec.ChargedNanoUSD
			if charge > p.AttemptNanoUSD {
				charge = p.AttemptNanoUSD
			}
			st.chargedNanoUSD += charge
			cur := st.ops[p.Operation]
			cur.Requests++
			cur.BillingUnits += rec.BillingUnits
			cur.Bytes += rec.SettledBytes
			cur.ChargedNanoUSD += charge
			st.ops[p.Operation] = cur

			if rec.LockCleanup && p.CleanupReserveNanoUSD > 0 && p.ResKey != "" {
				switch p.ResKind {
				case safety.KindBucket:
					if _, exists := st.activeBuckets[p.ResKey]; !exists {
						st.activeBuckets[p.ResKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindObject:
					if _, exists := st.activeObjects[p.ResKey]; !exists {
						st.activeObjects[p.ResKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindQueue:
					if _, exists := st.activeQueues[p.ResKey]; !exists {
						st.activeQueues[p.ResKey] = p.CleanupReserveNanoUSD
					}
				}
			}
			if rec.ReleaseCleanup && p.ResKey != "" {
				switch p.ResKind {
				case safety.KindBucket:
					delete(st.activeBuckets, p.ResKey)
				case safety.KindObject:
					delete(st.activeObjects, p.ResKey)
				case safety.KindQueue:
					delete(st.activeQueues, p.ResKey)
				}
			}
		default:
			return nil, fmt.Errorf("corrupt campaign journal: unknown event %q", rec.Event)
		}
	}

	// Any unresolved pending reservation (in-flight in another process or crashed during dispatch)
	// is treated conservatively as committed spend and cleanup reserve.
	for _, p := range st.pending {
		st.chargedNanoUSD += p.AttemptNanoUSD
		cur := st.ops[p.Operation]
		cur.Requests++
		cur.BillingUnits += ct.defaultBillingUnits(p.Operation, p.ReservedBytes)
		cur.Bytes += p.ReservedBytes
		cur.ChargedNanoUSD += p.AttemptNanoUSD
		st.ops[p.Operation] = cur
		if p.CleanupReserveNanoUSD > 0 {
			st.resourceCleanupNanoUSD += p.CleanupReserveNanoUSD
		}
	}
	for _, v := range st.activeBuckets {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activeObjects {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activeQueues {
		st.resourceCleanupNanoUSD += v
	}
	return st, nil
}

func (ct *costTracker) applyReplayedStateLocked(st *replayedCampaignState) {
	ct.capExceededCount = st.capExceededCount
	ct.ops = st.ops
	ct.activeBuckets = st.activeBuckets
	ct.activeObjects = st.activeObjects
	ct.activeQueues = st.activeQueues
	workCap := int64(0)
	if st.hasWorkCap {
		workCap = st.workCapNanoUSD
	}
	ct.meter.SyncLedgerState(st.chargedNanoUSD, st.resourceCleanupNanoUSD, workCap)
}

func appendCampaignRecord(f *os.File, seq uint64, rec campaignJournalRecord) error {
	rec.Version = campaignJournalVersion
	rec.Seq = seq
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	n, err := f.Write(line)
	if err != nil {
		_ = f.Truncate(off)
		return err
	}
	if n != len(line) {
		_ = f.Truncate(off)
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		_ = f.Truncate(off)
		return err
	}
	return nil
}

func (ct *costTracker) withLockedCampaignJournal(createIfMissing bool, fn func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error) error {
	if ct.statePath == "" {
		return nil
	}
	if err := verifyCampaignParentDir(ct.statePath); err != nil {
		return err
	}
	pathMu := campaignPathMutex(ct.statePath)
	pathMu.Lock()
	defer pathMu.Unlock()

	if !createIfMissing {
		if _, err := os.Lstat(ct.statePath); errors.Is(err, os.ErrNotExist) {
			return nil
		}
	}

	lockPath := ct.statePath + ".lock"
	lf, lockCreated, err := openCampaignFileNoFollow(lockPath)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock campaign %s: %w", lockPath, err)
	}
	defer func() {
		_ = syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	}()

	f, fileCreated, err := openCampaignFileNoFollow(ct.statePath)
	if err != nil {
		return err
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("read campaign %s: %w", ct.statePath, err)
	}
	st, err := ct.replayCampaignBytes(raw)
	if err != nil {
		return err
	}
	ct.applyReplayedStateLocked(st)

	if fn != nil {
		appendFn := func(rec campaignJournalRecord) error {
			if st.lastSeq == 0 {
				if err := appendCampaignRecord(f, 1, campaignJournalRecord{
					Event:    safety.EventMeta,
					Provider: ct.provider,
				}); err != nil {
					return err
				}
				st.lastSeq = 1
			}
			nextSeq := st.lastSeq + 1
			if err := appendCampaignRecord(f, nextSeq, rec); err != nil {
				return err
			}
			st.lastSeq = nextSeq
			if fileCreated || lockCreated {
				if err := syncCampaignDir(filepath.Dir(ct.statePath)); err != nil {
					return err
				}
				fileCreated = false
				lockCreated = false
			}
			return nil
		}
		if err := fn(st, appendFn); err != nil {
			return err
		}
	}
	return nil
}

func (ct *costTracker) syncFromSafetyJournalLocked() {
	if ct.journal == nil {
		return
	}
	st := ct.journal.State()
	var activeCleanup int64
	pt := ct.meter.Table()
	for _, e := range st.Entries {
		if e.State == safety.StateDeleted {
			continue
		}
		if pt != nil {
			switch e.Kind {
			case safety.KindBucket:
				activeCleanup += pt.Operations["bucket_create"].CleanupReserveNanoUSD
			case safety.KindObject:
				activeCleanup += pt.Operations["object_put"].CleanupReserveNanoUSD
			case safety.KindQueue:
				activeCleanup += pt.Operations["queue_create"].CleanupReserveNanoUSD
			}
		}
	}
	charged := st.ChargedNanoUSD + st.ReservedNanoUSD
	ct.meter.SyncLedgerState(charged, activeCleanup, st.WorkCapNanoUSD)
	ct.capExceededCount = st.CapExceededCount
	ct.ops = make(map[string]persistedOpCost, len(st.OpStats))
	for op, stat := range st.OpStats {
		ct.ops[op] = persistedOpCost{
			Requests:       stat.Requests,
			BillingUnits:   stat.BillingUnits,
			Bytes:          stat.Bytes,
			ChargedNanoUSD: stat.ChargedNanoUSD,
		}
	}
}

func (ct *costTracker) reserve(in safety.AttemptPricingInput, resKind, resKey string) (*safety.AttemptReservation, string, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.poisoned != nil {
		return nil, "", ct.poisoned
	}
	if ct.delegatedToLiveGuard {
		return nil, "", nil
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return nil, "", ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		res, err := ct.meter.ReserveAttempt(in)
		if err != nil {
			if errors.Is(err, safety.ErrCostCapExceeded) {
				if jerr := ct.journal.RecordCapExceeded(in.Operation); jerr != nil {
					ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", jerr.Error())
					return nil, "", ct.poisoned
				}
				ct.capExceededCount++
				return nil, "", hostkit.ProviderError(hostkit.CostCapExceeded, 0, "CostCapExceeded", err.Error())
			}
			return nil, "", hostkit.ProviderError(hostkit.Internal, 0, "PricingFailure", err.Error())
		}
		reservedBytes := in.PayloadSize
		if in.Operation == "object_get" {
			reservedBytes = in.EgressBytes
		}
		reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD
		attID, jerr := ct.journal.BeginAttempt(resKind, "", resKey, in.Operation, reservedNano, reservedBytes)
		if jerr != nil {
			res.Release()
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", jerr.Error())
			return nil, "", ct.poisoned
		}
		return res, attID, nil
	}

	if ct.statePath != "" {
		var (
			res   *safety.AttemptReservation
			attID string
			cerr  *hostkit.CloudError
		)
		jerr := ct.withLockedCampaignJournal(true, func(_ *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			var rerr error
			res, rerr = ct.meter.ReserveAttempt(in)
			if rerr != nil {
				if errors.Is(rerr, safety.ErrCostCapExceeded) {
					if aerr := appendRec(campaignJournalRecord{
						Event:     safety.EventCapExceeded,
						Operation: in.Operation,
					}); aerr != nil {
						return aerr
					}
					ct.capExceededCount++
					cerr = hostkit.ProviderError(hostkit.CostCapExceeded, 0, "CostCapExceeded", rerr.Error())
					return nil
				}
				cerr = hostkit.ProviderError(hostkit.Internal, 0, "PricingFailure", rerr.Error())
				return nil
			}
			attID = safety.NewToken128()
			reservedBytes := in.PayloadSize
			if in.Operation == "object_get" {
				reservedBytes = in.EgressBytes
			}
			if aerr := appendRec(campaignJournalRecord{
				Event:                 safety.EventReserve,
				AttemptID:             attID,
				Operation:             in.Operation,
				ResKind:               resKind,
				ResKey:                resKey,
				IsCleanup:             in.IsCleanup,
				AttemptNanoUSD:        res.Quote().AttemptNanoUSD,
				CleanupReserveNanoUSD: res.Quote().CleanupReserveNanoUSD,
				ReservedBytes:         reservedBytes,
			}); aerr != nil {
				res.Release()
				res = nil
				attID = ""
				return aerr
			}
			return nil
		})
		if jerr != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", jerr.Error())
			return nil, "", ct.poisoned
		}
		if cerr != nil {
			return nil, "", cerr
		}
		return res, attID, nil
	}

	res, err := ct.meter.ReserveAttempt(in)
	if err != nil {
		if errors.Is(err, safety.ErrCostCapExceeded) {
			ct.capExceededCount++
			return nil, "", hostkit.ProviderError(hostkit.CostCapExceeded, 0, "CostCapExceeded", err.Error())
		}
		return nil, "", hostkit.ProviderError(hostkit.Internal, 0, "PricingFailure", err.Error())
	}
	return res, "", nil
}

func (ct *costTracker) release(res *safety.AttemptReservation, attemptID string) *hostkit.CloudError {
	if res == nil {
		return nil
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()

	res.Release()
	if ct.journal != nil && attemptID != "" {
		if err := ct.journal.SettleAttemptWithDetails(attemptID, 0, 0, 0, true); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
	}
	if ct.statePath != "" && attemptID != "" {
		if err := ct.withLockedCampaignJournal(true, func(_ *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			return appendRec(campaignJournalRecord{
				Event:     safety.EventSettle,
				AttemptID: attemptID,
			})
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
	}
	return nil
}

func (ct *costTracker) settle(res *safety.AttemptReservation, attemptID, op string, chargeBytes, reportedBytes int64, resKind, resKey string, cleanSuccess, opSucceeded bool) *hostkit.CloudError {
	if res == nil {
		return nil
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()

	pt := ct.meter.Table()
	var actualNano int64 = -1
	var units int64 = 1
	if !cleanSuccess {
		// Ambiguous or interrupted transfer: preserve the full reserved quote.
		actualNano = res.Quote().AttemptNanoUSD
		if pt != nil {
			if t, ok := pt.Operations[op]; ok && t.ChunkBytes > 0 && chargeBytes > t.ChunkBytes {
				units = (chargeBytes + t.ChunkBytes - 1) / t.ChunkBytes
			}
		}
	} else if pt != nil {
		t, ok := pt.Operations[op]
		if !ok && op == "object_list_all" {
			t, ok = pt.Operations["object_list"]
		}
		if ok {
			if t.ChunkBytes > 0 && chargeBytes > t.ChunkBytes {
				units = (chargeBytes + t.ChunkBytes - 1) / t.ChunkBytes
			}
			in := safety.AttemptPricingInput{
				Operation: op,
				IsCleanup: res.Quote().IsCleanup,
			}
			if op == "object_get" {
				in.EgressBytes = chargeBytes
			} else {
				in.PayloadSize = chargeBytes
			}
			if q, err := ct.meter.QuoteAttempt(in); err == nil {
				actualNano = q.AttemptNanoUSD
			}
		}
	}

	if ct.journal != nil {
		charged := res.Commit(actualNano, opSucceeded && res.Quote().CleanupReserveNanoUSD > 0)
		if err := ct.journal.SettleAttemptWithDetails(attemptID, charged, reportedBytes, units, cleanSuccess); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return nil
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			lockCleanup := false
			releaseCleanup := false
			if opSucceeded {
				switch op {
				case "bucket_create":
					if _, exists := st.activeBuckets[resKey]; !exists {
						lockCleanup = true
					}
				case "object_put":
					if _, exists := st.activeObjects[resKey]; !exists {
						lockCleanup = true
					}
				case "queue_create":
					if _, exists := st.activeQueues[resKey]; !exists {
						lockCleanup = true
					}
				case "bucket_delete":
					if _, exists := st.activeBuckets[resKey]; exists {
						releaseCleanup = true
					}
				case "object_delete":
					if _, exists := st.activeObjects[resKey]; exists {
						releaseCleanup = true
					}
				case "queue_delete":
					if _, exists := st.activeQueues[resKey]; exists {
						releaseCleanup = true
					}
				}
			}
			charged := res.Commit(actualNano, lockCleanup)
			if err := appendRec(campaignJournalRecord{
				Event:          safety.EventSettle,
				AttemptID:      attemptID,
				Operation:      op,
				ChargedNanoUSD: charged,
				SettledBytes:   reportedBytes,
				BillingUnits:   units,
				LockCleanup:    lockCleanup,
				ReleaseCleanup: releaseCleanup,
			}); err != nil {
				return err
			}
			delete(st.pending, attemptID)
			st.chargedNanoUSD += charged
			cur := st.ops[op]
			cur.Requests++
			cur.BillingUnits += units
			cur.Bytes += reportedBytes
			cur.ChargedNanoUSD += charged
			st.ops[op] = cur
			if lockCleanup && res.Quote().CleanupReserveNanoUSD > 0 {
				switch resKind {
				case safety.KindBucket:
					st.activeBuckets[resKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindObject:
					st.activeObjects[resKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindQueue:
					st.activeQueues[resKey] = res.Quote().CleanupReserveNanoUSD
				}
				st.resourceCleanupNanoUSD += res.Quote().CleanupReserveNanoUSD
			}
			if releaseCleanup {
				switch resKind {
				case safety.KindBucket:
					if v, ok := st.activeBuckets[resKey]; ok {
						delete(st.activeBuckets, resKey)
						st.resourceCleanupNanoUSD -= v
					}
				case safety.KindObject:
					if v, ok := st.activeObjects[resKey]; ok {
						delete(st.activeObjects, resKey)
						st.resourceCleanupNanoUSD -= v
					}
				case safety.KindQueue:
					if v, ok := st.activeQueues[resKey]; ok {
						delete(st.activeQueues, resKey)
						st.resourceCleanupNanoUSD -= v
					}
				}
			}
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}

	lockCleanup := false
	if opSucceeded {
		switch op {
		case "bucket_create":
			if _, exists := ct.activeBuckets[resKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeBuckets[resKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "object_put":
			if _, exists := ct.activeObjects[resKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeObjects[resKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "queue_create":
			if _, exists := ct.activeQueues[resKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeQueues[resKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		}
	}

	charged := res.Commit(actualNano, lockCleanup)

	if opSucceeded {
		switch op {
		case "bucket_delete":
			if v, exists := ct.activeBuckets[resKey]; exists {
				delete(ct.activeBuckets, resKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		case "object_delete":
			if v, exists := ct.activeObjects[resKey]; exists {
				delete(ct.activeObjects, resKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		case "queue_delete":
			if v, exists := ct.activeQueues[resKey]; exists {
				delete(ct.activeQueues, resKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		}
	}

	cur := ct.ops[op]
	cur.Requests++
	cur.BillingUnits += units
	cur.Bytes += reportedBytes
	cur.ChargedNanoUSD += charged
	ct.ops[op] = cur
	return nil
}

func (ct *costTracker) lockResourceCleanupIfNeeded(op, resKind, resKey string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.delegatedToLiveGuard || ct.meter == nil || ct.meter.Table() == nil {
		return
	}
	resNano := ct.meter.Table().Operations[op].CleanupReserveNanoUSD
	if resNano <= 0 {
		return
	}
	if ct.statePath != "" {
		_ = ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			switch resKind {
			case safety.KindBucket:
				if _, ok := st.activeBuckets[resKey]; ok {
					return nil
				}
			case safety.KindQueue:
				if _, ok := st.activeQueues[resKey]; ok {
					return nil
				}
			default:
				return nil
			}
			attID := safety.NewToken128()
			if err := appendRec(campaignJournalRecord{
				Event:                 safety.EventReserve,
				AttemptID:             attID,
				Operation:             op,
				ResKind:               resKind,
				ResKey:                resKey,
				CleanupReserveNanoUSD: resNano,
			}); err != nil {
				return err
			}
			return appendRec(campaignJournalRecord{
				Event:       safety.EventSettle,
				AttemptID:   attID,
				Operation:   op,
				LockCleanup: true,
			})
		})
		return
	}
	switch resKind {
	case safety.KindBucket:
		if _, exists := ct.activeBuckets[resKey]; !exists {
			ct.activeBuckets[resKey] = resNano
			ct.meter.RestoreCharged(0, ct.meter.Snapshot().ResourceCleanupNanoUSD+resNano)
		}
	case safety.KindQueue:
		if _, exists := ct.activeQueues[resKey]; !exists {
			ct.activeQueues[resKey] = resNano
			ct.meter.RestoreCharged(0, ct.meter.Snapshot().ResourceCleanupNanoUSD+resNano)
		}
	}
}

func (ct *costTracker) costCapUSD() float64 {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.unconfiguredLive || ct.meter == nil {
		return 0
	}
	if ct.journal != nil {
		ct.syncFromSafetyJournalLocked()
	} else if ct.statePath != "" && ct.poisoned == nil {
		_ = ct.withLockedCampaignJournal(false, nil)
	}
	snap := ct.meter.Snapshot()
	return safety.NanoToUSD(snap.ActiveCapNanoUSD)
}

func (ct *costTracker) estimatedCostUSD() float64 {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.unconfiguredLive || ct.meter == nil {
		return 0
	}
	if ct.journal != nil {
		ct.syncFromSafetyJournalLocked()
	} else if ct.statePath != "" && ct.poisoned == nil {
		_ = ct.withLockedCampaignJournal(false, nil)
	}
	snap := ct.meter.Snapshot()
	return safety.NanoToUSD(snap.ChargedNanoUSD)
}

func (ct *costTracker) setWorkCapUSD(capUSD float64) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.poisoned != nil {
		return ct.poisoned
	}
	if ct.delegatedToLiveGuard {
		return ct.liveGuard.SetWorkCapUSD(capUSD)
	}
	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if err := ct.meter.SetWorkCapUSD(capUSD); err != nil {
			return hostkit.Preflightf("set_cost_cap_usd: %v", err)
		}
		snap := ct.meter.Snapshot()
		if err := ct.journal.RecordWorkCap(snap.ScriptWorkCapNanoUSD); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		if ct.onSetWorkCap != nil {
			if err := ct.onSetWorkCap(snap.ScriptWorkCapNanoUSD); err != nil {
				ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
				return ct.poisoned
			}
		}
		return nil
	}

	if ct.statePath != "" {
		var cerr *hostkit.CloudError
		jerr := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if err := ct.meter.SetWorkCapUSD(capUSD); err != nil {
				cerr = hostkit.Preflightf("set_cost_cap_usd: %v", err)
				return nil
			}
			snap := ct.meter.Snapshot()
			if err := appendRec(campaignJournalRecord{
				Event:          safety.EventWorkCap,
				WorkCapNanoUSD: snap.ScriptWorkCapNanoUSD,
			}); err != nil {
				return err
			}
			if ct.onSetWorkCap != nil {
				if err := ct.onSetWorkCap(snap.ScriptWorkCapNanoUSD); err != nil {
					return err
				}
			}
			st.workCapNanoUSD = snap.ScriptWorkCapNanoUSD
			st.hasWorkCap = true
			return nil
		})
		if jerr != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", jerr.Error())
			return ct.poisoned
		}
		return cerr
	}

	if err := ct.meter.SetWorkCapUSD(capUSD); err != nil {
		return hostkit.Preflightf("set_cost_cap_usd: %v", err)
	}
	snap := ct.meter.Snapshot()
	if ct.onSetWorkCap != nil {
		if err := ct.onSetWorkCap(snap.ScriptWorkCapNanoUSD); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
	}
	return nil
}

func (ct *costTracker) report() CostReport {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.unconfiguredLive || ct.meter == nil {
		return CostReport{
			Provider:          ct.provider,
			PriceTableVersion: "",
			byOp:              map[string]CostLineItem{},
		}
	}

	if ct.journal != nil {
		ct.syncFromSafetyJournalLocked()
	} else if ct.statePath != "" && ct.poisoned == nil {
		if err := ct.withLockedCampaignJournal(false, nil); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalCorrupt", err.Error())
		}
	}

	snap := ct.meter.Snapshot()
	pt := ct.meter.Table()
	ver := ""
	if pt != nil {
		ver = pt.VersionID()
	}

	names := make([]string, 0, len(ct.ops))
	for op, st := range ct.ops {
		if st.Requests > 0 {
			names = append(names, op)
		}
	}
	sort.Strings(names)

	items := make([]CostLineItem, 0, len(names))
	byOp := make(map[string]CostLineItem, len(names))
	var totalReqs, totalUnits, totalBytes int64
	for _, op := range names {
		st := ct.ops[op]
		it := buildCostLineItem(pt, op, st)
		items = append(items, it)
		byOp[op] = it
		totalReqs += it.Requests
		totalUnits += it.BillingUnits
		totalBytes += it.Bytes
	}

	return CostReport{
		Provider:          ct.provider,
		PriceTableVersion: ver,
		CapUSD:            safety.NanoToUSD(snap.ActiveCapNanoUSD),
		CeilingUSD:        safety.NanoToUSD(snap.CeilingNanoUSD),
		EstimatedUSD:      safety.NanoToUSD(snap.ChargedNanoUSD),
		TotalRequests:     totalReqs,
		TotalUnits:        totalUnits,
		TotalBytes:        totalBytes,
		CapExceededCount:  ct.capExceededCount,
		Items:             items,
		byOp:              byOp,
		table:             pt,
	}
}

// attemptScope tracks reservations and retry/throttle counts across a single
// physical adapter call (which may execute multiple attempts via RetryPolicy.Do).
type attemptScope struct {
	ct              *costTracker
	op              string
	in              safety.AttemptPricingInput
	resKind         string
	resKey          string
	res             *safety.AttemptReservation
	attemptID       string
	initialConsumed bool
	lastAttempt     hostkit.Attempt
	hasLastAttempt  bool
	abortErr        *hostkit.CloudError
	retries         int64
	throttles       int64
}

func (s *attemptScope) settlePreviousAttemptLocked() *hostkit.CloudError {
	if s.res == nil {
		return nil
	}
	res := s.res
	attID := s.attemptID
	s.res = nil
	s.attemptID = ""

	if s.hasLastAttempt && s.lastAttempt.NotSent {
		return s.ct.release(res, attID)
	}
	if s.op == "object_put" || s.op == "queue_send" {
		return s.ct.settle(res, attID, s.op, s.in.PayloadSize, s.in.PayloadSize, s.resKind, s.resKey, false, false)
	}
	if s.hasLastAttempt && s.lastAttempt.Err == nil {
		// HTTP status response without stream transfer failure (e.g. 429/503 status header, or completed first Do).
		return s.ct.settle(res, attID, s.op, 0, 0, s.resKind, s.resKey, true, false)
	}
	// Mid-stream or ambiguous transport failure: preserve full reserved bound.
	boundBytes := s.in.PayloadSize
	if s.op == "object_get" {
		boundBytes = s.in.EgressBytes
	}
	return s.ct.settle(res, attID, s.op, boundBytes, boundBytes, s.resKind, s.resKey, false, false)
}

func (h *Host) beginAttemptScope(ctx context.Context, op string, in safety.AttemptPricingInput, resKind, resKey string) (context.Context, *attemptScope, *hostkit.CloudError) {
	res, attID, cerr := h.cost.reserve(in, resKind, resKey)
	if cerr != nil {
		return ctx, nil, cerr
	}
	scope := &attemptScope{
		ct:        h.cost,
		op:        op,
		in:        in,
		resKind:   resKind,
		resKey:    resKey,
		res:       res,
		attemptID: attID,
	}
	ctxWithHooks := hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{
		BeforeAttempt: func(_ context.Context, attempt int) error {
			if scope.abortErr != nil {
				return scope.abortErr
			}
			if !scope.initialConsumed {
				scope.initialConsumed = true
				return nil
			}
			if scerr := scope.settlePreviousAttemptLocked(); scerr != nil {
				scope.abortErr = scerr
				return scerr
			}
			nextRes, nextAttID, cerr := scope.ct.reserve(scope.in, scope.resKind, scope.resKey)
			if cerr != nil {
				scope.abortErr = cerr
				return cerr
			}
			if attempt > 0 {
				scope.retries++
			}
			scope.res = nextRes
			scope.attemptID = nextAttID
			scope.hasLastAttempt = false
			return nil
		},
		AfterAttempt: func(callCtx context.Context, attempt int, a hostkit.Attempt) {
			scope.lastAttempt = a
			scope.hasLastAttempt = true
			if a.Status == 429 {
				scope.throttles++
			}
			if a.NotSent && a.Err != nil && (errors.Is(a.Err, context.Canceled) || errors.Is(a.Err, context.DeadlineExceeded) || (callCtx != nil && callCtx.Err() != nil) || ctx.Err() != nil) && scope.res != nil {
				if attempt > 0 && scope.retries > 0 {
					scope.retries--
				}
				if rerr := scope.ct.release(scope.res, scope.attemptID); rerr != nil && scope.abortErr == nil {
					scope.abortErr = rerr
				}
				scope.res = nil
				scope.attemptID = ""
			}
		},
	})
	return ctxWithHooks, scope, nil
}

func (s *attemptScope) finish(chargeBytes, reportedBytes int64, cleanSuccess, opSucceeded bool) (retries, throttles int64, abortErr *hostkit.CloudError) {
	if s == nil {
		return 0, 0, nil
	}
	if s.res != nil {
		if scerr := s.ct.settle(s.res, s.attemptID, s.op, chargeBytes, reportedBytes, s.resKind, s.resKey, cleanSuccess, opSucceeded); scerr != nil && s.abortErr == nil {
			s.abortErr = scerr
		}
		s.res = nil
		s.attemptID = ""
	}
	return s.retries, s.throttles, s.abortErr
}

// ---- Performance Metrics Tracker ----

type opMetricAccum struct {
	calls     int64
	errors    int64
	retries   int64
	throttles int64
	bytesIn   int64
	bytesOut  int64
	minNS     int64
	maxNS     int64
	totalNS   int64
	samples   []int64
}

func (a *opMetricAccum) record(dur time.Duration, failed bool, retries, throttles, bytesIn, bytesOut int64) {
	ns := dur.Nanoseconds()
	if ns < 0 {
		ns = 0
	}
	a.calls++
	if failed {
		a.errors++
	}
	a.retries += retries
	a.throttles += throttles
	a.bytesIn += bytesIn
	a.bytesOut += bytesOut
	if a.calls == 1 || ns < a.minNS {
		a.minNS = ns
	}
	if a.calls == 1 || ns > a.maxNS {
		a.maxNS = ns
	}
	a.totalNS += ns
	if len(a.samples) < MaxLatencySamplesPerOp {
		a.samples = append(a.samples, ns)
	} else {
		idx := int((a.calls - 1) % MaxLatencySamplesPerOp)
		a.samples[idx] = ns
	}
}

func (a *opMetricAccum) snapshot(op string) OpMetrics {
	if a == nil || a.calls == 0 {
		return OpMetrics{Operation: op}
	}
	w := len(a.samples)
	sorted := make([]int64, w)
	copy(sorted, a.samples)
	slices.Sort(sorted)

	idx50 := max(0, min(w-1, int(math.Ceil(0.50*float64(w)))-1))
	idx95 := max(0, min(w-1, int(math.Ceil(0.95*float64(w)))-1))

	minMS := float64(a.minNS) / 1e6
	p50MS := float64(sorted[idx50]) / 1e6
	p95MS := float64(sorted[idx95]) / 1e6
	maxMS := float64(a.maxNS) / 1e6
	totalMS := float64(a.totalNS) / 1e6
	meanMS := totalMS / float64(a.calls)

	return OpMetrics{
		Operation: op,
		Calls:     a.calls,
		Errors:    a.errors,
		Retries:   a.retries,
		Throttles: a.throttles,
		BytesIn:   a.bytesIn,
		BytesOut:  a.bytesOut,
		MinMS:     minMS,
		P50MS:     p50MS,
		P95MS:     p95MS,
		MaxMS:     maxMS,
		MeanMS:    meanMS,
		TotalMS:   totalMS,
	}
}

type metricsTracker struct {
	mu      sync.Mutex
	now     func() time.Time
	resetAt time.Time
	ops     map[string]*opMetricAccum
}

func newMetricsTracker(now func() time.Time) *metricsTracker {
	if now == nil {
		now = time.Now
	}
	return &metricsTracker{
		now:     now,
		resetAt: now(),
		ops:     map[string]*opMetricAccum{},
	}
}

func (mt *metricsTracker) reset() {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	mt.resetAt = mt.now()
	mt.ops = map[string]*opMetricAccum{}
}

func (mt *metricsTracker) record(op string, dur time.Duration, failed bool, retries, throttles, bytesIn, bytesOut int64) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	acc := mt.ops[op]
	if acc == nil {
		acc = &opMetricAccum{}
		mt.ops[op] = acc
	}
	acc.record(dur, failed, retries, throttles, bytesIn, bytesOut)
}

func (mt *metricsTracker) report() MetricsReport {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	elapsedNS := mt.now().Sub(mt.resetAt).Nanoseconds()
	if elapsedNS < 0 {
		elapsedNS = 0
	}
	names := make([]string, 0, len(mt.ops))
	for op, acc := range mt.ops {
		if acc.calls > 0 {
			names = append(names, op)
		}
	}
	sort.Strings(names)

	ops := make([]OpMetrics, 0, len(names))
	byOp := make(map[string]OpMetrics, len(names))
	var totalCalls, totalErrors, totalRetries, totalThrottles, totalBytesIn, totalBytesOut int64
	for _, op := range names {
		snap := mt.ops[op].snapshot(op)
		ops = append(ops, snap)
		byOp[op] = snap
		totalCalls += snap.Calls
		totalErrors += snap.Errors
		totalRetries += snap.Retries
		totalThrottles += snap.Throttles
		totalBytesIn += snap.BytesIn
		totalBytesOut += snap.BytesOut
	}

	return MetricsReport{
		ElapsedMS:      float64(elapsedNS) / 1e6,
		TotalCalls:     totalCalls,
		TotalErrors:    totalErrors,
		TotalRetries:   totalRetries,
		TotalThrottles: totalThrottles,
		TotalBytesIn:   totalBytesIn,
		TotalBytesOut:  totalBytesOut,
		Ops:            ops,
		byOp:           byOp,
	}
}

// ---- Host Cost & Performance Public Methods ----

// CostCapUSD returns the active cost cap in USD without modifying last_error().
func (h *Host) CostCapUSD() float64 {
	return h.cost.costCapUSD()
}

// SetCostCapUSD narrows the active script work sub-cap in USD within the
// durable operator total ceiling. Invalid or non-monotone values fail pre-flight
// with ErrorCode.INVALID_ARGUMENT without modifying the active cap.
func (h *Host) SetCostCapUSD(capUSD float64) error {
	if e := h.cost.setWorkCapUSD(capUSD); e != nil {
		return h.fail("set_cost_cap_usd", fmt.Sprintf("%g", capUSD), e)
	}
	h.ok()
	return nil
}

// EstimatedCost returns cumulative settled cost in USD without modifying last_error().
func (h *Host) EstimatedCost() float64 {
	return h.cost.estimatedCostUSD()
}

// CostReport returns an immutable CostReport snapshot without modifying last_error().
func (h *Host) CostReport() CostReport {
	return h.cost.report()
}

// MetricsReset clears performance telemetry counters and latency samples and
// restarts the elapsed_ms() timer without modifying estimated_cost(),
// cost_report(), or last_error().
func (h *Host) MetricsReset() {
	h.metrics.reset()
}

// Metrics returns an immutable MetricsReport snapshot without modifying last_error().
func (h *Host) Metrics() MetricsReport {
	return h.metrics.report()
}

// RecordSyntheticMetricSample records a synthetic operation observation into the
// host's MetricsTracker (used by acceptance tests to exercise >10,000 sample
// ring-buffer wraparound deterministically).
func (h *Host) RecordSyntheticMetricSample(op string, dur time.Duration, failed bool, retries, throttles, bytesIn, bytesOut int64) {
	h.metrics.record(op, dur, failed, retries, throttles, bytesIn, bytesOut)
}
