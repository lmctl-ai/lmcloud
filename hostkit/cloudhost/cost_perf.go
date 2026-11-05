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
	"strconv"
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

	// maxNonCleanupJournalBytes reserves 4 MiB of journal file headroom below
	// safety.MaxJournalFileBytes (64 MiB) so cleanup/delete and settlement
	// records can always be appended even after non-cleanup work is refused.
	maxNonCleanupJournalBytes = safety.MaxJournalFileBytes - (4 << 20)
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
	case op == "principal_current", strings.HasPrefix(op, "policy_"):
		return "permissions"
	case strings.HasPrefix(op, "function_"):
		return "function"
	case strings.HasPrefix(op, "userpool_"), strings.HasPrefix(op, "user_"), strings.HasPrefix(op, "group_"):
		return "userpool"
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
	Version                  int    `json:"v"`
	Seq                      uint64 `json:"seq"`
	Event                    string `json:"event"`
	Provider                 string `json:"provider,omitempty"`
	Region                   string `json:"region,omitempty"`
	Scope                    string `json:"scope,omitempty"`
	Endpoint                 string `json:"endpoint,omitempty"`
	PriceTableVersion        string `json:"price_table_version,omitempty"`
	PriceTableHash           string `json:"price_table_hash,omitempty"`
	PolicyHash               string `json:"policy_hash,omitempty"`
	CapNanoUSD               int64  `json:"cap_nano_usd,omitempty"`
	CeilingNanoUSD           int64  `json:"ceiling_nano_usd,omitempty"`
	MaxCleanupReserveNanoUSD int64  `json:"max_cleanup_reserve_nano_usd,omitempty"`
	AttemptID                string `json:"attempt_id,omitempty"`
	Operation                string `json:"operation,omitempty"`
	ResKind                  string `json:"res_kind,omitempty"`
	ResKey                   string `json:"res_key,omitempty"`
	IsCleanup                bool   `json:"is_cleanup,omitempty"`
	AttemptNanoUSD           int64  `json:"attempt_nano_usd,omitempty"`
	CleanupReserveNanoUSD    int64  `json:"cleanup_reserve_nano_usd,omitempty"`
	ReservedBytes            int64  `json:"reserved_bytes,omitempty"`
	ChargedNanoUSD           int64                      `json:"charged_nano_usd,omitempty"`
	OpStats                  map[string]persistedOpCost `json:"op_stats,omitempty"`
	SettledBytes             int64                      `json:"settled_bytes,omitempty"`
	BillingUnits             int64  `json:"billing_units,omitempty"`
	LockCleanup              bool   `json:"lock_cleanup,omitempty"`
	ReleaseCleanup           bool   `json:"release_cleanup,omitempty"`
	WorkCapNanoUSD           int64  `json:"work_cap_nano_usd,omitempty"`
	PolicyScope              string `json:"policy_scope,omitempty"`
	PolicyKind               string `json:"policy_kind,omitempty"`
	PolicyTarget             string `json:"policy_target,omitempty"`
	PolicyPrincipal          string `json:"policy_principal,omitempty"`
	PolicyDocument           string `json:"policy_document,omitempty"`
	PolicyIntentOp           string `json:"policy_intent_op,omitempty"`
	OwnerToken               string `json:"owner_token,omitempty"`
	Generation               string `json:"generation,omitempty"`
	IntentID                 string `json:"intent_id,omitempty"`
	ExpectedOwnerToken       string `json:"expected_owner_token,omitempty"`
	ExpectedGeneration       string `json:"expected_generation,omitempty"`
	FunctionDigest           string `json:"function_digest,omitempty"`
	FunctionState            string `json:"function_state,omitempty"`
	UserpoolIncarnation      string `json:"userpool_incarnation,omitempty"`
	UserpoolState            string `json:"userpool_state,omitempty"`
}

type replayedCampaignState struct {
	lastSeq                uint64
	journalFileBytes       int
	chargedNanoUSD         int64
	resourceCleanupNanoUSD int64
	workCapNanoUSD         int64
	hasWorkCap             bool
	capExceededCount       int64
	ops                    map[string]persistedOpCost
	activeBuckets          map[string]int64
	activeObjects          map[string]int64
	activeQueues           map[string]int64
	activeTables           map[string]int64
	activeItems            map[string]int64
	activePolicies         map[string]hostkit.PolicyAttachment
	ambiguousPolicies      map[string]hostkit.PolicyAttachment
	ambiguousStack         map[string][]hostkit.PolicyAttachment
	policyOwnerTokens      map[string]string
	maxPolicyGen           map[string]uint64
	latestPolicyIntent     map[string]string
	policyCleanup          map[string]int64
	activeFunctions        map[string]int64
	activeFunctionVersions map[string]int64
	activeFunctionAliases  map[string]int64
	activeFunctionEntries  map[string]safety.JournalFunctionEntry
	ambiguousFunctions     map[string]safety.JournalFunctionEntry
	ambiguousFunctionStack map[string][]safety.JournalFunctionEntry
	functionOwnerTokens    map[string]string
	maxFunctionGen         map[string]uint64
	latestFunctionIntent   map[string]string
	activeUserpools        map[string]int64
	activePoolUsers        map[string]int64
	activePoolGroups       map[string]int64
	activePoolMemberships  map[string]int64
	activeUserpoolEntries  map[string]safety.JournalUserpoolEntry
	ambiguousUserpools     map[string]safety.JournalUserpoolEntry
	ambiguousUserpoolStack map[string][]safety.JournalUserpoolEntry
	userpoolOwnerTokens    map[string]string
	maxUserpoolGen         map[string]uint64
	latestUserpoolIntent   map[string]string
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

type liveTablesOwnershipProvider interface {
	LiveTablesGuard() *safety.LiveGuard
}

func extractStoreLiveGuard(store hostkit.ObjectStore) *safety.LiveGuard {
	if gs, ok := store.(guardStore); ok {
		store = gs.s
	}
	if lp, ok := store.(liveGuardProvider); ok && lp.LiveGuard() != nil {
		return lp.LiveGuard()
	}
	return nil
}

func extractQueueLiveGuard(queue hostkit.Queue) *safety.LiveGuard {
	if gq, ok := queue.(guardQueue); ok {
		queue = gq.q
	}
	if lp, ok := queue.(liveGuardProvider); ok && lp.LiveGuard() != nil {
		return lp.LiveGuard()
	}
	return nil
}

func extractTablesLiveGuard(tables hostkit.Tables) *safety.LiveGuard {
	if gt, ok := tables.(guardTables); ok {
		tables = gt.t
	}
	if lp, ok := tables.(liveTablesOwnershipProvider); ok && lp.LiveTablesGuard() != nil {
		return lp.LiveTablesGuard()
	}
	return nil
}

type costTracker struct {
	mu                     sync.Mutex
	provider               string
	scope                  string
	meter                  *safety.CostMeter
	journal                *safety.Journal
	liveGuard              *safety.LiveGuard
	storeDelegated         bool
	queueDelegated         bool
	tablesDelegated        bool
	liveMode               bool
	unconfiguredLive       bool
	poisoned               *hostkit.CloudError
	statePath              string
	onSetWorkCap           func(workCapNanoUSD int64) error
	onToken                func(token string)
	capExceededCount       int64
	ops                    map[string]persistedOpCost
	activeBuckets          map[string]int64
	activeObjects          map[string]int64
	activeQueues           map[string]int64
	activeTables           map[string]int64
	activeItems            map[string]int64
	activePolicies         map[string]hostkit.PolicyAttachment
	ambiguousPolicies      map[string]hostkit.PolicyAttachment
	ambiguousStack         map[string][]hostkit.PolicyAttachment
	policyOwnerTokens      map[string]string
	maxPolicyGen           map[string]uint64
	latestPolicyIntent     map[string]string
	policyCleanup          map[string]int64
	activeFunctions        map[string]int64
	activeFunctionVersions map[string]int64
	activeFunctionAliases  map[string]int64
	activeFunctionEntries  map[string]safety.JournalFunctionEntry
	ambiguousFunctions     map[string]safety.JournalFunctionEntry
	ambiguousFunctionStack map[string][]safety.JournalFunctionEntry
	functionOwnerTokens    map[string]string
	maxFunctionGen         map[string]uint64
	latestFunctionIntent   map[string]string
	activeUserpools        map[string]int64
	activePoolUsers        map[string]int64
	activePoolGroups       map[string]int64
	activePoolMemberships  map[string]int64
	activeUserpoolEntries  map[string]safety.JournalUserpoolEntry
	ambiguousUserpools     map[string]safety.JournalUserpoolEntry
	ambiguousUserpoolStack map[string][]safety.JournalUserpoolEntry
	userpoolOwnerTokens    map[string]string
	maxUserpoolGen         map[string]uint64
	latestUserpoolIntent   map[string]string
	inFlightAttempts       map[string]bool
	verifiedCampaignRaw    []byte
	verifiedCampaignRecs   []campaignJournalRecord
}

func scopedResKey(endpoint, resKey string) string {
	if resKey == "" || endpoint == "" {
		return resKey
	}
	return endpoint + "\x00" + resKey
}

func journalAttemptName(resKey string) string {
	if resKey == "" {
		return ""
	}
	return strings.ReplaceAll(resKey, "\x00", "|")
}

func isKnownProvider(p string) bool {
	switch p {
	case "ref", "aws", "azure", "gcp", "oci":
		return true
	default:
		return false
	}
}

func isTablesOp(op, resKind string) bool {
	if resKind == safety.KindTable || resKind == safety.KindTableItem {
		return true
	}
	return strings.HasPrefix(op, "table_") || strings.HasPrefix(op, "item_")
}

func isPermissionsOp(op, resKind string) bool {
	if resKind == safety.KindPolicyAttachment {
		return true
	}
	return op == "principal_current" || strings.HasPrefix(op, "policy_")
}

func isFunctionOp(op, resKind string) bool {
	if resKind == safety.KindFunction || resKind == safety.KindFunctionVersion || resKind == safety.KindFunctionAlias {
		return true
	}
	return strings.HasPrefix(op, "function_")
}

func isUserpoolOp(op, resKind string) bool {
	if resKind == safety.KindUserpool || resKind == safety.KindPoolUser || resKind == safety.KindPoolGroup || resKind == safety.KindPoolMembership {
		return true
	}
	return strings.HasPrefix(op, "userpool_") || strings.HasPrefix(op, "user_") || strings.HasPrefix(op, "group_")
}

func hasFunctionChildren(activeVersions, activeAliases map[string]int64, scopedFunc string) bool {
	if scopedFunc == "" {
		return false
	}
	prefix := scopedFunc + "/"
	for k := range activeVersions {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	for k := range activeAliases {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func hasUserpoolChildren(activeUsers, activeGroups, activeMemberships map[string]int64, scopedPool string) bool {
	if scopedPool == "" {
		return false
	}
	prefix := scopedPool + "/"
	for k := range activeUsers {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	for k := range activeGroups {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	for k := range activeMemberships {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func hasJournalUserpoolChildren(activeCleanup map[string]int64, endpoint, pool string) bool {
	if pool == "" || len(activeCleanup) == 0 {
		return false
	}
	uPref := safety.KindPoolUser + "\x00" + endpoint + "\x00" + pool + "/"
	uPrefUnscoped := safety.KindPoolUser + "\x00\x00" + pool + "/"
	uParent := safety.KindPoolUser + "\x00" + pool + "\x00"
	gPref := safety.KindPoolGroup + "\x00" + endpoint + "\x00" + pool + "/"
	gPrefUnscoped := safety.KindPoolGroup + "\x00\x00" + pool + "/"
	gParent := safety.KindPoolGroup + "\x00" + pool + "\x00"
	mPref := safety.KindPoolMembership + "\x00" + endpoint + "\x00" + pool + "/"
	mPrefUnscoped := safety.KindPoolMembership + "\x00\x00" + pool + "/"
	mParent := safety.KindPoolMembership + "\x00" + pool + "\x00"
	for k := range activeCleanup {
		if strings.HasPrefix(k, uPref) || strings.HasPrefix(k, uPrefUnscoped) || strings.HasPrefix(k, uParent) ||
			strings.HasPrefix(k, gPref) || strings.HasPrefix(k, gPrefUnscoped) || strings.HasPrefix(k, gParent) ||
			strings.HasPrefix(k, mPref) || strings.HasPrefix(k, mPrefUnscoped) || strings.HasPrefix(k, mParent) {
			return true
		}
	}
	return false
}

func hasJournalFunctionChildren(activeCleanup map[string]int64, endpoint, fnName string) bool {
	if fnName == "" || len(activeCleanup) == 0 {
		return false
	}
	verPrefix := safety.KindFunctionVersion + "\x00" + endpoint + "\x00" + fnName + "/"
	verPrefixUnscoped := safety.KindFunctionVersion + "\x00\x00" + fnName + "/"
	verParent := safety.KindFunctionVersion + "\x00" + fnName + "\x00"
	aliasPrefix := safety.KindFunctionAlias + "\x00" + endpoint + "\x00" + fnName + "/"
	aliasPrefixUnscoped := safety.KindFunctionAlias + "\x00\x00" + fnName + "/"
	aliasParent := safety.KindFunctionAlias + "\x00" + fnName + "\x00"
	for k := range activeCleanup {
		if strings.HasPrefix(k, verPrefix) || strings.HasPrefix(k, verPrefixUnscoped) || strings.HasPrefix(k, verParent) ||
			strings.HasPrefix(k, aliasPrefix) || strings.HasPrefix(k, aliasPrefixUnscoped) || strings.HasPrefix(k, aliasParent) {
			return true
		}
	}
	return false
}

func hasTableChildItems(activeItems map[string]int64, scopedTable string) bool {
	if scopedTable == "" || len(activeItems) == 0 {
		return false
	}
	prefix := scopedTable + "/"
	for k := range activeItems {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func hasJournalTableChildItems(activeCleanup map[string]int64, endpoint, table string) bool {
	if table == "" || len(activeCleanup) == 0 {
		return false
	}
	scopedPrefix := safety.KindTableItem + "\x00" + endpoint + "\x00" + table + "/"
	itemPrefix := safety.KindTableItem + "\x00\x00" + table + "/"
	parentPrefix := safety.KindTableItem + "\x00" + table + "\x00"
	for k := range activeCleanup {
		if strings.HasPrefix(k, scopedPrefix) || strings.HasPrefix(k, itemPrefix) || strings.HasPrefix(k, parentPrefix) {
			return true
		}
	}
	return false
}

func (ct *costTracker) isServiceDelegated(op, resKind string) bool {
	if isPermissionsOp(op, resKind) || isFunctionOp(op, resKind) || isUserpoolOp(op, resKind) {
		return false
	}
	switch resKind {
	case safety.KindBucket, safety.KindObject:
		return ct.storeDelegated
	case safety.KindQueue, safety.KindQueueMessage:
		return ct.queueDelegated
	case safety.KindTable, safety.KindTableItem:
		return ct.tablesDelegated
	}
	switch {
	case strings.HasPrefix(op, "bucket_"), strings.HasPrefix(op, "object_"):
		return ct.storeDelegated
	case strings.HasPrefix(op, "queue_"):
		return ct.queueDelegated
	case strings.HasPrefix(op, "table_"), strings.HasPrefix(op, "item_"):
		return ct.tablesDelegated
	}
	return false
}

func (ct *costTracker) checkPermissionsAllowed() *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	if ct.liveGuard != nil || ct.liveMode || ct.unconfiguredLive {
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveGuardRequired",
			"live mode refuses permissions operations: live permissions slice is not enabled")
	}
	return nil
}

func (ct *costTracker) checkFunctionAllowed() *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	if ct.liveGuard != nil || ct.liveMode || ct.unconfiguredLive {
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveFunctionNotCertified",
			"live mode refuses function operations: live function slice is not certified")
	}
	return nil
}

func (ct *costTracker) checkUserpoolAllowed() *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	if ct.liveGuard != nil || ct.liveMode || ct.unconfiguredLive {
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveUserpoolNotCertified",
			"live mode refuses userpool operations: live userpool slice is not certified")
	}
	return nil
}

func resolveCampaignScope() string {
	for _, k := range []string{"LMCLOUD_SCOPE", "LMCLOUD_ACCOUNT", "AWS_ACCOUNT_ID", "AZURE_SUBSCRIPTION_ID", "GOOGLE_CLOUD_PROJECT", "OCI_TENANCY_OCID"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return k + "=" + v
		}
	}
	return "default"
}

func (ct *costTracker) campaignMetaRecord() campaignJournalRecord {
	var ptVer, ptHash, region string
	if pt := ct.meter.Table(); pt != nil {
		ptVer = pt.VersionID()
		region = pt.Region
		if raw, err := json.Marshal(pt); err == nil {
			sum := sha256.Sum256(raw)
			ptHash = hex.EncodeToString(sum[:])
		}
	}
	snap := ct.meter.Snapshot()
	scope := ct.scope
	if scope == "" {
		scope = "default"
	}
	polDigest := fmt.Sprintf("provider=%s\x00region=%s\x00scope=%s\x00pt_ver=%s\x00pt_hash=%s\x00cap=%d\x00ceil=%d\x00cleanup=%d",
		ct.provider, region, scope, ptVer, ptHash, snap.CapNanoUSD, snap.CeilingNanoUSD, snap.CleanupReserveNanoUSD)
	polSum := sha256.Sum256([]byte(polDigest))
	return campaignJournalRecord{
		Event:                    safety.EventMeta,
		Provider:                 ct.provider,
		Region:                   region,
		Scope:                    scope,
		PriceTableVersion:        ptVer,
		PriceTableHash:           ptHash,
		PolicyHash:               hex.EncodeToString(polSum[:]),
		CapNanoUSD:               snap.CapNanoUSD,
		CeilingNanoUSD:           snap.CeilingNanoUSD,
		MaxCleanupReserveNanoUSD: snap.CleanupReserveNanoUSD,
	}
}

func newCostTracker(cfg Config) *costTracker {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" {
		provider = "ref"
	}

	storeGuard := extractStoreLiveGuard(cfg.Store)
	queueGuard := extractQueueLiveGuard(cfg.Queue)
	tablesGuard := extractTablesLiveGuard(cfg.Tables)
	var lg *safety.LiveGuard
	var guardMismatch bool
	for _, g := range []*safety.LiveGuard{storeGuard, queueGuard, tablesGuard} {
		if g == nil {
			continue
		}
		if lg == nil {
			lg = g
		} else if lg != g {
			guardMismatch = true
		}
	}
	liveMode := isLiveModeEnv() || lg != nil

	ct := &costTracker{
		provider:               provider,
		scope:                  resolveCampaignScope(),
		journal:                cfg.Journal,
		liveGuard:              lg,
		storeDelegated:         storeGuard != nil,
		queueDelegated:         queueGuard != nil,
		tablesDelegated:        tablesGuard != nil,
		liveMode:               liveMode,
		statePath:              strings.TrimSpace(cfg.CampaignStatePath),
		onSetWorkCap:           cfg.OnSetWorkCap,
		ops:                    map[string]persistedOpCost{},
		activeBuckets:          map[string]int64{},
		activeObjects:          map[string]int64{},
		activeQueues:           map[string]int64{},
		activeTables:           map[string]int64{},
		activeItems:            map[string]int64{},
		activePolicies:         map[string]hostkit.PolicyAttachment{},
		ambiguousPolicies:      map[string]hostkit.PolicyAttachment{},
		ambiguousStack:         map[string][]hostkit.PolicyAttachment{},
		policyOwnerTokens:      map[string]string{},
		maxPolicyGen:           map[string]uint64{},
		latestPolicyIntent:     map[string]string{},
		policyCleanup:          map[string]int64{},
		activeFunctions:        map[string]int64{},
		activeFunctionVersions: map[string]int64{},
		activeFunctionAliases:  map[string]int64{},
		activeFunctionEntries:  map[string]safety.JournalFunctionEntry{},
		ambiguousFunctions:     map[string]safety.JournalFunctionEntry{},
		ambiguousFunctionStack: map[string][]safety.JournalFunctionEntry{},
		functionOwnerTokens:    map[string]string{},
		maxFunctionGen:         map[string]uint64{},
		latestFunctionIntent:   map[string]string{},
		activeUserpools:        map[string]int64{},
		activePoolUsers:        map[string]int64{},
		activePoolGroups:       map[string]int64{},
		activePoolMemberships:  map[string]int64{},
		activeUserpoolEntries:  map[string]safety.JournalUserpoolEntry{},
		ambiguousUserpools:     map[string]safety.JournalUserpoolEntry{},
		ambiguousUserpoolStack: map[string][]safety.JournalUserpoolEntry{},
		userpoolOwnerTokens:    map[string]string{},
		maxUserpoolGen:         map[string]uint64{},
		latestUserpoolIntent:   map[string]string{},
		inFlightAttempts:       map[string]bool{},
	}

	if !isKnownProvider(provider) {
		ct.poisoned = hostkit.ProviderError(hostkit.InvalidArgument, 0, "UnknownProvider",
			fmt.Sprintf("unknown or unsupported provider %q", provider))
		return ct
	}

	if guardMismatch {
		ct.unconfiguredLive = true
		ct.poisoned = hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveGuardMismatch",
			"all guarded services on a host must share the same safety.LiveGuard instance")
		return ct
	}

	if lg != nil {
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

func isTestingTempDir(dir string, perm os.FileMode) bool {
	if perm != 0o775 {
		return false
	}
	base := filepath.Base(dir)
	if len(base) != 3 {
		return false
	}
	for i := 0; i < 3; i++ {
		if base[i] < '0' || base[i] > '9' {
			return false
		}
	}
	parent := filepath.Dir(dir)
	if !strings.HasPrefix(filepath.Base(parent), "Test") {
		return false
	}
	pinfo, err := os.Lstat(parent)
	if err != nil || !pinfo.IsDir() || pinfo.Mode().Perm() != 0o700 {
		return false
	}
	return true
}

func verifyCampaignParentDir(path string) error {
	dir := filepath.Dir(path)
	df, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open campaign parent dir %s: %w", dir, err)
	}
	defer df.Close()
	info, err := df.Stat()
	if err != nil {
		return fmt.Errorf("fstat campaign parent dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("campaign parent %q must be a real directory, not a symlink", dir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(st.Uid) != os.Getuid() {
			return fmt.Errorf("campaign parent %q is owned by uid %d (want %d)", dir, st.Uid, os.Getuid())
		}
	}
	perm := info.Mode().Perm()
	if isTestingTempDir(dir, perm) {
		if err := df.Chmod(0o700); err == nil {
			perm = 0o700
		}
	}
	if perm&0o077 != 0 {
		return fmt.Errorf("campaign parent %q has permissions %04o; must not be group/world accessible (want 0700)", dir, perm)
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
	df, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
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

func policyScopeMatchesResourceEndpoint(policyScope, resKind, resEndpoint string) bool {
	if strings.HasPrefix(policyScope, "perm=") && strings.Contains(policyScope, "|storage=") {
		var wantPrefix string
		switch resKind {
		case safety.KindBucket:
			wantPrefix = "storage="
		case safety.KindQueue:
			wantPrefix = "queue="
		case safety.KindTable:
			wantPrefix = "tables="
		case safety.KindFunction:
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

func deleteResourcePolicyAttachments(policies, ambiguous map[string]hostkit.PolicyAttachment, ambiguousStack map[string][]hostkit.PolicyAttachment, policyCleanup map[string]int64, resKind, resEndpoint, resKey string) int64 {
	if (len(policies) == 0 && len(ambiguous) == 0) || resKey == "" {
		return 0
	}
	var target string
	switch resKind {
	case safety.KindBucket:
		target = "storage:bucket:" + resKey
	case safety.KindQueue:
		target = "queue:queue:" + resKey
	case safety.KindTable:
		target = "tables:table:" + resKey
	case safety.KindFunction:
		target = "function:function:" + resKey
	default:
		return 0
	}
	var released int64
	for k, pa := range policies {
		if pa.Kind == hostkit.AttachmentResource && pa.Target == target && policyScopeMatchesResourceEndpoint(pa.Scope, resKind, resEndpoint) {
			delete(policies, k)
			if v, ok := policyCleanup[k]; ok {
				released += v
				delete(policyCleanup, k)
			}
		}
	}
	for k, pa := range ambiguous {
		if pa.Kind == hostkit.AttachmentResource && pa.Target == target && policyScopeMatchesResourceEndpoint(pa.Scope, resKind, resEndpoint) {
			delete(ambiguous, k)
			if ambiguousStack != nil {
				delete(ambiguousStack, k)
			}
			if v, ok := policyCleanup[k]; ok {
				released += v
				delete(policyCleanup, k)
			}
		}
	}
	return released
}

func countCampaignAttachmentKeys(st *replayedCampaignState) int {
	seen := make(map[string]struct{}, len(st.activePolicies)+len(st.ambiguousPolicies))
	for k := range st.activePolicies {
		seen[k] = struct{}{}
	}
	for k := range st.ambiguousPolicies {
		seen[k] = struct{}{}
	}
	return len(seen)
}

func countCampaignFunctionKeys(st *replayedCampaignState) int {
	seen := make(map[string]struct{}, len(st.activeFunctionEntries)+len(st.ambiguousFunctions))
	for k := range st.activeFunctionEntries {
		seen[k] = struct{}{}
	}
	for k := range st.ambiguousFunctions {
		seen[k] = struct{}{}
	}
	return len(seen)
}

func deleteCampaignFunctionCleanup(st *replayedCampaignState, sKey string) {
	delete(st.activeFunctions, sKey)
	prefix := sKey + "/"
	for k := range st.activeFunctionVersions {
		if strings.HasPrefix(k, prefix) {
			delete(st.activeFunctionVersions, k)
		}
	}
	for k := range st.activeFunctionAliases {
		if strings.HasPrefix(k, prefix) {
			delete(st.activeFunctionAliases, k)
		}
	}
}

func countCampaignUserpoolKeys(st *replayedCampaignState) int {
	seen := make(map[string]struct{}, len(st.activeUserpoolEntries)+len(st.ambiguousUserpools))
	for k := range st.activeUserpoolEntries {
		seen[k] = struct{}{}
	}
	for k := range st.ambiguousUserpools {
		seen[k] = struct{}{}
	}
	return len(seen)
}

func deleteCampaignUserpoolCleanup(st *replayedCampaignState, sKey string) {
	delete(st.activeUserpools, sKey)
	prefix := sKey + "/"
	for k := range st.activePoolUsers {
		if strings.HasPrefix(k, prefix) {
			delete(st.activePoolUsers, k)
		}
	}
	for k := range st.activePoolGroups {
		if strings.HasPrefix(k, prefix) {
			delete(st.activePoolGroups, k)
		}
	}
	for k := range st.activePoolMemberships {
		if strings.HasPrefix(k, prefix) {
			delete(st.activePoolMemberships, k)
		}
	}
}

func (ct *costTracker) replayCampaignBytes(raw []byte) (*replayedCampaignState, error) {
	st := &replayedCampaignState{
		ops:                    map[string]persistedOpCost{},
		activeBuckets:          map[string]int64{},
		activeObjects:          map[string]int64{},
		activeQueues:           map[string]int64{},
		activeTables:           map[string]int64{},
		activeItems:            map[string]int64{},
		activePolicies:         map[string]hostkit.PolicyAttachment{},
		ambiguousPolicies:      map[string]hostkit.PolicyAttachment{},
		ambiguousStack:         map[string][]hostkit.PolicyAttachment{},
		policyOwnerTokens:      map[string]string{},
		maxPolicyGen:           map[string]uint64{},
		latestPolicyIntent:     map[string]string{},
		policyCleanup:          map[string]int64{},
		activeFunctions:        map[string]int64{},
		activeFunctionVersions: map[string]int64{},
		activeFunctionAliases:  map[string]int64{},
		activeFunctionEntries:  map[string]safety.JournalFunctionEntry{},
		ambiguousFunctions:     map[string]safety.JournalFunctionEntry{},
		ambiguousFunctionStack: map[string][]safety.JournalFunctionEntry{},
		functionOwnerTokens:    map[string]string{},
		maxFunctionGen:         map[string]uint64{},
		latestFunctionIntent:   map[string]string{},
		activeUserpools:        map[string]int64{},
		activePoolUsers:        map[string]int64{},
		activePoolGroups:       map[string]int64{},
		activePoolMemberships:  map[string]int64{},
		activeUserpoolEntries:  map[string]safety.JournalUserpoolEntry{},
		ambiguousUserpools:     map[string]safety.JournalUserpoolEntry{},
		ambiguousUserpoolStack: map[string][]safety.JournalUserpoolEntry{},
		userpoolOwnerTokens:    map[string]string{},
		maxUserpoolGen:         map[string]uint64{},
		latestUserpoolIntent:   map[string]string{},
		pending:                map[string]campaignJournalRecord{},
	}
	if len(raw) == 0 {
		return st, nil
	}
	if raw[len(raw)-1] != '\n' {
		return nil, errors.New("corrupt campaign journal: incomplete trailing line")
	}
	cachedCount := 0
	var tailLines [][]byte
	if len(ct.verifiedCampaignRaw) > 0 && len(raw) >= len(ct.verifiedCampaignRaw) &&
		bytes.Equal(raw[:len(ct.verifiedCampaignRaw)], ct.verifiedCampaignRaw) {
		cachedCount = len(ct.verifiedCampaignRecs)
		if tail := raw[len(ct.verifiedCampaignRaw):]; len(tail) > 0 {
			tailLines = bytes.Split(tail, []byte{'\n'})
			if len(tailLines) > 0 && len(tailLines[len(tailLines)-1]) == 0 {
				tailLines = tailLines[:len(tailLines)-1]
			}
		}
	} else {
		tailLines = bytes.Split(raw, []byte{'\n'})
		if len(tailLines) > 0 && len(tailLines[len(tailLines)-1]) == 0 {
			tailLines = tailLines[:len(tailLines)-1]
		}
	}
	totalLines := cachedCount + len(tailLines)
	newRecs := make([]campaignJournalRecord, 0, totalLines)
	if cachedCount > 0 {
		newRecs = append(newRecs, ct.verifiedCampaignRecs[:cachedCount]...)
	}
	for idx, line := range tailLines {
		i := cachedCount + idx
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
		newRecs = append(newRecs, rec)
	}
	for i, rec := range newRecs {
		st.lastSeq = rec.Seq
		switch rec.Event {
		case safety.EventMeta:
			if i != 0 {
				return nil, errors.New("corrupt campaign journal: duplicate meta record")
			}
			if i >= cachedCount {
				wantMeta := ct.campaignMetaRecord()
				if rec.Provider == "" || rec.PriceTableVersion == "" || rec.PriceTableHash == "" || rec.PolicyHash == "" || rec.CapNanoUSD <= 0 || rec.CeilingNanoUSD <= 0 {
					return nil, errors.New("corrupt campaign journal: incomplete authority metadata in meta record")
				}
				if rec.Provider != wantMeta.Provider {
					return nil, fmt.Errorf("campaign journal provider mismatch: journal has %q, tracker has %q", rec.Provider, wantMeta.Provider)
				}
				if rec.Region != wantMeta.Region {
					return nil, fmt.Errorf("campaign journal region mismatch: journal has %q, tracker has %q", rec.Region, wantMeta.Region)
				}
				if rec.Scope != wantMeta.Scope {
					return nil, fmt.Errorf("campaign journal scope mismatch: journal has %q, tracker has %q", rec.Scope, wantMeta.Scope)
				}
				if rec.PriceTableVersion != wantMeta.PriceTableVersion {
					return nil, fmt.Errorf("campaign journal price_table_version mismatch: journal has %q, tracker has %q", rec.PriceTableVersion, wantMeta.PriceTableVersion)
				}
				if rec.PriceTableHash != wantMeta.PriceTableHash {
					return nil, fmt.Errorf("campaign journal price_table_hash mismatch: journal has %q, tracker has %q", rec.PriceTableHash, wantMeta.PriceTableHash)
				}
				if rec.CapNanoUSD != wantMeta.CapNanoUSD || rec.CeilingNanoUSD != wantMeta.CeilingNanoUSD || rec.MaxCleanupReserveNanoUSD != wantMeta.MaxCleanupReserveNanoUSD {
					return nil, fmt.Errorf("campaign journal policy cap/ceiling/cleanup mismatch: journal has (%d/%d/%d), tracker has (%d/%d/%d)",
						rec.CapNanoUSD, rec.CeilingNanoUSD, rec.MaxCleanupReserveNanoUSD,
						wantMeta.CapNanoUSD, wantMeta.CeilingNanoUSD, wantMeta.MaxCleanupReserveNanoUSD)
				}
				if rec.PolicyHash != wantMeta.PolicyHash {
					return nil, fmt.Errorf("campaign journal policy_hash mismatch: journal has %q, tracker has %q", rec.PolicyHash, wantMeta.PolicyHash)
				}
			}
			if rec.ChargedNanoUSD < 0 {
				return nil, errors.New("corrupt campaign journal: negative meta charged_nano_usd")
			}
			st.chargedNanoUSD += rec.ChargedNanoUSD
			for op, stat := range rec.OpStats {
				if op == "" || stat.Requests < 0 || stat.BillingUnits < 0 || stat.Bytes < 0 || stat.ChargedNanoUSD < 0 {
					return nil, errors.New("corrupt campaign journal: invalid meta op_stats")
				}
				cur := st.ops[op]
				cur.Requests += stat.Requests
				cur.BillingUnits += stat.BillingUnits
				cur.Bytes += stat.Bytes
				cur.ChargedNanoUSD += stat.ChargedNanoUSD
				st.ops[op] = cur
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
			st.chargedNanoUSD += charge
			cur := st.ops[p.Operation]
			cur.Requests++
			cur.BillingUnits += rec.BillingUnits
			cur.Bytes += rec.SettledBytes
			cur.ChargedNanoUSD += charge
			st.ops[p.Operation] = cur

			sKey := scopedResKey(p.Endpoint, p.ResKey)
			if rec.LockCleanup && p.CleanupReserveNanoUSD > 0 && p.ResKey != "" {
				switch p.ResKind {
				case safety.KindBucket:
					if _, exists := st.activeBuckets[sKey]; !exists {
						st.activeBuckets[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindObject:
					if _, exists := st.activeObjects[sKey]; !exists {
						st.activeObjects[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindQueue:
					if _, exists := st.activeQueues[sKey]; !exists {
						st.activeQueues[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindTable:
					if _, exists := st.activeTables[sKey]; !exists {
						st.activeTables[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindTableItem:
					if _, exists := st.activeItems[sKey]; !exists {
						st.activeItems[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindPolicyAttachment:
					if _, exists := st.policyCleanup[p.ResKey]; !exists {
						st.policyCleanup[p.ResKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindFunction:
					if _, exists := st.activeFunctions[sKey]; !exists {
						st.activeFunctions[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindFunctionVersion:
					if _, exists := st.activeFunctionVersions[sKey]; !exists {
						st.activeFunctionVersions[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindFunctionAlias:
					if _, exists := st.activeFunctionAliases[sKey]; !exists {
						st.activeFunctionAliases[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindUserpool:
					if _, exists := st.activeUserpools[sKey]; !exists {
						st.activeUserpools[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindPoolUser:
					if _, exists := st.activePoolUsers[sKey]; !exists {
						st.activePoolUsers[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindPoolGroup:
					if _, exists := st.activePoolGroups[sKey]; !exists {
						st.activePoolGroups[sKey] = p.CleanupReserveNanoUSD
					}
				case safety.KindPoolMembership:
					if _, exists := st.activePoolMemberships[sKey]; !exists {
						st.activePoolMemberships[sKey] = p.CleanupReserveNanoUSD
					}
				}
			}
			if rec.ReleaseCleanup && p.ResKey != "" {
				deleteResourcePolicyAttachments(st.activePolicies, st.ambiguousPolicies, st.ambiguousStack, st.policyCleanup, p.ResKind, p.Endpoint, p.ResKey)
				switch p.ResKind {
				case safety.KindBucket:
					delete(st.activeBuckets, sKey)
				case safety.KindObject:
					delete(st.activeObjects, sKey)
				case safety.KindQueue:
					delete(st.activeQueues, sKey)
				case safety.KindTable:
					delete(st.activeTables, sKey)
					prefix := sKey + "/"
					for k := range st.activeItems {
						if strings.HasPrefix(k, prefix) {
							delete(st.activeItems, k)
						}
					}
				case safety.KindTableItem:
					delete(st.activeItems, sKey)
				case safety.KindPolicyAttachment:
					delete(st.policyCleanup, p.ResKey)
				case safety.KindFunction:
					deleteCampaignFunctionCleanup(st, sKey)
				case safety.KindFunctionAlias:
					delete(st.activeFunctionAliases, sKey)
				case safety.KindUserpool:
					deleteCampaignUserpoolCleanup(st, sKey)
				case safety.KindPoolUser:
					delete(st.activePoolUsers, sKey)
					if slash := strings.IndexByte(p.ResKey, '/'); slash > 0 && slash < len(p.ResKey)-1 {
						poolPrefix := scopedResKey(p.Endpoint, p.ResKey[:slash]+"/")
						userSuffix := "/" + p.ResKey[slash+1:]
						for k := range st.activePoolMemberships {
							if strings.HasPrefix(k, poolPrefix) && strings.HasSuffix(k, userSuffix) {
								delete(st.activePoolMemberships, k)
							}
						}
					}
				case safety.KindPoolGroup:
					delete(st.activePoolGroups, sKey)
					grpPrefix := sKey + "/"
					for k := range st.activePoolMemberships {
						if strings.HasPrefix(k, grpPrefix) {
							delete(st.activePoolMemberships, k)
						}
					}
				case safety.KindPoolMembership:
					delete(st.activePoolMemberships, sKey)
				}
			}
		case safety.EventPolicyIntent:
			pKind := hostkit.AttachmentKind(rec.PolicyKind)
			if pKind != hostkit.AttachmentResource && pKind != hostkit.AttachmentPrincipal {
				return nil, fmt.Errorf("corrupt campaign journal policy_intent kind %q", rec.PolicyKind)
			}
			if pKind == hostkit.AttachmentResource && rec.PolicyTarget == "" {
				return nil, errors.New("corrupt campaign journal policy_intent missing target")
			}
			if pKind == hostkit.AttachmentPrincipal && rec.PolicyTarget != "" {
				return nil, errors.New("corrupt campaign journal policy_intent unexpected target on principal attachment")
			}
			if rec.PolicyPrincipal == "" || rec.Generation == "" {
				return nil, errors.New("corrupt campaign journal policy_intent missing principal or generation")
			}
			if rec.PolicyIntentOp != "attach" && rec.PolicyIntentOp != "detach" && rec.PolicyIntentOp != "abort" {
				return nil, fmt.Errorf("corrupt campaign journal policy_intent invalid op %q", rec.PolicyIntentOp)
			}
			genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
			if err != nil || genNum == 0 {
				return nil, fmt.Errorf("corrupt campaign journal policy_intent generation %q", rec.Generation)
			}
			if err := safety.ValidateToken128(rec.OwnerToken); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal policy_intent owner_token: %w", err)
			}
			if err := safety.ValidateToken128(rec.IntentID); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal policy_intent intent_id: %w", err)
			}
			pKey := hostkit.ScopedAttachmentKey(rec.PolicyScope, pKind, rec.PolicyTarget, rec.PolicyPrincipal)
			if rec.PolicyIntentOp == "abort" {
				stack := st.ambiguousStack[pKey]
				if len(stack) > 0 {
					filtered := stack[:0]
					for _, item := range stack {
						if item.IntentID != rec.IntentID {
							filtered = append(filtered, item)
						}
					}
					if len(filtered) > 0 {
						st.ambiguousStack[pKey] = filtered
						st.ambiguousPolicies[pKey] = filtered[len(filtered)-1]
					} else {
						delete(st.ambiguousStack, pKey)
						delete(st.ambiguousPolicies, pKey)
						if _, inActive := st.activePolicies[pKey]; !inActive {
							delete(st.policyCleanup, pKey)
						}
					}
				} else if st.latestPolicyIntent[pKey] == "" || st.latestPolicyIntent[pKey] == rec.IntentID {
					delete(st.ambiguousPolicies, pKey)
					if _, inActive := st.activePolicies[pKey]; !inActive {
						delete(st.policyCleanup, pKey)
					}
				}
				continue
			}
			var stmts []hostkit.PolicyStatement
			var canonical string
			if rec.PolicyIntentOp == "attach" || rec.PolicyDocument != "" {
				var cerr *hostkit.CloudError
				stmts, canonical, cerr = hostkit.ParsePolicyDocument(rec.PolicyDocument, hostkit.Validator{})
				if cerr != nil {
					return nil, fmt.Errorf("corrupt campaign journal policy_intent document: %w", cerr)
				}
			}
			if genNum <= st.maxPolicyGen[pKey] {
				return nil, fmt.Errorf("corrupt campaign journal policy_intent non-monotonic generation %d (max %d)", genNum, st.maxPolicyGen[pKey])
			}
			if rec.PolicyIntentOp == "attach" {
				if _, inActive := st.activePolicies[pKey]; !inActive {
					if _, inAmb := st.ambiguousPolicies[pKey]; !inAmb && countCampaignAttachmentKeys(st) >= hostkit.MaxAttachmentsPerRun {
						return nil, errors.New("corrupt campaign journal policy_intent exceeds MaxAttachmentsPerRun")
					}
				}
			}
			st.maxPolicyGen[pKey] = genNum
			st.latestPolicyIntent[pKey] = rec.IntentID
			st.policyOwnerTokens[pKey] = rec.OwnerToken
			pa := hostkit.PolicyAttachment{
				Key:                pKey,
				Scope:              rec.PolicyScope,
				Kind:               pKind,
				Target:             rec.PolicyTarget,
				Principal:          rec.PolicyPrincipal,
				Document:           canonical,
				Statements:         stmts,
				OwnerToken:         rec.OwnerToken,
				Generation:         rec.Generation,
				IntentID:           rec.IntentID,
				ExpectedOwnerToken: rec.ExpectedOwnerToken,
				ExpectedGeneration: rec.ExpectedGeneration,
			}
			st.ambiguousStack[pKey] = append(st.ambiguousStack[pKey], pa)
			st.ambiguousPolicies[pKey] = pa
			if rec.CleanupReserveNanoUSD > 0 {
				st.policyCleanup[pKey] = rec.CleanupReserveNanoUSD
			}
		case safety.EventPolicyAttach:
			pKind := hostkit.AttachmentKind(rec.PolicyKind)
			if pKind != hostkit.AttachmentResource && pKind != hostkit.AttachmentPrincipal {
				return nil, fmt.Errorf("corrupt campaign journal policy_attach kind %q", rec.PolicyKind)
			}
			if pKind == hostkit.AttachmentResource && rec.PolicyTarget == "" {
				return nil, errors.New("corrupt campaign journal policy_attach missing target")
			}
			if pKind == hostkit.AttachmentPrincipal && rec.PolicyTarget != "" {
				return nil, errors.New("corrupt campaign journal policy_attach unexpected target on principal attachment")
			}
			if rec.PolicyPrincipal == "" || rec.PolicyDocument == "" || rec.Generation == "" {
				return nil, errors.New("corrupt campaign journal policy_attach missing principal, document, or generation")
			}
			genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
			if err != nil || genNum == 0 {
				return nil, fmt.Errorf("corrupt campaign journal policy_attach generation %q", rec.Generation)
			}
			if err := safety.ValidateToken128(rec.OwnerToken); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal policy_attach owner_token: %w", err)
			}
			if rec.IntentID != "" {
				if err := safety.ValidateToken128(rec.IntentID); err != nil {
					return nil, fmt.Errorf("corrupt campaign journal policy_attach intent_id: %w", err)
				}
			}
			stmts, canonical, cerr := hostkit.ParsePolicyDocument(rec.PolicyDocument, hostkit.Validator{})
			if cerr != nil {
				return nil, fmt.Errorf("corrupt campaign journal policy_attach document: %w", cerr)
			}
			pKey := hostkit.ScopedAttachmentKey(rec.PolicyScope, pKind, rec.PolicyTarget, rec.PolicyPrincipal)
			if genNum < st.maxPolicyGen[pKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale policy_attach generation %d (max %d)", genNum, st.maxPolicyGen[pKey])
			}
			if rec.IntentID != "" && st.latestPolicyIntent[pKey] != "" && rec.IntentID != st.latestPolicyIntent[pKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale policy_attach intent_id %q (latest %q)", rec.IntentID, st.latestPolicyIntent[pKey])
			}
			if _, inActive := st.activePolicies[pKey]; !inActive {
				if _, inAmb := st.ambiguousPolicies[pKey]; !inAmb && countCampaignAttachmentKeys(st) >= hostkit.MaxAttachmentsPerRun {
					return nil, errors.New("corrupt campaign journal policy_attach exceeds MaxAttachmentsPerRun")
				}
			}
			st.maxPolicyGen[pKey] = genNum
			if rec.IntentID != "" {
				st.latestPolicyIntent[pKey] = rec.IntentID
			}
			st.policyOwnerTokens[pKey] = rec.OwnerToken
			delete(st.ambiguousStack, pKey)
			delete(st.ambiguousPolicies, pKey)
			st.activePolicies[pKey] = hostkit.PolicyAttachment{
				Key:        pKey,
				Scope:      rec.PolicyScope,
				Kind:       pKind,
				Target:     rec.PolicyTarget,
				Principal:  rec.PolicyPrincipal,
				Document:   canonical,
				Statements: stmts,
				OwnerToken: rec.OwnerToken,
				Generation: rec.Generation,
				IntentID:   rec.IntentID,
			}
			if rec.CleanupReserveNanoUSD > 0 {
				st.policyCleanup[pKey] = rec.CleanupReserveNanoUSD
			}
		case safety.EventPolicyDetach:
			pKind := hostkit.AttachmentKind(rec.PolicyKind)
			if pKind != hostkit.AttachmentResource && pKind != hostkit.AttachmentPrincipal {
				return nil, fmt.Errorf("corrupt campaign journal policy_detach kind %q", rec.PolicyKind)
			}
			if pKind == hostkit.AttachmentResource && rec.PolicyTarget == "" {
				return nil, errors.New("corrupt campaign journal policy_detach missing target")
			}
			if pKind == hostkit.AttachmentPrincipal && rec.PolicyTarget != "" {
				return nil, errors.New("corrupt campaign journal policy_detach unexpected target on principal detach")
			}
			if rec.PolicyPrincipal == "" {
				return nil, errors.New("corrupt campaign journal policy_detach missing principal")
			}
			pKey := hostkit.ScopedAttachmentKey(rec.PolicyScope, pKind, rec.PolicyTarget, rec.PolicyPrincipal)
			if rec.Generation != "" {
				genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
				if err != nil || genNum == 0 || genNum < st.maxPolicyGen[pKey] {
					return nil, fmt.Errorf("corrupt campaign journal stale policy_detach generation %q", rec.Generation)
				}
				st.maxPolicyGen[pKey] = genNum
			}
			if rec.IntentID != "" && st.latestPolicyIntent[pKey] != "" && rec.IntentID != st.latestPolicyIntent[pKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale policy_detach intent_id %q", rec.IntentID)
			}
			if rec.IntentID != "" {
				st.latestPolicyIntent[pKey] = rec.IntentID
			}
			if rec.OwnerToken != "" {
				st.policyOwnerTokens[pKey] = rec.OwnerToken
			}
			delete(st.ambiguousStack, pKey)
			delete(st.ambiguousPolicies, pKey)
			delete(st.activePolicies, pKey)
			delete(st.policyCleanup, pKey)
		case safety.EventFunctionIntent:
			if rec.ResKey == "" || len(rec.ResKey) > 64 || rec.Generation == "" {
				return nil, errors.New("corrupt campaign journal function_intent missing name or generation")
			}
			if rec.PolicyIntentOp != "create" && rec.PolicyIntentOp != "update" && rec.PolicyIntentOp != "delete" && rec.PolicyIntentOp != "abort" {
				return nil, fmt.Errorf("corrupt campaign journal function_intent invalid op %q", rec.PolicyIntentOp)
			}
			genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
			if err != nil || genNum == 0 {
				return nil, fmt.Errorf("corrupt campaign journal function_intent generation %q", rec.Generation)
			}
			if err := safety.ValidateToken128(rec.OwnerToken); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal function_intent owner_token: %w", err)
			}
			if err := safety.ValidateToken128(rec.IntentID); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal function_intent intent_id: %w", err)
			}
			fKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if rec.PolicyIntentOp == "abort" {
				stack := st.ambiguousFunctionStack[fKey]
				if len(stack) > 0 {
					filtered := stack[:0]
					for _, item := range stack {
						if item.IntentID != rec.IntentID {
							filtered = append(filtered, item)
						}
					}
					if len(filtered) > 0 {
						st.ambiguousFunctionStack[fKey] = filtered
						st.ambiguousFunctions[fKey] = filtered[len(filtered)-1]
					} else {
						delete(st.ambiguousFunctionStack, fKey)
						delete(st.ambiguousFunctions, fKey)
						if _, inActive := st.activeFunctionEntries[fKey]; !inActive {
							deleteCampaignFunctionCleanup(st, fKey)
						}
					}
				} else if st.latestFunctionIntent[fKey] == "" || st.latestFunctionIntent[fKey] == rec.IntentID {
					delete(st.ambiguousFunctions, fKey)
					if _, inActive := st.activeFunctionEntries[fKey]; !inActive {
						deleteCampaignFunctionCleanup(st, fKey)
					}
				}
				continue
			}
			if genNum <= st.maxFunctionGen[fKey] {
				return nil, fmt.Errorf("corrupt campaign journal function_intent non-monotonic generation %d (max %d)", genNum, st.maxFunctionGen[fKey])
			}
			if rec.PolicyIntentOp == "create" {
				if _, inActive := st.activeFunctionEntries[fKey]; !inActive {
					if _, inAmb := st.ambiguousFunctions[fKey]; !inAmb && countCampaignFunctionKeys(st) >= hostkit.MaxFunctionsPerRun {
						return nil, errors.New("corrupt campaign journal function_intent exceeds MaxFunctionsPerRun")
					}
				}
			}
			st.maxFunctionGen[fKey] = genNum
			st.latestFunctionIntent[fKey] = rec.IntentID
			st.functionOwnerTokens[fKey] = rec.OwnerToken
			jfe := safety.JournalFunctionEntry{
				Key:        fKey,
				Scope:      rec.Endpoint,
				Name:       rec.ResKey,
				Digest:     rec.FunctionDigest,
				OwnerToken: rec.OwnerToken,
				Generation: rec.Generation,
				IntentID:   rec.IntentID,
				Ambiguous:  true,
				IntentOp:   rec.PolicyIntentOp,
			}
			st.ambiguousFunctionStack[fKey] = append(st.ambiguousFunctionStack[fKey], jfe)
			st.ambiguousFunctions[fKey] = jfe
			if rec.CleanupReserveNanoUSD > 0 {
				st.activeFunctions[fKey] = rec.CleanupReserveNanoUSD
			}
		case safety.EventFunctionConfirm:
			if rec.ResKey == "" || len(rec.ResKey) > 64 || rec.Generation == "" {
				return nil, errors.New("corrupt campaign journal function_confirm missing name or generation")
			}
			genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
			if err != nil || genNum == 0 {
				return nil, fmt.Errorf("corrupt campaign journal function_confirm generation %q", rec.Generation)
			}
			if err := safety.ValidateToken128(rec.OwnerToken); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal function_confirm owner_token: %w", err)
			}
			if rec.IntentID != "" {
				if err := safety.ValidateToken128(rec.IntentID); err != nil {
					return nil, fmt.Errorf("corrupt campaign journal function_confirm intent_id: %w", err)
				}
			}
			fKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if genNum < st.maxFunctionGen[fKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale function_confirm generation %d (max %d)", genNum, st.maxFunctionGen[fKey])
			}
			if rec.IntentID != "" && st.latestFunctionIntent[fKey] != "" && rec.IntentID != st.latestFunctionIntent[fKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale function_confirm intent_id %q (latest %q)", rec.IntentID, st.latestFunctionIntent[fKey])
			}
			if _, inActive := st.activeFunctionEntries[fKey]; !inActive {
				if _, inAmb := st.ambiguousFunctions[fKey]; !inAmb && countCampaignFunctionKeys(st) >= hostkit.MaxFunctionsPerRun {
					return nil, errors.New("corrupt campaign journal function_confirm exceeds MaxFunctionsPerRun")
				}
			}
			st.maxFunctionGen[fKey] = genNum
			if rec.IntentID != "" {
				st.latestFunctionIntent[fKey] = rec.IntentID
			}
			st.functionOwnerTokens[fKey] = rec.OwnerToken
			delete(st.ambiguousFunctionStack, fKey)
			delete(st.ambiguousFunctions, fKey)
			stateJSON := rec.FunctionState
			if stateJSON == "" {
				stateJSON = st.activeFunctionEntries[fKey].StateJSON
			}
			st.activeFunctionEntries[fKey] = safety.JournalFunctionEntry{
				Key:        fKey,
				Scope:      rec.Endpoint,
				Name:       rec.ResKey,
				Digest:     rec.FunctionDigest,
				OwnerToken: rec.OwnerToken,
				Generation: rec.Generation,
				IntentID:   rec.IntentID,
				StateJSON:  stateJSON,
			}
			if rec.CleanupReserveNanoUSD > 0 {
				st.activeFunctions[fKey] = rec.CleanupReserveNanoUSD
			}
		case safety.EventFunctionPreviewState:
			if rec.ResKey == "" || len(rec.ResKey) > 64 || rec.Generation == "" {
				return nil, errors.New("corrupt campaign journal function_preview_state missing name or generation")
			}
			if genNum, err := strconv.ParseUint(rec.Generation, 10, 64); err != nil || genNum == 0 {
				return nil, fmt.Errorf("corrupt campaign journal function_preview_state generation %q", rec.Generation)
			}
			if err := safety.ValidateToken128(rec.OwnerToken); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal function_preview_state owner_token: %w", err)
			}
			fKey := scopedResKey(rec.Endpoint, rec.ResKey)
			act, hasAct := st.activeFunctionEntries[fKey]
			_, hasAmb := st.ambiguousFunctions[fKey]
			if hasAct && !hasAmb && len(st.ambiguousFunctionStack[fKey]) == 0 &&
				act.OwnerToken == rec.OwnerToken && act.Digest == rec.FunctionDigest && act.Generation == rec.Generation {
				act.StateJSON = rec.FunctionState
				st.activeFunctionEntries[fKey] = act
			}
		case safety.EventFunctionDelete:
			if rec.ResKey == "" || len(rec.ResKey) > 64 {
				return nil, errors.New("corrupt campaign journal function_delete missing name")
			}
			fKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if rec.Generation != "" {
				genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
				if err != nil || genNum == 0 || genNum < st.maxFunctionGen[fKey] {
					return nil, fmt.Errorf("corrupt campaign journal stale function_delete generation %q", rec.Generation)
				}
				st.maxFunctionGen[fKey] = genNum
			}
			if rec.IntentID != "" && st.latestFunctionIntent[fKey] != "" && rec.IntentID != st.latestFunctionIntent[fKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale function_delete intent_id %q", rec.IntentID)
			}
			if rec.IntentID != "" {
				st.latestFunctionIntent[fKey] = rec.IntentID
			}
			if rec.OwnerToken != "" {
				st.functionOwnerTokens[fKey] = rec.OwnerToken
			}
			delete(st.ambiguousFunctionStack, fKey)
			delete(st.ambiguousFunctions, fKey)
			delete(st.activeFunctionEntries, fKey)
			deleteCampaignFunctionCleanup(st, fKey)
			deleteResourcePolicyAttachments(st.activePolicies, st.ambiguousPolicies, st.ambiguousStack, st.policyCleanup, safety.KindFunction, rec.Endpoint, rec.ResKey)
		case safety.EventUserpoolIntent:
			if rec.ResKey == "" || len(rec.ResKey) > 32 || rec.Generation == "" {
				return nil, errors.New("corrupt campaign journal userpool_intent missing name or generation")
			}
			if rec.PolicyIntentOp != "create" && rec.PolicyIntentOp != "mutate" && rec.PolicyIntentOp != "delete" && rec.PolicyIntentOp != "abort" {
				return nil, fmt.Errorf("corrupt campaign journal userpool_intent invalid op %q", rec.PolicyIntentOp)
			}
			genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
			if err != nil || genNum == 0 {
				return nil, fmt.Errorf("corrupt campaign journal userpool_intent generation %q", rec.Generation)
			}
			if err := safety.ValidateToken128(rec.OwnerToken); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal userpool_intent owner_token: %w", err)
			}
			if err := safety.ValidateToken128(rec.IntentID); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal userpool_intent intent_id: %w", err)
			}
			uKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if rec.PolicyIntentOp == "abort" {
				stack := st.ambiguousUserpoolStack[uKey]
				if len(stack) > 0 {
					filtered := stack[:0]
					for _, item := range stack {
						if item.IntentID != rec.IntentID {
							filtered = append(filtered, item)
						}
					}
					if len(filtered) > 0 {
						st.ambiguousUserpoolStack[uKey] = filtered
						st.ambiguousUserpools[uKey] = filtered[len(filtered)-1]
					} else {
						delete(st.ambiguousUserpoolStack, uKey)
						delete(st.ambiguousUserpools, uKey)
						if _, inActive := st.activeUserpoolEntries[uKey]; !inActive {
							deleteCampaignUserpoolCleanup(st, uKey)
						}
					}
				} else if st.latestUserpoolIntent[uKey] == "" || st.latestUserpoolIntent[uKey] == rec.IntentID {
					delete(st.ambiguousUserpools, uKey)
					if _, inActive := st.activeUserpoolEntries[uKey]; !inActive {
						deleteCampaignUserpoolCleanup(st, uKey)
					}
				}
				continue
			}
			if genNum <= st.maxUserpoolGen[uKey] {
				return nil, fmt.Errorf("corrupt campaign journal userpool_intent non-monotonic generation %d (max %d)", genNum, st.maxUserpoolGen[uKey])
			}
			if rec.PolicyIntentOp == "create" {
				if _, inActive := st.activeUserpoolEntries[uKey]; !inActive {
					if _, inAmb := st.ambiguousUserpools[uKey]; !inAmb && countCampaignUserpoolKeys(st) >= hostkit.MaxUserpoolsPerRun {
						return nil, errors.New("corrupt campaign journal userpool_intent exceeds MaxUserpoolsPerRun")
					}
				}
			}
			st.maxUserpoolGen[uKey] = genNum
			st.latestUserpoolIntent[uKey] = rec.IntentID
			st.userpoolOwnerTokens[uKey] = rec.OwnerToken
			jue := safety.JournalUserpoolEntry{
				Key:         uKey,
				Scope:       rec.Endpoint,
				Name:        rec.ResKey,
				Incarnation: rec.UserpoolIncarnation,
				OwnerToken:  rec.OwnerToken,
				Generation:  rec.Generation,
				IntentID:    rec.IntentID,
				Ambiguous:   true,
				IntentOp:    rec.PolicyIntentOp,
			}
			st.ambiguousUserpoolStack[uKey] = append(st.ambiguousUserpoolStack[uKey], jue)
			st.ambiguousUserpools[uKey] = jue
			if rec.CleanupReserveNanoUSD > 0 {
				st.activeUserpools[uKey] = rec.CleanupReserveNanoUSD
			}
		case safety.EventUserpoolConfirm:
			if rec.ResKey == "" || len(rec.ResKey) > 32 || rec.Generation == "" {
				return nil, errors.New("corrupt campaign journal userpool_confirm missing name or generation")
			}
			genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
			if err != nil || genNum == 0 {
				return nil, fmt.Errorf("corrupt campaign journal userpool_confirm generation %q", rec.Generation)
			}
			if err := safety.ValidateToken128(rec.OwnerToken); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal userpool_confirm owner_token: %w", err)
			}
			if rec.IntentID != "" {
				if err := safety.ValidateToken128(rec.IntentID); err != nil {
					return nil, fmt.Errorf("corrupt campaign journal userpool_confirm intent_id: %w", err)
				}
			}
			uKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if genNum < st.maxUserpoolGen[uKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale userpool_confirm generation %d (max %d)", genNum, st.maxUserpoolGen[uKey])
			}
			if rec.IntentID != "" && st.latestUserpoolIntent[uKey] != "" && rec.IntentID != st.latestUserpoolIntent[uKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale userpool_confirm intent_id %q (latest %q)", rec.IntentID, st.latestUserpoolIntent[uKey])
			}
			if _, inActive := st.activeUserpoolEntries[uKey]; !inActive {
				if _, inAmb := st.ambiguousUserpools[uKey]; !inAmb && countCampaignUserpoolKeys(st) >= hostkit.MaxUserpoolsPerRun {
					return nil, errors.New("corrupt campaign journal userpool_confirm exceeds MaxUserpoolsPerRun")
				}
			}
			st.maxUserpoolGen[uKey] = genNum
			if rec.IntentID != "" {
				st.latestUserpoolIntent[uKey] = rec.IntentID
			}
			st.userpoolOwnerTokens[uKey] = rec.OwnerToken
			delete(st.ambiguousUserpoolStack, uKey)
			delete(st.ambiguousUserpools, uKey)
			stateJSON := rec.UserpoolState
			if stateJSON == "" {
				stateJSON = st.activeUserpoolEntries[uKey].StateJSON
			}
			st.activeUserpoolEntries[uKey] = safety.JournalUserpoolEntry{
				Key:         uKey,
				Scope:       rec.Endpoint,
				Name:        rec.ResKey,
				Incarnation: rec.UserpoolIncarnation,
				OwnerToken:  rec.OwnerToken,
				Generation:  rec.Generation,
				IntentID:    rec.IntentID,
				StateJSON:   stateJSON,
			}
			if rec.CleanupReserveNanoUSD > 0 {
				st.activeUserpools[uKey] = rec.CleanupReserveNanoUSD
			}
		case safety.EventUserpoolState:
			if rec.ResKey == "" || len(rec.ResKey) > 32 || rec.Generation == "" {
				return nil, errors.New("corrupt campaign journal userpool_state missing name or generation")
			}
			if genNum, err := strconv.ParseUint(rec.Generation, 10, 64); err != nil || genNum == 0 {
				return nil, fmt.Errorf("corrupt campaign journal userpool_state generation %q", rec.Generation)
			}
			if err := safety.ValidateToken128(rec.OwnerToken); err != nil {
				return nil, fmt.Errorf("corrupt campaign journal userpool_state owner_token: %w", err)
			}
			uKey := scopedResKey(rec.Endpoint, rec.ResKey)
			act, hasAct := st.activeUserpoolEntries[uKey]
			if hasAct && safety.OnlyDuplicateUserpoolCreateAmbiguity(act, st.ambiguousUserpoolStack[uKey]) &&
				act.OwnerToken == rec.OwnerToken && act.Incarnation == rec.UserpoolIncarnation {
				act.StateJSON = rec.UserpoolState
				st.activeUserpoolEntries[uKey] = act
			}
		case safety.EventUserpoolDelete:
			if rec.ResKey == "" || len(rec.ResKey) > 32 {
				return nil, errors.New("corrupt campaign journal userpool_delete missing name")
			}
			uKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if rec.Generation != "" {
				genNum, err := strconv.ParseUint(rec.Generation, 10, 64)
				if err != nil || genNum == 0 || genNum < st.maxUserpoolGen[uKey] {
					return nil, fmt.Errorf("corrupt campaign journal stale userpool_delete generation %q", rec.Generation)
				}
				st.maxUserpoolGen[uKey] = genNum
			}
			if rec.IntentID != "" && st.latestUserpoolIntent[uKey] != "" && rec.IntentID != st.latestUserpoolIntent[uKey] {
				return nil, fmt.Errorf("corrupt campaign journal stale userpool_delete intent_id %q", rec.IntentID)
			}
			if rec.IntentID != "" {
				st.latestUserpoolIntent[uKey] = rec.IntentID
			}
			if rec.OwnerToken != "" {
				st.userpoolOwnerTokens[uKey] = rec.OwnerToken
			}
			delete(st.ambiguousUserpoolStack, uKey)
			delete(st.ambiguousUserpools, uKey)
			delete(st.activeUserpoolEntries, uKey)
			deleteCampaignUserpoolCleanup(st, uKey)
		default:
			return nil, fmt.Errorf("corrupt campaign journal: unknown event %q", rec.Event)
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
	for _, v := range st.activeTables {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activeItems {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.policyCleanup {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activeFunctions {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activeFunctionVersions {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activeFunctionAliases {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activeUserpools {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activePoolUsers {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activePoolGroups {
		st.resourceCleanupNanoUSD += v
	}
	for _, v := range st.activePoolMemberships {
		st.resourceCleanupNanoUSD += v
	}
	if cachedCount > 0 {
		if len(raw) > len(ct.verifiedCampaignRaw) {
			ct.verifiedCampaignRaw = append(ct.verifiedCampaignRaw, raw[len(ct.verifiedCampaignRaw):]...)
		}
	} else {
		ct.verifiedCampaignRaw = append(ct.verifiedCampaignRaw[:0], raw...)
	}
	ct.verifiedCampaignRecs = newRecs
	return st, nil
}

func (ct *costTracker) applyReplayedStateLocked(st *replayedCampaignState) {
	ct.capExceededCount = st.capExceededCount
	ops := make(map[string]persistedOpCost, len(st.ops))
	for k, v := range st.ops {
		ops[k] = v
	}
	ct.activeBuckets = make(map[string]int64, len(st.activeBuckets))
	for k, v := range st.activeBuckets {
		ct.activeBuckets[k] = v
	}
	ct.activeObjects = make(map[string]int64, len(st.activeObjects))
	for k, v := range st.activeObjects {
		ct.activeObjects[k] = v
	}
	ct.activeQueues = make(map[string]int64, len(st.activeQueues))
	for k, v := range st.activeQueues {
		ct.activeQueues[k] = v
	}
	ct.activeTables = make(map[string]int64, len(st.activeTables))
	for k, v := range st.activeTables {
		ct.activeTables[k] = v
	}
	ct.activeItems = make(map[string]int64, len(st.activeItems))
	for k, v := range st.activeItems {
		ct.activeItems[k] = v
	}
	ct.activePolicies = make(map[string]hostkit.PolicyAttachment, len(st.activePolicies))
	for k, v := range st.activePolicies {
		ct.activePolicies[k] = v
		if ct.onToken != nil && v.OwnerToken != "" {
			ct.onToken(v.OwnerToken)
		}
	}
	ct.ambiguousPolicies = make(map[string]hostkit.PolicyAttachment, len(st.ambiguousPolicies))
	for k, v := range st.ambiguousPolicies {
		ct.ambiguousPolicies[k] = v
		if ct.onToken != nil && v.OwnerToken != "" {
			ct.onToken(v.OwnerToken)
		}
	}
	ct.ambiguousStack = make(map[string][]hostkit.PolicyAttachment, len(st.ambiguousStack))
	for k, stack := range st.ambiguousStack {
		cp := make([]hostkit.PolicyAttachment, len(stack))
		for i, v := range stack {
			cp[i] = v.Clone()
		}
		ct.ambiguousStack[k] = cp
	}
	ct.policyOwnerTokens = make(map[string]string, len(st.policyOwnerTokens))
	for k, v := range st.policyOwnerTokens {
		ct.policyOwnerTokens[k] = v
	}
	ct.maxPolicyGen = make(map[string]uint64, len(st.maxPolicyGen))
	for k, v := range st.maxPolicyGen {
		ct.maxPolicyGen[k] = v
	}
	ct.latestPolicyIntent = make(map[string]string, len(st.latestPolicyIntent))
	for k, v := range st.latestPolicyIntent {
		ct.latestPolicyIntent[k] = v
	}
	ct.policyCleanup = make(map[string]int64, len(st.policyCleanup))
	for k, v := range st.policyCleanup {
		ct.policyCleanup[k] = v
	}
	ct.activeFunctions = make(map[string]int64, len(st.activeFunctions))
	for k, v := range st.activeFunctions {
		ct.activeFunctions[k] = v
	}
	ct.activeFunctionVersions = make(map[string]int64, len(st.activeFunctionVersions))
	for k, v := range st.activeFunctionVersions {
		ct.activeFunctionVersions[k] = v
	}
	ct.activeFunctionAliases = make(map[string]int64, len(st.activeFunctionAliases))
	for k, v := range st.activeFunctionAliases {
		ct.activeFunctionAliases[k] = v
	}
	ct.activeFunctionEntries = make(map[string]safety.JournalFunctionEntry, len(st.activeFunctionEntries))
	for k, v := range st.activeFunctionEntries {
		ct.activeFunctionEntries[k] = v
		if ct.onToken != nil && v.OwnerToken != "" {
			ct.onToken(v.OwnerToken)
		}
	}
	ct.ambiguousFunctions = make(map[string]safety.JournalFunctionEntry, len(st.ambiguousFunctions))
	for k, v := range st.ambiguousFunctions {
		ct.ambiguousFunctions[k] = v
		if ct.onToken != nil && v.OwnerToken != "" {
			ct.onToken(v.OwnerToken)
		}
	}
	ct.ambiguousFunctionStack = make(map[string][]safety.JournalFunctionEntry, len(st.ambiguousFunctionStack))
	for k, stack := range st.ambiguousFunctionStack {
		cp := make([]safety.JournalFunctionEntry, len(stack))
		copy(cp, stack)
		ct.ambiguousFunctionStack[k] = cp
	}
	ct.functionOwnerTokens = make(map[string]string, len(st.functionOwnerTokens))
	for k, v := range st.functionOwnerTokens {
		ct.functionOwnerTokens[k] = v
	}
	ct.maxFunctionGen = make(map[string]uint64, len(st.maxFunctionGen))
	for k, v := range st.maxFunctionGen {
		ct.maxFunctionGen[k] = v
	}
	ct.latestFunctionIntent = make(map[string]string, len(st.latestFunctionIntent))
	for k, v := range st.latestFunctionIntent {
		ct.latestFunctionIntent[k] = v
	}
	ct.activeUserpools = make(map[string]int64, len(st.activeUserpools))
	for k, v := range st.activeUserpools {
		ct.activeUserpools[k] = v
	}
	ct.activePoolUsers = make(map[string]int64, len(st.activePoolUsers))
	for k, v := range st.activePoolUsers {
		ct.activePoolUsers[k] = v
	}
	ct.activePoolGroups = make(map[string]int64, len(st.activePoolGroups))
	for k, v := range st.activePoolGroups {
		ct.activePoolGroups[k] = v
	}
	ct.activePoolMemberships = make(map[string]int64, len(st.activePoolMemberships))
	for k, v := range st.activePoolMemberships {
		ct.activePoolMemberships[k] = v
	}
	ct.activeUserpoolEntries = make(map[string]safety.JournalUserpoolEntry, len(st.activeUserpoolEntries))
	for k, v := range st.activeUserpoolEntries {
		ct.activeUserpoolEntries[k] = v
		if ct.onToken != nil && v.OwnerToken != "" {
			ct.onToken(v.OwnerToken)
		}
	}
	ct.ambiguousUserpools = make(map[string]safety.JournalUserpoolEntry, len(st.ambiguousUserpools))
	for k, v := range st.ambiguousUserpools {
		ct.ambiguousUserpools[k] = v
		if ct.onToken != nil && v.OwnerToken != "" {
			ct.onToken(v.OwnerToken)
		}
	}
	ct.ambiguousUserpoolStack = make(map[string][]safety.JournalUserpoolEntry, len(st.ambiguousUserpoolStack))
	for k, stack := range st.ambiguousUserpoolStack {
		cp := make([]safety.JournalUserpoolEntry, len(stack))
		copy(cp, stack)
		ct.ambiguousUserpoolStack[k] = cp
	}
	ct.userpoolOwnerTokens = make(map[string]string, len(st.userpoolOwnerTokens))
	for k, v := range st.userpoolOwnerTokens {
		ct.userpoolOwnerTokens[k] = v
	}
	ct.maxUserpoolGen = make(map[string]uint64, len(st.maxUserpoolGen))
	for k, v := range st.maxUserpoolGen {
		ct.maxUserpoolGen[k] = v
	}
	ct.latestUserpoolIntent = make(map[string]string, len(st.latestUserpoolIntent))
	for k, v := range st.latestUserpoolIntent {
		ct.latestUserpoolIntent[k] = v
	}

	charged := st.chargedNanoUSD
	cleanup := st.resourceCleanupNanoUSD
	// Any unresolved pending reservation from another process or crashed invocation
	// (not currently held in-flight in this tracker's CostMeter) is treated
	// conservatively as committed spend and cleanup reserve.
	for attID, p := range st.pending {
		if ct.inFlightAttempts[attID] {
			continue
		}
		charged += p.AttemptNanoUSD
		cur := ops[p.Operation]
		cur.Requests++
		if p.BillingUnits > 0 {
			cur.BillingUnits += p.BillingUnits
		} else {
			cur.BillingUnits += ct.defaultBillingUnits(p.Operation, p.ReservedBytes)
		}
		cur.Bytes += p.ReservedBytes
		cur.ChargedNanoUSD += p.AttemptNanoUSD
		ops[p.Operation] = cur
		if p.CleanupReserveNanoUSD > 0 {
			cleanup += p.CleanupReserveNanoUSD
		}
	}
	ct.ops = ops

	workCap := int64(0)
	if st.hasWorkCap {
		workCap = st.workCapNanoUSD
	}
	ct.meter.SyncLedgerState(charged, cleanup, workCap)
}

func appendCampaignRecord(f *os.File, seq uint64, rec campaignJournalRecord) ([]byte, campaignJournalRecord, error) {
	rec.Version = campaignJournalVersion
	rec.Seq = seq
	line, err := json.Marshal(rec)
	if err != nil {
		return nil, rec, err
	}
	line = append(line, '\n')
	off, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, rec, err
	}
	n, err := f.Write(line)
	if err != nil {
		_ = f.Truncate(off)
		return nil, rec, err
	}
	if n != len(line) {
		_ = f.Truncate(off)
		return nil, rec, io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		_ = f.Truncate(off)
		return nil, rec, err
	}
	return line, rec, nil
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

	_ = os.Remove(ct.statePath + ".compact.tmp")

	f, fileCreated, err := openCampaignFileNoFollow(ct.statePath)
	if err != nil {
		return err
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()

	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat campaign %s: %w", ct.statePath, err)
	}
	if fi.Size() > safety.MaxJournalFileBytes {
		return fmt.Errorf("campaign %s exceeds maximum size of %d bytes", ct.statePath, safety.MaxJournalFileBytes)
	}
	var raw []byte
	if fi.Size() > 0 {
		raw = make([]byte, fi.Size())
		if _, err := io.ReadFull(f, raw); err != nil {
			return fmt.Errorf("read campaign %s: %w", ct.statePath, err)
		}
	}
	st, err := ct.replayCampaignBytes(raw)
	if err != nil {
		return err
	}
	st.journalFileBytes = len(raw)
	if createIfMissing && fn != nil && len(raw) > 310<<10 {
		if compactedRaw, compactedRecs, compactedSeq, ok := compactSupersededCampaignStates(raw, ct.verifiedCampaignRecs); ok && len(compactedRaw) < len(raw) {
			newF, _ := rewriteCampaignFileAtomic(ct.statePath, compactedRaw)
			if newF != nil {
				_ = f.Close()
				f = newF
				st.lastSeq = compactedSeq
				st.journalFileBytes = len(compactedRaw)
				raw = compactedRaw
				ct.verifiedCampaignRaw = append(ct.verifiedCampaignRaw[:0], compactedRaw...)
				ct.verifiedCampaignRecs = compactedRecs
			}
		}
	}
	ct.applyReplayedStateLocked(st)

	if fn != nil {
		appendFn := func(rec campaignJournalRecord) error {
			if st.lastSeq == 0 {
				metaLine, metaRec, err := appendCampaignRecord(f, 1, ct.campaignMetaRecord())
				if err != nil {
					return err
				}
				st.lastSeq = 1
				st.journalFileBytes += len(metaLine)
				ct.verifiedCampaignRaw = append(ct.verifiedCampaignRaw[:0], metaLine...)
				ct.verifiedCampaignRecs = []campaignJournalRecord{metaRec}
			}
			nextSeq := st.lastSeq + 1
			line, savedRec, err := appendCampaignRecord(f, nextSeq, rec)
			if err != nil {
				return err
			}
			st.lastSeq = nextSeq
			st.journalFileBytes += len(line)
			if len(ct.verifiedCampaignRecs) == int(nextSeq-1) {
				ct.verifiedCampaignRaw = append(ct.verifiedCampaignRaw, line...)
				ct.verifiedCampaignRecs = append(ct.verifiedCampaignRecs, savedRec)
			}
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

func compactSupersededCampaignStates(raw []byte, cachedRecs []campaignJournalRecord) ([]byte, []campaignJournalRecord, uint64, bool) {
	recs := cachedRecs
	if len(recs) == 0 {
		lines := bytes.Split(raw, []byte{'\n'})
		recs = make([]campaignJournalRecord, 0, len(lines))
		for i, line := range lines {
			if i == len(lines)-1 && len(line) == 0 {
				continue
			}
			var rec campaignJournalRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				return nil, nil, 0, false
			}
			recs = append(recs, rec)
		}
	}
	lastUserpoolState := make(map[string]int)
	lastFunctionState := make(map[string]int)
	for idx, rec := range recs {
		switch rec.Event {
		case safety.EventUserpoolState:
			uKey := scopedResKey(rec.Endpoint, rec.ResKey)
			lastUserpoolState[uKey] = idx
		case safety.EventUserpoolConfirm:
			if rec.UserpoolState != "" {
				uKey := scopedResKey(rec.Endpoint, rec.ResKey)
				delete(lastUserpoolState, uKey)
			}
		case safety.EventUserpoolDelete:
			uKey := scopedResKey(rec.Endpoint, rec.ResKey)
			delete(lastUserpoolState, uKey)
		case safety.EventFunctionPreviewState:
			fKey := scopedResKey(rec.Endpoint, rec.ResKey)
			lastFunctionState[fKey] = idx
		case safety.EventFunctionConfirm:
			if rec.FunctionState != "" {
				fKey := scopedResKey(rec.Endpoint, rec.ResKey)
				delete(lastFunctionState, fKey)
			}
		case safety.EventFunctionDelete:
			fKey := scopedResKey(rec.Endpoint, rec.ResKey)
			delete(lastFunctionState, fKey)
		}
	}
	dropped := 0
	droppedBytes := 0
	for idx, rec := range recs {
		if rec.Event == safety.EventUserpoolState {
			uKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if lastIdx, ok := lastUserpoolState[uKey]; !ok || lastIdx != idx {
				dropped++
				droppedBytes += len(rec.UserpoolState) + 128
			}
		} else if rec.Event == safety.EventFunctionPreviewState {
			fKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if lastIdx, ok := lastFunctionState[fKey]; !ok || lastIdx != idx {
				dropped++
				droppedBytes += len(rec.FunctionState) + 128
			}
		}
	}
	var foldDrop map[int]bool
	var foldedMeta campaignJournalRecord
	foldedAny := false
	nearHardLimit := int64(len(raw))+1024 > safety.MaxJournalFileBytes
	if nearHardLimit && len(recs) > 0 && recs[0].Event == safety.EventMeta {
		foldDrop = make(map[int]bool)
		foldedMeta = recs[0]
		metaOps := make(map[string]persistedOpCost, len(foldedMeta.OpStats))
		for k, v := range foldedMeta.OpStats {
			metaOps[k] = v
		}
		type idxPair struct{ rIdx, sIdx int }
		pendingRes := make(map[string]int)
		activeChild := make(map[string]bool)
		childPairs := make(map[string][]idxPair)
		var foldablePairs []idxPair
		for idx, rec := range recs {
			switch rec.Event {
			case safety.EventReserve:
				pendingRes[rec.AttemptID] = idx
			case safety.EventSettle:
				rIdx, ok := pendingRes[rec.AttemptID]
				if !ok {
					continue
				}
				delete(pendingRes, rec.AttemptID)
				rRec := recs[rIdx]
				if !rec.LockCleanup && !rec.ReleaseCleanup {
					foldablePairs = append(foldablePairs, idxPair{rIdx, idx})
				} else if rRec.ResKind == safety.KindPoolUser || rRec.ResKind == safety.KindPoolGroup || rRec.ResKind == safety.KindPoolMembership {
					cKey := rRec.ResKind + "\x00" + scopedResKey(rRec.Endpoint, rRec.ResKey)
					if rec.LockCleanup {
						activeChild[cKey] = true
					}
					if rec.ReleaseCleanup {
						activeChild[cKey] = false
					}
					childPairs[cKey] = append(childPairs[cKey], idxPair{rIdx, idx})
				}
			case safety.EventUserpoolDelete:
				prefix := scopedResKey(rec.Endpoint, rec.ResKey) + "/"
				for cKey := range activeChild {
					if sep := strings.IndexByte(cKey, '\x00'); sep >= 0 && strings.HasPrefix(cKey[sep+1:], prefix) {
						activeChild[cKey] = false
					}
				}
			}
		}
		for cKey, pairs := range childPairs {
			if !activeChild[cKey] {
				foldablePairs = append(foldablePairs, pairs...)
			}
		}
		for _, pair := range foldablePairs {
			foldDrop[pair.rIdx] = true
			foldDrop[pair.sIdx] = true
			dropped += 2
			droppedBytes += 400
			foldedAny = true
			p := recs[pair.rIdx]
			s := recs[pair.sIdx]
			if s.BillingUnits == 0 && s.ChargedNanoUSD == 0 && !s.LockCleanup && !s.ReleaseCleanup {
				continue
			}
			charge := s.ChargedNanoUSD
			foldedMeta.ChargedNanoUSD += charge
			cur := metaOps[p.Operation]
			cur.Requests++
			cur.BillingUnits += s.BillingUnits
			cur.Bytes += s.SettledBytes
			cur.ChargedNanoUSD += charge
			metaOps[p.Operation] = cur
		}
		if len(metaOps) > 0 {
			foldedMeta.OpStats = metaOps
		}
	}
	if !nearHardLimit {
		if (dropped < 4 && droppedBytes <= 256<<10) || (len(raw) > 2<<20 && droppedBytes <= 256<<10) {
			return nil, nil, 0, false
		}
	} else if dropped == 0 {
		return nil, nil, 0, false
	}
	rawLines := bytes.Split(raw, []byte{'\n'})
	var buf bytes.Buffer
	compactedRecs := make([]campaignJournalRecord, 0, len(recs)-dropped)
	var seq uint64
	for idx, rec := range recs {
		if foldDrop[idx] {
			continue
		}
		if idx == 0 && foldedAny {
			rec = foldedMeta
		}
		if rec.Event == safety.EventUserpoolState {
			uKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if lastIdx, ok := lastUserpoolState[uKey]; !ok || lastIdx != idx {
				continue
			}
		}
		if rec.Event == safety.EventFunctionPreviewState {
			fKey := scopedResKey(rec.Endpoint, rec.ResKey)
			if lastIdx, ok := lastFunctionState[fKey]; !ok || lastIdx != idx {
				continue
			}
		}
		seq++
		origSeq := rec.Seq
		rec.Seq = seq
		compactedRecs = append(compactedRecs, rec)
		if !(idx == 0 && foldedAny) && idx < len(rawLines) && len(rawLines[idx]) > 0 {
			if origSeq == seq {
				buf.Write(rawLines[idx])
				buf.WriteByte('\n')
				continue
			}
			oldPrefix := fmt.Sprintf(`{"v":%d,"seq":%d,`, rec.Version, origSeq)
			if bytes.HasPrefix(rawLines[idx], []byte(oldPrefix)) {
				newPrefix := fmt.Sprintf(`{"v":%d,"seq":%d,`, rec.Version, seq)
				buf.WriteString(newPrefix)
				buf.Write(rawLines[idx][len(oldPrefix):])
				buf.WriteByte('\n')
				continue
			}
		}
		b, err := json.Marshal(rec)
		if err != nil {
			return nil, nil, 0, false
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), compactedRecs, seq, true
}

// opusCrashHook, opusStepHook, and opusDirSyncFail are fault-injection hooks for testing crash-safety during campaign journal compaction.
var (
	opusCrashHook   func(*os.File, []byte)
	opusStepHook    func(string)
	opusDirSyncFail func() bool
)

func opusStep(s string) {
	if opusStepHook != nil {
		opusStepHook(s)
	}
}

func rewriteCampaignFileAtomic(statePath string, raw []byte) (*os.File, error) {
	tmpPath := statePath + ".compact.tmp"
	_ = os.Remove(tmpPath)
	tf, _, err := openCampaignFileNoFollow(tmpPath)
	if err != nil {
		return nil, err
	}
	cleanupTmp := func() {
		_ = tf.Close()
		_ = os.Remove(tmpPath)
	}
	if _, err := tf.Seek(0, io.SeekStart); err != nil {
		cleanupTmp()
		return nil, err
	}
	if err := tf.Truncate(0); err != nil {
		cleanupTmp()
		return nil, err
	}
	if opusCrashHook != nil {
		opusCrashHook(tf, raw)
	}
	opusStep("tmp_open")
	n, err := tf.Write(raw)
	if err != nil {
		cleanupTmp()
		return nil, err
	}
	if n != len(raw) {
		cleanupTmp()
		return nil, io.ErrShortWrite
	}
	opusStep("tmp_written")
	if err := tf.Sync(); err != nil {
		cleanupTmp()
		return nil, err
	}
	opusStep("tmp_synced")
	if err := os.Rename(tmpPath, statePath); err != nil {
		cleanupTmp()
		return nil, err
	}
	opusStep("renamed")
	var syncErr error
	if opusDirSyncFail != nil && opusDirSyncFail() {
		syncErr = errors.New("injected dir fsync failure")
	} else if err := syncCampaignDir(filepath.Dir(statePath)); err != nil {
		syncErr = err
	} else {
		opusStep("dir_synced")
	}
	return tf, syncErr
}

func (ct *costTracker) syncFromSafetyJournalLocked() {
	if ct.journal == nil {
		return
	}
	st := ct.journal.State()
	var activeCleanup int64
	pt := ct.meter.Table()
	seenKeys := make(map[string]bool, len(st.Entries))
	for _, e := range st.Entries {
		if e.State == safety.StateDeleted {
			continue
		}
		seenKeys[e.Kind+"\x00"+e.Parent+"\x00"+e.Name] = true
		if pt != nil {
			switch e.Kind {
			case safety.KindBucket:
				activeCleanup += pt.Operations["bucket_create"].CleanupReserveNanoUSD
			case safety.KindObject:
				activeCleanup += pt.Operations["object_put"].CleanupReserveNanoUSD
			case safety.KindQueue:
				activeCleanup += pt.Operations["queue_create"].CleanupReserveNanoUSD
			case safety.KindTable:
				activeCleanup += pt.Operations["table_create"].CleanupReserveNanoUSD
			case safety.KindTableItem:
				activeCleanup += pt.Operations["item_put"].CleanupReserveNanoUSD
			case safety.KindFunction:
				activeCleanup += pt.Operations["function_create"].CleanupReserveNanoUSD
			case safety.KindFunctionVersion:
				activeCleanup += pt.Operations["function_publish_version"].CleanupReserveNanoUSD
			case safety.KindFunctionAlias:
				activeCleanup += pt.Operations["function_alias_set"].CleanupReserveNanoUSD
			case safety.KindUserpool:
				activeCleanup += pt.Operations["userpool_create"].CleanupReserveNanoUSD
			case safety.KindPoolUser:
				activeCleanup += pt.Operations["user_create"].CleanupReserveNanoUSD
			case safety.KindPoolGroup:
				activeCleanup += pt.Operations["group_create"].CleanupReserveNanoUSD
			case safety.KindPoolMembership:
				activeCleanup += pt.Operations["group_add_user"].CleanupReserveNanoUSD
			}
		}
	}
	for k, v := range st.ActiveCleanup {
		if !seenKeys[k] && v > 0 {
			activeCleanup += v
		}
	}
	pendingReserved := st.ReservedNanoUSD
	for _, att := range st.PendingAttempts {
		if ct.inFlightAttempts[att.AttemptID] && att.ReservedNanoUSD > 0 {
			pendingReserved -= att.ReservedNanoUSD
		}
	}
	if pendingReserved < 0 {
		pendingReserved = 0
	}
	charged := st.ChargedNanoUSD + pendingReserved
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
	ct.activePolicies = make(map[string]hostkit.PolicyAttachment, len(st.PolicyAttachments))
	for k, pa := range st.PolicyAttachments {
		stmts, canonical, cerr := hostkit.ParsePolicyDocument(pa.Document, hostkit.Validator{})
		if cerr != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalCorrupt", cerr.Error())
			return
		}
		if ct.onToken != nil && pa.OwnerToken != "" {
			ct.onToken(pa.OwnerToken)
		}
		ct.activePolicies[k] = hostkit.PolicyAttachment{
			Key:        k,
			Scope:      pa.Scope,
			Kind:       hostkit.AttachmentKind(pa.Kind),
			Target:     pa.Target,
			Principal:  pa.Principal,
			Document:   canonical,
			Statements: stmts,
			OwnerToken: pa.OwnerToken,
			Generation: pa.Generation,
			IntentID:   pa.IntentID,
		}
	}
	ct.ambiguousPolicies = make(map[string]hostkit.PolicyAttachment, len(st.AmbiguousPolicies))
	for k, pa := range st.AmbiguousPolicies {
		var stmts []hostkit.PolicyStatement
		var canonical string
		if pa.Document != "" {
			var cerr *hostkit.CloudError
			stmts, canonical, cerr = hostkit.ParsePolicyDocument(pa.Document, hostkit.Validator{})
			if cerr != nil {
				ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalCorrupt", cerr.Error())
				return
			}
		}
		if ct.onToken != nil && pa.OwnerToken != "" {
			ct.onToken(pa.OwnerToken)
		}
		ct.ambiguousPolicies[k] = hostkit.PolicyAttachment{
			Key:        k,
			Scope:      pa.Scope,
			Kind:       hostkit.AttachmentKind(pa.Kind),
			Target:     pa.Target,
			Principal:  pa.Principal,
			Document:   canonical,
			Statements: stmts,
			OwnerToken: pa.OwnerToken,
			Generation: pa.Generation,
			IntentID:   pa.IntentID,
		}
	}
	ct.ambiguousStack = make(map[string][]hostkit.PolicyAttachment, len(st.AmbiguousStack))
	for k, stack := range st.AmbiguousStack {
		cp := make([]hostkit.PolicyAttachment, 0, len(stack))
		for _, pa := range stack {
			var stmts []hostkit.PolicyStatement
			var canonical string
			if pa.Document != "" {
				var cerr *hostkit.CloudError
				stmts, canonical, cerr = hostkit.ParsePolicyDocument(pa.Document, hostkit.Validator{})
				if cerr != nil {
					ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalCorrupt", cerr.Error())
					return
				}
			}
			cp = append(cp, hostkit.PolicyAttachment{
				Key:        k,
				Scope:      pa.Scope,
				Kind:       hostkit.AttachmentKind(pa.Kind),
				Target:     pa.Target,
				Principal:  pa.Principal,
				Document:   canonical,
				Statements: stmts,
				OwnerToken: pa.OwnerToken,
				Generation: pa.Generation,
				IntentID:   pa.IntentID,
			})
		}
		ct.ambiguousStack[k] = cp
	}
	ct.policyOwnerTokens = make(map[string]string, len(st.PolicyTombstones))
	for k, tb := range st.PolicyTombstones {
		if tb.OwnerToken != "" {
			ct.policyOwnerTokens[k] = tb.OwnerToken
		}
	}
	ct.maxPolicyGen = make(map[string]uint64, len(st.MaxPolicyGen))
	for k, v := range st.MaxPolicyGen {
		ct.maxPolicyGen[k] = v
	}
	ct.latestPolicyIntent = make(map[string]string, len(st.LatestPolicyIntent))
	for k, v := range st.LatestPolicyIntent {
		ct.latestPolicyIntent[k] = v
	}
	ct.activeFunctionEntries = make(map[string]safety.JournalFunctionEntry, len(st.ActiveFunctions))
	for k, fe := range st.ActiveFunctions {
		ct.activeFunctionEntries[k] = fe
		if ct.onToken != nil && fe.OwnerToken != "" {
			ct.onToken(fe.OwnerToken)
		}
	}
	ct.ambiguousFunctions = make(map[string]safety.JournalFunctionEntry, len(st.AmbiguousFunctions))
	for k, fe := range st.AmbiguousFunctions {
		ct.ambiguousFunctions[k] = fe
		if ct.onToken != nil && fe.OwnerToken != "" {
			ct.onToken(fe.OwnerToken)
		}
	}
	ct.ambiguousFunctionStack = make(map[string][]safety.JournalFunctionEntry, len(st.AmbiguousFunctionStack))
	for k, stack := range st.AmbiguousFunctionStack {
		cp := make([]safety.JournalFunctionEntry, len(stack))
		copy(cp, stack)
		ct.ambiguousFunctionStack[k] = cp
	}
	ct.functionOwnerTokens = make(map[string]string, len(st.FunctionTombstones))
	for k, tb := range st.FunctionTombstones {
		if tb.OwnerToken != "" {
			ct.functionOwnerTokens[k] = tb.OwnerToken
		}
	}
	ct.maxFunctionGen = make(map[string]uint64, len(st.MaxFunctionGen))
	for k, v := range st.MaxFunctionGen {
		ct.maxFunctionGen[k] = v
	}
	ct.latestFunctionIntent = make(map[string]string, len(st.LatestFunctionIntent))
	for k, v := range st.LatestFunctionIntent {
		ct.latestFunctionIntent[k] = v
	}
	ct.activeUserpoolEntries = make(map[string]safety.JournalUserpoolEntry, len(st.ActiveUserpools))
	for k, ue := range st.ActiveUserpools {
		ct.activeUserpoolEntries[k] = ue
		if ct.onToken != nil && ue.OwnerToken != "" {
			ct.onToken(ue.OwnerToken)
		}
	}
	ct.ambiguousUserpools = make(map[string]safety.JournalUserpoolEntry, len(st.AmbiguousUserpools))
	for k, ue := range st.AmbiguousUserpools {
		ct.ambiguousUserpools[k] = ue
		if ct.onToken != nil && ue.OwnerToken != "" {
			ct.onToken(ue.OwnerToken)
		}
	}
	ct.ambiguousUserpoolStack = make(map[string][]safety.JournalUserpoolEntry, len(st.AmbiguousUserpoolStack))
	for k, stack := range st.AmbiguousUserpoolStack {
		cp := make([]safety.JournalUserpoolEntry, len(stack))
		copy(cp, stack)
		ct.ambiguousUserpoolStack[k] = cp
	}
	ct.userpoolOwnerTokens = make(map[string]string, len(st.UserpoolTombstones))
	for k, tb := range st.UserpoolTombstones {
		if tb.OwnerToken != "" {
			ct.userpoolOwnerTokens[k] = tb.OwnerToken
		}
	}
	ct.maxUserpoolGen = make(map[string]uint64, len(st.MaxUserpoolGen))
	for k, v := range st.MaxUserpoolGen {
		ct.maxUserpoolGen[k] = v
	}
	ct.latestUserpoolIntent = make(map[string]string, len(st.LatestUserpoolIntent))
	for k, v := range st.LatestUserpoolIntent {
		ct.latestUserpoolIntent[k] = v
	}
}

func (ct *costTracker) reserve(in safety.AttemptPricingInput, resKind, resKey string) (*safety.AttemptReservation, string, *hostkit.CloudError) {
	return ct.reserveForOp(in.Operation, "", in, resKind, resKey)
}

func (ct *costTracker) reserveForOp(recordOp, endpoint string, in safety.AttemptPricingInput, resKind, resKey string) (*safety.AttemptReservation, string, *hostkit.CloudError) {
	if recordOp == "" {
		recordOp = in.Operation
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if ct.poisoned != nil {
		return nil, "", ct.poisoned
	}
	if ct.isServiceDelegated(in.Operation, resKind) {
		return nil, "", nil
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return nil, "", ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return nil, "", ct.poisoned
		}
		res, err := ct.meter.ReserveAttempt(in)
		if err != nil {
			if errors.Is(err, safety.ErrCostCapExceeded) {
				if jerr := ct.journal.RecordCapExceeded(recordOp); jerr != nil {
					ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", jerr.Error())
					return nil, "", ct.poisoned
				}
				ct.capExceededCount++
				return nil, "", hostkit.ProviderError(hostkit.CostCapExceeded, 0, "CostCapExceeded", err.Error())
			}
			return nil, "", hostkit.ProviderError(hostkit.Internal, 0, "PricingFailure", err.Error())
		}
		if ct.liveGuard != nil || (ct.liveMode && (isTablesOp(in.Operation, resKind) || isPermissionsOp(in.Operation, resKind) || isFunctionOp(in.Operation, resKind) || isUserpoolOp(in.Operation, resKind))) {
			res.Release()
			return nil, "", hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveGuardRequired",
				fmt.Sprintf("live mode refuses unguarded adapter for %s (%s): LiveGuard ownership and recovery enforcement is required", in.Operation, resKind))
		}
		if !in.IsCleanup && ct.journal.FileSize()+4096 > maxNonCleanupJournalBytes {
			_ = ct.journal.Compact()
			if ct.journal.FileSize()+4096 > maxNonCleanupJournalBytes {
				res.Release()
				return nil, "", hostkit.ProviderError(hostkit.InvalidArgument, 0, "JournalSizeLimitExceeded",
					fmt.Sprintf("journal size exceeds non-cleanup headroom limit (%d bytes); only cleanup operations are permitted", maxNonCleanupJournalBytes))
			}
		}
		if in.IsCleanup && ct.journal.FileSize()+512 > safety.MaxJournalFileBytes {
			_ = ct.journal.Compact()
			if ct.journal.FileSize()+512 > safety.MaxJournalFileBytes {
				res.Release()
				return nil, "", hostkit.ProviderError(hostkit.InvalidArgument, 0, "JournalSizeLimitExceeded",
					fmt.Sprintf("journal size exceeds hard limit (%d bytes)", safety.MaxJournalFileBytes))
			}
		}
		reservedBytes := in.PayloadSize
		if in.Operation == "object_get" {
			reservedBytes = in.EgressBytes
		} else if in.Operation == "function_invoke" {
			reservedBytes = in.PayloadSize + in.EgressBytes
		}
		reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD
		attID, jerr := ct.journal.BeginAttempt(resKind, endpoint, journalAttemptName(resKey), recordOp, reservedNano, reservedBytes)
		if jerr != nil {
			res.Release()
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", jerr.Error())
			return nil, "", ct.poisoned
		}
		ct.inFlightAttempts[attID] = true
		return res, attID, nil
	}

	if ct.liveGuard != nil || (ct.liveMode && (isTablesOp(in.Operation, resKind) || isPermissionsOp(in.Operation, resKind) || isFunctionOp(in.Operation, resKind) || isUserpoolOp(in.Operation, resKind))) {
		return nil, "", hostkit.ProviderError(hostkit.PermissionDenied, 0, "LiveGuardRequired",
			fmt.Sprintf("live mode refuses unguarded adapter for %s (%s): LiveGuard ownership and recovery enforcement is required", in.Operation, resKind))
	}

	if ct.statePath != "" {
		var (
			res   *safety.AttemptReservation
			attID string
			cerr  *hostkit.CloudError
		)
		jerr := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !in.IsCleanup && st.journalFileBytes+4096 > maxNonCleanupJournalBytes {
				cerr = hostkit.ProviderError(hostkit.InvalidArgument, 0, "JournalSizeLimitExceeded",
					fmt.Sprintf("campaign journal size exceeds non-cleanup headroom limit (%d bytes); only cleanup operations are permitted", maxNonCleanupJournalBytes))
				return nil
			}
			if in.IsCleanup && int64(st.journalFileBytes)+512 > safety.MaxJournalFileBytes {
				cerr = hostkit.ProviderError(hostkit.InvalidArgument, 0, "JournalSizeLimitExceeded",
					fmt.Sprintf("campaign journal size exceeds hard limit (%d bytes)", safety.MaxJournalFileBytes))
				return nil
			}
			var rerr error
			res, rerr = ct.meter.ReserveAttempt(in)
			if rerr != nil {
				if errors.Is(rerr, safety.ErrCostCapExceeded) {
					if aerr := appendRec(campaignJournalRecord{
						Event:     safety.EventCapExceeded,
						Operation: recordOp,
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
			} else if in.Operation == "function_invoke" {
				reservedBytes = in.PayloadSize + in.EgressBytes
			}
			if aerr := appendRec(campaignJournalRecord{
				Event:                 safety.EventReserve,
				AttemptID:             attID,
				Endpoint:              endpoint,
				Operation:             recordOp,
				ResKind:               resKind,
				ResKey:                resKey,
				IsCleanup:             in.IsCleanup,
				AttemptNanoUSD:        res.Quote().AttemptNanoUSD,
				CleanupReserveNanoUSD: res.Quote().CleanupReserveNanoUSD,
				ReservedBytes:         reservedBytes,
				BillingUnits:          res.Quote().BillingUnits,
			}); aerr != nil {
				res.Release()
				res = nil
				attID = ""
				return aerr
			}
			ct.inFlightAttempts[attID] = true
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

	if ct.journal != nil && attemptID != "" {
		res.Release()
		delete(ct.inFlightAttempts, attemptID)
		if err := ct.journal.SettleAttemptWithDetails(attemptID, 0, 0, 0, true); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return nil
	}
	if ct.statePath != "" && attemptID != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			res.Release()
			delete(ct.inFlightAttempts, attemptID)
			if err := appendRec(campaignJournalRecord{
				Event:     safety.EventSettle,
				AttemptID: attemptID,
			}); err != nil {
				return err
			}
			delete(st.pending, attemptID)
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}
	res.Release()
	delete(ct.inFlightAttempts, attemptID)
	return nil
}

func (ct *costTracker) settle(res *safety.AttemptReservation, attemptID, op string, chargeBytes, reportedBytes int64, resKind, resKey string, cleanSuccess, opSucceeded bool) *hostkit.CloudError {
	return ct.settleAt(res, attemptID, op, "", chargeBytes, reportedBytes, resKind, resKey, cleanSuccess, opSucceeded)
}

func (ct *costTracker) settleAt(res *safety.AttemptReservation, attemptID, op, endpoint string, chargeBytes, reportedBytes int64, resKind, resKey string, cleanSuccess, opSucceeded bool) *hostkit.CloudError {
	return ct.settleAtWithUnits(res, attemptID, op, endpoint, chargeBytes, reportedBytes, 0, resKind, resKey, cleanSuccess, opSucceeded)
}

func (ct *costTracker) settleAtWithUnits(res *safety.AttemptReservation, attemptID, op, endpoint string, chargeBytes, reportedBytes, overrideUnits int64, resKind, resKey string, cleanSuccess, opSucceeded bool) *hostkit.CloudError {
	if res == nil {
		return nil
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()

	tariffOp := op
	if qOp := res.Quote().Operation; qOp != "" {
		tariffOp = qOp
	}
	pt := ct.meter.Table()
	var actualNano int64 = -1
	var units int64 = 1
	if overrideUnits > 0 {
		units = overrideUnits
	}
	if pt != nil {
		t, ok := pt.Operations[tariffOp]
		if !ok && tariffOp == "object_list_all" {
			t, ok = pt.Operations["object_list"]
		}
		if ok {
			if overrideUnits <= 0 && t.ChunkBytes > 0 && chargeBytes > t.ChunkBytes {
				units = (chargeBytes + t.ChunkBytes - 1) / t.ChunkBytes
			}
			in := safety.AttemptPricingInput{
				Operation:    tariffOp,
				IsCleanup:    res.Quote().IsCleanup,
				BillingUnits: units,
			}
			if tariffOp == "object_get" || tariffOp == "function_invoke" {
				in.EgressBytes = chargeBytes
			} else {
				in.PayloadSize = chargeBytes
			}
			if q, err := ct.meter.QuoteAttempt(in); err == nil {
				actualNano = q.AttemptNanoUSD
			}
		}
	}
	if !cleanSuccess && actualNano < res.Quote().AttemptNanoUSD {
		// Ambiguous or interrupted transfer: preserve the full reserved quote.
		actualNano = res.Quote().AttemptNanoUSD
		if res.Quote().BillingUnits > units {
			units = res.Quote().BillingUnits
		}
	}
	var excessErr *hostkit.CloudError
	if actualNano > res.Quote().AttemptNanoUSD {
		excessErr = hostkit.ProviderError(hostkit.Internal, 0, "ReservationExceeded",
			fmt.Sprintf("%s settled cost %d nano-USD exceeds admitted reservation %d nano-USD", tariffOp, actualNano, res.Quote().AttemptNanoUSD))
	}

	sKey := scopedResKey(endpoint, resKey)

	if ct.journal != nil {
		st := ct.journal.State()
		attName := journalAttemptName(resKey)
		rKey := resKind + "\x00" + endpoint + "\x00" + attName
		_, inEntries := st.Lookup(resKind, "", attName)
		_, inActiveCleanup := st.ActiveCleanup[rKey]
		lockCleanup := false
		releaseCleanup := false
		var cleanupNano int64
		if opSucceeded {
			switch op {
			case "bucket_create", "object_put", "queue_create", "table_create", "item_put", "policy_attach", "policy_attach_principal", "function_create", "function_publish_version", "function_alias_set", "userpool_create", "user_create", "group_create", "group_add_user":
				if !inEntries && !inActiveCleanup && res.Quote().CleanupReserveNanoUSD > 0 {
					lockCleanup = true
					cleanupNano = res.Quote().CleanupReserveNanoUSD
				}
			case "bucket_delete", "object_delete", "queue_delete", "item_delete", "policy_detach", "policy_detach_principal", "function_alias_delete", "user_delete", "group_delete", "group_remove_user":
				if inActiveCleanup || inEntries {
					releaseCleanup = true
				}
			case "table_delete":
				if inActiveCleanup || inEntries || hasJournalTableChildItems(st.ActiveCleanup, endpoint, resKey) {
					releaseCleanup = true
				}
			case "function_delete":
				if inActiveCleanup || inEntries || hasJournalFunctionChildren(st.ActiveCleanup, endpoint, resKey) {
					releaseCleanup = true
				}
			case "userpool_delete":
				if inActiveCleanup || inEntries || hasJournalUserpoolChildren(st.ActiveCleanup, endpoint, resKey) {
					releaseCleanup = true
				}
			}
		}
		charged := res.Commit(actualNano, lockCleanup)
		delete(ct.inFlightAttempts, attemptID)
		if err := ct.journal.SettleAttemptWithCleanup(attemptID, charged, reportedBytes, units, cleanupNano, releaseCleanup, cleanSuccess); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if excessErr != nil {
			ct.poisoned = excessErr
			return excessErr
		}
		return nil
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			lockCleanup := false
			releaseCleanup := false
			if opSucceeded {
				switch op {
				case "bucket_create":
					if _, exists := st.activeBuckets[sKey]; !exists {
						lockCleanup = true
					}
				case "object_put":
					if _, exists := st.activeObjects[sKey]; !exists {
						lockCleanup = true
					}
				case "queue_create":
					if _, exists := st.activeQueues[sKey]; !exists {
						lockCleanup = true
					}
				case "table_create":
					if _, exists := st.activeTables[sKey]; !exists {
						lockCleanup = true
					}
				case "item_put":
					if _, exists := st.activeItems[sKey]; !exists {
						lockCleanup = true
					}
				case "policy_attach", "policy_attach_principal":
					if _, exists := st.policyCleanup[resKey]; !exists {
						lockCleanup = true
					}
				case "function_create":
					if _, exists := st.activeFunctions[sKey]; !exists {
						lockCleanup = true
					}
				case "function_publish_version":
					if _, exists := st.activeFunctionVersions[sKey]; !exists {
						lockCleanup = true
					}
				case "function_alias_set":
					if _, exists := st.activeFunctionAliases[sKey]; !exists {
						lockCleanup = true
					}
				case "userpool_create":
					if _, exists := st.activeUserpools[sKey]; !exists {
						lockCleanup = true
					}
				case "user_create":
					if _, exists := st.activePoolUsers[sKey]; !exists {
						lockCleanup = true
					}
				case "group_create":
					if _, exists := st.activePoolGroups[sKey]; !exists {
						lockCleanup = true
					}
				case "group_add_user":
					if _, exists := st.activePoolMemberships[sKey]; !exists {
						lockCleanup = true
					}
				case "bucket_delete":
					if _, exists := st.activeBuckets[sKey]; exists {
						releaseCleanup = true
					}
				case "object_delete":
					if _, exists := st.activeObjects[sKey]; exists {
						releaseCleanup = true
					}
				case "queue_delete":
					if _, exists := st.activeQueues[sKey]; exists {
						releaseCleanup = true
					}
				case "table_delete":
					if _, exists := st.activeTables[sKey]; exists || hasTableChildItems(st.activeItems, sKey) {
						releaseCleanup = true
					}
				case "item_delete":
					if _, exists := st.activeItems[sKey]; exists {
						releaseCleanup = true
					}
				case "policy_detach", "policy_detach_principal":
					if _, exists := st.policyCleanup[resKey]; exists {
						releaseCleanup = true
					}
				case "function_delete":
					if _, exists := st.activeFunctions[sKey]; exists || hasFunctionChildren(st.activeFunctionVersions, st.activeFunctionAliases, sKey) {
						releaseCleanup = true
					}
				case "function_alias_delete":
					if _, exists := st.activeFunctionAliases[sKey]; exists {
						releaseCleanup = true
					}
				case "userpool_delete":
					if _, exists := st.activeUserpools[sKey]; exists || hasUserpoolChildren(st.activePoolUsers, st.activePoolGroups, st.activePoolMemberships, sKey) {
						releaseCleanup = true
					}
				case "user_delete":
					if _, exists := st.activePoolUsers[sKey]; exists {
						releaseCleanup = true
					}
				case "group_delete":
					if _, exists := st.activePoolGroups[sKey]; exists {
						releaseCleanup = true
					}
				case "group_remove_user":
					if _, exists := st.activePoolMemberships[sKey]; exists {
						releaseCleanup = true
					}
				}
			}
			charged := res.Commit(actualNano, lockCleanup)
			delete(ct.inFlightAttempts, attemptID)
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
					st.activeBuckets[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindObject:
					st.activeObjects[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindQueue:
					st.activeQueues[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindTable:
					st.activeTables[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindTableItem:
					st.activeItems[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindPolicyAttachment:
					st.policyCleanup[resKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindFunction:
					st.activeFunctions[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindFunctionVersion:
					st.activeFunctionVersions[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindFunctionAlias:
					st.activeFunctionAliases[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindUserpool:
					st.activeUserpools[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindPoolUser:
					st.activePoolUsers[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindPoolGroup:
					st.activePoolGroups[sKey] = res.Quote().CleanupReserveNanoUSD
				case safety.KindPoolMembership:
					st.activePoolMemberships[sKey] = res.Quote().CleanupReserveNanoUSD
				}
				st.resourceCleanupNanoUSD += res.Quote().CleanupReserveNanoUSD
			}
			if releaseCleanup {
				releasedPol := deleteResourcePolicyAttachments(st.activePolicies, st.ambiguousPolicies, st.ambiguousStack, st.policyCleanup, resKind, endpoint, resKey)
				st.resourceCleanupNanoUSD -= releasedPol
				switch resKind {
				case safety.KindBucket:
					if v, ok := st.activeBuckets[sKey]; ok {
						delete(st.activeBuckets, sKey)
						st.resourceCleanupNanoUSD -= v
					}
				case safety.KindObject:
					if v, ok := st.activeObjects[sKey]; ok {
						delete(st.activeObjects, sKey)
						st.resourceCleanupNanoUSD -= v
					}
				case safety.KindQueue:
					if v, ok := st.activeQueues[sKey]; ok {
						delete(st.activeQueues, sKey)
						st.resourceCleanupNanoUSD -= v
					}
				case safety.KindTable:
					if v, ok := st.activeTables[sKey]; ok {
						delete(st.activeTables, sKey)
						st.resourceCleanupNanoUSD -= v
					}
					prefix := sKey + "/"
					for k, v := range st.activeItems {
						if strings.HasPrefix(k, prefix) {
							delete(st.activeItems, k)
							st.resourceCleanupNanoUSD -= v
						}
					}
				case safety.KindTableItem:
					if v, ok := st.activeItems[sKey]; ok {
						delete(st.activeItems, sKey)
						st.resourceCleanupNanoUSD -= v
					}
				case safety.KindPolicyAttachment:
					if v, ok := st.policyCleanup[resKey]; ok {
						delete(st.policyCleanup, resKey)
						st.resourceCleanupNanoUSD -= v
					}
				case safety.KindFunction:
					if v, ok := st.activeFunctions[sKey]; ok {
						delete(st.activeFunctions, sKey)
						st.resourceCleanupNanoUSD -= v
					}
					prefix := sKey + "/"
					for k, v := range st.activeFunctionVersions {
						if strings.HasPrefix(k, prefix) {
							delete(st.activeFunctionVersions, k)
							st.resourceCleanupNanoUSD -= v
						}
					}
					for k, v := range st.activeFunctionAliases {
						if strings.HasPrefix(k, prefix) {
							delete(st.activeFunctionAliases, k)
							st.resourceCleanupNanoUSD -= v
						}
					}
				case safety.KindFunctionAlias:
					if v, ok := st.activeFunctionAliases[sKey]; ok {
						delete(st.activeFunctionAliases, sKey)
						st.resourceCleanupNanoUSD -= v
					}
				case safety.KindUserpool:
					if v, ok := st.activeUserpools[sKey]; ok {
						delete(st.activeUserpools, sKey)
						st.resourceCleanupNanoUSD -= v
					}
					prefix := sKey + "/"
					for k, v := range st.activePoolUsers {
						if strings.HasPrefix(k, prefix) {
							delete(st.activePoolUsers, k)
							st.resourceCleanupNanoUSD -= v
						}
					}
					for k, v := range st.activePoolGroups {
						if strings.HasPrefix(k, prefix) {
							delete(st.activePoolGroups, k)
							st.resourceCleanupNanoUSD -= v
						}
					}
					for k, v := range st.activePoolMemberships {
						if strings.HasPrefix(k, prefix) {
							delete(st.activePoolMemberships, k)
							st.resourceCleanupNanoUSD -= v
						}
					}
				case safety.KindPoolUser:
					if v, ok := st.activePoolUsers[sKey]; ok {
						delete(st.activePoolUsers, sKey)
						st.resourceCleanupNanoUSD -= v
					}
					if slash := strings.IndexByte(resKey, '/'); slash > 0 && slash < len(resKey)-1 {
						poolPrefix := scopedResKey(endpoint, resKey[:slash]+"/")
						userSuffix := "/" + resKey[slash+1:]
						for k, v := range st.activePoolMemberships {
							if strings.HasPrefix(k, poolPrefix) && strings.HasSuffix(k, userSuffix) {
								delete(st.activePoolMemberships, k)
								st.resourceCleanupNanoUSD -= v
							}
						}
					}
				case safety.KindPoolGroup:
					if v, ok := st.activePoolGroups[sKey]; ok {
						delete(st.activePoolGroups, sKey)
						st.resourceCleanupNanoUSD -= v
					}
					grpPrefix := sKey + "/"
					for k, v := range st.activePoolMemberships {
						if strings.HasPrefix(k, grpPrefix) {
							delete(st.activePoolMemberships, k)
							st.resourceCleanupNanoUSD -= v
						}
					}
				case safety.KindPoolMembership:
					if v, ok := st.activePoolMemberships[sKey]; ok {
						delete(st.activePoolMemberships, sKey)
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
		if excessErr != nil {
			ct.poisoned = excessErr
			return excessErr
		}
		return nil
	}

	delete(ct.inFlightAttempts, attemptID)

	lockCleanup := false
	if opSucceeded {
		switch op {
		case "bucket_create":
			if _, exists := ct.activeBuckets[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeBuckets[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "object_put":
			if _, exists := ct.activeObjects[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeObjects[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "queue_create":
			if _, exists := ct.activeQueues[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeQueues[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "table_create":
			if _, exists := ct.activeTables[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeTables[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "item_put":
			if _, exists := ct.activeItems[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeItems[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "policy_attach", "policy_attach_principal":
			if _, exists := ct.policyCleanup[resKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.policyCleanup[resKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "function_create":
			if _, exists := ct.activeFunctions[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeFunctions[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "function_publish_version":
			if _, exists := ct.activeFunctionVersions[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeFunctionVersions[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "function_alias_set":
			if _, exists := ct.activeFunctionAliases[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeFunctionAliases[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "userpool_create":
			if _, exists := ct.activeUserpools[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activeUserpools[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "user_create":
			if _, exists := ct.activePoolUsers[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activePoolUsers[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "group_create":
			if _, exists := ct.activePoolGroups[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activePoolGroups[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		case "group_add_user":
			if _, exists := ct.activePoolMemberships[sKey]; !exists && res.Quote().CleanupReserveNanoUSD > 0 {
				ct.activePoolMemberships[sKey] = res.Quote().CleanupReserveNanoUSD
				lockCleanup = true
			}
		}
	}

	charged := res.Commit(actualNano, lockCleanup)

	if opSucceeded {
		switch op {
		case "bucket_delete":
			if released := deleteResourcePolicyAttachments(ct.activePolicies, ct.ambiguousPolicies, ct.ambiguousStack, ct.policyCleanup, safety.KindBucket, endpoint, resKey); released > 0 {
				ct.meter.ReleaseResourceCleanup(released)
			}
			if v, exists := ct.activeBuckets[sKey]; exists {
				delete(ct.activeBuckets, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		case "object_delete":
			if v, exists := ct.activeObjects[sKey]; exists {
				delete(ct.activeObjects, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		case "queue_delete":
			if released := deleteResourcePolicyAttachments(ct.activePolicies, ct.ambiguousPolicies, ct.ambiguousStack, ct.policyCleanup, safety.KindQueue, endpoint, resKey); released > 0 {
				ct.meter.ReleaseResourceCleanup(released)
			}
			if v, exists := ct.activeQueues[sKey]; exists {
				delete(ct.activeQueues, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		case "table_delete":
			if released := deleteResourcePolicyAttachments(ct.activePolicies, ct.ambiguousPolicies, ct.ambiguousStack, ct.policyCleanup, safety.KindTable, endpoint, resKey); released > 0 {
				ct.meter.ReleaseResourceCleanup(released)
			}
			if v, exists := ct.activeTables[sKey]; exists {
				delete(ct.activeTables, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
			prefix := sKey + "/"
			for k, v := range ct.activeItems {
				if strings.HasPrefix(k, prefix) {
					delete(ct.activeItems, k)
					ct.meter.ReleaseResourceCleanup(v)
				}
			}
		case "item_delete":
			if v, exists := ct.activeItems[sKey]; exists {
				delete(ct.activeItems, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		case "policy_detach", "policy_detach_principal":
			if v, exists := ct.policyCleanup[resKey]; exists {
				delete(ct.policyCleanup, resKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		case "function_delete":
			if released := deleteResourcePolicyAttachments(ct.activePolicies, ct.ambiguousPolicies, ct.ambiguousStack, ct.policyCleanup, safety.KindFunction, endpoint, resKey); released > 0 {
				ct.meter.ReleaseResourceCleanup(released)
			}
			if v, exists := ct.activeFunctions[sKey]; exists {
				delete(ct.activeFunctions, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
			prefix := sKey + "/"
			for k, v := range ct.activeFunctionVersions {
				if strings.HasPrefix(k, prefix) {
					delete(ct.activeFunctionVersions, k)
					ct.meter.ReleaseResourceCleanup(v)
				}
			}
			for k, v := range ct.activeFunctionAliases {
				if strings.HasPrefix(k, prefix) {
					delete(ct.activeFunctionAliases, k)
					ct.meter.ReleaseResourceCleanup(v)
				}
			}
		case "function_alias_delete":
			if v, exists := ct.activeFunctionAliases[sKey]; exists {
				delete(ct.activeFunctionAliases, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
		case "userpool_delete":
			if v, exists := ct.activeUserpools[sKey]; exists {
				delete(ct.activeUserpools, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
			prefix := sKey + "/"
			for k, v := range ct.activePoolUsers {
				if strings.HasPrefix(k, prefix) {
					delete(ct.activePoolUsers, k)
					ct.meter.ReleaseResourceCleanup(v)
				}
			}
			for k, v := range ct.activePoolGroups {
				if strings.HasPrefix(k, prefix) {
					delete(ct.activePoolGroups, k)
					ct.meter.ReleaseResourceCleanup(v)
				}
			}
			for k, v := range ct.activePoolMemberships {
				if strings.HasPrefix(k, prefix) {
					delete(ct.activePoolMemberships, k)
					ct.meter.ReleaseResourceCleanup(v)
				}
			}
		case "user_delete":
			if v, exists := ct.activePoolUsers[sKey]; exists {
				delete(ct.activePoolUsers, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
			if slash := strings.IndexByte(resKey, '/'); slash > 0 && slash < len(resKey)-1 {
				poolPrefix := scopedResKey(endpoint, resKey[:slash]+"/")
				userSuffix := "/" + resKey[slash+1:]
				for k, v := range ct.activePoolMemberships {
					if strings.HasPrefix(k, poolPrefix) && strings.HasSuffix(k, userSuffix) {
						delete(ct.activePoolMemberships, k)
						ct.meter.ReleaseResourceCleanup(v)
					}
				}
			}
		case "group_delete":
			if v, exists := ct.activePoolGroups[sKey]; exists {
				delete(ct.activePoolGroups, sKey)
				ct.meter.ReleaseResourceCleanup(v)
			}
			grpPrefix := sKey + "/"
			for k, v := range ct.activePoolMemberships {
				if strings.HasPrefix(k, grpPrefix) {
					delete(ct.activePoolMemberships, k)
					ct.meter.ReleaseResourceCleanup(v)
				}
			}
		case "group_remove_user":
			if v, exists := ct.activePoolMemberships[sKey]; exists {
				delete(ct.activePoolMemberships, sKey)
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
	if excessErr != nil {
		ct.poisoned = excessErr
		return excessErr
	}
	return nil
}

func (ct *costTracker) refreshStateLocked() *hostkit.CloudError {
	if ct.poisoned != nil {
		return ct.poisoned
	}
	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}
	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(false, nil); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalCorrupt", err.Error())
			return ct.poisoned
		}
	}
	return nil
}

func (ct *costTracker) isOwnedResource(resKind, resKey string) (bool, *hostkit.CloudError) {
	return ct.isOwnedResourceAt(resKind, "", resKey)
}

func (ct *costTracker) isOwnedResourceAt(resKind, endpoint, resKey string) (bool, *hostkit.CloudError) {
	if resKey == "" {
		return false, nil
	}
	if resKind == safety.KindBucket {
		if fb := strings.TrimSpace(os.Getenv("LMCLOUD_FOREIGN_BUCKET")); fb != "" && resKey == fb {
			return false, nil
		}
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return false, cerr
	}
	if ct.journal != nil {
		st := ct.journal.State()
		if _, ok := st.ActiveCleanup[resKind+"\x00"+endpoint+"\x00"+resKey]; ok {
			return true, nil
		}
		if e, ok := st.Lookup(resKind, "", resKey); ok && e.State != safety.StateDeleted {
			if (e.Location != "" && e.Location == endpoint) ||
				(e.Location == "" && (endpoint == "" || (st.Meta.Endpoint != "" && st.Meta.Endpoint == endpoint))) {
				return true, nil
			}
		}
		if endpoint == "" || (st.Meta.Endpoint != "" && st.Meta.Endpoint == endpoint) {
			if _, ok := st.ActiveCleanup[resKind+"\x00\x00"+resKey]; ok {
				return true, nil
			}
		}
		if resKind == safety.KindFunction {
			fKey := scopedResKey(endpoint, resKey)
			if _, ok := st.ActiveFunctions[fKey]; ok {
				return true, nil
			}
			if _, ok := st.AmbiguousFunctions[fKey]; ok {
				return true, nil
			}
		}
		if resKind == safety.KindUserpool {
			uKey := scopedResKey(endpoint, resKey)
			if _, ok := st.ActiveUserpools[uKey]; ok {
				return true, nil
			}
			if _, ok := st.AmbiguousUserpools[uKey]; ok {
				return true, nil
			}
		}
		return false, nil
	}
	sKey := scopedResKey(endpoint, resKey)
	switch resKind {
	case safety.KindBucket:
		_, ok := ct.activeBuckets[sKey]
		return ok, nil
	case safety.KindQueue:
		_, ok := ct.activeQueues[sKey]
		return ok, nil
	case safety.KindTable:
		_, ok := ct.activeTables[sKey]
		return ok, nil
	case safety.KindFunction:
		if _, ok := ct.activeFunctions[sKey]; ok {
			return true, nil
		}
		if _, ok := ct.activeFunctionEntries[sKey]; ok {
			return true, nil
		}
		if _, ok := ct.ambiguousFunctions[sKey]; ok {
			return true, nil
		}
		return false, nil
	case safety.KindUserpool:
		if _, ok := ct.activeUserpools[sKey]; ok {
			return true, nil
		}
		if _, ok := ct.activeUserpoolEntries[sKey]; ok {
			return true, nil
		}
		if _, ok := ct.ambiguousUserpools[sKey]; ok {
			return true, nil
		}
		return false, nil
	case safety.KindPoolUser:
		_, ok := ct.activePoolUsers[sKey]
		return ok, nil
	case safety.KindPoolGroup:
		_, ok := ct.activePoolGroups[sKey]
		return ok, nil
	case safety.KindPoolMembership:
		_, ok := ct.activePoolMemberships[sKey]
		return ok, nil
	default:
		return false, nil
	}
}

func countDistinctPolicyKeys(active, ambiguous map[string]hostkit.PolicyAttachment, excludeKey string) int {
	seen := make(map[string]struct{}, len(active)+len(ambiguous))
	for k := range active {
		if k != excludeKey {
			seen[k] = struct{}{}
		}
	}
	for k := range ambiguous {
		if k != excludeKey {
			seen[k] = struct{}{}
		}
	}
	return len(seen)
}

func (ct *costTracker) checkPolicyAttachHeadroom(scope string, kind hostkit.AttachmentKind, target, principal string) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return cerr
	}
	key := hostkit.ScopedAttachmentKey(scope, kind, target, principal)
	if countDistinctPolicyKeys(ct.activePolicies, ct.ambiguousPolicies, key) >= hostkit.MaxAttachmentsPerRun {
		return hostkit.ProviderError(hostkit.InvalidArgument, 0, "AttachmentLimitExceeded",
			fmt.Sprintf("run attachment count exceeds maximum (%d)", hostkit.MaxAttachmentsPerRun))
	}
	return nil
}

func hasPendingPolicyIntent(stack []hostkit.PolicyAttachment, amb map[string]hostkit.PolicyAttachment, key, intentID string) bool {
	if intentID == "" {
		return false
	}
	for _, item := range stack {
		if item.IntentID == intentID {
			return true
		}
	}
	if cur, ok := amb[key]; ok && cur.IntentID == intentID {
		return true
	}
	return false
}

func (ct *costTracker) beginPolicyAttachIntent(scope string, kind hostkit.AttachmentKind, target, principal string, stmts []hostkit.PolicyStatement, rawDoc string) (hostkit.PolicyAttachment, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return hostkit.PolicyAttachment{}, cerr
	}
	key := hostkit.ScopedAttachmentKey(scope, kind, target, principal)
	if countDistinctPolicyKeys(ct.activePolicies, ct.ambiguousPolicies, key) >= hostkit.MaxAttachmentsPerRun {
		return hostkit.PolicyAttachment{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "AttachmentLimitExceeded",
			fmt.Sprintf("run attachment count exceeds maximum (%d)", hostkit.MaxAttachmentsPerRun))
	}
	clonedStmts := make([]hostkit.PolicyStatement, len(stmts))
	for i, s := range stmts {
		clonedStmts[i] = s.Clone()
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return hostkit.PolicyAttachment{}, ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return hostkit.PolicyAttachment{}, ct.poisoned
		}
		if countDistinctPolicyKeys(ct.activePolicies, ct.ambiguousPolicies, key) >= hostkit.MaxAttachmentsPerRun {
			return hostkit.PolicyAttachment{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "AttachmentLimitExceeded",
				fmt.Sprintf("run attachment count exceeds maximum (%d)", hostkit.MaxAttachmentsPerRun))
		}
		ownerToken := ""
		expectedOwner := ""
		expectedGen := ""
		if existing, ok := ct.activePolicies[key]; ok && existing.OwnerToken != "" {
			ownerToken = existing.OwnerToken
			expectedOwner = existing.OwnerToken
			expectedGen = existing.Generation
		} else if amb, ok := ct.ambiguousPolicies[key]; ok && amb.OwnerToken != "" {
			ownerToken = amb.OwnerToken
			expectedOwner = amb.OwnerToken
			expectedGen = amb.Generation
		} else if tok := ct.policyOwnerTokens[key]; tok != "" {
			ownerToken = tok
			expectedOwner = tok
		} else {
			ownerToken = safety.NewToken128()
		}
		nextGen := ct.maxPolicyGen[key] + 1
		genStr := strconv.FormatUint(nextGen, 10)
		intentID := safety.NewToken128()
		if err := ct.journal.RecordPolicyIntent(scope, string(kind), target, principal, "attach", rawDoc, ownerToken, genStr, intentID, expectedOwner, expectedGen, 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return hostkit.PolicyAttachment{}, ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return hostkit.PolicyAttachment{}, ct.poisoned
		}
		if ct.onToken != nil {
			ct.onToken(ownerToken)
		}
		return hostkit.PolicyAttachment{
			Key:                key,
			Scope:              scope,
			Kind:               kind,
			Target:             target,
			Principal:          principal,
			Document:           rawDoc,
			Statements:         clonedStmts,
			OwnerToken:         ownerToken,
			Generation:         genStr,
			IntentID:           intentID,
			ExpectedOwnerToken: expectedOwner,
			ExpectedGeneration: expectedGen,
		}, nil
	}

	if ct.statePath != "" {
		var outAtt hostkit.PolicyAttachment
		var cerr *hostkit.CloudError
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if countDistinctPolicyKeys(st.activePolicies, st.ambiguousPolicies, key) >= hostkit.MaxAttachmentsPerRun {
				cerr = hostkit.ProviderError(hostkit.InvalidArgument, 0, "AttachmentLimitExceeded",
					fmt.Sprintf("run attachment count exceeds maximum (%d)", hostkit.MaxAttachmentsPerRun))
				return nil
			}
			ownerToken := ""
			expectedOwner := ""
			expectedGen := ""
			if existing, ok := st.activePolicies[key]; ok && existing.OwnerToken != "" {
				ownerToken = existing.OwnerToken
				expectedOwner = existing.OwnerToken
				expectedGen = existing.Generation
			} else if amb, ok := st.ambiguousPolicies[key]; ok && amb.OwnerToken != "" {
				ownerToken = amb.OwnerToken
				expectedOwner = amb.OwnerToken
				expectedGen = amb.Generation
			} else if tok := st.policyOwnerTokens[key]; tok != "" {
				ownerToken = tok
				expectedOwner = tok
			} else {
				ownerToken = safety.NewToken128()
			}
			nextGen := st.maxPolicyGen[key] + 1
			genStr := strconv.FormatUint(nextGen, 10)
			intentID := safety.NewToken128()
			if err := appendRec(campaignJournalRecord{
				Event:              safety.EventPolicyIntent,
				IntentID:           intentID,
				PolicyScope:        scope,
				PolicyKind:         string(kind),
				PolicyTarget:       target,
				PolicyPrincipal:    principal,
				PolicyDocument:     rawDoc,
				PolicyIntentOp:     "attach",
				OwnerToken:         ownerToken,
				Generation:         genStr,
				ExpectedOwnerToken: expectedOwner,
				ExpectedGeneration: expectedGen,
			}); err != nil {
				return err
			}
			outAtt = hostkit.PolicyAttachment{
				Key:                key,
				Scope:              scope,
				Kind:               kind,
				Target:             target,
				Principal:          principal,
				Document:           rawDoc,
				Statements:         clonedStmts,
				OwnerToken:         ownerToken,
				Generation:         genStr,
				IntentID:           intentID,
				ExpectedOwnerToken: expectedOwner,
				ExpectedGeneration: expectedGen,
			}
			st.ambiguousStack[key] = append(st.ambiguousStack[key], outAtt.Clone())
			st.ambiguousPolicies[key] = outAtt.Clone()
			st.policyOwnerTokens[key] = ownerToken
			st.maxPolicyGen[key] = nextGen
			st.latestPolicyIntent[key] = intentID
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return hostkit.PolicyAttachment{}, ct.poisoned
		}
		if cerr != nil {
			return hostkit.PolicyAttachment{}, cerr
		}
		if ct.onToken != nil {
			ct.onToken(outAtt.OwnerToken)
		}
		return outAtt, nil
	}

	ownerToken := ""
	expectedOwner := ""
	expectedGen := ""
	if existing, ok := ct.activePolicies[key]; ok && existing.OwnerToken != "" {
		ownerToken = existing.OwnerToken
		expectedOwner = existing.OwnerToken
		expectedGen = existing.Generation
	} else if amb, ok := ct.ambiguousPolicies[key]; ok && amb.OwnerToken != "" {
		ownerToken = amb.OwnerToken
		expectedOwner = amb.OwnerToken
		expectedGen = amb.Generation
	} else if tok := ct.policyOwnerTokens[key]; tok != "" {
		ownerToken = tok
		expectedOwner = tok
	} else {
		ownerToken = safety.NewToken128()
	}
	nextGen := ct.maxPolicyGen[key] + 1
	genStr := strconv.FormatUint(nextGen, 10)
	intentID := safety.NewToken128()
	att := hostkit.PolicyAttachment{
		Key:                key,
		Scope:              scope,
		Kind:               kind,
		Target:             target,
		Principal:          principal,
		Document:           rawDoc,
		Statements:         clonedStmts,
		OwnerToken:         ownerToken,
		Generation:         genStr,
		IntentID:           intentID,
		ExpectedOwnerToken: expectedOwner,
		ExpectedGeneration: expectedGen,
	}
	ct.ambiguousStack[key] = append(ct.ambiguousStack[key], att.Clone())
	ct.ambiguousPolicies[key] = att.Clone()
	ct.policyOwnerTokens[key] = ownerToken
	ct.maxPolicyGen[key] = nextGen
	ct.latestPolicyIntent[key] = intentID
	if ct.onToken != nil {
		ct.onToken(ownerToken)
	}
	return att, nil
}

func (ct *costTracker) confirmPolicyAttach(att hostkit.PolicyAttachment) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := att.Key
	if key == "" {
		key = hostkit.ScopedAttachmentKey(att.Scope, att.Kind, att.Target, att.Principal)
		att.Key = key
	}
	attGen, _ := strconv.ParseUint(att.Generation, 10, 64)

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingPolicyIntent(ct.ambiguousStack[key], ct.ambiguousPolicies, key, att.IntentID) ||
			ct.latestPolicyIntent[key] != att.IntentID || attGen < ct.maxPolicyGen[key] {
			return nil
		}
		if err := ct.journal.RecordPolicyAttachScoped(att.Scope, string(att.Kind), att.Target, att.Principal, att.Document, att.OwnerToken, att.Generation, att.IntentID, 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingPolicyIntent(st.ambiguousStack[key], st.ambiguousPolicies, key, att.IntentID) ||
				st.latestPolicyIntent[key] != att.IntentID || attGen < st.maxPolicyGen[key] {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:           safety.EventPolicyAttach,
				IntentID:        att.IntentID,
				PolicyScope:     att.Scope,
				PolicyKind:      string(att.Kind),
				PolicyTarget:    att.Target,
				PolicyPrincipal: att.Principal,
				PolicyDocument:  att.Document,
				OwnerToken:      att.OwnerToken,
				Generation:      att.Generation,
			}); err != nil {
				return err
			}
			st.activePolicies[key] = att.Clone()
			st.policyOwnerTokens[key] = att.OwnerToken
			delete(st.ambiguousStack, key)
			delete(st.ambiguousPolicies, key)
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}

	if !hasPendingPolicyIntent(ct.ambiguousStack[key], ct.ambiguousPolicies, key, att.IntentID) ||
		ct.latestPolicyIntent[key] != att.IntentID || attGen < ct.maxPolicyGen[key] {
		return nil
	}
	ct.activePolicies[key] = att.Clone()
	ct.policyOwnerTokens[key] = att.OwnerToken
	delete(ct.ambiguousStack, key)
	delete(ct.ambiguousPolicies, key)
	return nil
}

func (ct *costTracker) hasOwnedPolicyAttachment(scope string, kind hostkit.AttachmentKind, target, principal string) (bool, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return false, cerr
	}
	key := hostkit.ScopedAttachmentKey(scope, kind, target, principal)
	if _, ok := ct.activePolicies[key]; ok {
		return true, nil
	}
	if _, ok := ct.ambiguousPolicies[key]; ok {
		return true, nil
	}
	return false, nil
}

func (ct *costTracker) beginPolicyDetachIntent(scope string, kind hostkit.AttachmentKind, target, principal string) (hostkit.PolicyAttachment, bool, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return hostkit.PolicyAttachment{}, false, cerr
	}
	key := hostkit.ScopedAttachmentKey(scope, kind, target, principal)

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return hostkit.PolicyAttachment{}, false, ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return hostkit.PolicyAttachment{}, false, ct.poisoned
		}
		existing, ok := ct.activePolicies[key]
		if amb, ambOk := ct.ambiguousPolicies[key]; ambOk {
			existing = amb
			ok = true
		}
		if !ok {
			return hostkit.PolicyAttachment{}, false, nil
		}
		nextGen := ct.maxPolicyGen[key] + 1
		genStr := strconv.FormatUint(nextGen, 10)
		intentID := safety.NewToken128()
		if err := ct.journal.RecordPolicyIntent(scope, string(kind), target, principal, "detach", "", existing.OwnerToken, genStr, intentID, existing.OwnerToken, existing.Generation, 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return hostkit.PolicyAttachment{}, false, ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return hostkit.PolicyAttachment{}, false, ct.poisoned
		}
		out := existing.Clone()
		out.Key = key
		out.Scope = scope
		out.ExpectedOwnerToken = existing.OwnerToken
		out.ExpectedGeneration = existing.Generation
		out.Generation = genStr
		out.IntentID = intentID
		return out, true, nil
	}

	if ct.statePath != "" {
		var out hostkit.PolicyAttachment
		var found bool
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			existing, ok := st.activePolicies[key]
			if amb, ambOk := st.ambiguousPolicies[key]; ambOk {
				existing = amb
				ok = true
			}
			if !ok {
				return nil
			}
			nextGen := st.maxPolicyGen[key] + 1
			genStr := strconv.FormatUint(nextGen, 10)
			intentID := safety.NewToken128()
			if err := appendRec(campaignJournalRecord{
				Event:              safety.EventPolicyIntent,
				IntentID:           intentID,
				PolicyScope:        scope,
				PolicyKind:         string(kind),
				PolicyTarget:       target,
				PolicyPrincipal:    principal,
				PolicyIntentOp:     "detach",
				OwnerToken:         existing.OwnerToken,
				Generation:         genStr,
				ExpectedOwnerToken: existing.OwnerToken,
				ExpectedGeneration: existing.Generation,
			}); err != nil {
				return err
			}
			out = existing.Clone()
			out.Key = key
			out.Scope = scope
			out.ExpectedOwnerToken = existing.OwnerToken
			out.ExpectedGeneration = existing.Generation
			out.Generation = genStr
			out.IntentID = intentID
			found = true
			st.ambiguousStack[key] = append(st.ambiguousStack[key], out.Clone())
			st.ambiguousPolicies[key] = out.Clone()
			st.policyOwnerTokens[key] = existing.OwnerToken
			st.maxPolicyGen[key] = nextGen
			st.latestPolicyIntent[key] = intentID
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return hostkit.PolicyAttachment{}, false, ct.poisoned
		}
		return out, found, nil
	}

	existing, ok := ct.activePolicies[key]
	if amb, ambOk := ct.ambiguousPolicies[key]; ambOk {
		existing = amb
		ok = true
	}
	if !ok {
		return hostkit.PolicyAttachment{}, false, nil
	}
	nextGen := ct.maxPolicyGen[key] + 1
	genStr := strconv.FormatUint(nextGen, 10)
	intentID := safety.NewToken128()
	out := existing.Clone()
	out.Key = key
	out.Scope = scope
	out.ExpectedOwnerToken = existing.OwnerToken
	out.ExpectedGeneration = existing.Generation
	out.Generation = genStr
	out.IntentID = intentID
	ct.ambiguousStack[key] = append(ct.ambiguousStack[key], out.Clone())
	ct.ambiguousPolicies[key] = out.Clone()
	ct.policyOwnerTokens[key] = existing.OwnerToken
	ct.maxPolicyGen[key] = nextGen
	ct.latestPolicyIntent[key] = intentID
	return out, true, nil
}

func (ct *costTracker) confirmPolicyDetach(att hostkit.PolicyAttachment) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := att.Key
	if key == "" {
		key = hostkit.ScopedAttachmentKey(att.Scope, att.Kind, att.Target, att.Principal)
		att.Key = key
	}
	attGen, _ := strconv.ParseUint(att.Generation, 10, 64)

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingPolicyIntent(ct.ambiguousStack[key], ct.ambiguousPolicies, key, att.IntentID) ||
			ct.latestPolicyIntent[key] != att.IntentID || attGen < ct.maxPolicyGen[key] {
			return nil
		}
		if err := ct.journal.RecordPolicyDetachScoped(att.Scope, string(att.Kind), att.Target, att.Principal, att.OwnerToken, att.Generation, att.IntentID); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingPolicyIntent(st.ambiguousStack[key], st.ambiguousPolicies, key, att.IntentID) ||
				st.latestPolicyIntent[key] != att.IntentID || attGen < st.maxPolicyGen[key] {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:           safety.EventPolicyDetach,
				IntentID:        att.IntentID,
				PolicyScope:     att.Scope,
				PolicyKind:      string(att.Kind),
				PolicyTarget:    att.Target,
				PolicyPrincipal: att.Principal,
				OwnerToken:      att.OwnerToken,
				Generation:      att.Generation,
			}); err != nil {
				return err
			}
			delete(st.activePolicies, key)
			delete(st.ambiguousStack, key)
			delete(st.ambiguousPolicies, key)
			delete(st.policyCleanup, key)
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}

	if !hasPendingPolicyIntent(ct.ambiguousStack[key], ct.ambiguousPolicies, key, att.IntentID) ||
		ct.latestPolicyIntent[key] != att.IntentID || attGen < ct.maxPolicyGen[key] {
		return nil
	}
	delete(ct.activePolicies, key)
	delete(ct.ambiguousStack, key)
	delete(ct.ambiguousPolicies, key)
	if releaseNano, ok := ct.policyCleanup[key]; ok {
		delete(ct.policyCleanup, key)
		if ct.meter != nil && releaseNano > 0 {
			ct.meter.ReleaseResourceCleanup(releaseNano)
		}
	}
	return nil
}

func (ct *costTracker) abortPolicyIntent(att hostkit.PolicyAttachment) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := att.Key
	if key == "" {
		key = hostkit.ScopedAttachmentKey(att.Scope, att.Kind, att.Target, att.Principal)
		att.Key = key
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingPolicyIntent(ct.ambiguousStack[key], ct.ambiguousPolicies, key, att.IntentID) {
			return nil
		}
		if err := ct.journal.RecordPolicyIntent(att.Scope, string(att.Kind), att.Target, att.Principal, "abort", "", att.OwnerToken, att.Generation, att.IntentID, "", "", 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingPolicyIntent(st.ambiguousStack[key], st.ambiguousPolicies, key, att.IntentID) {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:           safety.EventPolicyIntent,
				IntentID:        att.IntentID,
				PolicyScope:     att.Scope,
				PolicyKind:      string(att.Kind),
				PolicyTarget:    att.Target,
				PolicyPrincipal: att.Principal,
				PolicyIntentOp:  "abort",
				OwnerToken:      att.OwnerToken,
				Generation:      att.Generation,
			}); err != nil {
				return err
			}
			stack := st.ambiguousStack[key]
			if len(stack) > 0 {
				filtered := stack[:0]
				for _, item := range stack {
					if item.IntentID != att.IntentID {
						filtered = append(filtered, item)
					}
				}
				if len(filtered) > 0 {
					st.ambiguousStack[key] = filtered
					st.ambiguousPolicies[key] = filtered[len(filtered)-1]
				} else {
					delete(st.ambiguousStack, key)
					delete(st.ambiguousPolicies, key)
					if _, inActive := st.activePolicies[key]; !inActive {
						delete(st.policyCleanup, key)
					}
				}
			} else {
				delete(st.ambiguousPolicies, key)
				if _, inActive := st.activePolicies[key]; !inActive {
					delete(st.policyCleanup, key)
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

	if !hasPendingPolicyIntent(ct.ambiguousStack[key], ct.ambiguousPolicies, key, att.IntentID) {
		return nil
	}
	stack := ct.ambiguousStack[key]
	if len(stack) > 0 {
		filtered := stack[:0]
		for _, item := range stack {
			if item.IntentID != att.IntentID {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) > 0 {
			ct.ambiguousStack[key] = filtered
			ct.ambiguousPolicies[key] = filtered[len(filtered)-1]
			return nil
		}
		delete(ct.ambiguousStack, key)
	}
	delete(ct.ambiguousPolicies, key)
	if _, inActive := ct.activePolicies[key]; !inActive {
		if releaseNano, ok := ct.policyCleanup[key]; ok {
			delete(ct.policyCleanup, key)
			if ct.meter != nil && releaseNano > 0 {
				ct.meter.ReleaseResourceCleanup(releaseNano)
			}
		}
	}
	return nil
}

func (ct *costTracker) listPolicyAttachments() ([]hostkit.PolicyAttachment, *hostkit.CloudError) {
	return ct.listPolicyAttachmentsForScope("", "")
}

func (ct *costTracker) listPolicyAttachmentsForScope(scope, principal string) ([]hostkit.PolicyAttachment, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return nil, cerr
	}
	for _, amb := range ct.ambiguousPolicies {
		if amb.Scope != "" && scope != "" && amb.Scope != scope {
			continue
		}
		if principal != "" && amb.Principal != principal {
			continue
		}
		return nil, hostkit.ProviderError(hostkit.Conflict, 409, "RetainedPolicyIntent",
			fmt.Sprintf("policy attachment (%s, %s, %s) has an unresolved ambiguous intent; reconciliation required", amb.Kind, amb.Target, amb.Principal))
	}
	keys := make([]string, 0, len(ct.activePolicies))
	for k, pa := range ct.activePolicies {
		if pa.Scope != "" && scope != "" && pa.Scope != scope {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]hostkit.PolicyAttachment, 0, len(keys))
	for _, k := range keys {
		out = append(out, ct.activePolicies[k].Clone())
	}
	return out, nil
}

func (ct *costTracker) lockResourceCleanupIfNeeded(endpoint, op, resKind, resKey string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.isServiceDelegated(op, resKind) || ct.meter == nil || ct.meter.Table() == nil {
		return
	}
	resNano := ct.meter.Table().Operations[op].CleanupReserveNanoUSD
	if resNano <= 0 {
		return
	}
	if ct.journal != nil {
		st := ct.journal.State()
		attName := journalAttemptName(resKey)
		rKey := resKind + "\x00" + endpoint + "\x00" + attName
		if _, inEntries := st.Lookup(resKind, endpoint, attName); inEntries {
			return
		}
		if _, inActive := st.ActiveCleanup[rKey]; inActive {
			return
		}
		if attID, err := ct.journal.BeginAttempt(resKind, endpoint, attName, op, resNano, 0); err == nil {
			_ = ct.journal.SettleAttemptWithCleanup(attID, 0, 0, 0, resNano, false, false)
			ct.syncFromSafetyJournalLocked()
		}
		return
	}
	sKey := scopedResKey(endpoint, resKey)
	if ct.statePath != "" {
		_ = ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			switch resKind {
			case safety.KindBucket:
				if _, ok := st.activeBuckets[sKey]; ok {
					return nil
				}
			case safety.KindQueue:
				if _, ok := st.activeQueues[sKey]; ok {
					return nil
				}
			case safety.KindTable:
				if _, ok := st.activeTables[sKey]; ok {
					return nil
				}
			case safety.KindFunction:
				if _, ok := st.activeFunctions[sKey]; ok {
					return nil
				}
			case safety.KindUserpool:
				if _, ok := st.activeUserpools[sKey]; ok {
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
				Endpoint:              endpoint,
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
				Endpoint:    endpoint,
				LockCleanup: true,
			})
		})
		return
	}
	switch resKind {
	case safety.KindBucket:
		if _, exists := ct.activeBuckets[sKey]; !exists {
			ct.activeBuckets[sKey] = resNano
			ct.meter.RestoreCharged(0, ct.meter.Snapshot().ResourceCleanupNanoUSD+resNano)
		}
	case safety.KindQueue:
		if _, exists := ct.activeQueues[sKey]; !exists {
			ct.activeQueues[sKey] = resNano
			ct.meter.RestoreCharged(0, ct.meter.Snapshot().ResourceCleanupNanoUSD+resNano)
		}
	case safety.KindTable:
		if _, exists := ct.activeTables[sKey]; !exists {
			ct.activeTables[sKey] = resNano
			ct.meter.RestoreCharged(0, ct.meter.Snapshot().ResourceCleanupNanoUSD+resNano)
		}
	case safety.KindFunction:
		if _, exists := ct.activeFunctions[sKey]; !exists {
			ct.activeFunctions[sKey] = resNano
			ct.meter.RestoreCharged(0, ct.meter.Snapshot().ResourceCleanupNanoUSD+resNano)
		}
	case safety.KindUserpool:
		if _, exists := ct.activeUserpools[sKey]; !exists {
			ct.activeUserpools[sKey] = resNano
			ct.meter.RestoreCharged(0, ct.meter.Snapshot().ResourceCleanupNanoUSD+resNano)
		}
	}
}

func countDistinctFunctionKeys(active, ambiguous map[string]safety.JournalFunctionEntry, excludeKey string) int {
	seen := make(map[string]struct{}, len(active)+len(ambiguous))
	for k := range active {
		if k != excludeKey {
			seen[k] = struct{}{}
		}
	}
	for k := range ambiguous {
		if k != excludeKey {
			seen[k] = struct{}{}
		}
	}
	return len(seen)
}

func hasPendingFunctionIntent(stack []safety.JournalFunctionEntry, amb map[string]safety.JournalFunctionEntry, key, intentID string) bool {
	if intentID == "" {
		return false
	}
	for _, item := range stack {
		if item.IntentID == intentID {
			return true
		}
	}
	if cur, ok := amb[key]; ok && cur.IntentID == intentID {
		return true
	}
	return false
}

func (ct *costTracker) checkFunctionCreateHeadroom(endpoint, name string) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return cerr
	}
	key := scopedResKey(endpoint, name)
	if countDistinctFunctionKeys(ct.activeFunctionEntries, ct.ambiguousFunctions, key) >= hostkit.MaxFunctionsPerRun {
		return hostkit.ProviderError(hostkit.InvalidArgument, 0, "FunctionLimitExceeded",
			fmt.Sprintf("run function count exceeds maximum (%d)", hostkit.MaxFunctionsPerRun))
	}
	return nil
}

func (ct *costTracker) lookupFunctionEntry(endpoint, name string) (safety.JournalFunctionEntry, bool, safety.JournalFunctionEntry, bool, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return safety.JournalFunctionEntry{}, false, safety.JournalFunctionEntry{}, false, cerr
	}
	key := scopedResKey(endpoint, name)
	act, hasAct := ct.activeFunctionEntries[key]
	amb, hasAmb := ct.ambiguousFunctions[key]
	return act, hasAct, amb, hasAmb, nil
}

func (ct *costTracker) listAmbiguousFunctionsForEndpoint(endpoint string) ([]safety.JournalFunctionEntry, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return nil, cerr
	}
	var out []safety.JournalFunctionEntry
	for _, amb := range ct.ambiguousFunctions {
		if amb.Scope != "" && endpoint != "" && amb.Scope != endpoint {
			continue
		}
		if amb.Scope == "" && endpoint != "" {
			continue
		}
		out = append(out, amb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (ct *costTracker) beginFunctionIntent(endpoint, name, intentOp, digest string) (safety.JournalFunctionEntry, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return safety.JournalFunctionEntry{}, cerr
	}
	key := scopedResKey(endpoint, name)
	if intentOp == "create" {
		if countDistinctFunctionKeys(ct.activeFunctionEntries, ct.ambiguousFunctions, key) >= hostkit.MaxFunctionsPerRun {
			return safety.JournalFunctionEntry{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "FunctionLimitExceeded",
				fmt.Sprintf("run function count exceeds maximum (%d)", hostkit.MaxFunctionsPerRun))
		}
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return safety.JournalFunctionEntry{}, ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return safety.JournalFunctionEntry{}, ct.poisoned
		}
		if intentOp == "create" && countDistinctFunctionKeys(ct.activeFunctionEntries, ct.ambiguousFunctions, key) >= hostkit.MaxFunctionsPerRun {
			return safety.JournalFunctionEntry{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "FunctionLimitExceeded",
				fmt.Sprintf("run function count exceeds maximum (%d)", hostkit.MaxFunctionsPerRun))
		}
		ownerToken := ""
		if existing, ok := ct.activeFunctionEntries[key]; ok && existing.OwnerToken != "" {
			ownerToken = existing.OwnerToken
		} else if amb, ok := ct.ambiguousFunctions[key]; ok && amb.OwnerToken != "" {
			ownerToken = amb.OwnerToken
		} else if tok := ct.functionOwnerTokens[key]; tok != "" && intentOp != "create" {
			ownerToken = tok
		} else {
			ownerToken = safety.NewToken128()
		}
		nextGen := ct.maxFunctionGen[key] + 1
		genStr := strconv.FormatUint(nextGen, 10)
		intentID := safety.NewToken128()
		if err := ct.journal.RecordFunctionIntent(endpoint, name, intentOp, digest, ownerToken, genStr, intentID, "", "", 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return safety.JournalFunctionEntry{}, ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return safety.JournalFunctionEntry{}, ct.poisoned
		}
		if ct.onToken != nil {
			ct.onToken(ownerToken)
		}
		return safety.JournalFunctionEntry{
			Key:        key,
			Scope:      endpoint,
			Name:       name,
			Digest:     digest,
			OwnerToken: ownerToken,
			Generation: genStr,
			IntentID:   intentID,
			Ambiguous:  true,
			IntentOp:   intentOp,
		}, nil
	}

	if ct.statePath != "" {
		var outEntry safety.JournalFunctionEntry
		var cerr *hostkit.CloudError
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if intentOp == "create" && countDistinctFunctionKeys(st.activeFunctionEntries, st.ambiguousFunctions, key) >= hostkit.MaxFunctionsPerRun {
				cerr = hostkit.ProviderError(hostkit.InvalidArgument, 0, "FunctionLimitExceeded",
					fmt.Sprintf("run function count exceeds maximum (%d)", hostkit.MaxFunctionsPerRun))
				return nil
			}
			ownerToken := ""
			if existing, ok := st.activeFunctionEntries[key]; ok && existing.OwnerToken != "" {
				ownerToken = existing.OwnerToken
			} else if amb, ok := st.ambiguousFunctions[key]; ok && amb.OwnerToken != "" {
				ownerToken = amb.OwnerToken
			} else if tok := st.functionOwnerTokens[key]; tok != "" && intentOp != "create" {
				ownerToken = tok
			} else {
				ownerToken = safety.NewToken128()
			}
			nextGen := st.maxFunctionGen[key] + 1
			genStr := strconv.FormatUint(nextGen, 10)
			intentID := safety.NewToken128()
			if err := appendRec(campaignJournalRecord{
				Event:          safety.EventFunctionIntent,
				IntentID:       intentID,
				Endpoint:       endpoint,
				ResKey:         name,
				PolicyIntentOp: intentOp,
				FunctionDigest: digest,
				OwnerToken:     ownerToken,
				Generation:     genStr,
			}); err != nil {
				return err
			}
			outEntry = safety.JournalFunctionEntry{
				Key:        key,
				Scope:      endpoint,
				Name:       name,
				Digest:     digest,
				OwnerToken: ownerToken,
				Generation: genStr,
				IntentID:   intentID,
				Ambiguous:  true,
				IntentOp:   intentOp,
			}
			st.ambiguousFunctionStack[key] = append(st.ambiguousFunctionStack[key], outEntry)
			st.ambiguousFunctions[key] = outEntry
			st.functionOwnerTokens[key] = ownerToken
			st.maxFunctionGen[key] = nextGen
			st.latestFunctionIntent[key] = intentID
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return safety.JournalFunctionEntry{}, ct.poisoned
		}
		if cerr != nil {
			return safety.JournalFunctionEntry{}, cerr
		}
		if ct.onToken != nil {
			ct.onToken(outEntry.OwnerToken)
		}
		return outEntry, nil
	}

	ownerToken := ""
	if existing, ok := ct.activeFunctionEntries[key]; ok && existing.OwnerToken != "" {
		ownerToken = existing.OwnerToken
	} else if amb, ok := ct.ambiguousFunctions[key]; ok && amb.OwnerToken != "" {
		ownerToken = amb.OwnerToken
	} else if tok := ct.functionOwnerTokens[key]; tok != "" && intentOp != "create" {
		ownerToken = tok
	} else {
		ownerToken = safety.NewToken128()
	}
	nextGen := ct.maxFunctionGen[key] + 1
	genStr := strconv.FormatUint(nextGen, 10)
	intentID := safety.NewToken128()
	outEntry := safety.JournalFunctionEntry{
		Key:        key,
		Scope:      endpoint,
		Name:       name,
		Digest:     digest,
		OwnerToken: ownerToken,
		Generation: genStr,
		IntentID:   intentID,
		Ambiguous:  true,
		IntentOp:   intentOp,
	}
	ct.ambiguousFunctionStack[key] = append(ct.ambiguousFunctionStack[key], outEntry)
	ct.ambiguousFunctions[key] = outEntry
	ct.functionOwnerTokens[key] = ownerToken
	ct.maxFunctionGen[key] = nextGen
	ct.latestFunctionIntent[key] = intentID
	if ct.onToken != nil {
		ct.onToken(ownerToken)
	}
	return outEntry, nil
}

func (ct *costTracker) confirmFunctionIntent(entry safety.JournalFunctionEntry) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := entry.Key
	if key == "" {
		key = scopedResKey(entry.Scope, entry.Name)
		entry.Key = key
	}
	entryGen, _ := strconv.ParseUint(entry.Generation, 10, 64)

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingFunctionIntent(ct.ambiguousFunctionStack[key], ct.ambiguousFunctions, key, entry.IntentID) ||
			ct.latestFunctionIntent[key] != entry.IntentID || entryGen < ct.maxFunctionGen[key] {
			return nil
		}
		if err := ct.journal.RecordFunctionConfirmWithState(entry.Scope, entry.Name, entry.Digest, entry.OwnerToken, entry.Generation, entry.IntentID, entry.StateJSON, 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingFunctionIntent(st.ambiguousFunctionStack[key], st.ambiguousFunctions, key, entry.IntentID) ||
				st.latestFunctionIntent[key] != entry.IntentID || entryGen < st.maxFunctionGen[key] {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:          safety.EventFunctionConfirm,
				IntentID:       entry.IntentID,
				Endpoint:       entry.Scope,
				ResKey:         entry.Name,
				FunctionDigest: entry.Digest,
				OwnerToken:     entry.OwnerToken,
				Generation:     entry.Generation,
				FunctionState:  entry.StateJSON,
			}); err != nil {
				return err
			}
			confirmed := entry
			confirmed.Ambiguous = false
			confirmed.IntentOp = ""
			if confirmed.StateJSON == "" {
				confirmed.StateJSON = st.activeFunctionEntries[key].StateJSON
			}
			st.activeFunctionEntries[key] = confirmed
			st.functionOwnerTokens[key] = entry.OwnerToken
			delete(st.ambiguousFunctionStack, key)
			delete(st.ambiguousFunctions, key)
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}

	if !hasPendingFunctionIntent(ct.ambiguousFunctionStack[key], ct.ambiguousFunctions, key, entry.IntentID) ||
		ct.latestFunctionIntent[key] != entry.IntentID || entryGen < ct.maxFunctionGen[key] {
		return nil
	}
	confirmed := entry
	confirmed.Ambiguous = false
	confirmed.IntentOp = ""
	if confirmed.StateJSON == "" {
		confirmed.StateJSON = ct.activeFunctionEntries[key].StateJSON
	}
	ct.activeFunctionEntries[key] = confirmed
	ct.functionOwnerTokens[key] = entry.OwnerToken
	delete(ct.ambiguousFunctionStack, key)
	delete(ct.ambiguousFunctions, key)
	return nil
}

func (ct *costTracker) updateFunctionDryState(endpoint, name, expOwnerToken, expDigest, expGeneration string, mutate func(curStateJSON string) string) *hostkit.CloudError {
	if mutate == nil {
		return nil
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := scopedResKey(endpoint, name)

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		act, ok := ct.activeFunctionEntries[key]
		_, hasAmb := ct.ambiguousFunctions[key]
		if !ok || hasAmb || len(ct.ambiguousFunctionStack[key]) > 0 {
			return nil
		}
		if act.OwnerToken != expOwnerToken || act.Digest != expDigest || act.Generation != expGeneration {
			return nil
		}
		newState := mutate(act.StateJSON)
		if newState == act.StateJSON {
			return nil
		}
		if err := ct.journal.RecordFunctionPreviewState(act.Scope, act.Name, act.OwnerToken, act.Digest, act.Generation, newState); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			act, ok := st.activeFunctionEntries[key]
			_, hasAmb := st.ambiguousFunctions[key]
			if !ok || hasAmb || len(st.ambiguousFunctionStack[key]) > 0 {
				return nil
			}
			if act.OwnerToken != expOwnerToken || act.Digest != expDigest || act.Generation != expGeneration {
				return nil
			}
			newState := mutate(act.StateJSON)
			if newState == act.StateJSON {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:          safety.EventFunctionPreviewState,
				Endpoint:       act.Scope,
				ResKey:         act.Name,
				FunctionDigest: act.Digest,
				OwnerToken:     act.OwnerToken,
				Generation:     act.Generation,
				FunctionState:  newState,
			}); err != nil {
				return err
			}
			act.StateJSON = newState
			st.activeFunctionEntries[key] = act
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}

	act, ok := ct.activeFunctionEntries[key]
	_, hasAmb := ct.ambiguousFunctions[key]
	if !ok || hasAmb || len(ct.ambiguousFunctionStack[key]) > 0 {
		return nil
	}
	if act.OwnerToken != expOwnerToken || act.Digest != expDigest || act.Generation != expGeneration {
		return nil
	}
	act.StateJSON = mutate(act.StateJSON)
	ct.activeFunctionEntries[key] = act
	return nil
}

func (ct *costTracker) confirmFunctionDelete(entry safety.JournalFunctionEntry) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := entry.Key
	if key == "" {
		key = scopedResKey(entry.Scope, entry.Name)
		entry.Key = key
	}
	entryGen, _ := strconv.ParseUint(entry.Generation, 10, 64)

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingFunctionIntent(ct.ambiguousFunctionStack[key], ct.ambiguousFunctions, key, entry.IntentID) ||
			ct.latestFunctionIntent[key] != entry.IntentID || entryGen < ct.maxFunctionGen[key] {
			return nil
		}
		if err := ct.journal.RecordFunctionDelete(entry.Scope, entry.Name, entry.OwnerToken, entry.Generation, entry.IntentID); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingFunctionIntent(st.ambiguousFunctionStack[key], st.ambiguousFunctions, key, entry.IntentID) ||
				st.latestFunctionIntent[key] != entry.IntentID || entryGen < st.maxFunctionGen[key] {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:      safety.EventFunctionDelete,
				IntentID:   entry.IntentID,
				Endpoint:   entry.Scope,
				ResKey:     entry.Name,
				OwnerToken: entry.OwnerToken,
				Generation: entry.Generation,
			}); err != nil {
				return err
			}
			delete(st.activeFunctionEntries, key)
			delete(st.ambiguousFunctionStack, key)
			delete(st.ambiguousFunctions, key)
			deleteCampaignFunctionCleanup(st, key)
			deleteResourcePolicyAttachments(st.activePolicies, st.ambiguousPolicies, st.ambiguousStack, st.policyCleanup, safety.KindFunction, entry.Scope, entry.Name)
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}

	if !hasPendingFunctionIntent(ct.ambiguousFunctionStack[key], ct.ambiguousFunctions, key, entry.IntentID) ||
		ct.latestFunctionIntent[key] != entry.IntentID || entryGen < ct.maxFunctionGen[key] {
		return nil
	}
	delete(ct.activeFunctionEntries, key)
	delete(ct.ambiguousFunctionStack, key)
	delete(ct.ambiguousFunctions, key)
	return nil
}

func (ct *costTracker) abortFunctionIntent(entry safety.JournalFunctionEntry) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := entry.Key
	if key == "" {
		key = scopedResKey(entry.Scope, entry.Name)
		entry.Key = key
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingFunctionIntent(ct.ambiguousFunctionStack[key], ct.ambiguousFunctions, key, entry.IntentID) {
			return nil
		}
		if err := ct.journal.RecordFunctionIntent(entry.Scope, entry.Name, "abort", "", entry.OwnerToken, entry.Generation, entry.IntentID, "", "", 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingFunctionIntent(st.ambiguousFunctionStack[key], st.ambiguousFunctions, key, entry.IntentID) {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:          safety.EventFunctionIntent,
				IntentID:       entry.IntentID,
				Endpoint:       entry.Scope,
				ResKey:         entry.Name,
				PolicyIntentOp: "abort",
				OwnerToken:     entry.OwnerToken,
				Generation:     entry.Generation,
			}); err != nil {
				return err
			}
			stack := st.ambiguousFunctionStack[key]
			if len(stack) > 0 {
				filtered := stack[:0]
				for _, item := range stack {
					if item.IntentID != entry.IntentID {
						filtered = append(filtered, item)
					}
				}
				if len(filtered) > 0 {
					st.ambiguousFunctionStack[key] = filtered
					st.ambiguousFunctions[key] = filtered[len(filtered)-1]
				} else {
					delete(st.ambiguousFunctionStack, key)
					delete(st.ambiguousFunctions, key)
					if _, inActive := st.activeFunctionEntries[key]; !inActive {
						deleteCampaignFunctionCleanup(st, key)
					}
				}
			} else {
				delete(st.ambiguousFunctions, key)
				if _, inActive := st.activeFunctionEntries[key]; !inActive {
					deleteCampaignFunctionCleanup(st, key)
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

	if !hasPendingFunctionIntent(ct.ambiguousFunctionStack[key], ct.ambiguousFunctions, key, entry.IntentID) {
		return nil
	}
	stack := ct.ambiguousFunctionStack[key]
	if len(stack) > 0 {
		filtered := stack[:0]
		for _, item := range stack {
			if item.IntentID != entry.IntentID {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) > 0 {
			ct.ambiguousFunctionStack[key] = filtered
			ct.ambiguousFunctions[key] = filtered[len(filtered)-1]
			return nil
		}
		delete(ct.ambiguousFunctionStack, key)
	}
	delete(ct.ambiguousFunctions, key)
	if _, inActive := ct.activeFunctionEntries[key]; !inActive {
		if releaseNano, ok := ct.activeFunctions[key]; ok {
			delete(ct.activeFunctions, key)
			if ct.meter != nil && releaseNano > 0 {
				ct.meter.ReleaseResourceCleanup(releaseNano)
			}
		}
	}
	return nil
}

func countDistinctUserpoolKeys(active, ambiguous map[string]safety.JournalUserpoolEntry, excludeKey string) int {
	seen := make(map[string]struct{}, len(active)+len(ambiguous))
	for k := range active {
		if k != excludeKey {
			seen[k] = struct{}{}
		}
	}
	for k := range ambiguous {
		if k != excludeKey {
			seen[k] = struct{}{}
		}
	}
	return len(seen)
}

func hasPendingUserpoolIntent(stack []safety.JournalUserpoolEntry, amb map[string]safety.JournalUserpoolEntry, key, intentID string) bool {
	if intentID == "" {
		return false
	}
	for _, item := range stack {
		if item.IntentID == intentID {
			return true
		}
	}
	if cur, ok := amb[key]; ok && cur.IntentID == intentID {
		return true
	}
	return false
}

func (ct *costTracker) checkUserpoolCreateHeadroom(endpoint, name string) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return cerr
	}
	key := scopedResKey(endpoint, name)
	if countDistinctUserpoolKeys(ct.activeUserpoolEntries, ct.ambiguousUserpools, key) >= hostkit.MaxUserpoolsPerRun {
		return hostkit.ProviderError(hostkit.InvalidArgument, 0, "UserpoolLimitExceeded",
			fmt.Sprintf("run userpool count exceeds maximum (%d)", hostkit.MaxUserpoolsPerRun))
	}
	return nil
}

func (ct *costTracker) lookupUserpoolEntry(endpoint, name string) (safety.JournalUserpoolEntry, bool, safety.JournalUserpoolEntry, bool, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return safety.JournalUserpoolEntry{}, false, safety.JournalUserpoolEntry{}, false, cerr
	}
	key := scopedResKey(endpoint, name)
	act, hasAct := ct.activeUserpoolEntries[key]
	amb, hasAmb := ct.ambiguousUserpools[key]
	return act, hasAct, amb, hasAmb, nil
}

func (ct *costTracker) listAmbiguousUserpoolsForEndpoint(endpoint string) ([]safety.JournalUserpoolEntry, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return nil, cerr
	}
	var out []safety.JournalUserpoolEntry
	for _, amb := range ct.ambiguousUserpools {
		if amb.Scope != "" && endpoint != "" && amb.Scope != endpoint {
			continue
		}
		if amb.Scope == "" && endpoint != "" {
			continue
		}
		out = append(out, amb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (ct *costTracker) beginUserpoolIntent(endpoint, name, intentOp, incarnation string) (safety.JournalUserpoolEntry, *hostkit.CloudError) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if cerr := ct.refreshStateLocked(); cerr != nil {
		return safety.JournalUserpoolEntry{}, cerr
	}
	key := scopedResKey(endpoint, name)
	if intentOp == "create" {
		if countDistinctUserpoolKeys(ct.activeUserpoolEntries, ct.ambiguousUserpools, key) >= hostkit.MaxUserpoolsPerRun {
			return safety.JournalUserpoolEntry{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "UserpoolLimitExceeded",
				fmt.Sprintf("run userpool count exceeds maximum (%d)", hostkit.MaxUserpoolsPerRun))
		}
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return safety.JournalUserpoolEntry{}, ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return safety.JournalUserpoolEntry{}, ct.poisoned
		}
		if intentOp == "create" && countDistinctUserpoolKeys(ct.activeUserpoolEntries, ct.ambiguousUserpools, key) >= hostkit.MaxUserpoolsPerRun {
			return safety.JournalUserpoolEntry{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "UserpoolLimitExceeded",
				fmt.Sprintf("run userpool count exceeds maximum (%d)", hostkit.MaxUserpoolsPerRun))
		}
		ownerToken := ""
		if existing, ok := ct.activeUserpoolEntries[key]; ok && existing.OwnerToken != "" {
			ownerToken = existing.OwnerToken
		} else if amb, ok := ct.ambiguousUserpools[key]; ok && amb.OwnerToken != "" {
			ownerToken = amb.OwnerToken
		} else if tok := ct.userpoolOwnerTokens[key]; tok != "" && intentOp != "create" {
			ownerToken = tok
		} else {
			ownerToken = safety.NewToken128()
		}
		inc := incarnation
		if inc == "" {
			if existing, ok := ct.activeUserpoolEntries[key]; ok && existing.Incarnation != "" {
				inc = existing.Incarnation
			} else if amb, ok := ct.ambiguousUserpools[key]; ok && amb.Incarnation != "" {
				inc = amb.Incarnation
			} else if intentOp == "create" {
				inc = safety.NewToken128()
			}
		}
		nextGen := ct.maxUserpoolGen[key] + 1
		genStr := strconv.FormatUint(nextGen, 10)
		intentID := safety.NewToken128()
		if intentOp == "delete" && ct.journal.FileSize()+512 > safety.MaxJournalFileBytes {
			_ = ct.journal.Compact()
			if ct.journal.FileSize()+512 > safety.MaxJournalFileBytes {
				return safety.JournalUserpoolEntry{}, hostkit.ProviderError(hostkit.InvalidArgument, 0, "JournalSizeLimitExceeded",
					fmt.Sprintf("journal size exceeds hard limit (%d bytes)", safety.MaxJournalFileBytes))
			}
		}
		if err := ct.journal.RecordUserpoolIntent(endpoint, name, intentOp, inc, ownerToken, genStr, intentID, "", "", 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return safety.JournalUserpoolEntry{}, ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return safety.JournalUserpoolEntry{}, ct.poisoned
		}
		if ct.onToken != nil {
			ct.onToken(ownerToken)
		}
		return safety.JournalUserpoolEntry{
			Key:         key,
			Scope:       endpoint,
			Name:        name,
			Incarnation: inc,
			OwnerToken:  ownerToken,
			Generation:  genStr,
			IntentID:    intentID,
			Ambiguous:   true,
			IntentOp:    intentOp,
		}, nil
	}

	if ct.statePath != "" {
		var outEntry safety.JournalUserpoolEntry
		var cerr *hostkit.CloudError
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if intentOp == "create" && countDistinctUserpoolKeys(st.activeUserpoolEntries, st.ambiguousUserpools, key) >= hostkit.MaxUserpoolsPerRun {
				cerr = hostkit.ProviderError(hostkit.InvalidArgument, 0, "UserpoolLimitExceeded",
					fmt.Sprintf("run userpool count exceeds maximum (%d)", hostkit.MaxUserpoolsPerRun))
				return nil
			}
			ownerToken := ""
			if existing, ok := st.activeUserpoolEntries[key]; ok && existing.OwnerToken != "" {
				ownerToken = existing.OwnerToken
			} else if amb, ok := st.ambiguousUserpools[key]; ok && amb.OwnerToken != "" {
				ownerToken = amb.OwnerToken
			} else if tok := st.userpoolOwnerTokens[key]; tok != "" && intentOp != "create" {
				ownerToken = tok
			} else {
				ownerToken = safety.NewToken128()
			}
			inc := incarnation
			if inc == "" {
				if existing, ok := st.activeUserpoolEntries[key]; ok && existing.Incarnation != "" {
					inc = existing.Incarnation
				} else if amb, ok := st.ambiguousUserpools[key]; ok && amb.Incarnation != "" {
					inc = amb.Incarnation
				} else if intentOp == "create" {
					inc = safety.NewToken128()
				}
			}
			nextGen := st.maxUserpoolGen[key] + 1
			genStr := strconv.FormatUint(nextGen, 10)
			intentID := safety.NewToken128()
			if intentOp == "delete" && int64(st.journalFileBytes)+512 > safety.MaxJournalFileBytes {
				cerr = hostkit.ProviderError(hostkit.InvalidArgument, 0, "JournalSizeLimitExceeded",
					fmt.Sprintf("campaign journal size exceeds hard limit (%d bytes)", safety.MaxJournalFileBytes))
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:               safety.EventUserpoolIntent,
				IntentID:            intentID,
				Endpoint:            endpoint,
				ResKey:              name,
				PolicyIntentOp:      intentOp,
				UserpoolIncarnation: inc,
				OwnerToken:          ownerToken,
				Generation:          genStr,
			}); err != nil {
				return err
			}
			outEntry = safety.JournalUserpoolEntry{
				Key:         key,
				Scope:       endpoint,
				Name:        name,
				Incarnation: inc,
				OwnerToken:  ownerToken,
				Generation:  genStr,
				IntentID:    intentID,
				Ambiguous:   true,
				IntentOp:    intentOp,
			}
			st.ambiguousUserpoolStack[key] = append(st.ambiguousUserpoolStack[key], outEntry)
			st.ambiguousUserpools[key] = outEntry
			st.userpoolOwnerTokens[key] = ownerToken
			st.maxUserpoolGen[key] = nextGen
			st.latestUserpoolIntent[key] = intentID
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return safety.JournalUserpoolEntry{}, ct.poisoned
		}
		if cerr != nil {
			return safety.JournalUserpoolEntry{}, cerr
		}
		if ct.onToken != nil {
			ct.onToken(outEntry.OwnerToken)
		}
		return outEntry, nil
	}

	ownerToken := ""
	if existing, ok := ct.activeUserpoolEntries[key]; ok && existing.OwnerToken != "" && intentOp != "create" {
		ownerToken = existing.OwnerToken
	} else if amb, ok := ct.ambiguousUserpools[key]; ok && amb.OwnerToken != "" && intentOp != "create" {
		ownerToken = amb.OwnerToken
	} else if tok := ct.userpoolOwnerTokens[key]; tok != "" && intentOp != "create" {
		ownerToken = tok
	} else {
		ownerToken = safety.NewToken128()
	}
	inc := incarnation
	if inc == "" {
		if existing, ok := ct.activeUserpoolEntries[key]; ok && existing.Incarnation != "" && intentOp != "create" {
			inc = existing.Incarnation
		} else if amb, ok := ct.ambiguousUserpools[key]; ok && amb.Incarnation != "" && intentOp != "create" {
			inc = amb.Incarnation
		} else if intentOp == "create" {
			inc = safety.NewToken128()
		}
	}
	nextGen := ct.maxUserpoolGen[key] + 1
	genStr := strconv.FormatUint(nextGen, 10)
	intentID := safety.NewToken128()
	outEntry := safety.JournalUserpoolEntry{
		Key:         key,
		Scope:       endpoint,
		Name:        name,
		Incarnation: inc,
		OwnerToken:  ownerToken,
		Generation:  genStr,
		IntentID:    intentID,
		Ambiguous:   true,
		IntentOp:    intentOp,
	}
	ct.ambiguousUserpoolStack[key] = append(ct.ambiguousUserpoolStack[key], outEntry)
	ct.ambiguousUserpools[key] = outEntry
	ct.userpoolOwnerTokens[key] = ownerToken
	ct.maxUserpoolGen[key] = nextGen
	ct.latestUserpoolIntent[key] = intentID
	if ct.onToken != nil {
		ct.onToken(ownerToken)
	}
	return outEntry, nil
}

func (ct *costTracker) confirmUserpoolIntent(entry safety.JournalUserpoolEntry) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := entry.Key
	if key == "" {
		key = scopedResKey(entry.Scope, entry.Name)
		entry.Key = key
	}
	entryGen, _ := strconv.ParseUint(entry.Generation, 10, 64)

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingUserpoolIntent(ct.ambiguousUserpoolStack[key], ct.ambiguousUserpools, key, entry.IntentID) ||
			ct.latestUserpoolIntent[key] != entry.IntentID || entryGen < ct.maxUserpoolGen[key] {
			return nil
		}
		if err := ct.journal.RecordUserpoolConfirmWithState(entry.Scope, entry.Name, entry.Incarnation, entry.OwnerToken, entry.Generation, entry.IntentID, entry.StateJSON, 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingUserpoolIntent(st.ambiguousUserpoolStack[key], st.ambiguousUserpools, key, entry.IntentID) ||
				st.latestUserpoolIntent[key] != entry.IntentID || entryGen < st.maxUserpoolGen[key] {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:               safety.EventUserpoolConfirm,
				IntentID:            entry.IntentID,
				Endpoint:            entry.Scope,
				ResKey:              entry.Name,
				UserpoolIncarnation: entry.Incarnation,
				OwnerToken:          entry.OwnerToken,
				Generation:          entry.Generation,
				UserpoolState:       entry.StateJSON,
			}); err != nil {
				return err
			}
			confirmed := entry
			confirmed.Ambiguous = false
			confirmed.IntentOp = ""
			if confirmed.StateJSON == "" {
				confirmed.StateJSON = st.activeUserpoolEntries[key].StateJSON
			}
			st.activeUserpoolEntries[key] = confirmed
			st.userpoolOwnerTokens[key] = entry.OwnerToken
			delete(st.ambiguousUserpoolStack, key)
			delete(st.ambiguousUserpools, key)
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}

	if !hasPendingUserpoolIntent(ct.ambiguousUserpoolStack[key], ct.ambiguousUserpools, key, entry.IntentID) ||
		ct.latestUserpoolIntent[key] != entry.IntentID || entryGen < ct.maxUserpoolGen[key] {
		return nil
	}
	confirmed := entry
	confirmed.Ambiguous = false
	confirmed.IntentOp = ""
	if confirmed.StateJSON == "" {
		confirmed.StateJSON = ct.activeUserpoolEntries[key].StateJSON
	}
	ct.activeUserpoolEntries[key] = confirmed
	ct.userpoolOwnerTokens[key] = entry.OwnerToken
	delete(ct.ambiguousUserpoolStack, key)
	delete(ct.ambiguousUserpools, key)
	return nil
}

func (ct *costTracker) hasPoolUserCleanup(endpoint, pool, username string) bool {
	if ct == nil {
		return false
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	sKey := scopedResKey(endpoint, pool+"/"+username)
	if _, ok := ct.activePoolUsers[sKey]; ok {
		return true
	}
	if ct.journal != nil {
		st := ct.journal.State()
		uKey := safety.KindPoolUser + "\x00" + endpoint + "\x00" + pool + "/" + username
		uKeyUnscoped := safety.KindPoolUser + "\x00\x00" + pool + "/" + username
		if _, ok := st.ActiveCleanup[uKey]; ok {
			return true
		}
		if _, ok := st.ActiveCleanup[uKeyUnscoped]; ok {
			return true
		}
	}
	return false
}

func (ct *costTracker) hasPoolGroupCleanup(endpoint, pool, group string) bool {
	if ct == nil {
		return false
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	sKey := scopedResKey(endpoint, pool+"/"+group)
	if _, ok := ct.activePoolGroups[sKey]; ok {
		return true
	}
	if ct.journal != nil {
		st := ct.journal.State()
		gKey := safety.KindPoolGroup + "\x00" + endpoint + "\x00" + pool + "/" + group
		gKeyUnscoped := safety.KindPoolGroup + "\x00\x00" + pool + "/" + group
		if _, ok := st.ActiveCleanup[gKey]; ok {
			return true
		}
		if _, ok := st.ActiveCleanup[gKeyUnscoped]; ok {
			return true
		}
	}
	return false
}

func (ct *costTracker) hasAnyPoolMembershipCleanup(endpoint, pool string) bool {
	if ct == nil {
		return false
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	prefix := scopedResKey(endpoint, pool+"/")
	for k := range ct.activePoolMemberships {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	if ct.journal != nil {
		st := ct.journal.State()
		p1 := safety.KindPoolMembership + "\x00" + endpoint + "\x00" + pool + "/"
		p2 := safety.KindPoolMembership + "\x00\x00" + pool + "/"
		for k := range st.ActiveCleanup {
			if strings.HasPrefix(k, p1) || strings.HasPrefix(k, p2) {
				return true
			}
		}
	}
	return false
}

func (ct *costTracker) hasPoolMembershipCleanup(endpoint, pool, group, username string) bool {
	if ct == nil {
		return false
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	sKey := scopedResKey(endpoint, pool+"/"+group+"/"+username)
	if _, ok := ct.activePoolMemberships[sKey]; ok {
		return true
	}
	if ct.journal != nil {
		st := ct.journal.State()
		mKey := safety.KindPoolMembership + "\x00" + endpoint + "\x00" + pool + "/" + group + "/" + username
		mKeyUnscoped := safety.KindPoolMembership + "\x00\x00" + pool + "/" + group + "/" + username
		if _, ok := st.ActiveCleanup[mKey]; ok {
			return true
		}
		if _, ok := st.ActiveCleanup[mKeyUnscoped]; ok {
			return true
		}
	}
	return false
}

func (ct *costTracker) updateUserpoolState(endpoint, name, expOwnerToken, expIncarnation, expGen string, mutate func(curStateJSON string) string) *hostkit.CloudError {
	return ct.updateUserpoolStateOpts(endpoint, name, expOwnerToken, expIncarnation, expGen, false, false, mutate)
}

func (ct *costTracker) updateUserpoolStateOpts(endpoint, name, expOwnerToken, expIncarnation, _ string, isCleanup, allowRevokeHeadroom bool, mutate func(curStateJSON string) string) *hostkit.CloudError {
	if mutate == nil {
		return nil
	}
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := scopedResKey(endpoint, name)
	staleErr := hostkit.ProviderError(hostkit.Conflict, 409, "AmbiguousUserpoolState",
		fmt.Sprintf("userpool %q state changed concurrently during operation", name))
	maxStateBytes := 8 * 1024 * 1024
	if isCleanup || allowRevokeHeadroom {
		maxStateBytes = 8*1024*1024 + 64*1024
	}
	maxJournalBytes := int64(maxNonCleanupJournalBytes)
	if isCleanup {
		maxJournalBytes = safety.MaxJournalFileBytes
	}
	stateTooLargeErr := func(sz int) *hostkit.CloudError {
		return hostkit.ProviderError(hostkit.InvalidArgument, 0, "UserpoolStateLimitExceeded",
			fmt.Sprintf("userpool %q state size %d exceeds maximum 8 MiB", name, sz))
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		act, ok := ct.activeUserpoolEntries[key]
		_, hasAmb := ct.ambiguousUserpools[key]
		if !ok || ((hasAmb || len(ct.ambiguousUserpoolStack[key]) > 0) && !safety.OnlyDuplicateUserpoolCreateAmbiguity(act, ct.ambiguousUserpoolStack[key])) {
			return staleErr
		}
		if act.OwnerToken != expOwnerToken || act.Incarnation != expIncarnation {
			return staleErr
		}
		newState := mutate(act.StateJSON)
		if newState == act.StateJSON {
			return nil
		}
		if len(newState) > maxStateBytes {
			return stateTooLargeErr(len(newState))
		}
		if ct.journal.FileSize()+int64(len(newState))+1024 > maxJournalBytes {
			_ = ct.journal.Compact()
		}
		if ct.journal.FileSize()+int64(len(newState))+1024 > maxJournalBytes {
			return hostkit.ProviderError(hostkit.InvalidArgument, 0, "JournalSizeLimitExceeded",
				fmt.Sprintf("journal size would exceed headroom limit (%d bytes)", maxJournalBytes))
		}
		if err := ct.journal.RecordUserpoolState(act.Scope, act.Name, act.OwnerToken, act.Incarnation, act.Generation, newState); err != nil {
			if ct.journal.CheckHealth() == nil {
				return hostkit.ProviderError(hostkit.InvalidArgument, 0, "InvalidUserpoolState", err.Error())
			}
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		var cerr *hostkit.CloudError
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			act, ok := st.activeUserpoolEntries[key]
			_, hasAmb := st.ambiguousUserpools[key]
			if !ok || ((hasAmb || len(st.ambiguousUserpoolStack[key]) > 0) && !safety.OnlyDuplicateUserpoolCreateAmbiguity(act, st.ambiguousUserpoolStack[key])) {
				cerr = staleErr
				return nil
			}
			if act.OwnerToken != expOwnerToken || act.Incarnation != expIncarnation {
				cerr = staleErr
				return nil
			}
			newState := mutate(act.StateJSON)
			if newState == act.StateJSON {
				return nil
			}
			if len(newState) > maxStateBytes {
				cerr = stateTooLargeErr(len(newState))
				return nil
			}
			if int64(st.journalFileBytes)+int64(len(newState))+1024 > maxJournalBytes {
				cerr = hostkit.ProviderError(hostkit.InvalidArgument, 0, "JournalSizeLimitExceeded",
					fmt.Sprintf("campaign journal size would exceed headroom limit (%d bytes)", maxJournalBytes))
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:               safety.EventUserpoolState,
				Endpoint:            act.Scope,
				ResKey:              act.Name,
				UserpoolIncarnation: act.Incarnation,
				OwnerToken:          act.OwnerToken,
				Generation:          act.Generation,
				UserpoolState:       newState,
			}); err != nil {
				return err
			}
			act.StateJSON = newState
			st.activeUserpoolEntries[key] = act
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		if cerr != nil {
			return cerr
		}
		return nil
	}

	act, ok := ct.activeUserpoolEntries[key]
	_, hasAmb := ct.ambiguousUserpools[key]
	if !ok || ((hasAmb || len(ct.ambiguousUserpoolStack[key]) > 0) && !safety.OnlyDuplicateUserpoolCreateAmbiguity(act, ct.ambiguousUserpoolStack[key])) {
		return staleErr
	}
	if act.OwnerToken != expOwnerToken || act.Incarnation != expIncarnation {
		return staleErr
	}
	newState := mutate(act.StateJSON)
	if len(newState) > maxStateBytes {
		return stateTooLargeErr(len(newState))
	}
	act.StateJSON = newState
	ct.activeUserpoolEntries[key] = act
	return nil
}

func (ct *costTracker) confirmUserpoolDelete(entry safety.JournalUserpoolEntry) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := entry.Key
	if key == "" {
		key = scopedResKey(entry.Scope, entry.Name)
		entry.Key = key
	}
	entryGen, _ := strconv.ParseUint(entry.Generation, 10, 64)

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingUserpoolIntent(ct.ambiguousUserpoolStack[key], ct.ambiguousUserpools, key, entry.IntentID) ||
			ct.latestUserpoolIntent[key] != entry.IntentID || entryGen < ct.maxUserpoolGen[key] {
			return nil
		}
		if err := ct.journal.RecordUserpoolDelete(entry.Scope, entry.Name, entry.OwnerToken, entry.Generation, entry.IntentID); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingUserpoolIntent(st.ambiguousUserpoolStack[key], st.ambiguousUserpools, key, entry.IntentID) ||
				st.latestUserpoolIntent[key] != entry.IntentID || entryGen < st.maxUserpoolGen[key] {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:      safety.EventUserpoolDelete,
				IntentID:   entry.IntentID,
				Endpoint:   entry.Scope,
				ResKey:     entry.Name,
				OwnerToken: entry.OwnerToken,
				Generation: entry.Generation,
			}); err != nil {
				return err
			}
			delete(st.activeUserpoolEntries, key)
			delete(st.ambiguousUserpoolStack, key)
			delete(st.ambiguousUserpools, key)
			deleteCampaignUserpoolCleanup(st, key)
			deleteResourcePolicyAttachments(st.activePolicies, st.ambiguousPolicies, st.ambiguousStack, st.policyCleanup, safety.KindUserpool, entry.Scope, entry.Name)
			ct.applyReplayedStateLocked(st)
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}

	if !hasPendingUserpoolIntent(ct.ambiguousUserpoolStack[key], ct.ambiguousUserpools, key, entry.IntentID) ||
		ct.latestUserpoolIntent[key] != entry.IntentID || entryGen < ct.maxUserpoolGen[key] {
		return nil
	}
	delete(ct.activeUserpoolEntries, key)
	delete(ct.ambiguousUserpoolStack, key)
	delete(ct.ambiguousUserpools, key)
	return nil
}

func (ct *costTracker) abortUserpoolIntent(entry safety.JournalUserpoolEntry) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	key := entry.Key
	if key == "" {
		key = scopedResKey(entry.Scope, entry.Name)
		entry.Key = key
	}

	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		if ct.poisoned != nil {
			return ct.poisoned
		}
		if !hasPendingUserpoolIntent(ct.ambiguousUserpoolStack[key], ct.ambiguousUserpools, key, entry.IntentID) {
			return nil
		}
		if err := ct.journal.RecordUserpoolIntent(entry.Scope, entry.Name, "abort", "", entry.OwnerToken, entry.Generation, entry.IntentID, "", "", 0); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		ct.syncFromSafetyJournalLocked()
		return ct.poisoned
	}

	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, appendRec func(campaignJournalRecord) error) error {
			if !hasPendingUserpoolIntent(st.ambiguousUserpoolStack[key], st.ambiguousUserpools, key, entry.IntentID) {
				return nil
			}
			if err := appendRec(campaignJournalRecord{
				Event:          safety.EventUserpoolIntent,
				IntentID:       entry.IntentID,
				Endpoint:       entry.Scope,
				ResKey:         entry.Name,
				PolicyIntentOp: "abort",
				OwnerToken:     entry.OwnerToken,
				Generation:     entry.Generation,
			}); err != nil {
				return err
			}
			stack := st.ambiguousUserpoolStack[key]
			if len(stack) > 0 {
				filtered := stack[:0]
				for _, item := range stack {
					if item.IntentID != entry.IntentID {
						filtered = append(filtered, item)
					}
				}
				if len(filtered) > 0 {
					st.ambiguousUserpoolStack[key] = filtered
					st.ambiguousUserpools[key] = filtered[len(filtered)-1]
				} else {
					delete(st.ambiguousUserpoolStack, key)
					delete(st.ambiguousUserpools, key)
					if _, inActive := st.activeUserpoolEntries[key]; !inActive {
						deleteCampaignUserpoolCleanup(st, key)
					}
				}
			} else {
				delete(st.ambiguousUserpools, key)
				if _, inActive := st.activeUserpoolEntries[key]; !inActive {
					deleteCampaignUserpoolCleanup(st, key)
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

	if !hasPendingUserpoolIntent(ct.ambiguousUserpoolStack[key], ct.ambiguousUserpools, key, entry.IntentID) {
		return nil
	}
	stack := ct.ambiguousUserpoolStack[key]
	if len(stack) > 0 {
		filtered := stack[:0]
		for _, item := range stack {
			if item.IntentID != entry.IntentID {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) > 0 {
			ct.ambiguousUserpoolStack[key] = filtered
			ct.ambiguousUserpools[key] = filtered[len(filtered)-1]
			return nil
		}
		delete(ct.ambiguousUserpoolStack, key)
	}
	delete(ct.ambiguousUserpools, key)
	if _, inActive := ct.activeUserpoolEntries[key]; !inActive {
		if releaseNano, ok := ct.activeUserpools[key]; ok {
			delete(ct.activeUserpools, key)
			if ct.meter != nil && releaseNano > 0 {
				ct.meter.ReleaseResourceCleanup(releaseNano)
			}
		}
	}
	return nil
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
	if ct.liveGuard != nil {
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
	mu              sync.Mutex
	ct              *costTracker
	op              string
	endpoint        string
	in              safety.AttemptPricingInput
	baseCleanup     bool
	isRoot          bool
	hasSubOps       bool
	finished        bool
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

func (ct *costTracker) verifyActiveReservation(attemptID string) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.poisoned != nil {
		return ct.poisoned
	}
	if ct.journal != nil {
		if err := ct.journal.CheckHealth(); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			return ct.poisoned
		}
		return nil
	}
	if ct.statePath != "" {
		if err := ct.withLockedCampaignJournal(true, func(st *replayedCampaignState, _ func(campaignJournalRecord) error) error {
			if attemptID != "" {
				if _, ok := st.pending[attemptID]; !ok {
					return fmt.Errorf("missing pending reservation %s in campaign journal", attemptID)
				}
			}
			return nil
		}); err != nil {
			ct.poisoned = hostkit.ProviderError(hostkit.Internal, 0, "CampaignJournalWriteFailed", err.Error())
			return ct.poisoned
		}
	}
	return nil
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
	tariffOp := s.op
	if s.in.Operation != "" {
		tariffOp = s.in.Operation
	}
	reportedBytes := s.in.PayloadSize
	if s.hasSubOps {
		reportedBytes = 0
	}
	switch tariffOp {
	case "object_put", "queue_send", "item_put", "item_update", "item_delete":
		return s.ct.settleAt(res, attID, s.op, s.endpoint, s.in.PayloadSize, reportedBytes, s.resKind, s.resKey, false, false)
	}
	isPayloadRead := tariffOp == "object_get" || tariffOp == "queue_receive" || tariffOp == "item_get" || tariffOp == "item_query" || tariffOp == "item_scan" || s.in.PayloadSize > 0 || s.in.EgressBytes > 0
	headerOnlyNoPayload := s.hasLastAttempt &&
		s.lastAttempt.Err == nil &&
		(!isPayloadRead || s.lastAttempt.Status >= 400)
	if headerOnlyNoPayload {
		// HTTP status response without payload transfer (e.g. 429/503 status header, or completed non-payload Do).
		return s.ct.settleAt(res, attID, s.op, s.endpoint, 0, 0, s.resKind, s.resKey, true, false)
	}
	// Completed 2xx GET/Receive/Query/Scan or mid-stream/ambiguous transport failure: preserve full reserved bound.
	boundBytes := s.in.PayloadSize
	if tariffOp == "object_get" || s.in.EgressBytes > boundBytes {
		boundBytes = s.in.EgressBytes
	}
	if !s.hasSubOps {
		reportedBytes = boundBytes
	}
	return s.ct.settleAt(res, attID, s.op, s.endpoint, boundBytes, reportedBytes, s.resKind, s.resKey, false, false)
}

func attachScopeHooks(ctx context.Context, scope *attemptScope) context.Context {
	return hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{
		BeforeAttempt: func(_ context.Context, attempt int) error {
			scope.mu.Lock()
			defer scope.mu.Unlock()
			if scope.finished {
				return hostkit.ProviderError(hostkit.Internal, 0, "ScopeFinished", "attempt hook invoked after scope finished")
			}
			if scope.abortErr != nil {
				return scope.abortErr
			}
			if !scope.initialConsumed {
				if cerr := scope.ct.verifyActiveReservation(scope.attemptID); cerr != nil {
					scope.abortErr = cerr
					return cerr
				}
				scope.initialConsumed = true
				return nil
			}
			if scerr := scope.settlePreviousAttemptLocked(); scerr != nil {
				scope.abortErr = scerr
				return scerr
			}
			nextRes, nextAttID, cerr := scope.ct.reserveForOp(scope.op, scope.endpoint, scope.in, scope.resKind, scope.resKey)
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
		AfterAttempt: func(_ context.Context, attempt int, a hostkit.Attempt) {
			scope.mu.Lock()
			defer scope.mu.Unlock()
			scope.lastAttempt = a
			scope.hasLastAttempt = true
			if a.Status == 429 {
				scope.throttles++
			}
			if a.NotSent {
				if attempt > 0 && scope.retries > 0 {
					scope.retries--
				}
				if scope.res != nil {
					if rerr := scope.ct.release(scope.res, scope.attemptID); rerr != nil && scope.abortErr == nil {
						scope.abortErr = rerr
					}
					scope.res = nil
					scope.attemptID = ""
				}
			}
		},
	})
}

func attachSubOperationRunner(ctx context.Context, parent *attemptScope) context.Context {
	return hostkit.WithSubOperationRunner(ctx, func(subCtx context.Context, spec hostkit.SubOperationSpec, fn func(ctx context.Context) error) error {
		if fn == nil {
			return hostkit.ProviderError(hostkit.InvalidArgument, 0, "InvalidSubOperation", "sub-operation callback is nil")
		}
		opName := strings.TrimSpace(spec.Operation)
		if opName == "" || spec.PayloadBytes < 0 || spec.EgressBytes < 0 {
			return hostkit.ProviderError(hostkit.InvalidArgument, 0, "InvalidSubOperation", "invalid sub-operation specification")
		}

		parent.mu.Lock()
		if parent.finished {
			parent.mu.Unlock()
			return hostkit.ProviderError(hostkit.Internal, 0, "SubOperationAfterFinish", "sub-operation invoked after parent scope finished")
		}
		if parent.abortErr != nil {
			err := parent.abortErr
			parent.mu.Unlock()
			return err
		}
		// Only an authorized cleanup parent scope may charge against the cleanup ceiling.
		subIn := safety.AttemptPricingInput{
			Operation:   opName,
			PayloadSize: spec.PayloadBytes,
			EgressBytes: spec.EgressBytes,
			IsCleanup:   parent.baseCleanup,
		}
		transferToRoot := false
		if parent.isRoot && (!parent.initialConsumed || parent.hasSubOps) {
			transferToRoot = true
			if !parent.initialConsumed {
				parent.initialConsumed = true
				parent.hasSubOps = true
				if parent.res != nil {
					if rerr := parent.ct.release(parent.res, parent.attemptID); rerr != nil {
						parent.abortErr = rerr
						parent.res = nil
						parent.attemptID = ""
						parent.mu.Unlock()
						return rerr
					}
					parent.res = nil
					parent.attemptID = ""
				}
			} else if scerr := parent.settlePreviousAttemptLocked(); scerr != nil {
				parent.abortErr = scerr
				parent.mu.Unlock()
				return scerr
			}
		}
		// Reserve and durably record the initial sub-operation attempt BEFORE entering fn.
		childRes, childAttID, cerr := parent.ct.reserveForOp(parent.op, parent.endpoint, subIn, parent.resKind, parent.resKey)
		if cerr != nil {
			parent.abortErr = cerr
			parent.mu.Unlock()
			return cerr
		}
		child := &attemptScope{
			ct:          parent.ct,
			op:          parent.op,
			endpoint:    parent.endpoint,
			in:          subIn,
			baseCleanup: parent.baseCleanup,
			hasSubOps:   true,
			resKind:     parent.resKind,
			resKey:      parent.resKey,
			res:         childRes,
			attemptID:   childAttID,
		}
		parent.mu.Unlock()

		childCtx := attachScopeHooks(subCtx, child)
		childCtx = attachSubOperationRunner(childCtx, child)
		fnErr := fn(childCtx)

		if !transferToRoot {
			r, t, abortErr := child.finish(0, 0, fnErr == nil, false)
			parent.mu.Lock()
			defer parent.mu.Unlock()
			parent.retries += r
			parent.throttles += t
			if abortErr != nil && parent.abortErr == nil {
				parent.abortErr = abortErr
			}
			if parent.abortErr != nil {
				return parent.abortErr
			}
			return fnErr
		}

		parent.mu.Lock()
		defer parent.mu.Unlock()

		child.mu.Lock()
		child.finished = true
		parent.retries += child.retries
		parent.throttles += child.throttles
		if child.abortErr != nil && parent.abortErr == nil {
			parent.abortErr = child.abortErr
		}
		if child.res != nil {
			if child.hasLastAttempt && child.lastAttempt.NotSent {
				if rerr := child.ct.release(child.res, child.attemptID); rerr != nil && parent.abortErr == nil {
					parent.abortErr = rerr
				}
			} else {
				if parent.res != nil {
					if scerr := parent.settlePreviousAttemptLocked(); scerr != nil && parent.abortErr == nil {
						parent.abortErr = scerr
					}
				}
				parent.in = child.in
				parent.res = child.res
				parent.attemptID = child.attemptID
				parent.lastAttempt = child.lastAttempt
				parent.hasLastAttempt = child.hasLastAttempt
			}
			child.res = nil
			child.attemptID = ""
		}
		child.mu.Unlock()

		if parent.abortErr != nil {
			return parent.abortErr
		}
		return fnErr
	})
}

func (h *Host) beginAttemptScope(ctx context.Context, op string, in safety.AttemptPricingInput, resKind, resKey string) (context.Context, *attemptScope, *hostkit.CloudError) {
	endpoint := hostkit.EndpointFrom(ctx)
	res, attID, cerr := h.cost.reserveForOp(op, endpoint, in, resKind, resKey)
	if cerr != nil {
		return ctx, nil, cerr
	}
	scope := &attemptScope{
		ct:          h.cost,
		op:          op,
		endpoint:    endpoint,
		in:          in,
		baseCleanup: in.IsCleanup,
		isRoot:      true,
		resKind:     resKind,
		resKey:      resKey,
		res:         res,
		attemptID:   attID,
	}
	ctxWithHooks := attachScopeHooks(ctx, scope)
	ctxWithHooks = attachSubOperationRunner(ctxWithHooks, scope)
	return ctxWithHooks, scope, nil
}

func (s *attemptScope) releaseNotSent() *hostkit.CloudError {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = true
	if s.res != nil {
		rerr := s.ct.release(s.res, s.attemptID)
		s.res = nil
		s.attemptID = ""
		return rerr
	}
	return nil
}

func (s *attemptScope) finish(chargeBytes, reportedBytes int64, cleanSuccess, opSucceeded bool) (retries, throttles int64, abortErr *hostkit.CloudError) {
	return s.finishWithUnits(chargeBytes, reportedBytes, 0, cleanSuccess, opSucceeded)
}

func (s *attemptScope) finishWithUnits(chargeBytes, reportedBytes, overrideUnits int64, cleanSuccess, opSucceeded bool) (retries, throttles int64, abortErr *hostkit.CloudError) {
	if s == nil {
		return 0, 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finished = true
	if s.res != nil {
		if s.hasLastAttempt && s.lastAttempt.NotSent {
			if rerr := s.ct.release(s.res, s.attemptID); rerr != nil && s.abortErr == nil {
				s.abortErr = rerr
			}
		} else {
			if s.hasSubOps && chargeBytes == 0 {
				chargeBytes = s.in.PayloadSize
				if s.in.EgressBytes > chargeBytes {
					chargeBytes = s.in.EgressBytes
				}
			}
			if scerr := s.ct.settleAtWithUnits(s.res, s.attemptID, s.op, s.endpoint, chargeBytes, reportedBytes, overrideUnits, s.resKind, s.resKey, cleanSuccess, opSucceeded); scerr != nil && s.abortErr == nil {
				s.abortErr = scerr
			}
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
