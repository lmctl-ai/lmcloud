// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
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
		if t, ok := pt.Operations[op]; ok {
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

type persistedCostState struct {
	ChargedNanoUSD         int64                      `json:"charged_nano_usd"`
	ResourceCleanupNanoUSD int64                      `json:"resource_cleanup_nano_usd"`
	ScriptWorkCapNanoUSD   int64                      `json:"script_work_cap_nano_usd"`
	HasScriptWorkCap       bool                       `json:"has_script_work_cap"`
	CapExceededCount       int64                      `json:"cap_exceeded_count"`
	Ops                    map[string]persistedOpCost `json:"ops"`
	ActiveBuckets          map[string]bool            `json:"active_buckets"`
	ActiveObjects          map[string]bool            `json:"active_objects"`
	ActiveQueues           map[string]bool            `json:"active_queues"`
}

type costTracker struct {
	mu               sync.Mutex
	provider         string
	meter            *safety.CostMeter
	statePath        string
	onSetWorkCap     func(workCapNanoUSD int64) error
	capExceededCount int64
	ops              map[string]persistedOpCost
	activeBuckets    map[string]bool
	activeObjects    map[string]bool
	activeQueues     map[string]bool
}

func newCostTracker(cfg Config) *costTracker {
	provider := cfg.Provider
	if provider == "" {
		provider = "ref"
	}
	meter := cfg.Meter
	if meter == nil {
		pt := cfg.PriceTable
		if pt == nil {
			pt = safety.SyntheticSimPriceTable(provider)
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
	}
	ct := &costTracker{
		provider:      provider,
		meter:         meter,
		statePath:     cfg.CampaignStatePath,
		onSetWorkCap:  cfg.OnSetWorkCap,
		ops:           map[string]persistedOpCost{},
		activeBuckets: map[string]bool{},
		activeObjects: map[string]bool{},
		activeQueues:  map[string]bool{},
	}
	ct.loadStateLocked()
	return ct
}

func defaultCampaignStatePath() string {
	id := strings.TrimSpace(os.Getenv("LMCLOUD_CAMPAIGN_ID"))
	if id == "" {
		id = fmt.Sprintf("ppid-%d", os.Getppid())
	}
	var safe strings.Builder
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			safe.WriteByte(c)
		} else {
			safe.WriteByte('_')
		}
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("lmcloud-campaign-%d-%s.json", os.Getuid(), safe.String()))
}

func (ct *costTracker) loadStateLocked() {
	if ct.statePath == "" {
		return
	}
	raw, err := os.ReadFile(ct.statePath)
	if err != nil {
		return
	}
	var st persistedCostState
	if err := json.Unmarshal(raw, &st); err != nil {
		return
	}
	ct.meter.RestoreCharged(st.ChargedNanoUSD, st.ResourceCleanupNanoUSD)
	if st.HasScriptWorkCap && st.ScriptWorkCapNanoUSD > 0 {
		ct.meter.RestoreWorkCap(st.ScriptWorkCapNanoUSD)
	}
	ct.capExceededCount = st.CapExceededCount
	if st.Ops != nil {
		ct.ops = st.Ops
	}
	if st.ActiveBuckets != nil {
		ct.activeBuckets = st.ActiveBuckets
	}
	if st.ActiveObjects != nil {
		ct.activeObjects = st.ActiveObjects
	}
	if st.ActiveQueues != nil {
		ct.activeQueues = st.ActiveQueues
	}
}

func (ct *costTracker) saveStateLocked() {
	if ct.statePath == "" {
		return
	}
	snap := ct.meter.Snapshot()
	st := persistedCostState{
		ChargedNanoUSD:         snap.ChargedNanoUSD,
		ResourceCleanupNanoUSD: snap.ResourceCleanupNanoUSD,
		ScriptWorkCapNanoUSD:   snap.ScriptWorkCapNanoUSD,
		HasScriptWorkCap:       snap.HasScriptWorkCap,
		CapExceededCount:       ct.capExceededCount,
		Ops:                    ct.ops,
		ActiveBuckets:          ct.activeBuckets,
		ActiveObjects:          ct.activeObjects,
		ActiveQueues:           ct.activeQueues,
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := fmt.Sprintf("%s.%d.tmp", ct.statePath, os.Getpid())
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, ct.statePath)
}

func (ct *costTracker) reserve(in safety.AttemptPricingInput) (*safety.AttemptReservation, *hostkit.CloudError) {
	res, err := ct.meter.ReserveAttempt(in)
	if err != nil {
		ct.mu.Lock()
		if errors.Is(err, safety.ErrCostCapExceeded) {
			ct.capExceededCount++
			ct.saveStateLocked()
			ct.mu.Unlock()
			return nil, hostkit.ProviderError(hostkit.CostCapExceeded, 0, "CostCapExceeded", err.Error())
		}
		ct.mu.Unlock()
		return nil, hostkit.ProviderError(hostkit.Internal, 0, "PricingFailure", err.Error())
	}
	return res, nil
}

func (ct *costTracker) settle(res *safety.AttemptReservation, op string, settledBytes int64, resKind, resKey string, opSucceeded bool) {
	if res == nil {
		return
	}
	pt := ct.meter.Table()
	var actualNano int64 = -1
	var units int64 = 1
	if pt != nil {
		if t, ok := pt.Operations[op]; ok {
			if t.ChunkBytes > 0 && settledBytes > t.ChunkBytes {
				units = (settledBytes + t.ChunkBytes - 1) / t.ChunkBytes
			}
			in := safety.AttemptPricingInput{
				Operation: op,
				IsCleanup: res.Quote().IsCleanup,
			}
			if op == "object_get" {
				in.EgressBytes = settledBytes
			} else {
				in.PayloadSize = settledBytes
			}
			if q, err := ct.meter.QuoteAttempt(in); err == nil {
				actualNano = q.AttemptNanoUSD
			}
		}
	}

	ct.mu.Lock()
	defer ct.mu.Unlock()

	lockCleanup := false
	if opSucceeded {
		switch op {
		case "bucket_create":
			if !ct.activeBuckets[resKey] {
				ct.activeBuckets[resKey] = true
				lockCleanup = true
			}
		case "object_put":
			if !ct.activeObjects[resKey] {
				ct.activeObjects[resKey] = true
				lockCleanup = true
			}
		case "queue_create":
			if !ct.activeQueues[resKey] {
				ct.activeQueues[resKey] = true
				lockCleanup = true
			}
		}
	}

	charged := res.Commit(actualNano, lockCleanup)

	if opSucceeded {
		switch op {
		case "bucket_delete":
			if ct.activeBuckets[resKey] {
				delete(ct.activeBuckets, resKey)
				if pt != nil {
					ct.meter.ReleaseResourceCleanup(pt.Operations["bucket_create"].CleanupReserveNanoUSD)
				}
			}
		case "object_delete":
			if ct.activeObjects[resKey] {
				delete(ct.activeObjects, resKey)
				if pt != nil {
					ct.meter.ReleaseResourceCleanup(pt.Operations["object_put"].CleanupReserveNanoUSD)
				}
			}
		case "queue_delete":
			if ct.activeQueues[resKey] {
				delete(ct.activeQueues, resKey)
				if pt != nil {
					ct.meter.ReleaseResourceCleanup(pt.Operations["queue_create"].CleanupReserveNanoUSD)
				}
			}
		}
	}

	cur := ct.ops[op]
	cur.Requests++
	cur.BillingUnits += units
	cur.Bytes += settledBytes
	cur.ChargedNanoUSD += charged
	ct.ops[op] = cur
	ct.saveStateLocked()
}

func (ct *costTracker) costCapUSD() float64 {
	snap := ct.meter.Snapshot()
	return safety.NanoToUSD(snap.ActiveCapNanoUSD)
}

func (ct *costTracker) estimatedCostUSD() float64 {
	snap := ct.meter.Snapshot()
	return safety.NanoToUSD(snap.ChargedNanoUSD)
}

func (ct *costTracker) setWorkCapUSD(capUSD float64) *hostkit.CloudError {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if err := ct.meter.SetWorkCapUSD(capUSD); err != nil {
		return hostkit.Preflightf("set_cost_cap_usd: %v", err)
	}
	snap := ct.meter.Snapshot()
	if ct.onSetWorkCap != nil {
		if err := ct.onSetWorkCap(snap.ScriptWorkCapNanoUSD); err != nil {
			return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
		}
	}
	ct.saveStateLocked()
	return nil
}

func (ct *costTracker) report() CostReport {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	snap := ct.meter.Snapshot()
	pt := ct.meter.Table()
	ver := safety.SyntheticSimPriceTableVersion
	if pt != nil && pt.VersionID() != "" {
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
	ct        *costTracker
	op        string
	in        safety.AttemptPricingInput
	resKind   string
	resKey    string
	res       *safety.AttemptReservation
	retries   int64
	throttles int64
}

func (h *Host) beginAttemptScope(ctx context.Context, op string, in safety.AttemptPricingInput, resKind, resKey string) (context.Context, *attemptScope, *hostkit.CloudError) {
	res, cerr := h.cost.reserve(in)
	if cerr != nil {
		return ctx, nil, cerr
	}
	scope := &attemptScope{
		ct:      h.cost,
		op:      op,
		in:      in,
		resKind: resKind,
		resKey:  resKey,
		res:     res,
	}
	ctxWithHooks := hostkit.WithRetryHooks(ctx, hostkit.RetryHooks{
		BeforeAttempt: func(_ context.Context, attempt int) error {
			if attempt == 0 {
				return nil
			}
			// Settle the previous failed attempt with 0 payload/egress bytes.
			if scope.res != nil {
				scope.ct.settle(scope.res, scope.op, 0, scope.resKind, scope.resKey, false)
				scope.res = nil
			}
			nextRes, cerr := scope.ct.reserve(scope.in)
			if cerr != nil {
				return cerr
			}
			scope.retries++
			scope.res = nextRes
			return nil
		},
		AfterAttempt: func(_ context.Context, attempt int, a hostkit.Attempt) {
			if a.Status == 429 {
				scope.throttles++
			}
			if a.NotSent && attempt > 0 && a.Err != nil && ctx.Err() != nil && scope.res != nil {
				// Sleep was cancelled before dispatching the retry: release reservation without charging.
				scope.res.Commit(0, false)
				scope.res = nil
			}
		},
	})
	return ctxWithHooks, scope, nil
}

func (s *attemptScope) finish(settledBytes int64, opSucceeded bool) (retries, throttles int64) {
	if s == nil {
		return 0, 0
	}
	if s.res != nil {
		s.ct.settle(s.res, s.op, settledBytes, s.resKind, s.resKey, opSucceeded)
		s.res = nil
	}
	return s.retries, s.throttles
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
