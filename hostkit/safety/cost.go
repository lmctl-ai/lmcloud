// SPDX-License-Identifier: MIT

package safety

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	// NanoUSDPerUSD is 10^9 nano-USD per 1.00 USD.
	NanoUSDPerUSD int64 = 1_000_000_000

	// PriceTableSchemaVersion is the current regional price table format version.
	PriceTableSchemaVersion = 1

	secondsPerMonth = 30 * 24 * 3600
	bytesPerGiB     = 1024 * 1024 * 1024
)

//go:embed prices/*/*.json
var embeddedPricesFS embed.FS

// ErrCostCapExceeded is returned when an operation would exceed the active cost cap.
var ErrCostCapExceeded = errors.New("live cost cap exceeded")

// USDToNano converts a USD float64 to integer nano-USD, rounding up to avoid
// under-estimating charges.
func USDToNano(usd float64) int64 {
	if usd <= 0 {
		return 0
	}
	return int64(math.Ceil(usd * float64(NanoUSDPerUSD)))
}

// NanoToUSD converts integer nano-USD to float64 USD.
func NanoToUSD(nano int64) float64 {
	return float64(nano) / float64(NanoUSDPerUSD)
}

// OperationTariff defines the worst-case pricing components for one cloud operation.
type OperationTariff struct {
	RequestNanoUSD         int64 `json:"request_nano_usd"`
	ChunkBytes             int64 `json:"chunk_bytes,omitempty"`
	StorageGiBMonthNanoUSD int64 `json:"storage_gib_month_nano_usd,omitempty"`
	MinDurationSeconds     int64 `json:"min_duration_seconds,omitempty"`
	EgressGiBNanoUSD       int64 `json:"egress_gib_nano_usd,omitempty"`
	CleanupReserveNanoUSD  int64 `json:"cleanup_reserve_nano_usd,omitempty"`
}

// PriceTable holds the verified tariff schedule for one (provider, region).
type PriceTable struct {
	SchemaVersion                    int                        `json:"schema_version"`
	Provider                         string                     `json:"provider"`
	Region                           string                     `json:"region"`
	Currency                         string                     `json:"currency"`
	SourceURL                        string                     `json:"source_url"`
	EffectiveDate                    string                     `json:"effective_date"`
	MaxAgeDays                       int                        `json:"max_age_days"`
	CleanupReservePerResourceNanoUSD int64                      `json:"cleanup_reserve_per_resource_nano_usd"`
	Operations                       map[string]OperationTariff `json:"operations"`
}

// LoadEmbeddedPriceTable loads and validates the embedded price table for
// (provider, region) at timestamp now. Unknown provider/region or stale tables
// fail closed.
func LoadEmbeddedPriceTable(provider, region string, now time.Time) (*PriceTable, error) {
	return LoadPriceTableFromFS(embeddedPricesFS, provider, region, now)
}

// LoadPriceTableFromFS loads and validates `prices/<provider>/<region>.json`
// from fsys at timestamp now.
func LoadPriceTableFromFS(fsys fs.FS, provider, region string, now time.Time) (*PriceTable, error) {
	provider = strings.TrimSpace(provider)
	region = strings.TrimSpace(region)
	if !validProviders[provider] || region == "" || strings.ContainsAny(region, "/\\..") {
		return nil, fmt.Errorf("unknown or invalid price-table target %s/%s (fail closed)", provider, region)
	}
	relPath := fmt.Sprintf("prices/%s/%s.json", provider, region)
	raw, err := fs.ReadFile(fsys, relPath)
	if err != nil {
		return nil, fmt.Errorf("no price table for provider=%q region=%q (%s): %w", provider, region, relPath, err)
	}
	return ParsePriceTable(raw, provider, region, now)
}

// ParsePriceTable strictly decodes and validates a regional price table JSON document.
func ParsePriceTable(raw []byte, expectedProvider, expectedRegion string, now time.Time) (*PriceTable, error) {
	var pt PriceTable
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pt); err != nil {
		return nil, fmt.Errorf("parse price table: %w", err)
	}
	if err := pt.Validate(expectedProvider, expectedRegion, now); err != nil {
		return nil, err
	}
	return &pt, nil
}

// Validate checks the schema version, provider/region match, currency, source URL,
// effective_date freshness against max_age_days, and non-negative operation tariffs.
func (pt *PriceTable) Validate(expectedProvider, expectedRegion string, now time.Time) error {
	if pt == nil {
		return errors.New("nil price table")
	}
	if pt.SchemaVersion != PriceTableSchemaVersion {
		return fmt.Errorf("unsupported price table schema_version %d (want %d)", pt.SchemaVersion, PriceTableSchemaVersion)
	}
	if expectedProvider != "" && pt.Provider != expectedProvider {
		return fmt.Errorf("price table provider %q does not match expected %q", pt.Provider, expectedProvider)
	}
	if expectedRegion != "" && pt.Region != expectedRegion {
		return fmt.Errorf("price table region %q does not match expected %q", pt.Region, expectedRegion)
	}
	if pt.Currency != "USD" {
		return fmt.Errorf("unsupported price table currency %q (want USD)", pt.Currency)
	}
	if strings.TrimSpace(pt.SourceURL) == "" {
		return errors.New("price table source_url must not be empty")
	}
	if pt.MaxAgeDays <= 0 {
		return fmt.Errorf("price table max_age_days %d must be > 0", pt.MaxAgeDays)
	}
	eff, err := time.Parse("2006-01-02", strings.TrimSpace(pt.EffectiveDate))
	if err != nil {
		return fmt.Errorf("invalid price table effective_date %q (want YYYY-MM-DD): %w", pt.EffectiveDate, err)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	maxAge := time.Duration(pt.MaxAgeDays) * 24 * time.Hour
	if now.UTC().Sub(eff.UTC()) > maxAge {
		return fmt.Errorf("stale price table for %s/%s: effective_date %s exceeds max_age_days %d at %s",
			pt.Provider, pt.Region, pt.EffectiveDate, pt.MaxAgeDays, now.UTC().Format("2006-01-02"))
	}
	if pt.CleanupReservePerResourceNanoUSD < 0 {
		return errors.New("price table cleanup_reserve_per_resource_nano_usd must be >= 0")
	}
	if len(pt.Operations) == 0 {
		return errors.New("price table operations must not be empty")
	}
	for op, t := range pt.Operations {
		if t.RequestNanoUSD < 0 || t.ChunkBytes < 0 || t.StorageGiBMonthNanoUSD < 0 ||
			t.MinDurationSeconds < 0 || t.EgressGiBNanoUSD < 0 || t.CleanupReserveNanoUSD < 0 {
			return fmt.Errorf("price table operation %q has negative tariff component", op)
		}
	}
	return nil
}

// AttemptPricingInput describes a single cloud request attempt to be priced BEFORE dispatch.
type AttemptPricingInput struct {
	Operation   string
	PayloadSize int64
	EgressBytes int64
	IsCleanup   bool
}

// AttemptQuote is the worst-case pre-dispatch cost estimate for a single attempt.
type AttemptQuote struct {
	Operation             string
	AttemptNanoUSD        int64
	CleanupReserveNanoUSD int64
	IsCleanup             bool
}

// AttemptQuoter is an optional hook implemented by recovery adapters to customize
// or augment per-attempt pricing quotes.
type AttemptQuoter interface {
	QuoteAttempt(in AttemptPricingInput, base AttemptQuote) (AttemptQuote, error)
}

// Quote computes the worst-case pre-dispatch AttemptQuote for in using the
// regional price table. Unknown operations fail closed.
func (pt *PriceTable) Quote(in AttemptPricingInput) (AttemptQuote, error) {
	if pt == nil {
		return AttemptQuote{}, errors.New("nil price table (fail closed)")
	}
	tariff, ok := pt.Operations[in.Operation]
	if !ok {
		return AttemptQuote{}, fmt.Errorf("unknown operation %q in price table %s/%s (fail closed)", in.Operation, pt.Provider, pt.Region)
	}

	units := int64(1)
	if tariff.ChunkBytes > 0 && in.PayloadSize > tariff.ChunkBytes {
		units = (in.PayloadSize + tariff.ChunkBytes - 1) / tariff.ChunkBytes
	}
	attemptNano := tariff.RequestNanoUSD * units

	if tariff.StorageGiBMonthNanoUSD > 0 && in.PayloadSize > 0 {
		durSec := tariff.MinDurationSeconds
		if durSec <= 0 {
			durSec = 3600
		}
		// ceil(payloadBytes * storageRate * durSec / (bytesPerGiB * secondsPerMonth))
		num := float64(in.PayloadSize) * float64(tariff.StorageGiBMonthNanoUSD) * float64(durSec)
		den := float64(bytesPerGiB) * float64(secondsPerMonth)
		attemptNano += int64(math.Ceil(num / den))
	}

	if tariff.EgressGiBNanoUSD > 0 && in.EgressBytes > 0 {
		num := float64(in.EgressBytes) * float64(tariff.EgressGiBNanoUSD)
		attemptNano += int64(math.Ceil(num / float64(bytesPerGiB)))
	}

	cleanupNano := int64(0)
	if !in.IsCleanup {
		cleanupNano = tariff.CleanupReserveNanoUSD
	}

	return AttemptQuote{
		Operation:             in.Operation,
		AttemptNanoUSD:        attemptNano,
		CleanupReserveNanoUSD: cleanupNano,
		IsCleanup:             in.IsCleanup,
	}, nil
}

// CostSnapshot reports the current state of a CostMeter.
type CostSnapshot struct {
	CapNanoUSD             int64
	CeilingNanoUSD         int64
	CleanupReserveNanoUSD  int64
	WorkCeilingNanoUSD     int64
	ChargedNanoUSD         int64
	InFlightNanoUSD        int64
	ResourceCleanupNanoUSD int64
}

// TotalCommittedNanoUSD returns ChargedNanoUSD + InFlightNanoUSD + ResourceCleanupNanoUSD.
func (s CostSnapshot) TotalCommittedNanoUSD() int64 {
	return s.ChargedNanoUSD + s.InFlightNanoUSD + s.ResourceCleanupNanoUSD
}

// CostMeter enforces per-run cost caps, pre-attempt reservations, and the
// dedicated teardown/cleanup reserve pool.
type CostMeter struct {
	mu                     sync.Mutex
	table                  *PriceTable
	quoter                 AttemptQuoter
	capNanoUSD             int64
	ceilingNanoUSD         int64
	cleanupReserveNanoUSD  int64
	chargedNanoUSD         int64
	inFlightNanoUSD        int64
	resourceCleanupNanoUSD int64
}

// NewCostMeter constructs a CostMeter for policy and regional PriceTable.
func NewCostMeter(costPol CostPolicy, table *PriceTable, quoter AttemptQuoter) (*CostMeter, error) {
	costPol.applyDefaults()
	if err := costPol.validate(); err != nil {
		return nil, err
	}
	if table == nil {
		return nil, errors.New("cost meter requires a non-nil PriceTable")
	}
	capNano := USDToNano(costPol.CapUSD)
	ceilNano := USDToNano(costPol.CeilingUSD)
	resNano := USDToNano(costPol.CleanupReserveUSD)
	if capNano > ceilNano {
		return nil, fmt.Errorf("cost cap %d nano-USD exceeds hard ceiling %d nano-USD", capNano, ceilNano)
	}
	if resNano >= capNano {
		return nil, fmt.Errorf("cleanup reserve %d nano-USD must be less than cost cap %d nano-USD", resNano, capNano)
	}
	return &CostMeter{
		table:                 table,
		quoter:                quoter,
		capNanoUSD:            capNano,
		ceilingNanoUSD:        ceilNano,
		cleanupReserveNanoUSD: resNano,
	}, nil
}

// RestoreCharged sets the initial charged nano-USD (e.g. replayed from an existing journal).
func (m *CostMeter) RestoreCharged(chargedNanoUSD, resourceCleanupNanoUSD int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if chargedNanoUSD > m.chargedNanoUSD {
		m.chargedNanoUSD = chargedNanoUSD
	}
	if resourceCleanupNanoUSD > m.resourceCleanupNanoUSD {
		m.resourceCleanupNanoUSD = resourceCleanupNanoUSD
	}
}

// SetCapUSD updates the active run cost cap (rejected if > ceiling or <= cleanup reserve
// or below already committed spend).
func (m *CostMeter) SetCapUSD(capUSD float64) error {
	if math.IsNaN(capUSD) || math.IsInf(capUSD, 0) || capUSD <= 0 {
		return fmt.Errorf("invalid cost cap %v", capUSD)
	}
	newCap := USDToNano(capUSD)
	m.mu.Lock()
	defer m.mu.Unlock()
	if newCap > m.ceilingNanoUSD {
		return fmt.Errorf("%w: requested cap $%.4f exceeds hard ceiling $%.4f",
			ErrCostCapExceeded, capUSD, NanoToUSD(m.ceilingNanoUSD))
	}
	if newCap <= m.cleanupReserveNanoUSD {
		return fmt.Errorf("requested cap $%.4f must exceed cleanup reserve $%.4f",
			capUSD, NanoToUSD(m.cleanupReserveNanoUSD))
	}
	committed := m.chargedNanoUSD + m.inFlightNanoUSD + m.resourceCleanupNanoUSD
	if newCap < committed {
		return fmt.Errorf("%w: requested cap $%.6f is below already committed spend $%.6f",
			ErrCostCapExceeded, capUSD, NanoToUSD(committed))
	}
	m.capNanoUSD = newCap
	return nil
}

// Snapshot returns the current CostSnapshot.
func (m *CostMeter) Snapshot() CostSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return CostSnapshot{
		CapNanoUSD:             m.capNanoUSD,
		CeilingNanoUSD:         m.ceilingNanoUSD,
		CleanupReserveNanoUSD:  m.cleanupReserveNanoUSD,
		WorkCeilingNanoUSD:     m.capNanoUSD - m.cleanupReserveNanoUSD,
		ChargedNanoUSD:         m.chargedNanoUSD,
		InFlightNanoUSD:        m.inFlightNanoUSD,
		ResourceCleanupNanoUSD: m.resourceCleanupNanoUSD,
	}
}

// QuoteAttempt computes the worst-case AttemptQuote for in, invoking the
// optional AttemptQuoter hook if configured.
func (m *CostMeter) QuoteAttempt(in AttemptPricingInput) (AttemptQuote, error) {
	base, err := m.table.Quote(in)
	if err != nil {
		return AttemptQuote{}, err
	}
	if m.quoter != nil {
		q, err := m.quoter.QuoteAttempt(in, base)
		if err != nil {
			return AttemptQuote{}, err
		}
		if q.AttemptNanoUSD < 0 || q.CleanupReserveNanoUSD < 0 {
			return AttemptQuote{}, errors.New("AttemptQuoter returned negative cost")
		}
		if q.AttemptNanoUSD < base.AttemptNanoUSD {
			q.AttemptNanoUSD = base.AttemptNanoUSD
		}
		if q.CleanupReserveNanoUSD < base.CleanupReserveNanoUSD {
			q.CleanupReserveNanoUSD = base.CleanupReserveNanoUSD
		}
		q.Operation = base.Operation
		q.IsCleanup = base.IsCleanup
		return q, nil
	}
	return base, nil
}

// AttemptReservation represents funds reserved in a CostMeter for an in-flight HTTP attempt.
type AttemptReservation struct {
	meter  *CostMeter
	quote  AttemptQuote
	closed bool
}

// Quote returns the AttemptQuote associated with this reservation.
func (r *AttemptReservation) Quote() AttemptQuote {
	if r == nil {
		return AttemptQuote{}
	}
	return r.quote
}

// ReserveAttempt prices and reserves budget for a single HTTP attempt before dispatch.
//
// Ordinary work (`!in.IsCleanup`) must fit within `CapNanoUSD - CleanupReserveNanoUSD`
// (default $0.04 out of $0.05), preserving the $0.01 cleanup reserve exclusively
// for teardown/janitor operations (`in.IsCleanup == true`).
func (m *CostMeter) ReserveAttempt(in AttemptPricingInput) (*AttemptReservation, error) {
	quote, err := m.QuoteAttempt(in)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	needed := quote.AttemptNanoUSD + quote.CleanupReserveNanoUSD
	projected := m.chargedNanoUSD + m.inFlightNanoUSD + m.resourceCleanupNanoUSD + needed

	limit := m.capNanoUSD - m.cleanupReserveNanoUSD
	limitLabel := "work ceiling (cap minus cleanup reserve)"
	if in.IsCleanup {
		limit = m.capNanoUSD
		limitLabel = "total cap (including cleanup reserve)"
	}

	if projected > limit {
		return nil, fmt.Errorf("%w: operation %s requires %d nano-USD (projected %d > %s %d nano-USD / $%.4f)",
			ErrCostCapExceeded, in.Operation, needed, projected, limitLabel, limit, NanoToUSD(limit))
	}

	m.inFlightNanoUSD += needed
	return &AttemptReservation{
		meter: m,
		quote: quote,
	}, nil
}

// Commit finalizes an AttemptReservation after the HTTP attempt completes.
// If lockCleanupReserve is true (e.g. a resource was created), the reservation's
// CleanupReserveNanoUSD remains locked in ResourceCleanupNanoUSD until
// ReleaseResourceCleanup is called when the resource is deleted.
func (r *AttemptReservation) Commit(actualAttemptNanoUSD int64, lockCleanupReserve bool) int64 {
	if r == nil || r.meter == nil {
		return 0
	}
	r.meter.mu.Lock()
	defer r.meter.mu.Unlock()
	if r.closed {
		return 0
	}
	r.closed = true

	reservedTotal := r.quote.AttemptNanoUSD + r.quote.CleanupReserveNanoUSD
	r.meter.inFlightNanoUSD -= reservedTotal
	if r.meter.inFlightNanoUSD < 0 {
		r.meter.inFlightNanoUSD = 0
	}

	charge := actualAttemptNanoUSD
	if charge < 0 {
		charge = r.quote.AttemptNanoUSD
	}
	r.meter.chargedNanoUSD += charge
	if lockCleanupReserve && r.quote.CleanupReserveNanoUSD > 0 {
		r.meter.resourceCleanupNanoUSD += r.quote.CleanupReserveNanoUSD
	}
	return charge
}

// ReleaseResourceCleanup releases the per-resource cleanup reservation once a
// resource has been verified deleted during teardown.
func (m *CostMeter) ReleaseResourceCleanup(cleanupNanoUSD int64) {
	if m == nil || cleanupNanoUSD <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resourceCleanupNanoUSD -= cleanupNanoUSD
	if m.resourceCleanupNanoUSD < 0 {
		m.resourceCleanupNanoUSD = 0
	}
}
