// SPDX-License-Identifier: MIT

package safety

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// SessionConfig configures a single live host Session or a multi-invocation Supervisor.
type SessionConfig struct {
	Policy     Policy
	RunID      string
	SessionID  string
	Recovery   RecoveryAdapter
	PriceTable *PriceTable
	Errors     *hostkit.ErrorState
	Now        func() time.Time
}

// Session manages a single live-mode host execution: it attests caller identity
// and target scope against the immutable Policy, opens the flock-leased Journal,
// initializes the CostMeter and LiveGuard, and runs a bounded LIFO Sweep on
// teardown.
type Session struct {
	pol      Policy
	meta     JournalMeta
	journal  *Journal
	meter    *CostMeter
	recovery RecoveryAdapter
	guard    *LiveGuard
	now      func() time.Time
}

// OpenSession validates cfg, attests the caller's live identity and scope,
// opens `<Policy.JournalDir>/<RunID>.jsonl` under an exclusive flock lease,
// restores any previously charged spend from the journal, and returns the
// active Session.
func OpenSession(ctx context.Context, cfg SessionConfig) (*Session, error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid live policy: %w", err)
	}
	if cfg.Recovery == nil {
		return nil, errors.New("live session requires a non-nil RecoveryAdapter")
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	runID := strings.TrimSpace(cfg.RunID)
	if runID == "" {
		runID = NewRunID(nowFn())
	}
	if err := ValidateRunID(runID); err != nil {
		return nil, err
	}
	sessID := strings.TrimSpace(cfg.SessionID)
	if sessID == "" {
		sessID = "sess-" + NewToken128()[:12]
	}

	// 1. Control-plane identity attestation and scope verification BEFORE opening
	// the journal or allowing any data-plane operation.
	ident, err := cfg.Recovery.AttestIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("live identity attestation failed: %w", err)
	}
	scope, err := cfg.Recovery.ResolveScope(ctx, "storage")
	if err != nil {
		return nil, fmt.Errorf("live scope resolution failed: %w", err)
	}
	if ident.Provider != scope.Provider || ident.Account != scope.Account {
		return nil, fmt.Errorf("attested identity (%s/%s) does not match resolved scope (%s/%s)",
			ident.Provider, ident.Account, scope.Provider, scope.Account)
	}
	if err := cfg.Policy.CheckScope(ident.Provider, ident.Account, scope.Scope, scope.Region); err != nil {
		return nil, fmt.Errorf("live policy scope rejection: %w", err)
	}
	if scope.Endpoint != "" {
		if err := cfg.Policy.CheckEndpoint("storage", scope.Endpoint); err != nil {
			return nil, fmt.Errorf("live policy endpoint rejection: %w", err)
		}
	}

	// 2. Load regional price table (fail closed if missing or stale).
	pt := cfg.PriceTable
	if pt == nil {
		var perr error
		pt, perr = LoadEmbeddedPriceTable(cfg.Policy.Provider, scope.Region, nowFn())
		if perr != nil {
			return nil, fmt.Errorf("load price table: %w", perr)
		}
	} else if err := pt.Validate(cfg.Policy.Provider, scope.Region, nowFn()); err != nil {
		return nil, fmt.Errorf("validate price table: %w", err)
	}

	meter, err := NewCostMeter(cfg.Policy.Cost, pt, cfg.Recovery)
	if err != nil {
		return nil, err
	}

	meta := JournalMeta{
		RunID:         runID,
		SessionID:     sessID,
		PolicyHash:    cfg.Policy.Hash(),
		Provider:      cfg.Policy.Provider,
		Account:       ident.Account,
		Tenant:        ident.Tenant,
		Scope:         scope.Scope,
		Region:        scope.Region,
		Endpoint:      scope.Endpoint,
		StartedAtUnix: nowFn().UTC().Unix(),
	}

	j, err := OpenJournal(cfg.Policy.JournalDir, meta)
	if err != nil {
		return nil, err
	}
	j.SetClock(nowFn)
	meta = j.Meta()

	st := j.State()
	restoreMeterFromState(meter, pt, st)

	guard, err := NewLiveGuard(GuardConfig{
		Policy:    cfg.Policy,
		Journal:   j,
		Meter:     meter,
		Recovery:  cfg.Recovery,
		Errors:    cfg.Errors,
		StartedAt: nowFn(),
		Now:       nowFn,
	})
	if err != nil {
		_ = j.Close()
		return nil, err
	}

	return &Session{
		pol:      cfg.Policy,
		meta:     meta,
		journal:  j,
		meter:    meter,
		recovery: cfg.Recovery,
		guard:    guard,
		now:      nowFn,
	}, nil
}

// RunID returns the session's run ID.
func (s *Session) RunID() string { return s.meta.RunID }

// Meta returns the session's JournalMeta.
func (s *Session) Meta() JournalMeta { return s.meta }

// Journal returns the active Journal.
func (s *Session) Journal() *Journal { return s.journal }

// Meter returns the active CostMeter.
func (s *Session) Meter() *CostMeter { return s.meter }

// Guard returns the active LiveGuard.
func (s *Session) Guard() *LiveGuard { return s.guard }

// WrapStore wraps an ObjectStore with the session's LiveGuard.
func (s *Session) WrapStore(store hostkit.ObjectStore) *GuardStore {
	return s.guard.WrapStore(store)
}

// WrapQueue wraps a Queue with the session's LiveGuard.
func (s *Session) WrapQueue(queue hostkit.Queue) *GuardQueue {
	return s.guard.WrapQueue(queue)
}

// Close releases the flock lease and closes the underlying journal without
// running a sweep (used between invocations in a multi-invocation campaign).
func (s *Session) Close() error {
	if s == nil || s.journal == nil {
		return nil
	}
	return s.journal.Close()
}

// FinishAndSweep executes an active LIFO recovery sweep bounded by
// Policy.Limits.MaxCleanupSeconds, compacts the journal, and closes the session.
func (s *Session) FinishAndSweep(ctx context.Context) (SweepReport, error) {
	if s == nil || s.journal == nil {
		return SweepReport{}, errors.New("session is closed")
	}
	cleanupDur := time.Duration(s.pol.Limits.MaxCleanupSeconds) * time.Second
	if cleanupDur <= 0 {
		cleanupDur = DefaultMaxCleanupSeconds * time.Second
	}
	sweepCtx, cancel := context.WithTimeout(ctx, cleanupDur)
	defer cancel()

	rep, sweepErr := Sweep(sweepCtx, s.recovery, SweepOptions{
		Journal:    s.journal,
		Policy:     &s.pol,
		Meter:      s.meter,
		Apply:      true,
		ScanPrefix: true,
		Now:        s.now,
	})
	closeErr := s.journal.Close()
	if sweepErr != nil {
		return rep, sweepErr
	}
	return rep, closeErr
}

// RestoreMeterFromState seeds meter with the cumulative ChargedNanoUSD and
// active/pending reservations replayed from st.
func RestoreMeterFromState(meter *CostMeter, pt *PriceTable, st LedgerState) {
	restoreMeterFromState(meter, pt, st)
}

func restoreMeterFromState(meter *CostMeter, pt *PriceTable, st LedgerState) {
	if meter == nil || pt == nil {
		return
	}
	chargedNano := st.ChargedNanoUSD
	var activeCleanupNano int64
	seenKeys := make(map[string]bool, len(st.Entries))
	for _, e := range st.Entries {
		if e.State != StateDeleted {
			seenKeys[e.Kind+"\x00"+e.Parent+"\x00"+e.Name] = true
		}
		var opName string
		switch e.Kind {
		case KindBucket:
			opName = "bucket_create"
		case KindQueue:
			opName = "queue_create"
		case KindObject:
			opName = "object_put"
		}
		opPrice := pt.Operations[opName]
		switch e.State {
		case StateConfirmed:
			activeCleanupNano += opPrice.CleanupReserveNanoUSD
		case StatePending:
			// LOW 12: Account for unresolved pending intent reservations after a crash
			// so subsequent work or recovery sweeps never undercount committed spend.
			// Explicit reservations are in st.PendingAttempts (and summed below);
			// fall back to base tariff only when no reservation was recorded.
			if e.ReservedNanoUSD == 0 {
				chargedNano += opPrice.RequestNanoUSD + opPrice.CleanupReserveNanoUSD
			}
			activeCleanupNano += opPrice.CleanupReserveNanoUSD
		}
	}
	for k, v := range st.ActiveCleanup {
		if !seenKeys[k] && v > 0 {
			activeCleanupNano += v
		}
	}
	for _, a := range st.PendingAttempts {
		if a.ReservedNanoUSD > 0 {
			chargedNano += a.ReservedNanoUSD
		}
	}
	meter.RestoreCharged(chargedNano, activeCleanupNano)
	if st.WorkCapNanoUSD > 0 {
		meter.RestoreWorkCap(st.WorkCapNanoUSD)
	}
}

// Supervisor coordinates a multi-invocation live campaign sharing a single
// RunID, SessionID, Policy, and journal file across sequential host invocations,
// and ensures deterministic pre-campaign and post-campaign LIFO sweeps.
type Supervisor struct {
	cfg SessionConfig
}

// NewSupervisor creates a campaign Supervisor and assigns a stable RunID and
// SessionID if not already set in cfg.
func NewSupervisor(cfg SessionConfig) (*Supervisor, error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, err
	}
	if cfg.Recovery == nil {
		return nil, errors.New("supervisor requires a non-nil RecoveryAdapter")
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	if strings.TrimSpace(cfg.RunID) == "" {
		cfg.RunID = NewRunID(nowFn())
	}
	if err := ValidateRunID(cfg.RunID); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.SessionID) == "" {
		cfg.SessionID = "sess-" + NewToken128()[:12]
	}
	return &Supervisor{cfg: cfg}, nil
}

// RunID returns the campaign's shared RunID.
func (s *Supervisor) RunID() string { return s.cfg.RunID }

// SessionID returns the campaign's shared SessionID.
func (s *Supervisor) SessionID() string { return s.cfg.SessionID }

// RunInvocation opens the shared campaign Session (acquiring the flock lease
// and replaying accumulated state and cost), executes fn, and closes the
// session's flock lease so the next invocation (or final campaign sweep) can
// proceed.
func (s *Supervisor) RunInvocation(ctx context.Context, fn func(ctx context.Context, sess *Session) error) error {
	sess, err := OpenSession(ctx, s.cfg)
	if err != nil {
		return err
	}
	defer sess.Close()
	if err := fn(ctx, sess); err != nil {
		return err
	}
	return sess.Close()
}

// FinishCampaign opens the campaign journal one final time, runs the LIFO
// ownership-verifying sweep, compacts the journal, and closes the lease.
func (s *Supervisor) FinishCampaign(ctx context.Context) (SweepReport, error) {
	sess, err := OpenSession(ctx, s.cfg)
	if err != nil {
		return SweepReport{}, err
	}
	return sess.FinishAndSweep(ctx)
}

// ListRunJournals returns the sorted list of `<run_id>.jsonl` run IDs found in journalDir.
func ListRunJournals(journalDir string) ([]string, error) {
	cleanDir, err := EnsureStateDir(journalDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(cleanDir)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", cleanDir, err)
	}
	var runIDs []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		runID := strings.TrimSuffix(e.Name(), ".jsonl")
		if ValidateRunID(runID) == nil {
			runIDs = append(runIDs, runID)
		}
	}
	sort.Strings(runIDs)
	return runIDs, nil
}

// SweepAllStale scans journalDir for any run journals with remaining active
// entries that are not currently locked by a live process, and runs Sweep on
// each one.
func SweepAllStale(ctx context.Context, journalDir string, policy *Policy, recovery RecoveryAdapter, apply bool) ([]SweepReport, error) {
	runIDs, err := ListRunJournals(journalDir)
	if err != nil {
		return nil, err
	}
	var reports []SweepReport
	for _, runID := range runIDs {
		path := filepath.Join(journalDir, runID+".jsonl")
		st, err := LoadJournal(path)
		if err != nil {
			return reports, err
		}
		hasActive := false
		for _, e := range st.Entries {
			if e.State == StatePending || e.State == StateConfirmed {
				hasActive = true
				break
			}
		}
		if !hasActive {
			continue
		}
		var meter *CostMeter
		pt, perr := LoadEmbeddedPriceTable(st.Meta.Provider, st.Meta.Region, time.Now().UTC())
		if perr != nil {
			if apply {
				return reports, fmt.Errorf("sweep stale journal %s: %w", runID, perr)
			}
		} else {
			var costPol CostPolicy
			if policy != nil {
				costPol = policy.Cost
			}
			costPol.applyDefaults()
			m, merr := NewCostMeter(costPol, pt, recovery)
			if merr != nil {
				if apply {
					return reports, fmt.Errorf("sweep stale journal %s: %w", runID, merr)
				}
			} else {
				restoreMeterFromState(m, pt, *st)
				meter = m
			}
		}
		rep, err := Sweep(ctx, recovery, SweepOptions{
			JournalDir: journalDir,
			RunID:      runID,
			Policy:     policy,
			Meter:      meter,
			Apply:      apply,
			ScanPrefix: true,
		})
		if errors.Is(err, ErrJournalLeaseBusy) {
			continue
		}
		if err != nil {
			return reports, err
		}
		reports = append(reports, rep)
	}
	return reports, nil
}
