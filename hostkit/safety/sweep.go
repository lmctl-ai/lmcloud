// SPDX-License-Identifier: MIT

package safety

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// DefaultPendingIntentGraceSeconds is the default grace period (10 seconds,
// matching the per-attempt cloud request timeout) before a StatePending intent
// that reads as absent is tombstoned as StateDeleted.
const DefaultPendingIntentGraceSeconds = 10

// SweepOptions configures a dry-run or active LIFO recovery sweep.
type SweepOptions struct {
	// JournalDir is the directory containing `<RunID>.jsonl` when Journal is nil.
	JournalDir string
	// RunID identifies the run journal to sweep when Journal is nil.
	RunID string
	// Journal is an already-open Journal (optional; if nil, Sweep opens or loads the journal).
	Journal *Journal
	// Policy optionally validates the journal's scope against the active live Policy.
	Policy *Policy
	// Meter optionally tracks and bounds cleanup request costs using the cleanup reserve.
	Meter *CostMeter
	// Apply must be true to perform deletions and mutate the journal; false (the
	// zero value) runs in dry-run mode.
	Apply bool
	// ScanPrefix also queries Recovery.FindOwned for any remaining resources
	// with this run's prefix and reports unowned siblings without deleting them.
	ScanPrefix bool
	// PollAttempts bounds how many times PollDelete is called per resource (default 5).
	PollAttempts int
	// PollInterval is the delay between PollDelete checks when > 1 attempt is needed.
	PollInterval time.Duration
	// PendingGraceSeconds overrides DefaultPendingIntentGraceSeconds when > 0.
	PendingGraceSeconds int
	// Now returns the current time for evaluating the pending-intent grace period.
	Now func() time.Time
}

// SweepItem describes the outcome of inspecting or sweeping one resource.
type SweepItem struct {
	Kind       string
	Parent     string
	Name       string
	ProviderID string
	Reason     string
}

// SweepReport summarizes the outcome of a Sweep invocation.
type SweepReport struct {
	RunID          string
	DryRun         bool
	WouldDelete    []SweepItem
	Deleted        []SweepItem
	Absent         []SweepItem
	Retained       []SweepItem
	UnownedSkipped []SweepItem
	Failed         []SweepItem
}

// Clean reports whether the sweep left zero failed items and zero pending
// un-swept items (in Apply mode).
func (r SweepReport) Clean() bool {
	return len(r.Failed) == 0
}

// Sweep executes a LIFO ownership-revalidating recovery pass over a run journal.
//
// Invariants:
//   - Dry-run by default (`opts.Apply == false`): makes zero DeleteOwned calls
//     and does not mutate the journal file.
//   - In Apply mode (`opts.Apply == true`), acquires the exclusive flock lease
//     on the journal file (unless opts.Journal is already open).
//   - Verifies caller identity and scope via Recovery.AttestIdentity and
//     Recovery.ResolveScope before touching any resource.
//   - Re-reads remote ownership tags immediately before every delete; any
//     resource with missing or mismatched RunID/OwnerNonce/CreateToken is
//     marked `retained` and NEVER deleted.
//   - Empties proven-owned child objects before deleting a proven-owned bucket,
//     and retains the bucket if any unexpected/unowned child object is present.
//   - Polls asynchronous deletions via PollDelete before writing a `deleted`
//     tombstone.
func Sweep(ctx context.Context, recovery RecoveryAdapter, opts SweepOptions) (SweepReport, error) {
	if recovery == nil {
		return SweepReport{}, errors.New("sweep requires a non-nil RecoveryAdapter")
	}
	pollAttempts := opts.PollAttempts
	if pollAttempts <= 0 {
		pollAttempts = 5
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	pendingGraceSec := int64(DefaultPendingIntentGraceSeconds)
	if opts.PendingGraceSeconds > 0 {
		pendingGraceSec = int64(opts.PendingGraceSeconds)
	}

	var (
		j     *Journal
		state LedgerState
	)

	if opts.Journal != nil {
		j = opts.Journal
		state = j.State()
	} else {
		path, err := JournalPath(opts.JournalDir, opts.RunID)
		if err != nil {
			return SweepReport{}, err
		}
		loaded, err := LoadJournal(path)
		if err != nil {
			return SweepReport{}, err
		}
		if opts.Apply {
			opened, err := OpenJournal(opts.JournalDir, loaded.Meta)
			if err != nil {
				return SweepReport{}, err
			}
			j = opened
			defer j.Close()
			state = j.State()
		} else {
			state = *loaded
		}
	}

	meta := state.Meta
	report := SweepReport{
		RunID:  meta.RunID,
		DryRun: !opts.Apply,
	}

	// 1. Attest caller identity and target scope against journal meta (and policy if supplied).
	ident, err := recovery.AttestIdentity(ctx)
	if err != nil {
		return report, fmt.Errorf("sweep identity attestation failed: %w", err)
	}
	if ident.Provider != meta.Provider || ident.Account != meta.Account {
		return report, fmt.Errorf("sweep attested identity (%s/%s) does not match journal meta (%s/%s)",
			ident.Provider, ident.Account, meta.Provider, meta.Account)
	}
	scope, err := recovery.ResolveScope(ctx, "storage")
	if err != nil {
		return report, fmt.Errorf("sweep scope resolution failed: %w", err)
	}
	if scope.Provider != meta.Provider || scope.Account != meta.Account || scope.Region != meta.Region || scope.Scope != meta.Scope {
		return report, fmt.Errorf("sweep resolved scope (%s/%s/%s/%s) does not match journal meta (%s/%s/%s/%s)",
			scope.Provider, scope.Account, scope.Scope, scope.Region,
			meta.Provider, meta.Account, meta.Scope, meta.Region)
	}
	if opts.Policy != nil {
		if err := opts.Policy.CheckScope(ident.Provider, ident.Account, scope.Scope, scope.Region); err != nil {
			return report, fmt.Errorf("sweep policy scope check failed: %w", err)
		}
	}

	sweptChildren := make(map[string]bool)

	// Helper to sweep a single entry.
	var sweepEntry func(entry LedgerEntry)
	sweepEntry = func(entry LedgerEntry) {
		key := resourceKey(entry.Kind, entry.Parent, entry.Name)
		if sweptChildren[key] {
			return
		}
		if entry.Retain || entry.State == StateRetained {
			report.Retained = append(report.Retained, SweepItem{
				Kind:       entry.Kind,
				Parent:     entry.Parent,
				Name:       entry.Name,
				ProviderID: entry.ProviderID,
				Reason:     nonEmptyReason(entry.Reason, "already marked retained in journal"),
			})
			return
		}

		ref := ResourceRef{
			Kind:       entry.Kind,
			Parent:     entry.Parent,
			Location:   nonEmptyReason(entry.Location, meta.Region),
			Name:       entry.Name,
			ProviderID: entry.ProviderID,
		}

		ro, readErr := recovery.ReadOwnership(ctx, ref)
		if (readErr == nil && !ro.Exists) || (readErr != nil && recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
			reason := "definitively absent"
			inGraceWindow := entry.State == StatePending &&
				entry.IntentAtUnix > 0 &&
				nowFn().UTC().Unix() < entry.IntentAtUnix+pendingGraceSec
			if inGraceWindow {
				reason = "definitively absent (within pending-intent grace period; keeping intent for re-check)"
			} else if opts.Apply && j != nil {
				_ = j.Deleted(entry.Kind, entry.Parent, entry.Name, 0)
			}
			report.Absent = append(report.Absent, SweepItem{
				Kind:       entry.Kind,
				Parent:     entry.Parent,
				Name:       entry.Name,
				ProviderID: entry.ProviderID,
				Reason:     reason,
			})
			sweptChildren[key] = true
			return
		}
		if readErr != nil {
			if recovery.ClassifyAbsent(readErr) == AbsenceAmbiguous {
				reason := "ambiguous absence/permission response: " + readErr.Error()
				if opts.Apply && j != nil {
					_ = j.Retain(entry.Kind, entry.Parent, entry.Name, reason)
				}
				report.Retained = append(report.Retained, SweepItem{
					Kind:       entry.Kind,
					Parent:     entry.Parent,
					Name:       entry.Name,
					ProviderID: entry.ProviderID,
					Reason:     reason,
				})
				return
			}
			report.Failed = append(report.Failed, SweepItem{
				Kind:       entry.Kind,
				Parent:     entry.Parent,
				Name:       entry.Name,
				ProviderID: entry.ProviderID,
				Reason:     "read ownership failed: " + readErr.Error(),
			})
			return
		}

		if verr := ro.VerifyMatchesEntry(entry, meta); verr != nil {
			reason := "ownership mismatch: " + verr.Error()
			if opts.Apply && j != nil {
				_ = j.Retain(entry.Kind, entry.Parent, entry.Name, reason)
			}
			report.Retained = append(report.Retained, SweepItem{
				Kind:       entry.Kind,
				Parent:     entry.Parent,
				Name:       entry.Name,
				ProviderID: ro.ProviderID,
				Reason:     reason,
			})
			return
		}

		// If this is a bucket, ReadOwnership MUST have verified child object listing
		// (ChildrenVerified == true). Any remaining ChildKeys must be proven-owned
		// and swept first, or the bucket is retained.
		if entry.Kind == KindBucket {
			if !ro.ChildrenVerified {
				reason := fmt.Sprintf("bucket %q child object listing was not verified by ReadOwnership", entry.Name)
				if opts.Apply && j != nil {
					_ = j.Retain(KindBucket, "", entry.Name, reason)
				}
				report.Retained = append(report.Retained, SweepItem{
					Kind:       KindBucket,
					Name:       entry.Name,
					ProviderID: ro.ProviderID,
					Reason:     reason,
				})
				return
			}
			if len(ro.ChildKeys) > 0 {
				for _, childKey := range ro.ChildKeys {
					cKey := resourceKey(KindObject, entry.Name, childKey)
					if sweptChildren[cKey] {
						continue
					}
					childEntry, ok := state.Lookup(KindObject, entry.Name, childKey)
					if !ok || childEntry.Retain || childEntry.State == StateRetained {
						reason := fmt.Sprintf("bucket %q contains unjournaled or retained child object %q", entry.Name, childKey)
						if opts.Apply && j != nil {
							_ = j.Retain(KindBucket, "", entry.Name, reason)
						}
						report.Retained = append(report.Retained, SweepItem{
							Kind:       KindBucket,
							Name:       entry.Name,
							ProviderID: ro.ProviderID,
							Reason:     reason,
						})
						return
					}
					sweepEntry(childEntry)
					if !sweptChildren[cKey] {
						reason := fmt.Sprintf("bucket %q child object %q could not be swept", entry.Name, childKey)
						if opts.Apply && j != nil {
							_ = j.Retain(KindBucket, "", entry.Name, reason)
						}
						report.Retained = append(report.Retained, SweepItem{
							Kind:       KindBucket,
							Name:       entry.Name,
							ProviderID: ro.ProviderID,
							Reason:     reason,
						})
						return
					}
				}
			}
		}

		if !opts.Apply {
			report.WouldDelete = append(report.WouldDelete, SweepItem{
				Kind:       entry.Kind,
				Parent:     entry.Parent,
				Name:       entry.Name,
				ProviderID: ro.ProviderID,
				Reason:     "ownership verified",
			})
			sweptChildren[key] = true
			return
		}

		var res *AttemptReservation
		if opts.Meter != nil {
			opName := deleteOpForKind(entry.Kind)
			if opName != "" {
				var rerr error
				res, rerr = opts.Meter.ReserveAttempt(AttemptPricingInput{
					Operation: opName,
					IsCleanup: true,
				})
				if rerr != nil {
					report.Failed = append(report.Failed, SweepItem{
						Kind:       entry.Kind,
						Parent:     entry.Parent,
						Name:       entry.Name,
						ProviderID: ro.ProviderID,
						Reason:     "cleanup cost reservation failed: " + rerr.Error(),
					})
					return
				}
			}
		}

		delErr := recovery.DeleteOwned(ctx, ref, ro)
		var charged int64
		if res != nil {
			charged = res.Commit(-1, false)
		}
		if delErr != nil && recovery.ClassifyAbsent(delErr) != AbsenceDefinitive {
			if recovery.ClassifyAbsent(delErr) == AbsenceAmbiguous {
				reason := "ambiguous delete response: " + delErr.Error()
				_ = j.Retain(entry.Kind, entry.Parent, entry.Name, reason)
				report.Retained = append(report.Retained, SweepItem{
					Kind:       entry.Kind,
					Parent:     entry.Parent,
					Name:       entry.Name,
					ProviderID: ro.ProviderID,
					Reason:     reason,
				})
				return
			}
			_ = j.RecordCost(entry.Kind, entry.Parent, entry.Name, "failed_sweep_delete", charged)
			report.Failed = append(report.Failed, SweepItem{
				Kind:       entry.Kind,
				Parent:     entry.Parent,
				Name:       entry.Name,
				ProviderID: ro.ProviderID,
				Reason:     "delete failed: " + delErr.Error(),
			})
			return
		}

		// Poll until the deletion has converged before writing the `deleted` tombstone.
		confirmedDeleted := false
		for attempt := 0; attempt < pollAttempts; attempt++ {
			done, pollErr := recovery.PollDelete(ctx, ref)
			if (pollErr == nil && done) || (pollErr != nil && recovery.ClassifyAbsent(pollErr) == AbsenceDefinitive) {
				confirmedDeleted = true
				break
			}
			if pollErr != nil && recovery.ClassifyAbsent(pollErr) == AbsenceAmbiguous {
				reason := "ambiguous poll-delete response: " + pollErr.Error()
				_ = j.Retain(entry.Kind, entry.Parent, entry.Name, reason)
				report.Retained = append(report.Retained, SweepItem{
					Kind:       entry.Kind,
					Parent:     entry.Parent,
					Name:       entry.Name,
					ProviderID: ro.ProviderID,
					Reason:     reason,
				})
				return
			}
			if attempt+1 < pollAttempts && opts.PollInterval > 0 {
				select {
				case <-ctx.Done():
					report.Failed = append(report.Failed, SweepItem{
						Kind:       entry.Kind,
						Parent:     entry.Parent,
						Name:       entry.Name,
						ProviderID: ro.ProviderID,
						Reason:     "context cancelled while polling delete: " + ctx.Err().Error(),
					})
					return
				case <-time.After(opts.PollInterval):
				}
			}
		}

		if !confirmedDeleted {
			_ = j.RecordCost(entry.Kind, entry.Parent, entry.Name, "pending_async_delete", charged)
			report.Failed = append(report.Failed, SweepItem{
				Kind:       entry.Kind,
				Parent:     entry.Parent,
				Name:       entry.Name,
				ProviderID: ro.ProviderID,
				Reason:     fmt.Sprintf("delete not yet converged after %d poll attempts", pollAttempts),
			})
			return
		}

		if err := j.Deleted(entry.Kind, entry.Parent, entry.Name, charged); err != nil {
			report.Failed = append(report.Failed, SweepItem{
				Kind:       entry.Kind,
				Parent:     entry.Parent,
				Name:       entry.Name,
				ProviderID: ro.ProviderID,
				Reason:     "write deleted tombstone failed: " + err.Error(),
			})
			return
		}
		report.Deleted = append(report.Deleted, SweepItem{
			Kind:       entry.Kind,
			Parent:     entry.Parent,
			Name:       entry.Name,
			ProviderID: ro.ProviderID,
			Reason:     "deleted and verified absent",
		})
		sweptChildren[key] = true
	}

	// 2. Sweep in LIFO order: first all child entries (objects/messages) in
	// reverse order, then all top-level entries (buckets/queues) in reverse order.
	for i := len(state.Entries) - 1; i >= 0; i-- {
		e := state.Entries[i]
		if e.Kind == KindObject || e.Kind == KindQueueMessage {
			sweepEntry(e)
		}
	}
	for i := len(state.Entries) - 1; i >= 0; i-- {
		e := state.Entries[i]
		if e.Kind != KindObject && e.Kind != KindQueueMessage {
			sweepEntry(e)
		}
	}

	// 3. Optional prefix scan: identify any remaining prefix-matching resources
	// on the provider and refuse to delete any unowned sibling.
	if opts.ScanPrefix {
		pfx, err := ExpectedLivePrefix(meta.RunID)
		if err != nil {
			report.Failed = append(report.Failed, SweepItem{
				Kind:   "prefix_scan",
				Name:   meta.RunID,
				Reason: "compute expected live prefix failed: " + err.Error(),
			})
		} else {
			found, ferr := recovery.FindOwned(ctx, pfx)
			if ferr != nil {
				report.Failed = append(report.Failed, SweepItem{
					Kind:   "prefix_scan",
					Name:   pfx,
					Reason: "FindOwned failed: " + ferr.Error(),
				})
			} else {
				for _, ref := range found {
					key := resourceKey(ref.Kind, ref.Parent, ref.Name)
					if sweptChildren[key] {
						continue
					}
					if _, inJournal := state.Lookup(ref.Kind, ref.Parent, ref.Name); !inJournal {
						report.UnownedSkipped = append(report.UnownedSkipped, SweepItem{
							Kind:       ref.Kind,
							Parent:     ref.Parent,
							Name:       ref.Name,
							ProviderID: ref.ProviderID,
							Reason:     "not present in run journal; refusing to delete unowned sibling",
						})
					}
				}
			}
		}
	}

	if opts.Apply && j != nil {
		if err := j.Compact(); err != nil {
			return report, fmt.Errorf("compact journal after sweep: %w", err)
		}
	}

	return report, nil
}

func deleteOpForKind(kind string) string {
	switch kind {
	case KindBucket:
		return "bucket_delete"
	case KindObject:
		return "object_delete"
	case KindQueue:
		return "queue_delete"
	case KindQueueMessage:
		return "queue_ack"
	default:
		return ""
	}
}

func nonEmptyReason(a, fallback string) string {
	if a != "" {
		return a
	}
	return fallback
}
