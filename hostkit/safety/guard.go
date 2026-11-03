// SPDX-License-Identifier: MIT

package safety

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// GuardConfig configures a LiveGuard wrapping an ObjectStore and/or Queue.
type GuardConfig struct {
	Policy    Policy
	Journal   *Journal
	Meter     *CostMeter
	Recovery  RecoveryAdapter
	Errors    *hostkit.ErrorState
	StartedAt time.Time
	Now       func() time.Time
}

// LiveGuard enforces live policy limits, cost reservations, durable
// intent-before-create journaling, remote ownership verification, parent
// ownership checks, and create-token redaction across an ObjectStore and Queue.
type LiveGuard struct {
	pol       Policy
	journal   *Journal
	meter     *CostMeter
	recovery  RecoveryAdapter
	errors    *hostkit.ErrorState
	startedAt time.Time
	now       func() time.Time

	mu          sync.Mutex
	bucketsMade int
	queuesMade  int
	objectsMade int
	msgsSent    int
	totalBytes  int64
}

// NewLiveGuard creates a LiveGuard and seeds its counters from the journal's
// current replayed state.
func NewLiveGuard(cfg GuardConfig) (*LiveGuard, error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy for LiveGuard: %w", err)
	}
	if cfg.Journal == nil {
		return nil, errors.New("LiveGuard requires a non-nil Journal")
	}
	if cfg.Meter == nil {
		return nil, errors.New("LiveGuard requires a non-nil CostMeter")
	}
	if cfg.Recovery == nil {
		return nil, errors.New("LiveGuard requires a non-nil RecoveryAdapter")
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	st := cfg.Journal.State()
	started := cfg.StartedAt
	if st.StartedAtUnix > 0 {
		started = time.Unix(st.StartedAtUnix, 0).UTC()
	} else if started.IsZero() {
		started = nowFn()
	}
	g := &LiveGuard{
		pol:         cfg.Policy,
		journal:     cfg.Journal,
		meter:       cfg.Meter,
		recovery:    cfg.Recovery,
		errors:      cfg.Errors,
		startedAt:   started,
		now:         nowFn,
		bucketsMade: st.BucketsCreated,
		queuesMade:  st.QueuesCreated,
		objectsMade: st.ObjectsCreated,
		msgsSent:    st.MessagesSent,
		totalBytes:  st.TotalPayloadBytes,
	}

	for _, e := range st.Entries {
		g.registerRedactions(e.OwnerNonce, e.CreateToken)
	}
	return g, nil
}

func journalWriteErr(err error) *hostkit.CloudError {
	if err == nil {
		return nil
	}
	return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
}

func (g *LiveGuard) registerRedactions(tokens ...string) {
	if g.errors == nil {
		return
	}
	for _, tok := range tokens {
		if tok != "" {
			g.errors.AddRedaction(tok)
		}
	}
}

func (g *LiveGuard) withRequestTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(DefaultMaxRequestTimeoutSeconds)*time.Second)
}

func readOwnershipOpForKind(kind string) string {
	switch kind {
	case KindBucket:
		return "bucket_read_ownership"
	case KindQueue:
		return "queue_read_ownership"
	case KindObject:
		return "object_head"
	default:
		return "bucket_read_ownership"
	}
}

func (g *LiveGuard) readOwnershipMetered(ctx context.Context, ref ResourceRef, isCleanup bool, reason string) (RemoteOwnership, error, *hostkit.CloudError) {
	op := readOwnershipOpForKind(ref.Kind)
	res, cerr := g.reserveOp(AttemptPricingInput{Operation: op, IsCleanup: isCleanup})
	if cerr != nil {
		return RemoteOwnership{}, nil, cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(g.journal.RecordCost(ref.Kind, ref.Parent, ref.Name, reason, charged)); jerr != nil {
		return RemoteOwnership{}, nil, jerr
	}
	reqCtx, cancel := g.withRequestTimeout(ctx)
	defer cancel()
	ro, err := g.recovery.ReadOwnership(reqCtx, ref)
	return ro, err, nil
}

func (g *LiveGuard) checkWallClock() *hostkit.CloudError {
	if err := g.journal.CheckHealth(); err != nil {
		return journalWriteErr(err)
	}
	maxDur := time.Duration(g.pol.Limits.MaxRunSeconds) * time.Second
	if maxDur > 0 && g.now().Sub(g.startedAt) > maxDur {
		return hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveRunDeadlineExceeded",
			fmt.Sprintf("live run exceeded max_run_seconds (%ds)", g.pol.Limits.MaxRunSeconds),
		)
	}
	return nil
}

func (g *LiveGuard) requireMutationsAllowed(op string) *hostkit.CloudError {
	if cerr := g.checkWallClock(); cerr != nil {
		return cerr
	}
	if !g.pol.AllowMutations {
		return hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveMutationDisabled",
			fmt.Sprintf("%s refused: policy allow_mutations is false", op),
		)
	}
	return nil
}

func (g *LiveGuard) reserveOp(in AttemptPricingInput) (*AttemptReservation, *hostkit.CloudError) {
	if cerr := g.checkWallClock(); cerr != nil {
		return nil, cerr
	}
	res, err := g.meter.ReserveAttempt(in)
	if err != nil {
		code := hostkit.PermissionDenied
		pcode := "LiveCostCapExceeded"
		if !errors.Is(err, ErrCostCapExceeded) {
			code = hostkit.Internal
			pcode = "LivePricingFailure"
		}
		return nil, hostkit.ProviderError(code, 0, pcode, err.Error())
	}
	return res, nil
}

func (g *LiveGuard) verifyOwnedParent(ctx context.Context, parentKind, parentName string, absentKind hostkit.Absence, isCleanup bool) (LedgerEntry, *hostkit.CloudError) {
	if cerr := g.checkWallClock(); cerr != nil {
		return LedgerEntry{}, cerr
	}
	meta := g.journal.Meta()
	if err := ValidateLiveResourceName(meta.RunID, parentName); err != nil {
		return LedgerEntry{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"UnownedParentResource",
			fmt.Sprintf("refusing operation on unowned %s %q: %v", parentKind, parentName, err),
		)
	}
	entry, ok := g.journal.Lookup(parentKind, "", parentName)
	if ok && (entry.Retain || entry.State == StateRetained) {
		return LedgerEntry{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"UnownedParentResource",
			fmt.Sprintf("%s %q is marked retained in journal (%s)", parentKind, parentName, nonEmptyReason(entry.Reason, "retained")),
		)
	}

	ref := ResourceRef{
		Kind:     parentKind,
		Location: meta.Region,
		Name:     parentName,
	}
	if ok {
		ref.ProviderID = entry.ProviderID
	}
	ro, err, cerr := g.readOwnershipMetered(ctx, ref, isCleanup, "verify_parent_ownership")
	if cerr != nil {
		return LedgerEntry{}, cerr
	}
	if (err == nil && !ro.Exists) || (err != nil && g.recovery.ClassifyAbsent(err) == AbsenceDefinitive) {
		return LedgerEntry{}, hostkit.ProviderError(
			hostkit.NotFound,
			404,
			"NotFound",
			fmt.Sprintf("%s %q does not exist", parentKind, parentName),
		).WithAbsent(absentKind)
	}
	if !ok || entry.State != StateConfirmed {
		return LedgerEntry{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"UnownedParentResource",
			fmt.Sprintf("%s %q is not a confirmed resource of run %s", parentKind, parentName, meta.RunID),
		)
	}
	if err != nil {
		if g.recovery.ClassifyAbsent(err) == AbsenceAmbiguous {
			if jerr := journalWriteErr(g.journal.Retain(parentKind, "", parentName, "ambiguous parent ownership probe: "+err.Error())); jerr != nil {
				return LedgerEntry{}, jerr
			}
		}
		return LedgerEntry{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"ParentOwnershipVerificationFailed",
			fmt.Sprintf("failed to verify ownership of %s %q: %v", parentKind, parentName, err),
		)
	}
	if verr := ro.VerifyMatchesEntry(entry, meta); verr != nil {
		if jerr := journalWriteErr(g.journal.Retain(parentKind, "", parentName, "parent ownership mismatch: "+verr.Error())); jerr != nil {
			return LedgerEntry{}, jerr
		}
		return LedgerEntry{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"ParentOwnershipMismatch",
			fmt.Sprintf("%s %q failed remote ownership verification: %v", parentKind, parentName, verr),
		)
	}
	if entry.ProviderID != "" && ro.ProviderID != "" && ro.ProviderID != entry.ProviderID {
		reason := fmt.Sprintf("parent provider_id changed from %q to %q", entry.ProviderID, ro.ProviderID)
		if jerr := journalWriteErr(g.journal.Retain(parentKind, "", parentName, reason)); jerr != nil {
			return LedgerEntry{}, jerr
		}
		return LedgerEntry{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"ParentOwnershipMismatch",
			reason,
		)
	}
	return entry, nil
}

// WrapStore wraps an ObjectStore with live safety guards.
func (g *LiveGuard) WrapStore(store hostkit.ObjectStore) *GuardStore {
	return &GuardStore{guard: g, store: store}
}

// WrapQueue wraps a Queue with live safety guards.
func (g *LiveGuard) WrapQueue(queue hostkit.Queue) *GuardQueue {
	return &GuardQueue{guard: g, queue: queue}
}

// GuardStore wraps a hostkit.ObjectStore so every mutation goes through
// policy validation, cost reservation, fsynced journal intent, remote ownership
// verification, and journal confirmation.
type GuardStore struct {
	guard *LiveGuard
	store hostkit.ObjectStore
}

func (s *GuardStore) CreateBucket(ctx context.Context, bucket string) (bool, error) {
	g := s.guard
	if cerr := g.requireMutationsAllowed("bucket_create"); cerr != nil {
		return false, cerr
	}
	meta := g.journal.Meta()
	if err := ValidateLiveResourceName(meta.RunID, bucket); err != nil {
		return false, hostkit.ProviderError(hostkit.PermissionDenied, 0, "InvalidLiveResourceName", err.Error())
	}

	g.mu.Lock()
	existing, hasExisting := g.journal.Lookup(KindBucket, "", bucket)
	if hasExisting && (existing.State == StateRetained || existing.Retain) {
		g.mu.Unlock()
		return false, hostkit.ProviderError(
			hostkit.Conflict,
			409,
			"ForeignResourceCollision",
			nonEmptyReason(existing.Reason, "bucket is marked retained in journal"),
		)
	}
	if !hasExisting && g.bucketsMade >= g.pol.Limits.MaxBuckets {
		g.mu.Unlock()
		return false, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("max_buckets limit (%d) reached", g.pol.Limits.MaxBuckets),
		)
	}
	g.mu.Unlock()

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "bucket_create"})
	if cerr != nil {
		return false, cerr
	}
	reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD

	intent, err := g.journal.BeginCreate(KindBucket, "", meta.Region, bucket, reservedNano)
	if err != nil {
		res.Commit(0, false)
		return false, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
	}
	g.registerRedactions(intent.OwnerNonce, intent.CreateToken)

	if intent.AlreadyConfirmed {
		if existing.State == StateRetained || existing.Retain {
			res.Commit(0, false)
			return false, hostkit.ProviderError(
				hostkit.Conflict,
				409,
				"ForeignResourceCollision",
				nonEmptyReason(existing.Reason, "bucket is marked retained in journal"),
			)
		}
		if existing.State == StateConfirmed {
			// Already confirmed in this run: verify remote ownership is still intact
			// and return created=false without overwriting tokens.
			ro, rerr, rcerr := g.readOwnershipMetered(ctx, ResourceRef{
				Kind:       KindBucket,
				Location:   meta.Region,
				Name:       bucket,
				ProviderID: existing.ProviderID,
			}, false, "duplicate_bucket_create_check")
			charged := res.Commit(-1, false)
			if rcerr != nil {
				return false, rcerr
			}
			if jerr := journalWriteErr(g.journal.RecordCost(KindBucket, "", bucket, "duplicate_bucket_create", charged)); jerr != nil {
				return false, jerr
			}
			if rerr != nil {
				return false, hostkit.AsCloudError(rerr)
			}
			if !ro.Exists {
				if jerr := journalWriteErr(g.journal.Retain(KindBucket, "", bucket, "confirmed bucket disappeared remotely")); jerr != nil {
					return false, jerr
				}
				return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", "confirmed bucket no longer exists remotely")
			}
			if verr := ro.VerifyMatchesEntry(existing, meta); verr != nil {
				if jerr := journalWriteErr(g.journal.Retain(KindBucket, "", bucket, verr.Error())); jerr != nil {
					return false, jerr
				}
				return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", verr.Error())
			}
			return false, nil
		}
	}

	pendingEntry := LedgerEntry{
		Kind:         KindBucket,
		Location:     meta.Region,
		Name:         bucket,
		OwnerNonce:   intent.OwnerNonce,
		CreateToken:  intent.CreateToken,
		IntentAtUnix: intent.IntentAtUnix,
		State:        StatePending,
	}

	// Prove absence (or prior pending convergence in this run) BEFORE dispatching
	// CreateBucket so an adapter that tags on duplicate create can never overwrite
	// a pre-existing foreign or untagged bucket's tags.
	preRO, preErr, preCerr := g.readOwnershipMetered(ctx, ResourceRef{
		Kind:     KindBucket,
		Location: meta.Region,
		Name:     bucket,
	}, false, "pre_create_bucket_check")
	if preCerr != nil {
		res.Commit(0, false)
		return false, preCerr
	}
	if preErr == nil && preRO.Exists {
		if hasExisting && existing.State == StatePending && preRO.VerifyMatchesEntry(pendingEntry, meta) == nil {
			charged := res.Commit(-1, true)
			if err := g.journal.Confirm(KindBucket, "", bucket, ConfirmDetails{
				ProviderID:          preRO.ProviderID,
				Location:            preRO.Location,
				ETag:                preRO.ETag,
				Generation:          preRO.Generation,
				ConfirmedAtUnix:     g.now().UTC().Unix(),
				ServerCreatedAtUnix: preRO.CreatedAtUnix,
				ChargedNanoUSD:      charged,
			}); err != nil {
				return false, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			}
			g.mu.Lock()
			g.bucketsMade++
			g.mu.Unlock()
			return true, nil
		}
		verr := preRO.VerifyMatchesEntry(pendingEntry, meta)
		reason := "pre-existing foreign or untagged bucket collision"
		if verr != nil {
			reason = "pre-existing foreign or untagged bucket collision: " + verr.Error()
		}
		charged := res.Commit(-1, false)
		if jerr := journalWriteErr(g.journal.Retain(KindBucket, "", bucket, reason)); jerr != nil {
			return false, jerr
		}
		if jerr := journalWriteErr(g.journal.RecordCost(KindBucket, "", bucket, "foreign_or_untagged_bucket_collision", charged)); jerr != nil {
			return false, jerr
		}
		return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", reason)
	}
	if preErr != nil && g.recovery.ClassifyAbsent(preErr) != AbsenceDefinitive {
		charged := res.Commit(-1, false)
		reason := "ambiguous pre-create bucket ownership probe: " + preErr.Error()
		if jerr := journalWriteErr(g.journal.Retain(KindBucket, "", bucket, reason)); jerr != nil {
			return false, jerr
		}
		if jerr := journalWriteErr(g.journal.RecordCost(KindBucket, "", bucket, "ambiguous_pre_create_bucket", charged)); jerr != nil {
			return false, jerr
		}
		return false, hostkit.ProviderError(hostkit.PermissionDenied, 0, "AmbiguousPreCreateProbe", reason)
	}

	ctxWithTags := WithOwnershipTags(ctx, OwnershipTags{
		RunID:         meta.RunID,
		OwnerNonce:    intent.OwnerNonce,
		CreateToken:   intent.CreateToken,
		CreatedAtUnix: intent.IntentAtUnix,
	})
	reqCtx, cancel := g.withRequestTimeout(ctxWithTags)
	created, callErr := s.store.CreateBucket(reqCtx, bucket)
	cancel()
	callErr = hostkit.NilIfTyped(callErr)

	// Always read back remote ownership to verify whether the bucket now exists
	// and carries our RunID + OwnerNonce.
	ro, readErr, rcerr := g.readOwnershipMetered(ctxWithTags, ResourceRef{
		Kind:     KindBucket,
		Location: meta.Region,
		Name:     bucket,
	}, false, "post_create_bucket_check")
	if rcerr != nil {
		res.Commit(-1, true)
		return false, rcerr
	}

	if readErr == nil && ro.Exists {
		if verr := ro.VerifyMatchesEntry(pendingEntry, meta); verr != nil {
			// A foreign or untagged resource with the same name exists!
			// Record as Retain (not Failed) so repeat creates in this run never
			// adopt or overwrite its tags and so any untagged bucket created before
			// a tagging failure remains visible in the journal and sweep report.
			charged := res.Commit(-1, false)
			if jerr := journalWriteErr(g.journal.Retain(KindBucket, "", bucket, "foreign or untagged collision: "+verr.Error())); jerr != nil {
				return false, jerr
			}
			if jerr := journalWriteErr(g.journal.RecordCost(KindBucket, "", bucket, "foreign_or_untagged_bucket_collision", charged)); jerr != nil {
				return false, jerr
			}
			return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", verr.Error())
		}
		if callErr == nil {
			charged := res.Commit(-1, true)
			if err := g.journal.Confirm(KindBucket, "", bucket, ConfirmDetails{
				ProviderID:          ro.ProviderID,
				Location:            ro.Location,
				ETag:                ro.ETag,
				Generation:          ro.Generation,
				ConfirmedAtUnix:     g.now().UTC().Unix(),
				ServerCreatedAtUnix: ro.CreatedAtUnix,
				ChargedNanoUSD:      charged,
			}); err != nil {
				return false, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			}
			g.mu.Lock()
			if !hasExisting {
				g.bucketsMade++
			}
			g.mu.Unlock()
			if ro.CreateToken != "" && ro.CreateToken == intent.CreateToken {
				return true, nil
			}
			return created, nil
		}
	}

	if callErr != nil {
		if (readErr == nil && !ro.Exists) || (readErr != nil && g.recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
			charged := res.Commit(-1, false)
			if jerr := journalWriteErr(g.journal.Failed(KindBucket, "", bucket, callErr.Error(), charged)); jerr != nil {
				return false, jerr
			}
		} else {
			// Ambiguous outcome: keep intent + cleanup reserve in journal for recovery.
			charged := res.Commit(-1, true)
			if jerr := journalWriteErr(g.journal.RecordCost(KindBucket, "", bucket, "ambiguous_bucket_create", charged)); jerr != nil {
				return false, jerr
			}
		}
		return false, callErr
	}

	// Adapter reported success, but ReadOwnership could not verify our tags!
	charged := res.Commit(-1, true)
	if jerr := journalWriteErr(g.journal.Retain(KindBucket, "", bucket, "post-create ownership verification failed")); jerr != nil {
		return false, jerr
	}
	if jerr := journalWriteErr(g.journal.RecordCost(KindBucket, "", bucket, "unverified_bucket_create", charged)); jerr != nil {
		return false, jerr
	}
	if readErr != nil {
		return false, hostkit.ProviderError(hostkit.Internal, 0, "OwnershipVerificationFailed", readErr.Error())
	}
	return false, hostkit.ProviderError(hostkit.Internal, 0, "OwnershipVerificationFailed", "created bucket was not visible to ReadOwnership")
}

func (s *GuardStore) DeleteBucket(ctx context.Context, bucket string) error {
	g := s.guard
	if cerr := g.requireMutationsAllowed("bucket_delete"); cerr != nil {
		return cerr
	}
	meta := g.journal.Meta()
	if err := ValidateLiveResourceName(meta.RunID, bucket); err != nil {
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "UnownedResourceDeleteRefused", err.Error())
	}

	entry, ok := g.journal.Lookup(KindBucket, "", bucket)
	if ok && (entry.Retain || entry.State == StateRetained) {
		return hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"RetainedResourceDeleteRefused",
			fmt.Sprintf("refusing to delete retained bucket %q: %s", bucket, nonEmptyReason(entry.Reason, "marked retained in journal")),
		)
	}
	ref := ResourceRef{Kind: KindBucket, Location: meta.Region, Name: bucket}
	if ok {
		ref.ProviderID = entry.ProviderID
	}

	listRes, lcerr := g.reserveOp(AttemptPricingInput{Operation: "object_list", IsCleanup: true})
	if lcerr != nil {
		return lcerr
	}
	listCharged := listRes.Commit(-1, false)
	if jerr := journalWriteErr(g.journal.RecordCost(KindBucket, "", bucket, "pre_delete_bucket_list_children", listCharged)); jerr != nil {
		return jerr
	}
	ro, readErr, rcerr := g.readOwnershipMetered(ctx, ref, true, "pre_delete_bucket_check")
	if rcerr != nil {
		return rcerr
	}
	if (readErr == nil && !ro.Exists) || (readErr != nil && g.recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
		if ok {
			if jerr := journalWriteErr(g.journal.Deleted(KindBucket, "", bucket, 0)); jerr != nil {
				return jerr
			}
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["bucket_create"].CleanupReserveNanoUSD)
		}
		return hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket does not exist").WithAbsent(hostkit.AbsentBucket)
	}
	if readErr != nil {
		return hostkit.AsCloudError(readErr)
	}
	if !ok {
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "UnownedResourceDeleteRefused",
			fmt.Sprintf("bucket %q is not tracked in journal %s", bucket, meta.RunID))
	}
	if verr := ro.VerifyMatchesEntry(entry, meta); verr != nil {
		if jerr := journalWriteErr(g.journal.Retain(KindBucket, "", bucket, verr.Error())); jerr != nil {
			return jerr
		}
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "OwnershipMismatch", verr.Error())
	}
	if !ro.ChildrenVerified {
		if jerr := journalWriteErr(g.journal.Retain(KindBucket, "", bucket, "bucket child listing was not verified by ReadOwnership")); jerr != nil {
			return jerr
		}
		return hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"ChildListingRequired",
			fmt.Sprintf("refusing to delete bucket %q: ReadOwnership did not verify child object listing", bucket),
		)
	}
	if len(ro.ChildKeys) > 0 {
		return hostkit.ProviderError(
			hostkit.Conflict,
			409,
			"BucketNotEmpty",
			fmt.Sprintf("bucket %q is not empty (%d child object(s) present)", bucket, len(ro.ChildKeys)),
		)
	}

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "bucket_delete", IsCleanup: true})
	if cerr != nil {
		return cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(g.journal.RecordCost(KindBucket, "", bucket, "bucket_delete", charged)); jerr != nil {
		return jerr
	}
	reqCtx, cancel := g.withRequestTimeout(ctx)
	err := hostkit.NilIfTyped(s.store.DeleteBucket(reqCtx, bucket))
	cancel()
	if err != nil {
		if g.recovery.ClassifyAbsent(err) == AbsenceDefinitive {
			if jerr := journalWriteErr(g.journal.Deleted(KindBucket, "", bucket, 0)); jerr != nil {
				return jerr
			}
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["bucket_create"].CleanupReserveNanoUSD)
		}
		return err
	}
	if err := g.journal.Deleted(KindBucket, "", bucket, 0); err != nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
	}
	g.meter.ReleaseResourceCleanup(g.meter.table.Operations["bucket_create"].CleanupReserveNanoUSD)
	return nil
}

func (s *GuardStore) HeadBucket(ctx context.Context, bucket string) error {
	res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "bucket_exists"})
	if cerr != nil {
		return cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(s.guard.journal.RecordCost(KindBucket, "", bucket, "bucket_exists", charged)); jerr != nil {
		return jerr
	}
	reqCtx, cancel := s.guard.withRequestTimeout(ctx)
	defer cancel()
	return hostkit.NilIfTyped(s.store.HeadBucket(reqCtx, bucket))
}

func (s *GuardStore) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "bucket_list"})
	if cerr != nil {
		return nil, "", cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(s.guard.journal.RecordCost(KindBucket, "", "", "bucket_list", charged)); jerr != nil {
		return nil, "", jerr
	}
	reqCtx, cancel := s.guard.withRequestTimeout(ctx)
	defer cancel()
	names, next, err := s.store.ListBuckets(reqCtx, token)
	return names, next, hostkit.NilIfTyped(err)
}

func (s *GuardStore) PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (hostkit.ObjectMeta, error) {
	g := s.guard
	if cerr := g.requireMutationsAllowed("object_put"); cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindBucket, bucket, hostkit.AbsentBucket, false); cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}

	sz := int64(len(body))
	if sz > g.pol.Limits.MaxObjectBytes {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("object size %d exceeds max_object_bytes (%d)", sz, g.pol.Limits.MaxObjectBytes),
		)
	}

	g.mu.Lock()
	existingObj, hasObj := g.journal.Lookup(KindObject, bucket, key)
	if hasObj && (existingObj.Retain || existingObj.State == StateRetained) {
		g.mu.Unlock()
		return hostkit.ObjectMeta{}, hostkit.ProviderError(
			hostkit.Conflict,
			409,
			"ForeignResourceCollision",
			nonEmptyReason(existingObj.Reason, "object is marked retained in journal"),
		)
	}
	if !hasObj && g.objectsMade >= g.pol.Limits.MaxObjects {
		g.mu.Unlock()
		return hostkit.ObjectMeta{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("max_objects limit (%d) reached", g.pol.Limits.MaxObjects),
		)
	}
	if g.totalBytes+sz > g.pol.Limits.MaxTotalBytes {
		g.mu.Unlock()
		return hostkit.ObjectMeta{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("total payload bytes %d would exceed max_total_bytes (%d)", g.totalBytes+sz, g.pol.Limits.MaxTotalBytes),
		)
	}
	g.mu.Unlock()

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "object_put", PayloadSize: sz})
	if cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}
	reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD

	jMeta := g.journal.Meta()
	intent, err := g.journal.BeginCreateWithBytes(KindObject, bucket, jMeta.Region, key, reservedNano, sz)
	if err != nil {
		res.Commit(0, false)
		return hostkit.ObjectMeta{}, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
	}
	g.registerRedactions(intent.OwnerNonce, intent.CreateToken)
	g.mu.Lock()
	if !hasObj {
		g.objectsMade++
	}
	g.totalBytes += sz
	g.mu.Unlock()

	tags := OwnershipTags{
		RunID:         jMeta.RunID,
		OwnerNonce:    intent.OwnerNonce,
		CreateToken:   intent.CreateToken,
		CreatedAtUnix: intent.IntentAtUnix,
	}
	mergedMeta := make(map[string]string, len(metadata)+4)
	maps.Copy(mergedMeta, metadata)
	maps.Copy(mergedMeta, tags.Map())

	ctxWithTags := WithOwnershipTags(ctx, tags)
	reqCtx, cancel := g.withRequestTimeout(ctxWithTags)
	om, callErr := s.store.PutObject(reqCtx, bucket, key, body, contentType, mergedMeta)
	cancel()
	callErr = hostkit.NilIfTyped(callErr)
	if callErr != nil {
		ro, rerr, rcerr := g.readOwnershipMetered(ctxWithTags, ResourceRef{
			Kind:     KindObject,
			Parent:   bucket,
			Location: jMeta.Region,
			Name:     key,
		}, false, "post_failed_object_put_check")
		if rcerr != nil {
			res.Commit(-1, true)
			return hostkit.ObjectMeta{}, rcerr
		}
		if (rerr == nil && !ro.Exists) || (rerr != nil && g.recovery.ClassifyAbsent(rerr) == AbsenceDefinitive) {
			charged := res.Commit(-1, false)
			g.mu.Lock()
			if !hasObj && g.objectsMade > 0 {
				g.objectsMade--
			}
			g.totalBytes -= sz
			if g.totalBytes < 0 {
				g.totalBytes = 0
			}
			g.mu.Unlock()
			if jerr := journalWriteErr(g.journal.Failed(KindObject, bucket, key, callErr.Error(), charged)); jerr != nil {
				return hostkit.ObjectMeta{}, jerr
			}
		} else {
			charged := res.Commit(-1, true)
			if jerr := journalWriteErr(g.journal.RecordCost(KindObject, bucket, key, "ambiguous_object_put", charged)); jerr != nil {
				return hostkit.ObjectMeta{}, jerr
			}
		}
		return hostkit.ObjectMeta{}, callErr
	}

	charged := res.Commit(-1, !hasObj)
	if err := g.journal.Confirm(KindObject, bucket, key, ConfirmDetails{
		Location:        jMeta.Region,
		ETag:            om.ETag,
		ConfirmedAtUnix: g.now().UTC().Unix(),
		ChargedNanoUSD:  charged,
	}); err != nil {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
	}
	return om, nil
}

func (s *GuardStore) GetObject(ctx context.Context, bucket, key string, limit int64) ([]byte, error) {
	maxBytes := s.guard.pol.Limits.MaxObjectBytes
	clampedLimit := limit
	if clampedLimit <= 0 || (maxBytes > 0 && clampedLimit > maxBytes) {
		clampedLimit = maxBytes
	}
	res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "object_get", EgressBytes: clampedLimit})
	if cerr != nil {
		return nil, cerr
	}
	baseQuote, qerr := s.guard.meter.QuoteAttempt(AttemptPricingInput{Operation: "object_get", EgressBytes: 0})
	baseNano := int64(0)
	if qerr == nil {
		baseNano = baseQuote.AttemptNanoUSD
	}
	if jerr := journalWriteErr(s.guard.journal.RecordCost(KindObject, bucket, key, "object_get_request", baseNano)); jerr != nil {
		res.Commit(0, false)
		return nil, jerr
	}
	reqCtx, cancel := s.guard.withRequestTimeout(ctx)
	body, err := s.store.GetObject(reqCtx, bucket, key, clampedLimit)
	cancel()
	err = hostkit.NilIfTyped(err)
	if err == nil && maxBytes > 0 && int64(len(body)) > maxBytes {
		err = hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("downloaded object size %d exceeds max_object_bytes (%d)", len(body), maxBytes),
		)
		body = nil
	}
	actualQuote, qerr := s.guard.meter.QuoteAttempt(AttemptPricingInput{
		Operation:   "object_get",
		EgressBytes: int64(len(body)),
	})
	actualNano := int64(-1)
	if qerr == nil {
		actualNano = actualQuote.AttemptNanoUSD
	}
	charged := res.Commit(actualNano, false)
	egressDelta := charged - baseNano
	if egressDelta > 0 {
		if jerr := journalWriteErr(s.guard.journal.RecordCost(KindObject, bucket, key, "object_get_egress", egressDelta)); jerr != nil && err == nil {
			return nil, jerr
		}
	}
	return body, err
}

func (s *GuardStore) HeadObject(ctx context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "object_head"})
	if cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(s.guard.journal.RecordCost(KindObject, bucket, key, "object_head", charged)); jerr != nil {
		return hostkit.ObjectMeta{}, jerr
	}
	reqCtx, cancel := s.guard.withRequestTimeout(ctx)
	defer cancel()
	om, err := s.store.HeadObject(reqCtx, bucket, key)
	return om, hostkit.NilIfTyped(err)
}

func (s *GuardStore) DeleteObject(ctx context.Context, bucket, key string) error {
	g := s.guard
	if cerr := g.requireMutationsAllowed("object_delete"); cerr != nil {
		return cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindBucket, bucket, hostkit.AbsentBucket, true); cerr != nil {
		return cerr
	}
	meta := g.journal.Meta()
	entry, ok := g.journal.Lookup(KindObject, bucket, key)
	if ok && (entry.Retain || entry.State == StateRetained) {
		return hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"RetainedResourceDeleteRefused",
			fmt.Sprintf("refusing to delete retained object %s/%s: %s", bucket, key, nonEmptyReason(entry.Reason, "marked retained in journal")),
		)
	}
	ref := ResourceRef{Kind: KindObject, Parent: bucket, Location: meta.Region, Name: key}

	ro, readErr, rcerr := g.readOwnershipMetered(ctx, ref, true, "pre_delete_object_check")
	if rcerr != nil {
		return rcerr
	}
	if (readErr == nil && !ro.Exists) || (readErr != nil && g.recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
		if ok {
			if jerr := journalWriteErr(g.journal.Deleted(KindObject, bucket, key, 0)); jerr != nil {
				return jerr
			}
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["object_put"].CleanupReserveNanoUSD)
		}
		return hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchKey", "object does not exist").WithAbsent(hostkit.AbsentObject)
	}
	if readErr != nil {
		return hostkit.AsCloudError(readErr)
	}
	if !ok {
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "UnownedResourceDeleteRefused",
			fmt.Sprintf("object %s/%s is not tracked in journal %s", bucket, key, meta.RunID))
	}
	if verr := ro.VerifyMatchesEntry(entry, meta); verr != nil {
		if jerr := journalWriteErr(g.journal.Retain(KindObject, bucket, key, verr.Error())); jerr != nil {
			return jerr
		}
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "OwnershipMismatch", verr.Error())
	}

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "object_delete", IsCleanup: true})
	if cerr != nil {
		return cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(g.journal.RecordCost(KindObject, bucket, key, "object_delete", charged)); jerr != nil {
		return jerr
	}
	reqCtx, cancel := g.withRequestTimeout(ctx)
	err := hostkit.NilIfTyped(s.store.DeleteObject(reqCtx, bucket, key))
	cancel()
	if err != nil {
		if g.recovery.ClassifyAbsent(err) == AbsenceDefinitive {
			if jerr := journalWriteErr(g.journal.Deleted(KindObject, bucket, key, 0)); jerr != nil {
				return jerr
			}
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["object_put"].CleanupReserveNanoUSD)
		}
		return err
	}
	if err := g.journal.Deleted(KindObject, bucket, key, 0); err != nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
	}
	g.meter.ReleaseResourceCleanup(g.meter.table.Operations["object_put"].CleanupReserveNanoUSD)
	return nil
}

func (s *GuardStore) ListObjects(ctx context.Context, bucket, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "object_list"})
	if cerr != nil {
		return hostkit.ObjectPage{}, cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(s.guard.journal.RecordCost(KindObject, bucket, prefix, "object_list", charged)); jerr != nil {
		return hostkit.ObjectPage{}, jerr
	}
	reqCtx, cancel := s.guard.withRequestTimeout(ctx)
	defer cancel()
	page, err := s.store.ListObjects(reqCtx, bucket, prefix, max, token)
	return page, hostkit.NilIfTyped(err)
}

func (s *GuardStore) BucketCreateToken(ctx context.Context, bucket string) (string, error) {
	if cerr := s.guard.checkWallClock(); cerr != nil {
		return "", cerr
	}
	if r, ok := s.store.(hostkit.BucketCreateTokenReader); ok {
		res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "bucket_read_ownership"})
		if cerr != nil {
			return "", cerr
		}
		charged := res.Commit(-1, false)
		if jerr := journalWriteErr(s.guard.journal.RecordCost(KindBucket, "", bucket, "bucket_create_token", charged)); jerr != nil {
			return "", jerr
		}
		reqCtx, cancel := s.guard.withRequestTimeout(ctx)
		defer cancel()
		tok, err := r.BucketCreateToken(reqCtx, bucket)
		return tok, hostkit.NilIfTyped(err)
	}
	ro, err, cerr := s.guard.readOwnershipMetered(ctx, ResourceRef{
		Kind:     KindBucket,
		Location: s.guard.journal.Meta().Region,
		Name:     bucket,
	}, false, "bucket_create_token")
	if cerr != nil {
		return "", cerr
	}
	if err != nil {
		return "", hostkit.AsCloudError(err)
	}
	return ro.CreateToken, nil
}

// GuardQueue wraps a hostkit.Queue so every queue and message operation goes
// through live policy validation, cost reservation, fsynced journal intent,
// remote ownership verification, and parent-ownership checks.
type GuardQueue struct {
	guard *LiveGuard
	queue hostkit.Queue
}

func (q *GuardQueue) QueueCaps() hostkit.QueueCaps {
	return q.queue.QueueCaps()
}

func (q *GuardQueue) QueueCapsFor(ctx context.Context, queue string) hostkit.QueueCaps {
	return hostkit.CapsFor(ctx, q.queue, queue)
}

func (q *GuardQueue) CreateQueue(ctx context.Context, queue string) (bool, error) {
	g := q.guard
	if cerr := g.requireMutationsAllowed("queue_create"); cerr != nil {
		return false, cerr
	}
	meta := g.journal.Meta()
	if err := ValidateLiveResourceName(meta.RunID, queue); err != nil {
		return false, hostkit.ProviderError(hostkit.PermissionDenied, 0, "InvalidLiveResourceName", err.Error())
	}

	g.mu.Lock()
	existing, hasExisting := g.journal.Lookup(KindQueue, "", queue)
	if hasExisting && (existing.State == StateRetained || existing.Retain) {
		g.mu.Unlock()
		return false, hostkit.ProviderError(
			hostkit.Conflict,
			409,
			"ForeignResourceCollision",
			nonEmptyReason(existing.Reason, "queue is marked retained in journal"),
		)
	}
	if !hasExisting && g.queuesMade >= g.pol.Limits.MaxQueues {
		g.mu.Unlock()
		return false, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("max_queues limit (%d) reached", g.pol.Limits.MaxQueues),
		)
	}
	g.mu.Unlock()

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_create"})
	if cerr != nil {
		return false, cerr
	}
	reservedNano := res.Quote().AttemptNanoUSD + res.Quote().CleanupReserveNanoUSD

	intent, err := g.journal.BeginCreate(KindQueue, "", meta.Region, queue, reservedNano)
	if err != nil {
		res.Commit(0, false)
		return false, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
	}
	g.registerRedactions(intent.OwnerNonce, intent.CreateToken)

	if intent.AlreadyConfirmed {
		if existing.State == StateRetained || existing.Retain {
			res.Commit(0, false)
			return false, hostkit.ProviderError(
				hostkit.Conflict,
				409,
				"ForeignResourceCollision",
				nonEmptyReason(existing.Reason, "queue is marked retained in journal"),
			)
		}
		if existing.State == StateConfirmed {
			ro, rerr, rcerr := g.readOwnershipMetered(ctx, ResourceRef{
				Kind:       KindQueue,
				Location:   meta.Region,
				Name:       queue,
				ProviderID: existing.ProviderID,
			}, false, "duplicate_queue_create_check")
			charged := res.Commit(-1, false)
			if rcerr != nil {
				return false, rcerr
			}
			if jerr := journalWriteErr(g.journal.RecordCost(KindQueue, "", queue, "duplicate_queue_create", charged)); jerr != nil {
				return false, jerr
			}
			if rerr != nil {
				return false, hostkit.AsCloudError(rerr)
			}
			if !ro.Exists {
				if jerr := journalWriteErr(g.journal.Retain(KindQueue, "", queue, "confirmed queue disappeared remotely")); jerr != nil {
					return false, jerr
				}
				return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", "confirmed queue no longer exists remotely")
			}
			if verr := ro.VerifyMatchesEntry(existing, meta); verr != nil {
				if jerr := journalWriteErr(g.journal.Retain(KindQueue, "", queue, verr.Error())); jerr != nil {
					return false, jerr
				}
				return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", verr.Error())
			}
			return false, nil
		}
	}

	pendingEntry := LedgerEntry{
		Kind:         KindQueue,
		Location:     meta.Region,
		Name:         queue,
		OwnerNonce:   intent.OwnerNonce,
		CreateToken:  intent.CreateToken,
		IntentAtUnix: intent.IntentAtUnix,
		State:        StatePending,
	}

	// Prove absence (or prior pending convergence in this run) BEFORE dispatching
	// CreateQueue so a pre-existing foreign or untagged queue is never adopted.
	preRO, preErr, preCerr := g.readOwnershipMetered(ctx, ResourceRef{
		Kind:     KindQueue,
		Location: meta.Region,
		Name:     queue,
	}, false, "pre_create_queue_check")
	if preCerr != nil {
		res.Commit(0, false)
		return false, preCerr
	}
	if preErr == nil && preRO.Exists {
		if hasExisting && existing.State == StatePending && preRO.VerifyMatchesEntry(pendingEntry, meta) == nil {
			charged := res.Commit(-1, true)
			if err := g.journal.Confirm(KindQueue, "", queue, ConfirmDetails{
				ProviderID:          preRO.ProviderID,
				Location:            preRO.Location,
				ConfirmedAtUnix:     g.now().UTC().Unix(),
				ServerCreatedAtUnix: preRO.CreatedAtUnix,
				ChargedNanoUSD:      charged,
			}); err != nil {
				return false, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			}
			g.mu.Lock()
			g.queuesMade++
			g.mu.Unlock()
			return true, nil
		}
		verr := preRO.VerifyMatchesEntry(pendingEntry, meta)
		reason := "pre-existing foreign or untagged queue collision"
		if verr != nil {
			reason = "pre-existing foreign or untagged queue collision: " + verr.Error()
		}
		charged := res.Commit(-1, false)
		if jerr := journalWriteErr(g.journal.Retain(KindQueue, "", queue, reason)); jerr != nil {
			return false, jerr
		}
		if jerr := journalWriteErr(g.journal.RecordCost(KindQueue, "", queue, "foreign_or_untagged_queue_collision", charged)); jerr != nil {
			return false, jerr
		}
		return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", reason)
	}
	if preErr != nil && g.recovery.ClassifyAbsent(preErr) != AbsenceDefinitive {
		charged := res.Commit(-1, false)
		reason := "ambiguous pre-create queue ownership probe: " + preErr.Error()
		if jerr := journalWriteErr(g.journal.Retain(KindQueue, "", queue, reason)); jerr != nil {
			return false, jerr
		}
		if jerr := journalWriteErr(g.journal.RecordCost(KindQueue, "", queue, "ambiguous_pre_create_queue", charged)); jerr != nil {
			return false, jerr
		}
		return false, hostkit.ProviderError(hostkit.PermissionDenied, 0, "AmbiguousPreCreateProbe", reason)
	}

	ctxWithTags := WithOwnershipTags(ctx, OwnershipTags{
		RunID:         meta.RunID,
		OwnerNonce:    intent.OwnerNonce,
		CreateToken:   intent.CreateToken,
		CreatedAtUnix: intent.IntentAtUnix,
	})
	reqCtx, cancel := g.withRequestTimeout(ctxWithTags)
	created, callErr := q.queue.CreateQueue(reqCtx, queue)
	cancel()
	callErr = hostkit.NilIfTyped(callErr)

	ro, readErr, rcerr := g.readOwnershipMetered(ctxWithTags, ResourceRef{
		Kind:     KindQueue,
		Location: meta.Region,
		Name:     queue,
	}, false, "post_create_queue_check")
	if rcerr != nil {
		res.Commit(-1, true)
		return false, rcerr
	}

	if readErr == nil && ro.Exists {
		if verr := ro.VerifyMatchesEntry(pendingEntry, meta); verr != nil {
			charged := res.Commit(-1, false)
			if jerr := journalWriteErr(g.journal.Retain(KindQueue, "", queue, "foreign or untagged collision: "+verr.Error())); jerr != nil {
				return false, jerr
			}
			if jerr := journalWriteErr(g.journal.RecordCost(KindQueue, "", queue, "foreign_or_untagged_queue_collision", charged)); jerr != nil {
				return false, jerr
			}
			return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", verr.Error())
		}
		if callErr == nil {
			charged := res.Commit(-1, true)
			if err := g.journal.Confirm(KindQueue, "", queue, ConfirmDetails{
				ProviderID:          ro.ProviderID,
				Location:            ro.Location,
				ConfirmedAtUnix:     g.now().UTC().Unix(),
				ServerCreatedAtUnix: ro.CreatedAtUnix,
				ChargedNanoUSD:      charged,
			}); err != nil {
				return false, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
			}
			g.mu.Lock()
			if !hasExisting {
				g.queuesMade++
			}
			g.mu.Unlock()
			if ro.CreateToken != "" && ro.CreateToken == intent.CreateToken {
				return true, nil
			}
			return created, nil
		}
	}

	if callErr != nil {
		if (readErr == nil && !ro.Exists) || (readErr != nil && g.recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
			charged := res.Commit(-1, false)
			if jerr := journalWriteErr(g.journal.Failed(KindQueue, "", queue, callErr.Error(), charged)); jerr != nil {
				return false, jerr
			}
		} else {
			charged := res.Commit(-1, true)
			if jerr := journalWriteErr(g.journal.RecordCost(KindQueue, "", queue, "ambiguous_queue_create", charged)); jerr != nil {
				return false, jerr
			}
		}
		return false, callErr
	}

	charged := res.Commit(-1, true)
	if jerr := journalWriteErr(g.journal.Retain(KindQueue, "", queue, "post-create queue ownership verification failed")); jerr != nil {
		return false, jerr
	}
	if jerr := journalWriteErr(g.journal.RecordCost(KindQueue, "", queue, "unverified_queue_create", charged)); jerr != nil {
		return false, jerr
	}
	if readErr != nil {
		return false, hostkit.ProviderError(hostkit.Internal, 0, "OwnershipVerificationFailed", readErr.Error())
	}
	return false, hostkit.ProviderError(hostkit.Internal, 0, "OwnershipVerificationFailed", "created queue was not visible to ReadOwnership")
}

func (q *GuardQueue) DeleteQueue(ctx context.Context, queue string) error {
	g := q.guard
	if cerr := g.requireMutationsAllowed("queue_delete"); cerr != nil {
		return cerr
	}
	meta := g.journal.Meta()
	if err := ValidateLiveResourceName(meta.RunID, queue); err != nil {
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "UnownedResourceDeleteRefused", err.Error())
	}

	entry, ok := g.journal.Lookup(KindQueue, "", queue)
	if ok && (entry.Retain || entry.State == StateRetained) {
		return hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"RetainedResourceDeleteRefused",
			fmt.Sprintf("refusing to delete retained queue %q: %s", queue, nonEmptyReason(entry.Reason, "marked retained in journal")),
		)
	}
	ref := ResourceRef{Kind: KindQueue, Location: meta.Region, Name: queue}
	if ok {
		ref.ProviderID = entry.ProviderID
	}

	ro, readErr, rcerr := g.readOwnershipMetered(ctx, ref, true, "pre_delete_queue_check")
	if rcerr != nil {
		return rcerr
	}
	if (readErr == nil && !ro.Exists) || (readErr != nil && g.recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
		if ok {
			if jerr := journalWriteErr(g.journal.Deleted(KindQueue, "", queue, 0)); jerr != nil {
				return jerr
			}
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["queue_create"].CleanupReserveNanoUSD)
		}
		return hostkit.ProviderError(hostkit.NotFound, 404, "NonExistentQueue", "queue does not exist").WithAbsent(hostkit.AbsentQueue)
	}
	if readErr != nil {
		return hostkit.AsCloudError(readErr)
	}
	if !ok {
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "UnownedResourceDeleteRefused",
			fmt.Sprintf("queue %q is not tracked in journal %s", queue, meta.RunID))
	}
	if verr := ro.VerifyMatchesEntry(entry, meta); verr != nil {
		if jerr := journalWriteErr(g.journal.Retain(KindQueue, "", queue, verr.Error())); jerr != nil {
			return jerr
		}
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "OwnershipMismatch", verr.Error())
	}

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_delete", IsCleanup: true})
	if cerr != nil {
		return cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(g.journal.RecordCost(KindQueue, "", queue, "queue_delete", charged)); jerr != nil {
		return jerr
	}
	reqCtx, cancel := g.withRequestTimeout(ctx)
	err := hostkit.NilIfTyped(q.queue.DeleteQueue(reqCtx, queue))
	cancel()
	if err != nil {
		if g.recovery.ClassifyAbsent(err) == AbsenceDefinitive {
			if jerr := journalWriteErr(g.journal.Deleted(KindQueue, "", queue, 0)); jerr != nil {
				return jerr
			}
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["queue_create"].CleanupReserveNanoUSD)
		}
		return err
	}
	if err := g.journal.Deleted(KindQueue, "", queue, 0); err != nil {
		return hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
	}
	g.meter.ReleaseResourceCleanup(g.meter.table.Operations["queue_create"].CleanupReserveNanoUSD)
	return nil
}

func (q *GuardQueue) LookupQueue(ctx context.Context, queue string) error {
	res, cerr := q.guard.reserveOp(AttemptPricingInput{Operation: "queue_exists"})
	if cerr != nil {
		return cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(q.guard.journal.RecordCost(KindQueue, "", queue, "queue_exists", charged)); jerr != nil {
		return jerr
	}
	reqCtx, cancel := q.guard.withRequestTimeout(ctx)
	defer cancel()
	return hostkit.NilIfTyped(q.queue.LookupQueue(reqCtx, queue))
}

func (q *GuardQueue) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	res, cerr := q.guard.reserveOp(AttemptPricingInput{Operation: "queue_list"})
	if cerr != nil {
		return nil, "", cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(q.guard.journal.RecordCost(KindQueue, "", "", "queue_list", charged)); jerr != nil {
		return nil, "", jerr
	}
	reqCtx, cancel := q.guard.withRequestTimeout(ctx)
	defer cancel()
	names, next, err := q.queue.ListQueues(reqCtx, token)
	return names, next, hostkit.NilIfTyped(err)
}

func (q *GuardQueue) Send(ctx context.Context, queue, wire string) (string, error) {
	g := q.guard
	if cerr := g.requireMutationsAllowed("queue_send"); cerr != nil {
		return "", cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindQueue, queue, hostkit.AbsentQueue, false); cerr != nil {
		return "", cerr
	}

	sz := int64(len(wire))
	if sz > g.pol.Limits.MaxMessageBytes {
		return "", hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("message size %d exceeds max_message_bytes (%d)", sz, g.pol.Limits.MaxMessageBytes),
		)
	}

	g.mu.Lock()
	if g.msgsSent >= g.pol.Limits.MaxMessages {
		g.mu.Unlock()
		return "", hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("max_messages limit (%d) reached", g.pol.Limits.MaxMessages),
		)
	}
	if g.totalBytes+sz > g.pol.Limits.MaxTotalBytes {
		g.mu.Unlock()
		return "", hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"LiveLimitExceeded",
			fmt.Sprintf("total payload bytes %d would exceed max_total_bytes (%d)", g.totalBytes+sz, g.pol.Limits.MaxTotalBytes),
		)
	}
	g.mu.Unlock()

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_send", PayloadSize: sz})
	if cerr != nil {
		return "", cerr
	}
	charged := res.Commit(-1, false)
	// Durably persist the send cost, message count, and payload byte reservation
	// BEFORE dispatching to the provider so poisoned journals fail closed before
	// dispatch and ambiguous/lost-reply sends count against campaign limits.
	if jerr := journalWriteErr(g.journal.RecordCostWithBytes(KindQueueMessage, queue, "send", "queue_send", charged, sz)); jerr != nil {
		return "", jerr
	}
	g.mu.Lock()
	g.msgsSent++
	g.totalBytes += sz
	g.mu.Unlock()

	reqCtx, cancel := g.withRequestTimeout(ctx)
	defer cancel()
	id, err := q.queue.Send(reqCtx, queue, wire)
	return id, hostkit.NilIfTyped(err)
}

func (q *GuardQueue) Receive(ctx context.Context, queue string, max, waitSeconds, visibility int) ([]hostkit.RawMessage, error) {
	g := q.guard
	if _, cerr := g.verifyOwnedParent(ctx, KindQueue, queue, hostkit.AbsentQueue, false); cerr != nil {
		return nil, cerr
	}
	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_receive"})
	if cerr != nil {
		return nil, cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(g.journal.RecordCost(KindQueue, "", queue, "queue_receive", charged)); jerr != nil {
		return nil, jerr
	}
	reqCtx, cancel := g.withRequestTimeout(ctx)
	defer cancel()
	msgs, err := q.queue.Receive(reqCtx, queue, max, waitSeconds, visibility)
	return msgs, hostkit.NilIfTyped(err)
}

func (q *GuardQueue) Ack(ctx context.Context, queue, receipt string) error {
	g := q.guard
	if cerr := g.requireMutationsAllowed("queue_ack"); cerr != nil {
		return cerr
	}
	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_ack"})
	if cerr != nil {
		return cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindQueue, queue, hostkit.AbsentQueue, false); cerr != nil {
		res.Commit(0, false)
		return cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(g.journal.RecordCost(KindQueueMessage, queue, "ack", "queue_ack", charged)); jerr != nil {
		return jerr
	}
	reqCtx, cancel := g.withRequestTimeout(ctx)
	defer cancel()
	return hostkit.NilIfTyped(q.queue.Ack(reqCtx, queue, receipt))
}

func (q *GuardQueue) Nack(ctx context.Context, queue, receipt string, visibility int) (string, error) {
	g := q.guard
	if cerr := g.requireMutationsAllowed("queue_nack"); cerr != nil {
		return "", cerr
	}
	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_nack"})
	if cerr != nil {
		return "", cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindQueue, queue, hostkit.AbsentQueue, false); cerr != nil {
		res.Commit(0, false)
		return "", cerr
	}
	charged := res.Commit(-1, false)
	if jerr := journalWriteErr(g.journal.RecordCost(KindQueueMessage, queue, "nack", "queue_nack", charged)); jerr != nil {
		return "", jerr
	}
	reqCtx, cancel := g.withRequestTimeout(ctx)
	defer cancel()
	newReceipt, err := q.queue.Nack(reqCtx, queue, receipt, visibility)
	return newReceipt, hostkit.NilIfTyped(err)
}

func (q *GuardQueue) QueueCreateToken(ctx context.Context, queue string) (string, error) {
	if cerr := q.guard.checkWallClock(); cerr != nil {
		return "", cerr
	}
	if r, ok := q.queue.(hostkit.QueueCreateTokenReader); ok {
		res, cerr := q.guard.reserveOp(AttemptPricingInput{Operation: "queue_read_ownership"})
		if cerr != nil {
			return "", cerr
		}
		charged := res.Commit(-1, false)
		if jerr := journalWriteErr(q.guard.journal.RecordCost(KindQueue, "", queue, "queue_create_token", charged)); jerr != nil {
			return "", jerr
		}
		reqCtx, cancel := q.guard.withRequestTimeout(ctx)
		defer cancel()
		tok, err := r.QueueCreateToken(reqCtx, queue)
		return tok, hostkit.NilIfTyped(err)
	}
	ro, err, cerr := q.guard.readOwnershipMetered(ctx, ResourceRef{
		Kind:     KindQueue,
		Location: q.guard.journal.Meta().Region,
		Name:     queue,
	}, false, "queue_create_token")
	if cerr != nil {
		return "", cerr
	}
	if err != nil {
		return "", hostkit.AsCloudError(err)
	}
	return ro.CreateToken, nil
}
