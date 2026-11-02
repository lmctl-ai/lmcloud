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
	started := cfg.StartedAt
	if started.IsZero() {
		started = nowFn()
	}
	g := &LiveGuard{
		pol:       cfg.Policy,
		journal:   cfg.Journal,
		meter:     cfg.Meter,
		recovery:  cfg.Recovery,
		errors:    cfg.Errors,
		startedAt: started,
		now:       nowFn,
	}

	st := cfg.Journal.State()
	for _, e := range st.Entries {
		g.registerRedactions(e.OwnerNonce, e.CreateToken)
		switch e.Kind {
		case KindBucket:
			g.bucketsMade++
		case KindQueue:
			g.queuesMade++
		case KindObject:
			g.objectsMade++
		case KindQueueMessage:
			g.msgsSent++
		}
	}
	return g, nil
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

func (g *LiveGuard) checkWallClock() *hostkit.CloudError {
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

func (g *LiveGuard) verifyOwnedParent(ctx context.Context, parentKind, parentName string, absentKind hostkit.Absence) (LedgerEntry, *hostkit.CloudError) {
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
	if !ok || entry.State != StateConfirmed {
		// Read-only probe to report NOT_FOUND for a genuinely missing parent vs
		// PERMISSION_DENIED for a foreign parent.
		ro, err := g.recovery.ReadOwnership(ctx, ResourceRef{
			Kind:     parentKind,
			Location: meta.Region,
			Name:     parentName,
		})
		if (err == nil && !ro.Exists) || (err != nil && g.recovery.ClassifyAbsent(err) == AbsenceDefinitive) {
			return LedgerEntry{}, hostkit.ProviderError(
				hostkit.NotFound,
				404,
				"NotFound",
				fmt.Sprintf("%s %q does not exist", parentKind, parentName),
			).WithAbsent(absentKind)
		}
		return LedgerEntry{}, hostkit.ProviderError(
			hostkit.PermissionDenied,
			0,
			"UnownedParentResource",
			fmt.Sprintf("%s %q is not a confirmed resource of run %s", parentKind, parentName, meta.RunID),
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

	if intent.AlreadyConfirmed && existing.State == StateConfirmed {
		// Already confirmed in this run: verify remote ownership is still intact
		// and return created=false without overwriting tokens.
		ro, rerr := g.recovery.ReadOwnership(ctx, ResourceRef{
			Kind:       KindBucket,
			Location:   meta.Region,
			Name:       bucket,
			ProviderID: existing.ProviderID,
		})
		charged := res.Commit(-1, false)
		_ = g.journal.RecordCost(KindBucket, "", bucket, "duplicate_bucket_create_check", charged)
		if rerr != nil {
			return false, hostkit.AsCloudError(rerr)
		}
		if verr := ro.VerifyMatchesEntry(existing, meta); verr != nil {
			_ = g.journal.Retain(KindBucket, "", bucket, verr.Error())
			return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", verr.Error())
		}
		return false, nil
	}

	ctxWithTags := WithOwnershipTags(ctx, OwnershipTags{
		RunID:         meta.RunID,
		OwnerNonce:    intent.OwnerNonce,
		CreateToken:   intent.CreateToken,
		CreatedAtUnix: intent.IntentAtUnix,
	})
	created, callErr := s.store.CreateBucket(ctxWithTags, bucket)
	callErr = hostkit.NilIfTyped(callErr)

	// Always read back remote ownership to verify whether the bucket now exists
	// and carries our RunID + OwnerNonce.
	ro, readErr := g.recovery.ReadOwnership(ctxWithTags, ResourceRef{
		Kind:     KindBucket,
		Location: meta.Region,
		Name:     bucket,
	})
	pendingEntry := LedgerEntry{
		Kind:         KindBucket,
		Location:     meta.Region,
		Name:         bucket,
		OwnerNonce:   intent.OwnerNonce,
		CreateToken:  intent.CreateToken,
		IntentAtUnix: intent.IntentAtUnix,
		State:        StatePending,
	}

	if readErr == nil && ro.Exists {
		if verr := ro.VerifyMatchesEntry(pendingEntry, meta); verr != nil {
			// A foreign or untagged resource with the same name exists!
			// Drop our pending intent (so we never claim or delete it) and fail closed.
			charged := res.Commit(-1, false)
			_ = g.journal.Failed(KindBucket, "", bucket, "foreign collision: "+verr.Error(), charged)
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
			_ = g.journal.Failed(KindBucket, "", bucket, callErr.Error(), charged)
		} else {
			// Ambiguous outcome: keep intent + cleanup reserve in journal for recovery.
			charged := res.Commit(-1, true)
			_ = g.journal.RecordCost(KindBucket, "", bucket, "ambiguous_bucket_create", charged)
		}
		return false, callErr
	}

	// Adapter reported success, but ReadOwnership could not verify our tags!
	charged := res.Commit(-1, true)
	_ = g.journal.Retain(KindBucket, "", bucket, "post-create ownership verification failed")
	_ = g.journal.RecordCost(KindBucket, "", bucket, "unverified_bucket_create", charged)
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
	ref := ResourceRef{Kind: KindBucket, Location: meta.Region, Name: bucket}
	if ok {
		ref.ProviderID = entry.ProviderID
	}

	ro, readErr := g.recovery.ReadOwnership(ctx, ref)
	if (readErr == nil && !ro.Exists) || (readErr != nil && g.recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
		if ok {
			_ = g.journal.Deleted(KindBucket, "", bucket, 0)
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
		_ = g.journal.Retain(KindBucket, "", bucket, verr.Error())
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "OwnershipMismatch", verr.Error())
	}

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "bucket_delete", IsCleanup: true})
	if cerr != nil {
		return cerr
	}
	err := hostkit.NilIfTyped(s.store.DeleteBucket(ctx, bucket))
	charged := res.Commit(-1, false)
	if err != nil {
		if g.recovery.ClassifyAbsent(err) == AbsenceDefinitive {
			_ = g.journal.Deleted(KindBucket, "", bucket, charged)
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["bucket_create"].CleanupReserveNanoUSD)
		} else {
			_ = g.journal.RecordCost(KindBucket, "", bucket, "failed_bucket_delete", charged)
		}
		return err
	}
	if err := g.journal.Deleted(KindBucket, "", bucket, charged); err != nil {
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
	err := hostkit.NilIfTyped(s.store.HeadBucket(ctx, bucket))
	charged := res.Commit(-1, false)
	_ = s.guard.journal.RecordCost(KindBucket, "", bucket, "bucket_exists", charged)
	return err
}

func (s *GuardStore) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "bucket_list"})
	if cerr != nil {
		return nil, "", cerr
	}
	names, next, err := s.store.ListBuckets(ctx, token)
	err = hostkit.NilIfTyped(err)
	charged := res.Commit(-1, false)
	_ = s.guard.journal.RecordCost(KindBucket, "", "", "bucket_list", charged)
	return names, next, err
}

func (s *GuardStore) PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (hostkit.ObjectMeta, error) {
	g := s.guard
	if cerr := g.requireMutationsAllowed("object_put"); cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindBucket, bucket, hostkit.AbsentBucket); cerr != nil {
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
	_, hasObj := g.journal.Lookup(KindObject, bucket, key)
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
	intent, err := g.journal.BeginCreate(KindObject, bucket, jMeta.Region, key, reservedNano)
	if err != nil {
		res.Commit(0, false)
		return hostkit.ObjectMeta{}, hostkit.ProviderError(hostkit.Internal, 0, "JournalWriteFailed", err.Error())
	}
	g.registerRedactions(intent.OwnerNonce, intent.CreateToken)

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
	om, callErr := s.store.PutObject(ctxWithTags, bucket, key, body, contentType, mergedMeta)
	callErr = hostkit.NilIfTyped(callErr)
	if callErr != nil {
		ro, rerr := g.recovery.ReadOwnership(ctxWithTags, ResourceRef{
			Kind:     KindObject,
			Parent:   bucket,
			Location: jMeta.Region,
			Name:     key,
		})
		if (rerr == nil && !ro.Exists) || (rerr != nil && g.recovery.ClassifyAbsent(rerr) == AbsenceDefinitive) {
			charged := res.Commit(-1, false)
			_ = g.journal.Failed(KindObject, bucket, key, callErr.Error(), charged)
		} else {
			charged := res.Commit(-1, true)
			_ = g.journal.RecordCost(KindObject, bucket, key, "ambiguous_object_put", charged)
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
	g.mu.Lock()
	if !hasObj {
		g.objectsMade++
	}
	g.totalBytes += sz
	g.mu.Unlock()
	return om, nil
}

func (s *GuardStore) GetObject(ctx context.Context, bucket, key string, limit int64) ([]byte, error) {
	egressEst := limit
	if egressEst <= 0 || egressEst > s.guard.pol.Limits.MaxObjectBytes {
		egressEst = s.guard.pol.Limits.MaxObjectBytes
	}
	res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "object_get", EgressBytes: egressEst})
	if cerr != nil {
		return nil, cerr
	}
	body, err := s.store.GetObject(ctx, bucket, key, limit)
	err = hostkit.NilIfTyped(err)
	actualQuote, qerr := s.guard.meter.QuoteAttempt(AttemptPricingInput{
		Operation:   "object_get",
		EgressBytes: int64(len(body)),
	})
	actualNano := int64(-1)
	if qerr == nil {
		actualNano = actualQuote.AttemptNanoUSD
	}
	charged := res.Commit(actualNano, false)
	_ = s.guard.journal.RecordCost(KindObject, bucket, key, "object_get", charged)
	return body, err
}

func (s *GuardStore) HeadObject(ctx context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	res, cerr := s.guard.reserveOp(AttemptPricingInput{Operation: "object_head"})
	if cerr != nil {
		return hostkit.ObjectMeta{}, cerr
	}
	om, err := s.store.HeadObject(ctx, bucket, key)
	err = hostkit.NilIfTyped(err)
	charged := res.Commit(-1, false)
	_ = s.guard.journal.RecordCost(KindObject, bucket, key, "object_head", charged)
	return om, err
}

func (s *GuardStore) DeleteObject(ctx context.Context, bucket, key string) error {
	g := s.guard
	if cerr := g.requireMutationsAllowed("object_delete"); cerr != nil {
		return cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindBucket, bucket, hostkit.AbsentBucket); cerr != nil {
		return cerr
	}
	meta := g.journal.Meta()
	entry, ok := g.journal.Lookup(KindObject, bucket, key)
	ref := ResourceRef{Kind: KindObject, Parent: bucket, Location: meta.Region, Name: key}

	ro, readErr := g.recovery.ReadOwnership(ctx, ref)
	if (readErr == nil && !ro.Exists) || (readErr != nil && g.recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
		if ok {
			_ = g.journal.Deleted(KindObject, bucket, key, 0)
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
		_ = g.journal.Retain(KindObject, bucket, key, verr.Error())
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "OwnershipMismatch", verr.Error())
	}

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "object_delete", IsCleanup: true})
	if cerr != nil {
		return cerr
	}
	err := hostkit.NilIfTyped(s.store.DeleteObject(ctx, bucket, key))
	charged := res.Commit(-1, false)
	if err != nil {
		if g.recovery.ClassifyAbsent(err) == AbsenceDefinitive {
			_ = g.journal.Deleted(KindObject, bucket, key, charged)
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["object_put"].CleanupReserveNanoUSD)
		} else {
			_ = g.journal.RecordCost(KindObject, bucket, key, "failed_object_delete", charged)
		}
		return err
	}
	if err := g.journal.Deleted(KindObject, bucket, key, charged); err != nil {
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
	page, err := s.store.ListObjects(ctx, bucket, prefix, max, token)
	err = hostkit.NilIfTyped(err)
	charged := res.Commit(-1, false)
	_ = s.guard.journal.RecordCost(KindObject, bucket, prefix, "object_list", charged)
	return page, err
}

func (s *GuardStore) BucketCreateToken(ctx context.Context, bucket string) (string, error) {
	if r, ok := s.store.(hostkit.BucketCreateTokenReader); ok {
		tok, err := r.BucketCreateToken(ctx, bucket)
		return tok, hostkit.NilIfTyped(err)
	}
	ro, err := s.guard.recovery.ReadOwnership(ctx, ResourceRef{
		Kind:     KindBucket,
		Location: s.guard.journal.Meta().Region,
		Name:     bucket,
	})
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

	if intent.AlreadyConfirmed && existing.State == StateConfirmed {
		ro, rerr := g.recovery.ReadOwnership(ctx, ResourceRef{
			Kind:       KindQueue,
			Location:   meta.Region,
			Name:       queue,
			ProviderID: existing.ProviderID,
		})
		charged := res.Commit(-1, false)
		_ = g.journal.RecordCost(KindQueue, "", queue, "duplicate_queue_create_check", charged)
		if rerr != nil {
			return false, hostkit.AsCloudError(rerr)
		}
		if verr := ro.VerifyMatchesEntry(existing, meta); verr != nil {
			_ = g.journal.Retain(KindQueue, "", queue, verr.Error())
			return false, hostkit.ProviderError(hostkit.Conflict, 409, "ForeignResourceCollision", verr.Error())
		}
		return false, nil
	}

	ctxWithTags := WithOwnershipTags(ctx, OwnershipTags{
		RunID:         meta.RunID,
		OwnerNonce:    intent.OwnerNonce,
		CreateToken:   intent.CreateToken,
		CreatedAtUnix: intent.IntentAtUnix,
	})
	created, callErr := q.queue.CreateQueue(ctxWithTags, queue)
	callErr = hostkit.NilIfTyped(callErr)

	ro, readErr := g.recovery.ReadOwnership(ctxWithTags, ResourceRef{
		Kind:     KindQueue,
		Location: meta.Region,
		Name:     queue,
	})
	pendingEntry := LedgerEntry{
		Kind:         KindQueue,
		Location:     meta.Region,
		Name:         queue,
		OwnerNonce:   intent.OwnerNonce,
		CreateToken:  intent.CreateToken,
		IntentAtUnix: intent.IntentAtUnix,
		State:        StatePending,
	}

	if readErr == nil && ro.Exists {
		if verr := ro.VerifyMatchesEntry(pendingEntry, meta); verr != nil {
			charged := res.Commit(-1, false)
			_ = g.journal.Failed(KindQueue, "", queue, "foreign collision: "+verr.Error(), charged)
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
			_ = g.journal.Failed(KindQueue, "", queue, callErr.Error(), charged)
		} else {
			charged := res.Commit(-1, true)
			_ = g.journal.RecordCost(KindQueue, "", queue, "ambiguous_queue_create", charged)
		}
		return false, callErr
	}

	charged := res.Commit(-1, true)
	_ = g.journal.Retain(KindQueue, "", queue, "post-create queue ownership verification failed")
	_ = g.journal.RecordCost(KindQueue, "", queue, "unverified_queue_create", charged)
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
	ref := ResourceRef{Kind: KindQueue, Location: meta.Region, Name: queue}
	if ok {
		ref.ProviderID = entry.ProviderID
	}

	ro, readErr := g.recovery.ReadOwnership(ctx, ref)
	if (readErr == nil && !ro.Exists) || (readErr != nil && g.recovery.ClassifyAbsent(readErr) == AbsenceDefinitive) {
		if ok {
			_ = g.journal.Deleted(KindQueue, "", queue, 0)
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
		_ = g.journal.Retain(KindQueue, "", queue, verr.Error())
		return hostkit.ProviderError(hostkit.PermissionDenied, 0, "OwnershipMismatch", verr.Error())
	}

	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_delete", IsCleanup: true})
	if cerr != nil {
		return cerr
	}
	err := hostkit.NilIfTyped(q.queue.DeleteQueue(ctx, queue))
	charged := res.Commit(-1, false)
	if err != nil {
		if g.recovery.ClassifyAbsent(err) == AbsenceDefinitive {
			_ = g.journal.Deleted(KindQueue, "", queue, charged)
			g.meter.ReleaseResourceCleanup(g.meter.table.Operations["queue_create"].CleanupReserveNanoUSD)
		} else {
			_ = g.journal.RecordCost(KindQueue, "", queue, "failed_queue_delete", charged)
		}
		return err
	}
	if err := g.journal.Deleted(KindQueue, "", queue, charged); err != nil {
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
	err := hostkit.NilIfTyped(q.queue.LookupQueue(ctx, queue))
	charged := res.Commit(-1, false)
	_ = q.guard.journal.RecordCost(KindQueue, "", queue, "queue_exists", charged)
	return err
}

func (q *GuardQueue) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	res, cerr := q.guard.reserveOp(AttemptPricingInput{Operation: "queue_list"})
	if cerr != nil {
		return nil, "", cerr
	}
	names, next, err := q.queue.ListQueues(ctx, token)
	err = hostkit.NilIfTyped(err)
	charged := res.Commit(-1, false)
	_ = q.guard.journal.RecordCost(KindQueue, "", "", "queue_list", charged)
	return names, next, err
}

func (q *GuardQueue) Send(ctx context.Context, queue, wire string) (string, error) {
	g := q.guard
	if cerr := g.requireMutationsAllowed("queue_send"); cerr != nil {
		return "", cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindQueue, queue, hostkit.AbsentQueue); cerr != nil {
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

	id, err := q.queue.Send(ctx, queue, wire)
	err = hostkit.NilIfTyped(err)
	if err != nil {
		charged := res.Commit(-1, false)
		_ = g.journal.RecordCost(KindQueueMessage, queue, "send", "failed_queue_send", charged)
		return "", err
	}

	charged := res.Commit(-1, false)
	msgName := id
	if msgName == "" {
		msgName = "msg"
	}
	_ = g.journal.RecordCost(KindQueueMessage, queue, msgName, "queue_send", charged)

	g.mu.Lock()
	g.msgsSent++
	g.totalBytes += sz
	g.mu.Unlock()
	return id, nil
}

func (q *GuardQueue) Receive(ctx context.Context, queue string, max, waitSeconds, visibility int) ([]hostkit.RawMessage, error) {
	g := q.guard
	if _, cerr := g.verifyOwnedParent(ctx, KindQueue, queue, hostkit.AbsentQueue); cerr != nil {
		return nil, cerr
	}
	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_receive"})
	if cerr != nil {
		return nil, cerr
	}
	msgs, err := q.queue.Receive(ctx, queue, max, waitSeconds, visibility)
	err = hostkit.NilIfTyped(err)
	charged := res.Commit(-1, false)
	_ = g.journal.RecordCost(KindQueue, "", queue, "queue_receive", charged)
	return msgs, err
}

func (q *GuardQueue) Ack(ctx context.Context, queue, receipt string) error {
	g := q.guard
	if cerr := g.requireMutationsAllowed("queue_ack"); cerr != nil {
		return cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindQueue, queue, hostkit.AbsentQueue); cerr != nil {
		return cerr
	}
	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_ack", IsCleanup: true})
	if cerr != nil {
		return cerr
	}
	err := hostkit.NilIfTyped(q.queue.Ack(ctx, queue, receipt))
	charged := res.Commit(-1, false)
	_ = g.journal.RecordCost(KindQueueMessage, queue, "ack", "queue_ack", charged)
	return err
}

func (q *GuardQueue) Nack(ctx context.Context, queue, receipt string, visibility int) (string, error) {
	g := q.guard
	if cerr := g.requireMutationsAllowed("queue_nack"); cerr != nil {
		return "", cerr
	}
	if _, cerr := g.verifyOwnedParent(ctx, KindQueue, queue, hostkit.AbsentQueue); cerr != nil {
		return "", cerr
	}
	res, cerr := g.reserveOp(AttemptPricingInput{Operation: "queue_nack"})
	if cerr != nil {
		return "", cerr
	}
	newReceipt, err := q.queue.Nack(ctx, queue, receipt, visibility)
	err = hostkit.NilIfTyped(err)
	charged := res.Commit(-1, false)
	_ = g.journal.RecordCost(KindQueueMessage, queue, "nack", "queue_nack", charged)
	return newReceipt, err
}

func (q *GuardQueue) QueueCreateToken(ctx context.Context, queue string) (string, error) {
	if r, ok := q.queue.(hostkit.QueueCreateTokenReader); ok {
		tok, err := r.QueueCreateToken(ctx, queue)
		return tok, hostkit.NilIfTyped(err)
	}
	ro, err := q.guard.recovery.ReadOwnership(ctx, ResourceRef{
		Kind:     KindQueue,
		Location: q.guard.journal.Meta().Region,
		Name:     queue,
	})
	if err != nil {
		return "", hostkit.AsCloudError(err)
	}
	return ro.CreateToken, nil
}
