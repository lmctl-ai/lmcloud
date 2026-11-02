// SPDX-License-Identifier: MIT

package safety

import (
	"context"
	"fmt"
	"strconv"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// OwnershipTags holds the mandatory ownership metadata attached to every
// resource created in live mode.
type OwnershipTags struct {
	RunID         string
	OwnerNonce    string
	CreateToken   string
	CreatedAtUnix int64
}

// Map returns the canonical provider tag/metadata key-value map.
func (t OwnershipTags) Map() map[string]string {
	m := map[string]string{
		TagKeyRunID:       t.RunID,
		TagKeyOwnerNonce:  t.OwnerNonce,
		TagKeyCreateToken: t.CreateToken,
	}
	if t.CreatedAtUnix > 0 {
		m[TagKeyCreatedAt] = strconv.FormatInt(t.CreatedAtUnix, 10)
	}
	return m
}

type ownershipTagsKey struct{}

// WithOwnershipTags attaches OwnershipTags to ctx and also sets hostkit's
// CreateToken on ctx so adapters using either mechanism receive the token.
func WithOwnershipTags(ctx context.Context, tags OwnershipTags) context.Context {
	ctx = hostkit.WithCreateToken(ctx, tags.CreateToken)
	return context.WithValue(ctx, ownershipTagsKey{}, tags)
}

// OwnershipTagsFrom retrieves the OwnershipTags attached to ctx, if any.
func OwnershipTagsFrom(ctx context.Context) (OwnershipTags, bool) {
	v, ok := ctx.Value(ownershipTagsKey{}).(OwnershipTags)
	return v, ok
}

// AttestedIdentity is the live caller identity returned by a provider's control
// plane (e.g. AWS STS GetCallerIdentity) before any data-plane call is allowed.
type AttestedIdentity struct {
	Provider  string
	Account   string
	Tenant    string
	Principal string
	AuthMode  string
}

// ResolvedScope is the provider's attested target scope and endpoint for a service.
type ResolvedScope struct {
	Provider string
	Account  string
	Tenant   string
	Scope    string
	Region   string
	Endpoint string
}

// ResourceRef identifies a cloud resource for ownership probing, discovery, or deletion.
type ResourceRef struct {
	Kind       string
	Parent     string
	Location   string
	Name       string
	ProviderID string
}

// RemoteOwnership is the ownership metadata read back from a live cloud resource.
type RemoteOwnership struct {
	Exists        bool
	ProviderID    string
	Account       string
	Scope         string
	Location      string
	RunID         string
	OwnerNonce    string
	CreateToken   string
	ETag          string
	Generation    string
	CreatedAtUnix int64
	// ChildKeys optionally lists object keys currently inside a bucket when
	// inspected during recovery.
	ChildKeys []string
}

// VerifyMatchesEntry checks that the remote resource exists and its ownership
// tags match the journal's Meta and LedgerEntry. Any mismatch returns an error
// so the caller fails closed (retaining rather than deleting).
func (ro RemoteOwnership) VerifyMatchesEntry(entry LedgerEntry, meta JournalMeta) error {
	if !ro.Exists {
		return fmt.Errorf("remote resource %s %s/%s does not exist", entry.Kind, entry.Parent, entry.Name)
	}
	if ro.Account != "" && ro.Account != meta.Account {
		return fmt.Errorf("remote account %q does not match journal account %q", ro.Account, meta.Account)
	}
	if ro.Scope != "" && ro.Scope != meta.Scope {
		return fmt.Errorf("remote scope %q does not match journal scope %q", ro.Scope, meta.Scope)
	}
	if ro.RunID == "" {
		return fmt.Errorf("remote resource %s %s/%s has no %s tag", entry.Kind, entry.Parent, entry.Name, TagKeyRunID)
	}
	if ro.RunID != meta.RunID {
		return fmt.Errorf("remote %s %q does not match journal run_id %q", TagKeyRunID, ro.RunID, meta.RunID)
	}
	if entry.OwnerNonce == "" {
		return fmt.Errorf("journal entry for %s %s/%s has empty owner_nonce", entry.Kind, entry.Parent, entry.Name)
	}
	if ro.OwnerNonce != entry.OwnerNonce {
		return fmt.Errorf("remote %s %q does not match journal owner_nonce %q", TagKeyOwnerNonce, ro.OwnerNonce, entry.OwnerNonce)
	}
	if ro.CreateToken != "" && entry.CreateToken != "" && ro.CreateToken != entry.CreateToken {
		return fmt.Errorf("remote %s %q does not match journal create_token %q", TagKeyCreateToken, ro.CreateToken, entry.CreateToken)
	}
	return nil
}

// AbsenceClass distinguishes authoritative non-existence from ambiguous
// permission/masked-404 responses (such as S3 403 on HEAD or OCI
// 404 NotAuthorizedOrNotFound).
type AbsenceClass string

const (
	// AbsenceDefinitive means the provider authoritatively confirmed the
	// resource does not exist (e.g. S3 404 NoSuchBucket/NoSuchKey, SQS
	// NonExistentQueue).
	AbsenceDefinitive AbsenceClass = "definitive_absent"
	// AbsenceAmbiguous means the response could be either non-existence or a
	// permission denial (e.g. OCI 404 NotAuthorizedOrNotFound, S3 403 on HEAD).
	// Sweeps and guards MUST NOT treat AbsenceAmbiguous as deleted.
	AbsenceAmbiguous AbsenceClass = "ambiguous"
	// AbsencePresentOrError means the failure is a transient or non-absence error.
	AbsencePresentOrError AbsenceClass = "present_or_error"
)

// RecoveryAdapter is the provider-neutral live recovery and attestation
// interface implemented by each provider adapter (and by FakeRecoveryBackend in
// Stage 1 tests).
type RecoveryAdapter interface {
	// AttestIdentity queries the provider's identity service (e.g. STS) and
	// returns the active caller identity.
	AttestIdentity(ctx context.Context) (AttestedIdentity, error)

	// ResolveScope resolves the target account, scope, region, and endpoint for service.
	ResolveScope(ctx context.Context, service string) (ResolvedScope, error)

	// ReadOwnership reads the live resource's ownership tags/metadata without mutating it.
	// If the resource is definitively absent, ReadOwnership returns
	// RemoteOwnership{Exists: false}, nil (or an error that ClassifyAbsent maps
	// to AbsenceDefinitive).
	ReadOwnership(ctx context.Context, ref ResourceRef) (RemoteOwnership, error)

	// FindOwned enumerates candidate resources in the target scope whose names
	// begin with prefix (e.g. "lmcloud-conf-<run12>-").
	FindOwned(ctx context.Context, prefix string) ([]ResourceRef, error)

	// DeleteOwned deletes a resource whose ownership has just been verified.
	DeleteOwned(ctx context.Context, ref ResourceRef, expected RemoteOwnership) error

	// PollDelete checks whether a delete (including asynchronous deletes like
	// Azure Queue or S3 bucket propagation) has completed and the resource is
	// definitively absent.
	PollDelete(ctx context.Context, ref ResourceRef) (deleted bool, err error)

	// ClassifyAbsent classifies an error returned by ReadOwnership, DeleteOwned,
	// or PollDelete into AbsenceDefinitive, AbsenceAmbiguous, or AbsencePresentOrError.
	ClassifyAbsent(err error) AbsenceClass

	// QuoteAttempt allows the adapter to customize or augment the regional price
	// table quote before an attempt is reserved.
	QuoteAttempt(in AttemptPricingInput, base AttemptQuote) (AttemptQuote, error)
}
