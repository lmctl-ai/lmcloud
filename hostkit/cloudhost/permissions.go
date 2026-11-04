// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"fmt"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func missingPermissions() *hostkit.CloudError {
	return hostkit.ProviderError(hostkit.Internal, 0, "", "this host has no permissions adapter")
}

func clonePolicyStatements(stmts []hostkit.PolicyStatement) []hostkit.PolicyStatement {
	out := make([]hostkit.PolicyStatement, len(stmts))
	for i, s := range stmts {
		out[i] = s.Clone()
	}
	return out
}

// Policy is the host-side representation of the schema's Policy builder/value type.
type Policy struct {
	h       *Host
	stmts   []hostkit.PolicyStatement
	invalid *hostkit.CloudError
}

// Statement validates and appends a single statement, returning a new Policy snapshot.
func (p *Policy) Statement(effect string, actions, resources []string) (*Policy, error) {
	const op = "Policy.statement"
	if p == nil || p.h == nil {
		return nil, fmt.Errorf("%s: nil Policy", op)
	}
	if p.invalid != nil {
		err := p.h.fail(op, "", p.invalid)
		return &Policy{h: p.h, stmts: clonePolicyStatements(p.stmts), invalid: p.invalid}, err
	}
	if len(p.stmts) >= hostkit.MaxPolicyStatements {
		ce := hostkit.Preflightf("policy statement count exceeds maximum (%d)", hostkit.MaxPolicyStatements)
		err := p.h.fail(op, "", ce)
		return &Policy{h: p.h, stmts: clonePolicyStatements(p.stmts), invalid: ce}, err
	}
	st, ce := hostkit.ValidateAndNormalizeStatement(effect, actions, resources, *p.h.cfg.Validator)
	if ce != nil {
		err := p.h.fail(op, "", ce)
		return &Policy{h: p.h, stmts: clonePolicyStatements(p.stmts), invalid: ce}, err
	}
	nextStmts := append(clonePolicyStatements(p.stmts), st)
	if _, ce := hostkit.SerializeCanonicalPolicy(nextStmts); ce != nil {
		err := p.h.fail(op, "", ce)
		return &Policy{h: p.h, stmts: clonePolicyStatements(p.stmts), invalid: ce}, err
	}
	p.h.ok()
	return &Policy{h: p.h, stmts: nextStmts}, nil
}

// Document returns the canonical UTF-8 JSON policy document.
func (p *Policy) Document() (string, error) {
	const op = "Policy.document"
	if p == nil || p.h == nil {
		return "", fmt.Errorf("%s: nil Policy", op)
	}
	if p.invalid != nil {
		return "", p.h.fail(op, "", p.invalid)
	}
	raw, ce := hostkit.SerializeCanonicalPolicy(p.stmts)
	if ce != nil {
		return "", p.h.fail(op, "", ce)
	}
	p.h.ok()
	return raw, nil
}

// Len returns the number of statements in the policy without modifying last_error.
func (p *Policy) Len() int64 {
	if p == nil || p.invalid != nil {
		return 0
	}
	return int64(len(p.stmts))
}

// LintFinding wraps hostkit.LintFinding for the VM.
type LintFinding struct {
	f hostkit.LintFinding
}

func (lf *LintFinding) Code() string          { return lf.f.Code }
func (lf *LintFinding) Severity() string      { return lf.f.Severity }
func (lf *LintFinding) StatementIndex() int64 { return int64(lf.f.StatementIndex) }
func (lf *LintFinding) Message() string       { return lf.f.Message }

// LintReport wraps hostkit.LintReport for the VM.
type LintReport struct {
	r hostkit.LintReport
}

func (lr *LintReport) OK() bool   { return lr.r.OK() }
func (lr *LintReport) Len() int64 { return int64(len(lr.r.Findings)) }
func (lr *LintReport) At(idx int64) (*LintFinding, error) {
	if idx < 0 || idx >= int64(len(lr.r.Findings)) {
		return nil, fmt.Errorf("LintReport.at(%d): %v (len %d)", idx, errIndex, len(lr.r.Findings))
	}
	return &LintFinding{f: lr.r.Findings[idx]}, nil
}

// PolicyNew returns an empty Policy builder.
func (h *Host) PolicyNew() *Policy {
	h.ok()
	return &Policy{
		h:     h,
		stmts: []hostkit.PolicyStatement{},
	}
}

// PolicyParse parses a canonical v1 JSON policy document (Tier-1 validation).
func (h *Host) PolicyParse(raw string) (*Policy, error) {
	const op = "policy_parse"
	stmts, _, ce := hostkit.ParsePolicyDocument(raw, *h.cfg.Validator)
	if ce != nil {
		err := h.fail(op, "", ce)
		return &Policy{
			h:       h,
			stmts:   []hostkit.PolicyStatement{},
			invalid: ce,
		}, err
	}
	h.ok()
	return &Policy{h: h, stmts: stmts}, nil
}

// PolicyLint runs Tier-2 semantic lint on p.
func (h *Host) PolicyLint(p *Policy) (*LintReport, error) {
	const op = "policy_lint"
	if p == nil {
		ce := hostkit.Preflightf("policy must not be nil")
		return &LintReport{}, h.fail(op, "", ce)
	}
	if p.invalid != nil {
		return &LintReport{}, h.fail(op, "", p.invalid)
	}
	rep := hostkit.LintPolicy(p.stmts, *h.cfg.Validator)
	h.ok()
	return &LintReport{r: rep}, nil
}

func isDefinitivePolicyRefusal(ce *hostkit.CloudError) bool {
	if ce == nil {
		return false
	}
	switch ce.Code {
	case hostkit.Unauthenticated, hostkit.PermissionDenied, hostkit.InvalidArgument, hostkit.NotFound, hostkit.PreconditionFailed:
		return true
	default:
		return false
	}
}

func (h *Host) permissionsScope() (string, *hostkit.CloudError) {
	permEP, _, e := h.cfg.Endpoints.Resolve("permissions")
	if e != nil {
		return "", e
	}
	stEP, _, _ := h.cfg.Endpoints.Resolve("storage")
	qEP, _, _ := h.cfg.Endpoints.Resolve("queue")
	tblEP, _, _ := h.cfg.Endpoints.Resolve("tables")
	return "perm=" + permEP + "|storage=" + stEP + "|queue=" + qEP + "|tables=" + tblEP, nil
}

func (h *Host) checkPermissionsRouteAllowed(ctx context.Context) *hostkit.CloudError {
	if ce := h.cost.checkPermissionsAllowed(); ce != nil {
		return ce
	}
	if ep := hostkit.EndpointFrom(ctx); ep != "" && !hostkit.IsLoopbackEndpoint(ep) {
		return hostkit.ProviderError(hostkit.PermissionDenied, 403, "LiveModeUnsupported",
			"live mode refuses permissions operations: live permissions slice is not enabled")
	}
	if r, ok := h.cfg.Permissions.(hostkit.Router); ok && r.Pick != nil {
		if _, err := r.Pick(hostkit.WithForbidLiveRoute(ctx)); err != nil {
			if ce := hostkit.AsCloudError(err); ce != nil && ce.Code == hostkit.PermissionDenied {
				return ce
			}
		}
	}
	return nil
}

// PrincipalCurrent resolves the caller's active principal identifier.
func (h *Host) PrincipalCurrent(dry bool) (string, error) {
	const op = "principal_current"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	ctx, cancel, e := h.opCtx("permissions", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return "", h.fail(op, "", e)
	}
	defer cancel()
	if h.cfg.Permissions == nil {
		failed = true
		return "", h.fail(op, "", missingPermissions())
	}
	if ce := h.checkPermissionsRouteAllowed(ctx); ce != nil {
		failed = true
		return "", h.fail(op, "", ce)
	}
	if dry {
		pr, err := h.cfg.Permissions.CurrentPrincipal(ctx)
		if err != nil {
			return "", h.fail(op, "", hostkit.AsCloudError(err))
		}
		if ce := hostkit.ValidatePrincipal(pr); ce != nil {
			return "", h.fail(op, "", hostkit.ProviderError(hostkit.Internal, 0, "InvalidPrincipal", ce.Message))
		}
		h.ok()
		return pr, nil
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, "", "")
	if cerr != nil {
		failed = true
		return "", h.fail(op, "", cerr)
	}
	pr, err := h.cfg.Permissions.CurrentPrincipal(mctx)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, int64(len(pr)), true, err == nil && pr != "")
	if abortErr != nil {
		failed = true
		return "", h.fail(op, "", abortErr)
	}
	if err != nil {
		failed = true
		return "", h.fail(op, "", hostkit.AsCloudError(err))
	}
	if ce := hostkit.ValidatePrincipal(pr); ce != nil {
		failed = true
		return "", h.fail(op, "", hostkit.ProviderError(hostkit.Internal, 0, "InvalidPrincipal", ce.Message))
	}
	h.ok()
	return pr, nil
}

func targetSafetyKind(kind string) string {
	switch kind {
	case "bucket":
		return safety.KindBucket
	case "queue":
		return safety.KindQueue
	case "table":
		return safety.KindTable
	default:
		return ""
	}
}

func (h *Host) verifyTargetExistsAndOwned(dry bool, target hostkit.AnchoredTarget, requireOwned bool) *hostkit.CloudError {
	switch target.Kind {
	case "bucket":
		sctx, cancel, e := h.opCtx("storage", h.cfg.OpTimeout)
		if e != nil {
			return e
		}
		defer cancel()
		ep := hostkit.EndpointFrom(sctx)
		if ep != "" && !hostkit.IsLoopbackEndpoint(ep) {
			return hostkit.ProviderError(hostkit.PermissionDenied, 403, "LiveModeUnsupported",
				"live mode refuses permissions operations: live permissions slice is not enabled")
		}
		if dry {
			exists, e := h.bucketExists(sctx, true, target.Name)
			if e != nil {
				return e
			}
			if !exists {
				return notFound(hostkit.AbsentBucket, fmt.Sprintf("bucket %q does not exist (dry-run preview)", target.Name))
			}
			if requireOwned && !h.ov(sctx).bucketCreatedInDry(target.Name) {
				owned, cerr := h.cost.isOwnedResourceAt(safety.KindBucket, ep, target.Name)
				if cerr != nil {
					return cerr
				}
				if !owned {
					return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
						fmt.Sprintf("bucket %q exists but is not owned by this run", target.Name))
				}
			}
			return nil
		}
		exists, ce := h.meteredBucketExists(sctx, target.Name, false)
		if ce != nil {
			return ce
		}
		if !exists {
			return notFound(hostkit.AbsentBucket, fmt.Sprintf("bucket %q does not exist", target.Name))
		}
		if requireOwned {
			owned, cerr := h.cost.isOwnedResourceAt(safety.KindBucket, ep, target.Name)
			if cerr != nil {
				return cerr
			}
			if !owned {
				return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
					fmt.Sprintf("bucket %q exists but is not owned by this run", target.Name))
			}
		}
		return nil

	case "queue":
		qctx, cancel, e := h.opCtx("queue", h.cfg.OpTimeout)
		if e != nil {
			return e
		}
		defer cancel()
		ep := hostkit.EndpointFrom(qctx)
		if ep != "" && !hostkit.IsLoopbackEndpoint(ep) {
			return hostkit.ProviderError(hostkit.PermissionDenied, 403, "LiveModeUnsupported",
				"live mode refuses permissions operations: live permissions slice is not enabled")
		}
		if dry {
			if e := h.requireQueue(qctx, true, target.Name); e != nil {
				return e
			}
			if requireOwned {
				if createdInDry, ok := h.ov(qctx).queue(target.Name); !ok || !createdInDry {
					owned, cerr := h.cost.isOwnedResourceAt(safety.KindQueue, ep, target.Name)
					if cerr != nil {
						return cerr
					}
					if !owned {
						return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
							fmt.Sprintf("queue %q exists but is not owned by this run", target.Name))
					}
				}
			}
			return nil
		}
		exists, ce := h.meteredQueueExists(qctx, target.Name)
		if ce != nil {
			return ce
		}
		if !exists {
			return notFound(hostkit.AbsentQueue, fmt.Sprintf("queue %q does not exist", target.Name))
		}
		if requireOwned {
			owned, cerr := h.cost.isOwnedResourceAt(safety.KindQueue, ep, target.Name)
			if cerr != nil {
				return cerr
			}
			if !owned {
				return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
					fmt.Sprintf("queue %q exists but is not owned by this run", target.Name))
			}
		}
		return nil

	case "table":
		tctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
		if e != nil {
			return e
		}
		defer cancel()
		ep := hostkit.EndpointFrom(tctx)
		if ep != "" && !hostkit.IsLoopbackEndpoint(ep) {
			return hostkit.ProviderError(hostkit.PermissionDenied, 403, "LiveModeUnsupported",
				"live mode refuses permissions operations: live permissions slice is not enabled")
		}
		if dry {
			if e := h.requireTable(tctx, true, target.Name); e != nil {
				return e
			}
			if requireOwned {
				if dt, ok := h.ov(tctx).table(target.Name); !ok || !dt.createdNow {
					owned, cerr := h.cost.isOwnedResourceAt(safety.KindTable, ep, target.Name)
					if cerr != nil {
						return cerr
					}
					if !owned {
						return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
							fmt.Sprintf("table %q exists but is not owned by this run", target.Name))
					}
				}
			}
			return nil
		}
		exists, ce := h.meteredTableExists(tctx, target.Name, false)
		if ce != nil {
			return ce
		}
		if !exists {
			return notFound(hostkit.AbsentTable, fmt.Sprintf("table %q does not exist", target.Name))
		}
		if requireOwned {
			owned, cerr := h.cost.isOwnedResourceAt(safety.KindTable, ep, target.Name)
			if cerr != nil {
				return cerr
			}
			if !owned {
				return hostkit.ProviderError(hostkit.PermissionDenied, 403, "ForeignResource",
					fmt.Sprintf("table %q exists but is not owned by this run", target.Name))
			}
		}
		return nil

	default:
		return hostkit.Preflightf("unknown target entity kind %q", target.Kind)
	}
}

func (h *Host) validateExecutablePolicy(p *Policy) (string, *hostkit.CloudError) {
	if p == nil {
		return "", hostkit.Preflightf("policy must not be nil")
	}
	if p.invalid != nil {
		return "", p.invalid
	}
	rep := hostkit.LintPolicy(p.stmts, *h.cfg.Validator)
	if !rep.OK() {
		for _, f := range rep.Findings {
			if f.Severity == "error" {
				return "", hostkit.Preflightf("policy failed semantic lint (%s at statement %d): %s", f.Code, f.StatementIndex, f.Message)
			}
		}
	}
	return hostkit.SerializeCanonicalPolicy(p.stmts)
}

func (h *Host) checkDryAttachHeadroom(ovCtx context.Context, scope string, kind hostkit.AttachmentKind, target, principal string) *hostkit.CloudError {
	committed, cerr := h.cost.listPolicyAttachmentsForScope(scope, "")
	if cerr != nil {
		return cerr
	}
	merged := h.ov(ovCtx).mergePolicies(committed)
	wantKey := hostkit.AttachmentKey(kind, target, principal)
	for _, att := range merged {
		if hostkit.AttachmentKey(att.Kind, att.Target, att.Principal) == wantKey {
			return nil
		}
	}
	if len(merged) >= hostkit.MaxAttachmentsPerRun {
		return hostkit.ProviderError(hostkit.InvalidArgument, 0, "AttachmentLimitExceeded",
			fmt.Sprintf("run attachment count exceeds maximum (%d)", hostkit.MaxAttachmentsPerRun))
	}
	return nil
}

// PolicyAttach attaches a resource-scoped policy to target for principal (replace-per-key).
func (h *Host) PolicyAttach(dry bool, target, principal string, policy *Policy) error {
	const op = "policy_attach"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()

	anchored, ce := hostkit.ValidateTargetEntity(target, *h.cfg.Validator)
	if ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}
	if ce := hostkit.ValidatePrincipal(principal); ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}
	rawDoc, ce := h.validateExecutablePolicy(policy)
	if ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}
	if ce := hostkit.ValidateResourceAttachScope(anchored, policy.stmts, *h.cfg.Validator); ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}
	bytesIn = int64(len(rawDoc))

	ctx, cancel, e := h.opCtx("permissions", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, target, e)
	}
	defer cancel()
	scopeKey, e := h.permissionsScope()
	if e != nil {
		failed = true
		return h.fail(op, target, e)
	}
	ovCtx := hostkit.WithEndpoint(ctx, scopeKey)

	if ce := h.checkPermissionsRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}

	if dry {
		if ce := h.checkDryAttachHeadroom(ovCtx, scopeKey, hostkit.AttachmentResource, target, principal); ce != nil {
			failed = true
			return h.fail(op, target, ce)
		}
		if ce := h.verifyTargetExistsAndOwned(true, anchored, true); ce != nil {
			failed = true
			return h.fail(op, target, ce)
		}
		h.ov(ovCtx).attachPolicy(hostkit.PolicyAttachment{
			Key:        hostkit.ScopedAttachmentKey(scopeKey, hostkit.AttachmentResource, target, principal),
			Scope:      scopeKey,
			Kind:       hostkit.AttachmentResource,
			Target:     target,
			Principal:  principal,
			Document:   rawDoc,
			Statements: clonePolicyStatements(policy.stmts),
		})
		h.ok()
		return nil
	}

	if h.cfg.Permissions == nil {
		failed = true
		return h.fail(op, target, missingPermissions())
	}

	if ce := h.cost.checkPolicyAttachHeadroom(scopeKey, hostkit.AttachmentResource, target, principal); ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}
	if ce := h.verifyTargetExistsAndOwned(false, anchored, true); ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}

	attKey := hostkit.ScopedAttachmentKey(scopeKey, hostkit.AttachmentResource, target, principal)
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation:   op,
		PayloadSize: bytesIn,
	}, safety.KindPolicyAttachment, attKey)
	if cerr != nil {
		failed = true
		return h.fail(op, target, cerr)
	}

	att, cerr := h.cost.beginPolicyAttachIntent(scopeKey, hostkit.AttachmentResource, target, principal, policy.stmts, rawDoc)
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return h.fail(op, target, cerr)
	}
	h.errs.AddRedaction(att.OwnerToken)

	actx := hostkit.WithExpectedAttachment(hostkit.WithCreateToken(mctx, att.OwnerToken), att)
	err := h.cfg.Permissions.AttachPolicy(actx, att)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(bytesIn, bytesIn, true, err == nil)
	if abortErr != nil {
		failed = true
		return h.fail(op, target, abortErr)
	}
	if err != nil {
		failed = true
		ce := hostkit.AsCloudError(err)
		if isDefinitivePolicyRefusal(ce) {
			_ = h.cost.abortPolicyIntent(att)
		}
		return h.fail(op, target, ce)
	}
	if cerr := h.cost.confirmPolicyAttach(att); cerr != nil {
		failed = true
		return h.fail(op, target, cerr)
	}
	h.ok()
	return nil
}

// PolicyAttachPrincipal attaches an identity-scoped policy to principal (replace-per-key).
func (h *Host) PolicyAttachPrincipal(dry bool, principal string, policy *Policy) error {
	const op = "policy_attach_principal"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()

	if ce := hostkit.ValidatePrincipal(principal); ce != nil {
		failed = true
		return h.fail(op, principal, ce)
	}
	rawDoc, ce := h.validateExecutablePolicy(policy)
	if ce != nil {
		failed = true
		return h.fail(op, principal, ce)
	}
	targets, ce := hostkit.ValidatePrincipalAttachScope(policy.stmts, *h.cfg.Validator)
	if ce != nil {
		failed = true
		return h.fail(op, principal, ce)
	}
	bytesIn = int64(len(rawDoc))

	ctx, cancel, e := h.opCtx("permissions", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, principal, e)
	}
	defer cancel()
	scopeKey, e := h.permissionsScope()
	if e != nil {
		failed = true
		return h.fail(op, principal, e)
	}
	ovCtx := hostkit.WithEndpoint(ctx, scopeKey)

	if ce := h.checkPermissionsRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, principal, ce)
	}

	if dry {
		if ce := h.checkDryAttachHeadroom(ovCtx, scopeKey, hostkit.AttachmentPrincipal, "", principal); ce != nil {
			failed = true
			return h.fail(op, principal, ce)
		}
		for _, tgt := range targets {
			if ce := h.verifyTargetExistsAndOwned(true, tgt, true); ce != nil {
				failed = true
				return h.fail(op, principal, ce)
			}
		}
		h.ov(ovCtx).attachPolicy(hostkit.PolicyAttachment{
			Key:        hostkit.ScopedAttachmentKey(scopeKey, hostkit.AttachmentPrincipal, "", principal),
			Scope:      scopeKey,
			Kind:       hostkit.AttachmentPrincipal,
			Target:     "",
			Principal:  principal,
			Document:   rawDoc,
			Statements: clonePolicyStatements(policy.stmts),
		})
		h.ok()
		return nil
	}

	if h.cfg.Permissions == nil {
		failed = true
		return h.fail(op, principal, missingPermissions())
	}

	if ce := h.cost.checkPolicyAttachHeadroom(scopeKey, hostkit.AttachmentPrincipal, "", principal); ce != nil {
		failed = true
		return h.fail(op, principal, ce)
	}
	for _, tgt := range targets {
		if ce := h.verifyTargetExistsAndOwned(false, tgt, true); ce != nil {
			failed = true
			return h.fail(op, principal, ce)
		}
	}

	attKey := hostkit.ScopedAttachmentKey(scopeKey, hostkit.AttachmentPrincipal, "", principal)
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{
		Operation:   op,
		PayloadSize: bytesIn,
	}, safety.KindPolicyAttachment, attKey)
	if cerr != nil {
		failed = true
		return h.fail(op, principal, cerr)
	}

	att, cerr := h.cost.beginPolicyAttachIntent(scopeKey, hostkit.AttachmentPrincipal, "", principal, policy.stmts, rawDoc)
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return h.fail(op, principal, cerr)
	}
	h.errs.AddRedaction(att.OwnerToken)

	actx := hostkit.WithExpectedAttachment(hostkit.WithCreateToken(mctx, att.OwnerToken), att)
	err := h.cfg.Permissions.AttachPolicy(actx, att)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(bytesIn, bytesIn, true, err == nil)
	if abortErr != nil {
		failed = true
		return h.fail(op, principal, abortErr)
	}
	if err != nil {
		failed = true
		ce := hostkit.AsCloudError(err)
		if isDefinitivePolicyRefusal(ce) {
			_ = h.cost.abortPolicyIntent(att)
		}
		return h.fail(op, principal, ce)
	}
	if cerr := h.cost.confirmPolicyAttach(att); cerr != nil {
		failed = true
		return h.fail(op, principal, cerr)
	}
	h.ok()
	return nil
}

// PolicyDetach removes a resource-scoped policy attachment for (target, principal).
func (h *Host) PolicyDetach(dry bool, target, principal string) error {
	const op = "policy_detach"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	anchored, ce := hostkit.ValidateTargetEntity(target, *h.cfg.Validator)
	if ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}
	if ce := hostkit.ValidatePrincipal(principal); ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}

	ctx, cancel, e := h.opCtx("permissions", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, target, e)
	}
	defer cancel()
	scopeKey, e := h.permissionsScope()
	if e != nil {
		failed = true
		return h.fail(op, target, e)
	}
	ovCtx := hostkit.WithEndpoint(ctx, scopeKey)

	if ce := h.checkPermissionsRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, target, ce)
	}

	if dry {
		if ce := h.verifyTargetExistsAndOwned(true, anchored, true); ce != nil {
			failed = true
			return h.fail(op, target, ce)
		}
		h.ov(ovCtx).detachPolicy(hostkit.AttachmentResource, target, principal)
		h.ok()
		return nil
	}

	if h.cfg.Permissions == nil {
		failed = true
		return h.fail(op, target, missingPermissions())
	}

	ownedAtt, cerr := h.cost.hasOwnedPolicyAttachment(scopeKey, hostkit.AttachmentResource, target, principal)
	if cerr != nil {
		failed = true
		return h.fail(op, target, cerr)
	}
	if !ownedAtt {
		if ce := h.verifyTargetExistsAndOwned(false, anchored, true); ce != nil {
			failed = true
			return h.fail(op, target, ce)
		}
		h.ok()
		return nil
	}

	attKey := hostkit.ScopedAttachmentKey(scopeKey, hostkit.AttachmentResource, target, principal)
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, IsCleanup: true}, safety.KindPolicyAttachment, attKey)
	if cerr != nil {
		failed = true
		return h.fail(op, target, cerr)
	}

	existing, foundNow, cerr := h.cost.beginPolicyDetachIntent(scopeKey, hostkit.AttachmentResource, target, principal)
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return h.fail(op, target, cerr)
	}
	if !foundNow {
		if rerr := scope.releaseNotSent(); rerr != nil {
			failed = true
			return h.fail(op, target, rerr)
		}
		h.ok()
		return nil
	}
	h.errs.AddRedaction(existing.OwnerToken)

	dctx := hostkit.WithExpectedAttachment(hostkit.WithCreateToken(mctx, existing.OwnerToken), existing)
	err := h.cfg.Permissions.DetachPolicy(dctx, hostkit.AttachmentResource, target, principal)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, true, err == nil)
	if abortErr != nil {
		failed = true
		return h.fail(op, target, abortErr)
	}
	if err != nil {
		failed = true
		ce := hostkit.AsCloudError(err)
		if isDefinitivePolicyRefusal(ce) {
			_ = h.cost.abortPolicyIntent(existing)
		}
		return h.fail(op, target, ce)
	}
	if cerr := h.cost.confirmPolicyDetach(existing); cerr != nil {
		failed = true
		return h.fail(op, target, cerr)
	}
	h.ok()
	return nil
}

// PolicyDetachPrincipal removes an identity-scoped policy attachment for principal.
func (h *Host) PolicyDetachPrincipal(dry bool, principal string) error {
	const op = "policy_detach_principal"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	if ce := hostkit.ValidatePrincipal(principal); ce != nil {
		failed = true
		return h.fail(op, principal, ce)
	}

	ctx, cancel, e := h.opCtx("permissions", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, principal, e)
	}
	defer cancel()
	scopeKey, e := h.permissionsScope()
	if e != nil {
		failed = true
		return h.fail(op, principal, e)
	}
	ovCtx := hostkit.WithEndpoint(ctx, scopeKey)

	if ce := h.checkPermissionsRouteAllowed(ctx); ce != nil {
		failed = true
		return h.fail(op, principal, ce)
	}

	if dry {
		h.ov(ovCtx).detachPolicy(hostkit.AttachmentPrincipal, "", principal)
		h.ok()
		return nil
	}

	if h.cfg.Permissions == nil {
		failed = true
		return h.fail(op, principal, missingPermissions())
	}

	ownedAtt, cerr := h.cost.hasOwnedPolicyAttachment(scopeKey, hostkit.AttachmentPrincipal, "", principal)
	if cerr != nil {
		failed = true
		return h.fail(op, principal, cerr)
	}
	if !ownedAtt {
		h.ok()
		return nil
	}

	attKey := hostkit.ScopedAttachmentKey(scopeKey, hostkit.AttachmentPrincipal, "", principal)
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, IsCleanup: true}, safety.KindPolicyAttachment, attKey)
	if cerr != nil {
		failed = true
		return h.fail(op, principal, cerr)
	}

	existing, foundNow, cerr := h.cost.beginPolicyDetachIntent(scopeKey, hostkit.AttachmentPrincipal, "", principal)
	if cerr != nil {
		_ = scope.releaseNotSent()
		failed = true
		return h.fail(op, principal, cerr)
	}
	if !foundNow {
		if rerr := scope.releaseNotSent(); rerr != nil {
			failed = true
			return h.fail(op, principal, rerr)
		}
		h.ok()
		return nil
	}
	h.errs.AddRedaction(existing.OwnerToken)

	dctx := hostkit.WithExpectedAttachment(hostkit.WithCreateToken(mctx, existing.OwnerToken), existing)
	err := h.cfg.Permissions.DetachPolicy(dctx, hostkit.AttachmentPrincipal, "", principal)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, true, err == nil)
	if abortErr != nil {
		failed = true
		return h.fail(op, principal, abortErr)
	}
	if err != nil {
		failed = true
		ce := hostkit.AsCloudError(err)
		if isDefinitivePolicyRefusal(ce) {
			_ = h.cost.abortPolicyIntent(existing)
		}
		return h.fail(op, principal, ce)
	}
	if cerr := h.cost.confirmPolicyDetach(existing); cerr != nil {
		failed = true
		return h.fail(op, principal, cerr)
	}
	h.ok()
	return nil
}

// PolicyCheck evaluates whether principal is allowed to perform action on resource
// under the run's journaled policy attachments (default Deny, explicit Allow, Deny overrides Allow).
func (h *Host) PolicyCheck(dry bool, principal, action, resource string) (bool, error) {
	const op = "policy_check"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()

	anchored, ce := hostkit.ValidatePolicyCheckInputs(principal, action, resource, *h.cfg.Validator)
	if ce != nil {
		failed = true
		return false, h.fail(op, resource, ce)
	}

	ctx, cancel, e := h.opCtx("permissions", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, resource, e)
	}
	defer cancel()
	scopeKey, e := h.permissionsScope()
	if e != nil {
		failed = true
		return false, h.fail(op, resource, e)
	}
	ovCtx := hostkit.WithEndpoint(ctx, scopeKey)

	if ce := h.checkPermissionsRouteAllowed(ctx); ce != nil {
		failed = true
		return false, h.fail(op, resource, ce)
	}

	if dry {
		if ce := h.verifyTargetExistsAndOwned(true, anchored, false); ce != nil {
			failed = true
			return false, h.fail(op, resource, ce)
		}
		if ce := hostkit.ValidatePolicyCheckActionResourceType(action, resource, *h.cfg.Validator); ce != nil {
			failed = true
			return false, h.fail(op, resource, ce)
		}
		committed, cerr := h.cost.listPolicyAttachmentsForScope(scopeKey, principal)
		if cerr != nil {
			failed = true
			return false, h.fail(op, resource, cerr)
		}
		merged := h.ov(ovCtx).mergePolicies(committed)
		allowed := hostkit.EvaluatePolicies(merged, principal, action, resource)
		h.ok()
		return allowed, nil
	}

	if h.cfg.Permissions == nil {
		failed = true
		return false, h.fail(op, resource, missingPermissions())
	}

	if ce := h.verifyTargetExistsAndOwned(false, anchored, false); ce != nil {
		failed = true
		return false, h.fail(op, resource, ce)
	}
	if ce := hostkit.ValidatePolicyCheckActionResourceType(action, resource, *h.cfg.Validator); ce != nil {
		failed = true
		return false, h.fail(op, resource, ce)
	}

	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, targetSafetyKind(anchored.Kind), anchored.Name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, resource, cerr)
	}

	err := h.cfg.Permissions.CheckPolicy(mctx, principal, action, resource)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, true, err == nil)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, resource, abortErr)
	}
	if err != nil {
		failed = true
		return false, h.fail(op, resource, hostkit.AsCloudError(err))
	}

	attachments, cerr := h.cost.listPolicyAttachmentsForScope(scopeKey, principal)
	if cerr != nil {
		failed = true
		return false, h.fail(op, resource, cerr)
	}
	allowed := hostkit.EvaluatePolicies(attachments, principal, action, resource)
	h.ok()
	return allowed, nil
}
