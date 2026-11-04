// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"net/url"
	"reflect"
	"time"
)

// Backend is a provider adapter that serves both slices.
type Backend interface {
	ObjectStore
	Queue
}

// Router forwards every adapter call to the backend chosen per call, so a
// host that keeps several backends (an offline fake, a simulator client, a
// live client) writes one Pick function instead of one router method per
// operation. It implements ObjectStore, Queue, QueueCapsProvider and the
// optional create-token readers (and the deprecated creation timers); optional
// interfaces forward when the chosen backend implements them.
type Router struct {
	// Pick chooses the backend for this call, usually from EndpointFrom(ctx).
	// Returning an error fails the call with that error.
	Pick func(ctx context.Context) (Backend, error)
}

// EndpointRoutes is the common Pick policy: no endpoint override uses
// Offline (or Live when Offline is nil), a loopback endpoint uses Sim, any
// other endpoint uses Live. A nil backend for the selected route returns
// Unavailable (or a default INTERNAL error).
type EndpointRoutes struct {
	Offline, Sim, Live Backend
	// UseLive forces Live even without an endpoint (e.g. an explicit
	// LM<PROVIDER>_LIVE=1); nil means never.
	UseLive func() bool
	// Unavailable builds the error for a route with no backend.
	Unavailable func(route string) error
}

type forbidLiveRouteKey struct{}

// WithForbidLiveRoute marks ctx so EndpointRoutes.Pick refuses any route that
// resolves to the live cloud backend.
func WithForbidLiveRoute(ctx context.Context) context.Context {
	return context.WithValue(ctx, forbidLiveRouteKey{}, true)
}

// ForbidLiveRouteFrom reports whether ctx forbids routing to the live backend.
func ForbidLiveRouteFrom(ctx context.Context) bool {
	v, _ := ctx.Value(forbidLiveRouteKey{}).(bool)
	return v
}

// IsLoopbackEndpoint reports whether ep is a valid URL with a loopback host.
func IsLoopbackEndpoint(ep string) bool {
	if ep == "" {
		return false
	}
	u, err := url.Parse(ep)
	return err == nil && IsLoopbackHost(u.Hostname())
}

// Pick implements the routing policy for Router.Pick.
func (e EndpointRoutes) Pick(ctx context.Context) (Backend, error) {
	ep := EndpointFrom(ctx)
	var route string
	var b Backend
	switch {
	case ep == "" && (e.UseLive == nil || !e.UseLive()) && e.Offline != nil:
		route, b = "offline", e.Offline
	case ep == "":
		route, b = "live", e.Live
	default:
		u, err := url.Parse(ep)
		if err == nil && IsLoopbackHost(u.Hostname()) {
			route, b = "sim", e.Sim
		} else {
			route, b = "live", e.Live
		}
	}
	if route == "live" && ForbidLiveRouteFrom(ctx) {
		return nil, ProviderError(PermissionDenied, 403, "LiveModeUnsupported", "operation is not enabled for live cloud routes")
	}
	if b != nil {
		return b, nil
	}
	if e.Unavailable != nil {
		return nil, e.Unavailable(route)
	}
	return nil, ProviderError(Internal, 0, "", "no "+route+" backend is configured for this host")
}

func (r Router) pick(ctx context.Context) (Backend, error) {
	if r.Pick == nil {
		return nil, ProviderError(Internal, 0, "", "router has no Pick function")
	}
	b, err := r.Pick(ctx)
	if err = NilIfTyped(err); err != nil {
		return nil, err
	}
	if b == nil || isNilPointer(b) {
		return nil, ProviderError(Internal, 0, "", "router picked no backend")
	}
	return b, nil
}

func (r Router) CreateBucket(ctx context.Context, b string) (bool, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return false, err
	}
	return be.CreateBucket(ctx, b)
}

func (r Router) DeleteBucket(ctx context.Context, b string) error {
	be, err := r.pick(ctx)
	if err != nil {
		return err
	}
	return be.DeleteBucket(ctx, b)
}

func (r Router) HeadBucket(ctx context.Context, b string) error {
	be, err := r.pick(ctx)
	if err != nil {
		return err
	}
	return be.HeadBucket(ctx, b)
}

func (r Router) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return nil, "", err
	}
	return be.ListBuckets(ctx, token)
}

func (r Router) PutObject(ctx context.Context, b, k string, body []byte, ct string, meta map[string]string) (ObjectMeta, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return ObjectMeta{}, err
	}
	return be.PutObject(ctx, b, k, body, ct, meta)
}

func (r Router) GetObject(ctx context.Context, b, k string, limit int64) ([]byte, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return nil, err
	}
	return be.GetObject(ctx, b, k, limit)
}

func (r Router) HeadObject(ctx context.Context, b, k string) (ObjectMeta, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return ObjectMeta{}, err
	}
	return be.HeadObject(ctx, b, k)
}

func (r Router) DeleteObject(ctx context.Context, b, k string) error {
	be, err := r.pick(ctx)
	if err != nil {
		return err
	}
	return be.DeleteObject(ctx, b, k)
}

func (r Router) ListObjects(ctx context.Context, b, prefix string, max int, token string) (ObjectPage, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return ObjectPage{}, err
	}
	return be.ListObjects(ctx, b, prefix, max, token)
}

// QueueCaps is only a fallback: the host asks QueueCapsFor per call. It
// reports the conservative caps (no long poll, text-only wire).
func (r Router) QueueCaps() QueueCaps { return QueueCaps{LongPoll: false, TextOnlyWire: true} }

// QueueCapsFor reports the chosen backend's caps for this call.
func (r Router) QueueCapsFor(ctx context.Context, queue string) QueueCaps {
	be, err := r.pick(ctx)
	if err != nil {
		return r.QueueCaps()
	}
	return CapsFor(ctx, be, queue)
}

// CapsFor returns q's caps for this call, preferring QueueCapsProvider.
func CapsFor(ctx context.Context, q Queue, queue string) QueueCaps {
	if p, ok := q.(QueueCapsProvider); ok {
		return p.QueueCapsFor(ctx, queue)
	}
	return q.QueueCaps()
}

func (r Router) CreateQueue(ctx context.Context, q string) (bool, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return false, err
	}
	return be.CreateQueue(ctx, q)
}

func (r Router) DeleteQueue(ctx context.Context, q string) error {
	be, err := r.pick(ctx)
	if err != nil {
		return err
	}
	return be.DeleteQueue(ctx, q)
}

func (r Router) LookupQueue(ctx context.Context, q string) error {
	be, err := r.pick(ctx)
	if err != nil {
		return err
	}
	return be.LookupQueue(ctx, q)
}

func (r Router) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return nil, "", err
	}
	return be.ListQueues(ctx, token)
}

func (r Router) Send(ctx context.Context, q, wire string) (string, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return "", err
	}
	return be.Send(ctx, q, wire)
}

func (r Router) Receive(ctx context.Context, q string, max, wait, vis int) ([]RawMessage, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return nil, err
	}
	return be.Receive(ctx, q, max, wait, vis)
}

func (r Router) Ack(ctx context.Context, q, receipt string) error {
	be, err := r.pick(ctx)
	if err != nil {
		return err
	}
	return be.Ack(ctx, q, receipt)
}

func (r Router) Nack(ctx context.Context, q, receipt string, vis int) (string, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return "", err
	}
	return be.Nack(ctx, q, receipt, vis)
}

// errNoTimer is returned when the chosen backend cannot report creation times.
var errNoTimer = ProviderError(Internal, 0, "", "backend does not report creation times")

func (r Router) BucketCreatedAt(ctx context.Context, b string) (time.Time, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if t, ok := be.(BucketCreationTimer); ok {
		return t.BucketCreatedAt(ctx, b)
	}
	return time.Time{}, errNoTimer
}

func (r Router) QueueCreatedAt(ctx context.Context, q string) (time.Time, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if t, ok := be.(QueueCreationTimer); ok {
		return t.QueueCreatedAt(ctx, q)
	}
	return time.Time{}, errNoTimer
}

var errNoToken = ProviderError(Internal, 0, "", "backend does not store create tokens")

func (r Router) BucketCreateToken(ctx context.Context, b string) (string, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return "", err
	}
	if t, ok := be.(BucketCreateTokenReader); ok {
		return t.BucketCreateToken(ctx, b)
	}
	return "", errNoToken
}

func (r Router) QueueCreateToken(ctx context.Context, q string) (string, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return "", err
	}
	if t, ok := be.(QueueCreateTokenReader); ok {
		return t.QueueCreateToken(ctx, q)
	}
	return "", errNoToken
}

func (r Router) TableCreateToken(ctx context.Context, table string) (string, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return "", err
	}
	if t, ok := be.(TableCreateTokenReader); ok {
		return t.TableCreateToken(ctx, table)
	}
	return "", errNoToken
}

func (r Router) DescribeTable(ctx context.Context, table string) (TableInfo, error) {
	t, err := r.pickTables(ctx)
	if err != nil {
		return TableInfo{}, err
	}
	return t.DescribeTable(ctx, table)
}

var errNoTables = ProviderError(Internal, 0, "", "backend does not support tables")

func (r Router) pickTables(ctx context.Context) (Tables, error) {
	be, err := r.pick(ctx)
	if err != nil {
		return nil, err
	}
	if t, ok := be.(Tables); ok {
		return t, nil
	}
	return nil, errNoTables
}

func (r Router) CreateTable(ctx context.Context, name string, sorted bool) (bool, error) {
	t, err := r.pickTables(ctx)
	if err != nil {
		return false, err
	}
	return t.CreateTable(ctx, name, sorted)
}

func (r Router) DeleteTable(ctx context.Context, name string) error {
	t, err := r.pickTables(ctx)
	if err != nil {
		return err
	}
	return t.DeleteTable(ctx, name)
}

func (r Router) HeadTable(ctx context.Context, name string) error {
	t, err := r.pickTables(ctx)
	if err != nil {
		return err
	}
	return t.HeadTable(ctx, name)
}

func (r Router) ListTables(ctx context.Context, token string) ([]string, string, error) {
	t, err := r.pickTables(ctx)
	if err != nil {
		return nil, "", err
	}
	return t.ListTables(ctx, token)
}

func (r Router) PutItem(ctx context.Context, table string, item Item, mode PutMode, expectVersion string) (Item, error) {
	t, err := r.pickTables(ctx)
	if err != nil {
		return Item{}, err
	}
	return t.PutItem(ctx, table, item, mode, expectVersion)
}

func (r Router) GetItem(ctx context.Context, table, pk, sk string) (Item, error) {
	t, err := r.pickTables(ctx)
	if err != nil {
		return Item{}, err
	}
	return t.GetItem(ctx, table, pk, sk)
}

func (r Router) DeleteItem(ctx context.Context, table, pk, sk string) error {
	t, err := r.pickTables(ctx)
	if err != nil {
		return err
	}
	return t.DeleteItem(ctx, table, pk, sk)
}

func (r Router) UpdateItem(ctx context.Context, table, pk, sk string, changes Item) (Item, error) {
	t, err := r.pickTables(ctx)
	if err != nil {
		return Item{}, err
	}
	return t.UpdateItem(ctx, table, pk, sk, changes)
}

func (r Router) Query(ctx context.Context, table, pk, skFrom, skTo string, max int, token string) (TablePage, error) {
	t, err := r.pickTables(ctx)
	if err != nil {
		return TablePage{}, err
	}
	return t.Query(ctx, table, pk, skFrom, skTo, max, token)
}

func (r Router) Scan(ctx context.Context, table string, max int, token string) (TablePage, error) {
	t, err := r.pickTables(ctx)
	if err != nil {
		return TablePage{}, err
	}
	return t.Scan(ctx, table, max, token)
}

var errNoPermissions = ProviderError(Internal, 0, "", "backend does not support permissions")

func (r Router) pickPermissions(ctx context.Context) (Permissions, error) {
	be, err := r.pick(WithForbidLiveRoute(ctx))
	if err != nil {
		return nil, err
	}
	if p, ok := be.(Permissions); ok && !isNilPointer(p) {
		return p, nil
	}
	return nil, errNoPermissions
}

func (r Router) CurrentPrincipal(ctx context.Context) (string, error) {
	p, err := r.pickPermissions(ctx)
	if err != nil {
		return "", err
	}
	return p.CurrentPrincipal(ctx)
}

func (r Router) AttachPolicy(ctx context.Context, att PolicyAttachment) error {
	p, err := r.pickPermissions(ctx)
	if err != nil {
		return err
	}
	return p.AttachPolicy(ctx, att)
}

func (r Router) DetachPolicy(ctx context.Context, kind AttachmentKind, target, principal string) error {
	p, err := r.pickPermissions(ctx)
	if err != nil {
		return err
	}
	return p.DetachPolicy(ctx, kind, target, principal)
}

func (r Router) CheckPolicy(ctx context.Context, principal, action, resource string) error {
	p, err := r.pickPermissions(ctx)
	if err != nil {
		return err
	}
	return p.CheckPolicy(ctx, principal, action, resource)
}

var errNoFunctions = ProviderError(Internal, 0, "", "backend does not support functions")

func (r Router) pickFunctions(ctx context.Context) (Functions, error) {
	be, err := r.pick(WithForbidLiveRoute(ctx))
	if err != nil {
		return nil, err
	}
	if fn, ok := be.(Functions); ok && !isNilPointer(fn) {
		return fn, nil
	}
	return nil, errNoFunctions
}

func (r Router) CreateFunction(ctx context.Context, in FunctionUpdateInput) (bool, FunctionSnapshot, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return false, FunctionSnapshot{}, err
	}
	return fn.CreateFunction(ctx, in)
}

func (r Router) UpdateFunction(ctx context.Context, in FunctionUpdateInput) (FunctionSnapshot, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return FunctionSnapshot{}, err
	}
	return fn.UpdateFunction(ctx, in)
}

func (r Router) DeleteFunction(ctx context.Context, name string) (bool, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return false, err
	}
	return fn.DeleteFunction(ctx, name)
}

func (r Router) FunctionExists(ctx context.Context, name string) (bool, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return false, err
	}
	return fn.FunctionExists(ctx, name)
}

func (r Router) GetFunction(ctx context.Context, name, qualifier string) (FunctionSnapshot, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return FunctionSnapshot{}, err
	}
	return fn.GetFunction(ctx, name, qualifier)
}

func (r Router) ListFunctions(ctx context.Context) ([]string, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return nil, err
	}
	return fn.ListFunctions(ctx)
}

func (r Router) PublishFunctionVersion(ctx context.Context, name, expectRevision string) (string, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return "", err
	}
	return fn.PublishFunctionVersion(ctx, name, expectRevision)
}

func (r Router) ListFunctionVersions(ctx context.Context, name string) ([]string, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return nil, err
	}
	return fn.ListFunctionVersions(ctx, name)
}

func (r Router) SetFunctionAlias(ctx context.Context, name, alias, version string) (bool, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return false, err
	}
	return fn.SetFunctionAlias(ctx, name, alias, version)
}

func (r Router) GetFunctionAlias(ctx context.Context, name, alias string) (string, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return "", err
	}
	return fn.GetFunctionAlias(ctx, name, alias)
}

func (r Router) DeleteFunctionAlias(ctx context.Context, name, alias string) (bool, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return false, err
	}
	return fn.DeleteFunctionAlias(ctx, name, alias)
}

func (r Router) InvokeFunction(ctx context.Context, in FunctionInvokeInput) (FunctionInvokeOutput, error) {
	fn, err := r.pickFunctions(ctx)
	if err != nil {
		return FunctionInvokeOutput{}, err
	}
	return fn.InvokeFunction(ctx, in)
}

func (r Router) PeekFunctionQuota(ctx context.Context, name, qualifier string) (int64, int64, bool) {
	be, err := r.pick(WithForbidLiveRoute(ctx))
	if err != nil {
		return 0, 0, false
	}
	if p, ok := be.(FunctionQuotaPeeker); ok && !isNilPointer(p) {
		return p.PeekFunctionQuota(ctx, name, qualifier)
	}
	return 0, 0, false
}

func (r Router) PeekFunctionVersionHeadroom(ctx context.Context, name, expectRevision string) (string, error) {
	be, err := r.pick(WithForbidLiveRoute(ctx))
	if err != nil {
		return "", err
	}
	if p, ok := be.(FunctionQuotaPeeker); ok && !isNilPointer(p) {
		return p.PeekFunctionVersionHeadroom(ctx, name, expectRevision)
	}
	return "", nil
}

func (r Router) PeekFunctionAliasHeadroom(ctx context.Context, name, alias, version string) (bool, error) {
	be, err := r.pick(WithForbidLiveRoute(ctx))
	if err != nil {
		return true, err
	}
	if p, ok := be.(FunctionQuotaPeeker); ok && !isNilPointer(p) {
		return p.PeekFunctionAliasHeadroom(ctx, name, alias, version)
	}
	return true, nil
}

func (r Router) FunctionOwnerToken(ctx context.Context, name string) (string, bool, error) {
	be, err := r.pick(WithForbidLiveRoute(ctx))
	if err != nil {
		return "", false, err
	}
	if or, ok := be.(FunctionOwnershipReader); ok && !isNilPointer(or) {
		return or.FunctionOwnerToken(ctx, name)
	}
	return "", false, errNoToken
}

// isNilPointer catches a typed-nil backend (e.g. a nil *Client stored in a
// Backend), which would otherwise panic on the first method call.
func isNilPointer(v any) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
