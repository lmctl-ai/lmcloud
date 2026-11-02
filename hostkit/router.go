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

// isNilPointer catches a typed-nil backend (e.g. a nil *Client stored in a
// Backend), which would otherwise panic on the first method call.
func isNilPointer(v any) bool {
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
