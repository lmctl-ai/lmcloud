// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// guardStore and guardQueue pass every adapter error through
// hostkit.NilIfTyped, so an adapter that returns a typed-nil *CloudError
// through error is treated as success everywhere the host looks at errors.
// They also expose the optional interfaces of the wrapped adapter.
type guardStore struct{ s hostkit.ObjectStore }

var errNoTimer = hostkit.ProviderError(hostkit.Internal, 0, "", "adapter does not report creation times")

func (g guardStore) CreateBucket(ctx context.Context, b string) (bool, error) {
	v, err := g.s.CreateBucket(ctx, b)
	return v, hostkit.NilIfTyped(err)
}
func (g guardStore) DeleteBucket(ctx context.Context, b string) error {
	return hostkit.NilIfTyped(g.s.DeleteBucket(ctx, b))
}
func (g guardStore) HeadBucket(ctx context.Context, b string) error {
	return hostkit.NilIfTyped(g.s.HeadBucket(ctx, b))
}
func (g guardStore) ListBuckets(ctx context.Context, token string) ([]string, string, error) {
	v, next, err := g.s.ListBuckets(ctx, token)
	return v, next, hostkit.NilIfTyped(err)
}
func (g guardStore) PutObject(ctx context.Context, b, k string, body []byte, ct string, meta map[string]string) (hostkit.ObjectMeta, error) {
	v, err := g.s.PutObject(ctx, b, k, body, ct, meta)
	return v, hostkit.NilIfTyped(err)
}
func (g guardStore) GetObject(ctx context.Context, b, k string, limit int64) ([]byte, error) {
	v, err := g.s.GetObject(ctx, b, k, limit)
	return v, hostkit.NilIfTyped(err)
}
func (g guardStore) HeadObject(ctx context.Context, b, k string) (hostkit.ObjectMeta, error) {
	v, err := g.s.HeadObject(ctx, b, k)
	return v, hostkit.NilIfTyped(err)
}
func (g guardStore) DeleteObject(ctx context.Context, b, k string) error {
	return hostkit.NilIfTyped(g.s.DeleteObject(ctx, b, k))
}
func (g guardStore) ListObjects(ctx context.Context, b, prefix string, max int, token string) (hostkit.ObjectPage, error) {
	v, err := g.s.ListObjects(ctx, b, prefix, max, token)
	return v, hostkit.NilIfTyped(err)
}
func (g guardStore) BucketCreatedAt(ctx context.Context, b string) (time.Time, error) {
	if t, ok := g.s.(hostkit.BucketCreationTimer); ok {
		v, err := t.BucketCreatedAt(ctx, b)
		return v, hostkit.NilIfTyped(err)
	}
	return time.Time{}, errNoTimer
}

type guardQueue struct{ q hostkit.Queue }

func (g guardQueue) QueueCaps() hostkit.QueueCaps { return g.q.QueueCaps() }
func (g guardQueue) QueueCapsFor(ctx context.Context, queue string) hostkit.QueueCaps {
	return hostkit.CapsFor(ctx, g.q, queue)
}
func (g guardQueue) CreateQueue(ctx context.Context, q string) (bool, error) {
	v, err := g.q.CreateQueue(ctx, q)
	return v, hostkit.NilIfTyped(err)
}
func (g guardQueue) DeleteQueue(ctx context.Context, q string) error {
	return hostkit.NilIfTyped(g.q.DeleteQueue(ctx, q))
}
func (g guardQueue) LookupQueue(ctx context.Context, q string) error {
	return hostkit.NilIfTyped(g.q.LookupQueue(ctx, q))
}
func (g guardQueue) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	v, next, err := g.q.ListQueues(ctx, token)
	return v, next, hostkit.NilIfTyped(err)
}
func (g guardQueue) Send(ctx context.Context, q, wire string) (string, error) {
	v, err := g.q.Send(ctx, q, wire)
	return v, hostkit.NilIfTyped(err)
}
func (g guardQueue) Receive(ctx context.Context, q string, max, wait, vis int) ([]hostkit.RawMessage, error) {
	v, err := g.q.Receive(ctx, q, max, wait, vis)
	return v, hostkit.NilIfTyped(err)
}
func (g guardQueue) Ack(ctx context.Context, q, receipt string) error {
	return hostkit.NilIfTyped(g.q.Ack(ctx, q, receipt))
}
func (g guardQueue) Nack(ctx context.Context, q, receipt string, vis int) (string, error) {
	v, err := g.q.Nack(ctx, q, receipt, vis)
	return v, hostkit.NilIfTyped(err)
}
func (g guardQueue) QueueCreatedAt(ctx context.Context, q string) (time.Time, error) {
	if t, ok := g.q.(hostkit.QueueCreationTimer); ok {
		v, err := t.QueueCreatedAt(ctx, q)
		return v, hostkit.NilIfTyped(err)
	}
	return time.Time{}, errNoTimer
}

func (g guardStore) BucketCreateToken(ctx context.Context, b string) (string, error) {
	if r, ok := g.s.(hostkit.BucketCreateTokenReader); ok {
		v, err := r.BucketCreateToken(ctx, b)
		return v, hostkit.NilIfTyped(err)
	}
	return "", errNoToken
}

func (g guardQueue) QueueCreateToken(ctx context.Context, q string) (string, error) {
	if r, ok := g.q.(hostkit.QueueCreateTokenReader); ok {
		v, err := r.QueueCreateToken(ctx, q)
		return v, hostkit.NilIfTyped(err)
	}
	return "", errNoToken
}

var errNoToken = hostkit.ProviderError(hostkit.Internal, 0, "", "adapter does not store create tokens")
