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

type guardTables struct{ t hostkit.Tables }

func (g guardTables) CreateTable(ctx context.Context, name string, sorted bool) (bool, error) {
	v, err := g.t.CreateTable(ctx, name, sorted)
	return v, hostkit.NilIfTyped(err)
}
func (g guardTables) DeleteTable(ctx context.Context, name string) error {
	return hostkit.NilIfTyped(g.t.DeleteTable(ctx, name))
}
func (g guardTables) HeadTable(ctx context.Context, name string) error {
	return hostkit.NilIfTyped(g.t.HeadTable(ctx, name))
}
func (g guardTables) ListTables(ctx context.Context, token string) ([]string, string, error) {
	v, next, err := g.t.ListTables(ctx, token)
	return v, next, hostkit.NilIfTyped(err)
}
func (g guardTables) PutItem(ctx context.Context, table string, item hostkit.Item, mode hostkit.PutMode, expectVersion string) (hostkit.Item, error) {
	v, err := g.t.PutItem(ctx, table, item, mode, expectVersion)
	return v, hostkit.NilIfTyped(err)
}
func (g guardTables) GetItem(ctx context.Context, table, pk, sk string) (hostkit.Item, error) {
	v, err := g.t.GetItem(ctx, table, pk, sk)
	return v, hostkit.NilIfTyped(err)
}
func (g guardTables) DeleteItem(ctx context.Context, table, pk, sk string) error {
	return hostkit.NilIfTyped(g.t.DeleteItem(ctx, table, pk, sk))
}
func (g guardTables) UpdateItem(ctx context.Context, table, pk, sk string, changes hostkit.Item) (hostkit.Item, error) {
	v, err := g.t.UpdateItem(ctx, table, pk, sk, changes)
	return v, hostkit.NilIfTyped(err)
}
func (g guardTables) Query(ctx context.Context, table, pk, skFrom, skTo string, max int, token string) (hostkit.TablePage, error) {
	v, err := g.t.Query(ctx, table, pk, skFrom, skTo, max, token)
	return v, hostkit.NilIfTyped(err)
}
func (g guardTables) Scan(ctx context.Context, table string, max int, token string) (hostkit.TablePage, error) {
	v, err := g.t.Scan(ctx, table, max, token)
	return v, hostkit.NilIfTyped(err)
}
func (g guardTables) TableCreateToken(ctx context.Context, table string) (string, error) {
	if r, ok := g.t.(hostkit.TableCreateTokenReader); ok {
		v, err := r.TableCreateToken(ctx, table)
		return v, hostkit.NilIfTyped(err)
	}
	return "", errNoToken
}

func (g guardTables) DescribeTable(ctx context.Context, table string) (hostkit.TableInfo, error) {
	v, err := g.t.DescribeTable(ctx, table)
	return v, hostkit.NilIfTyped(err)
}

type guardPermissions struct{ p hostkit.Permissions }

func (g guardPermissions) CurrentPrincipal(ctx context.Context) (string, error) {
	v, err := g.p.CurrentPrincipal(ctx)
	return v, hostkit.NilIfTyped(err)
}

func (g guardPermissions) AttachPolicy(ctx context.Context, att hostkit.PolicyAttachment) error {
	return hostkit.NilIfTyped(g.p.AttachPolicy(ctx, att))
}

func (g guardPermissions) DetachPolicy(ctx context.Context, kind hostkit.AttachmentKind, target, principal string) error {
	return hostkit.NilIfTyped(g.p.DetachPolicy(ctx, kind, target, principal))
}

func (g guardPermissions) CheckPolicy(ctx context.Context, principal, action, resource string) error {
	return hostkit.NilIfTyped(g.p.CheckPolicy(ctx, principal, action, resource))
}

type guardFunctions struct{ f hostkit.Functions }

func (g guardFunctions) CreateFunction(ctx context.Context, in hostkit.FunctionUpdateInput) (bool, hostkit.FunctionSnapshot, error) {
	created, v, err := g.f.CreateFunction(ctx, in)
	return created, v, hostkit.NilIfTyped(err)
}

func (g guardFunctions) UpdateFunction(ctx context.Context, in hostkit.FunctionUpdateInput) (hostkit.FunctionSnapshot, error) {
	v, err := g.f.UpdateFunction(ctx, in)
	return v, hostkit.NilIfTyped(err)
}

func (g guardFunctions) DeleteFunction(ctx context.Context, name string) (bool, error) {
	existed, err := g.f.DeleteFunction(ctx, name)
	return existed, hostkit.NilIfTyped(err)
}

func (g guardFunctions) FunctionExists(ctx context.Context, name string) (bool, error) {
	v, err := g.f.FunctionExists(ctx, name)
	return v, hostkit.NilIfTyped(err)
}

func (g guardFunctions) GetFunction(ctx context.Context, name, qualifier string) (hostkit.FunctionSnapshot, error) {
	v, err := g.f.GetFunction(ctx, name, qualifier)
	return v, hostkit.NilIfTyped(err)
}

func (g guardFunctions) ListFunctions(ctx context.Context) ([]string, error) {
	v, err := g.f.ListFunctions(ctx)
	return v, hostkit.NilIfTyped(err)
}

func (g guardFunctions) PublishFunctionVersion(ctx context.Context, name, expectRevision string) (string, error) {
	ver, err := g.f.PublishFunctionVersion(ctx, name, expectRevision)
	return ver, hostkit.NilIfTyped(err)
}

func (g guardFunctions) ListFunctionVersions(ctx context.Context, name string) ([]string, error) {
	v, err := g.f.ListFunctionVersions(ctx, name)
	return v, hostkit.NilIfTyped(err)
}

func (g guardFunctions) SetFunctionAlias(ctx context.Context, name, alias, version string) (bool, error) {
	created, err := g.f.SetFunctionAlias(ctx, name, alias, version)
	return created, hostkit.NilIfTyped(err)
}

func (g guardFunctions) GetFunctionAlias(ctx context.Context, name, alias string) (string, error) {
	v, err := g.f.GetFunctionAlias(ctx, name, alias)
	return v, hostkit.NilIfTyped(err)
}

func (g guardFunctions) DeleteFunctionAlias(ctx context.Context, name, alias string) (bool, error) {
	existed, err := g.f.DeleteFunctionAlias(ctx, name, alias)
	return existed, hostkit.NilIfTyped(err)
}

func (g guardFunctions) InvokeFunction(ctx context.Context, in hostkit.FunctionInvokeInput) (hostkit.FunctionInvokeOutput, error) {
	v, err := g.f.InvokeFunction(ctx, in)
	return v, hostkit.NilIfTyped(err)
}

func (g guardFunctions) PeekFunctionQuota(ctx context.Context, name, qualifier string) (int64, int64, bool) {
	if p, ok := g.f.(hostkit.FunctionQuotaPeeker); ok {
		return p.PeekFunctionQuota(ctx, name, qualifier)
	}
	return 0, 0, false
}

func (g guardFunctions) PeekFunctionVersionHeadroom(ctx context.Context, name, expectRevision string) (string, error) {
	if p, ok := g.f.(hostkit.FunctionQuotaPeeker); ok {
		v, err := p.PeekFunctionVersionHeadroom(ctx, name, expectRevision)
		return v, hostkit.NilIfTyped(err)
	}
	return "", nil
}

func (g guardFunctions) PeekFunctionAliasHeadroom(ctx context.Context, name, alias, version string) (bool, error) {
	if p, ok := g.f.(hostkit.FunctionQuotaPeeker); ok {
		created, err := p.PeekFunctionAliasHeadroom(ctx, name, alias, version)
		return created, hostkit.NilIfTyped(err)
	}
	return true, nil
}

func (g guardFunctions) FunctionOwnerToken(ctx context.Context, name string) (string, bool, error) {
	if r, ok := g.f.(hostkit.FunctionOwnershipReader); ok {
		v, ex, err := r.FunctionOwnerToken(ctx, name)
		return v, ex, hostkit.NilIfTyped(err)
	}
	return "", false, errNoToken
}

var errNoToken = hostkit.ProviderError(hostkit.Internal, 0, "", "adapter does not store create tokens")
