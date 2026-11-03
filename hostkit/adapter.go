// SPDX-License-Identifier: MIT

package hostkit

import (
	"context"
	"time"
)

// ObjectMeta is the normalized object metadata snapshot.
type ObjectMeta struct {
	Exists      bool
	Bucket      string
	Key         string
	Size        int64
	ETag        string
	ContentType string
	Metadata    map[string]string
}

// ObjectSummary is one list entry.
type ObjectSummary struct {
	Key  string
	Size int64
	ETag string
}

// ObjectPage is one list page. NextToken is "" on the last page.
type ObjectPage struct {
	Items     []ObjectSummary
	NextToken string
}

// ObjectStore is the provider adapter for the object storage slice. The host
// has already validated every argument and attached the resolved endpoint to
// ctx (EndpointFrom). Errors must be *CloudError classified onto the shared
// enum; any other error is reported as INTERNAL. See durable-memory/09-hostkit.md.
type ObjectStore interface {
	// CreateBucket returns created=true for a new bucket. A provider that can
	// tell the bucket is already owned returns (false, nil); otherwise it
	// returns CONFLICT and the host probes HeadBucket to decide.
	CreateBucket(ctx context.Context, bucket string) (created bool, err error)
	// DeleteBucket deletes an empty bucket; NOT_FOUND when absent, CONFLICT when not empty.
	DeleteBucket(ctx context.Context, bucket string) error
	// HeadBucket returns nil when the bucket exists and is accessible; NOT_FOUND
	// only for a genuine absence (never for an ambiguous denial).
	HeadBucket(ctx context.Context, bucket string) error
	// ListBuckets returns one page of bucket names.
	ListBuckets(ctx context.Context, token string) (names []string, next string, err error)
	// PutObject stores body and returns the resulting metadata (ETag unquoted).
	PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (ObjectMeta, error)
	// GetObject returns the body, failing (never truncating) above limit bytes; use ReadBounded.
	GetObject(ctx context.Context, bucket, key string, limit int64) ([]byte, error)
	// HeadObject returns metadata. A missing object is NOT_FOUND with Absent
	// object or bucket when the provider says which; ambiguous denials are
	// PERMISSION_DENIED.
	HeadObject(ctx context.Context, bucket, key string) (ObjectMeta, error)
	// DeleteObject deletes a key; NOT_FOUND (with Absent when known) if missing.
	DeleteObject(ctx context.Context, bucket, key string) error
	// ListObjects returns one page of at most max keys in byte order after token.
	ListObjects(ctx context.Context, bucket, prefix string, max int, token string) (ObjectPage, error)
}

// RawMessage is a received message in wire form.
type RawMessage struct {
	ID      string
	Wire    string
	Receipt string
}

// QueueCaps declares transport properties the host must compensate for.
type QueueCaps struct {
	// LongPoll is true when Receive itself honours waitSeconds. When false the
	// host calls Receive with waitSeconds=0 inside WaitLoop.
	LongPoll bool
	// TextOnlyWire is true when message bodies travel as JSON/XML text (the host
	// then applies the __lmcloud_b64__ envelope to unsafe bytes). False when the
	// adapter base64-encodes the whole message itself.
	TextOnlyWire bool
	// MaxMessageWireBytes, when > 0, is the adapter-attested maximum wire bytes
	// a single received message can occupy on the provider transport.
	MaxMessageWireBytes int64
	// MaxBatchWireBytes, when > 0, is the adapter-attested maximum wire bytes
	// a single Receive response batch can occupy on the provider transport.
	MaxBatchWireBytes int64
}

// Queue is the provider adapter for the queue slice.
type Queue interface {
	QueueCaps() QueueCaps
	// CreateQueue returns created=true for a new queue, (false, nil) if it already exists.
	CreateQueue(ctx context.Context, queue string) (created bool, err error)
	// DeleteQueue deletes a queue; NOT_FOUND when absent.
	DeleteQueue(ctx context.Context, queue string) error
	// LookupQueue returns nil when the queue exists; NOT_FOUND when absent.
	LookupQueue(ctx context.Context, queue string) error
	// ListQueues returns one page of queue names.
	ListQueues(ctx context.Context, token string) (names []string, next string, err error)
	// Send enqueues an already-encoded wire body and returns the message ID.
	Send(ctx context.Context, queue, wire string) (id string, err error)
	// Receive returns up to max messages, hiding them for visibility seconds.
	Receive(ctx context.Context, queue string, max, waitSeconds, visibility int) ([]RawMessage, error)
	// Ack deletes the message. NOT_FOUND Absent=message for an already-gone
	// message, Absent=queue for a missing queue, INVALID_ARGUMENT for a receipt
	// the provider rejects as malformed.
	Ack(ctx context.Context, queue, receipt string) error
	// Nack changes visibility and returns the receipt valid from now on.
	Nack(ctx context.Context, queue, receipt string, visibility int) (newReceipt string, err error)
}

// QueueCapsProvider is optional: a Queue that implements it reports caps per
// call (for example per route or per queue) and the host uses it instead of
// QueueCaps(). QueueCaps() stays for source compatibility.
type QueueCapsProvider interface {
	QueueCapsFor(ctx context.Context, queue string) QueueCaps
}

// BucketCreationTimer returns a bucket's server-side creation time.
//
// Deprecated: since hostkit v3 the host no longer uses creation times as
// proof of ownership (clock skew and concurrent creators make it unsound);
// implement BucketCreateTokenReader instead. Kept for source compatibility.
type BucketCreationTimer interface {
	BucketCreatedAt(ctx context.Context, bucket string) (time.Time, error)
}

// QueueCreationTimer is the queue counterpart of BucketCreationTimer.
//
// Deprecated: ignored since hostkit v3; implement QueueCreateTokenReader.
type QueueCreationTimer interface {
	QueueCreatedAt(ctx context.Context, queue string) (time.Time, error)
}

type createTokenKey struct{}

// WithCreateToken attaches the per-call create token (the host does this for
// every bucket_create/queue_create before calling the adapter).
func WithCreateToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, createTokenKey{}, token)
}

// CreateToken returns the token of the create call in ctx ("" if none). An
// adapter implementing a CreateTokenReader must store it on the resource
// atomically, in the same provider request that creates the resource (a tag,
// label or metadata field of the create call), so that reading it back proves
// which create request made the resource.
func CreateToken(ctx context.Context) string {
	v, _ := ctx.Value(createTokenKey{}).(string)
	return v
}

// BucketCreateTokenReader is optional. When CreateBucket reports CONFLICT and
// the bucket is accessible, the host reads the token stored at creation: it
// returns created=true only if it equals this call's CreateToken (an earlier
// attempt of the same call created it); in every other case created=false.
// Return ("", nil) when the bucket carries no token.
type BucketCreateTokenReader interface {
	BucketCreateToken(ctx context.Context, bucket string) (string, error)
}

// QueueCreateTokenReader is the queue counterpart of BucketCreateTokenReader.
type QueueCreateTokenReader interface {
	QueueCreateToken(ctx context.Context, queue string) (string, error)
}

// TableCreateTokenReader is the tables counterpart of BucketCreateTokenReader.
type TableCreateTokenReader interface {
	TableCreateToken(ctx context.Context, table string) (string, error)
}

// TableInfo describes an existing table's authoritative key layout and creation token.
type TableInfo struct {
	Sorted      bool
	CreateToken string
}

// TableDescriber returns an existing table's key layout (sorted vs key-only)
// and creation token in a single read-only probe. It is part of the required
// Tables interface and kept as a named sub-interface for callers that only
// inspect table metadata.
type TableDescriber interface {
	DescribeTable(ctx context.Context, table string) (TableInfo, error)
}

// TableOpMetrics carries authoritative prior/deleted item billing telemetry
// reported by a Tables adapter during PutItem, UpdateItem, or DeleteItem.
type TableOpMetrics struct {
	PriorExists   bool
	PriorBytes    int64
	NewBytes      int64
	Authoritative bool
}

type tableOpMetricsKey struct{}

// WithTableOpMetrics attaches a TableOpMetrics sink to ctx.
func WithTableOpMetrics(ctx context.Context, sink *TableOpMetrics) context.Context {
	return context.WithValue(ctx, tableOpMetricsKey{}, sink)
}

// ReportTableOpMetrics records m into the TableOpMetrics sink attached to ctx, if any.
func ReportTableOpMetrics(ctx context.Context, m TableOpMetrics) {
	if sink, ok := ctx.Value(tableOpMetricsKey{}).(*TableOpMetrics); ok && sink != nil {
		if m.PriorExists {
			sink.PriorExists = true
		}
		if m.PriorBytes > sink.PriorBytes {
			sink.PriorBytes = m.PriorBytes
		}
		if m.NewBytes > sink.NewBytes {
			sink.NewBytes = m.NewBytes
		}
		if m.Authoritative {
			sink.Authoritative = true
		}
	}
}

// PutMode selects the write precondition for Tables.PutItem.
type PutMode int

const (
	PutUnconditional PutMode = iota // item_put(table, item)
	PutIfAbsent                     // item_put_if_absent(table, item)
	PutIfVersion                    // item_put_if_version(table, item, expectVersion)
)

// Attribute type tag constants returned by TableItem.attr_type / Attr.Kind.
const (
	AttrString = "string"
	AttrInt    = "int"
	AttrNumber = "number"
	AttrBool   = "bool"
)

// Attr is one typed attribute value. Exactly one pointer is non-nil.
type Attr struct {
	S *string  `json:"s,omitempty"`
	I *int64   `json:"i,omitempty"`
	N *float64 `json:"n,omitempty"`
	B *bool    `json:"b,omitempty"`
}

// StringAttr constructs a string Attr.
func StringAttr(v string) Attr { return Attr{S: &v} }

// IntAttr constructs an int64 Attr.
func IntAttr(v int64) Attr { return Attr{I: &v} }

// NumberAttr constructs a float64 Attr.
func NumberAttr(v float64) Attr { return Attr{N: &v} }

// BoolAttr constructs a bool Attr.
func BoolAttr(v bool) Attr { return Attr{B: &v} }

// Kind returns the schema type tag ("string", "int", "number", "bool") or "" if unset.
func (a Attr) Kind() string {
	switch {
	case a.S != nil:
		return AttrString
	case a.I != nil:
		return AttrInt
	case a.N != nil:
		return AttrNumber
	case a.B != nil:
		return AttrBool
	default:
		return ""
	}
}

// CanonicalValueBytes returns the canonical value byte cost for item budget calculation.
func (a Attr) CanonicalValueBytes() int {
	switch {
	case a.S != nil:
		return len(*a.S)
	case a.I != nil:
		return 8
	case a.N != nil:
		return 8
	case a.B != nil:
		return 1
	default:
		return 0
	}
}

// Clone returns an independent copy of a.
func (a Attr) Clone() Attr {
	switch {
	case a.S != nil:
		v := *a.S
		return Attr{S: &v}
	case a.I != nil:
		v := *a.I
		return Attr{I: &v}
	case a.N != nil:
		v := *a.N
		return Attr{N: &v}
	case a.B != nil:
		v := *a.B
		return Attr{B: &v}
	default:
		return Attr{}
	}
}

// Item is the normalized table item value passed between host and adapter.
type Item struct {
	PK      string          `json:"pk"`
	SK      string          `json:"sk,omitempty"`
	Version string          `json:"version,omitempty"`
	Exists  bool            `json:"exists"`
	Attrs   map[string]Attr `json:"attrs,omitempty"`
}

// Clone returns a deep copy of it.
func (it Item) Clone() Item {
	out := Item{
		PK:      it.PK,
		SK:      it.SK,
		Version: it.Version,
		Exists:  it.Exists,
	}
	if it.Attrs != nil {
		out.Attrs = make(map[string]Attr, len(it.Attrs))
		for k, v := range it.Attrs {
			out.Attrs[k] = v.Clone()
		}
	}
	return out
}

// TablePage is one query or scan page. NextToken is "" on the last page.
type TablePage struct {
	Items     []Item
	NextToken string
}

// Tables is the provider adapter for the tables (structured KV/document) slice.
// The host has already validated every argument (table name, key charset/length,
// attribute names/types/sizes, canonical item budget, page bounds, query range)
// and attached the resolved endpoint to ctx (EndpointFrom).
type Tables interface {
	// CreateTable creates a key-only (sorted=false) or composite-key (sorted=true)
	// table and blocks until it is ACTIVE. Returns created=true for a new table,
	// (false, nil) if it already exists with the SAME key layout, or CONFLICT if
	// it already exists with the OTHER key layout.
	CreateTable(ctx context.Context, name string, sorted bool) (created bool, err error)
	// DeleteTable deletes the table and blocks until deletion completes; NOT_FOUND when absent.
	DeleteTable(ctx context.Context, name string) error
	// HeadTable returns nil when the table exists and is accessible; NOT_FOUND when absent.
	HeadTable(ctx context.Context, name string) error
	// DescribeTable returns the authoritative key layout and creation token of
	// an existing table; NOT_FOUND (Absent=table) when absent.
	DescribeTable(ctx context.Context, name string) (TableInfo, error)
	// ListTables returns one provider page of logical table names (excluding any
	// internal metadata table such as lmcloudmeta).
	ListTables(ctx context.Context, token string) (names []string, next string, err error)

	// PutItem writes item under mode and returns the stored item with its new
	// non-empty Version and Exists=true.
	//   - PutUnconditional: creates or replaces the item, rotating Version.
	//   - PutIfAbsent: CONFLICT when the item already exists.
	//   - PutIfVersion: NOT_FOUND (Absent=item) when the item is absent;
	//     PRECONDITION_FAILED when the stored version != expectVersion.
	// NOT_FOUND (Absent=table) when the table does not exist.
	// INVALID_ARGUMENT (Preflight) when item.SK == "" on a sorted table or
	// item.SK != "" on a key-only table.
	PutItem(ctx context.Context, table string, item Item, mode PutMode, expectVersion string) (Item, error)
	// GetItem reads one item; NOT_FOUND with Absent=table or Absent=item.
	GetItem(ctx context.Context, table, pk, sk string) (Item, error)
	// DeleteItem deletes one item; NOT_FOUND with Absent=table or Absent=item.
	DeleteItem(ctx context.Context, table, pk, sk string) error
	// UpdateItem merges changes.Attrs onto an EXISTING item, rotates Version and
	// returns the full updated item; NOT_FOUND (Absent=table or Absent=item) when
	// the table or item does not exist.
	UpdateItem(ctx context.Context, table, pk, sk string, changes Item) (Item, error)
	// Query returns one page of items in partition pk (and within [skFrom, skTo)
	// in ascending UTF-8 byte order on a sorted table). INVALID_ARGUMENT when
	// skFrom != "" or skTo != "" on a key-only table.
	Query(ctx context.Context, table, pk, skFrom, skTo string, max int, token string) (TablePage, error)
	// Scan returns one page of items across all partitions.
	Scan(ctx context.Context, table string, max int, token string) (TablePage, error)
}
