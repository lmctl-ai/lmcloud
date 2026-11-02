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

// BucketCreationTimer is optional: it returns a bucket's server-side creation
// time. When CreateBucket reports CONFLICT and the bucket is accessible, the
// host returns created=true if the bucket was created at or after the start
// of this bucket_create call (a retried or interrupted create that the server
// already completed), else false (it already existed). Without it the host
// returns false.
type BucketCreationTimer interface {
	BucketCreatedAt(ctx context.Context, bucket string) (time.Time, error)
}

// QueueCreationTimer is the queue counterpart of BucketCreationTimer, used
// when CreateQueue reports CONFLICT.
type QueueCreationTimer interface {
	QueueCreatedAt(ctx context.Context, queue string) (time.Time, error)
}
