// SPDX-License-Identifier: MIT

package safety

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// ErrFakeAmbiguous is returned by FakeRecoveryBackend when a resource is marked
// to simulate an ambiguous 403/404 response (e.g. OCI 404 NotAuthorizedOrNotFound).
var ErrFakeAmbiguous = errors.New("404 NotAuthorizedOrNotFound: ambiguous absence or permission denial")

type fakeObjectState struct {
	Key         string            `json:"key"`
	Body        []byte            `json:"body"`
	ETag        string            `json:"etag"`
	ContentType string            `json:"content_type"`
	Metadata    map[string]string `json:"metadata"`
	CreatedUnix int64             `json:"created_unix"`
}

type fakeBucketState struct {
	Name        string                     `json:"name"`
	Account     string                     `json:"account"`
	Scope       string                     `json:"scope"`
	Location    string                     `json:"location"`
	ProviderID  string                     `json:"provider_id"`
	Tags        map[string]string          `json:"tags"`
	CreatedUnix int64                      `json:"created_unix"`
	Objects     map[string]fakeObjectState `json:"objects"`
}

type fakeMessageState struct {
	ID      string `json:"id"`
	Wire    string `json:"wire"`
	Receipt string `json:"receipt"`
}

type fakeQueueState struct {
	Name        string             `json:"name"`
	Account     string             `json:"account"`
	Scope       string             `json:"scope"`
	Location    string             `json:"location"`
	ProviderID  string             `json:"provider_id"`
	Tags        map[string]string  `json:"tags"`
	CreatedUnix int64              `json:"created_unix"`
	Messages    []fakeMessageState `json:"messages"`
}

type fakePersistentStore struct {
	Buckets       map[string]*fakeBucketState `json:"buckets"`
	Queues        map[string]*fakeQueueState  `json:"queues"`
	PendingPolls  map[string]int              `json:"pending_polls"`
	AmbiguousKeys map[string]bool             `json:"ambiguous_keys"`
	DeleteLog     []string                    `json:"delete_log"`
	NextMsgSeq    int                         `json:"next_msg_seq"`
}

// FakeRecoveryBackend is a deterministic in-memory and optional file-backed
// implementation of RecoveryAdapter, hostkit.ObjectStore, and hostkit.Queue
// used by Stage 1 safety and recovery tests without making any network calls.
type FakeRecoveryBackend struct {
	mu               sync.Mutex
	statePath        string
	provider         string
	account          string
	tenant           string
	scope            string
	region           string
	storageEndpoint  string
	asyncDeletePolls int
	echoTokenOnOp    map[string]bool
	data             fakePersistentStore
}

// NewFakeRecoveryBackend creates an in-memory FakeRecoveryBackend.
func NewFakeRecoveryBackend(provider, account, scope, region string) *FakeRecoveryBackend {
	return &FakeRecoveryBackend{
		provider:        provider,
		account:         account,
		scope:           scope,
		region:          region,
		storageEndpoint: fmt.Sprintf("https://s3.%s.amazonaws.com", region),
		echoTokenOnOp:   make(map[string]bool),
		data: fakePersistentStore{
			Buckets:       make(map[string]*fakeBucketState),
			Queues:        make(map[string]*fakeQueueState),
			PendingPolls:  make(map[string]int),
			AmbiguousKeys: make(map[string]bool),
		},
	}
}

// NewPersistentFakeRecoveryBackend creates a file-backed FakeRecoveryBackend
// that persists every mutation to statePath so cross-process crash (`kill -9`)
// and recovery tests share durable simulated cloud state.
func NewPersistentFakeRecoveryBackend(statePath, provider, account, scope, region string) (*FakeRecoveryBackend, error) {
	b := NewFakeRecoveryBackend(provider, account, scope, region)
	b.statePath = statePath
	if err := b.loadLocked(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *FakeRecoveryBackend) loadLocked() error {
	if b.statePath == "" {
		return nil
	}
	raw, err := os.ReadFile(b.statePath)
	if errors.Is(err, os.ErrNotExist) || len(raw) == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	var st fakePersistentStore
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	if st.Buckets == nil {
		st.Buckets = make(map[string]*fakeBucketState)
	}
	if st.Queues == nil {
		st.Queues = make(map[string]*fakeQueueState)
	}
	if st.PendingPolls == nil {
		st.PendingPolls = make(map[string]int)
	}
	if st.AmbiguousKeys == nil {
		st.AmbiguousKeys = make(map[string]bool)
	}
	b.data = st
	return nil
}

func (b *FakeRecoveryBackend) saveLocked() error {
	if b.statePath == "" {
		return nil
	}
	raw, err := json.MarshalIndent(b.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := b.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.statePath)
}

// SetIdentity overrides the attested caller account, scope, or region (to test
// scope mismatch refusal).
func (b *FakeRecoveryBackend) SetIdentity(account, scope, region string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.account = account
	b.scope = scope
	b.region = region
}

// SetAsyncDeletePolls configures how many PollDelete calls are required before
// a deleted resource is reported as definitively absent.
func (b *FakeRecoveryBackend) SetAsyncDeletePolls(polls int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asyncDeletePolls = polls
}

// SetAmbiguous configures whether inspecting or deleting (kind, parent, name)
// returns an ambiguous 404/403 error.
func (b *FakeRecoveryBackend) SetAmbiguous(kind, parent, name string, ambiguous bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	k := resourceKey(kind, parent, name)
	if ambiguous {
		b.data.AmbiguousKeys[k] = true
	} else {
		delete(b.data.AmbiguousKeys, k)
	}
	_ = b.saveLocked()
}

// SetEchoTokenOnOp configures op ("bucket_create", "queue_create", "object_put")
// to fail and echo the caller's CreateToken and OwnerNonce in the error message
// and provider code.
func (b *FakeRecoveryBackend) SetEchoTokenOnOp(op string, enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.echoTokenOnOp[op] = enabled
}

// SeedBucket pre-creates a bucket in the simulated cloud with custom tags and
// account/scope (to simulate foreign or unowned pre-existing resources).
func (b *FakeRecoveryBackend) SeedBucket(name string, tags map[string]string, account, scope string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	if account == "" {
		account = b.account
	}
	if scope == "" {
		scope = b.scope
	}
	cpTags := make(map[string]string, len(tags))
	maps.Copy(cpTags, tags)
	b.data.Buckets[name] = &fakeBucketState{
		Name:        name,
		Account:     account,
		Scope:       scope,
		Location:    b.region,
		ProviderID:  "arn:aws:s3:::" + name,
		Tags:        cpTags,
		CreatedUnix: time.Now().UTC().Unix(),
		Objects:     make(map[string]fakeObjectState),
	}
	_ = b.saveLocked()
}

// SeedObject pre-creates an object inside bucket with custom metadata/tags.
func (b *FakeRecoveryBackend) SeedObject(bucket, key string, body []byte, meta map[string]string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	bkt, ok := b.data.Buckets[bucket]
	if !ok {
		return
	}
	cpMeta := make(map[string]string, len(meta))
	maps.Copy(cpMeta, meta)
	bkt.Objects[key] = fakeObjectState{
		Key:         key,
		Body:        append([]byte(nil), body...),
		ETag:        "etag-" + key,
		ContentType: "application/octet-stream",
		Metadata:    cpMeta,
		CreatedUnix: time.Now().UTC().Unix(),
	}
	_ = b.saveLocked()
}

// SeedQueue pre-creates a queue in the simulated cloud with custom tags and account/scope.
func (b *FakeRecoveryBackend) SeedQueue(name string, tags map[string]string, account, scope string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	if account == "" {
		account = b.account
	}
	if scope == "" {
		scope = b.scope
	}
	cpTags := make(map[string]string, len(tags))
	maps.Copy(cpTags, tags)
	b.data.Queues[name] = &fakeQueueState{
		Name:        name,
		Account:     account,
		Scope:       scope,
		Location:    b.region,
		ProviderID:  fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", b.region, account, name),
		Tags:        cpTags,
		CreatedUnix: time.Now().UTC().Unix(),
	}
	_ = b.saveLocked()
}

// HasBucket reports whether bucket currently exists in the simulated cloud.
func (b *FakeRecoveryBackend) HasBucket(bucket string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	_, ok := b.data.Buckets[bucket]
	return ok
}

// HasObject reports whether bucket/key currently exists in the simulated cloud.
func (b *FakeRecoveryBackend) HasObject(bucket, key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	bkt, ok := b.data.Buckets[bucket]
	if !ok {
		return false
	}
	_, ok = bkt.Objects[key]
	return ok
}

// HasQueue reports whether queue currently exists in the simulated cloud.
func (b *FakeRecoveryBackend) HasQueue(queue string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	_, ok := b.data.Queues[queue]
	return ok
}

// DeleteLog returns a copy of all delete operations executed against the fake backend.
func (b *FakeRecoveryBackend) DeleteLog() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	return append([]string(nil), b.data.DeleteLog...)
}

// --- RecoveryAdapter implementation ---

func (b *FakeRecoveryBackend) AttestIdentity(_ context.Context) (AttestedIdentity, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return AttestedIdentity{
		Provider:  b.provider,
		Account:   b.account,
		Tenant:    b.tenant,
		Principal: b.scope,
		AuthMode:  "imds_role",
	}, nil
}

func (b *FakeRecoveryBackend) ResolveScope(_ context.Context, _ string) (ResolvedScope, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return ResolvedScope{
		Provider: b.provider,
		Account:  b.account,
		Tenant:   b.tenant,
		Scope:    b.scope,
		Region:   b.region,
		Endpoint: b.storageEndpoint,
	}, nil
}

func (b *FakeRecoveryBackend) ReadOwnership(_ context.Context, ref ResourceRef) (RemoteOwnership, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()

	k := resourceKey(ref.Kind, ref.Parent, ref.Name)
	if b.data.AmbiguousKeys[k] {
		return RemoteOwnership{}, ErrFakeAmbiguous
	}

	switch ref.Kind {
	case KindBucket:
		bkt, ok := b.data.Buckets[ref.Name]
		if !ok {
			return RemoteOwnership{Exists: false}, nil
		}
		var children []string
		for ck := range bkt.Objects {
			children = append(children, ck)
		}
		sort.Strings(children)
		createdAt, _ := strconv.ParseInt(bkt.Tags[TagKeyCreatedAt], 10, 64)
		if createdAt == 0 {
			createdAt = bkt.CreatedUnix
		}
		return RemoteOwnership{
			Exists:        true,
			ProviderID:    bkt.ProviderID,
			Account:       bkt.Account,
			Scope:         bkt.Scope,
			Location:      bkt.Location,
			RunID:         bkt.Tags[TagKeyRunID],
			OwnerNonce:    bkt.Tags[TagKeyOwnerNonce],
			CreateToken:   bkt.Tags[TagKeyCreateToken],
			CreatedAtUnix: createdAt,
			ChildKeys:     children,
		}, nil

	case KindObject:
		bkt, ok := b.data.Buckets[ref.Parent]
		if !ok {
			return RemoteOwnership{Exists: false}, nil
		}
		obj, ok := bkt.Objects[ref.Name]
		if !ok {
			return RemoteOwnership{Exists: false}, nil
		}
		createdAt, _ := strconv.ParseInt(obj.Metadata[TagKeyCreatedAt], 10, 64)
		if createdAt == 0 {
			createdAt = obj.CreatedUnix
		}
		return RemoteOwnership{
			Exists:        true,
			ProviderID:    fmt.Sprintf("arn:aws:s3:::%s/%s", ref.Parent, ref.Name),
			Account:       bkt.Account,
			Scope:         bkt.Scope,
			Location:      bkt.Location,
			RunID:         obj.Metadata[TagKeyRunID],
			OwnerNonce:    obj.Metadata[TagKeyOwnerNonce],
			CreateToken:   obj.Metadata[TagKeyCreateToken],
			ETag:          obj.ETag,
			CreatedAtUnix: createdAt,
		}, nil

	case KindQueue:
		q, ok := b.data.Queues[ref.Name]
		if !ok {
			return RemoteOwnership{Exists: false}, nil
		}
		createdAt, _ := strconv.ParseInt(q.Tags[TagKeyCreatedAt], 10, 64)
		if createdAt == 0 {
			createdAt = q.CreatedUnix
		}
		return RemoteOwnership{
			Exists:        true,
			ProviderID:    q.ProviderID,
			Account:       q.Account,
			Scope:         q.Scope,
			Location:      q.Location,
			RunID:         q.Tags[TagKeyRunID],
			OwnerNonce:    q.Tags[TagKeyOwnerNonce],
			CreateToken:   q.Tags[TagKeyCreateToken],
			CreatedAtUnix: createdAt,
		}, nil

	case KindQueueMessage:
		q, ok := b.data.Queues[ref.Parent]
		if !ok {
			return RemoteOwnership{Exists: false}, nil
		}
		for _, m := range q.Messages {
			if m.ID == ref.Name {
				return RemoteOwnership{
					Exists:     true,
					ProviderID: m.ID,
					Account:    q.Account,
					Scope:      q.Scope,
					Location:   q.Location,
					RunID:      q.Tags[TagKeyRunID],
					OwnerNonce: q.Tags[TagKeyOwnerNonce],
				}, nil
			}
		}
		return RemoteOwnership{Exists: false}, nil
	}

	return RemoteOwnership{Exists: false}, nil
}

func (b *FakeRecoveryBackend) FindOwned(_ context.Context, prefix string) ([]ResourceRef, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()

	var out []ResourceRef
	for name, bkt := range b.data.Buckets {
		if strings.HasPrefix(name, prefix) {
			out = append(out, ResourceRef{
				Kind:       KindBucket,
				Location:   bkt.Location,
				Name:       name,
				ProviderID: bkt.ProviderID,
			})
		}
	}
	for name, q := range b.data.Queues {
		if strings.HasPrefix(name, prefix) {
			out = append(out, ResourceRef{
				Kind:       KindQueue,
				Location:   q.Location,
				Name:       name,
				ProviderID: q.ProviderID,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (b *FakeRecoveryBackend) DeleteOwned(_ context.Context, ref ResourceRef, _ RemoteOwnership) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()

	k := resourceKey(ref.Kind, ref.Parent, ref.Name)
	if b.data.AmbiguousKeys[k] {
		return ErrFakeAmbiguous
	}

	switch ref.Kind {
	case KindBucket:
		bkt, ok := b.data.Buckets[ref.Name]
		if !ok {
			return hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket not found").WithAbsent(hostkit.AbsentBucket)
		}
		if len(bkt.Objects) > 0 {
			return hostkit.ProviderError(hostkit.Conflict, 409, "BucketNotEmpty", "bucket is not empty")
		}
		delete(b.data.Buckets, ref.Name)
	case KindObject:
		bkt, ok := b.data.Buckets[ref.Parent]
		if !ok {
			return hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket not found").WithAbsent(hostkit.AbsentBucket)
		}
		delete(bkt.Objects, ref.Name)
	case KindQueue:
		delete(b.data.Queues, ref.Name)
	case KindQueueMessage:
		if q, ok := b.data.Queues[ref.Parent]; ok {
			var kept []fakeMessageState
			for _, m := range q.Messages {
				if m.ID != ref.Name {
					kept = append(kept, m)
				}
			}
			q.Messages = kept
		}
	}

	b.data.DeleteLog = append(b.data.DeleteLog, fmt.Sprintf("%s:%s/%s", ref.Kind, ref.Parent, ref.Name))
	if b.asyncDeletePolls > 1 {
		b.data.PendingPolls[k] = b.asyncDeletePolls - 1
	}
	return b.saveLocked()
}

func (b *FakeRecoveryBackend) PollDelete(_ context.Context, ref ResourceRef) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()

	k := resourceKey(ref.Kind, ref.Parent, ref.Name)
	if b.data.AmbiguousKeys[k] {
		return false, ErrFakeAmbiguous
	}
	if rem := b.data.PendingPolls[k]; rem > 0 {
		b.data.PendingPolls[k] = rem - 1
		_ = b.saveLocked()
		return false, nil
	}
	delete(b.data.PendingPolls, k)
	_ = b.saveLocked()
	return true, nil
}

func (b *FakeRecoveryBackend) ClassifyAbsent(err error) AbsenceClass {
	if err == nil {
		return AbsencePresentOrError
	}
	if errors.Is(err, ErrFakeAmbiguous) {
		return AbsenceAmbiguous
	}
	var ce *hostkit.CloudError
	if errors.As(err, &ce) && ce != nil {
		if ce.Code == hostkit.NotFound {
			if strings.Contains(ce.ProviderCode, "NotAuthorizedOrNotFound") {
				return AbsenceAmbiguous
			}
			return AbsenceDefinitive
		}
		if ce.Code == hostkit.PermissionDenied {
			return AbsenceAmbiguous
		}
	}
	return AbsencePresentOrError
}

func (b *FakeRecoveryBackend) QuoteAttempt(_ AttemptPricingInput, base AttemptQuote) (AttemptQuote, error) {
	return base, nil
}

// --- hostkit.ObjectStore implementation ---

func (b *FakeRecoveryBackend) CreateBucket(ctx context.Context, bucket string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()

	tags, _ := OwnershipTagsFrom(ctx)
	if b.echoTokenOnOp["bucket_create"] {
		return false, hostkit.ProviderError(
			hostkit.Internal,
			500,
			"TagRejected_"+tags.CreateToken,
			fmt.Sprintf("provider rejected create_token=%s owner_nonce=%s", tags.CreateToken, tags.OwnerNonce),
		)
	}

	if existing, ok := b.data.Buckets[bucket]; ok {
		if existing.Account != b.account {
			return false, hostkit.ProviderError(hostkit.Conflict, 409, "BucketAlreadyExists", "bucket owned by another account")
		}
		if tags.CreateToken != "" && existing.Tags[TagKeyCreateToken] == tags.CreateToken {
			return true, nil
		}
		return false, nil
	}

	b.data.Buckets[bucket] = &fakeBucketState{
		Name:        bucket,
		Account:     b.account,
		Scope:       b.scope,
		Location:    b.region,
		ProviderID:  "arn:aws:s3:::" + bucket,
		Tags:        tags.Map(),
		CreatedUnix: time.Now().UTC().Unix(),
		Objects:     make(map[string]fakeObjectState),
	}
	_ = b.saveLocked()
	return true, nil
}

func (b *FakeRecoveryBackend) DeleteBucket(ctx context.Context, bucket string) error {
	return b.DeleteOwned(ctx, ResourceRef{Kind: KindBucket, Name: bucket}, RemoteOwnership{})
}

func (b *FakeRecoveryBackend) HeadBucket(_ context.Context, bucket string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	if _, ok := b.data.Buckets[bucket]; !ok {
		return hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket does not exist").WithAbsent(hostkit.AbsentBucket)
	}
	return nil
}

func (b *FakeRecoveryBackend) ListBuckets(_ context.Context, _ string) ([]string, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	var names []string
	for name := range b.data.Buckets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, "", nil
}

func (b *FakeRecoveryBackend) PutObject(ctx context.Context, bucket, key string, body []byte, contentType string, metadata map[string]string) (hostkit.ObjectMeta, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()

	tags, _ := OwnershipTagsFrom(ctx)
	if b.echoTokenOnOp["object_put"] {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(
			hostkit.Internal,
			500,
			"PutRejected_"+tags.CreateToken,
			fmt.Sprintf("put failed with token %s and nonce %s", tags.CreateToken, tags.OwnerNonce),
		)
	}

	bkt, ok := b.data.Buckets[bucket]
	if !ok {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket does not exist").WithAbsent(hostkit.AbsentBucket)
	}
	cpMeta := make(map[string]string, len(metadata))
	maps.Copy(cpMeta, metadata)
	etag := fmt.Sprintf("etag-%s-%d", key, len(body))
	bkt.Objects[key] = fakeObjectState{
		Key:         key,
		Body:        append([]byte(nil), body...),
		ETag:        etag,
		ContentType: contentType,
		Metadata:    cpMeta,
		CreatedUnix: time.Now().UTC().Unix(),
	}
	_ = b.saveLocked()
	return hostkit.ObjectMeta{
		Exists:      true,
		Bucket:      bucket,
		Key:         key,
		Size:        int64(len(body)),
		ETag:        etag,
		ContentType: contentType,
		Metadata:    cpMeta,
	}, nil
}

func (b *FakeRecoveryBackend) GetObject(_ context.Context, bucket, key string, limit int64) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	bkt, ok := b.data.Buckets[bucket]
	if !ok {
		return nil, hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket does not exist").WithAbsent(hostkit.AbsentBucket)
	}
	obj, ok := bkt.Objects[key]
	if !ok {
		return nil, hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchKey", "object does not exist").WithAbsent(hostkit.AbsentObject)
	}
	if limit > 0 && int64(len(obj.Body)) > limit {
		return nil, hostkit.ProviderError(hostkit.InvalidArgument, 400, "EntityTooLarge", "object exceeds read limit")
	}
	return append([]byte(nil), obj.Body...), nil
}

func (b *FakeRecoveryBackend) HeadObject(_ context.Context, bucket, key string) (hostkit.ObjectMeta, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	bkt, ok := b.data.Buckets[bucket]
	if !ok {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket does not exist").WithAbsent(hostkit.AbsentBucket)
	}
	obj, ok := bkt.Objects[key]
	if !ok {
		return hostkit.ObjectMeta{}, hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchKey", "object does not exist").WithAbsent(hostkit.AbsentObject)
	}
	return hostkit.ObjectMeta{
		Exists:      true,
		Bucket:      bucket,
		Key:         key,
		Size:        int64(len(obj.Body)),
		ETag:        obj.ETag,
		ContentType: obj.ContentType,
		Metadata:    obj.Metadata,
	}, nil
}

func (b *FakeRecoveryBackend) DeleteObject(ctx context.Context, bucket, key string) error {
	return b.DeleteOwned(ctx, ResourceRef{Kind: KindObject, Parent: bucket, Name: key}, RemoteOwnership{})
}

func (b *FakeRecoveryBackend) ListObjects(_ context.Context, bucket, prefix string, max int, _ string) (hostkit.ObjectPage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	bkt, ok := b.data.Buckets[bucket]
	if !ok {
		return hostkit.ObjectPage{}, hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket does not exist").WithAbsent(hostkit.AbsentBucket)
	}
	var items []hostkit.ObjectSummary
	for k, obj := range bkt.Objects {
		if strings.HasPrefix(k, prefix) {
			items = append(items, hostkit.ObjectSummary{
				Key:  k,
				Size: int64(len(obj.Body)),
				ETag: obj.ETag,
			})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	if max > 0 && len(items) > max {
		items = items[:max]
	}
	return hostkit.ObjectPage{Items: items}, nil
}

func (b *FakeRecoveryBackend) BucketCreateToken(_ context.Context, bucket string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	bkt, ok := b.data.Buckets[bucket]
	if !ok {
		return "", hostkit.ProviderError(hostkit.NotFound, 404, "NoSuchBucket", "bucket does not exist").WithAbsent(hostkit.AbsentBucket)
	}
	return bkt.Tags[TagKeyCreateToken], nil
}

// --- hostkit.Queue implementation ---

func (b *FakeRecoveryBackend) QueueCaps() hostkit.QueueCaps {
	return hostkit.QueueCaps{LongPoll: true, TextOnlyWire: true}
}

func (b *FakeRecoveryBackend) CreateQueue(ctx context.Context, queue string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()

	tags, _ := OwnershipTagsFrom(ctx)
	if b.echoTokenOnOp["queue_create"] {
		return false, hostkit.ProviderError(
			hostkit.Internal,
			500,
			"QueueTagRejected_"+tags.CreateToken,
			fmt.Sprintf("queue create failed with token %s and nonce %s", tags.CreateToken, tags.OwnerNonce),
		)
	}

	if existing, ok := b.data.Queues[queue]; ok {
		if existing.Account != b.account {
			return false, hostkit.ProviderError(hostkit.Conflict, 409, "QueueAlreadyExists", "queue owned by another account")
		}
		if tags.CreateToken != "" && existing.Tags[TagKeyCreateToken] == tags.CreateToken {
			return true, nil
		}
		return false, nil
	}

	b.data.Queues[queue] = &fakeQueueState{
		Name:        queue,
		Account:     b.account,
		Scope:       b.scope,
		Location:    b.region,
		ProviderID:  fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", b.region, b.account, queue),
		Tags:        tags.Map(),
		CreatedUnix: time.Now().UTC().Unix(),
	}
	_ = b.saveLocked()
	return true, nil
}

func (b *FakeRecoveryBackend) DeleteQueue(ctx context.Context, queue string) error {
	return b.DeleteOwned(ctx, ResourceRef{Kind: KindQueue, Name: queue}, RemoteOwnership{})
}

func (b *FakeRecoveryBackend) LookupQueue(_ context.Context, queue string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	if _, ok := b.data.Queues[queue]; !ok {
		return hostkit.ProviderError(hostkit.NotFound, 404, "NonExistentQueue", "queue does not exist").WithAbsent(hostkit.AbsentQueue)
	}
	return nil
}

func (b *FakeRecoveryBackend) ListQueues(_ context.Context, _ string) ([]string, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	var names []string
	for name := range b.data.Queues {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, "", nil
}

func (b *FakeRecoveryBackend) Send(_ context.Context, queue, wire string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	q, ok := b.data.Queues[queue]
	if !ok {
		return "", hostkit.ProviderError(hostkit.NotFound, 404, "NonExistentQueue", "queue does not exist").WithAbsent(hostkit.AbsentQueue)
	}
	b.data.NextMsgSeq++
	id := fmt.Sprintf("msg-%d", b.data.NextMsgSeq)
	rcpt := fmt.Sprintf("rcpt-%d", b.data.NextMsgSeq)
	q.Messages = append(q.Messages, fakeMessageState{ID: id, Wire: wire, Receipt: rcpt})
	_ = b.saveLocked()
	return id, nil
}

func (b *FakeRecoveryBackend) Receive(_ context.Context, queue string, max, _, _ int) ([]hostkit.RawMessage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	q, ok := b.data.Queues[queue]
	if !ok {
		return nil, hostkit.ProviderError(hostkit.NotFound, 404, "NonExistentQueue", "queue does not exist").WithAbsent(hostkit.AbsentQueue)
	}
	var out []hostkit.RawMessage
	for i, m := range q.Messages {
		if max > 0 && i >= max {
			break
		}
		out = append(out, hostkit.RawMessage{ID: m.ID, Wire: m.Wire, Receipt: m.Receipt})
	}
	return out, nil
}

func (b *FakeRecoveryBackend) Ack(_ context.Context, queue, receipt string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	q, ok := b.data.Queues[queue]
	if !ok {
		return hostkit.ProviderError(hostkit.NotFound, 404, "NonExistentQueue", "queue does not exist").WithAbsent(hostkit.AbsentQueue)
	}
	for i, m := range q.Messages {
		if m.Receipt == receipt {
			q.Messages = append(q.Messages[:i], q.Messages[i+1:]...)
			_ = b.saveLocked()
			return nil
		}
	}
	return hostkit.ProviderError(hostkit.NotFound, 404, "ReceiptHandleIsInvalid", "receipt not found").WithAbsent(hostkit.AbsentMessage)
}

func (b *FakeRecoveryBackend) Nack(_ context.Context, queue, receipt string, _ int) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	q, ok := b.data.Queues[queue]
	if !ok {
		return "", hostkit.ProviderError(hostkit.NotFound, 404, "NonExistentQueue", "queue does not exist").WithAbsent(hostkit.AbsentQueue)
	}
	for i, m := range q.Messages {
		if m.Receipt == receipt {
			newRcpt := m.Receipt + "-nack"
			q.Messages[i].Receipt = newRcpt
			_ = b.saveLocked()
			return newRcpt, nil
		}
	}
	return "", hostkit.ProviderError(hostkit.NotFound, 404, "ReceiptHandleIsInvalid", "receipt not found").WithAbsent(hostkit.AbsentMessage)
}

func (b *FakeRecoveryBackend) QueueCreateToken(_ context.Context, queue string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_ = b.loadLocked()
	q, ok := b.data.Queues[queue]
	if !ok {
		return "", hostkit.ProviderError(hostkit.NotFound, 404, "NonExistentQueue", "queue does not exist").WithAbsent(hostkit.AbsentQueue)
	}
	return q.Tags[TagKeyCreateToken], nil
}
