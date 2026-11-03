// SPDX-License-Identifier: MIT

package cloudhost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"sync"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func missingTables() *hostkit.CloudError {
	return hostkit.ProviderError(hostkit.Internal, 0, "", "this host has no tables adapter")
}

func tableItemTarget(table, pk, sk string) string {
	if table == "" {
		if sk == "" {
			return pk
		}
		return pk + "/" + sk
	}
	if sk == "" {
		return table + "/" + pk
	}
	return table + "/" + pk + "/" + sk
}

// TableItem is the state behind the schema's TableItem object.
// Local builder calls validate eagerly and record any pre-flight error on both
// the host's last_error and the item's sticky invalid field so chained
// `cloud.item_put(t, cloud.item_new(...).set_*(...))` calls also fail pre-flight.
type TableItem struct {
	mu      sync.Mutex
	host    *Host
	item    hostkit.Item
	invalid *hostkit.CloudError
}

func newTableItemFromHostkit(h *Host, it hostkit.Item) *TableItem {
	cp := it.Clone()
	if cp.Attrs == nil {
		cp.Attrs = map[string]hostkit.Attr{}
	}
	return &TableItem{host: h, item: cp}
}

func emptyTableItem(h *Host, pk, sk string) *TableItem {
	return &TableItem{
		host: h,
		item: hostkit.Item{
			PK:     pk,
			SK:     sk,
			Exists: false,
			Attrs:  map[string]hostkit.Attr{},
		},
	}
}

func (it *TableItem) fail(op, target string, e *hostkit.CloudError) error {
	if it.host != nil {
		return it.host.fail(op, target, e)
	}
	if e == nil || e.OK() {
		return nil
	}
	return &hostkit.AbortError{Message: hostkit.FormatAbort(op, target, e), Err: e}
}

func (it *TableItem) ok() {
	if it.host != nil {
		it.host.ok()
	}
}

func (it *TableItem) snapshot() (hostkit.Item, *hostkit.CloudError) {
	if it == nil {
		return hostkit.Item{}, hostkit.Preflightf("item must not be nil")
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.item.Clone(), it.invalid
}

func (it *TableItem) setAttr(op, name string, val hostkit.Attr) (*TableItem, error) {
	it.mu.Lock()
	if err := hostkit.AttrName(name); err != nil {
		it.invalid = err
		it.mu.Unlock()
		return it, it.fail(op, name, err)
	}
	switch {
	case val.S != nil:
		if err := hostkit.AttrStringValue(*val.S); err != nil {
			it.invalid = err
			it.mu.Unlock()
			return it, it.fail(op, name, err)
		}
	case val.N != nil:
		if err := hostkit.AttrNumberValue(*val.N); err != nil {
			it.invalid = err
			it.mu.Unlock()
			return it, it.fail(op, name, err)
		}
	}
	if it.item.Attrs == nil {
		it.item.Attrs = map[string]hostkit.Attr{}
	}
	cand := make(map[string]hostkit.Attr, len(it.item.Attrs)+1)
	for k, v := range it.item.Attrs {
		cand[k] = v
	}
	cand[name] = val.Clone()
	if _, err := hostkit.CanonicalItemBytes(cand); err != nil {
		it.invalid = err
		it.mu.Unlock()
		return it, it.fail(op, name, err)
	}
	it.item.Attrs[name] = val.Clone()
	it.mu.Unlock()
	it.ok()
	return it, nil
}

// SetString sets a string attribute on it.
func (it *TableItem) SetString(name, v string) (*TableItem, error) {
	return it.setAttr("set_string", name, hostkit.StringAttr(v))
}

// SetInt sets an int64 attribute on it.
func (it *TableItem) SetInt(name string, v int64) (*TableItem, error) {
	return it.setAttr("set_int", name, hostkit.IntAttr(v))
}

// SetNumber sets a float64 attribute on it.
func (it *TableItem) SetNumber(name string, v float64) (*TableItem, error) {
	return it.setAttr("set_number", name, hostkit.NumberAttr(v))
}

// SetBool sets a bool attribute on it.
func (it *TableItem) SetBool(name string, v bool) (*TableItem, error) {
	return it.setAttr("set_bool", name, hostkit.BoolAttr(v))
}

// Remove deletes an attribute from the local item builder.
func (it *TableItem) Remove(name string) (*TableItem, error) {
	it.mu.Lock()
	if err := hostkit.AttrName(name); err != nil {
		it.invalid = err
		it.mu.Unlock()
		return it, it.fail("remove", name, err)
	}
	delete(it.item.Attrs, name)
	it.mu.Unlock()
	it.ok()
	return it, nil
}

// Has reports whether attribute name is present on it.
func (it *TableItem) Has(name string) bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	_, ok := it.item.Attrs[name]
	return ok
}

// TypeOf returns the attribute type tag ("string", "int", "number", "bool") or "" if absent.
func (it *TableItem) TypeOf(name string) string {
	it.mu.Lock()
	defer it.mu.Unlock()
	a, ok := it.item.Attrs[name]
	if !ok {
		return ""
	}
	return a.Kind()
}

// GetString returns the string value of attribute name, failing pre-flight if absent or not a string.
func (it *TableItem) GetString(name string) (string, error) {
	it.mu.Lock()
	a, ok := it.item.Attrs[name]
	it.mu.Unlock()
	if !ok {
		return "", it.fail("get_string", name, hostkit.Preflightf("attribute %q is not present on item", name))
	}
	if a.S == nil {
		return "", it.fail("get_string", name, hostkit.Preflightf("attribute %q has type %q, want %q", name, a.Kind(), hostkit.AttrString))
	}
	it.ok()
	return *a.S, nil
}

// GetInt returns the int64 value of attribute name, failing pre-flight if absent or not an int.
func (it *TableItem) GetInt(name string) (int64, error) {
	it.mu.Lock()
	a, ok := it.item.Attrs[name]
	it.mu.Unlock()
	if !ok {
		return 0, it.fail("get_int", name, hostkit.Preflightf("attribute %q is not present on item", name))
	}
	if a.I == nil {
		return 0, it.fail("get_int", name, hostkit.Preflightf("attribute %q has type %q, want %q", name, a.Kind(), hostkit.AttrInt))
	}
	it.ok()
	return *a.I, nil
}

// GetNumber returns the float64 value of attribute name, failing pre-flight if absent or not a number.
func (it *TableItem) GetNumber(name string) (float64, error) {
	it.mu.Lock()
	a, ok := it.item.Attrs[name]
	it.mu.Unlock()
	if !ok {
		return 0, it.fail("get_number", name, hostkit.Preflightf("attribute %q is not present on item", name))
	}
	if a.N == nil {
		return 0, it.fail("get_number", name, hostkit.Preflightf("attribute %q has type %q, want %q", name, a.Kind(), hostkit.AttrNumber))
	}
	it.ok()
	return *a.N, nil
}

// GetBool returns the bool value of attribute name, failing pre-flight if absent or not a bool.
func (it *TableItem) GetBool(name string) (bool, error) {
	it.mu.Lock()
	a, ok := it.item.Attrs[name]
	it.mu.Unlock()
	if !ok {
		return false, it.fail("get_bool", name, hostkit.Preflightf("attribute %q is not present on item", name))
	}
	if a.B == nil {
		return false, it.fail("get_bool", name, hostkit.Preflightf("attribute %q has type %q, want %q", name, a.Kind(), hostkit.AttrBool))
	}
	it.ok()
	return *a.B, nil
}

// Names returns the sorted list of user attribute names on it.
func (it *TableItem) Names() []string {
	it.mu.Lock()
	defer it.mu.Unlock()
	out := make([]string, 0, len(it.item.Attrs))
	for k := range it.item.Attrs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Len returns the number of user attributes on it.
func (it *TableItem) Len() int64 {
	it.mu.Lock()
	defer it.mu.Unlock()
	return int64(len(it.item.Attrs))
}

// PK returns the partition key.
func (it *TableItem) PK() string {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.item.PK
}

// SK returns the sort key ("" on key-only items).
func (it *TableItem) SK() string {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.item.SK
}

// Version returns the provider version token ("" on local unsaved items).
func (it *TableItem) Version() string {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.item.Version
}

// Exists reports whether the item existed on the server.
func (it *TableItem) Exists() bool {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.item.Exists
}

// TablePage is the immutable TablePage snapshot returned by item_query and item_scan.
type TablePage struct {
	Items     []*TableItem
	NextToken string
}

type tableCursorEnvelope struct {
	EP     string `json:"ep"`
	Op     string `json:"op"`
	Table  string `json:"t"`
	PK     string `json:"pk,omitempty"`
	SKFrom string `json:"f,omitempty"`
	SKTo   string `json:"to,omitempty"`
	Raw    string `json:"r"`
}

func encodeTableCursor(env tableCursorEnvelope) string {
	if env.Raw == "" {
		return ""
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return ""
	}
	return "lmc1." + base64.RawURLEncoding.EncodeToString(raw)
}

func decodeTableCursor(token string, want tableCursorEnvelope) (string, *hostkit.CloudError) {
	if token == "" {
		return "", nil
	}
	if !strings.HasPrefix(token, "lmc1.") {
		return "", hostkit.Preflightf("invalid continuation token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "lmc1."))
	if err != nil {
		return "", hostkit.Preflightf("invalid continuation token")
	}
	var got tableCursorEnvelope
	if err := json.Unmarshal(raw, &got); err != nil || got.Raw == "" {
		return "", hostkit.Preflightf("invalid continuation token")
	}
	if got.EP != want.EP || got.Op != want.Op || got.Table != want.Table ||
		got.PK != want.PK || got.SKFrom != want.SKFrom || got.SKTo != want.SKTo {
		return "", hostkit.Preflightf("continuation token does not match query/scan parameters")
	}
	return got.Raw, nil
}

func (h *Host) validateReturnedItem(it hostkit.Item, requireVersion bool) (hostkit.Item, int64, *hostkit.CloudError) {
	if e := h.cfg.Validator.TableKey(it.PK); e != nil {
		return hostkit.Item{}, 0, hostkit.ProviderError(hostkit.Internal, 0, "InvalidProviderItem", "provider returned an invalid partition key")
	}
	if it.SK != "" {
		if e := h.cfg.Validator.TableKey(it.SK); e != nil {
			return hostkit.Item{}, 0, hostkit.ProviderError(hostkit.Internal, 0, "InvalidProviderItem", "provider returned an invalid sort key")
		}
	}
	if requireVersion && it.Version == "" {
		return hostkit.Item{}, 0, hostkit.ProviderError(hostkit.Internal, 0, "MissingItemVersion", "provider returned a stored item without a version token")
	}
	canonBytes, cerr := hostkit.CanonicalItemBytes(it.Attrs)
	if cerr != nil {
		return hostkit.Item{}, int64(hostkit.MaxItemCanonicalBytes), hostkit.ProviderError(hostkit.Internal, 0, "OversizedTableItem", cerr.Message)
	}
	out := it.Clone()
	out.Exists = true
	if out.Attrs == nil {
		out.Attrs = map[string]hostkit.Attr{}
	}
	return out, int64(canonBytes), nil
}

// ItemNew implements both cloud.item_new(pk) and cloud.item_new(pk, sk).
func (h *Host) ItemNew(pk, sk string, hasSK bool) (*TableItem, error) {
	const op = "item_new"
	if e := h.cfg.Validator.TableKey(pk); e != nil {
		it := &TableItem{host: h, item: hostkit.Item{PK: pk, SK: sk, Attrs: map[string]hostkit.Attr{}}, invalid: e}
		return it, h.fail(op, tableItemTarget("", pk, sk), e)
	}
	if hasSK {
		if e := h.cfg.Validator.TableKey(sk); e != nil {
			it := &TableItem{host: h, item: hostkit.Item{PK: pk, SK: sk, Attrs: map[string]hostkit.Attr{}}, invalid: e}
			return it, h.fail(op, tableItemTarget("", pk, sk), e)
		}
	}
	h.ok()
	return &TableItem{
		host: h,
		item: hostkit.Item{
			PK:    pk,
			SK:    sk,
			Attrs: map[string]hostkit.Attr{},
		},
	}, nil
}

func (h *Host) realTableExists(ctx context.Context, name string) (bool, *hostkit.CloudError) {
	if h.cfg.Tables == nil {
		return false, missingTables()
	}
	e := hostkit.AsCloudError(h.cfg.Tables.HeadTable(ctx, name))
	switch {
	case e == nil:
		return true, nil
	case isNotFound(e):
		return false, nil
	default:
		return false, e
	}
}

func (h *Host) meteredTableExists(ctx context.Context, name string, isCleanup bool) (bool, *hostkit.CloudError) {
	if h.cfg.Tables == nil {
		return false, missingTables()
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "table_exists", safety.AttemptPricingInput{Operation: "table_exists", IsCleanup: isCleanup}, safety.KindTable, name)
	if cerr != nil {
		return false, cerr
	}
	exists, e := h.realTableExists(mctx, name)
	_, _, aerr := scope.finish(0, 0, true, e == nil)
	if aerr != nil {
		e = aerr
	}
	return exists, e
}

func (h *Host) meteredTableCreateToken(ctx context.Context, name, token string) (bool, *hostkit.CloudError) {
	if token == "" || h.cfg.Tables == nil {
		return false, nil
	}
	rawTables := h.cfg.Tables
	if gt, ok := rawTables.(guardTables); ok {
		rawTables = gt.t
	}
	r, ok := rawTables.(hostkit.TableCreateTokenReader)
	if !ok {
		return false, nil
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, "table_read_ownership", safety.AttemptPricingInput{Operation: "table_read_ownership"}, safety.KindTable, name)
	if cerr != nil {
		return false, cerr
	}
	got, err := r.TableCreateToken(mctx, name)
	err = hostkit.NilIfTyped(err)
	_, _, aerr := scope.finish(0, 0, true, err == nil)
	if aerr != nil {
		return false, aerr
	}
	if err != nil {
		if ce := hostkit.AsCloudError(err); ce != nil && ce.Code == hostkit.CostCapExceeded {
			return false, ce
		}
		return false, nil
	}
	return got == token, nil
}

func (h *Host) tableExists(ctx context.Context, dry bool, name string) (bool, *hostkit.CloudError) {
	if dry {
		if dt, ok := h.ov(ctx).table(name); ok {
			return dt.exists, nil
		}
	}
	return h.realTableExists(ctx, name)
}

func (h *Host) requireTable(ctx context.Context, dry bool, name string) *hostkit.CloudError {
	exists, e := h.tableExists(ctx, dry, name)
	if e != nil {
		return e
	}
	if !exists {
		return notFound(hostkit.AbsentTable, "table does not exist (dry-run preview)")
	}
	return nil
}

// TableCreate implements both table_create(name) and table_create(name, sorted).
func (h *Host) TableCreate(dry bool, name string, sorted bool) (bool, error) {
	const op = "table_create"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Table(name); e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()
	if dry {
		if dt, ok := h.ov(ctx).table(name); ok && dt.exists {
			if dt.hasSorted && dt.sorted != sorted {
				failed = true
				return false, h.fail(op, name, hostkit.ProviderError(hostkit.Conflict, 409, "ResourceInUseException", "table already exists with a different key layout (dry-run preview)"))
			}
			h.ok()
			return false, nil
		}
		exists, e := h.tableExists(ctx, true, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		h.ov(ctx).setTable(name, true, sorted, true, !exists)
		h.ok()
		return !exists, nil
	}
	if h.cfg.Tables == nil {
		failed = true
		return false, h.fail(op, name, missingTables())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindTable, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	token := newCreateToken()
	h.errs.AddRedaction(token)
	mctx = hostkit.WithCreateToken(mctx, token)
	created, err := h.cfg.Tables.CreateTable(mctx, name, sorted)
	var abortErr *hostkit.CloudError
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if ce.Code == hostkit.Conflict {
			retries, throttles, abortErr = scope.finish(0, 0, true, false)
			if abortErr != nil {
				failed = true
				return false, h.fail(op, name, abortErr)
			}
			proven, terr := h.meteredTableCreateToken(ctx, name, token)
			if terr != nil {
				failed = true
				return false, h.fail(op, name, terr)
			}
			if proven {
				h.cost.lockResourceCleanupIfNeeded(op, safety.KindTable, name)
				h.ok()
				return true, nil
			}
			failed = true
			return false, h.fail(op, name, ce)
		}
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return false, h.fail(op, name, ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, true)
	if abortErr != nil {
		failed = true
		return false, h.fail(op, name, abortErr)
	}
	h.ok()
	return created, nil
}

// TableDelete implements table_delete.
func (h *Host) TableDelete(dry bool, name string) (bool, error) {
	const op = "table_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Table(name); e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()
	if dry {
		exists, e := h.tableExists(ctx, true, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		h.ov(ctx).setTable(name, false, false, false, false)
		h.ok()
		return exists, nil
	}
	if h.cfg.Tables == nil {
		failed = true
		return false, h.fail(op, name, missingTables())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, IsCleanup: true}, safety.KindTable, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	ce := hostkit.AsCloudError(h.cfg.Tables.DeleteTable(mctx, name))
	var abortErr *hostkit.CloudError
	switch {
	case ce == nil:
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, name, abortErr)
		}
		h.ok()
		return true, nil
	case isNotFound(ce):
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return false, h.fail(op, name, abortErr)
		}
		h.ok()
		return false, nil
	default:
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return false, h.fail(op, name, ce)
	}
}

// TableExists implements table_exists.
func (h *Host) TableExists(dry bool, name string) (bool, error) {
	const op = "table_exists"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	if e := h.cfg.Validator.Table(name); e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	defer cancel()
	if dry {
		exists, e := h.tableExists(ctx, true, name)
		if e != nil {
			failed = true
			return false, h.fail(op, name, e)
		}
		h.ok()
		return exists, nil
	}
	if h.cfg.Tables == nil {
		failed = true
		return false, h.fail(op, name, missingTables())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindTable, name)
	if cerr != nil {
		failed = true
		return false, h.fail(op, name, cerr)
	}
	exists, e := h.realTableExists(mctx, name)
	var abortErr *hostkit.CloudError
	retries, throttles, abortErr = scope.finish(0, 0, true, e == nil)
	if abortErr != nil {
		e = abortErr
	}
	if e != nil {
		failed = true
		return false, h.fail(op, name, e)
	}
	h.ok()
	return exists, nil
}

// TableList implements table_list: every page, sorted, de-duplicated, excluding lmcloudmeta.
func (h *Host) TableList(dry bool) ([]string, error) {
	const op = "table_list"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	ctx, cancel, e := h.opCtx("tables", h.cfg.ListTimeout)
	if e != nil {
		failed = true
		return nil, h.fail(op, "", e)
	}
	defer cancel()
	if h.cfg.Tables == nil {
		failed = true
		return nil, h.fail(op, "", missingTables())
	}
	names, e := hostkit.ListAll(ctx, h.cfg.MaxPages, func(ctx context.Context, token string) ([]string, string, error) {
		if dry {
			return h.cfg.Tables.ListTables(ctx, token)
		}
		mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op}, safety.KindTable, "")
		if cerr != nil {
			return nil, "", cerr
		}
		items, next, err := h.cfg.Tables.ListTables(mctx, token)
		r, t, abortErr := scope.finish(0, 0, true, err == nil)
		retries += r
		throttles += t
		if abortErr != nil {
			return nil, "", abortErr
		}
		return items, next, err
	})
	if e != nil {
		failed = true
		return nil, h.fail(op, "", e)
	}
	if dry {
		names = h.ov(ctx).mergeTables(names)
	}
	filtered := make([]string, 0, len(names))
	for _, n := range names {
		if n == "lmcloudmeta" {
			continue
		}
		filtered = append(filtered, n)
	}
	h.ok()
	return hostkit.SortedUnique(filtered), nil
}

// ItemPut implements both item_put(table, item) and item_put(table, item, expectVersion).
func (h *Host) ItemPut(dry bool, table string, ti *TableItem, mode hostkit.PutMode, expectVersion string) (*TableItem, error) {
	const op = "item_put"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesOut int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, bytesOut)
		}
	}()
	rawItem, inv := ti.snapshot()
	none := emptyTableItem(h, rawItem.PK, rawItem.SK)
	tgt := tableItemTarget(table, rawItem.PK, rawItem.SK)
	if e := h.cfg.Validator.Table(table); e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	if inv != nil {
		failed = true
		return none, h.fail(op, tgt, inv)
	}
	if e := h.cfg.Validator.TableKey(rawItem.PK); e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	if rawItem.SK != "" {
		if e := h.cfg.Validator.TableKey(rawItem.SK); e != nil {
			failed = true
			return none, h.fail(op, tgt, e)
		}
	}
	canonBytes, cerr := hostkit.CanonicalItemBytes(rawItem.Attrs)
	if cerr != nil {
		failed = true
		return none, h.fail(op, tgt, cerr)
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	defer cancel()
	if dry {
		if e := h.requireTable(ctx, true, table); e != nil {
			failed = true
			return none, h.fail(op, tgt, e)
		}
		if dt, ok := h.ov(ctx).table(table); ok && dt.hasSorted {
			if dt.sorted && rawItem.SK == "" {
				failed = true
				return none, h.fail(op, tgt, hostkit.Preflightf("table %q has a composite key and requires a sort key (sk)", table))
			}
			if !dt.sorted && rawItem.SK != "" {
				failed = true
				return none, h.fail(op, tgt, hostkit.Preflightf("table %q is partition-key-only and does not accept a sort key (sk)", table))
			}
		}
		ik := rawItem.PK + "\x00" + rawItem.SK
		st, cur := h.ov(ctx).tableItem(table, ik)
		switch mode {
		case hostkit.PutIfAbsent:
			if st == dryPresent {
				failed = true
				return none, h.fail(op, tgt, hostkit.ProviderError(hostkit.Conflict, 409, "ConditionalCheckFailedException", "item already exists (dry-run preview)"))
			}
		case hostkit.PutIfVersion:
			if st == dryObjectGone {
				failed = true
				return none, h.fail(op, tgt, notFound(hostkit.AbsentItem, "item does not exist (dry-run preview)"))
			}
			if st == dryPresent && cur.Version != expectVersion {
				failed = true
				return none, h.fail(op, tgt, hostkit.ProviderError(hostkit.PreconditionFailed, 412, "ConditionalCheckFailedException", "item version mismatch (dry-run preview)"))
			}
		}
		stored := rawItem.Clone()
		stored.Exists = true
		stored.Version = h.ov(ctx).nextDryVersion(table, rawItem.PK, rawItem.SK)
		h.ov(ctx).putTableItem(table, ik, stored)
		h.ok()
		return newTableItemFromHostkit(h, stored), nil
	}
	if h.cfg.Tables == nil {
		failed = true
		return none, h.fail(op, tgt, missingTables())
	}
	sz := int64(canonBytes)
	mctx, scope, rerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, PayloadSize: sz}, safety.KindTableItem, tgt)
	if rerr != nil {
		failed = true
		return none, h.fail(op, tgt, rerr)
	}
	stored, err := h.cfg.Tables.PutItem(mctx, table, rawItem, mode, expectVersion)
	var abortErr *hostkit.CloudError
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if ce != nil && ce.Preflight {
			if relErr := h.cost.release(scope.res, scope.attemptID); relErr != nil {
				ce = relErr
			}
		} else {
			retries, throttles, abortErr = scope.finish(sz, sz, false, false)
			if abortErr != nil {
				ce = abortErr
			}
		}
		failed = true
		return none, h.fail(op, tgt, ce)
	}
	validStored, _, verr := h.validateReturnedItem(stored, true)
	if verr != nil {
		retries, throttles, abortErr = scope.finish(sz, sz, true, false)
		if abortErr != nil {
			verr = abortErr
		}
		failed = true
		return none, h.fail(op, tgt, verr)
	}
	retries, throttles, abortErr = scope.finish(sz, sz, true, true)
	if abortErr != nil {
		failed = true
		return none, h.fail(op, tgt, abortErr)
	}
	bytesOut = sz
	h.ok()
	return newTableItemFromHostkit(h, validStored), nil
}

// ItemGet implements both item_get(table, pk) and item_get(table, pk, sk).
func (h *Host) ItemGet(dry bool, table, pk, sk string, hasSK bool) (*TableItem, error) {
	const op = "item_get"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()
	none := emptyTableItem(h, pk, sk)
	tgt := tableItemTarget(table, pk, sk)
	if e := h.cfg.Validator.Table(table); e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	if e := h.cfg.Validator.TableKey(pk); e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	if hasSK {
		if e := h.cfg.Validator.TableKey(sk); e != nil {
			failed = true
			return none, h.fail(op, tgt, e)
		}
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	defer cancel()
	if dry {
		ik := pk + "\x00" + sk
		switch st, cur := h.ov(ctx).tableItem(table, ik); st {
		case dryBucketGone:
			failed = true
			return none, h.fail(op, tgt, notFound(hostkit.AbsentTable, "table does not exist (dry-run preview)"))
		case dryObjectGone:
			h.ok()
			return none, nil
		case dryPresent:
			h.ok()
			return newTableItemFromHostkit(h, cur), nil
		}
	}
	if h.cfg.Tables == nil {
		failed = true
		return none, h.fail(op, tgt, missingTables())
	}
	var scope *attemptScope
	mctx := ctx
	if !dry {
		var cerr *hostkit.CloudError
		mctx, scope, cerr = h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, PayloadSize: hostkit.MaxItemCanonicalBytes}, safety.KindTableItem, tgt)
		if cerr != nil {
			failed = true
			return none, h.fail(op, tgt, cerr)
		}
	}
	got, err := h.cfg.Tables.GetItem(mctx, table, pk, sk)
	var abortErr *hostkit.CloudError
	if err == nil {
		validGot, gotBytes, verr := h.validateReturnedItem(got, true)
		if verr != nil {
			retries, throttles, abortErr = scope.finish(gotBytes, gotBytes, true, false)
			if abortErr != nil {
				verr = abortErr
			}
			failed = true
			return none, h.fail(op, tgt, verr)
		}
		retries, throttles, abortErr = scope.finish(gotBytes, gotBytes, true, true)
		if abortErr != nil {
			failed = true
			return none, h.fail(op, tgt, abortErr)
		}
		bytesIn = gotBytes
		h.ok()
		return newTableItemFromHostkit(h, validGot), nil
	}
	ce := hostkit.AsCloudError(err)
	if ce != nil && ce.Preflight {
		if !dry {
			if relErr := h.cost.release(scope.res, scope.attemptID); relErr != nil {
				ce = relErr
			}
		}
		failed = true
		return none, h.fail(op, tgt, ce)
	}
	if !isNotFound(ce) {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return none, h.fail(op, tgt, ce)
	}
	switch ce.Absent {
	case hostkit.AbsentItem:
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return none, h.fail(op, tgt, abortErr)
		}
		h.ok()
		return none, nil
	case hostkit.AbsentTable:
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return none, h.fail(op, tgt, ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, true)
	if abortErr != nil {
		failed = true
		return none, h.fail(op, tgt, abortErr)
	}
	var exists bool
	var perr *hostkit.CloudError
	if dry {
		exists, perr = h.realTableExists(ctx, table)
	} else {
		exists, perr = h.meteredTableExists(ctx, table, false)
	}
	if perr != nil {
		failed = true
		return none, h.fail(op, tgt, perr)
	}
	if !exists {
		failed = true
		return none, h.fail(op, tgt, ce.WithAbsent(hostkit.AbsentTable))
	}
	h.ok()
	return none, nil
}

// ItemDelete implements both item_delete(table, pk) and item_delete(table, pk, sk).
func (h *Host) ItemDelete(dry bool, table, pk, sk string, hasSK bool) error {
	const op = "item_delete"
	start := h.cfg.Now()
	failed := false
	var retries, throttles int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, 0)
		}
	}()
	tgt := tableItemTarget(table, pk, sk)
	if e := h.cfg.Validator.Table(table); e != nil {
		failed = true
		return h.fail(op, tgt, e)
	}
	if e := h.cfg.Validator.TableKey(pk); e != nil {
		failed = true
		return h.fail(op, tgt, e)
	}
	if hasSK {
		if e := h.cfg.Validator.TableKey(sk); e != nil {
			failed = true
			return h.fail(op, tgt, e)
		}
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return h.fail(op, tgt, e)
	}
	defer cancel()
	if dry {
		if e := h.requireTable(ctx, true, table); e != nil {
			failed = true
			return h.fail(op, tgt, e)
		}
		h.ov(ctx).deleteTableItem(table, pk+"\x00"+sk)
		h.ok()
		return nil
	}
	if h.cfg.Tables == nil {
		failed = true
		return h.fail(op, tgt, missingTables())
	}
	mctx, scope, cerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, IsCleanup: true}, safety.KindTableItem, tgt)
	if cerr != nil {
		failed = true
		return h.fail(op, tgt, cerr)
	}
	ce := hostkit.AsCloudError(h.cfg.Tables.DeleteItem(mctx, table, pk, sk))
	var abortErr *hostkit.CloudError
	if ce == nil {
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return h.fail(op, tgt, abortErr)
		}
		h.ok()
		return nil
	}
	if ce.Preflight {
		if relErr := h.cost.release(scope.res, scope.attemptID); relErr != nil {
			ce = relErr
		}
		failed = true
		return h.fail(op, tgt, ce)
	}
	if !isNotFound(ce) {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return h.fail(op, tgt, ce)
	}
	switch ce.Absent {
	case hostkit.AbsentItem:
		retries, throttles, abortErr = scope.finish(0, 0, true, true)
		if abortErr != nil {
			failed = true
			return h.fail(op, tgt, abortErr)
		}
		h.ok()
		return nil
	case hostkit.AbsentTable:
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return h.fail(op, tgt, ce)
	}
	retries, throttles, abortErr = scope.finish(0, 0, true, true)
	if abortErr != nil {
		failed = true
		return h.fail(op, tgt, abortErr)
	}
	exists, perr := h.meteredTableExists(ctx, table, true)
	if perr != nil {
		failed = true
		return h.fail(op, tgt, perr)
	}
	if !exists {
		failed = true
		return h.fail(op, tgt, ce.WithAbsent(hostkit.AbsentTable))
	}
	h.ok()
	return nil
}

// ItemUpdate implements both item_update(table, pk, changes) and item_update(table, pk, sk, changes).
func (h *Host) ItemUpdate(dry bool, table, pk, sk string, hasSK bool, changes *TableItem) (*TableItem, error) {
	const op = "item_update"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesOut int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, 0, bytesOut)
		}
	}()
	none := emptyTableItem(h, pk, sk)
	tgt := tableItemTarget(table, pk, sk)
	if e := h.cfg.Validator.Table(table); e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	if e := h.cfg.Validator.TableKey(pk); e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	if hasSK {
		if e := h.cfg.Validator.TableKey(sk); e != nil {
			failed = true
			return none, h.fail(op, tgt, e)
		}
	}
	rawChanges, inv := changes.snapshot()
	if inv != nil {
		failed = true
		return none, h.fail(op, tgt, inv)
	}
	chgBytes, cerr := hostkit.CanonicalItemBytes(rawChanges.Attrs)
	if cerr != nil {
		failed = true
		return none, h.fail(op, tgt, cerr)
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return none, h.fail(op, tgt, e)
	}
	defer cancel()
	if dry {
		if e := h.requireTable(ctx, true, table); e != nil {
			failed = true
			return none, h.fail(op, tgt, e)
		}
		ik := pk + "\x00" + sk
		st, cur := h.ov(ctx).tableItem(table, ik)
		if st == dryObjectGone {
			failed = true
			return none, h.fail(op, tgt, notFound(hostkit.AbsentItem, "item does not exist (dry-run preview)"))
		}
		if st == dryUnknown {
			curIt, err := h.ItemGet(true, table, pk, sk, hasSK)
			if err != nil {
				failed = true
				return none, err
			}
			if !curIt.Exists() {
				failed = true
				return none, h.fail(op, tgt, notFound(hostkit.AbsentItem, "item does not exist (dry-run preview)"))
			}
			cur, _ = curIt.snapshot()
		}
		if cur.Attrs == nil {
			cur.Attrs = map[string]hostkit.Attr{}
		}
		for k, v := range rawChanges.Attrs {
			cur.Attrs[k] = v.Clone()
		}
		if _, cerr := hostkit.CanonicalItemBytes(cur.Attrs); cerr != nil {
			failed = true
			return none, h.fail(op, tgt, cerr)
		}
		cur.PK = pk
		cur.SK = sk
		cur.Exists = true
		cur.Version = h.ov(ctx).nextDryVersion(table, pk, sk)
		h.ov(ctx).putTableItem(table, ik, cur)
		h.ok()
		return newTableItemFromHostkit(h, cur), nil
	}
	if h.cfg.Tables == nil {
		failed = true
		return none, h.fail(op, tgt, missingTables())
	}
	rawChanges.PK = pk
	rawChanges.SK = sk
	mctx, scope, rerr := h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, PayloadSize: hostkit.MaxItemCanonicalBytes}, safety.KindTableItem, tgt)
	if rerr != nil {
		failed = true
		return none, h.fail(op, tgt, rerr)
	}
	updated, err := h.cfg.Tables.UpdateItem(mctx, table, pk, sk, rawChanges)
	var abortErr *hostkit.CloudError
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if ce != nil && ce.Preflight {
			if relErr := h.cost.release(scope.res, scope.attemptID); relErr != nil {
				ce = relErr
			}
		} else {
			retries, throttles, abortErr = scope.finish(int64(chgBytes), int64(chgBytes), false, false)
			if abortErr != nil {
				ce = abortErr
			}
		}
		failed = true
		return none, h.fail(op, tgt, ce)
	}
	validUpdated, updBytes, verr := h.validateReturnedItem(updated, true)
	if verr != nil {
		retries, throttles, abortErr = scope.finish(updBytes, updBytes, true, false)
		if abortErr != nil {
			verr = abortErr
		}
		failed = true
		return none, h.fail(op, tgt, verr)
	}
	chargeBytes := updBytes
	if int64(chgBytes) > chargeBytes {
		chargeBytes = int64(chgBytes)
	}
	retries, throttles, abortErr = scope.finish(chargeBytes, int64(chgBytes), true, true)
	if abortErr != nil {
		failed = true
		return none, h.fail(op, tgt, abortErr)
	}
	bytesOut = int64(chgBytes)
	h.ok()
	return newTableItemFromHostkit(h, validUpdated), nil
}

// ItemQuery implements both item_query overloads.
func (h *Host) ItemQuery(dry bool, table, pk, skFrom, skTo string, maxItems int64, token string) (*TablePage, error) {
	const op = "item_query"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()
	empty := &TablePage{}
	tgt := tableItemTarget(table, pk, "")
	for _, e := range []*hostkit.CloudError{
		h.cfg.Validator.Table(table),
		h.cfg.Validator.TableKey(pk),
		h.cfg.Validator.QueryRange(skFrom, skTo),
	} {
		if e != nil {
			failed = true
			return empty, h.fail(op, tgt, e)
		}
	}
	max, e := hostkit.TablePageMax(maxItems)
	if e != nil {
		failed = true
		return empty, h.fail(op, tgt, e)
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return empty, h.fail(op, tgt, e)
	}
	defer cancel()
	ep := hostkit.EndpointFrom(ctx)
	envWant := tableCursorEnvelope{
		EP:     ep,
		Op:     op,
		Table:  table,
		PK:     pk,
		SKFrom: skFrom,
		SKTo:   skTo,
	}
	rawToken, e := decodeTableCursor(token, envWant)
	if e != nil {
		failed = true
		return empty, h.fail(op, tgt, e)
	}
	if dry {
		if dt, ok := h.ov(ctx).table(table); ok {
			if !dt.exists {
				failed = true
				return empty, h.fail(op, tgt, notFound(hostkit.AbsentTable, "table does not exist (dry-run preview)"))
			}
			if dt.hasSorted && !dt.sorted && (skFrom != "" || skTo != "") {
				failed = true
				return empty, h.fail(op, tgt, hostkit.Preflightf("sort key range [sk_from, sk_to) is not valid on partition-key-only table %q", table))
			}
			if dt.createdNow {
				h.ok()
				return empty, nil
			}
		}
	}
	if h.cfg.Tables == nil {
		failed = true
		return empty, h.fail(op, tgt, missingTables())
	}
	var scope *attemptScope
	mctx := ctx
	maxPageBytes := int64(max) * hostkit.MaxItemCanonicalBytes
	if !dry {
		var cerr *hostkit.CloudError
		mctx, scope, cerr = h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, PayloadSize: maxPageBytes}, safety.KindTable, table)
		if cerr != nil {
			failed = true
			return empty, h.fail(op, tgt, cerr)
		}
	}
	page, err := h.cfg.Tables.Query(mctx, table, pk, skFrom, skTo, max, rawToken)
	var abortErr *hostkit.CloudError
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if !dry {
			if ce != nil && ce.Preflight {
				if relErr := h.cost.release(scope.res, scope.attemptID); relErr != nil {
					ce = relErr
				}
			} else {
				retries, throttles, abortErr = scope.finish(0, 0, true, false)
				if abortErr != nil {
					ce = abortErr
				}
			}
		}
		failed = true
		return empty, h.fail(op, tgt, ce)
	}
	if len(page.Items) > max {
		retries, throttles, abortErr = scope.finish(maxPageBytes, maxPageBytes, true, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned more items than max_items")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return empty, h.fail(op, tgt, ce)
	}
	if rawToken != "" && page.NextToken == rawToken {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "pagination stalled: continuation token repeated")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return empty, h.fail(op, tgt, ce)
	}
	outItems := make([]*TableItem, 0, len(page.Items))
	var pageBytes int64
	for _, it := range page.Items {
		validIt, ib, verr := h.validateReturnedItem(it, true)
		pageBytes += ib
		if verr != nil {
			retries, throttles, abortErr = scope.finish(pageBytes, pageBytes, true, false)
			if abortErr != nil {
				verr = abortErr
			}
			failed = true
			return empty, h.fail(op, tgt, verr)
		}
		outItems = append(outItems, newTableItemFromHostkit(h, validIt))
	}
	sort.SliceStable(outItems, func(i, j int) bool { return outItems[i].SK() < outItems[j].SK() })
	retries, throttles, abortErr = scope.finish(pageBytes, pageBytes, true, true)
	if abortErr != nil {
		failed = true
		return empty, h.fail(op, tgt, abortErr)
	}
	bytesIn = pageBytes
	envWant.Raw = page.NextToken
	h.ok()
	return &TablePage{Items: outItems, NextToken: encodeTableCursor(envWant)}, nil
}

// ItemScan implements both item_scan overloads.
func (h *Host) ItemScan(dry bool, table string, maxItems int64, token string) (*TablePage, error) {
	const op = "item_scan"
	start := h.cfg.Now()
	failed := false
	var retries, throttles, bytesIn int64
	defer func() {
		if !dry {
			h.metrics.record(op, h.cfg.Now().Sub(start), failed, retries, throttles, bytesIn, 0)
		}
	}()
	empty := &TablePage{}
	if e := h.cfg.Validator.Table(table); e != nil {
		failed = true
		return empty, h.fail(op, table, e)
	}
	max, e := hostkit.TablePageMax(maxItems)
	if e != nil {
		failed = true
		return empty, h.fail(op, table, e)
	}
	ctx, cancel, e := h.opCtx("tables", h.cfg.OpTimeout)
	if e != nil {
		failed = true
		return empty, h.fail(op, table, e)
	}
	defer cancel()
	ep := hostkit.EndpointFrom(ctx)
	envWant := tableCursorEnvelope{
		EP:    ep,
		Op:    op,
		Table: table,
	}
	rawToken, e := decodeTableCursor(token, envWant)
	if e != nil {
		failed = true
		return empty, h.fail(op, table, e)
	}
	if dry {
		if dt, ok := h.ov(ctx).table(table); ok {
			if !dt.exists {
				failed = true
				return empty, h.fail(op, table, notFound(hostkit.AbsentTable, "table does not exist (dry-run preview)"))
			}
			if dt.createdNow {
				h.ok()
				return empty, nil
			}
		}
	}
	if h.cfg.Tables == nil {
		failed = true
		return empty, h.fail(op, table, missingTables())
	}
	var scope *attemptScope
	mctx := ctx
	maxPageBytes := int64(max) * hostkit.MaxItemCanonicalBytes
	if !dry {
		var cerr *hostkit.CloudError
		mctx, scope, cerr = h.beginAttemptScope(ctx, op, safety.AttemptPricingInput{Operation: op, PayloadSize: maxPageBytes}, safety.KindTable, table)
		if cerr != nil {
			failed = true
			return empty, h.fail(op, table, cerr)
		}
	}
	page, err := h.cfg.Tables.Scan(mctx, table, max, rawToken)
	var abortErr *hostkit.CloudError
	if err != nil {
		ce := hostkit.AsCloudError(err)
		if !dry {
			if ce != nil && ce.Preflight {
				if relErr := h.cost.release(scope.res, scope.attemptID); relErr != nil {
					ce = relErr
				}
			} else {
				retries, throttles, abortErr = scope.finish(0, 0, true, false)
				if abortErr != nil {
					ce = abortErr
				}
			}
		}
		failed = true
		return empty, h.fail(op, table, ce)
	}
	if len(page.Items) > max {
		retries, throttles, abortErr = scope.finish(maxPageBytes, maxPageBytes, true, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "provider returned more items than max_items")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return empty, h.fail(op, table, ce)
	}
	if rawToken != "" && page.NextToken == rawToken {
		retries, throttles, abortErr = scope.finish(0, 0, true, false)
		ce := hostkit.ProviderError(hostkit.Internal, 0, "", "pagination stalled: continuation token repeated")
		if abortErr != nil {
			ce = abortErr
		}
		failed = true
		return empty, h.fail(op, table, ce)
	}
	outItems := make([]*TableItem, 0, len(page.Items))
	var pageBytes int64
	for _, it := range page.Items {
		validIt, ib, verr := h.validateReturnedItem(it, true)
		pageBytes += ib
		if verr != nil {
			retries, throttles, abortErr = scope.finish(pageBytes, pageBytes, true, false)
			if abortErr != nil {
				verr = abortErr
			}
			failed = true
			return empty, h.fail(op, table, verr)
		}
		outItems = append(outItems, newTableItemFromHostkit(h, validIt))
	}
	retries, throttles, abortErr = scope.finish(pageBytes, pageBytes, true, true)
	if abortErr != nil {
		failed = true
		return empty, h.fail(op, table, abortErr)
	}
	bytesIn = pageBytes
	envWant.Raw = page.NextToken
	h.ok()
	return &TablePage{Items: outItems, NextToken: encodeTableCursor(envWant)}, nil
}
