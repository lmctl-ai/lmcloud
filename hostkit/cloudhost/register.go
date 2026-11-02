// SPDX-License-Identifier: MIT

package cloudhost

import (
	"fmt"
	"io"
	"os"
	"sort"

	lmcode "github.com/lmctl-ai/lmcode-go"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// Snapshot types handed to the VM. They are immutable after creation, so
// their accessors are identical in real and dry runs.
type (
	errSnapshot  struct{ e hostkit.CloudError }
	metaSnapshot struct{ m hostkit.ObjectMeta }
	summary      struct{ s hostkit.ObjectSummary }
	pageSnapshot struct{ p Page }
	message      struct{ m Message }
	messageList  struct{ items []Message }
)

type method = func(self any, args []lmcode.Value) (lmcode.Value, error)

// hostErr converts an abort into the RUN_HOST error the VM reports.
func hostErr(err error) error {
	if err == nil {
		return nil
	}
	return lmcode.NewHostError(err.Error())
}

type registrar struct {
	reg   *lmcode.Registry
	first error
}

func (r *registrar) must(err error) {
	if err != nil && r.first == nil {
		r.first = err
	}
}

// pure registers a method whose dry behaviour equals its real behaviour
// (local state or immutable snapshots).
func (r *registrar) pure(typ, name string, params []string, ret string, fn method) {
	r.must(r.reg.Method(typ, name, params, ret, fn, lmcode.Dry[lmcode.Method](fn)))
}

// op registers a Cloud operation as (real, dry) from one dry-aware implementation.
func (r *registrar) op(name string, params []string, ret string, impl func(h *Host, dry bool, args []lmcode.Value) (lmcode.Value, error)) {
	real := func(self any, args []lmcode.Value) (lmcode.Value, error) { return impl(self.(*Host), false, args) }
	dry := func(self any, args []lmcode.Value) (lmcode.Value, error) { return impl(self.(*Host), true, args) }
	r.must(r.reg.Method("Cloud", name, params, ret, real, lmcode.Dry[lmcode.Method](dry)))
}

func (r *registrar) strList(items []string) (lmcode.Value, error) {
	newList := r.reg.FunctionBySignature("fn str_list() -> StrList")
	add := r.reg.MethodBySignature("method StrList.add(string) -> StrList")
	if newList == nil || add == nil {
		return lmcode.None(), lmcode.NewHostError("std StrList is not registered")
	}
	v, err := newList.Fn(nil)
	if err != nil {
		return lmcode.None(), err
	}
	for _, s := range items {
		if _, err := add.Fn(v.Obj, []lmcode.Value{lmcode.String(s)}); err != nil {
			return lmcode.None(), err
		}
	}
	return v, nil
}

func (r *registrar) strMap(m map[string]string) (lmcode.Value, error) {
	newMap := r.reg.FunctionBySignature("fn str_map() -> StrMap")
	set := r.reg.MethodBySignature("method StrMap.set(string, string) -> StrMap")
	if newMap == nil || set == nil {
		return lmcode.None(), lmcode.NewHostError("std StrMap is not registered")
	}
	v, err := newMap.Fn(nil)
	if err != nil {
		return lmcode.None(), err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, err := set.Fn(v.Obj, []lmcode.Value{lmcode.String(k), lmcode.String(m[k])}); err != nil {
			return lmcode.None(), err
		}
	}
	return v, nil
}

func strMapArg(v lmcode.Value) (map[string]string, error) {
	if v.Obj == nil {
		return map[string]string{}, nil
	}
	sm, ok := v.Obj.(*lmcode.StrMap)
	if !ok {
		return nil, lmcode.NewHostError(fmt.Sprintf("expected StrMap, got %T", v.Obj))
	}
	out := map[string]string{}
	for _, e := range sm.Entries() {
		out[e.Key] = e.Value
	}
	return out, nil
}

// Register binds the shared schema: testing helpers, the `cloud` context and
// every method, each with an explicit dry slot. out receives print output.
func Register(reg *lmcode.Registry, out io.Writer) error {
	if out == nil {
		out = os.Stdout
	}
	r := &registrar{reg: reg}
	r.must(lmcode.RegisterTesting(reg, out))
	for _, t := range []string{"bool", "float", "int"} {
		t := t
		fn := lmcode.Function(func(args []lmcode.Value) (lmcode.Value, error) {
			var s string
			switch t {
			case "bool":
				s = fmt.Sprint(args[0].Bool)
			case "float":
				s = lmcode.FormatG15(args[0].Float)
			default:
				s = fmt.Sprint(args[0].Int)
			}
			_, err := io.WriteString(out, s+"\n")
			return lmcode.None(), err
		})
		r.must(reg.Function("print", []string{t}, "void", fn, lmcode.Dry(fn)))
	}
	r.must(reg.Context("cloud", "Cloud"))
	r.must(declareEnums(reg))

	// Configuration and status: local state, identical in dry runs.
	r.pure("Cloud", "provider", nil, "string", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(self.(*Host).Provider()), nil
	})
	r.pure("Cloud", "endpoint", []string{"string"}, "string", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		ep, err := self.(*Host).Endpoint(a[0].Str)
		return lmcode.String(ep), hostErr(err)
	})
	r.pure("Cloud", "set_endpoint", []string{"string", "string"}, "Cloud", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		h := self.(*Host)
		return lmcode.Object("Cloud", h), hostErr(h.SetEndpoint(a[0].Str, a[1].Str))
	})
	r.pure("Cloud", "abort_on_error", nil, "bool", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(self.(*Host).AbortOnError()), nil
	})
	r.pure("Cloud", "set_abort_on_error", []string{"bool"}, "Cloud", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		h := self.(*Host)
		h.SetAbortOnError(a[0].Bool)
		return lmcode.Object("Cloud", h), nil
	})
	r.pure("Cloud", "last_error", nil, "CloudError", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("CloudError", &errSnapshot{e: self.(*Host).LastError()}), nil
	})

	// Buckets.
	r.op("bucket_create", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.BucketCreate(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("bucket_delete", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.BucketDelete(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("bucket_exists", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.BucketExists(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("bucket_list", nil, "StrList", func(h *Host, dry bool, _ []lmcode.Value) (lmcode.Value, error) {
		v, err := h.BucketList(dry)
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return r.strList(v)
	})

	// Objects.
	putMeta := func(m *hostkit.ObjectMeta, err error) (lmcode.Value, error) {
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("ObjectMeta", &metaSnapshot{m: *m}), nil
	}
	r.op("object_put", []string{"string", "string", "string"}, "ObjectMeta", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return putMeta(h.ObjectPut(dry, a[0].Str, a[1].Str, a[2].Str, "application/octet-stream", map[string]string{}))
	})
	r.op("object_put", []string{"string", "string", "string", "string", "StrMap"}, "ObjectMeta", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		meta, err := strMapArg(a[4])
		if err != nil {
			return lmcode.None(), err
		}
		return putMeta(h.ObjectPut(dry, a[0].Str, a[1].Str, a[2].Str, a[3].Str, meta))
	})
	r.op("object_get", []string{"string", "string"}, "string", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.ObjectGet(dry, a[0].Str, a[1].Str)
		return lmcode.String(v), hostErr(err)
	})
	r.op("object_head", []string{"string", "string"}, "ObjectMeta", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return putMeta(h.ObjectHead(dry, a[0].Str, a[1].Str))
	})
	r.op("object_delete", []string{"string", "string"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), hostErr(h.ObjectDelete(dry, a[0].Str, a[1].Str))
	})
	listPage := func(p *Page, err error) (lmcode.Value, error) {
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("ObjectListPage", &pageSnapshot{p: *p}), nil
	}
	r.op("object_list", []string{"string", "string"}, "ObjectListPage", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return listPage(h.ObjectList(dry, a[0].Str, a[1].Str, 0, ""))
	})
	r.op("object_list", []string{"string", "string", "int", "string"}, "ObjectListPage", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return listPage(h.ObjectList(dry, a[0].Str, a[1].Str, a[2].Int, a[3].Str))
	})
	r.op("object_list_all", []string{"string", "string"}, "StrList", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.ObjectListAll(dry, a[0].Str, a[1].Str)
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return r.strList(v)
	})

	// Queues.
	r.op("queue_create", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.QueueCreate(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("queue_delete", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.QueueDelete(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("queue_exists", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.QueueExists(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("queue_list", nil, "StrList", func(h *Host, dry bool, _ []lmcode.Value) (lmcode.Value, error) {
		v, err := h.QueueList(dry)
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return r.strList(v)
	})
	r.op("queue_send", []string{"string", "string"}, "string", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.QueueSend(dry, a[0].Str, a[1].Str)
		return lmcode.String(v), hostErr(err)
	})
	recv := func(msgs []Message, err error) (lmcode.Value, error) {
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("QueueMessageList", &messageList{items: msgs}), nil
	}
	r.op("queue_receive", []string{"string"}, "QueueMessageList", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return recv(h.QueueReceive(dry, a[0].Str, hostkit.DefaultReceiveMax, hostkit.DefaultReceiveWait, hostkit.DefaultReceiveVisible))
	})
	r.op("queue_receive", []string{"string", "int", "int", "int"}, "QueueMessageList", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return recv(h.QueueReceive(dry, a[0].Str, a[1].Int, a[2].Int, a[3].Int))
	})
	r.op("queue_ack", []string{"string", "string"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), hostErr(h.QueueAck(dry, a[0].Str, a[1].Str))
	})
	r.op("queue_nack", []string{"string", "string", "int"}, "string", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.QueueNack(dry, a[0].Str, a[1].Str, a[2].Int)
		return lmcode.String(v), hostErr(err)
	})

	// Snapshot accessors.
	ce := func(self any) hostkit.CloudError { return self.(*errSnapshot).e }
	r.pure("CloudError", "ok", nil, "bool", func(s any, _ []lmcode.Value) (lmcode.Value, error) { e := ce(s); return lmcode.Bool(e.OK()), nil })
	r.pure("CloudError", "code", nil, "ErrorCode", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(string(ce(s).Code)), nil })
	r.pure("CloudError", "http_status", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(int64(ce(s).HTTPStatus)), nil })
	r.pure("CloudError", "provider_code", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(ce(s).ProviderCode), nil })
	r.pure("CloudError", "message", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(ce(s).Message), nil })

	om := func(self any) hostkit.ObjectMeta { return self.(*metaSnapshot).m }
	r.pure("ObjectMeta", "exists", nil, "bool", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Bool(om(s).Exists), nil })
	r.pure("ObjectMeta", "bucket", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(om(s).Bucket), nil })
	r.pure("ObjectMeta", "key", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(om(s).Key), nil })
	r.pure("ObjectMeta", "size", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(om(s).Size), nil })
	r.pure("ObjectMeta", "etag", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(om(s).ETag), nil })
	r.pure("ObjectMeta", "content_type", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(om(s).ContentType), nil })
	r.pure("ObjectMeta", "metadata", nil, "StrMap", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return r.strMap(om(s).Metadata) })

	sm := func(self any) hostkit.ObjectSummary { return self.(*summary).s }
	r.pure("ObjectSummary", "key", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(sm(s).Key), nil })
	r.pure("ObjectSummary", "size", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(sm(s).Size), nil })
	r.pure("ObjectSummary", "etag", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(sm(s).ETag), nil })

	pg := func(self any) Page { return self.(*pageSnapshot).p }
	r.pure("ObjectListPage", "len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(int64(len(pg(s).Items))), nil })
	r.pure("ObjectListPage", "at", []string{"int"}, "ObjectSummary", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		p := pg(s)
		if a[0].Int < 0 || a[0].Int >= int64(len(p.Items)) {
			return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("ObjectListPage.at(%d): %v (len %d)", a[0].Int, errIndex, len(p.Items)))
		}
		return lmcode.Object("ObjectSummary", &summary{s: p.Items[a[0].Int]}), nil
	})
	r.pure("ObjectListPage", "keys", nil, "StrList", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		p := pg(s)
		keys := make([]string, len(p.Items))
		for i, it := range p.Items {
			keys[i] = it.Key
		}
		return r.strList(keys)
	})
	r.pure("ObjectListPage", "has_more", nil, "bool", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Bool(pg(s).NextToken != ""), nil })
	r.pure("ObjectListPage", "next_token", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(pg(s).NextToken), nil })

	qm := func(self any) Message { return self.(*message).m }
	r.pure("QueueMessage", "id", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(qm(s).ID), nil })
	r.pure("QueueMessage", "body", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(qm(s).Body), nil })
	r.pure("QueueMessage", "receipt", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(qm(s).Receipt), nil })
	ml := func(self any) []Message { return self.(*messageList).items }
	r.pure("QueueMessageList", "len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(int64(len(ml(s)))), nil })
	r.pure("QueueMessageList", "at", []string{"int"}, "QueueMessage", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		items := ml(s)
		if a[0].Int < 0 || a[0].Int >= int64(len(items)) {
			return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("QueueMessageList.at(%d): %v (len %d)", a[0].Int, errIndex, len(items)))
		}
		return lmcode.Object("QueueMessage", &message{m: items[a[0].Int]}), nil
	})
	return r.first
}

// enumDeclarer is lmcode-go's Registry.Enum (proposed patch, branch
// dry-enum-string). It is called through an interface so hostkit still
// builds against an lmcode-go without it; such builds keep the old dry-run
// limitation for enum results (last_error().code() in --dry-run).
type enumDeclarer interface {
	Enum(name string, values []string) error
}

// EnumsDeclared reports whether the linked lmcode-go can declare the schema's
// ErrorCode enum, i.e. whether dry runs can evaluate last_error().code().
func EnumsDeclared() bool {
	_, ok := any(lmcode.NewRegistryWithoutStd()).(enumDeclarer)
	return ok
}

func declareEnums(reg *lmcode.Registry) error {
	d, ok := any(reg).(enumDeclarer)
	if !ok {
		return nil
	}
	codes := make([]string, len(hostkit.Codes))
	for i, c := range hostkit.Codes {
		codes[i] = string(c)
	}
	return d.Enum("ErrorCode", codes)
}
