// SPDX-License-Identifier: MIT

package cloudhost

import (
	"fmt"
	"io"
	"math"
	"os"
	"sort"

	lmcode "github.com/lmctl-ai/lmcode-go"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// Snapshot types handed to the VM. They are immutable after creation, so
// their accessors are identical in real and dry runs.
type (
	errSnapshot           struct{ e hostkit.CloudError }
	metaSnapshot          struct{ m hostkit.ObjectMeta }
	summary               struct{ s hostkit.ObjectSummary }
	pageSnapshot          struct{ p Page }
	message               struct{ m Message }
	messageList           struct{ items []Message }
	costLineItemSnapshot  struct{ it CostLineItem }
	costReportSnapshot    struct{ r CostReport }
	opMetricsSnapshot     struct{ m OpMetrics }
	metricsReportSnapshot struct{ r MetricsReport }
	tablePageSnapshot     struct{ p TablePage }
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

func strListArg(v lmcode.Value) ([]string, error) {
	if v.Obj == nil {
		return nil, nil
	}
	sl, ok := v.Obj.(*lmcode.StrList)
	if !ok {
		return nil, lmcode.NewHostError(fmt.Sprintf("expected StrList, got %T", v.Obj))
	}
	return sl.Values(), nil
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

	// Tables & Items.
	tableItemVal := func(it *TableItem, err error) (lmcode.Value, error) {
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("TableItem", it), nil
	}
	tableItemArg := func(v lmcode.Value) (*TableItem, error) {
		if v.Obj == nil {
			return nil, lmcode.NewHostError("expected TableItem, got nil")
		}
		it, ok := v.Obj.(*TableItem)
		if !ok {
			return nil, lmcode.NewHostError(fmt.Sprintf("expected TableItem, got %T", v.Obj))
		}
		return it, nil
	}
	r.pure("Cloud", "item_new", []string{"string"}, "TableItem", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return tableItemVal(self.(*Host).ItemNew(a[0].Str, "", false))
	})
	r.pure("Cloud", "item_new", []string{"string", "string"}, "TableItem", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return tableItemVal(self.(*Host).ItemNew(a[0].Str, a[1].Str, true))
	})
	r.op("table_create", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.TableCreate(dry, a[0].Str, false)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("table_create", []string{"string", "bool"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.TableCreate(dry, a[0].Str, a[1].Bool)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("table_delete", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.TableDelete(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("table_exists", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.TableExists(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("table_list", nil, "StrList", func(h *Host, dry bool, _ []lmcode.Value) (lmcode.Value, error) {
		v, err := h.TableList(dry)
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return r.strList(v)
	})
	r.op("item_put", []string{"string", "TableItem"}, "TableItem", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		it, err := tableItemArg(a[1])
		if err != nil {
			return lmcode.None(), err
		}
		return tableItemVal(h.ItemPut(dry, a[0].Str, it, hostkit.PutUnconditional, ""))
	})
	r.op("item_put", []string{"string", "TableItem", "string"}, "TableItem", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		it, err := tableItemArg(a[1])
		if err != nil {
			return lmcode.None(), err
		}
		mode := hostkit.PutIfVersion
		if a[2].Str == "" {
			mode = hostkit.PutIfAbsent
		}
		return tableItemVal(h.ItemPut(dry, a[0].Str, it, mode, a[2].Str))
	})
	r.op("item_get", []string{"string", "string"}, "TableItem", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return tableItemVal(h.ItemGet(dry, a[0].Str, a[1].Str, "", false))
	})
	r.op("item_get", []string{"string", "string", "string"}, "TableItem", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return tableItemVal(h.ItemGet(dry, a[0].Str, a[1].Str, a[2].Str, true))
	})
	r.op("item_delete", []string{"string", "string"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), hostErr(h.ItemDelete(dry, a[0].Str, a[1].Str, "", false))
	})
	r.op("item_delete", []string{"string", "string", "string"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), hostErr(h.ItemDelete(dry, a[0].Str, a[1].Str, a[2].Str, true))
	})
	r.op("item_update", []string{"string", "string", "TableItem"}, "TableItem", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		it, err := tableItemArg(a[2])
		if err != nil {
			return lmcode.None(), err
		}
		return tableItemVal(h.ItemUpdate(dry, a[0].Str, a[1].Str, "", false, it))
	})
	r.op("item_update", []string{"string", "string", "string", "TableItem"}, "TableItem", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		it, err := tableItemArg(a[3])
		if err != nil {
			return lmcode.None(), err
		}
		return tableItemVal(h.ItemUpdate(dry, a[0].Str, a[1].Str, a[2].Str, true, it))
	})
	tablePageVal := func(p *TablePage, err error) (lmcode.Value, error) {
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("TablePage", &tablePageSnapshot{p: *p}), nil
	}
	r.op("item_query", []string{"string", "string"}, "TablePage", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return tablePageVal(h.ItemQuery(dry, a[0].Str, a[1].Str, "", "", 0, ""))
	})
	r.op("item_query", []string{"string", "string", "string", "string", "int", "string"}, "TablePage", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return tablePageVal(h.ItemQuery(dry, a[0].Str, a[1].Str, a[2].Str, a[3].Str, a[4].Int, a[5].Str))
	})
	r.op("item_scan", []string{"string"}, "TablePage", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return tablePageVal(h.ItemScan(dry, a[0].Str, 0, ""))
	})
	r.op("item_scan", []string{"string", "int", "string"}, "TablePage", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return tablePageVal(h.ItemScan(dry, a[0].Str, a[1].Int, a[2].Str))
	})

	// Permissions.
	policyVal := func(p *Policy, err error) (lmcode.Value, error) {
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("Policy", p), nil
	}
	policyArg := func(v lmcode.Value) (*Policy, error) {
		if v.Obj == nil {
			return nil, lmcode.NewHostError("expected Policy, got nil")
		}
		p, ok := v.Obj.(*Policy)
		if !ok {
			return nil, lmcode.NewHostError(fmt.Sprintf("expected Policy, got %T", v.Obj))
		}
		return p, nil
	}
	r.op("principal_current", nil, "string", func(h *Host, dry bool, _ []lmcode.Value) (lmcode.Value, error) {
		v, err := h.PrincipalCurrent(dry)
		return lmcode.String(v), hostErr(err)
	})
	r.pure("Cloud", "policy_new", nil, "Policy", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("Policy", self.(*Host).PolicyNew()), nil
	})
	r.pure("Cloud", "policy_parse", []string{"string"}, "Policy", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return policyVal(self.(*Host).PolicyParse(a[0].Str))
	})
	r.pure("Cloud", "policy_lint", []string{"Policy"}, "LintReport", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		p, err := policyArg(a[0])
		if err != nil {
			return lmcode.None(), err
		}
		rep, err := self.(*Host).PolicyLint(p)
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("LintReport", rep), nil
	})
	r.op("policy_attach", []string{"string", "string", "Policy"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		p, err := policyArg(a[2])
		if err != nil {
			return lmcode.None(), err
		}
		return lmcode.None(), hostErr(h.PolicyAttach(dry, a[0].Str, a[1].Str, p))
	})
	r.op("policy_attach_principal", []string{"string", "Policy"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		p, err := policyArg(a[1])
		if err != nil {
			return lmcode.None(), err
		}
		return lmcode.None(), hostErr(h.PolicyAttachPrincipal(dry, a[0].Str, p))
	})
	r.op("policy_detach", []string{"string", "string"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), hostErr(h.PolicyDetach(dry, a[0].Str, a[1].Str))
	})
	r.op("policy_detach_principal", []string{"string"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), hostErr(h.PolicyDetachPrincipal(dry, a[0].Str))
	})
	r.op("policy_check", []string{"string", "string", "string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.PolicyCheck(dry, a[0].Str, a[1].Str, a[2].Str)
		return lmcode.Bool(v), hostErr(err)
	})

	// Functions.
	fnCfgVal := func(fc *FunctionConfig, err error) (lmcode.Value, error) {
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("FunctionConfig", fc), nil
	}
	fnCfgArg := func(v lmcode.Value) (*FunctionConfig, error) {
		if v.Obj == nil {
			return nil, lmcode.NewHostError("expected FunctionConfig, got nil")
		}
		fc, ok := v.Obj.(*FunctionConfig)
		if !ok {
			return nil, lmcode.NewHostError(fmt.Sprintf("expected FunctionConfig, got %T", v.Obj))
		}
		return fc, nil
	}
	fnInvVal := func(res *FunctionInvokeResult, err error) (lmcode.Value, error) {
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return lmcode.Object("FunctionInvokeResult", res), nil
	}
	r.pure("Cloud", "function_config", []string{"string", "string"}, "FunctionConfig", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(self.(*Host).FunctionConfig(a[0].Str, a[1].Str))
	})
	r.op("function_create", []string{"string", "FunctionConfig"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		fc, err := fnCfgArg(a[1])
		if err != nil {
			return lmcode.None(), err
		}
		v, err := h.FunctionCreate(dry, a[0].Str, fc)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("function_update", []string{"string", "FunctionConfig"}, "FunctionConfig", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		fc, err := fnCfgArg(a[1])
		if err != nil {
			return lmcode.None(), err
		}
		return fnCfgVal(h.FunctionUpdate(dry, a[0].Str, fc, "", false))
	})
	r.op("function_update", []string{"string", "FunctionConfig", "string"}, "FunctionConfig", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		fc, err := fnCfgArg(a[1])
		if err != nil {
			return lmcode.None(), err
		}
		return fnCfgVal(h.FunctionUpdate(dry, a[0].Str, fc, a[2].Str, true))
	})
	r.op("function_delete", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.FunctionDelete(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("function_exists", []string{"string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.FunctionExists(dry, a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("function_get", []string{"string"}, "FunctionConfig", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(h.FunctionGet(dry, a[0].Str, "", false))
	})
	r.op("function_get", []string{"string", "string"}, "FunctionConfig", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(h.FunctionGet(dry, a[0].Str, a[1].Str, true))
	})
	r.op("function_list", nil, "StrList", func(h *Host, dry bool, _ []lmcode.Value) (lmcode.Value, error) {
		v, err := h.FunctionList(dry)
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return r.strList(v)
	})
	r.op("function_publish_version", []string{"string"}, "string", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.FunctionPublishVersion(dry, a[0].Str, "", false)
		return lmcode.String(v), hostErr(err)
	})
	r.op("function_publish_version", []string{"string", "string"}, "string", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.FunctionPublishVersion(dry, a[0].Str, a[1].Str, true)
		return lmcode.String(v), hostErr(err)
	})
	r.op("function_versions", []string{"string"}, "StrList", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.FunctionVersions(dry, a[0].Str)
		if err != nil {
			return lmcode.None(), hostErr(err)
		}
		return r.strList(v)
	})
	r.op("function_alias_set", []string{"string", "string", "string"}, "void", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.None(), hostErr(h.FunctionAliasSet(dry, a[0].Str, a[1].Str, a[2].Str))
	})
	r.op("function_alias_get", []string{"string", "string"}, "string", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.FunctionAliasGet(dry, a[0].Str, a[1].Str)
		return lmcode.String(v), hostErr(err)
	})
	r.op("function_alias_delete", []string{"string", "string"}, "bool", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		v, err := h.FunctionAliasDelete(dry, a[0].Str, a[1].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.op("function_invoke", []string{"string", "string"}, "FunctionInvokeResult", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return fnInvVal(h.FunctionInvoke(dry, a[0].Str, "", a[1].Str, false))
	})
	r.op("function_invoke", []string{"string", "string", "string"}, "FunctionInvokeResult", func(h *Host, dry bool, a []lmcode.Value) (lmcode.Value, error) {
		return fnInvVal(h.FunctionInvoke(dry, a[0].Str, a[1].Str, a[2].Str, true))
	})

	// Cost & Performance.
	r.pure("Cloud", "cost_cap_usd", nil, "float", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Float(self.(*Host).CostCapUSD()), nil
	})
	r.pure("Cloud", "set_cost_cap_usd", []string{"float"}, "Cloud", func(self any, a []lmcode.Value) (lmcode.Value, error) {
		h := self.(*Host)
		return lmcode.Object("Cloud", h), hostErr(h.SetCostCapUSD(a[0].Float))
	})
	r.pure("Cloud", "estimated_cost", nil, "float", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Float(self.(*Host).EstimatedCost()), nil
	})
	r.pure("Cloud", "cost_report", nil, "CostReport", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("CostReport", &costReportSnapshot{r: self.(*Host).CostReport()}), nil
	})
	r.pure("Cloud", "metrics_reset", nil, "Cloud", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		h := self.(*Host)
		h.MetricsReset()
		return lmcode.Object("Cloud", h), nil
	})
	r.pure("Cloud", "metrics", nil, "MetricsReport", func(self any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("MetricsReport", &metricsReportSnapshot{r: self.(*Host).Metrics()}), nil
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

	cli := func(self any) CostLineItem { return self.(*costLineItemSnapshot).it }
	r.pure("CostLineItem", "operation", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(cli(s).Operation), nil })
	r.pure("CostLineItem", "service", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(cli(s).Service), nil })
	r.pure("CostLineItem", "requests", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(cli(s).Requests), nil })
	r.pure("CostLineItem", "billing_units", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(cli(s).BillingUnits), nil })
	r.pure("CostLineItem", "bytes", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(cli(s).Bytes), nil })
	r.pure("CostLineItem", "unit_price_usd", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(cli(s).UnitPriceUSD), nil })
	r.pure("CostLineItem", "byte_price_usd_per_gib", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Float(cli(s).BytePriceUSDPerGiB), nil
	})
	r.pure("CostLineItem", "estimated_usd", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(cli(s).EstimatedUSD), nil })

	cr := func(self any) CostReport { return self.(*costReportSnapshot).r }
	r.pure("CostReport", "provider", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(cr(s).Provider), nil })
	r.pure("CostReport", "price_table_version", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(cr(s).PriceTableVersion), nil
	})
	r.pure("CostReport", "cap_usd", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(cr(s).CapUSD), nil })
	r.pure("CostReport", "ceiling_usd", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(cr(s).CeilingUSD), nil })
	r.pure("CostReport", "estimated_usd", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(cr(s).EstimatedUSD), nil })
	r.pure("CostReport", "total_requests", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(cr(s).TotalRequests), nil })
	r.pure("CostReport", "total_units", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(cr(s).TotalUnits), nil })
	r.pure("CostReport", "total_bytes", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(cr(s).TotalBytes), nil })
	r.pure("CostReport", "cap_exceeded_count", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(cr(s).CapExceededCount), nil })
	r.pure("CostReport", "len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(int64(len(cr(s).Items))), nil })
	r.pure("CostReport", "at", []string{"int"}, "CostLineItem", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		rep := cr(s)
		if a[0].Int < 0 || a[0].Int >= int64(len(rep.Items)) {
			return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("CostReport.at(%d): %v (len %d)", a[0].Int, errIndex, len(rep.Items)))
		}
		return lmcode.Object("CostLineItem", &costLineItemSnapshot{it: rep.Items[a[0].Int]}), nil
	})
	r.pure("CostReport", "item", []string{"string"}, "CostLineItem", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("CostLineItem", &costLineItemSnapshot{it: cr(s).Item(a[0].Str)}), nil
	})
	r.pure("CostReport", "summary", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(cr(s).Summary()), nil })

	opm := func(self any) OpMetrics { return self.(*opMetricsSnapshot).m }
	r.pure("OpMetrics", "operation", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(opm(s).Operation), nil })
	r.pure("OpMetrics", "calls", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(opm(s).Calls), nil })
	r.pure("OpMetrics", "errors", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(opm(s).Errors), nil })
	r.pure("OpMetrics", "retries", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(opm(s).Retries), nil })
	r.pure("OpMetrics", "throttles", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(opm(s).Throttles), nil })
	r.pure("OpMetrics", "bytes_in", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(opm(s).BytesIn), nil })
	r.pure("OpMetrics", "bytes_out", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(opm(s).BytesOut), nil })
	r.pure("OpMetrics", "min_ms", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(opm(s).MinMS), nil })
	r.pure("OpMetrics", "p50_ms", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(opm(s).P50MS), nil })
	r.pure("OpMetrics", "p95_ms", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(opm(s).P95MS), nil })
	r.pure("OpMetrics", "max_ms", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(opm(s).MaxMS), nil })
	r.pure("OpMetrics", "mean_ms", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(opm(s).MeanMS), nil })
	r.pure("OpMetrics", "total_ms", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(opm(s).TotalMS), nil })

	mr := func(self any) MetricsReport { return self.(*metricsReportSnapshot).r }
	r.pure("MetricsReport", "elapsed_ms", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Float(mr(s).ElapsedMS), nil })
	r.pure("MetricsReport", "total_calls", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(mr(s).TotalCalls), nil })
	r.pure("MetricsReport", "total_errors", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(mr(s).TotalErrors), nil })
	r.pure("MetricsReport", "total_retries", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(mr(s).TotalRetries), nil })
	r.pure("MetricsReport", "total_throttles", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(mr(s).TotalThrottles), nil })
	r.pure("MetricsReport", "total_bytes_in", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(mr(s).TotalBytesIn), nil })
	r.pure("MetricsReport", "total_bytes_out", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(mr(s).TotalBytesOut), nil })
	r.pure("MetricsReport", "len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.Int(int64(len(mr(s).Ops))), nil })
	r.pure("MetricsReport", "at", []string{"int"}, "OpMetrics", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		rep := mr(s)
		if a[0].Int < 0 || a[0].Int >= int64(len(rep.Ops)) {
			return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("MetricsReport.at(%d): %v (len %d)", a[0].Int, errIndex, len(rep.Ops)))
		}
		return lmcode.Object("OpMetrics", &opMetricsSnapshot{m: rep.Ops[a[0].Int]}), nil
	})
	r.pure("MetricsReport", "op", []string{"string"}, "OpMetrics", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Object("OpMetrics", &opMetricsSnapshot{m: mr(s).Op(a[0].Str)}), nil
	})
	r.pure("MetricsReport", "summary", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) { return lmcode.String(mr(s).Summary()), nil })

	ti := func(self any) *TableItem { return self.(*TableItem) }
	r.pure("TableItem", "set_string", []string{"string", "string"}, "TableItem", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return tableItemVal(ti(s).SetString(a[0].Str, a[1].Str))
	})
	r.pure("TableItem", "set_int", []string{"string", "int"}, "TableItem", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return tableItemVal(ti(s).SetInt(a[0].Str, a[1].Int))
	})
	r.pure("TableItem", "set_number", []string{"string", "float"}, "TableItem", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		v := a[1].Float
		if math.Abs(v) == math.Pow(10.0, -130.0) {
			v = math.Copysign(hostkit.MinPortableFloatAbs, v)
		}
		return tableItemVal(ti(s).SetNumber(a[0].Str, v))
	})
	r.pure("TableItem", "set_bool", []string{"string", "bool"}, "TableItem", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return tableItemVal(ti(s).SetBool(a[0].Str, a[1].Bool))
	})
	r.pure("TableItem", "remove", []string{"string"}, "TableItem", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return tableItemVal(ti(s).Remove(a[0].Str))
	})
	r.pure("TableItem", "has", []string{"string"}, "bool", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(ti(s).Has(a[0].Str)), nil
	})
	r.pure("TableItem", "type_of", []string{"string"}, "string", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(ti(s).TypeOf(a[0].Str)), nil
	})
	r.pure("TableItem", "get_string", []string{"string"}, "string", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		v, err := ti(s).GetString(a[0].Str)
		return lmcode.String(v), hostErr(err)
	})
	r.pure("TableItem", "get_int", []string{"string"}, "int", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		v, err := ti(s).GetInt(a[0].Str)
		return lmcode.Int(v), hostErr(err)
	})
	r.pure("TableItem", "get_number", []string{"string"}, "float", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		v, err := ti(s).GetNumber(a[0].Str)
		return lmcode.Float(v), hostErr(err)
	})
	r.pure("TableItem", "get_bool", []string{"string"}, "bool", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		v, err := ti(s).GetBool(a[0].Str)
		return lmcode.Bool(v), hostErr(err)
	})
	r.pure("TableItem", "names", nil, "StrList", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return r.strList(ti(s).Names())
	})
	r.pure("TableItem", "len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(ti(s).Len()), nil
	})
	r.pure("TableItem", "pk", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(ti(s).PK()), nil
	})
	r.pure("TableItem", "sk", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(ti(s).SK()), nil
	})
	r.pure("TableItem", "version", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(ti(s).Version()), nil
	})
	r.pure("TableItem", "exists", nil, "bool", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(ti(s).Exists()), nil
	})

	tp := func(self any) TablePage { return self.(*tablePageSnapshot).p }
	r.pure("TablePage", "len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(int64(len(tp(s).Items))), nil
	})
	r.pure("TablePage", "at", []string{"int"}, "TableItem", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		p := tp(s)
		if a[0].Int < 0 || a[0].Int >= int64(len(p.Items)) {
			return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("TablePage.at(%d): %v (len %d)", a[0].Int, errIndex, len(p.Items)))
		}
		return lmcode.Object("TableItem", p.Items[a[0].Int]), nil
	})
	r.pure("TablePage", "has_more", nil, "bool", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(tp(s).NextToken != ""), nil
	})
	r.pure("TablePage", "next_token", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(tp(s).NextToken), nil
	})

	pol := func(self any) *Policy { return self.(*Policy) }
	r.pure("Policy", "statement", []string{"string", "StrList", "StrList"}, "Policy", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		actions, err := strListArg(a[1])
		if err != nil {
			return lmcode.None(), err
		}
		resources, err := strListArg(a[2])
		if err != nil {
			return lmcode.None(), err
		}
		return policyVal(pol(s).Statement(a[0].Str, actions, resources))
	})
	r.pure("Policy", "document", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		v, err := pol(s).Document()
		return lmcode.String(v), hostErr(err)
	})
	r.pure("Policy", "len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(pol(s).Len()), nil
	})

	lr := func(self any) *LintReport { return self.(*LintReport) }
	r.pure("LintReport", "ok", nil, "bool", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(lr(s).OK()), nil
	})
	r.pure("LintReport", "len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(lr(s).Len()), nil
	})
	r.pure("LintReport", "at", []string{"int"}, "LintFinding", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		f, err := lr(s).At(a[0].Int)
		if err != nil {
			return lmcode.None(), lmcode.NewHostError(err.Error())
		}
		return lmcode.Object("LintFinding", f), nil
	})

	lf := func(self any) *LintFinding { return self.(*LintFinding) }
	r.pure("LintFinding", "code", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(lf(s).Code()), nil
	})
	r.pure("LintFinding", "severity", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(lf(s).Severity()), nil
	})
	r.pure("LintFinding", "message", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(lf(s).Message()), nil
	})

	fc := func(self any) *FunctionConfig { return self.(*FunctionConfig) }
	r.pure("FunctionConfig", "name", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).Name()), nil
	})
	r.pure("FunctionConfig", "exists", nil, "bool", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(fc(s).Exists()), nil
	})
	r.pure("FunctionConfig", "state", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).State()), nil
	})
	r.pure("FunctionConfig", "runtime", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).Runtime()), nil
	})
	r.pure("FunctionConfig", "set_runtime", []string{"string"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).SetRuntime(a[0].Str))
	})
	r.pure("FunctionConfig", "handler", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).Handler()), nil
	})
	r.pure("FunctionConfig", "set_handler", []string{"string"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).SetHandler(a[0].Str))
	})
	r.pure("FunctionConfig", "code_source", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).CodeSource()), nil
	})
	r.pure("FunctionConfig", "inline_code", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).InlineCode()), nil
	})
	r.pure("FunctionConfig", "set_inline_code", []string{"string"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).SetInlineCode(a[0].Str))
	})
	r.pure("FunctionConfig", "package_bucket", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).PackageBucket()), nil
	})
	r.pure("FunctionConfig", "package_key", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).PackageKey()), nil
	})
	r.pure("FunctionConfig", "set_package_object", []string{"string", "string"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).SetPackageObject(a[0].Str, a[1].Str))
	})
	r.pure("FunctionConfig", "code_sha256", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).CodeSHA256()), nil
	})
	r.pure("FunctionConfig", "timeout_seconds", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(fc(s).TimeoutSeconds()), nil
	})
	r.pure("FunctionConfig", "set_timeout_seconds", []string{"int"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).SetTimeoutSeconds(a[0].Int))
	})
	r.pure("FunctionConfig", "memory_mb", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(fc(s).MemoryMB()), nil
	})
	r.pure("FunctionConfig", "set_memory_mb", []string{"int"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).SetMemoryMB(a[0].Int))
	})
	r.pure("FunctionConfig", "concurrency", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(fc(s).Concurrency()), nil
	})
	r.pure("FunctionConfig", "set_concurrency", []string{"int"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).SetConcurrency(a[0].Int))
	})
	r.pure("FunctionConfig", "env", []string{"string"}, "string", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		v, err := fc(s).Env(a[0].Str)
		return lmcode.String(v), hostErr(err)
	})
	r.pure("FunctionConfig", "has_env", []string{"string"}, "bool", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(fc(s).HasEnv(a[0].Str)), nil
	})
	r.pure("FunctionConfig", "set_env", []string{"string", "string"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).SetEnv(a[0].Str, a[1].Str))
	})
	r.pure("FunctionConfig", "remove_env", []string{"string"}, "FunctionConfig", func(s any, a []lmcode.Value) (lmcode.Value, error) {
		return fnCfgVal(fc(s).RemoveEnv(a[0].Str))
	})
	r.pure("FunctionConfig", "env_names", nil, "StrList", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return r.strList(fc(s).EnvNames())
	})
	r.pure("FunctionConfig", "env_len", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(fc(s).EnvLen()), nil
	})
	r.pure("FunctionConfig", "version", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).Version()), nil
	})
	r.pure("FunctionConfig", "revision_id", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fc(s).RevisionID()), nil
	})

	fir := func(self any) *FunctionInvokeResult { return self.(*FunctionInvokeResult) }
	r.pure("FunctionInvokeResult", "status_code", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(fir(s).StatusCode()), nil
	})
	r.pure("FunctionInvokeResult", "payload", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fir(s).Payload()), nil
	})
	r.pure("FunctionInvokeResult", "logs", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fir(s).Logs()), nil
	})
	r.pure("FunctionInvokeResult", "function_error", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fir(s).FunctionError()), nil
	})
	r.pure("FunctionInvokeResult", "is_error", nil, "bool", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Bool(fir(s).IsError()), nil
	})
	r.pure("FunctionInvokeResult", "executed_version", nil, "string", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.String(fir(s).ExecutedVersion()), nil
	})
	r.pure("FunctionInvokeResult", "duration_ms", nil, "float", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Float(fir(s).DurationMS()), nil
	})
	r.pure("FunctionInvokeResult", "billed_ms", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(fir(s).BilledMS()), nil
	})
	r.pure("FunctionInvokeResult", "memory_mb", nil, "int", func(s any, _ []lmcode.Value) (lmcode.Value, error) {
		return lmcode.Int(fir(s).MemoryMB()), nil
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
