// SPDX-License-Identifier: MIT

// Command lmcloud-ref is the reference host: the shared lmcloud schema served
// by hostkit/cloudhost on top of the in-memory fakeadapter. It validates the
// shared package against the conformance scenarios without any simulator.
//
//	lmcloud-ref [cloud] --lmcode FILE ...
//
// Environment:
//
//	LMCLOUD_REF_STATE      state file shared across processes (default: per-user temp file)
//	LMCLOUD_REF_AUTH       "open" (default) or "enforce"
//	LMCLOUD_REF_TOKEN_ENV  name of the variable holding the caller credential (default LMCLOUD_REF_TOKEN)
//	LMCLOUD_REF_ALLOW      credential accepted in enforce mode
//	LMCLOUD_REF_DENY       credential authenticated but denied in enforce mode
//	LMCLOUD_REF_PAGE_SIZE  list page size (default 1000)
//	LMCLOUD_REF_REPORT     if set, print adapter call counts and run hooks to stderr
//	LMCLOUD_REF_FAIL_INIT  if set, Program.Init fails (exercises the exit-2 path)
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/cloudhost"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/invoke"
	"github.com/lmctl-ai/lmcloud/schema"
)

var version = "0.1.0"

func main() {
	args := os.Args[1:] // Program.Main accepts the optional "cloud" word itself
	var fake *fakeadapter.Fake
	report := os.Getenv("LMCLOUD_REF_REPORT") != ""
	hook := func(name string) func() {
		return func() {
			if report {
				fmt.Fprintf(os.Stderr, "lmcloud-ref hook %s\n", name)
			}
		}
	}
	prog := cloudhost.Program{
		Notices: "lmcloud-ref notices: github.com/lmctl-ai/lmcode-go (MIT), github.com/lmctl-ai/lmcloud (MIT)",
		Hooks:   invoke.Hooks{BeforeRun: hook("before_run"), AfterRun: hook("after_run")},
		Init: func() error {
			if os.Getenv("LMCLOUD_REF_FAIL_INIT") != "" {
				return fmt.Errorf("LMCLOUD_REF_FAIL_INIT is set")
			}
			return nil
		},
		Name:    "lmcloud-ref",
		Version: version,
		Schema:  schema.Bytes,
		NewConfig: func(dry bool) (cloudhost.Config, error) {
			fake = newFake()
			return cloudhost.Config{
				Provider:  "ref",
				Store:     fake,
				Queue:     fake,
				Endpoints: &hostkit.EndpointResolver{Prefix: "LMCLOUD_REF"},
			}, nil
		},
	}
	code := prog.Main(args)
	if fake != nil && report {
		calls := fake.Calls()
		names := make([]string, 0, len(calls))
		for n := range calls {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(os.Stderr, "lmcloud-ref call %s=%d\n", n, calls[n])
		}
		fmt.Fprintf(os.Stderr, "lmcloud-ref mutator_calls=%d\n", fake.MutatorCalls())
	}
	os.Exit(code)
}

func newFake() *fakeadapter.Fake {
	state := os.Getenv("LMCLOUD_REF_STATE")
	if state == "" {
		state = filepath.Join(os.TempDir(), fmt.Sprintf("lmcloud-ref-%d.json", os.Getuid()))
	}
	tokenEnv := os.Getenv("LMCLOUD_REF_TOKEN_ENV")
	if tokenEnv == "" {
		tokenEnv = "LMCLOUD_REF_TOKEN"
	}
	pageSize, _ := strconv.Atoi(os.Getenv("LMCLOUD_REF_PAGE_SIZE"))
	return fakeadapter.New(fakeadapter.Options{
		StatePath: state,
		PageSize:  pageSize,
		Auth: fakeadapter.Auth{
			Enforce:    os.Getenv("LMCLOUD_REF_AUTH") == "enforce",
			Credential: func() string { return os.Getenv(tokenEnv) },
			Allow:      os.Getenv("LMCLOUD_REF_ALLOW"),
			Deny:       os.Getenv("LMCLOUD_REF_DENY"),
		},
	})
}
