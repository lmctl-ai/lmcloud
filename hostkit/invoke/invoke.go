// SPDX-License-Identifier: MIT

// Package invoke owns the shared lmcode host run loop: parse the invocation
// arguments, read the caller's invocation manifest (dry/real, single/builder),
// load each registered slot, select its result sink, run it (real or dry),
// complete it, and emit exactly one terminal envelope.
//
// Attribution: Runner, abort and Failure are copied from
// github.com/lmctl-ai/lmgcp internal/invoke at 4ba074b (MIT); ParseArgs is
// extracted from lmgcp cmd/lmgcp/main.go at the same commit. Nothing here is
// provider specific.
package invoke

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/lmctl-ai/lmcode-go"
)

// Invocation is a parsed `--lmcode/--first/--last FILE ...` command line plus
// the caller's manifest (LMCODE_INVOCATION_FILE) when present.
type Invocation struct {
	Results *lmcode.InvocationResults
	// Order lists registration indices in execution order (--first, plain, --last).
	Order []int
	// Builder is true for builder-mode invocations, including one-slot builders.
	Builder bool
	// Dry is the invocation mode taken from the manifest; never from an ambient flag.
	Dry bool
}

// IsInvocation reports whether args (without argv[0]) start an lmcode invocation.
func IsInvocation(args []string) bool {
	return len(args) >= 1 && (args[0] == "--lmcode" || args[0] == "--first" || args[0] == "--last")
}

// ParseArgs parses args (without argv[0]). It always consults the standard
// manifest through lmcode.InvocationResultsFromCommand, so `lmscript --dry-run`
// reaches the host as a dry invocation.
func ParseArgs(args []string) (*Invocation, error) {
	type part struct {
		file     string
		priority int
		index    int
	}
	var parts []part
	var files []string
	add := func(file string, priority int) bool {
		if file == "" || strings.HasPrefix(file, "--") {
			return false
		}
		parts = append(parts, part{file: file, priority: priority, index: len(parts)})
		files = append(files, file)
		return true
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--lmcode", "--first", "--last":
			priority := 1
			if args[i] == "--first" {
				priority = 0
			} else if args[i] == "--last" {
				priority = 2
			}
			if i+1 >= len(args) || !add(args[i+1], priority) {
				return nil, lmcode.NewError(lmcode.CLI_USAGE, "missing FILE after "+args[i])
			}
			i++
		default:
			if !add(args[i], 1) {
				return nil, lmcode.NewError(lmcode.CLI_USAGE, "unexpected argument "+strconv.Quote(args[i]))
			}
		}
	}
	if len(parts) == 0 {
		return nil, lmcode.NewError(lmcode.CLI_USAGE, "no bytecode FILE given")
	}
	results, err := lmcode.InvocationResultsFromCommand(files)
	if err != nil {
		return nil, err
	}
	inv := &Invocation{Results: results, Builder: len(parts) > 1, Dry: results.Dry()}
	if manifest := os.Getenv("LMCODE_INVOCATION_FILE"); manifest != "" {
		var meta struct {
			Mode string `json:"mode"`
		}
		if raw, err := os.ReadFile(manifest); err == nil && json.Unmarshal(raw, &meta) == nil {
			inv.Builder = meta.Mode == "builder"
		}
	}
	inv.Order = make([]int, len(parts))
	for i := range parts {
		inv.Order[i] = i
	}
	sort.SliceStable(inv.Order, func(i, j int) bool {
		a, b := parts[inv.Order[i]], parts[inv.Order[j]]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		return a.index < b.index
	})
	return inv, nil
}

// Hooks are the provider-specific edges of the run loop. All are optional.
type Hooks struct {
	BeforeRun func()
	// AfterRun runs after each slot's Program.Run returns (watchdog stopped),
	// before the slot is completed or failed. Added in hostkit v2.
	AfterRun      func()
	OnRunError    func(error)
	Cleanup       func()
	AuthError     func() string
	StartWatchdog func(func(error)) func()
}

// Runner executes every registration in Results against one schema/registry.
type Runner struct {
	Results  *lmcode.InvocationResults
	Registry *lmcode.Registry
	Schema   []byte
	Contract lmcode.ResultContract
	Context  *lmcode.Context
	Hooks    Hooks
	// Order lists registration indices in execution order. Nil keeps add order.
	Order []int
	// Dry copies the invocation mode for watchdog frames emitted outside the collector.
	Dry bool
	// Builder marks a builder-mode invocation even when it has one slot.
	Builder bool
	// RecoveryID/Path are appended to hard-abort failure messages.
	RecoveryID   string
	RecoveryPath string
	// Out defaults to os.Stdout.
	Out io.Writer
}

func (r *Runner) out() io.Writer {
	if r.Out != nil {
		return r.Out
	}
	return os.Stdout
}

// Execute returns the process exit code after writing one frame.
func (r *Runner) Execute() int {
	if r.Results == nil || r.Registry == nil || r.Context == nil {
		return Failure("cli", lmcode.NewError(lmcode.CLI_USAGE, "lmcode invoke: missing runner state"))
	}
	r.Context.SetDry(r.Dry)
	registrations := r.Results.Registrations()
	byIndex := make(map[int]lmcode.InvocationRegistration, len(registrations))
	for _, registration := range registrations {
		byIndex[registration.Index] = registration
	}
	order := r.Order
	if len(order) == 0 {
		order = make([]int, 0, len(registrations))
		for _, registration := range registrations {
			order = append(order, registration.Index)
		}
	}
	for _, index := range order {
		registration, ok := byIndex[index]
		if !ok {
			_ = r.Results.Fail(&index, "load", lmcode.NewError(lmcode.LOAD_UNBOUND, "lmcode invoke: unknown slot index"))
			break
		}
		code, err := os.ReadFile(registration.File)
		if err != nil {
			_ = r.Results.Fail(&index, "load", lmcode.NewError(lmcode.LOAD_BAD_BYTECODE, err.Error()))
			break
		}
		program, err := lmcode.Load(code, r.Schema, r.Registry)
		if err != nil {
			_ = r.Results.Fail(&index, "load", err)
			break
		}
		if _, err := r.Results.Select(index, r.Registry, r.Contract); err != nil {
			_ = r.Results.Fail(&index, "run", err)
			break
		}

		if r.Hooks.BeforeRun != nil {
			r.Hooks.BeforeRun()
		}
		stopWatchdog := func() {}
		if r.Hooks.StartWatchdog != nil {
			stopWatchdog = r.Hooks.StartWatchdog(func(watchdogErr error) {
				// Program.Run is still active: never touch provider state here.
				if r.Hooks.OnRunError != nil {
					r.Hooks.OnRunError(watchdogErr)
				}
				r.abort(index, watchdogErr)
			})
		}
		runErr := program.Run(r.Context, r.Registry)
		if stopWatchdog != nil {
			stopWatchdog()
		}
		if r.Hooks.AfterRun != nil {
			r.Hooks.AfterRun()
		}

		if r.Hooks.AuthError != nil {
			if message := r.Hooks.AuthError(); message != "" {
				r.cleanup()
				_ = r.Results.Fail(nil, "app", lmcode.NewError(lmcode.APP_FAIL, message))
				break
			}
		}
		if runErr != nil {
			r.cleanup()
			if r.Hooks.OnRunError != nil {
				r.Hooks.OnRunError(runErr)
			}
			_ = r.Results.Fail(&index, "run", runErr)
			break
		}
		if err := r.Results.Complete(index); err != nil {
			_ = r.Results.Fail(&index, "run", err)
			break
		}
	}
	return r.Results.WriteFrame(r.out())
}

func (r *Runner) cleanup() {
	if r.Hooks.Cleanup != nil {
		r.Hooks.Cleanup()
	}
}

// abort emits a terminal failure while Program.Run may still be active. It
// deliberately does not call Cleanup or the collector. The payload matches the
// collector failure order, including part for any builder and dry markers.
func (r *Runner) abort(index int, err error) {
	code, message := lmcode.RUN_HOST, err.Error()
	var native *lmcode.Error
	if errors.As(err, &native) {
		code, message = native.Code, native.Message
	}
	if r.RecoveryID != "" {
		message += " (recovery run=" + r.RecoveryID
		if r.RecoveryPath != "" {
			message += " ledger=" + r.RecoveryPath
		}
		message += ")"
	}
	payload := `{"ok":false,"phase":"run","code":` + lmcode.JSONEscape(code) +
		`,"message":` + lmcode.JSONEscape(message)
	if r.Builder || len(r.Results.Registrations()) > 1 {
		payload += `,"part":` + strconv.Itoa(index)
	}
	if r.Dry {
		payload += `,"dry":true`
	}
	payload += "}"
	if _, err := fmt.Fprintf(r.out(), "LMCODE_RETURN_BEGIN\n%s\nLMCODE_RETURN_END\n", payload); err != nil {
		os.Exit(4)
	}
	os.Exit(3)
}

// Failure emits a single pre-collector failure frame and returns its exit code.
func Failure(phase string, err error) int {
	return lmcode.FailureFrame(os.Stdout, phase, err)
}
