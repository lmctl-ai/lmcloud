// SPDX-License-Identifier: MIT

package cloudhost

import (
	"fmt"
	"io"
	"os"
	"strings"

	lmcode "github.com/lmctl-ai/lmcode-go"

	"github.com/lmctl-ai/lmcloud/hostkit/invoke"
)

// Program describes the host binary around the shared schema.
type Program struct {
	Name    string // binary name for --version
	Version string
	Schema  []byte // exact raw schema bytes (github.com/lmctl-ai/lmcloud/schema.Bytes)
	// NewConfig builds the adapter configuration. It receives the invocation's
	// dry flag BEFORE any provider setup, so dry runs can skip credential or
	// network initialisation.
	NewConfig func(dry bool) (Config, error)
	Out       io.Writer

	// --- added in hostkit v2 (all optional) ---

	// Hooks are passed to the invoke.Runner (memory watchdog, BeforeRun, AfterRun, ...).
	Hooks invoke.Hooks
	// Init runs before an invocation is parsed (e.g. memory budget from the
	// environment). An error is a CLI_USAGE failure frame (exit 2).
	Init func() error
	// Help is printed for no arguments, --help and -h (default: built-in usage).
	Help string
	// Notices is printed for --notices; when empty --notices is a usage error.
	Notices string
	// Commands adds host-specific top-level flags, keyed by args[0] after the
	// optional "cloud" word, e.g. {"--sweep": fn}. fn returns the exit code.
	Commands map[string]func(args []string, out io.Writer) int
}

const usage = "usage: HOST [cloud] --version | --help | --notices | --lmcode-schema [--json] | --lmcode-signatures [--without-std] | [--lmcode|--first|--last] FILE ..."

func (p Program) out() io.Writer {
	if p.Out != nil {
		return p.Out
	}
	return os.Stdout
}

func (p Program) help() string {
	if p.Help != "" {
		return p.Help
	}
	return strings.Replace(usage, "HOST", p.Name, 1) + "\n"
}

// NewRegistry returns a registry with std plus the shared schema registered.
func NewRegistry(out io.Writer) (*lmcode.Registry, error) {
	reg := lmcode.NewRegistry()
	if err := Register(reg, out); err != nil {
		return nil, err
	}
	return reg, nil
}

// Signatures returns the canonical signatures the host serves; withoutStd
// lists only the shared-schema declarations (lmscript --without-std).
func Signatures(withoutStd bool) ([]string, error) {
	reg := lmcode.NewRegistry()
	if withoutStd {
		reg = lmcode.NewRegistryWithoutStd()
	}
	if err := Register(reg, io.Discard); err != nil {
		return nil, err
	}
	if withoutStd {
		return reg.HostSignatures(), nil
	}
	return reg.Signatures(), nil
}

// Main runs the host CLI for args (without argv[0]) and returns the exit code.
// A leading "cloud" word (the schema subcommand) is accepted and ignored.
func (p Program) Main(args []string) int {
	out := p.out()
	if len(args) > 0 && args[0] == "cloud" {
		args = args[1:]
	}
	switch {
	case len(args) == 0 || (len(args) == 1 && (args[0] == "--help" || args[0] == "-h")):
		fmt.Fprint(out, p.help())
		return 0
	case len(args) == 1 && (args[0] == "--version" || args[0] == "-V"):
		fmt.Fprintf(out, "%s %s\n", p.Name, p.Version)
		return 0
	case len(args) == 1 && args[0] == "--notices" && p.Notices != "":
		fmt.Fprint(out, p.Notices)
		if !strings.HasSuffix(p.Notices, "\n") {
			fmt.Fprintln(out)
		}
		return 0
	case args[0] == "--lmcode-schema" && (len(args) == 1 || (len(args) == 2 && args[1] == "--json")):
		// Both forms print the exact raw schema bytes; lmscript binds by their SHA-256.
		_, _ = out.Write(p.Schema)
		return 0
	case args[0] == "--lmcode-signatures" && (len(args) == 1 || (len(args) == 2 && args[1] == "--without-std")):
		sigs, err := Signatures(len(args) == 2)
		if err != nil {
			return invoke.Failure("app", lmcode.NewError(lmcode.APP_FAIL, err.Error()))
		}
		for _, s := range sigs {
			fmt.Fprintln(out, s)
		}
		return 0
	case p.Commands[args[0]] != nil:
		return p.Commands[args[0]](args, out)
	case invoke.IsInvocation(args):
	default:
		return invoke.Failure("cli", lmcode.NewError(lmcode.CLI_USAGE, strings.Replace(usage, "HOST", p.Name, 1)))
	}

	if p.Init != nil {
		if err := p.Init(); err != nil {
			return invoke.Failure("cli", lmcode.NewError(lmcode.CLI_USAGE, err.Error()))
		}
	}
	inv, err := invoke.ParseArgs(args)
	if err != nil {
		return invoke.Failure("cli", err)
	}
	cfg, err := p.NewConfig(inv.Dry)
	if err != nil {
		return invoke.Failure("app", lmcode.NewError(lmcode.APP_FAIL, err.Error()))
	}
	reg, err := NewRegistry(out)
	if err != nil {
		return invoke.Failure("app", lmcode.NewError(lmcode.APP_FAIL, err.Error()))
	}
	contract, err := lmcode.ResultContractFromSchema(p.Schema)
	if err != nil {
		return invoke.Failure("load", err)
	}
	h := New(cfg)
	ctx := lmcode.NewContext()
	ctx.Set("cloud", h)
	runner := &invoke.Runner{
		Results:  inv.Results,
		Registry: reg,
		Schema:   p.Schema,
		Contract: contract,
		Context:  ctx,
		Hooks:    p.Hooks,
		Order:    inv.Order,
		Dry:      inv.Dry,
		Builder:  inv.Builder,
		Out:      out,
	}
	return runner.Execute()
}
