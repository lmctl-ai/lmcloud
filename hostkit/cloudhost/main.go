// SPDX-License-Identifier: MIT

package cloudhost

import (
	"fmt"
	"io"
	"os"

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
}

const usage = "usage: HOST --version | --lmcode-schema [--json] | --lmcode-signatures | [--lmcode|--first|--last] FILE ..."

func (p Program) out() io.Writer {
	if p.Out != nil {
		return p.Out
	}
	return os.Stdout
}

// NewRegistry returns a registry with std plus the shared schema registered.
func NewRegistry(out io.Writer) (*lmcode.Registry, error) {
	reg := lmcode.NewRegistry()
	if err := Register(reg, out); err != nil {
		return nil, err
	}
	return reg, nil
}

// Main runs the host CLI for args (without argv[0]) and returns the exit code.
func (p Program) Main(args []string) int {
	out := p.out()
	switch {
	case len(args) == 1 && args[0] == "--version":
		fmt.Fprintf(out, "%s %s\n", p.Name, p.Version)
		return 0
	case len(args) >= 1 && args[0] == "--lmcode-schema" && (len(args) == 1 || (len(args) == 2 && args[1] == "--json")):
		// Both forms print the exact raw schema bytes; lmscript binds by their SHA-256.
		_, _ = out.Write(p.Schema)
		return 0
	case len(args) == 1 && args[0] == "--lmcode-signatures":
		reg, err := NewRegistry(io.Discard)
		if err != nil {
			return invoke.Failure("app", lmcode.NewError(lmcode.APP_FAIL, err.Error()))
		}
		for _, s := range reg.Signatures() {
			fmt.Fprintln(out, s)
		}
		return 0
	case invoke.IsInvocation(args):
	default:
		return invoke.Failure("cli", lmcode.NewError(lmcode.CLI_USAGE, usage))
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
		Order:    inv.Order,
		Dry:      inv.Dry,
		Builder:  inv.Builder,
		Out:      out,
	}
	return runner.Execute()
}
