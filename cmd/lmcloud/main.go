// SPDX-License-Identifier: MIT

package main

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/lmctl-ai/lmcode-go"
	"github.com/opentofu/opentofu/internal/lmhost"
	"github.com/opentofu/opentofu/schema"
)

//go:embed VERSION
var rawVersion string

func printSchemaSummary(reg *lmcode.Registry) {
	current := ""
	var order []string
	members := make(map[string][]string)
	for _, sig := range reg.Signatures() {
		if strings.HasPrefix(sig, "context ") || strings.HasPrefix(sig, "fn ") {
			fmt.Println(sig)
		} else if strings.HasPrefix(sig, "method ") {
			body := sig[7:]
			idx := strings.Index(body, ".")
			if idx > 0 {
				typeName := body[:idx]
				if typeName != current {
					current = typeName
					order = append(order, typeName)
				}
				members[typeName] = append(members[typeName], body)
			}
		}
	}
	for _, t := range order {
		fmt.Printf("%s:\n", t)
		for _, m := range members[t] {
			fmt.Printf("  %s\n", m)
		}
	}
}

func main() {
	os.Exit(realMain(os.Args))
}

func realMain(args []string) int {
	host := lmhost.NewHost()
	reg := lmcode.NewRegistry()
	if err := lmhost.Register(reg, host); err != nil {
		return lmcode.ReportAppFailure("failed to register host: " + err.Error())
	}

	const usage = "usage: lmcloud --version | --lmcode-schema [--json] | --lmcode-signatures [--without-std] | --lmcode FILE [FILE ...]\n"

	if len(args) == 2 && args[1] == "--version" {
		v := strings.TrimSpace(rawVersion)
		if v == "" {
			v = "0.1.0"
		}
		fmt.Printf("lmcloud %s\n", v)
		return 0
	}

	if len(args) >= 2 && args[1] == "--lmcode-schema" {
		if len(args) == 2 {
			printSchemaSummary(reg)
			return 0
		}
		if len(args) == 3 && args[2] == "--json" {
			_, err := os.Stdout.Write(schema.EmbeddedSchema)
			if err != nil {
				return 4
			}
			return 0
		}
		fmt.Fprint(os.Stderr, usage)
		return 2
	}

	if len(args) == 3 && args[1] == "--lmcode-signatures" && args[2] == "--without-std" {
		for _, s := range reg.HostSignatures() {
			fmt.Println(s)
		}
		return 0
	}
	if len(args) == 2 && args[1] == "--lmcode-signatures" {
		for _, s := range reg.Signatures() {
			fmt.Println(s)
		}
		return 0
	}

	if len(args) >= 3 && args[1] == "--lmcode" {
		for i := 2; i < len(args); i++ {
			if args[i] == "" || strings.HasPrefix(args[i], "--") {
				fmt.Fprint(os.Stderr, usage)
				return 2
			}
		}

		ctx := lmcode.NewContext()
		ctx.Set("tofu", host)

		for i := 2; i < len(args); i++ {
			codeBytes, err := os.ReadFile(args[i])
			if err != nil {
				return lmcode.ReportError("load", lmcode.NewError(lmcode.LOAD_BAD_BYTECODE, err.Error()))
			}
			prog, err := lmcode.Load(codeBytes, schema.EmbeddedSchema, reg)
			if err != nil {
				return lmcode.ReportError("load", err)
			}
			if err := prog.Run(ctx, reg); err != nil {
				return lmcode.ReportError("run", err)
			}
			lmcode.ReportOK()
		}
		return 0
	}

	fmt.Fprint(os.Stderr, usage)
	return 2
}
