// SPDX-License-Identifier: MIT

package lmhost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/lmctl-ai/lmcode-go"
	"github.com/opentofu/opentofu/internal/addrs"
	backendInit "github.com/opentofu/opentofu/internal/backend/init"
	"github.com/opentofu/opentofu/internal/command"
	"github.com/opentofu/opentofu/internal/command/cliconfig"
	"github.com/opentofu/opentofu/internal/command/system"
	"github.com/opentofu/opentofu/internal/command/views"
	viewsjson "github.com/opentofu/opentofu/internal/command/views/json"
	"github.com/opentofu/opentofu/internal/command/workdir"
	"github.com/opentofu/opentofu/internal/configs"
	"github.com/opentofu/opentofu/internal/encryption"
	"github.com/opentofu/opentofu/internal/plans"
	"github.com/opentofu/opentofu/internal/plans/planfile"
	"github.com/opentofu/opentofu/internal/terminal"
	"github.com/opentofu/svchost/disco"
)

// Host implements the lmcloud host object for OpenTofu operations.
type Host struct {
	mu        sync.Mutex
	vars      map[string]string
	lastError string
	services  *disco.Disco
	initOnce  sync.Once
}

// Plan represents the planned changes for an infrastructure configuration.
type Plan struct {
	host         *Host
	dir          string
	addCount     int64
	changeCount  int64
	destroyCount int64
	summaryText  string
	filePath     string
	errored      bool
	lastError    string
}

// NewHost creates a new initialized Host.
func NewHost() *Host {
	h := &Host{
		vars:     make(map[string]string),
		services: disco.New(),
	}
	return h
}

// newCapturedStreams creates OS-pipe-backed terminal streams capturing stdout and stderr.
func newCapturedStreams() (*terminal.Streams, func() (string, string)) {
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	_ = stdinW.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(&stdoutBuf, stdoutR)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(&stderrBuf, stderrR)
	}()

	streams := &terminal.Streams{
		Stdout: &terminal.OutputStream{File: stdoutW},
		Stderr: &terminal.OutputStream{File: stderrW},
		Stdin:  &terminal.InputStream{File: stdinR},
	}

	done := func() (string, string) {
		_ = stdinR.Close()
		_ = stdoutW.Close()
		_ = stderrW.Close()
		wg.Wait()
		_ = stdoutR.Close()
		_ = stderrR.Close()
		return stdoutBuf.String(), stderrBuf.String()
	}

	return streams, done
}

func (h *Host) ensureInit() {
	h.initOnce.Do(func() {
		ctx := context.Background()
		cfg, _ := cliconfig.LoadConfig(ctx)
		if cfg == nil {
			cfg = &cliconfig.Config{}
		}
		credsSrc, err := credentialsSource(cfg)
		if err != nil {
			credsSrc = nil
		}
		h.services = newServiceDiscovery(ctx, cfg.RegistryProtocols, credsSrc)
		configureHostServices(h.services, cfg)
		backendInit.Init(h.services)
	})
}

// runCommand runs an OpenTofu command in the specified directory while capturing output.
func (h *Host) runCommand(dir string, fn func(meta command.Meta) int) (int, string, string) {
	h.ensureInit()

	origWd, err := os.Getwd()
	if err != nil {
		h.lastError = fmt.Sprintf("cannot get current working directory: %s", err)
		return 1, "", h.lastError
	}

	targetDir := dir
	if targetDir == "" {
		targetDir = "."
	}
	absTarget, err := filepath.Abs(targetDir)
	if err != nil {
		h.lastError = fmt.Sprintf("cannot resolve directory %q: %s", dir, err)
		return 1, "", h.lastError
	}
	if stat, err := os.Stat(absTarget); err != nil || !stat.IsDir() {
		h.lastError = fmt.Sprintf("directory %q does not exist or is not a directory", dir)
		return 1, "", h.lastError
	}

	ctx := context.Background()
	cfg, _ := cliconfig.LoadConfig(ctx)
	if cfg == nil {
		cfg = &cliconfig.Config{}
	}
	configureHostServices(h.services, cfg)

	providerSrc, _ := buildProviderSource(
		ctx,
		cfg.ProviderInstallation,
		cfg.RegistryProtocols,
		h.services,
		cfg.OCICredentialsPolicy,
		origWd,
		absTarget,
	)
	unmanagedProviders, _ := parseReattachProviders(os.Getenv("TF_REATTACH_PROVIDERS"))
	configDir, err := cliconfig.ConfigDir()
	if err != nil {
		configDir = ""
	}

	if err := os.Chdir(absTarget); err != nil {
		h.lastError = fmt.Sprintf("cannot change directory to %q: %s", absTarget, err)
		return 1, "", h.lastError
	}
	defer func() {
		_ = os.Chdir(origWd)
	}()

	streams, done := newCapturedStreams()
	view := views.NewView(streams).SetRunningInAutomation(true)
	meta := command.Meta{
		WorkingDir:    workdir.NewDir("."),
		View:          view,
		Services:      h.services,
		CallerContext: ctx,
		ShutdownCh:    make(<-chan struct{}),
		SystemCfg: system.Config{
			RunningInAutomation: true,
			CLIConfigDir:        configDir,
			PluginCacheDir:      cfg.PluginCacheDir,
			GlobalPluginDirs:    globalPluginDirs(),
		},
		PluginCacheMayBreakDependencyLockFile: cfg.PluginCacheMayBreakDependencyLockFile,
		MakeRegistryHTTPClient: func() *retryablehttp.Client {
			return newRegistryHTTPClient(ctx, cfg.RegistryProtocols)
		},
		ModulePackageFetcher:         remoteModulePackageFetcher(ctx, cfg.OCICredentialsPolicy),
		ProviderSource:               providerSrc,
		ProviderDevOverrides:         providerDevOverrides(cfg.ProviderInstallation),
		UnmanagedProviders:           unmanagedProviders,
		OCICredentialsPolicyBuilder:  cfg.OCICredentialsPolicy,
		ProviderSourceLocationConfig: providerSourceLocationConfigFromEnv(),
	}

	code := fn(meta)
	plugin.CleanupClients()
	stdout, stderr := done()
	return code, stdout, stderr
}

func (h *Host) persistedVarsPath(absDir string) string {
	return filepath.Join(absDir, ".terraform", "lmcloud-vars.json")
}

func (h *Host) syncVarsForDir(dir string) map[string]string {
	merged := make(map[string]string, len(h.vars))
	targetDir := dir
	if targetDir == "" {
		targetDir = "."
	}
	absDir, err := filepath.Abs(targetDir)
	if err == nil {
		if data, readErr := os.ReadFile(h.persistedVarsPath(absDir)); readErr == nil {
			_ = json.Unmarshal(data, &merged)
		}
	}
	for k, v := range h.vars {
		merged[k] = v
	}
	if err == nil && len(merged) > 0 {
		if stat, statErr := os.Stat(absDir); statErr == nil && stat.IsDir() {
			tfDir := filepath.Join(absDir, ".terraform")
			if mkErr := os.MkdirAll(tfDir, 0755); mkErr == nil {
				if data, jsonErr := json.MarshalIndent(merged, "", "  "); jsonErr == nil {
					_ = os.WriteFile(h.persistedVarsPath(absDir), data, 0600)
				}
			}
		}
	}
	return merged
}

func (h *Host) buildVarArgs(dir string) []string {
	vars := h.syncVarsForDir(dir)
	if len(vars) == 0 {
		return nil
	}

	var declared map[string]struct{}
	targetDir := dir
	if targetDir == "" {
		targetDir = "."
	}
	if absDir, err := filepath.Abs(targetDir); err == nil {
		if mod, diags := configs.NewParser(nil).LoadConfigDir(absDir); mod != nil && !diags.HasErrors() {
			declared = make(map[string]struct{}, len(mod.Variables))
			for k := range mod.Variables {
				declared[k] = struct{}{}
			}
		}
	}

	keys := make([]string, 0, len(vars))
	for k := range vars {
		if declared != nil {
			if _, ok := declared[k]; !ok {
				continue
			}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	varArgs := make([]string, 0, len(keys)*2)
	for _, k := range keys {
		varArgs = append(varArgs, "-var", fmt.Sprintf("%s=%s", k, vars[k]))
	}
	return varArgs
}

// Init initializes the working directory.
func (h *Host) Init(dir string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.InitCommand{Meta: meta}).Run([]string{"-input=false", "-no-color"})
	})
	if code == 0 {
		if len(h.vars) > 0 {
			_ = h.syncVarsForDir(dir)
		}
		h.lastError = ""
		return true
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return false
}

// Validate validates the configuration in the directory.
func (h *Host) Validate(dir string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.ValidateCommand{Meta: meta}).Run([]string{"-no-color"})
	})
	if code == 0 {
		h.lastError = ""
		return true
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return false
}

// Fmt formats HCL code string.
func (h *Host) Fmt(text string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	streams, done := newCapturedStreams()
	view := views.NewView(streams).SetRunningInAutomation(true)
	meta := command.Meta{
		WorkingDir:    workdir.NewDir("."),
		View:          view,
		CallerContext: context.Background(),
		ShutdownCh:    make(<-chan struct{}),
		SystemCfg: system.Config{
			RunningInAutomation: true,
		},
	}

	code := command.RunCommand(command.FmtCommander(strings.NewReader(text)), meta, []string{"-"})
	stdout, stderr := done()
	if code == 0 {
		h.lastError = ""
		return stdout
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return text
}

// Var sets a variable value for subsequent plan/apply/destroy runs.
func (h *Host) Var(name, value string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.vars[name] = value
}

// Plan generates an execution plan for the configuration directory.
func (h *Host) Plan(dir string) *Plan {
	h.mu.Lock()
	defer h.mu.Unlock()

	tmpFile, err := os.CreateTemp("", "lmcloud-plan-*.tfplan")
	if err != nil {
		h.lastError = fmt.Sprintf("cannot create temporary plan file: %s", err)
		return &Plan{
			errored:     true,
			lastError:   h.lastError,
			summaryText: "Plan failed: " + h.lastError,
		}
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()

	varArgs := h.buildVarArgs(dir)
	args := []string{"-input=false", "-no-color", "-out=" + tmpPath}
	args = append(args, varArgs...)

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.PlanCommand{Meta: meta}).Run(args)
	})

	if code != 0 {
		_ = os.Remove(tmpPath)
		h.lastError = strings.TrimSpace(stderr)
		if h.lastError == "" {
			h.lastError = strings.TrimSpace(stdout)
		}
		return &Plan{
			errored:     true,
			lastError:   h.lastError,
			summaryText: "Plan failed: " + h.lastError,
		}
	}

	h.lastError = ""
	r, err := planfile.Open(tmpPath, encryption.PlanEncryptionDisabled())
	if err != nil {
		h.lastError = fmt.Sprintf("cannot open plan file: %s", err)
		return &Plan{
			filePath:    tmpPath,
			errored:     true,
			lastError:   h.lastError,
			summaryText: "Plan failed: " + h.lastError,
		}
	}

	p, err := r.ReadPlan()
	if err != nil {
		h.lastError = fmt.Sprintf("cannot read plan: %s", err)
		return &Plan{
			filePath:    tmpPath,
			errored:     true,
			lastError:   h.lastError,
			summaryText: "Plan failed: " + h.lastError,
		}
	}

	var cs viewsjson.ChangeSummary
	cs.Operation = viewsjson.OperationPlanned
	if p != nil && p.Changes != nil {
		for _, change := range p.Changes.Resources {
			if change.Action == plans.Delete && change.Addr.Resource.Resource.Mode == addrs.DataResourceMode {
				continue
			}
			if change.Importing != nil {
				cs.Import++
			}
			switch change.Action {
			case plans.Create:
				cs.Add++
			case plans.Delete:
				cs.Remove++
			case plans.Update:
				cs.Change++
			case plans.CreateThenDelete, plans.DeleteThenCreate:
				cs.Add++
				cs.Remove++
			case plans.ForgetThenCreate:
				cs.Add++
				cs.Forget++
			case plans.Forget:
				cs.Forget++
			}
		}
	}

	return &Plan{
		host:         h,
		dir:          dir,
		addCount:     int64(cs.Add),
		changeCount:  int64(cs.Change),
		destroyCount: int64(cs.Remove),
		summaryText:  cs.String(),
		filePath:     tmpPath,
	}
}

// Apply applies configuration changes or a saved plan.
func (h *Host) Apply(dir string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	varArgs := h.buildVarArgs(dir)
	args := []string{"-auto-approve", "-input=false", "-no-color"}
	args = append(args, varArgs...)

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.ApplyCommand{Meta: meta}).Run(args)
	})

	if code == 0 {
		h.lastError = ""
		return true
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return false
}

// Destroy destroys infrastructure resources managed by configuration.
func (h *Host) Destroy(dir string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	varArgs := h.buildVarArgs(dir)
	args := []string{"-auto-approve", "-input=false", "-no-color"}
	args = append(args, varArgs...)

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.ApplyCommand{Meta: meta, Destroy: true}).Run(args)
	})

	if code == 0 {
		h.lastError = ""
		return true
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return false
}

// Output reads an output variable from state.
func (h *Host) Output(dir, name string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	if strings.TrimSpace(name) == "" {
		h.lastError = "output name must not be empty"
		return ""
	}

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.OutputCommand{Meta: meta}).Run([]string{"-no-color", "-json", name})
	})
	if code != 0 {
		h.lastError = strings.TrimSpace(stderr)
		if h.lastError == "" {
			h.lastError = strings.TrimSpace(stdout)
		}
		if h.lastError == "" {
			h.lastError = fmt.Sprintf("output %q not found", name)
		}
		return ""
	}

	h.lastError = ""
	raw := strings.TrimSpace(stdout)
	if raw == "" || raw == "null" {
		return ""
	}

	var strVal string
	if err := json.Unmarshal([]byte(raw), &strVal); err == nil {
		return strVal
	}
	return raw
}

// ShowState returns the state snapshot as JSON.
func (h *Host) ShowState(dir string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.ShowCommand{Meta: meta}).Run([]string{"-json"})
	})
	if code == 0 {
		h.lastError = ""
		return stdout
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return "{}"
}

// LastError returns the error message from the last failed operation.
func (h *Host) LastError() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastError
}

// PlanJSON generates a plan in dir and returns the machine-readable plan in JSON format.
func (h *Host) PlanJSON(dir string) string {
	p := h.Plan(dir)
	if p.errored {
		return "{}"
	}
	defer os.Remove(p.filePath)
	return p.JSON()
}

// StateList lists the addresses of resources in state.
func (h *Host) StateList(dir string) string {
	h.mu.Lock()
	defer h.mu.Unlock()

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.StateListCommand{StateMeta: command.StateMeta{Meta: meta}}).Run([]string{})
	})
	if code == 0 {
		h.lastError = ""
		return stdout
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return ""
}

// FmtCheck checks if configuration files in dir are formatted.
func (h *Host) FmtCheck(dir string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return command.RunCommand(command.FmtCommander(nil), meta, []string{"-check", "-list=false"})
	})
	if code == 0 {
		h.lastError = ""
		return true
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return false
}

// Import imports an existing resource into state.
func (h *Host) Import(dir, addr, id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	varArgs := h.buildVarArgs(dir)
	args := []string{"-input=false", "-no-color"}
	args = append(args, varArgs...)
	args = append(args, addr, id)

	code, stdout, stderr := h.runCommand(dir, func(meta command.Meta) int {
		return (&command.ImportCommand{Meta: meta}).Run(args)
	})
	if code == 0 {
		h.lastError = ""
		return true
	}
	h.lastError = strings.TrimSpace(stderr)
	if h.lastError == "" {
		h.lastError = strings.TrimSpace(stdout)
	}
	return false
}

// Add returns the number of resources to add.
func (p *Plan) Add() int64 {
	if p == nil {
		return 0
	}
	return p.addCount
}

// Change returns the number of resources to change.
func (p *Plan) Change() int64 {
	if p == nil {
		return 0
	}
	return p.changeCount
}

// Destroy returns the number of resources to destroy.
func (p *Plan) Destroy() int64 {
	if p == nil {
		return 0
	}
	return p.destroyCount
}

// JSON returns the machine-readable plan representation in JSON format.
func (p *Plan) JSON() string {
	if p == nil || p.errored || p.filePath == "" || p.host == nil {
		return "{}"
	}
	p.host.mu.Lock()
	defer p.host.mu.Unlock()

	code, stdout, stderr := p.host.runCommand(p.dir, func(meta command.Meta) int {
		return (&command.ShowCommand{Meta: meta}).Run([]string{"-json", p.filePath})
	})
	if code == 0 {
		return stdout
	}
	p.host.lastError = strings.TrimSpace(stderr)
	if p.host.lastError == "" {
		p.host.lastError = strings.TrimSpace(stdout)
	}
	return "{}"
}

// Summary returns the plan change summary string.
func (p *Plan) Summary() string {
	if p == nil {
		return ""
	}
	return p.summaryText
}

// Save writes the plan file to the given destination path.
func (p *Plan) Save(path string) bool {
	if p == nil || p.errored || p.filePath == "" {
		return false
	}
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		return false
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return false
	}
	return true
}

// Register registers all lmcloud host methods and context with the lmcode registry.
func Register(reg *lmcode.Registry, h *Host) error {
	if err := lmcode.RegisterTesting(reg, nil); err != nil {
		return err
	}

	// Methods on Tofu
	if err := reg.Method("Tofu", "init", []string{"string"}, "bool", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		ok := host.Init(args[0].Str)
		return lmcode.Bool(ok), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "validate", []string{"string"}, "bool", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		ok := host.Validate(args[0].Str)
		return lmcode.Bool(ok), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "fmt", []string{"string"}, "string", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		res := host.Fmt(args[0].Str)
		return lmcode.Str(res), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "fmt_check", []string{"string"}, "bool", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		ok := host.FmtCheck(args[0].Str)
		return lmcode.Bool(ok), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "import", []string{"string", "string", "string"}, "bool", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		ok := host.Import(args[0].Str, args[1].Str, args[2].Str)
		return lmcode.Bool(ok), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "plan", []string{"string"}, "Plan", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		p := host.Plan(args[0].Str)
		return lmcode.Obj("Plan", p), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "plan_json", []string{"string"}, "string", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		res := host.PlanJSON(args[0].Str)
		return lmcode.Str(res), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "apply", []string{"string"}, "bool", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		ok := host.Apply(args[0].Str)
		return lmcode.Bool(ok), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "destroy", []string{"string"}, "bool", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		ok := host.Destroy(args[0].Str)
		return lmcode.Bool(ok), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "output", []string{"string", "string"}, "string", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		res := host.Output(args[0].Str, args[1].Str)
		return lmcode.Str(res), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "var", []string{"string", "string"}, "void", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		host.Var(args[0].Str, args[1].Str)
		return lmcode.None(), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "show_state", []string{"string"}, "string", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		res := host.ShowState(args[0].Str)
		return lmcode.Str(res), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "state_list", []string{"string"}, "string", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		res := host.StateList(args[0].Str)
		return lmcode.Str(res), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Tofu", "last_error", []string{}, "string", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		host := self.(*Host)
		return lmcode.Str(host.LastError()), nil
	}); err != nil {
		return err
	}

	// Methods on Plan
	if err := reg.Method("Plan", "add", []string{}, "int", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		p := self.(*Plan)
		return lmcode.Int(p.Add()), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Plan", "change", []string{}, "int", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		p := self.(*Plan)
		return lmcode.Int(p.Change()), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Plan", "destroy", []string{}, "int", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		p := self.(*Plan)
		return lmcode.Int(p.Destroy()), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Plan", "json", []string{}, "string", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		p := self.(*Plan)
		return lmcode.Str(p.JSON()), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Plan", "summary", []string{}, "string", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		p := self.(*Plan)
		return lmcode.Str(p.Summary()), nil
	}); err != nil {
		return err
	}
	if err := reg.Method("Plan", "save", []string{"string"}, "bool", func(self any, args []lmcode.Value) (lmcode.Value, error) {
		p := self.(*Plan)
		ok := p.Save(args[0].Str)
		return lmcode.Bool(ok), nil
	}); err != nil {
		return err
	}

	// Context
	if err := reg.Context("tofu", "Tofu"); err != nil {
		return err
	}

	return nil
}
