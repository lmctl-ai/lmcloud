package hostkit

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Portable limits for the function slice (durable-memory/15-function-design.md §3.1 & §4.1).
const (
	MaxFunctionNameLen            = 32
	MinFunctionNameLen            = 3
	MaxFunctionHandlerLen         = 65
	MinFunctionHandlerLen         = 3
	MaxFunctionInlineCodeBytes    = 64 * 1024        // 64 KiB
	MaxFunctionPackageBytes       = 16 * 1024 * 1024 // 16 MiB compressed
	MaxFunctionUncompressedBytes  = 64 * 1024 * 1024 // 64 MiB uncompressed total
	MaxFunctionSingleEntryBytes   = 32 * 1024 * 1024 // 32 MiB per archive entry
	MaxFunctionArchiveEntries     = 256
	MinFunctionTimeoutSeconds     = 1
	MaxFunctionTimeoutSeconds     = 230
	DefaultFunctionTimeoutSeconds = 3
	DefaultFunctionMemoryMB       = 128
	MaxFunctionMemoryMB           = 2048
	DefaultFunctionConcurrency    = 0
	MinFunctionConcurrency        = -1
	MaxFunctionConcurrency        = 100
	MaxFunctionEnvVars            = 64
	MaxFunctionEnvKeyBytes        = 64
	MaxFunctionEnvValueBytes      = 4096
	MaxFunctionEnvTotalBytes      = 4096
	MinFunctionAliasNameLen       = 2
	MaxFunctionAliasNameLen       = 32
	MaxFunctionVersions           = 16
	MaxFunctionAliases            = 16
	MaxFunctionStagedBundles      = 19
	MaxFunctionInvokePayloadBytes = 1 * 1024 * 1024 // 1 MiB
	MaxFunctionResponseBytes      = 1 * 1024 * 1024 // 1 MiB
	MaxFunctionWireBytes          = 2 * 1024 * 1024 // 2 MiB
	MaxFunctionLogBytes           = 4096
	MaxFunctionsPerRun            = 64
)

// Supported function runtimes.
const (
	RuntimePython312 = "python3.12"
	RuntimeNodeJS20x = "nodejs20.x"
)

// Function code sources.
const (
	CodeSourceInline         = "inline"
	CodeSourceObject         = "object"
	FunctionCodeSourceInline = "inline"
	FunctionCodeSourceObject = "object"
)

// Function lifecycle states.
const (
	FunctionStateCreating = "creating"
	FunctionStateActive   = "active"
	FunctionStateMutating = "mutating"
	FunctionStateDeleting = "deleting"
)

var (
	functionNameRe      = regexp.MustCompile(`^[a-z][a-z0-9]{2,31}$`)
	functionHandlerRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,31}\.[A-Za-z_][A-Za-z0-9_]{0,31}$`)
	functionEnvKeyRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	functionAliasNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)
	functionDigitsRe    = regexp.MustCompile(`^[0-9]+$`)
	functionVersionRe   = regexp.MustCompile(`^[1-9][0-9]{0,8}$`)
)

var reservedFunctionNames = map[string]bool{
	"lmcloudmeta":   true,
	"lmcloudfnmeta": true,
	"tables":        true,
	"functions":     true,
	"default":       true,
	"system":        true,
	"latest":        true,
	"$latest":       true,
}

var reservedAliasNames = map[string]bool{
	"latest":  true,
	"$latest": true,
	"default": true,
	"system":  true,
}

var reservedEnvExact = map[string]bool{
	"PATH":                           true,
	"LD_LIBRARY_PATH":                true,
	"LD_PRELOAD":                     true,
	"PYTHONPATH":                     true,
	"NODE_OPTIONS":                   true,
	"NODE_PATH":                      true,
	"HOME":                           true,
	"USER":                           true,
	"TMPDIR":                         true,
	"TEMP":                           true,
	"TMP":                            true,
	"PORT":                           true,
	"K_SERVICE":                      true,
	"K_REVISION":                     true,
	"K_CONFIGURATION":                true,
	"GOOGLE_APPLICATION_CREDENTIALS": true,
	"OCI_CLI_KEY_FILE":               true,
}

var reservedEnvPrefixes = []string{
	"AWS_",
	"LAMBDA_",
	"LMCLOUD_",
	"LMAWS_",
	"LMAZURE_",
	"LMGCP_",
	"LMOCI_",
	"AZURE_",
	"FUNCTIONS_",
	"WEBSITE_",
	"GOOGLE_",
	"CLOUD_RUN_",
	"OCI_",
	"FN_",
}

// ValidateFunctionName enforces portable function naming rules:
// 3..32 chars, ^[a-z][a-z0-9]{2,31}$, not reserved.
func ValidateFunctionName(name string) *CloudError {
	if len(name) < MinFunctionNameLen || len(name) > MaxFunctionNameLen {
		return Preflightf("function name %q length must be between %d and %d bytes (got %d)",
			name, MinFunctionNameLen, MaxFunctionNameLen, len(name))
	}
	if !functionNameRe.MatchString(name) {
		return Preflightf("function name %q must match ^[a-z][a-z0-9]{2,31}$", name)
	}
	if reservedFunctionNames[strings.ToLower(name)] {
		return Preflightf("function name %q is reserved", name)
	}
	return nil
}

// ValidateFunctionRuntime enforces supported portable runtimes ("python3.12", "nodejs20.x").
func ValidateFunctionRuntime(runtime string) *CloudError {
	switch runtime {
	case RuntimePython312, RuntimeNodeJS20x:
		return nil
	default:
		return Preflightf("unsupported function runtime %q: want %q or %q", runtime, RuntimePython312, RuntimeNodeJS20x)
	}
}

// ValidateFunctionHandler enforces <module>.<export> format (3..65 ASCII bytes).
func ValidateFunctionHandler(handler string) *CloudError {
	if len(handler) < MinFunctionHandlerLen || len(handler) > MaxFunctionHandlerLen {
		return Preflightf("function handler %q length must be between %d and %d bytes (got %d)",
			handler, MinFunctionHandlerLen, MaxFunctionHandlerLen, len(handler))
	}
	if !functionHandlerRe.MatchString(handler) {
		return Preflightf("function handler %q must match <module>.<export> (^[A-Za-z_][A-Za-z0-9_]{0,31}\\.[A-Za-z_][A-Za-z0-9_]{0,31}$)", handler)
	}
	return nil
}

// SplitFunctionHandler splits a validated <module>.<export> string.
func SplitFunctionHandler(handler string) (module, export string, err *CloudError) {
	if cerr := ValidateFunctionHandler(handler); cerr != nil {
		return "", "", cerr
	}
	dot := strings.IndexByte(handler, '.')
	return handler[:dot], handler[dot+1:], nil
}

// HandlerFilename returns "<module>.py" for python3.12 or "<module>.js" for nodejs20.x.
func HandlerFilename(runtime, handler string) (string, *CloudError) {
	if cerr := ValidateFunctionRuntime(runtime); cerr != nil {
		return "", cerr
	}
	mod, _, cerr := SplitFunctionHandler(handler)
	if cerr != nil {
		return "", cerr
	}
	if runtime == RuntimePython312 {
		return mod + ".py", nil
	}
	return mod + ".js", nil
}

// ValidateFunctionInlineCode validates inline function source code (1..65536 UTF-8 bytes, no NUL).
func ValidateFunctionInlineCode(code string) *CloudError {
	if len(code) == 0 {
		return Preflightf("inline_code must not be empty")
	}
	if len(code) > MaxFunctionInlineCodeBytes {
		return Preflightf("inline_code size %d exceeds maximum of %d bytes", len(code), MaxFunctionInlineCodeBytes)
	}
	if !utf8.ValidString(code) {
		return Preflightf("inline_code must be valid UTF-8")
	}
	if strings.IndexByte(code, 0) >= 0 {
		return Preflightf("inline_code must not contain NUL bytes")
	}
	return nil
}

// ValidateFunctionTimeout validates timeout_seconds (1..230).
func ValidateFunctionTimeout(seconds int64) *CloudError {
	if seconds < MinFunctionTimeoutSeconds || seconds > MaxFunctionTimeoutSeconds {
		return Preflightf("timeout_seconds must be between %d and %d (got %d)",
			MinFunctionTimeoutSeconds, MaxFunctionTimeoutSeconds, seconds)
	}
	return nil
}

// ValidateFunctionMemoryMB validates memory_mb ({128, 256, 512, 1024, 2048}).
func ValidateFunctionMemoryMB(mb int64) *CloudError {
	switch mb {
	case 128, 256, 512, 1024, 2048:
		return nil
	default:
		return Preflightf("memory_mb must be one of {128, 256, 512, 1024, 2048} (got %d)", mb)
	}
}

// ValidateFunctionConcurrency validates concurrency (-1..100).
func ValidateFunctionConcurrency(c int64) *CloudError {
	if c < MinFunctionConcurrency || c > MaxFunctionConcurrency {
		return Preflightf("concurrency must be between %d and %d (got %d)",
			MinFunctionConcurrency, MaxFunctionConcurrency, c)
	}
	return nil
}

// ValidateFunctionEnvKey validates an environment variable key and checks reserved names/prefixes.
func ValidateFunctionEnvKey(key string) *CloudError {
	if len(key) == 0 || len(key) > MaxFunctionEnvKeyBytes {
		return Preflightf("env key %q length must be between 1 and %d bytes (got %d)", key, MaxFunctionEnvKeyBytes, len(key))
	}
	if !functionEnvKeyRe.MatchString(key) {
		return Preflightf("env key %q must match ^[A-Za-z_][A-Za-z0-9_]{0,63}$", key)
	}
	if strings.HasPrefix(key, "_") {
		return Preflightf("env key %q must not start with reserved prefix \"_\"", key)
	}
	upper := strings.ToUpper(key)
	if reservedEnvExact[upper] {
		return Preflightf("env key %q is reserved", key)
	}
	for _, pfx := range reservedEnvPrefixes {
		if strings.HasPrefix(upper, pfx) {
			return Preflightf("env key %q uses reserved prefix %q", key, pfx)
		}
	}
	return nil
}

// ValidateFunctionEnvValue validates an environment variable value (0..4096 UTF-8 bytes, no NUL).
func ValidateFunctionEnvValue(val string) *CloudError {
	if len(val) > MaxFunctionEnvValueBytes {
		return Preflightf("env value length %d exceeds maximum of %d bytes", len(val), MaxFunctionEnvValueBytes)
	}
	if !utf8.ValidString(val) {
		return Preflightf("env value must be valid UTF-8")
	}
	if strings.IndexByte(val, 0) >= 0 {
		return Preflightf("env value must not contain NUL bytes")
	}
	return nil
}

// ValidateFunctionEnvMap validates an entire environment map against key, value, count, and aggregate byte limits.
func ValidateFunctionEnvMap(env map[string]string) *CloudError {
	if len(env) > MaxFunctionEnvVars {
		return Preflightf("env variable count %d exceeds maximum of %d", len(env), MaxFunctionEnvVars)
	}
	totalBytes := 0
	for k, v := range env {
		if cerr := ValidateFunctionEnvKey(k); cerr != nil {
			return cerr
		}
		if cerr := ValidateFunctionEnvValue(v); cerr != nil {
			return cerr
		}
		totalBytes += len(k) + len(v)
	}
	if totalBytes > MaxFunctionEnvTotalBytes {
		return Preflightf("aggregate env byte size %d exceeds maximum of %d bytes", totalBytes, MaxFunctionEnvTotalBytes)
	}
	return nil
}

// ValidateFunctionAliasName validates an alias name (2..32 chars, ^[a-z][a-z0-9_]{1,31}$, not reserved).
func ValidateFunctionAliasName(alias string) *CloudError {
	if len(alias) < MinFunctionAliasNameLen || len(alias) > MaxFunctionAliasNameLen {
		return Preflightf("alias name %q length must be between %d and %d bytes", alias, MinFunctionAliasNameLen, MaxFunctionAliasNameLen)
	}
	if reservedAliasNames[strings.ToLower(alias)] {
		return Preflightf("alias name %q is reserved", alias)
	}
	if !functionAliasNameRe.MatchString(alias) {
		return Preflightf("alias name %q must match ^[a-z][a-z0-9_]{1,31}$", alias)
	}
	return nil
}

// ValidateFunctionVersionString validates a published version identifier (positive decimal integer "1", "2", ...).
func ValidateFunctionVersionString(version string) *CloudError {
	if !functionVersionRe.MatchString(version) {
		return Preflightf("invalid function version %q: must be a positive integer string (\"1\", \"2\", ...)", version)
	}
	if _, err := strconv.ParseUint(version, 10, 64); err != nil {
		return Preflightf("invalid function version %q: %v", version, err)
	}
	return nil
}

// ValidateFunctionQualifier validates an optional qualifier ("", "$LATEST", positive version integer, or valid alias name).
func ValidateFunctionQualifier(qualifier string) *CloudError {
	if qualifier == "" || qualifier == "$LATEST" {
		return nil
	}
	if functionVersionRe.MatchString(qualifier) {
		if _, err := strconv.ParseUint(qualifier, 10, 64); err == nil {
			return nil
		}
	}
	if functionDigitsRe.MatchString(qualifier) {
		return Preflightf("invalid function qualifier %q: numeric qualifiers must be positive integers >= 1", qualifier)
	}
	if strings.EqualFold(qualifier, "$latest") || strings.EqualFold(qualifier, "latest") {
		return Preflightf("invalid function qualifier %q", qualifier)
	}
	return ValidateFunctionAliasName(qualifier)
}

// ValidateFunctionExpectRevision validates an optional optimistic-concurrency revision token.
func ValidateFunctionExpectRevision(rev string) *CloudError {
	if rev == "" {
		return nil
	}
	if len(rev) > 128 {
		return Preflightf("expect_revision length %d exceeds maximum of 128 bytes", len(rev))
	}
	for i := 0; i < len(rev); i++ {
		c := rev[i]
		if c < 0x21 || c > 0x7E {
			return Preflightf("expect_revision contains invalid character 0x%02x", c)
		}
	}
	return nil
}

// ValidateFunctionInvokePayload validates the synchronous JSON invocation payload (<= 1 MiB, valid RFC 8259 JSON, depth <= 64).
func ValidateFunctionInvokePayload(payloadJSON string) *CloudError {
	if len(payloadJSON) == 0 {
		return Preflightf("payload_json must not be empty")
	}
	if len(payloadJSON) > MaxFunctionInvokePayloadBytes {
		return Preflightf("payload_json size %d exceeds maximum of %d bytes (1 MiB)", len(payloadJSON), MaxFunctionInvokePayloadBytes)
	}
	if !utf8.ValidString(payloadJSON) {
		return Preflightf("payload_json must be valid UTF-8")
	}
	if strings.IndexByte(payloadJSON, 0) >= 0 {
		return Preflightf("payload_json must not contain NUL bytes")
	}
	if err := validateInvokeJSONDepth([]byte(payloadJSON), 64); err != nil {
		return Preflightf("payload_json is not valid JSON: %v", err)
	}
	return nil
}

func validateInvokeJSONDepth(raw []byte, maxDepth int) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("empty JSON payload")
	}
	depth := 0
	inString := false
	escaped := false
	for i := 0; i < len(trimmed); i++ {
		b := trimmed[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				return fmt.Errorf("JSON nesting depth exceeds maximum of %d", maxDepth)
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return fmt.Errorf("unexpected closing bracket")
			}
		}
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("trailing tokens after JSON value")
	}
	return nil
}

// ArchiveFileEntry represents a validated file inside a function deployment bundle.
type ArchiveFileEntry struct {
	Path string
	Data []byte
}

var deterministicZipTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

// BuildDeterministicZip builds a canonical, reproducible ZIP archive from a list of file entries
// and returns the archive bytes along with its lowercase hex SHA-256 digest.
func BuildDeterministicZip(entries []ArchiveFileEntry) ([]byte, string, *CloudError) {
	if len(entries) == 0 {
		return nil, "", Preflightf("archive must contain at least one file entry")
	}
	if len(entries) > MaxFunctionArchiveEntries {
		return nil, "", Preflightf("archive entry count %d exceeds maximum of %d", len(entries), MaxFunctionArchiveEntries)
	}
	sorted := make([]ArchiveFileEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, 6)
	})

	for _, e := range sorted {
		fh := &zip.FileHeader{
			Name:           e.Path,
			Method:         zip.Deflate,
			Modified:       deterministicZipTime,
			CreatorVersion: 20,
			ReaderVersion:  20,
		}
		fh.SetMode(0o644)
		fh.Extra = nil
		w, err := zw.CreateHeader(fh)
		if err != nil {
			return nil, "", ProviderError(Internal, 0, "ArchiveBuildFailed", err.Error())
		}
		if _, err := w.Write(e.Data); err != nil {
			return nil, "", ProviderError(Internal, 0, "ArchiveBuildFailed", err.Error())
		}
	}
	if err := zw.Close(); err != nil {
		return nil, "", ProviderError(Internal, 0, "ArchiveBuildFailed", err.Error())
	}
	zipBytes := buf.Bytes()
	sum := sha256.Sum256(zipBytes)
	return zipBytes, hex.EncodeToString(sum[:]), nil
}

// BuildDeterministicInlineZip packages inline source code as <module>.py or <module>.js
// inside a deterministic ZIP archive and returns the ZIP bytes and lowercase hex SHA-256 digest.
func BuildDeterministicInlineZip(runtime, handler, inlineCode string) ([]byte, string, *CloudError) {
	if cerr := ValidateFunctionInlineCode(inlineCode); cerr != nil {
		return nil, "", cerr
	}
	filename, cerr := HandlerFilename(runtime, handler)
	if cerr != nil {
		return nil, "", cerr
	}
	return BuildDeterministicZip([]ArchiveFileEntry{
		{
			Path: filename,
			Data: []byte(inlineCode),
		},
	})
}

func validateArchiveEntryPath(rawPath string) (string, *CloudError) {
	if rawPath == "" {
		return "", Preflightf("archive entry has empty path")
	}
	if strings.IndexByte(rawPath, 0) >= 0 {
		return "", Preflightf("archive entry path contains NUL byte")
	}
	if strings.ContainsRune(rawPath, '\\') {
		return "", Preflightf("archive entry path %q must not contain backslashes", rawPath)
	}
	if strings.HasPrefix(rawPath, "/") {
		return "", Preflightf("archive entry path %q must be relative (leading '/' forbidden)", rawPath)
	}
	if len(rawPath) >= 2 && rawPath[1] == ':' {
		return "", Preflightf("archive entry path %q must not contain drive prefix", rawPath)
	}
	trimmed := strings.TrimSuffix(rawPath, "/")
	if trimmed == "" {
		return "", Preflightf("archive entry path %q is invalid", rawPath)
	}
	segs := strings.Split(trimmed, "/")
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			return "", Preflightf("archive entry path %q contains invalid segment %q", rawPath, seg)
		}
		for i := 0; i < len(seg); i++ {
			if seg[i] < 0x20 || seg[i] == 0x7F {
				return "", Preflightf("archive entry path %q contains control character", rawPath)
			}
		}
	}
	return strings.Join(segs, "/"), nil
}

func isZipMagic(raw []byte) bool {
	return bytes.HasPrefix(raw, []byte("PK\x03\x04")) ||
		bytes.HasPrefix(raw, []byte("PK\x05\x06")) ||
		bytes.HasPrefix(raw, []byte("PK\x07\x08"))
}

func isPlainSourcePackage(runtime, key string, raw []byte) bool {
	if isZipMagic(raw) {
		return false
	}
	lowerKey := strings.ToLower(strings.TrimSpace(key))
	if strings.HasSuffix(lowerKey, ".zip") {
		return false
	}
	if runtime == RuntimePython312 && strings.HasSuffix(lowerKey, ".py") {
		return true
	}
	if runtime == RuntimeNodeJS20x && (strings.HasSuffix(lowerKey, ".js") || strings.HasSuffix(lowerKey, ".mjs") || strings.HasSuffix(lowerKey, ".cjs")) {
		return true
	}
	return false
}

// ValidateAndCanonicalizePackage validates a downloaded package object (either a ZIP archive
// or a single-file UTF-8 source script matching the runtime extension) against all §4.2.1
// zip-bomb, path-traversal, symlink/device, case-collision, and handler-presence guards,
// and returns the canonical deterministic ZIP archive bytes and lowercase hex SHA-256 digest.
func ValidateAndCanonicalizePackage(runtime, handler, key string, raw []byte) ([]byte, string, *CloudError) {
	if len(raw) == 0 {
		return nil, "", Preflightf("package object %q is empty", key)
	}
	if len(raw) > MaxFunctionPackageBytes {
		return nil, "", Preflightf("package object %q size %d exceeds maximum compressed size of %d bytes (16 MiB)",
			key, len(raw), MaxFunctionPackageBytes)
	}
	wantEntry, cerr := HandlerFilename(runtime, handler)
	if cerr != nil {
		return nil, "", cerr
	}

	if isPlainSourcePackage(runtime, key, raw) {
		if !utf8.Valid(raw) {
			return nil, "", Preflightf("package source object %q must be valid UTF-8", key)
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			return nil, "", Preflightf("package source object %q must not contain NUL bytes", key)
		}
		return BuildDeterministicZip([]ArchiveFileEntry{
			{
				Path: wantEntry,
				Data: append([]byte(nil), raw...),
			},
		})
	}

	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, "", Preflightf("invalid ZIP archive in package object %q: %v", key, err)
	}
	if len(zr.File) == 0 {
		return nil, "", Preflightf("ZIP archive in package object %q contains 0 entries", key)
	}
	if len(zr.File) > MaxFunctionArchiveEntries {
		return nil, "", Preflightf("ZIP archive in package object %q has %d entries (exceeds maximum of %d)",
			key, len(zr.File), MaxFunctionArchiveEntries)
	}

	seenLower := make(map[string]string, len(zr.File))
	var entries []ArchiveFileEntry
	var totalUncompressed int64
	foundHandler := false

	for _, f := range zr.File {
		if f.Flags&0x1 != 0 {
			return nil, "", Preflightf("ZIP archive entry %q is encrypted (unsupported)", f.Name)
		}
		cleanPath, pathErr := validateArchiveEntryPath(f.Name)
		if pathErr != nil {
			return nil, "", pathErr
		}
		mode := f.Mode()
		if mode&(os.ModeSymlink|os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeCharDevice|os.ModeIrregular) != 0 {
			return nil, "", Preflightf("ZIP archive entry %q has forbidden file mode %v (symlinks/devices/FIFOs/sockets forbidden)", f.Name, mode)
		}
		if f.CreatorVersion>>8 == 3 {
			unixType := (f.ExternalAttrs >> 16) & 0o170000
			if unixType != 0 && unixType != 0o100000 && unixType != 0o040000 {
				return nil, "", Preflightf("ZIP archive entry %q has forbidden Unix file type 0%o", f.Name, unixType)
			}
		}

		lowerPath := strings.ToLower(cleanPath)
		if prev, exists := seenLower[lowerPath]; exists {
			return nil, "", Preflightf("ZIP archive contains duplicate or case-colliding entries %q and %q", prev, cleanPath)
		}
		seenLower[lowerPath] = cleanPath

		if strings.HasSuffix(f.Name, "/") || mode.IsDir() {
			if f.UncompressedSize64 > 0 {
				return nil, "", Preflightf("ZIP archive directory entry %q has non-zero size", f.Name)
			}
			continue
		}
		if f.UncompressedSize64 > MaxFunctionSingleEntryBytes {
			return nil, "", Preflightf("ZIP archive entry %q uncompressed size %d exceeds per-entry limit of %d bytes (32 MiB)",
				cleanPath, f.UncompressedSize64, MaxFunctionSingleEntryBytes)
		}
		if totalUncompressed+int64(f.UncompressedSize64) > MaxFunctionUncompressedBytes {
			return nil, "", Preflightf("ZIP archive cumulative uncompressed size exceeds maximum of %d bytes (64 MiB)",
				MaxFunctionUncompressedBytes)
		}

		rc, err := f.Open()
		if err != nil {
			return nil, "", Preflightf("open ZIP archive entry %q: %v", cleanPath, err)
		}
		limit := int64(MaxFunctionSingleEntryBytes) + 1
		remainingTotal := int64(MaxFunctionUncompressedBytes) - totalUncompressed + 1
		if remainingTotal < limit {
			limit = remainingTotal
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, limit))
		_ = rc.Close()
		if readErr != nil {
			return nil, "", Preflightf("read ZIP archive entry %q: %v", cleanPath, readErr)
		}
		if int64(len(data)) > MaxFunctionSingleEntryBytes {
			return nil, "", Preflightf("ZIP archive entry %q decompressed stream exceeds per-entry limit of %d bytes (32 MiB)",
				cleanPath, MaxFunctionSingleEntryBytes)
		}
		totalUncompressed += int64(len(data))
		if totalUncompressed > MaxFunctionUncompressedBytes {
			return nil, "", Preflightf("ZIP archive decompressed stream exceeds cumulative limit of %d bytes (64 MiB)",
				MaxFunctionUncompressedBytes)
		}
		if uint64(len(data)) != f.UncompressedSize64 {
			return nil, "", Preflightf("ZIP archive entry %q header size %d does not match actual decompressed size %d",
				cleanPath, f.UncompressedSize64, len(data))
		}
		if cleanPath == wantEntry && len(data) > 0 {
			foundHandler = true
		}
		entries = append(entries, ArchiveFileEntry{
			Path: cleanPath,
			Data: data,
		})
	}

	if !foundHandler {
		return nil, "", Preflightf("ZIP archive in package object %q is missing required non-empty handler file %q for handler %q",
			key, wantEntry, handler)
	}

	return BuildDeterministicZip(entries)
}

// ExtractCanonicalZip extracts a canonical ZIP archive into destDir with 0400/0500 read-only permissions.
func ExtractCanonicalZip(zipBytes []byte, destDir string) *CloudError {
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return ProviderError(Internal, 0, "BundleCorrupt", fmt.Sprintf("corrupt staged bundle archive: %v", err))
	}
	var dirs []string
	seenDirs := make(map[string]bool)
	for _, f := range zr.File {
		cleanPath, pathErr := validateArchiveEntryPath(f.Name)
		if pathErr != nil {
			return ProviderError(Internal, 0, "BundleCorrupt", pathErr.Error())
		}
		targetPath := destDir + "/" + cleanPath
		if slash := strings.LastIndexByte(targetPath, '/'); slash > len(destDir) {
			parentDir := targetPath[:slash]
			if !seenDirs[parentDir] {
				if err := os.MkdirAll(parentDir, 0o700); err != nil {
					return ProviderError(Internal, 0, "BundleExtractFailed", err.Error())
				}
				seenDirs[parentDir] = true
				dirs = append(dirs, parentDir)
			}
		}
		rc, err := f.Open()
		if err != nil {
			return ProviderError(Internal, 0, "BundleExtractFailed", err.Error())
		}
		data, err := io.ReadAll(io.LimitReader(rc, MaxFunctionSingleEntryBytes+1))
		_ = rc.Close()
		if err != nil || int64(len(data)) > MaxFunctionSingleEntryBytes {
			return ProviderError(Internal, 0, "BundleExtractFailed", "failed to read bundle entry")
		}
		if err := os.WriteFile(targetPath, data, 0o400); err != nil {
			return ProviderError(Internal, 0, "BundleExtractFailed", err.Error())
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		return len(dirs[i]) > len(dirs[j])
	})
	for _, d := range dirs {
		_ = os.Chmod(d, 0o500)
	}
	_ = os.Chmod(destDir, 0o500)
	return nil
}

// TruncateUTF8LogTail truncates logs to at most maxBytes (4096) from the tail
// without splitting a multi-byte UTF-8 rune at the leading cut boundary.
func TruncateUTF8LogTail(logs string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(logs) <= maxBytes {
		return logs
	}
	tail := logs[len(logs)-maxBytes:]
	for len(tail) > 0 && !utf8.RuneStart(tail[0]) {
		tail = tail[1:]
	}
	if !utf8.ValidString(tail) {
		tail = strings.ToValidUTF8(tail, "")
	}
	return tail
}

// FunctionSnapshot is the immutable provider/adapter representation of a function configuration
// (either $LATEST or a published version).
type FunctionSnapshot struct {
	Name           string            `json:"name"`
	Runtime        string            `json:"runtime"`
	Handler        string            `json:"handler"`
	CodeSource     string            `json:"code_source"`
	CodeSHA256     string            `json:"code_sha256"`
	InlineCode     string            `json:"inline_code,omitempty"`
	PackageBucket  string            `json:"package_bucket,omitempty"`
	PackageKey     string            `json:"package_key,omitempty"`
	TimeoutSeconds int64             `json:"timeout_seconds"`
	MemoryMB       int64             `json:"memory_mb"`
	Concurrency    int64             `json:"concurrency"`
	Env            map[string]string `json:"env,omitempty"`
	Version        string            `json:"version"`
	RevisionID     string            `json:"revision_id"`
	Generation     uint64            `json:"generation,omitempty"`
	OwnerToken     string            `json:"owner_token,omitempty"`
	IncarnationID  string            `json:"incarnation_id,omitempty"`
	BundleZip      []byte            `json:"-"`
}

// Clone returns a deep copy of FunctionSnapshot.
func (s FunctionSnapshot) Clone() FunctionSnapshot {
	out := s
	if s.Env != nil {
		out.Env = make(map[string]string, len(s.Env))
		for k, v := range s.Env {
			out.Env[k] = v
		}
	}
	if s.BundleZip != nil {
		out.BundleZip = append([]byte(nil), s.BundleZip...)
	}
	return out
}

// SameCanonicalConfig reports whether two FunctionSnapshots have identical canonical configuration
// for idempotent function_create comparison (§4.1: runtime, handler, code_source, code_sha256,
// package_bucket, package_key, timeout_seconds, memory_mb, concurrency, and env map).
func (s FunctionSnapshot) SameCanonicalConfig(other FunctionSnapshot) bool {
	if s.Runtime != other.Runtime ||
		s.Handler != other.Handler ||
		s.CodeSource != other.CodeSource ||
		s.CodeSHA256 != other.CodeSHA256 ||
		s.PackageBucket != other.PackageBucket ||
		s.PackageKey != other.PackageKey ||
		s.TimeoutSeconds != other.TimeoutSeconds ||
		s.MemoryMB != other.MemoryMB ||
		s.Concurrency != other.Concurrency {
		return false
	}
	if len(s.Env) != len(other.Env) {
		return false
	}
	for k, v := range s.Env {
		ov, ok := other.Env[k]
		if !ok || ov != v {
			return false
		}
	}
	return true
}

// FunctionMutationFence carries expected ownership, incarnation, and monotonic generation
// fences for mutating function adapter operations (including version publish and alias mutations).
type FunctionMutationFence struct {
	OwnerToken    string
	IncarnationID string
	Generation    uint64
	IntentID      string
}

type functionMutationFenceKey struct{}

// WithFunctionMutationFence attaches a FunctionMutationFence to ctx.
func WithFunctionMutationFence(ctx context.Context, fence FunctionMutationFence) context.Context {
	return context.WithValue(ctx, functionMutationFenceKey{}, fence)
}

// FunctionMutationFenceFrom extracts a FunctionMutationFence from ctx, if present.
func FunctionMutationFenceFrom(ctx context.Context) FunctionMutationFence {
	if ctx == nil {
		return FunctionMutationFence{}
	}
	if f, ok := ctx.Value(functionMutationFenceKey{}).(FunctionMutationFence); ok {
		return f
	}
	return FunctionMutationFence{}
}

// FunctionUpdateInput carries parameters for CreateFunction and UpdateFunction.
type FunctionUpdateInput struct {
	Snapshot           FunctionSnapshot
	ExpectRevision     string
	OwnerToken         string
	ExpectedOwnerToken string
	Generation         uint64
	IntentID           string
}

// FunctionInvokeInput carries parameters for synchronous Function invocation,
// including optional pre-admission pinned target identity and quota expectations.
type FunctionInvokeInput struct {
	Name                string
	Qualifier           string
	PayloadJSON         string
	ExpectedOwnerToken  string
	ExpectedIncarnation string
	ExpectedRevisionID  string
	ExpectedVersion     string
	ExpectedTimeoutSec  int64
	ExpectedMemoryMB    int64
	RejectIfPresent     bool
}

// FunctionInvokeOutput carries the result of a synchronous Function invocation.
type FunctionInvokeOutput struct {
	StatusCode      int64
	Payload         string
	Logs            string
	FunctionError   string
	ExecutedVersion string
	BilledMS        int64
	TimeoutSeconds  int64
	MemoryMB        int64
}

// Functions is the provider adapter interface for the serverless function slice.
type Functions interface {
	CreateFunction(ctx context.Context, in FunctionUpdateInput) (created bool, snap FunctionSnapshot, err error)
	UpdateFunction(ctx context.Context, in FunctionUpdateInput) (snap FunctionSnapshot, err error)
	DeleteFunction(ctx context.Context, name string) (existed bool, err error)
	FunctionExists(ctx context.Context, name string) (bool, error)
	GetFunction(ctx context.Context, name, qualifier string) (FunctionSnapshot, error)
	ListFunctions(ctx context.Context) ([]string, error)
	PublishFunctionVersion(ctx context.Context, name, expectRevision string) (string, error)
	ListFunctionVersions(ctx context.Context, name string) ([]string, error)
	SetFunctionAlias(ctx context.Context, name, alias, version string) (created bool, err error)
	GetFunctionAlias(ctx context.Context, name, alias string) (string, error)
	DeleteFunctionAlias(ctx context.Context, name, alias string) (existed bool, err error)
	InvokeFunction(ctx context.Context, in FunctionInvokeInput) (FunctionInvokeOutput, error)
}

// Optional FunctionQuotaPeeker allows cloudhost to inspect the target snapshot's
// timeout_seconds and memory_mb and check version/alias headroom before reserving attempt cost,
// without charging an extra operation line item.
type FunctionQuotaPeeker interface {
	PeekFunctionQuota(ctx context.Context, name, qualifier string) (timeoutSeconds, memoryMB int64, found bool)
	PeekFunctionVersionHeadroom(ctx context.Context, name, expectRevision string) (nextVersion string, err error)
	PeekFunctionAliasHeadroom(ctx context.Context, name, alias, version string) (isNew bool, err error)
}

// Optional FunctionTargetPinner resolves the authoritative target snapshot before invocation admission
// and provides coherent read-only state for dry-run overlays.
type FunctionTargetPinner interface {
	ResolveFunctionTarget(ctx context.Context, name, qualifier string) (snap FunctionSnapshot, found bool)
	PeekDryFunctionState(ctx context.Context, name string) (latest FunctionSnapshot, versions map[string]FunctionSnapshot, versionOrder []string, aliases map[string]string, found bool)
}

// AuthoritativeFunctionAdapter reports the concrete adapter receiver implementing InvokeFunction
// so cloudhost can detect when InvokeFunction has been wrapped/overridden by an outer struct.
type AuthoritativeFunctionAdapter interface {
	AuthoritativeAdapterSelf() any
}

// Optional FunctionOwnershipReader allows cloudhost to verify function ownership tokens.
type FunctionOwnershipReader interface {
	FunctionOwnerToken(ctx context.Context, name string) (ownerToken string, exists bool, err error)
}
