module github.com/lmctl-ai/lmcloud

go 1.26.0

require github.com/lmctl-ai/lmcode-go v0.6.39-0.20261031234045-77932bf7134a

// !!! TEMPORARY LOCAL PATCH — lmcode-go dry enum results (hostkit v3) !!!
// lmcode-go 77932bf rejects a dry callback that returns an enum constant string
// ("dry callback for ErrorCode returned string"), so dry runs that call
// cloud.last_error().code() fail. ../lmcode-go-patched is a clone of branch
// dry-enum-string (commit 23ff76b, adds Registry.Enum); it is NOT published.
// Replace directives do not propagate: every host that wants the fix needs the
// same line in its own go.mod (see durable-memory/09-hostkit.md, v3).
// REMOVE this replace when Registry.Enum is merged upstream and the lmcode-go
// pin above (and sdk.lock) is bumped to a commit that contains it.
replace github.com/lmctl-ai/lmcode-go => ../lmcode-go-patched
