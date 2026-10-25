# Embedded Providers Architecture

## Overview

In `lmcloud` v0.1.x, infrastructure configurations initially relied exclusively on the built-in `terraform_data` resource. Real cloud providers in OpenTofu/Terraform are standalone executables communicating over OS pipes via `go-plugin` and gRPC. Downloading providers normally requires external internet access during `tofu init`.

To enable rich offline tasks (passwords, tokens, file templating, time-based rotation, TLS certificates, archives, and triggers), `lmcloud` embeds six utility providers directly into the static binary:
1. `random` (HashiCorp / IBM, MPL-2.0)
2. `null` (HashiCorp / IBM, MPL-2.0)
3. `local` (HashiCorp / IBM, MPL-2.0)
4. `time` (HashiCorp / IBM, MPL-2.0)
5. `archive` (HashiCorp / IBM, MPL-2.0)
6. `tls` (HashiCorp / IBM, MPL-2.0)

## In-Process gRPC Architecture

Rather than compiling separate plugin executables or opening TCP/Unix sockets, providers are linked as standard Go libraries and served in-memory:

1. **`bufconn` In-Memory Transport:**
   `internal/builtin/providers/inprocess.go` provisions an in-memory listener via `google.golang.org/grpc/test/bufconn.Listen(1024 * 1024)`.
2. **In-Process gRPC Server:**
   A standard `grpc.NewServer()` serves `tf6server.GRPCProviderPlugin` over the memory buffer.
3. **In-Process Dialing:**
   The client dials using `grpc.WithContextDialer` hooked directly to `bufconn.Dial()`, returning an in-process `providers.Interface`.
4. **Lifecycle Management:**
   When OpenTofu shuts down the provider interface (`Close()`), both the gRPC client connection and the server listener are stopped cleanly.

## Upstream Integration Points

1. **Provider Resolution (`internal/command/meta_providers.go`):**
   `InternalProviders()` registers factories for each embedded provider under `builtin`, `hashicorp`, default registry hostname, and `registry.terraform.io`.
2. **Dependency Installer (`internal/providercache/installer.go`):**
   `Install()` checks if the required provider matches an embedded type and skips network lookups during `tofu init`.
3. **Lock File Exemption (`internal/depsfile/locks.go`):**
   `ProviderIsLockable()` treats embedded utility providers as internal, preventing failures due to missing `.terraform.lock.hcl` entries in offline environments.

## Protobuf Namespace Resolution

Both OpenTofu (`internal/tfplugin6`, `internal/tfplugin5`) and `terraform-plugin-go` register identical protocol buffer schemas (`tfplugin6.proto`, `tfplugin5.proto`). Go's protobuf v2 runtime panics if two packages register the same file descriptor.

To resolve this without requiring external shell environment variables:
- `internal/tfplugin6/conflict.go` and `internal/tfplugin5/conflict.go` execute in `init()`:
  ```go
  if os.Getenv("GOLANG_PROTOBUF_REGISTRATION_CONFLICT") == "" {
      _ = os.Setenv("GOLANG_PROTOBUF_REGISTRATION_CONFLICT", "warn")
  }
  ```
- Similarly, `internal/builtin/providers/inprocess.go` suppresses unconfigured SDK debug logging:
  ```go
  _ = os.Setenv("TF_LOG_SDK", "off")
  _ = os.Setenv("TF_LOG_SDK_PROTO", "off")
  _ = os.Setenv("TF_LOG_PROVIDER", "off")
  ```

## Binary Size Deltas (Static `CGO_ENABLED=0 -ldflags "-s -w"`)

All binaries compiled with Go 1.26 on `linux-x64` with `-trimpath -ldflags "-s -w"`:

| Configuration | Binary Size (bytes) | Delta | Notes |
| --- | --- | --- | --- |
| Baseline (`v0.1.4`) | 110,891,168 | - | Built-in `terraform_data` only |
| Engine + `null` | 114,827,424 | +3.75 MB | Adds gRPC server, bufconn, plugin6 bridge |
| + `local` | 114,948,000 | +120 KB | File and sensitive file rendering |
| + `time` | 115,128,000 | +180 KB | Timestamps and rotation timers |
| + `random` | 115,368,000 | +240 KB | Crypto random strings, IDs, pets |
| + `archive` | 115,788,000 | +420 KB | Tar and zip directory archiving |
| + `tls` | 116,256,928 | +850 KB | ECDSA/RSA keys, X.509 cert chains |
| **Total Delta** | **116,256,928** | **+5.36 MB (+4.8%)** | All 6 providers embedded |

## Licensing

All embedded providers are open-source software licensed under Mozilla Public License 2.0 (MPL-2.0). Upstream notices and full license texts are maintained in [`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
