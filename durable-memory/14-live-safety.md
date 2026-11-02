# 14. Live Mode Safety Foundation (`hostkit/safety`)

This document specifies **Stage 1 of Live Mode**: the shared, provider-neutral safety, recovery-journal, cost-metering, and supervision package (`github.com/lmctl-ai/lmcloud/hostkit/safety`). It makes **zero real cloud calls** itself and is strictly additive to `hostkit`.

---

## 1. Operator Decisions & Stage 1 Scope

1. **Default remains sim/fake:** No host ever contacts a live cloud endpoint unless the double opt-in gate (`LMCLOUD_LIVE=1` **and** `LM<HOST>_LIVE=1`) and a validated `live-policy.json` file are supplied.
2. **Stage 1 live provider scope:** AWS only for now (account `254332045686`, region `us-east-1`, IAM role `awsspot-admin`). Other providers (`azure`, `gcp`, `oci`) remain disabled in `ResolveExecutionMode` until explicitly enabled in later stages.
3. **Mutation boundaries:** Live runs are either **read-only** (`allow_mutations: false`) or permitted to create **new** resources only when they carry the run's reserved prefix (`lmcloud-conf-<run12>-`) and mandatory ownership metadata (`lmcloud_run_id`, `lmcloud_owner_nonce`, `lmcloud_create_token`, `lmcloud_created_at`).
4. **Never adopt or delete unowned resources:** Pre-existing resources (even if they share the `lmcloud-conf-<run12>-` prefix) that lack this run's journaled `owner_nonce` and `run_id` are treated as foreign collisions (`CONFLICT` / `ForeignResourceCollision`) and are **never** adopted or deleted.
5. **No `--force-stale` and no Windows live mode:** Journal concurrency is governed strictly by POSIX `flock(LOCK_EX|LOCK_NB)` on `0600` files inside `0700` directories. Windows explicitly refuses live mode (`WindowsLiveUnsupported`).

---

## 2. Package Layout (`hostkit/safety`)

| File | Responsibility |
| --- | --- |
| `policy.go` | Immutable `Policy` (`live-policy.json`) parser/validator (`DisallowUnknownFields`), canonical SHA-256 `Hash()`, `DefaultAWSLivePolicy`, double opt-in gate `ResolveExecutionMode`, mixed live+loopback rejection, Windows refusal, `NewRunID` (`^run-[0-9]{10,}-[0-9a-f]{12}$`), and `ValidateLiveResourceName` (`lmcloud-conf-<run12>-<slug>-<seq>`). |
| `journal.go` | Append-only JSONL `Journal` (`JournalMeta`, `JournalRecord`, `LedgerEntry`, `LedgerState`), `EnsureStateDir` (`0700` leaf, no symlinks, UID check), `OpenJournal` (`O_NOFOLLOW`, `0600`, `flock`, torn-tail truncation + `fsync`), `BeginCreate` (persists 128-bit `OwnerNonce` and `CreateToken` before network call), `Confirm`, `Failed` (never cancels `confirmed`), `Retain`, `Deleted`, `RecordCost`, `Compact` (atomic temp + `fsync` + `os.Rename` + dir `fsync`), `LoadJournal`, and `ReplayJournal`. |
| `journal_unix.go` / `journal_windows.go` | Platform-specific `flock(LOCK_EX|LOCK_NB)`, owner UID verification, `SIGXFSZ` handling, and explicit Windows refusal. |
| `cost.go` & `prices/aws/us-east-1.json` | Embedded regional price-table loader (`LoadEmbeddedPriceTable`, `LoadPriceTableFromFS`, fail-closed on unknown provider/region/operation or stale `effective_date > max_age_days`), `CostMeter` (`$0.05` default cap, `$0.25` ceiling, `$0.01` cleanup reserve so ordinary work stops at `$0.04`), pre-attempt `ReserveAttempt`, `Commit`, `ReleaseResourceCleanup`, and `AttemptQuoter` (`QuoteAttempt`). |
| `recovery.go` | Provider-neutral `RecoveryAdapter` interface (`AttestIdentity`, `ResolveScope`, `ReadOwnership`, `FindOwned`, `DeleteOwned`, `PollDelete`, `ClassifyAbsent`, `QuoteAttempt`), `OwnershipTags` context helpers (`WithOwnershipTags`, `OwnershipTagsFrom`), and `RemoteOwnership.VerifyMatchesEntry`. |
| `guard.go` | `LiveGuard`, `GuardStore` (`hostkit.ObjectStore`), and `GuardQueue` (`hostkit.Queue`) wrappers enforcing read-only mode, resource/byte/wall-clock limits, pre-attempt cost reservation, `intent -> adapter -> ReadOwnership -> confirm`, parent ownership verification for child operations, idempotent missing-resource delete probes without issuing `DELETE` on unowned resources, and token registration with `hostkit.ErrorState.AddRedaction`. |
| `sweep.go` | Ownership-revalidating LIFO sweeper (`Sweep`): dry-run by default (`Apply: false`), identity/scope attestation before sweep, re-reading remote ownership before every delete, emptying proven-owned child objects before deleting a bucket (retaining if unexpected children exist), classifying ambiguous 403/404 (`AbsenceAmbiguous`) as `retained`, polling async deletions via `PollDelete` before writing `deleted` tombstones, and journal compaction. |
| `session.go` | Single-invocation `Session` (`OpenSession`, `FinishAndSweep`) and multi-invocation campaign `Supervisor` (`NewSupervisor`, `RunInvocation`, `FinishCampaign`, `ListRunJournals`, `SweepAllStale`). |
| `fakerecovery.go` | Deterministic in-memory and file-backed persistent `FakeRecoveryBackend` implementing `RecoveryAdapter`, `hostkit.ObjectStore`, and `hostkit.Queue` for offline Stage 1 testing. |

---

## 3. Core Safety Invariants

1. **Intent-Before-Create with Persisted Nonces:**
   - `Journal.BeginCreate` generates a 128-bit `OwnerNonce` (resource identity) and a 128-bit `CreateToken` (attempt idempotency token), writes the `intent` JSONL record, and `fsync`s the journal file **before** the adapter dispatches any create request.
   - Retries of a `pending` create reuse the persisted `OwnerNonce` and `CreateToken`.
   - Duplicate creates of an already-`confirmed` resource never overwrite `OwnerNonce` or `CreateToken`, and a subsequent `Journal.Failed` call **never** cancels an already-`confirmed` entry.
2. **Torn-Tail Recovery vs Middle-Line Corruption:**
   - If a crash or disk-full (`EFBIG`) leaves an incomplete final line without a trailing `\n`, `OpenJournal` truncates the incomplete tail back to the last `\n` and `fsync`s, while `LoadJournal` tolerates and ignores the torn final line.
   - Any corrupt or invalid JSONL line in the middle of the file (terminated by `\n`) is **fatal**.
3. **Create-Token Redaction:**
   - Every `OwnerNonce` and `CreateToken` is registered with `hostkit.ErrorState.AddRedaction` before network dispatch so echoed tokens in provider error messages or codes are replaced with `[create-token]`.
4. **LIFO Ownership-Revalidating Sweep:**
   - Child objects (`object`) and queue messages (`queue_message`) are swept in reverse creation order before top-level buckets (`bucket`) and queues (`queue`).
   - Before deleting a bucket, `Sweep` inspects `RemoteOwnership.ChildKeys`; if any unjournaled or unowned child object is present, the bucket is marked `retained` and never deleted.
   - Asynchronous deletions are polled via `RecoveryAdapter.PollDelete` until convergence before writing the `deleted` record.
