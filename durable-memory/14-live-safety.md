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
| `journal.go` | Append-only JSONL `Journal` (`JournalMeta`, `JournalRecord`, `LedgerEntry`, `LedgerState`), `EnsureStateDir` (`0700` leaf, no symlinks, UID check), `OpenJournal` (`O_NOFOLLOW`, `0600`, exclusive `flock` on a dedicated never-renamed `<run_id>.lock` file, torn-tail truncation + `fsync`, endpoint userinfo/query/fragment redaction via `RedactEndpoint`), `BeginCreate` (persists 128-bit `OwnerNonce`, `CreateToken`, and `ReservedNanoUSD` before network call), `Confirm` (refuses `retained` entries), `Failed` (never cancels `confirmed` or `retained`), `Retain` (sticky across confirm and compaction), `Deleted`, `RecordCost`, `Compact` (atomic temp + `fsync` + `os.Rename` + dir `fsync` while holding `<run_id>.lock`), failed-write rollback + poisoning, persisted campaign counters (`StartedAtUnix`, `BucketsCreated`, `QueuesCreated`, `ObjectsCreated`, `MessagesSent`, `TotalPayloadBytes`), `LoadJournal`, and `ReplayJournal`. |
| `journal_unix.go` / `journal_windows.go` | Platform-specific `flock(LOCK_EX|LOCK_NB)`, owner UID verification, package `init()` installing `signal.Ignore(syscall.SIGXFSZ)` so exceeded file-size limits return `EFBIG` instead of killing the process, and explicit Windows refusal. |
| `cost.go` & `prices/aws/us-east-1.json` | Embedded regional price-table loader (`LoadEmbeddedPriceTable`, `LoadPriceTableFromFS`, fail-closed on unknown provider/region/operation or stale `effective_date > max_age_days`), `CostMeter` (`$0.05` default cap, `$0.25` ceiling, `$0.01` cleanup reserve so ordinary work stops at `$0.04`), pre-attempt `ReserveAttempt`, `Commit`, `ReleaseResourceCleanup`, and `AttemptQuoter` (`QuoteAttempt` clamped to `max(base, q)` per component so adapters can never discount below the embedded tariff floor). |
| `recovery.go` | Provider-neutral `RecoveryAdapter` interface (`AttestIdentity`, `ResolveScope`, `ReadOwnership`, `FindOwned`, `DeleteOwned`, `PollDelete`, `ClassifyAbsent`, `QuoteAttempt`), `OwnershipTags` context helpers (`WithOwnershipTags`, `OwnershipTagsFrom`), and `RemoteOwnership` (including mandatory `ChildrenVerified` for bucket child listings and `VerifyMatchesEntry`). |
| `guard.go` | `LiveGuard`, `GuardStore` (`hostkit.ObjectStore`), and `GuardQueue` (`hostkit.Queue`) wrappers enforcing read-only mode, persisted campaign resource/byte/wall-clock limits, `GetObject` limit clamping to `MaxObjectBytes`, ordinary-work billing for `Queue.Ack`, pre-attempt cost reservation, `intent -> adapter -> ReadOwnership -> confirm` (marking post-create ownership collisions as `retained`), refusing `CreateBucket`/`CreateQueue`/`Delete*` on `retained` entries, mandatory `ChildrenVerified` + empty `ChildKeys` check on `DeleteBucket`, and token registration with `hostkit.ErrorState.AddRedaction`. |
| `sweep.go` | Ownership-revalidating LIFO sweeper (`Sweep`): dry-run by default (`Apply: false`), identity/scope attestation before sweep, pending-intent grace period (`DefaultPendingIntentGraceSeconds = 10s`) before tombstoning absent `pending` intents, re-reading remote ownership before every delete, requiring `ChildrenVerified` and emptying proven-owned child objects before deleting a bucket (retaining if `ChildrenVerified` is false or unexpected children exist), recording `FindOwned` errors in `SweepReport.Failed`, classifying ambiguous 403/404 (`AbsenceAmbiguous`) as `retained`, polling async deletions via `PollDelete` before writing `deleted` tombstones, and journal compaction. |
| `session.go` | Single-invocation `Session` (`OpenSession`, `FinishAndSweep`, restoring both committed spend and unresolved `pending` intent reservations) and multi-invocation campaign `Supervisor` (`NewSupervisor`, `RunInvocation`, `FinishCampaign`, `ListRunJournals`, `SweepAllStale` with `CostMeter` enforcement). |
| `fakerecovery.go` | Deterministic in-memory and file-backed persistent `FakeRecoveryBackend` implementing `RecoveryAdapter`, `hostkit.ObjectStore`, and `hostkit.Queue` for offline Stage 1 testing. |

---

## 3. Core Safety Invariants

1. **Intent-Before-Create with Persisted Nonces & Sticky Retention:**
   - `Journal.BeginCreate` generates a 128-bit `OwnerNonce` (resource identity) and a 128-bit `CreateToken` (attempt idempotency token), writes the `intent` JSONL record (including `ReservedNanoUSD`), and `fsync`s the journal file **before** the adapter dispatches any create request.
   - Retries of a `pending` create reuse the persisted `OwnerNonce` and `CreateToken`.
   - Duplicate creates of an already-`confirmed` resource never overwrite `OwnerNonce` or `CreateToken`, and a subsequent `Journal.Failed` call **never** cancels an already-`confirmed` or `retained` entry.
   - Any post-create ownership mismatch or ambiguous state records the resource as `retained` (`Retain: true`, `StateRetained`). Retained entries are sticky across `Confirm` and `Compact`, are short-circuited in `CreateBucket`/`CreateQueue` before touching the adapter (preventing duplicate-create tag overwrites), and are refused by all guard `Delete*` operations.
2. **Dedicated `.lock` Lease & Failed-Write Rollback/Poisoning:**
   - `OpenJournal` holds its `flock(LOCK_EX|LOCK_NB)` lease on a dedicated `<run_id>.lock` sibling file that is never renamed or unlinked during `Compact()`, eliminating any lease race across atomic `.jsonl.tmp -> .jsonl` renames.
   - If a crash or disk-full (`EFBIG`) leaves an incomplete final line without a trailing `\n`, `OpenJournal` truncates the incomplete tail back to the last `\n` and `fsync`s, while `LoadJournal` tolerates and ignores the torn final line.
   - If any write, short write, or `fsync` fails on an open `Journal`, `appendLocked` immediately truncates and seeks the file back to the last good offset and poisons the `Journal` instance so subsequent appends fail closed without creating middle-line JSON corruption.
   - Any corrupt or invalid JSONL line in the middle of the file (terminated by `\n`) is **fatal**.
3. **Create-Token & Endpoint Redaction:**
   - Every `OwnerNonce` and `CreateToken` is registered with `hostkit.ErrorState.AddRedaction` before network dispatch so echoed tokens in provider error messages or codes are replaced with `[create-token]`.
   - `RedactEndpoint` strips any URL userinfo, query parameters, or fragments before persisting `JournalMeta.Endpoint`, and `ReplayJournal` rejects unredacted endpoints.
4. **LIFO Ownership-Revalidating Sweep & Mandatory Child Listing:**
   - Child objects (`object`) are swept in reverse creation order (LIFO) before top-level buckets (`bucket`) and queues (`queue`). Queue messages are tracked for cost (`EventCost`), cumulative count (`MessagesSent`), and payload bytes (`TotalPayloadBytes`), and are removed when their owning queue (`queue`) is deleted during the sweep.
   - Before deleting a bucket (in either `GuardStore.DeleteBucket` or `Sweep`), `RemoteOwnership.ChildrenVerified` must be `true`; if child listing could not be verified or if any unjournaled/unowned child object is present in `RemoteOwnership.ChildKeys`, the bucket is retained and never deleted.
   - `Sweep` honors a grace period (`DefaultPendingIntentGraceSeconds = 10s`) from `IntentAtUnix` before tombstoning a `pending` entry that reads as absent, preventing premature tombstoning of an in-flight create that has not yet converged.
   - Asynchronous deletions are polled via `RecoveryAdapter.PollDelete` until convergence before writing the `deleted` record.
