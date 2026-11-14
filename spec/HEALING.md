# HEALING (sibling to `spec/IMPLEMENTATION.md`)

Status of this document: **slice 1 implemented**. Slices 2–5 are specified here only so the boundary is visible. They are not implemented.

`spec/IMPLEMENTATION.md` is **not edited**. Its SHA-256 remains
`9643ee06f6817b08c57ea585fd8f919d4b23639bffd817a4a3084c7c9d0d30ae`
(`tests/unit/test_spec_integrity.py`). This file is the sibling that describes the failure corpus.

Implementing slice 1 does not install it on the host and does not make the installation OPERATIONAL. `healing` defaults to `off`.

## 1. The loop

The healer loop is a projection plus, later, ordinary jobs:

1. **Collect.** The engine reads the append-only events log and the related tables and writes a snapshot when the item set changed. A later disposable process, or a model, obtains that snapshot with `omg heal collect` or the MCP `heal` tool. It does not query the database to invent a corpus.
2. **Healer.** A role, independent of the author of the failing work, reads a snapshot. Not this slice.
3. **Diagnose and propose.** The healer explains the failure and proposes a fix. Not this slice. Proposal does not enqueue.
4. **Fix job.** `enforce` may enqueue a fix. That fix is a normal oh-my-grok job. It still needs a plan, user approval, and review. Not this slice.
5. **Lessons and outside review.** A lessons store, and ingestion from the reserved `github_review_bot` source. Not this slice.

Slice 1 is only step 1. In every mode, including `enforce`, collect does not enqueue a task, a dispatch, or a job.

## 2. Hard rules

- **No silent bus rewrite.** Collect does not flip a job phase, does not update a job, task, review, verification, or dispatch row. A new snapshot appends one `failures_collected` audit event. That event has a null `job_id`, so it does not mark a job dirty and does not flush a boulder. An unchanged item set does not append that event. It only updates `seen_count` and `last_seen_at` on the latest snapshot.
- **Projection, not authority.** Snapshots are derived, the same way `.omo/boulder.json` is derived. The engine does not read `failure_snapshots` or `failure_items` when it decides a transition. Collect builds the item set from source tables only. It reads the latest snapshot's corpus hash to skip an identical insert. A tampered item payload is not copied into the next corpus. A model must not read the raw database to build the corpus.
- **Healer independence is slice 2.** This slice adds no roster role, no routine, no Bot binding, and no independence group. The MCP `heal` tool does not require a binding.
- **A durable fix is a normal job.** It needs a plan, a user approval, and review. Slice 1 never creates that job. `shadow` and `enforce` differ only by the mode recorded on the snapshot.
- **`github_review_bot` is reserved.** The name is a future source. Events of that kind are ignored. Nothing in this slice fetches GitHub review comments.

## 3. Feature flag

`policy.json` key `features.healing`, modes `off | shadow | enforce`, default `off`. It is frozen into a job at submit with the other flags. Collect does **not** consult that frozen copy. It reads the process's current policy, so a job submitted while the flag was off is still collected after the flag is turned on, and turning the flag off stops new snapshots.

| Mode | Collect |
|---|---|
| `off` | Refusal (`gate_refused`, "healing is off; collect writes nothing"). No snapshot row and no `failures_collected` event. |
| `shadow` | Writes a snapshot and one audit event when the item set changed. An unchanged set bumps `seen_count` on the latest snapshot. Records `mode=shadow` on a new snapshot. Enqueues nothing. |
| `enforce` | Same write as `shadow`, with `mode=enforce` on a new snapshot. Enqueues nothing. Later slices are what make `enforce` enqueue, and only as a normal job. |

`omg heal show` reads a snapshot that already exists. It does not consult the flag and it does not write.

## 4. What a snapshot contains

Migration 6 adds `failure_snapshots` and `failure_items`. Migration 7 adds `seen_count` (default 1) and `last_seen_at` (backfilled from `created_at`). A collect inserts one snapshot (`id`, monotonic `seq`, `mode`, `item_count`, `corpus_sha256`, `created_at`, `seen_count`, `last_seen_at`) and one item row per failure only when the item-set fingerprint differs from the latest snapshot.

An item body is canonical JSON: `json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. The item sha256 is the SHA-256 of that text. The corpus sha256 is the SHA-256 of the canonical JSON array of those item sha256s, in item order. That corpus sha256 is the fingerprint. Order is `(class, job_id, source, identity)`. Identity is `event_id`, else the `event_ids` list, else `review_id`, else `record`, else `job_id`.

Snapshot id, `created_at`, `last_seen_at`, and `seen_count` are not part of an item hash. Mode is not part of the fingerprint either: a collect whose items match the latest snapshot does not replace that snapshot's mode. A second collect on unchanged sources keeps the same snapshot id, increments `seen_count`, and sets `last_seen_at`. It does not insert a snapshot or a `failures_collected` event. The audit row from the first collect is not a source, so it does not change the fingerprint. A changed item set inserts a new snapshot with `seen_count` 1.

### Sources in this slice

| Source | Class | When |
|---|---|---|
| `blocked_job` | `blocked` | `jobs.phase='blocked'`. Body includes `phase`, and `blocked_from` / `failure_reason` when set. |
| `repair_cycle` | `repair` | One item per `events.kind='repair_cycle'` row whose job still exists. Body includes `event_id` and, when the event data has them, `failures`, `reason`, `max`, and `task_id`. |
| `repair_cycle` | `repair` | If `jobs.repair_cycles>0` and that job has no `repair_cycle` event, one item from the counter: `failures` plus `record="jobs.repair_cycles"`. A later `done` job keeps its counter, so it stays in the corpus. When events exist, the counter is not also emitted. |
| `review_finding` | `review` | One item per `reviews` row with `verdict='reject'`, including invalidated rows. Body includes `review_id`, `type`, `findings`, `invalidated`, and `revision` / `plan_revision_id` / `task_id` when set. |
| `repeated_failure` | `repeated` | One item when a job has two or more `repair_cycle` events. Body includes `count` and `event_ids`. |
| `stall` | `stall` | A non-terminal task on a job whose phase is not `done`, `failed`, `cancelled`, or `blocked`. See below. |
| `github_review_bot` | — | Reserved. Not emitted. |

Every item has `class`, `source`, and `job_id`. Accept verdicts, a running job with `repair_cycles=0`, and events of other kinds (including `failures_collected`) are not items. A stall's identity is its `task_id`. Items that already had an `event_id`, `event_ids`, `review_id`, or `record` still use that, so their hashes do not change.

### Stall items

| Reason | When |
|---|---|
| `awaiting_resume` | Status is `awaiting_resume` and `updated_at` is at least `stall_awaiting_resume_seconds` old. Default 600 (10 minutes). |
| `lease_expired` | Status is `working` and `lease_expires_at` is in the past. A working task whose lease has not expired is not a stall. |
| `dispatch_stuck` | The current dispatch is `pending`, `sending`, or `retry_wait`, not superseded, and either `lease_until` is in the past or the dispatch row has been idle for `lease_seconds`. |
| `no_progress` | Any other `queued`, `dispatched`, or `submitted` task, or a `working` task with no lease, idle for `lease_seconds`. Default 1800, the same value as the task lease. |

The body includes `task_id`, `role`, `status`, `reason`, `threshold_seconds`, and `dispatch_id` / `channel` when the task has a current dispatch. It does not include the age. A second collect of the same stall therefore has the same item sha256.

Collect does not wake a Bot, does not insert a dispatch, and does not change the task. `healing` `off` still writes nothing, so a stall that exists is not snapshotted until the flag is `shadow` or `enforce`. Those two modes still only differ by the mode stored on the snapshot. Wakes are not this flag. They belong to the host watchdog (`features.watchdog`, `docs/RUNBOOK.md`).

## 5. Interfaces

- `oh_my_grok/healing.py`: `collect(conn, mode)` and `show(conn, snapshot_id=None)`.
- `omg heal collect` prints the snapshot id, `sha256:`, the mode, one line per item (`class`, job id, item sha256), and `status: written` or `status: unchanged`. `--json` prints the same object, including `written`, `status`, and `seen_count`. Exit 5 when the flag is off. Exit 0 when the corpus was collected, including an empty corpus and an unchanged snapshot.
- `omg heal show [SNAPSHOT]` prints the latest snapshot, or that id, including `seen_count`. Exit 3 when none exists. It does not write.
- `omg heal prune-duplicates` collapses consecutive snapshots with the same corpus sha256. It keeps the first of each run, sums `seen_count`, and keeps the latest `last_seen_at`. A later non-adjacent run of the same hash is kept. The default is a dry run. `--apply` deletes the duplicate snapshots and their items. Collect and the watchdog never run it.
- MCP tool `heal` with `action=collect|show` and optional `snapshot_id` (show only). It is read-only with respect to jobs. It does not require a healer binding. There is no enqueue action. An unchanged collect still returns the current item set and does not insert a snapshot.

## 6. Later slices (not implemented)

- **Slice 2.** A healer role, its routine, its Bot binding, and an independence group distinct from the author of the failing change.
- **Slice 3.** Diagnose and propose from a snapshot. Still no enqueue.
- **Slice 4.** In `enforce` only, enqueue the proposal as a normal oh-my-grok job. That job still needs a plan, user approval, and review. `shadow` stays record-only.
- **Slice 5.** A lessons store, and collection from `github_review_bot`.

Until those slices exist, `enforce` and `shadow` have the same effect: a snapshot and an audit event when the item set changed, or a `seen_count` bump when it did not.

## Known gap

Submit-time refusals (`ValidationError` before a job row exists) are not visible to `omg heal collect`. The engine rejects the request before inserting a job, so collect has no row and no event to project. Reserve this as a later collection source. Not implemented.
