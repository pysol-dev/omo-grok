# Migration notes

## Name cutover (not done in this change)

The code in this tree is **oh-my-grok** (`omg`, package `oh_my_grok`). That does not rename the live host.

Still deferred, and not performed here:

- Renaming the GitHub repository. The live URL remains https://github.com/pysol-dev/omo-grok . The intended name is `pysol-dev/oh-my-grok`. That URL is not live. After the repository is renamed, the old URL will redirect.
- Moving the live checkout from `/workspace/omo` to the documented path `/workspace/omg`.
- Re-registering the MCP connector. It is still `user-omo`. This tree's server name is `omg`; the intended connector name is `omg` / `user-omg`.
- Renaming live Grok Bot routines from `omo-bus-*` / `omo-reconcile` to `omg-bus-*` / `omg-reconcile`. The files in `routines/` are the new instructions. Do not delete the live routines.
- Rotating webhook keys. Do not regenerate secrets for this rename.

Compatibility that stays in the code: `omoctl` execs `omg`; `OMO_*` environment variables are accepted when the `OMG_*` name is unset; boulder readers accept `x_omo_grok` as well as `x_omg`; a `state/omo.sqlite3` file is opened when `state/omg.sqlite3` is absent; git history still accepts an `Omo-Job:` trailer; verifier profiles still fail closed on `OMO_VERIFY_TEMPLATE` and accept runner name `omo-unittest-child`. A profile argv that still ends at `<checkout>/omo_grok/unittest_child.py` (or `oracle_child.py`) is loaded as the same file under `oh_my_grok/`.

`spec/IMPLEMENTATION.md` was not edited and still uses the old names.

## Prior build
Reconnaissance on 2026-11-03 (ledger T00/T01) found that `/workspace/omo` **did not exist** before this run. None of
the following existed anywhere on the box:

- `bus.py` or `omoctl`
- an omo SQLite database
- `hooks.json`
- any omo routine

The earlier claim of an existing SQLite build at `/workspace/omo` could therefore not be reproduced or backed up. It
is recorded as an **unverified prior claim**. Nothing was migrated, and existing Bots and routines were not touched.

## Schema migrations in this build
| Version | Content |
|---|---|
| 1 | Core tables: jobs, tasks, deps, attempts, artifacts, inputs, plan revisions, approvals, role bindings, outbox, verifications, reviews, events |
| 2 | `hooks_meta` (booleans only) and `gate_results` tables plus indexes. See `oh_my_grok/db.py` `MIGRATIONS` |
| 3 | `verifications.assurance TEXT NOT NULL DEFAULT 'none'` (oracle / cooperative / none). Applied automatically on the next open, after the automatic backup |
| 4 | `verifications.sandbox TEXT NOT NULL DEFAULT 'none'` (mechanism used: `bwrap` / `none`) and `verifications.tamper_json TEXT NOT NULL DEFAULT '[]'` (trusted-file changes seen during the run). Old rows read `none` / `[]` |
| 5 | Adaptive orchestration: `jobs.intent`, `jobs.roster_class`, `jobs.scope_json`; tables `escalations`, `tool_receipts`, `work_sessions`, `boulder_projection`, `repo_leases`. A job that has no frozen `policies_json.features` keeps every new feature off |
| 6 | Failure corpus: `failure_snapshots` and `failure_items`. Written only by `omg heal collect` / MCP `heal` when `features.healing` is `shadow` or `enforce`. Not read back as authority. A job that has no frozen `healing` key keeps that flag off; collect itself follows the current policy |
| 7 | `failure_snapshots.seen_count` (default 1) and `failure_snapshots.last_seen_at` (backfilled from `created_at`). `omg heal collect` inserts a snapshot only when the item-set fingerprint differs from the latest snapshot; an unchanged collect bumps `seen_count` and `last_seen_at` and does not append another `failures_collected` event. Existing duplicate rows are kept. Collapse them only with `omg heal prune-duplicates` (dry-run) and then `omg heal prune-duplicates --apply`. That command is never run by collect or the watchdog |

Each migration is recorded in `schema_migrations` with a checksum, and a mismatch is reported by `doctor`.
`omg migrate` takes an automatic backup first when the DB is not empty (`omoctl migrate` is the same command). Roll back with `omg restore <backup>`.

## Cutover and rollback

### What this installation is
This build **is** the installation under `/workspace/omo`. There is nothing older to retire here: recon (T00/T01)
found no prior `bus.py`, SQLite DB, hooks, or omo routines on the box. Prior claims of an existing SQLite build at
this path were unreproducible (see Prior build above).

### What exists now (as of 2026-11-06)
- SQLite schema **v4** at `state/omo.sqlite3` (migrations 1–4). Automatic pre-migrate backups live under
  `state/backups/pre-migrate-v*.sqlite3` (currently `pre-migrate-v2-*.sqlite3` and `pre-migrate-v3-*.sqlite3`).
- `user-omo` MCP registered (stdio command server).
- **8 logical roles** on **5 bots**: Hephaestus plus Explorer, Librarian, Metis, Momus, and Executor (Metis also
  binds `qa-executor`; Momus also binds `code-reviewer`).
- **7** `omo-bus-*` webhook routines created, verified, and hooked (explorer, librarian, metis, momus, executor,
  code-reviewer, qa-executor). The optional Hephaestus resume webhook is **not configured**.
- Live jobs on DB evidence: `e667cf20` (§10.20 / §10.21) and `9fa4f055` (§10.22). See ledger T11.
- Status remains **PARTIALLY INSTALLED / NOT OPERATIONAL**. Do not claim OPERATIONAL.

### Cutover meaning
Cutover means accepting this tree as the live install and continuing operations against it — not migrating off a
previous `/workspace/omo` build. Bots and routines already created stay in place.

### Rollback (code / DB)
1. Stop in-flight claims. After any code or DB rollback, restart/reload the MCP server process so
   processes are not stale (fingerprint / `stale_server` check). On the live host that process is still the `user-omo` connector until it is re-registered.
2. Restore SQLite from a backup under `state/backups/` with
   `./omg restore state/backups/pre-migrate-vN-<timestamp>.sqlite3` (TTY required; integrity-checked; keeps a
   pre-restore copy of the current DB). `omoctl restore` runs the same CLI.
3. Keep `state/secrets/hooks.json` mode **0600** (`doctor` checks this). Do not make it world-readable.
4. **Do not delete** Bots or webhook routines as part of a rollback — leave them configured. Live routines may still be named `omo-bus-*`.
5. Grok Bot conversations and agent memory are **not** restored from filesystem backups; only the SQLite state
   (and whatever you keep under `state/` / `jobs/`) comes back from `omg restore` / file restore.

Uninstall (remove the MCP registration, disable/delete routines, delete the tree) is a separate destructive path in
`docs/RUNBOOK.md` §12 — not the rollback path.

### Host cutover for the adaptive branch (not done from this checkout)
This branch does not touch the live runtime, the live database, webhook keys, routines, or Bot profiles. The parent does the cutover, after an independent review of the diff:

1. Stop in-flight claims. Do not delete Bots or webhook routines (`omo-bus-*` on the live host today).
2. Deploy this tree onto the host checkout. The documented path is `/workspace/omg`; the live directory is still `/workspace/omo` until someone moves it. Keep `state/secrets/hooks.json` where it is. An existing `state/omo.sqlite3` keeps working.
3. Install the OS package `bubblewrap` if `bwrap` is missing. On a host that blocks unprivileged user namespaces, set `kernel.apparmor_restrict_unprivileged_userns=0` or candidate runs and language servers fail closed.
4. From the checkout: `scripts/bootstrap.sh` (hash-pinned `.venv` and `tools/`). Then `./omg migrate` (backs up a non-empty DB, applies schema v7) and `./omg doctor`. Duplicate heal snapshots already stored are not deleted by migrate. After v7, `./omg heal prune-duplicates` reports them and `./omg heal prune-duplicates --apply` collapses consecutive identical ones. Do not expect the watchdog to do that.
5. `./omg mcp-command` prints `<venv python> <code root>/oh_my_grok/mcp_server.py`. Re-registering that command as `omg` / `user-omg` is a later cutover step. Until then, restart the existing `user-omo` process only if you point it at this tree and accept that its registered name is still the old one. The tool list is `submit, claim, context, checkpoint, complete, status, reconcile, cancel, escalate, docs, heal`.
6. Paste the updated instructions from `agents/hephaestus-omg.md` and `routines/*.md` into the existing routines when you are ready to rename them in place. Do not create new Bots and do not delete the current routines to do it.
7. Leave every feature in `config/policy.json` at `off` until `./omg lsp canary` passes on that host. Then turn on one feature at a time (`shadow`, then `enforce`).
8. `./omg doctor` stays NOT OPERATIONAL until the database holds a passed gate for a real implement job with engine LSP and git receipts, and a person records `omg attest host_cutover`, `attest live_smoke` and `attest live_e2e` from a TTY. This branch cannot record those.

### Honest gaps (still open)
- Routine run receipts for the live jobs are still pending (not readable from Hephaestus's session); T11 remains
  PARTIAL.
- Webhook key rotation is recommended (keys were chat-pasted on 2026-11-04; see `docs/SECURITY.md` and RUNBOOK
  rotation steps).
- Approval is **SOFT** only (local TTY receipt on a shared computer).
- No Auto Review rule was created.
- Hephaestus resume webhook is optional and not set (`hephaestus` remains unhooked).
