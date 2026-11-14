# oh-my-grok runbook

The documented checkout is `/workspace/omg`. The live host checkout is still `/workspace/omo` until cutover moves it. Commands below are `omg` (`omoctl` execs the same CLI). The MCP server name in this tree is `omg`; the live connector is still `user-omo` and has not been re-registered. Routine files in this repo are `omg-bus-<role>` and `omg-reconcile`; live Grok Bot routines still use the old names until they are renamed in place. Do not delete bots or routines as part of this rename, and do not regenerate webhook secrets.

`spec/IMPLEMENTATION.md` is frozen and still uses the old names. Newer docs use oh-my-grok.

Everyday use is talking to Hephaestus (`agents/hephaestus-omg.md`).
The commands below are operator controls. Exit codes:

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | internal |
| 2 | invalid |
| 3 | not found |
| 4 | conflict |
| 5 | gate refused |
| 6 | integrity |
| 7 | aborted / no TTY |
| 8 | doctor problems |
| 9 | test failed / not run |

## 1. Install (already done on this box)
```bash
cd /workspace/omg
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
./omg migrate
./omg doctor
./omg test unit
./omg test integration
```

## 1b. Fresh clone (relocation-safe)
`scripts/bootstrap.sh` is the install. It does not use sudo and it does not read or write the live runtime.

```bash
# host packages this script does not install: Python >= 3.12, git, bubblewrap (bwrap)
git clone https://github.com/pysol-dev/omo-grok.git
# intended name pysol-dev/oh-my-grok is not live yet; the old URL will redirect after the repository is renamed
cd omo-grok
scripts/bootstrap.sh          # .venv from requirements.lock, tools/ from tooling locks
./omg migrate
./omg doctor               # live status is derived; NOT OPERATIONAL until evidence exists
./omg lsp status           # which language servers are present, which languages fail closed
./omg lsp canary           # each present server must find a planted defect
./omg mcp-command          # exact stdio command for this checkout
```

`scripts/bootstrap.sh --check` exits 8 when a piece is missing. Placeholders in shipped config are `${OMG_CODE_ROOT}`, `${OMG_PYTHON}`, `${OMG_TOOLS}`, `${OMG_NODE}` and `${OMG_SITE}`. The legacy `${OMO_*}` spellings expand to the same values. Nothing in code or config hardcodes `/workspace/omo` or `/workspace/omg`. `OMG_PYTHON` wins over `OMO_PYTHON` when both are set.

Host-side needs this script cannot do: the `bubblewrap` package, unprivileged user namespaces (otherwise the sandbox fails closed), registering the MCP command in Grok Bot, binding roles, webhook secrets via `omg hook set` or `hook serve` (never paste keys into chat), and pasting routine instructions. See `docs/MIGRATION.md` for the cutover order. Do not delete Bots or routines as part of install.

## 2. Register the MCP server in Grok Bot (command server; user/parent step)
Register a custom **command** (stdio) MCP server named `omg` (the live connector is still `user-omo` until you re-register it; this runbook does not do that):

```
<CODE_ROOT>/.venv/bin/python <CODE_ROOT>/oh_my_grok/mcp_server.py
```

Print the exact command for this checkout with `./omg mcp-command` (it is computed from the checkout location
and `OMG_PYTHON` (or legacy `OMO_PYTHON`), so a relocated checkout never carries a stale path). Install the runtime first with
`scripts/bootstrap.sh`. The command needs no environment variables or secrets. Registration applies account-wide.

Confirm it from **at least two Bots**, for example Hephaestus and Explorer: the tool list should contain exactly
`submit, claim, context, checkpoint, complete, status, reconcile, cancel, escalate, docs`, and a `status` call should succeed. A local
`python -m` test does not count as registration.

## 3. Bind roles to Bots and routines
1. `./omg roles import config/roles.example.json` imports all 8 bindings as **unverified**, with no routine. The
   Bot ids come from the task brief and are unverified until read back.
2. On each Bot, create a webhook-triggered routine named `omg-bus-<role>`. Paste the instructions from
   `routines/<role>.md`. One Bot may host several role routines; the defaults are code-reviewer on Momus and
   qa-executor on Metis. The Hephaestus routine (`routines/hephaestus.md`) is optional.
3. Record the routine id and verify:
   `./omg roles bind ROLE --bot-id ID --bot-name NAME --routine-id RID --routine-name omg-bus-ROLE --group g-NAME --verified --provenance "read back <date>"`
   Use `--max-concurrent 1` for Bots that host several roles. Re-binding creates a new version; the old one is kept.
4. Optional: `routines/omg-reconcile.md` is a Hephaestus scheduled routine (every 15 min). Create it only if the
   user approves the ongoing usage.

## 4. Webhook secrets (user-only step)
For each async role, open the routine in the Grok Bot UI (desktop) and copy its webhook URL and key. Then run:

```bash
/workspace/omg/omg hook set ROLE   # hidden prompts for URL and key; nothing echoed
/workspace/omg/omg hook list       # role: configured true/false only
/workspace/omg/omg hook check ROLE --probe   # TLS handshake only, no POST
```

Never paste keys into chat, argv or files.

Pasted values are cleaned before validation: bracketed-paste markers (`ESC[200~`/`ESC[201~`, with or without ESC),
every control or non-printable character (CR, LF, TAB, ESC, zero-width), surrounding whitespace, and one matching
pair of surrounding quotes or `<...>`. Each prompt allows 3 tries. A rejection prints only a diagnostic (length,
empty, scheme http/https/empty/other, host present, whether characters were removed), never the value.
Metis serves two roles (`metis`, then `qa-executor`) and Momus two (`momus`, then `code-reviewer`); each has its
own routine (`omg-bus-<role>`) with its own URL and key, so run `hook set` once per role.

**Browser form (when terminal paste delivers nothing):** some GUI paste tools cannot type into a terminal
(`hook set` then sees length=0). Use the local-only masked form instead:

```bash
cd /workspace/omg && (umask 077; ./omg hook serve > state/logs/hook_serve.log 2>&1; rm -f state/logs/hook_serve.log) &
cat /tmp/omg_hook_form_url     # http://127.0.0.1:<random port>/setup/<per-run session token>  (file mode 0600)
```

The tokenized URL is written only to the 0600 URL file, never to stdout (`--print-url` overrides this; don't use
it with a log redirect). The log is created under umask 077 (mode 0600) in `state/logs/`, holds only status
lines, and the subshell deletes it once the server stops (Finish, idle timeout, Ctrl-C or SIGTERM); the server itself also removes the URL file and known log paths on those same stops. The token is a **per-run session
token**: 256 bits from `secrets.token_urlsafe(32)`, valid for any number of requests until the server stops, and
never reused across runs. It is not single-use.

Open that URL in the box browser. There is one section per async role, in this order: explorer, librarian, metis,
qa-executor (Metis), momus, code-reviewer (Momus), executor. Each section shows the bot, the routine and a
"Configured already: yes/no" line, plus two masked fields (URL, key). Paste into the fields, leave both blank to
skip a role, then press **Save**. The page reports configured / skipped / error per role, with the same safe
diagnostics as `hook set` and never the values. You can resubmit as often as needed. **Finish**, idle timeout, Ctrl-C (SIGINT) or SIGTERM stops the server and deletes the URL file (and known redirect logs). Idle timeout defaults to 30 minutes (`--idle-minutes N`).
How it is protected:
- It binds to 127.0.0.1 only, on a random port (`--port`).
- Every path except `/setup/<token>` returns 404.
- A Host other than `127.0.0.1:<port>`, or a foreign Origin, gets 403 (DNS-rebinding guard).
- Values travel only in the POST body (urlencoded, max 64 KB).
- Request logging is off, and responses are no-store with a strict CSP and `Referrer-Policy: same-origin`. With `no-referrer`, Chrome
  sends `Origin: null` on the same-origin form POST, which the strict Origin check rejects with 403; `null` is never accepted.
- Values pass through the same `sanitize_input` and `set_hook` validation as `hook set`, and are stored only
  in `state/secrets/hooks.json` (0600).

**Rotation (recommended now for all 7 roles; see SECURITY.md "2026-11-04 disclosure"):** for each async role,
open that role's Bot, then its `omg-bus-<role>` routine panel, and regenerate the webhook key (and URL if offered).
Then enter the new pair through `hook serve` (above) or `hook set ROLE`, never via chat. Check with `hook list`, then
`hook check ROLE --probe` (TLS only, no POST). The old key stops working at regeneration, so a job in flight shows
`HTTP 401/403: webhook key rejected` until the new pair is stored; then `resume JOB`.

## 5. Start a job
- Normally you say "plan this: <goal> in <repo>" to Hephaestus. Hephaestus classifies the request and calls `omg.submit` with an intent.
- Fallback: `./omg submit --goal-file goal.md --repo /path/to/repo [--plan-only|--implement|--fixture] [--intent explanation|investigation|implementation] [--scope-file scope.json] [--roster-class quick|standard|heavy] [--criteria-file c.txt] [--verifier-profile NAME] [--idempotency-key K]`
- With `adaptive_roster` `off` or `shadow`, omitting `--intent` keeps the original full team. `--roster-class` is accepted only when the flag is `enforce`.
- With `adaptive_roster` `enforce`, `--intent` is required.
  - `explanation` records the decision and creates no job.
  - `investigation` is read-only and accepts plan-only mode.
  - `implementation` requires `--scope-file`: a JSON object with `files_estimate`, `new_dependency`, `external_api`, `security_sensitive`, and `cross_cutting`. Unknown keys are rejected. The engine picks the smallest class; `--roster-class` may only raise it.
- `scope.json` for a one-file change with no new dependency, no external API, and no security-sensitive or cross-cutting work:

```json
{"files_estimate": 1, "new_dependency": false, "external_api": false, "security_sensitive": false, "cross_cutting": false}
```

- Real repos default to plan-only and must be clean git repos (optionally restricted by `repo_allowlist`).
- Live smoke: `./omg test live --fixture-only [--timeout 3600] [--poll 60] [--json]`. The harness submits the synthetic calc fixture as `intent=implementation` with that one-file scope, then reconciles and observes the database. The same submit is accepted when `adaptive_roster` is `enforce`, `shadow`, or `off`. Real progress still requires bound, verified Grok Bot routines. Missing bindings report NOT RUN.

## 6. Plan review and approval
- `./omg plan show JOB` prints the revision, hash, Momus verdict and full plan.
- `./omg approve JOB --plan-hash <64-hex> [--no-edit] [--accept-reduced-assurance]` needs an interactive TTY. You
  type the first 12 characters of the hash. It records a SOFT receipt.
- `./omg deny JOB --reason "..."` creates a new plan revision. The number of rounds is capped.

## 7. Pending work and status
- `./omg status [JOB] [--json]` shows the phase, `next_action`, task states, `block_reason`, dispatch state,
  verifications, gates and the `awaiting_resume` list.
- `awaiting_resume` tasks are Hephaestus tasks. Hephaestus claims them in its next chat turn.

## 8. Interrupted runs and reconciliation
`./omg reconcile [JOB]` (also the MCP tool `reconcile`) does the following:

- expires leases (requeue, or block when out of attempts)
- recovers interrupted sends as uncertain retries
- re-wakes unclaimed tasks after `rewake_after_seconds`, at most `max_rewakes` times, then blocks
- re-runs verification that stopped mid-run
- schedules ready work and flushes the outbox

It is safe to run repeatedly.

## 9. Verifier profiles
These live in `config/verifiers.json`. Each profile has these fields:

| Field | Requirement |
|---|---|
| `argv` | absolute interpreter, no shell; a Python interpreter must be run isolated (`-I` before `-m`). It must resolve (realpath) inside `/usr` (not `/usr/local`): children run the system interpreter inside the sandbox, never the venv |
| `cwd` | inside the worktree |
| `env_allow` | allowed environment variables |
| `timeout_seconds` | run time limit |
| `protected_paths` | paths the Executor must not change relative to base |
| `editable_paths` | allowlist: the ONLY paths the Executor may add, change, delete or rename |
| `runner` | `"omg-unittest-child"`, required for Python profiles; argv must then end with the absolute path of `oh_my_grok/unittest_child.py` (no `-m`) |
| `start_dir` | relative test discovery dir for the advisory unittest child (e.g. `tests`) |
| `expected_tests` | non-empty unique list of test ids that must ALL run and pass (no extras, skips or failures) |
| `oracle` | `{"name": "<key in oh_my_grok/oracles.py ORACLES>", "cases_per_function": 8..2000, "modules": [...]}`. **Required** for every profile named `fixture-*`. Without it a profile is `cooperative` (see below). `type_checks` was removed in T07 round 3 and is refused |
| `source_extensions` | allowlist of file extensions the candidate may add or change (default `[".py"]`) |
| `pure_modules` | `{"allow_imports": [...]}`. **Required** for every `fixture-*` profile: every changed `.py` under `editable_paths` must pass the pure-function rule (no environment/context observation, no state between calls; imports only from this list, at most `math`, `operator`, `cmath`, `numbers`). `fixture-calc-unittest` allows none |
| `static_scan` | AST-scan rule overrides (`allow_imports`, `allow_attrs`, `allow_calls`, `forbid_imports`, `allow_dunder_overrides`, `allow_builtin_subclass`); cannot be disabled |
| `exit_code_only` | required `true` for non-Python argv; the pass then rests on exit code alone (REDUCED assurance) |

A profile whose argv or referenced script contains `OMG_VERIFY_TEMPLATE` or the legacy marker `OMO_VERIFY_TEMPLATE` is refused. So are:
- a missing profile
- a Python profile without `-I` or without the unittest child and `expected_tests`, or a `fixture-*` profile without an `oracle` or `pure_modules`
- a non-Python profile without `exit_code_only: true`

Before running, the verifier diffs base..candidate (`--no-renames`, so renames count as delete+add) and rejects the
candidate without executing it when any changed path:
- is outside `editable_paths` or inside `protected_paths`;
- is an interpreter or test-runner hook (`sitecustomize.py`, `usercustomize.py`, `*.pth`, `conftest.py`, `pytest.ini`,
  `tox.ini`, `setup.cfg`, `pyproject.toml`), at any depth;
- is a top-level module or package (in the cwd or an argv directory) whose name shadows a stdlib module, a module the
  verifier uses (`unittest`, `pytest`, `site`, `importlib`, ...) or anything in the interpreter's site-packages.
  The list is unioned with the install-time snapshot `config/shadow_names.json`, so a later interpreter change can
  only add names, never drop them. To regenerate it, write `sys.stdlib_module_names` with the venv Python.
- is a `__pycache__`/`.pyc`/`.pyo`/native file, a symlink, a submodule, has an extension outside `source_extensions`,
  is binary or not UTF-8, or (for `.py`) fails the static AST scan (see SECURITY.md).

The trusted parent (which never imports candidate code) then decides the result:
- **oracle profiles** (assurance `oracle`): in each of 3 varied, neutral sandboxed runs (with different
  address-space limits: low / 4 GiB / none) the oracle child must answer every case (exhaustive [-16,16]^2 grid,
  boundary pairs, keyword/mixed-form and aliased-equal-argument copies, bool cases, magnitudes up to 2**4096, fresh random draws and per-run fresh large-magnitude draws (50 per function per run); keyword
  calls make the parameter names `a`, `b` part of the contract) with a raw JSON value that is `type(v) is int` and equal to the trusted oracle's answer,
  then exit 0, and the runs must agree. The advisory unittest child must also report a clean run; its report alone
  does not make a run pass.
- **profiles without an oracle** (assurance `cooperative`): the unittest child's report decides, but a candidate can
  forge it. The detail line says so, the record stores `assurance=cooperative`, and the final gate requires an accepted
  `code_review` and `qa` on the same revision from Bots outside the executor's Bot and independence group (or an
  approval with `accept_reduced_assurance=true`, labelled REDUCED ASSURANCE).
- exit-code-only profiles are `cooperative` too.

See SECURITY.md for what this does and does not prove.

Every child that runs candidate code (unittest child, oracle runs, exit-code commands) runs inside the bubblewrap
sandbox (read-only `/usr`, fresh writable checkout copy, private `/tmp`, no network, no view of `state/`, the code,
the venv, `/home` or `/workspace`) with a scrubbed environment (no `OMO_*`, nothing secret in env, argv or fds). If
bwrap is unavailable verification fails closed (`no sandbox available`); `doctor` shows `candidate_sandbox`. Trusted
files (code, config, venv) are hashed before and after; any change fails the run with `TAMPER` and a `tamper` event.
Migration v3 adds `verifications.assurance`, v4 adds `verifications.sandbox` and `tamper_json` (auto-applied with a
backup on the next open). A missing base revision fails closed.
`./omg doctor` lists the usable profiles.

## 10. Backups and migrations
- `./omg backup --out /path/file.sqlite3` uses the SQLite backup API and an integrity check.
- `./omg migrate --dry-run`, then `./omg migrate`. Migrate takes an automatic backup first when the DB is not
  empty. Migrations are versioned and checksummed.
- `./omg restore FILE` needs a TTY. Stop all omo activity first. It verifies the backup's integrity before
  swapping it in, and keeps the old DB.

## 11. Failed / dead-letter dispatches
- `status` shows the dispatch `status`, `http_status` and `last_error` (redacted).
- `failed` rows are permanent: 401/403/404/410, or retries exhausted.
- Fix the cause, then run `./omg resume JOB` (add `--grant-repair-cycles N` when the repair budget is exhausted).
  Then run `./omg reconcile JOB`.

## 11b. Cutover and rollback
See `docs/MIGRATION.md` (Cutover and rollback). The live install is still `/workspace/omo` with connector `user-omo` and `omo-bus-*` routines. Moving that checkout, re-registering MCP, and renaming those routines are cutover steps and are not done here. To roll code/DB back: stop omg/omo activity, `./omg restore state/backups/pre-migrate-vN-<ts>.sqlite3` (`omoctl restore` is the same command), keep
`state/secrets/hooks.json` at 0600, restart the MCP server process after a code rollback, and **do not delete** Bots or
routines. Filesystem backups do not restore Grok Bot conversations or agent memory. Uninstall (§12) is a
separate destructive path.

## 12. Cancel and uninstall
- `./omg cancel JOB --reason "..."` asks for TTY confirmation. Nothing is deleted. Worktrees and branches in user
  repos are kept for inspection. Remove them yourself with
  `git worktree remove <path>` and `git branch -D omg/<id>` (older jobs may still be `omo/<id>`) only when you want to.
- Uninstall (destructive; not part of the rename):
  1. Remove the MCP registration. On the live host today that registration is `user-omo`.
  2. Disable or delete the webhook routines in the Grok Bot UI. Live routines may still be named `omo-bus-*` / `omo-reconcile`; this repo's files are `omg-bus-*` / `omg-reconcile`.
  3. Optionally run `omg export` for jobs you want to keep.
  4. Delete the checkout (`/workspace/omo` until it is moved, `/workspace/omg` after).

  User repositories are never touched by the uninstall. Check that no worktree you need lives under `jobs/`
  (fixtures only).

## 13. Watchdog (host service)

Reconcile normally runs only when a Bot routine calls it, and that routine is not a 24/7 process. The watchdog is a
long-running `omg watchdog run` loop in this checkout's venv. It does not need systemd or cron: PID 1 on this host is
tini, there is no user bus, and there is no crontab. The process supervises its own loop. `start` daemonizes that
loop. `ensure` is what a coarse external backstop calls after a reboot.

The flag is `features.watchdog` in the policy file this checkout loads (`config/policy.json`, or `OMG_CONFIG_DIR`).
It defaults to `off`. Do not commit that file from a live host. Other feature defaults are unchanged.

| Mode | What a tick does |
|---|---|
| `off` | Writes a heartbeat. Does not reconcile, collect, detect, or wake. |
| `shadow` | Reconcile, then `heal collect` (which still obeys `features.healing`), then stall records. No stall wakes. An unchanged heal corpus does not insert another snapshot. |
| `on` | Same as `shadow`, and wakes a stalled role when that role has a hook in the secrets store. |

Thresholds (policy keys, code defaults):

| Key | Default | Meaning |
|---|---|---|
| `watchdog_interval_seconds` | 60 | Sleep between ticks. `--interval` on `run` / `start` / `ensure` overrides it for that process. |
| `stall_awaiting_resume_seconds` | 600 | `awaiting_resume` older than this is a stall. |
| `lease_seconds` | 1800 | Every other open task or dispatch. A `working` task with an unexpired lease is not a stall. |
| `watchdog_wake_cap` | 3 | Stall wakes recorded per task. Further ticks record one `stall_wake_capped` and do not POST. |
| `backoff_base_seconds`, `backoff_cap_seconds` | 30, 1800 | Wait before the next wake of the same task: base, then double, until the cap. |
| `watchdog_stale_intervals` | 3 | Doctor calls the heartbeat stale after this many intervals. |
| `watchdog_log_max_bytes`, `watchdog_log_backups` | 1048576, 3 | `state/logs/watchdog.log` rotation. |

A wake is a POST through the same transport the dispatcher uses, with the task's current `dispatch_id`, so a claim
still matches. A queued task is handed back to the scheduler, which still refuses it while a dependency is unfinished
or the job is waiting for approval. Backoff, the per-task cap, and an in-flight webhook row stop a second POST. Events are
`stall_detected`, `stall_no_hook`, `stall_wake`, and `stall_wake_capped`. They do not contain webhook URLs, keys, or
headers.

New Hephaestus work stays on the local `awaiting_resume` channel unless the binding is enabled, has a routine id,
is verified, and a hook is stored. A hook by itself does not change that, in any watchdog mode. A stall with no hook
records `stall_no_hook` and is not POSTed. A stored hook lets the watchdog wake a task that is already parked; the
row stays `awaiting_resume` until something claims that same `dispatch_id`.

`omg doctor` reports the flag. `off` passes. `shadow` or `on` passes only while the process is alive and the
heartbeat is fresh; otherwise the check is `stale` and doctor exits 8. `omg watchdog status` prints the same facts
and exits 3 when the process is not running.

```bash
# edit the host policy (not a committed file): "watchdog": "shadow" or "on" inside features
cd /workspace/omg
./omg watchdog run                 # foreground loop; leave it running
./omg watchdog start               # same loop, daemonized (pidfile + lock under state/watchdog/)
./omg watchdog status
./omg watchdog stop
./omg watchdog ensure              # start only if the lock is not held; recovers a stale pidfile
```

`start` is idempotent: a second start while the lock is held does not spawn another process. A pidfile whose pid is
dead is replaced. Logs are `state/logs/watchdog.log` (rotated, mode 0600). The heartbeat is
`state/watchdog/heartbeat.json`.

Nothing respawns the daemon when the host reboots. Point whatever low-frequency backstop you have at `ensure`. This
host has no cron and no systemd, so the backstop has to be something you already run after boot (a login script, a
manual check, another machine). It is safe to call on a timer of any coarse period: if the watchdog is alive,
`ensure` exits 0 without starting a second copy.

```bash
# after a host restart, from the checkout the daemon should run in:
/workspace/omg/omg watchdog ensure
```

The live checkout is still `/workspace/omo` until cutover. Use that directory, and `omoctl`, until the move. `ensure`
does not rotate webhook keys and does not edit the policy file.

`omg heal collect` (and each watchdog tick that is allowed to collect) writes a snapshot only when the repair-item
set changed. The same set updates `seen_count` and `last_seen_at` on the latest snapshot. The tick log says
`heal_collect=written` or `heal_collect=unchanged`. Snapshots already duplicated before schema v7 stay until an
operator collapses them. Migrate does not delete them, and the watchdog does not either.

```bash
./omg migrate
./omg heal prune-duplicates            # dry-run; prints how many consecutive duplicates would go
./omg heal prune-duplicates --apply    # keep the first of each run, sum seen_count, delete the rest
```

## Troubleshooting
| Symptom | Cause / action |
|---|---|
| Webhook returned `200` but the task was never claimed | 200 only means accepted. Check that the routine run started and that the Bot has the `omg` MCP (live connector may still be `user-omo` until re-registered). `reconcile` re-wakes after `rewake_after_seconds`, at most `max_rewakes` times, then blocks with "never claimed". Check the routine instructions, then `resume` |
| Missing MCP (`omg.claim` unknown in the routine) | Register the command server (§2) and confirm it in that Bot. `./omg doctor` checks the server locally |
| Paused or deleted routine | HTTP 404/410 means "routine missing, paused or disabled". The task blocks with no retries. Re-enable the routine, re-bind if its id changed, then `resume` |
| Changed or wrong key | HTTP 401/403 means "webhook key rejected". Run `hook set ROLE`, then `resume` |
| Exhausted retry budget | The dispatch becomes `failed` after `dispatch_max_retries`. Repeated 429 means the platform rate limit: wait, then `resume`. Lower `per_bot_hourly_dispatch_limit` if needed |
| Repair budget exhausted (3 cycles) | The job is `blocked` with each cycle's diagnostics. `resume JOB --grant-repair-cycles 1` only after reading why |
| `dispatch deferred: no enabled role binding` / `bot_busy` | Bind or verify the role, or wait for the shared Bot to finish (per-Bot serialization) |
| Doctor shows "NOT OPERATIONAL" | Expected while status is PARTIALLY INSTALLED / NOT OPERATIONAL. Live §10.20–§10.22 passed on DB evidence; routine receipts and other gaps remain (README, `docs/MIGRATION.md`). Doctor OK is not OPERATIONAL |
| MCP tool returns `stale_server` | The omo code or config on disk changed after this MCP server process started (it fingerprints `oh_my_grok/**/*.py` and the config dir). Restart the omo MCP server (reload the connector) and retry. This exists because a stale server once ran old verifier code against a new child script |
| `webhook for ROLE not configured` while `hook list` says configured | Can no longer happen: dispatch, `roles list` and `hook list` all read `state/secrets/hooks.json`. `hooks_meta` is only an audit trail |
