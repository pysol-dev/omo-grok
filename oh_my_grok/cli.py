"""omg: operator CLI. Shares the Engine with the MCP server (no duplicated workflow logic).

Exit codes (stable): 0 ok | 1 internal error | 2 invalid input | 3 not found | 4 conflict | 5 gate refused |
6 integrity failure | 7 aborted (no human confirmation / no TTY) | 8 doctor found problems | 9 test not run / failed
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import __version__, db, sandbox
from .config import TEMPLATE_MARKERS, load_policy, load_verifier_profiles
from .errors import OmgError, ValidationError
from .hooks import _check_perms, hook_status, load_hooks, set_hook, validate_url
from .paths import CODE_ROOT, get_paths
from .redact import redact, redact_obj
from .roster import CLASSES, INTENTS, validate_scope
from .states import ROLES
from . import verifier

EXIT_OK, EXIT_INTERNAL, EXIT_ABORTED, EXIT_DOCTOR, EXIT_TEST = 0, 1, 7, 8, 9


def _out(args, data, human: str | None = None):
    data = redact_obj(data)
    if getattr(args, "json", False) or human is None:
        print(json.dumps(data, indent=2, sort_keys=True, default=str))
    else:
        print(redact(human))


def _engine():
    from .engine import Engine
    return Engine()


def _confirm(prompt: str, expect: str) -> bool:
    """Interactive human confirmation. Requires a real TTY on stdin; never accepts piped input."""
    if not sys.stdin.isatty():
        print("refused: this action requires an interactive terminal (TTY) confirmation", file=sys.stderr)
        return False
    sys.stderr.write(prompt)
    sys.stderr.flush()
    ans = sys.stdin.readline().strip()
    return ans == expect


def cmd_mcp_command(args) -> int:
    """The exact, absolute command to register as the command-based `omg` MCP app (computed, never stored)."""
    from .paths import mcp_command
    print(mcp_command())
    return 0


# ---------------------------------------------------------------- doctor / migrate
def cmd_doctor(args) -> int:
    paths = get_paths()
    checks = []

    def add(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    add("python>=3.11", sys.version_info >= (3, 11), sys.version.split()[0])
    try:
        import importlib
        from importlib.metadata import version
        importlib.import_module("mcp")
        add("mcp_sdk_importable", True, f"mcp=={version('mcp')}")
        mod = importlib.import_module("mcp.server.mcpserver")
        add("mcp_server_api", hasattr(mod, "MCPServer"), "mcp.server.mcpserver.MCPServer")
    except Exception as e:  # pragma: no cover
        add("mcp_sdk_importable", False, str(e))
    try:
        from .mcp_server import TOOL_NAMES, server
        import asyncio
        names = [t.name for t in asyncio.run(server.list_tools())]
        add("mcp_tools_exact", sorted(names) == sorted(TOOL_NAMES), ",".join(names))
        forbidden = {"approve", "ship", "mark_done", "shell", "secret", "exec"} & set(names)
        add("no_privileged_mcp_tools", not forbidden, ",".join(sorted(forbidden)))
    except Exception as e:
        add("mcp_server_loads", False, redact(str(e)))
    lock = CODE_ROOT / "requirements.lock"
    add("requirements_lock_present", lock.exists(), str(lock))
    try:
        paths.ensure()
        conn = db.connect(paths.db_path)
        pend = db.pending_migrations(conn) if db.current_version(conn) else db.MIGRATIONS
        add("db_reachable", True, str(paths.db_path))
        add("db_journal_wal", conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal")
        add("db_foreign_keys", conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1)
        add("db_integrity", conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
        add("db_migrations_current", not pend, f"version={db.current_version(conn)} latest={db.LATEST_VERSION}"
            + (" (run omg migrate)" if pend else ""))
        conn.close()
    except Exception as e:
        add("db_reachable", False, redact(str(e)))
    for d in (paths.state_dir, paths.secrets_dir):
        if d.exists():
            add(f"perms_0700:{d.name}", (d.stat().st_mode & 0o077) == 0, oct(d.stat().st_mode & 0o777))
    if paths.db_path.exists():
        add("perms_db_0600", (paths.db_path.stat().st_mode & 0o077) == 0)
    if paths.hooks_path.exists() or paths.hooks_path.is_symlink():
        try:
            _check_perms(paths)
            add("hooks_file_0600", True)
        except OmgError as e:
            add("hooks_file_0600", False, e.message)
    try:
        load_policy(paths.config_dir)
        add("policy_valid", True)
    except OmgError as e:
        add("policy_valid", False, e.message)
    profs = load_verifier_profiles(paths.config_dir)
    usable = []
    for name, prof in profs.items():
        probs = verifier.preflight(name, prof)
        if not probs:
            usable.append(name)
        elif not any(marker in json.dumps(prof) for marker in TEMPLATE_MARKERS):
            add(f"verifier_profile:{name}", False, "; ".join(probs))
    add("verifier_profiles_usable", bool(usable), ",".join(usable) or "none (template profiles fail closed)")
    add("git_available", shutil.which("git") is not None)
    sb = sandbox.probe()  # candidate code never runs without it; verification fails closed
    add("candidate_sandbox", sb.ok, f"{sb.mechanism}: {sb.detail}")
    lsp_info = {}
    try:
        from .lsp import profiles as lsp_profiles
        from .lsp import runner as lsp_runner
        cfg = lsp_profiles.load(paths.config_dir)
        lsp_info = lsp_runner.tool_status(cfg)
        pol = load_policy(paths.config_dir)
        needed = pol["features"].get("lsp", "off") != "off"
        add("lsp_config_valid", True, ",".join(sorted(lsp_info)))
        missing = {n: v["missing"] for n, v in lsp_info.items() if not v["present"]}
        if needed:
            add("lsp_tools_present", not missing, "; ".join(f"{n}: {m}" for n, m in missing.items())
                + (" (run scripts/bootstrap.sh)" if missing else ""))
    except OmgError as e:
        add("lsp_config_valid", False, e.message)
    try:
        from . import watchdog
        wd = watchdog.status(paths)
        add("watchdog", wd["ok"], wd["detail"])
    except Exception as ex:  # noqa: BLE001 - doctor reports the failure instead of crashing
        wd = None
        add("watchdog", False, redact(str(ex))[:300])
    # informational (do not fail doctor): live wiring is the operator's job
    info = {"hooks_configured": hook_status(paths), "lsp_tools": lsp_info,
            "features_default": load_policy(paths.config_dir)["features"]}
    if wd is not None:
        info["watchdog"] = {k: wd[k] for k in ("alive", "pid", "mode", "stale", "heartbeat_age_seconds", "detail")}
    try:
        e = _engine()
        info["bindings"] = [{k: b[k] for k in ("role", "bot_name", "routine_id", "verified_at")}
                            for b in e.list_bindings()]
        e.close()
    except Exception as ex:
        info["bindings_error"] = redact(str(ex))
    ok = all(c["ok"] for c in checks)
    try:
        e = _engine()
        op = e.operational_state()
        e.close()
    except Exception as ex:  # pragma: no cover
        op = {"state": "NOT OPERATIONAL: evidence could not be read (" + redact(str(ex))[:100] + ")", "criteria": {}}
    info["operational_criteria"] = op["criteria"]
    data = {"ok": ok, "version": __version__, "checks": checks, "info": info, "live_status": op["state"]}
    lines = [f"{'PASS' if c['ok'] else 'FAIL'}  {c['check']}  {c['detail']}" for c in checks]
    lines.append("hooks configured: " + ", ".join(f"{r}={v}" for r, v in info["hooks_configured"].items()))
    lines.append(data["live_status"])
    lines.append("doctor: " + ("OK" if ok else "PROBLEMS FOUND"))
    _out(args, data, "\n".join(lines))
    return EXIT_OK if ok else EXIT_DOCTOR


def cmd_migrate(args) -> int:
    paths = get_paths()
    paths.ensure()
    conn = db.connect(paths.db_path)
    cur = db.current_version(conn)
    if args.dry_run:
        todo = db.migrate(conn, dry_run=True)
        _out(args, {"current": cur, "pending": todo, "dry_run": True},
             f"current schema v{cur}; pending: {todo or 'none'} (dry run, nothing changed)")
        return EXIT_OK
    bk = None
    if cur and db.pending_migrations(conn):
        bk = db.backup(conn, paths.backups_dir / f"pre-migrate-v{cur}-{int(time.time())}.sqlite3")
    done = db.migrate(conn)
    _out(args, {"previous": cur, "applied": done, "current": db.current_version(conn), "backup": bk and str(bk)},
         f"applied {done or 'nothing'}; schema now v{db.current_version(conn)}" + (f"; backup {bk}" if bk else ""))
    return EXIT_OK


def cmd_backup(args) -> int:
    e = _engine()
    p = db.backup(e.conn, Path(args.out))
    _out(args, {"backup": str(p)}, f"backup written (integrity ok): {p}")
    return EXIT_OK


def cmd_restore(args) -> int:
    paths = get_paths()
    if not _confirm(f"Restore {args.src} over {paths.db_path}? Stop all omg processes first. Type 'restore': ",
                    "restore"):
        return EXIT_ABORTED
    if paths.db_path.exists():
        conn = db.connect(paths.db_path)
        db.backup(conn, paths.backups_dir / f"pre-restore-{int(time.time())}.sqlite3")
        conn.close()
    db.restore(Path(args.src), paths.db_path)
    _out(args, {"restored": str(args.src)}, f"restored {args.src}")
    return EXIT_OK


# ---------------------------------------------------------------- job commands
def cmd_status(args) -> int:
    e = _engine()
    s = e.status(args.job)
    if args.json:
        _out(args, s)
        return EXIT_OK
    if args.job:
        lines = [f"job {s['job_id']}  phase={s['phase']}  mode={s['mode']}",
                 f"  next: {s['next_action']}"]
        if s.get("WARNING"):
            lines.insert(0, f"!!! {s['WARNING']} !!!")
        if s.get("blocked_reason"):
            lines.append(f"  blocked: {s['blocked_reason']}")
        if s.get("plan"):
            lines.append(f"  plan: {s['plan']['plan_hash']} ({s['plan']['review_status']})")
        if s.get("approval"):
            lines.append(f"  approval: {s['approval']['label']}")
        for t in s["tasks"]:
            d = t["dispatch"] or {}
            lines.append(f"  - {t['kind']:<12} {t['role']:<14} {t['status']:<16} cycle={t['cycle']} "
                         f"attempt={t['attempt_no']} dispatch={d.get('status', '-')}"
                         + (f"  [{t['block_reason']}]" if t["block_reason"] else ""))
        for g in s["gates"]:
            lines.append(f"  gate {g['revision'][:12]}: passed={bool(g['passed'])} assurance={g['assurance']}"
                         + ("  !!! REDUCED ASSURANCE !!!" if g.get("reduced_assurance") else ""))
        _out(args, s, "\n".join(lines))
    else:
        lines = [f"schema v{s['schema_version']}"]
        for j in s["jobs"]:
            lines.append(f"{j['job_id']}  {j['phase']:<18} {j['mode']:<9} {j['goal'][:60]!r}")
        lines.append("bindings: " + ", ".join(f"{b['role']}={'bound' if b['bound'] else '-'}"
                                              f"{'/verified' if b['verified_at'] else ''}"
                                              f"{'/hook' if b['webhook_configured'] else ''}" for b in s["bindings"]))
        _out(args, s, "\n".join(lines))
    return EXIT_OK


def _load_scope(path: str) -> dict:
    """Same attestation the MCP submit tool accepts: a complete scope object, no extra keys."""
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        raise ValidationError("scope file must be a JSON object") from None
    return validate_scope(raw)


def cmd_submit(args) -> int:
    goal = Path(args.goal_file).read_text()
    meta = {}
    if args.criteria_file:
        meta = json.loads(Path(args.criteria_file).read_text())
    # real repositories default to plan_only; implement must be explicit (and the repo allowlisted)
    mode = "fixture" if args.fixture else ("implement" if args.implement else "plan_only")
    key = args.idempotency_key or f"cli:{os.getpid()}:{time.time_ns()}"
    scope = _load_scope(args.scope_file) if args.scope_file else None
    e = _engine()
    try:
        r = e.submit(goal, key, repo=args.repo, mode=mode, constraints=meta.get("constraints"),
                     acceptance_criteria=meta.get("acceptance_criteria"), verifier_profile=args.verifier_profile,
                     actor="omg", intent=args.intent, roster_class=args.roster_class, scope=scope)
    finally:
        e.close()
    if r.get("action") == "answer_directly":
        _out(args, r, "explanation: no job created; answer the user directly")
        return EXIT_OK
    extra = f" intent={r['intent']} roster={r['roster_class']}" if r.get("intent") else ""
    _out(args, r, f"job {r['job_id']} {'created' if r['created'] else 'already exists'} phase={r['phase']} "
                  f"mode={r['mode']}{extra}")
    return EXIT_OK


def cmd_plan_show(args) -> int:
    e = _engine()
    p = e.plan_show(args.job)
    if args.json or not p["current"]:
        _out(args, p, None if args.json else "no plan revision yet")
        return EXIT_OK
    c = p["current"]
    human = (f"job {p['job_id']} phase={p['phase']}\nplan revision {c['revision_id']}\nplan hash: {c['plan_hash']}\n"
             f"momus: {c['review_status']}" + (f" ({c['momus_review']['verdict']})" if c["momus_review"] else "")
             + "\n" + "-" * 72 + "\n" + c["content"] + "\n" + "-" * 72
             + (f"\nto approve: {c['approve_command']}" if c["approve_command"] else ""))
    _out(args, p, human)
    return EXIT_OK


def cmd_approve(args) -> int:
    e = _engine()
    p = e.plan_show(args.job)
    c = p["current"]
    if not c or c["plan_hash"] != args.plan_hash:
        print("refused: --plan-hash does not match the current plan revision", file=sys.stderr)
        return 5
    print(c["content"], file=sys.stderr)
    print("\nSOFT APPROVAL: this is a local workflow gate on a shared account, NOT a security boundary.\n"
          f"scope: job={args.job} plan_hash={args.plan_hash} allow_edit={not args.no_edit} "
          f"accept_reduced_assurance={args.accept_reduced_assurance} production_merge_or_deploy=False",
          file=sys.stderr)
    if not _confirm("Type the first 12 characters of the plan hash to approve: ", args.plan_hash[:12]):
        print("approval NOT recorded", file=sys.stderr)
        return EXIT_ABORTED
    actor = f"human@tty:{os.environ.get('USER', 'unknown')}"
    r = e.approve(args.job, args.plan_hash, actor=actor, evidence=f"interactive TTY confirmation via omg on "
                  f"{os.ttyname(sys.stdin.fileno())}", allow_edit=not args.no_edit,
                  accept_reduced_assurance=args.accept_reduced_assurance)
    _out(args, r, f"SOFT approval {r['approval_id']} recorded; implementation_started={r['implementation_started']}")
    return EXIT_OK


def cmd_deny(args) -> int:
    e = _engine()
    r = e.deny(args.job, args.reason, actor=f"human:{os.environ.get('USER', 'unknown')}")
    _out(args, r, f"denied; job phase={r['phase']}")
    return EXIT_OK


def cmd_cancel(args) -> int:
    if not _confirm(f"Cancel job {args.job}? Nothing is deleted. Type 'cancel': ", "cancel"):
        return EXIT_ABORTED
    e = _engine()
    r = e.cancel(args.job, args.reason, actor=f"human:{os.environ.get('USER', 'unknown')}", confirmed=True)
    _out(args, r, f"job phase={r['phase']}")
    return EXIT_OK


def cmd_resume(args) -> int:
    e = _engine()
    r = e.resume(args.job, actor="omg", grant_repair_cycles=args.grant_repair_cycles)
    _out(args, r, f"resumed; phase={r['phase']} requeued={r['requeued_tasks']}")
    return EXIT_OK


def cmd_reconcile(args) -> int:
    e = _engine()
    r = e.reconcile(args.job)
    _out(args, r, " ".join(f"{k}={v}" for k, v in r.items()))
    return EXIT_OK


def cmd_export(args) -> int:
    e = _engine()
    r = e.export(args.job, Path(args.out))
    _out(args, r, f"exported to {r['path']} (artifacts={r['artifacts']}, integrity_ok={r['integrity_ok']})")
    return EXIT_OK if r["integrity_ok"] else 6


# ---------------------------------------------------------------- hooks / roles
HOOK_PROMPT_ATTEMPTS = 3


def _url_problem(clean: str, removed: bool) -> str | None:
    from .hooks import url_diagnostic
    try:
        validate_url(clean)
        return None
    except OmgError as e:
        return f"{e.message} ({url_diagnostic(clean, removed)}; the value itself is not shown)"


def _key_problem(clean: str, removed: bool) -> str | None:
    from .hooks import validate_key
    p = validate_key(clean)
    return None if p is None else f"{p} (non_printable_or_paste_markers_removed={removed}; key not shown)"


def _prompt_hidden(prompt: str, problem) -> str | None:
    """Hidden prompt with sanitizing (bracketed paste, control chars, whitespace, one pair of quotes/<>) and up to
    HOOK_PROMPT_ATTEMPTS tries. Diagnostics never include the value."""
    from .hooks import sanitize_input
    for attempt in range(1, HOOK_PROMPT_ATTEMPTS + 1):
        try:
            raw = getpass.getpass(prompt)
        except EOFError:
            raw = ""
        clean, removed = sanitize_input(raw)
        why = problem(clean, removed)
        if why is None:
            return clean
        left = HOOK_PROMPT_ATTEMPTS - attempt
        print(f"invalid input: {why}" + (f"; try again ({left} left)" if left else "; giving up"), file=sys.stderr)
    return None


def cmd_hook_set(args) -> int:
    if args.role not in ROLES:
        print(f"unknown role {args.role}", file=sys.stderr)
        return 2
    url = _prompt_hidden(f"webhook URL for {args.role} (input hidden): ", _url_problem)
    if url is None:
        return 2
    key = _prompt_hidden(f"webhook Bearer key for {args.role} (input hidden): ", _key_problem)
    if key is None:
        return 2
    paths = get_paths()
    set_hook(paths, args.role, url, key)
    e = _engine()
    e.mark_hook_configured(args.role, True)
    _out(args, {"role": args.role, "configured": True}, f"webhook for {args.role} stored (0600); value not shown")
    return EXIT_OK


def cmd_hook_serve(args) -> int:
    """Local-only masked web form (127.0.0.1, random port, per-run session token) for GUIs that cannot paste into a
    terminal. Writes the URL only to the URL file (0600) unless --print-url; stops on Finish, idle timeout, Ctrl-C or
    SIGTERM (URL file and known redirect logs are removed)."""
    from .hook_form import URL_FILE, HookFormServer
    paths = get_paths()
    # Known redirect-log locations (RUNBOOK recipe + legacy /tmp path from earlier drafts).
    cleanup = [paths.logs_dir / "hook_serve.log", Path("/tmp/omg_hook_serve.log"),
               Path("/tmp/omo_hook_serve.log"), Path("/tmp/omo_hook_form_url")]
    srv = HookFormServer(paths, _engine, idle_seconds=args.idle_minutes * 60, port=args.port,
                         url_file=Path(args.url_file) if args.url_file else URL_FILE,
                         cleanup_paths=cleanup)
    srv.arm_signal_handlers()  # before publishing the URL file, so SIGTERM during startup still cleans up
    srv.write_url_file()  # before announcing it, so a reader of the file never races the server start
    if args.print_url:
        print(f"omg webhook setup form (local only, per-run session token): {srv.url}", flush=True)
    print(f"omg webhook setup form URL written to {srv.url_file} (0600; not printed, use --print-url to show it). Stops on 'Finish', idle timeout, Ctrl-C or SIGTERM "
          f"(after {args.idle_minutes:g} idle minutes max). Values are never echoed or logged.", flush=True)
    reason = srv.serve()
    print(f"setup server stopped ({reason})", flush=True)
    return EXIT_OK


def cmd_hook_check(args) -> int:
    paths = get_paths()
    res = {}
    try:
        data = load_hooks(paths)
        res["file_permissions_ok"] = True
    except OmgError as e:
        _out(args, {"file_permissions_ok": False, "error": e.message}, f"FAIL: {e.message}")
        return 6
    roles = [args.role] if args.role else list(ROLES)
    ok = True
    for r in roles:
        h = data.get(r)
        entry = {"configured": bool(h)}
        if h:
            try:
                validate_url(h["url"])
                entry["url_valid"] = True
            except OmgError:
                entry["url_valid"] = False
                ok = False
            entry["key_present"] = bool(h.get("key"))
            if args.probe and entry["url_valid"]:
                entry["tls_connect_ok"] = _probe(h["url"])
                ok = ok and entry["tls_connect_ok"]
        res[r] = entry
    _out(args, res, "\n".join(f"{r}: {v}" for r, v in res.items()))
    return EXIT_OK if ok else 2


def _probe(url: str) -> bool:
    """Harmless connectivity check: TCP(+TLS) handshake only; sends NO HTTP request, so no routine run is triggered."""
    import socket
    import ssl
    from urllib.parse import urlparse
    u = urlparse(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        with socket.create_connection((u.hostname, port), timeout=5) as sock:
            if u.scheme == "https":
                with ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname):
                    pass
        return True
    except OSError:
        return False


def cmd_hook_list(args) -> int:
    st = hook_status(get_paths())
    _out(args, st, "\n".join(f"{r}: {'configured' if v else 'not configured'}" for r, v in st.items()))
    return EXIT_OK


def cmd_roles_list(args) -> int:
    e = _engine()
    b = e.list_bindings()
    _out(args, b, "\n".join(f"{x['role']:<14} {x['bot_name'] or '-':<11} routine={x['routine_id'] or '-'} "
                            f"verified={bool(x['verified_at'])} hook={x['webhook_configured']} "
                            f"group={x['independence_group'] or '-'}" for x in b))
    return EXIT_OK


def cmd_roles_import(args) -> int:
    e = _engine()
    r = e.import_bindings(Path(args.file), provenance=f"import:{args.file}")
    _out(args, r, f"imported {len(r)} UNVERIFIED bindings (bind each with --routine-id ... --verified after testing)")
    return EXIT_OK


def cmd_roles_bind(args) -> int:
    e = _engine()
    r = e.bind_role(args.role, args.bot_id, args.bot_name, routine_id=args.routine_id,
                    routine_name=args.routine_name, enabled=not args.disabled, max_concurrent=args.max_concurrent,
                    independence_group=args.group, provenance=args.provenance or "omg roles bind",
                    verified=args.verified, force=args.force)
    _out(args, r, f"{r['role']} -> {r['bot_name']} v{r['version']} verified={bool(r['verified_at'])}")
    return EXIT_OK


# ---------------------------------------------------------------- tests
def _pytest(suite: str, extra: list[str]) -> int:
    tdir = CODE_ROOT / "tests" / suite
    cmd = [sys.executable, "-m", "pytest", str(tdir), "-q", "-p", "no:cacheprovider", *extra]
    print("running: " + " ".join(cmd), file=sys.stderr)
    return subprocess.call(cmd, cwd=str(CODE_ROOT))


def cmd_test(args) -> int:
    if args.suite in ("unit", "integration"):
        rc = _pytest(args.suite, args.pytest_args or [])
        return EXIT_OK if rc == 0 else EXIT_TEST
    if not args.fixture_only:
        print("refused: live tests run only with --fixture-only (synthetic fixture, no real repo edits)",
              file=sys.stderr)
        return 2
    from .live import run_live_fixture
    res = run_live_fixture(timeout=args.timeout, poll=args.poll)
    _out(args, res, res.get("summary"))
    return EXIT_OK if res.get("result") == "PASSED" else EXIT_TEST


# ---------------------------------------------------------------- adaptive surfaces
def _watchdog_interval(args) -> float | None:
    if args.interval is None:
        return None
    if args.interval <= 0:
        raise ValidationError("--interval must be a positive number of seconds")
    return float(args.interval)


def cmd_watchdog_run(args) -> int:
    from . import watchdog
    res = watchdog.serve(interval=_watchdog_interval(args), once=args.once)
    if res.get("already_running"):
        _out(args, res, f"watchdog already running pid={res.get('pid')}")
        return EXIT_OK
    _out(args, res, f"watchdog stopped after {res.get('ticks')} tick(s)")
    return EXIT_OK


def cmd_watchdog_start(args) -> int:
    from . import watchdog
    res = watchdog.start(interval=_watchdog_interval(args))
    if not res.get("ok"):
        _out(args, res, f"watchdog failed to start: {res.get('error', '')}")
        return EXIT_INTERNAL
    state = "already running" if res.get("already_running") else "started"
    _out(args, res, f"watchdog {state} pid={res.get('pid')}")
    return EXIT_OK


def cmd_watchdog_ensure(args) -> int:
    return cmd_watchdog_start(args)


def cmd_watchdog_stop(args) -> int:
    from . import watchdog
    res = watchdog.stop()
    if not res.get("ok"):
        _out(args, res, "watchdog did not stop")
        return EXIT_INTERNAL
    text = "watchdog already stopped" if res.get("already_stopped") else "watchdog stopped"
    _out(args, res, text)
    return EXIT_OK


def cmd_watchdog_status(args) -> int:
    from . import watchdog
    res = watchdog.status()
    age = res.get("heartbeat_age_seconds")
    age_text = "none" if age is None else f"{age:.0f}s"
    _out(args, res, f"watchdog {res['detail']} mode={res['mode']} alive={res['alive']} "
                    f"pid={res.get('pid')} heartbeat_age={age_text}")
    return EXIT_OK if res["alive"] else 3


def cmd_features(args) -> int:
    from . import features
    pol = load_policy(get_paths().config_dir)
    data = {"configured": pol["features"], "modes": {k: list(v) for k, v in features.FEATURE_MODES.items()},
            "note": "a job freezes the effective set at submit; later changes never affect a running job"}
    if args.job:
        e = _engine()
        data["job"] = e.job_features(args.job)
        e.close()
    _out(args, data, "\n".join([f"{k:<16} configured={pol['features'][k]:<8} modes={'|'.join(m)}"
                                for k, m in features.FEATURE_MODES.items()]
                               + ([f"job {args.job}: {data['job']}"] if args.job else [])))
    return EXIT_OK


def _heal_lines(r) -> str:
    lines = [f"snapshot {r['snapshot_id']}", f"sha256: {r['sha256']}", f"mode: {r['mode']}",
             f"items: {r['item_count']}"]
    if r.get("status") in ("written", "unchanged"):
        lines.append(f"status: {r['status']}")
    if "seen_count" in r:
        lines.append(f"seen: {r['seen_count']}")
    lines += [f"  {it['class']}  {it['job_id']}  {it['sha256']}" for it in r["items"]]
    return "\n".join(lines)


def _prune_lines(r) -> str:
    if r["dry_run"]:
        return (f"dry-run: {r['would_delete']} consecutive duplicate snapshot(s) would be deleted; "
                f"{r['kept_count']} kept")
    return f"applied: deleted {r['deleted']} consecutive duplicate snapshot(s); {r['kept_count']} kept"


def cmd_heal_collect(args) -> int:
    e = _engine()
    try:
        r = e.heal_collect()
    finally:
        e.close()
    _out(args, r, _heal_lines(r))
    return EXIT_OK


def cmd_heal_show(args) -> int:
    e = _engine()
    try:
        r = e.heal_show(args.snapshot)
    finally:
        e.close()
    _out(args, r, _heal_lines(r))
    return EXIT_OK


def cmd_heal_prune(args) -> int:
    e = _engine()
    try:
        r = e.heal_prune_duplicates(apply=bool(args.apply))
    finally:
        e.close()
    _out(args, r, _prune_lines(r))
    return EXIT_OK


def cmd_boulder(args) -> int:
    e = _engine()
    if args.refresh:
        e.project_job(args.job)
    works = [w for w in e.active_work() if w["job_id"] == args.job]
    e.close()
    if not works:
        _out(args, {"job_id": args.job, "active": False}, f"job {args.job} is not active (done, failed or cancelled)")
        return EXIT_OK
    r = works[0]
    _out(args, r, f"work {r['work_id']}  plan {r['plan_name']}  phase={r['phase']}  intent={r['intent']}\n"
                  f"  next: {r['next_action']}\n  boulder: {r['boulder_path']}")
    return EXIT_OK


def cmd_receipts(args) -> int:
    e = _engine()
    rows = e.receipts_for(args.job)
    e.close()
    _out(args, {"job_id": args.job, "receipts": rows},
         "\n".join(f"{r['level']:<18} {r['kind']:<16} {r['status']:<10} rev={str(r['revision'])[:12]:<12} "
                   f"{r['tool']} {r['tool_version'] or ''}" for r in rows) or "no receipts")
    return EXIT_OK


def cmd_docs(args) -> int:
    e = _engine()
    r = e.docs(args.job, args.query, args.library, args.library_id)
    e.close()
    _out(args, r, (r.get("text") or r.get("error", ""))[:4000])
    return EXIT_OK if r.get("ok") else 1


def cmd_attest(args) -> int:
    from .operational import ATTEST_KINDS
    print(f"You are attesting: {args.kind} = {ATTEST_KINDS[args.kind]}", file=sys.stderr)
    print(f"Statement: {args.statement}", file=sys.stderr)
    if not _confirm("Type ATTEST to record this as a human attestation: ", "ATTEST"):
        print("aborted", file=sys.stderr)
        return EXIT_ABORTED
    e = _engine()
    r = e.attest(args.kind, getpass.getuser(), args.statement)
    e.close()
    _out(args, r, f"recorded attestation {args.kind}")
    return EXIT_OK


def _lsp_cfg():
    from .lsp import profiles as lsp_profiles
    return lsp_profiles.load(get_paths().config_dir)


def cmd_lsp_status(args) -> int:
    from .lsp import runner
    cfg = _lsp_cfg()
    ts = runner.tool_status(cfg)
    sb = sandbox.probe()
    data = {"sandbox": {"ok": sb.ok, "detail": sb.detail}, "profiles": ts,
            "code_extensions_without_profile": sorted(
                e for e, lang in cfg["code_extensions"].items()
                if not any(e in p["extensions"] for p in cfg["profiles"].values() if p["enabled"])),
            "note": "presence only; run `omg lsp canary` to prove each server finds a planted defect here"}
    _out(args, data, "\n".join([f"sandbox: {'ok' if sb.ok else 'UNAVAILABLE'} {sb.detail}"]
                               + [f"{n}: {'present' if v['present'] else 'MISSING ' + str(v['missing'])}"
                                  for n, v in ts.items()]
                               + ["uncovered code extensions (fail closed): "
                                  + ", ".join(data["code_extensions_without_profile"])]))
    return EXIT_OK if sb.ok and all(v["present"] for v in ts.values()) else EXIT_DOCTOR


def cmd_lsp_canary(args) -> int:
    import tempfile
    from .lsp import runner
    cfg = _lsp_cfg()
    with tempfile.TemporaryDirectory(prefix="omg-lsp-canary-") as d:
        res = runner.canary_all(cfg, sandbox.probe(), Path(d), args.profile or None)
    ok = bool(res) and all(r["status"] == "ok" for r in res.values())
    _out(args, {"ok": ok, "profiles": res},
         "\n".join(f"{n}: {r['status']}" + (f" {r['server']} mode={r['mode']} codes={r['canary']['bad_codes']}"
                                            if r["status"] == "ok" else f" {r['reason']}: {r['detail']}")
                   for n, r in res.items()))
    return EXIT_OK if ok else EXIT_DOCTOR


def cmd_lsp_check(args) -> int:
    import tempfile
    from .lsp import runner
    cfg = _lsp_cfg()
    with tempfile.TemporaryDirectory(prefix="omg-lsp-check-") as d:
        res = runner.evaluate(Path(args.repo), args.base, args.candidate, cfg, sandbox.probe(), Path(d))
    _out(args, res, f"{res['status']}: new={len(res['new'])} config_violations={res['config_violations']} "
                    f"suppressions={len(res['suppressions'])} reasons={res['reasons']}")
    return EXIT_OK if res["status"] in ("clean", "not_applicable") else EXIT_DOCTOR


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="omg", description="oh-my-grok operator CLI (fallback controls; everyday use is "
                                "talking to Hephaestus). Exit codes: 0 ok, 1 internal, 2 invalid, 3 not found, "
                                "4 conflict, 5 gate refused, 6 integrity, 7 aborted, 8 doctor problems, 9 test failed.")
    p.add_argument("--version", action="version", version=f"omg {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_, json_=True, parent=sub):
        sp = parent.add_parser(name, help=help_, description=help_)
        if json_:
            sp.add_argument("--json", action="store_true", help="machine-readable output")
        sp.set_defaults(fn=fn)
        return sp

    add("doctor", cmd_doctor, "check installation, DB, permissions, MCP SDK and verifier profiles")
    add("mcp-command", cmd_mcp_command, "print the exact MCP registration command for this checkout", json_=False)
    sp = add("migrate", cmd_migrate, "apply schema migrations (auto-backup first)")
    sp.add_argument("--dry-run", action="store_true")
    sp = add("status", cmd_status, "show jobs or one job")
    sp.add_argument("job", nargs="?")
    sp = add("submit", cmd_submit, "submit a job (default plan_only for real repos)")
    sp.add_argument("--goal-file", required=True)
    sp.add_argument("--repo")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--plan-only", action="store_true", help="plan only (default for real repositories)")
    g.add_argument("--implement", action="store_true", help="allow implementation after approval (repo must be "
                   "in policy repo_allowlist)")
    g.add_argument("--fixture", action="store_true", help="synthetic fixture job (creates its own repo)")
    sp.add_argument("--criteria-file", help="JSON {constraints:[], acceptance_criteria:[]}")
    sp.add_argument("--verifier-profile")
    sp.add_argument("--idempotency-key")
    sp.add_argument("--intent", choices=list(INTENTS),
                    help="explanation records a decision and creates no job; investigation is read-only; "
                         "implementation needs --scope-file when adaptive_roster=enforce. "
                         "Omit to keep the original team while the flag is off or shadow")
    sp.add_argument("--roster-class", choices=list(CLASSES),
                    help="implementation only, and only when adaptive_roster=enforce; never below the scope floor")
    sp.add_argument("--scope-file",
                    help="JSON scope attestation (files_estimate, new_dependency, external_api, "
                         "security_sensitive, cross_cutting). Required for implementation when "
                         "adaptive_roster=enforce; unknown keys are rejected")
    plan = sub.add_parser("plan", help="plan commands").add_subparsers(dest="plan_cmd", required=True)
    sp = add("show", cmd_plan_show, "show the current plan revision, hash and Momus review", parent=plan)
    sp.add_argument("job")
    sp = add("approve", cmd_approve, "SOFT human approval of the exact reviewed plan hash (interactive TTY)")
    sp.add_argument("job")
    sp.add_argument("--plan-hash", required=True)
    sp.add_argument("--no-edit", action="store_true", help="approve the plan but do not authorize implementation")
    sp.add_argument("--accept-reduced-assurance", action="store_true",
                    help="allow the final gate when reviewers are not independent of the executor")
    sp = add("deny", cmd_deny, "reject the plan with feedback (creates a new revision, bounded)")
    sp.add_argument("job")
    sp.add_argument("--reason", required=True)
    sp = add("cancel", cmd_cancel, "cancel a job (interactive TTY; nothing deleted)")
    sp.add_argument("job")
    sp.add_argument("--reason", required=True)
    sp = add("resume", cmd_resume, "resume a blocked job after fixing the cause")
    sp.add_argument("job")
    sp.add_argument("--grant-repair-cycles", type=int, default=0)
    sp = add("reconcile", cmd_reconcile, "recover leases/dispatches, re-wake unclaimed tasks, flush outbox")
    sp.add_argument("job", nargs="?")
    sp = add("export", cmd_export, "write a sanitized evidence pack")
    sp.add_argument("job")
    sp.add_argument("--out", required=True)
    sp = add("backup", cmd_backup, "consistent SQLite backup (backup API + integrity check)")
    sp.add_argument("--out", required=True)
    sp = add("restore", cmd_restore, "restore a backup (interactive TTY; stop omg processes first)")
    sp.add_argument("src")
    hook = sub.add_parser("hook", help="webhook secrets").add_subparsers(dest="hook_cmd", required=True)
    sp = add("set", cmd_hook_set, "store URL+key for ROLE via hidden prompts (never echoed)", parent=hook)
    sp.add_argument("role", choices=ROLES)
    sp = add("check", cmd_hook_check, "redacted config check; --probe does a TLS handshake only (no POST)",
             parent=hook)
    sp.add_argument("role", nargs="?", choices=ROLES)
    sp.add_argument("--probe", action="store_true")
    add("list", cmd_hook_list, "role -> configured/unconfigured only", parent=hook)
    sp = add("serve", cmd_hook_serve, "local-only masked web form for URL+key entry (127.0.0.1, per-run session token)",
             parent=hook)
    sp.add_argument("--port", type=int, default=0, help="default: random free port")
    sp.add_argument("--idle-minutes", type=float, default=30.0)
    sp.add_argument("--url-file", default=None, help="default: /tmp/omg_hook_form_url")
    sp.add_argument("--print-url", action="store_true", help="also print the tokenized URL to stdout (off by default)")
    roles = sub.add_parser("roles", help="role -> Bot -> routine bindings").add_subparsers(dest="roles_cmd",
                                                                                           required=True)
    add("list", cmd_roles_list, "show active bindings", parent=roles)
    sp = add("import", cmd_roles_import, "import bindings as UNVERIFIED", parent=roles)
    sp.add_argument("file")
    sp = add("bind", cmd_roles_bind, "create a new binding version", parent=roles)
    sp.add_argument("role", choices=ROLES)
    sp.add_argument("--bot-id", required=True)
    sp.add_argument("--bot-name", required=True)
    sp.add_argument("--routine-id")
    sp.add_argument("--routine-name")
    sp.add_argument("--group", help="independence group (default: bot id)")
    sp.add_argument("--max-concurrent", type=int, default=1)
    sp.add_argument("--verified", action="store_true", help="routine was tested live")
    sp.add_argument("--disabled", action="store_true")
    sp.add_argument("--provenance")
    sp.add_argument("--force", action="store_true")
    wd = sub.add_parser("watchdog", help="host loop for reconcile, heal collect, and stall wakes").add_subparsers(
        dest="watchdog_cmd", required=True)

    def _interval(sp):
        sp.add_argument("--interval", type=float, default=None,
                        help="seconds between ticks (default: policy watchdog_interval_seconds)")

    sp = add("run", cmd_watchdog_run, "foreground loop; this process is the service", parent=wd)
    _interval(sp)
    sp.add_argument("--once", action="store_true", help="run one tick and exit")
    sp = add("start", cmd_watchdog_start, "daemonize the loop (pidfile and lock; idempotent)", parent=wd)
    _interval(sp)
    add("stop", cmd_watchdog_stop, "stop the daemon; a stale pidfile is cleared", parent=wd)
    add("status", cmd_watchdog_status, "report alive or stale from the pidfile and heartbeat", parent=wd)
    sp = add("ensure", cmd_watchdog_ensure, "start the daemon only when it is not alive", parent=wd)
    _interval(sp)
    heal = sub.add_parser("heal", help="project failures into a snapshot (does not change jobs)").add_subparsers(
        dest="heal_cmd", required=True)
    add("collect", cmd_heal_collect, "derive a failure snapshot from the database", parent=heal)
    sp = add("show", cmd_heal_show, "show one failure snapshot (latest if no id is given)", parent=heal)
    sp.add_argument("snapshot", nargs="?")
    sp = add("prune-duplicates", cmd_heal_prune,
             "collapse consecutive identical snapshots (dry-run unless --apply; never automatic)", parent=heal)
    group = sp.add_mutually_exclusive_group()
    group.add_argument("--dry-run", action="store_true", help="report only (the default)")
    group.add_argument("--apply", action="store_true", help="delete the duplicate snapshots")
    sp = add("features", cmd_features, "show feature modes (configured, and frozen into one job)")
    sp.add_argument("job", nargs="?")
    sp = add("boulder", cmd_boulder, "show the active work (plan, phase, next action, sessions); --refresh rewrites .omo/")
    sp.add_argument("job")
    sp.add_argument("--refresh", action="store_true")
    sp = add("receipts", cmd_receipts, "list the engine-held tool receipts of a job")
    sp.add_argument("job")
    sp = add("docs", cmd_docs, "ask the engine to query Context7 for a job (creates a receipt)")
    sp.add_argument("job")
    sp.add_argument("--query", required=True)
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--library")
    g.add_argument("--library-id")
    sp = add("attest", cmd_attest, "record a HUMAN attestation of live evidence (interactive TTY)")
    sp.add_argument("kind", choices=["host_cutover", "live_smoke", "live_e2e"])
    sp.add_argument("--statement", required=True)
    lsp = sub.add_parser("lsp", help="language-server diagnostics gate").add_subparsers(dest="lsp_cmd", required=True)
    add("status", cmd_lsp_status, "sandbox and tool presence, uncovered languages", parent=lsp)
    sp = add("canary", cmd_lsp_canary, "prove each server finds a planted defect on this machine", parent=lsp)
    sp.add_argument("--profile", action="append")
    sp = add("check", cmd_lsp_check, "base->candidate diagnostics delta for a repository", parent=lsp)
    sp.add_argument("--repo", required=True)
    sp.add_argument("--base", required=True)
    sp.add_argument("--candidate", required=True)
    sp = add("test", cmd_test, "run test suites")
    sp.add_argument("suite", choices=["unit", "integration", "live"])
    sp.add_argument("--fixture-only", action="store_true")
    sp.add_argument("--timeout", type=int, default=3600)
    sp.add_argument("--poll", type=int, default=60)
    sp.add_argument("pytest_args", nargs="*")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except OmgError as e:
        if getattr(args, "json", False):
            print(json.dumps(redact_obj(e.to_dict()), sort_keys=True))
        else:
            print(f"error[{e.code}]: {redact(e.message)}", file=sys.stderr)
        return e.exit_code
    except KeyboardInterrupt:
        return EXIT_ABORTED
    except Exception as e:
        print(f"internal error: {redact(str(e))}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
