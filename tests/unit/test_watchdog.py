"""Host watchdog: loop isolation, single instance, stall wakes, redaction, doctor."""
import json
import os
import subprocess
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from helpers import SECRET_KEY  # pyright: ignore[reportImplicitRelativeImport]

from oh_my_grok import db, watchdog
from oh_my_grok.engine import Engine
from oh_my_grok.hooks import set_hook
from oh_my_grok.paths import get_paths
from oh_my_grok.transport import HttpResult

ROOT = Path(__file__).resolve().parents[2]
OMG = str(ROOT / "omg")
NOW = 1_800_000_000.0
HEPHAESTUS = "f497e4a7-5d7d-46e4-829f-b0da987cbac4"
HOOK_URL = "https://wd-secret.invalid/hephaestus/ZZwatchdogPATH"
HOOK_KEY = "hk_WD_SUPERSECRET_0123456789"


def _run(args):
    return subprocess.run([OMG, *args], capture_output=True, text=True, env=os.environ.copy(), timeout=90,
                          check=False)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _policy(feats, **extra):
    path = Path(os.environ["OMG_CONFIG_DIR"]) / "policy.json"
    data = json.loads(path.read_text())
    data["features"] = feats
    data.update(extra)
    path.write_text(json.dumps(data))


def _job(conn, phase="running"):
    jid = str(uuid.uuid4())
    now = db.utcnow()
    conn.execute(
        "INSERT INTO jobs(id,idempotency_key,goal,mode,requirements_json,requirements_hash,phase,"
        "version,policies_json,created_at,updated_at) VALUES (?,?,?,?,?,?,?,1,'{}',?,?)",
        (jid, "k-" + jid, "goal", "fixture", '{"goal":"g"}', "h" * 64, phase, now, now))
    return jid


def _task(conn, job_id, *, role="hephaestus", kind="integrate", status="awaiting_resume"):
    tid = str(uuid.uuid4())
    now = db.utcnow()
    conn.execute(
        "INSERT INTO tasks(id,job_id,kind,role,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
        (tid, job_id, kind, role, status, now, now))
    return tid


def _touch(conn, task_id, ts, **fields):
    cols, args = ["updated_at=?"], [_iso(ts)]
    for key, value in fields.items():
        cols.append(f"{key}=?")
        args.append(value)
    args.append(task_id)
    conn.execute(f"UPDATE tasks SET {', '.join(cols)} WHERE id=?", args)


def _dispatch(conn, job_id, task_id, role, *, now=NOW):
    did = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO dispatch_outbox(id,job_id,task_id,attempt,role,channel,idempotency_key,status,"
        "next_attempt_at,last_error,created_at,updated_at) VALUES (?,?,?,?,?,'local',?,?,?,?,?,?)",
        (did, job_id, task_id, 1, role, "idem-" + did, "accepted", now,
         "local: no verified resume routine; awaiting explicit Hephaestus resumption", _iso(now), _iso(now)))
    conn.execute("UPDATE tasks SET current_dispatch_id=? WHERE id=?", (did, task_id))
    return did


def _park(conn, age, now=NOW):
    jid = _job(conn)
    tid = _task(conn, jid)
    did = _dispatch(conn, jid, tid, "hephaestus", now=now)
    _touch(conn, tid, now - age)
    return jid, tid, did


class Transport:
    """Counts posts. Does not retain the URL or key, so a failed assertion cannot print them."""

    def __init__(self, result=None):
        self.n = 0
        self.bodies = []
        self.result = result if result is not None else HttpResult(200, None, None)

    def __call__(self, url, key, body, ct, rt):
        self.n += 1
        self.bodies.append({"dispatch_id": body.get("dispatch_id"), "task_id": body.get("task_id")})
        return self.result


def _kinds(conn, kind):
    return conn.execute("SELECT data_json FROM events WHERE kind=? ORDER BY id", (kind,)).fetchall()


def _assert_clean(blob: str):
    for needle in (HOOK_URL, HOOK_KEY, "wd-secret.invalid", "ZZwatchdogPATH", "Authorization", "Bearer"):
        if needle in blob:
            raise AssertionError("secret material leaked into watchdog output")


def test_off_skips_the_bus_and_shadow_records_without_waking(omg_home):
    transport = Transport()
    e = Engine(transport=transport)
    try:
        _park(e.conn, 600)
        out = watchdog.tick(e, now=NOW)
        assert out["mode"] == "off"
        assert out["steps"]["reconcile"]["skipped"] is True
        assert transport.n == 0
        assert _kinds(e.conn, "stall_detected") == []
        _policy({"watchdog": "shadow"})
        set_hook(get_paths(), "hephaestus", HOOK_URL, HOOK_KEY)
        out = watchdog.tick(e, now=NOW)
        assert out["mode"] == "shadow"
        assert out["steps"]["stalls"]["shadow"] == 1
        assert out["steps"]["stalls"]["woken"] == 0
        assert transport.n == 0
        assert len(_kinds(e.conn, "stall_detected")) == 1
        assert _kinds(e.conn, "stall_wake") == []
    finally:
        e.close()


def test_shadow_ticks_log_written_then_unchanged_heal_snapshot(omg_home):
    _policy({"watchdog": "shadow", "healing": "shadow"})
    e = Engine()
    try:
        jid = _job(e.conn, phase="done")
        e.conn.execute("UPDATE jobs SET repair_cycles=1 WHERE id=?", (jid,))
        first = watchdog.tick(e, now=NOW)
        second = watchdog.tick(e, now=NOW)
        assert first["steps"]["heal_collect"]["status"] == "written"
        assert first["steps"]["heal_collect"]["written"] is True
        assert second["steps"]["heal_collect"]["status"] == "unchanged"
        assert second["steps"]["heal_collect"]["written"] is False
        assert e.conn.execute("SELECT COUNT(*) FROM failure_snapshots").fetchone()[0] == 1
        assert e.conn.execute("SELECT seen_count FROM failure_snapshots").fetchone()[0] == 2
        log = (get_paths().logs_dir / "watchdog.log").read_text()
        assert "heal_collect=written" in log
        assert "heal_collect=unchanged" in log
    finally:
        e.close()


def test_step_failure_does_not_skip_later_steps(omg_home):
    _policy({"watchdog": "on"})
    e = Engine()
    calls = []

    def broken(job_id: str | None = None, flush: bool = True) -> dict[str, int]:
        del job_id, flush
        calls.append("reconcile")
        raise RuntimeError("reconcile-broke")

    def heal():
        calls.append("heal")
        return {"snapshot_id": "s", "item_count": 0, "mode": "shadow"}

    e.reconcile = broken
    e.heal_collect = heal
    try:
        out = watchdog.tick(e, now=NOW)
    finally:
        e.close()
    assert calls == ["reconcile", "heal"]
    assert out["steps"]["reconcile"]["ok"] is False
    assert "reconcile-broke" in out["steps"]["reconcile"]["error"]
    assert out["steps"]["heal_collect"]["ok"] is True
    assert out["steps"]["stalls"]["ok"] is True
    stored = json.loads(watchdog.heartbeat_path(get_paths()).read_text())
    assert stored["steps"]["reconcile"]["ok"] is False
    assert stored["steps"]["stalls"]["ok"] is True


def test_loop_continues_after_a_tick_exception(omg_home):
    calls = {"n": 0}

    def boom(_engine):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("tick-broke")
        return {"mode": "off", "steps": {}}

    res = watchdog.serve(max_ticks=2, interval=0.01, sleep=lambda _s: None, tick_fn=boom)
    assert res["ok"] is True and res["ticks"] == 2 and calls["n"] == 2


def test_lock_is_single_instance_and_replaces_a_dead_pidfile(omg_home):
    paths = get_paths()
    paths.ensure()
    first = watchdog.InstanceLock(paths)
    second = watchdog.InstanceLock(paths)
    assert first.acquire() is True
    try:
        assert second.acquire() is False
        assert json.loads(watchdog._pid_path(paths).read_text())["pid"] == os.getpid()
        assert watchdog.status(paths)["alive"] is True
    finally:
        first.release()
    assert watchdog.status(paths)["alive"] is False
    watchdog._pid_path(paths).write_text(json.dumps({"pid": 2_100_000_000}))
    assert first.acquire() is True
    try:
        assert json.loads(watchdog._pid_path(paths).read_text())["pid"] == os.getpid()
    finally:
        first.release()


def test_no_hook_records_one_event_and_leaves_awaiting_resume(omg_home):
    _policy({"watchdog": "on"})
    transport = Transport()
    e = Engine(transport=transport)
    try:
        _jid, tid, did = _park(e.conn, 600)
        watchdog.tick(e, now=NOW)
        watchdog.tick(e, now=NOW + 10_000)
        assert transport.n == 0
        rows = _kinds(e.conn, "stall_no_hook")
        assert len(rows) == 1
        body = json.loads(rows[0]["data_json"])
        assert body["role"] == "hephaestus" and body["status"] == "awaiting_resume"
        assert body["dispatch_id"] == did
        task = e._one("SELECT status, current_dispatch_id FROM tasks WHERE id=?", (tid,))
        assert task["status"] == "awaiting_resume" and task["current_dispatch_id"] == did
        channel = e._one("SELECT channel FROM dispatch_outbox WHERE id=?", (did,))["channel"]
        assert channel == "local"
    finally:
        e.close()


def test_wake_backoff_cap_and_same_timestamp_are_idempotent(omg_home):
    _policy({"watchdog": "on"}, watchdog_wake_cap=3)
    transport = Transport()
    e = Engine(transport=transport)
    try:
        _jid, tid, did = _park(e.conn, 600)
        set_hook(get_paths(), "hephaestus", "https://hooks.invalid/hephaestus", SECRET_KEY)
        watchdog.tick(e, now=NOW)
        watchdog.tick(e, now=NOW)
        watchdog.tick(e, now=NOW + 9)
        assert transport.n == 1
        assert transport.bodies[0]["dispatch_id"] == did
        watchdog.tick(e, now=NOW + 10)
        watchdog.tick(e, now=NOW + 30)
        assert transport.n == 3
        watchdog.tick(e, now=NOW + 70)
        watchdog.tick(e, now=NOW + 100_000)
        assert transport.n == 3
        assert len(_kinds(e.conn, "stall_wake")) == 3
        assert len(_kinds(e.conn, "stall_wake_capped")) == 1
        task = e._one("SELECT status FROM tasks WHERE id=?", (tid,))
        assert task["status"] == "awaiting_resume"
    finally:
        e.close()


def test_wake_errors_do_not_leak_hook_material(omg_home):
    _policy({"watchdog": "on"})
    echoed = f"POST {HOOK_URL} failed key={HOOK_KEY} Authorization: Bearer {HOOK_KEY}"
    transport = Transport(HttpResult(None, None, echoed))
    e = Engine(transport=transport)
    try:
        _park(e.conn, 3600)
        set_hook(get_paths(), "hephaestus", HOOK_URL, HOOK_KEY)
        watchdog.tick(e, now=NOW)
        assert transport.n == 1
        blob = (watchdog.heartbeat_path(get_paths()).read_text()
                + (get_paths().logs_dir / "watchdog.log").read_text()
                + " ".join((row["data_json"] or "") for row in e._all("SELECT data_json FROM events")))
        _assert_clean(blob)
        assert len(_kinds(e.conn, "stall_wake")) == 1
    finally:
        e.close()


def test_queued_stall_is_not_dispatched_before_its_dependencies_pass(omg_home):
    _policy({"watchdog": "on"})
    transport = Transport()
    e = Engine(transport=transport)
    try:
        jid = _job(e.conn)
        upstream = _task(e.conn, jid, role="explorer", kind="explore", status="dispatched")
        waiting = _task(e.conn, jid, role="metis", kind="analyze", status="queued")
        e.conn.execute("INSERT INTO task_deps(task_id, depends_on) VALUES (?,?)", (waiting, upstream))
        _touch(e.conn, waiting, NOW - 1800)
        e.bind_role("metis", "41b28a72-3ece-45b9-9008-000f3fce4da7", "Metis", routine_id="routine-metis",
                    routine_name="omg-bus-metis", verified=True, provenance="test")
        set_hook(get_paths(), "metis", "https://hooks.invalid/metis", SECRET_KEY)
        watchdog.tick(e, now=NOW)
        row = e._one("SELECT status, current_dispatch_id FROM tasks WHERE id=?", (waiting,))
        assert row["status"] == "queued" and row["current_dispatch_id"] is None
        assert transport.n == 0
        assert _kinds(e.conn, "stall_wake") == []
    finally:
        e.close()


def test_ready_queued_stall_is_scheduled_when_reconcile_did_not(omg_home):
    _policy({"watchdog": "on"})
    transport = Transport()
    e = Engine(transport=transport)
    e.reconcile = lambda *a, **k: {}
    try:
        jid = _job(e.conn)
        waiting = _task(e.conn, jid, role="executor", kind="implement", status="queued")
        _touch(e.conn, waiting, NOW - 1800)
        e.bind_role("executor", "e3dfae0e-9d90-4358-8e90-2e4c6734b092", "Executor",
                    routine_id="routine-executor", routine_name="omg-bus-executor", verified=True, provenance="test")
        set_hook(get_paths(), "executor", "https://hooks.invalid/executor", SECRET_KEY)
        watchdog.tick(e, now=NOW)
        row = e._one("SELECT status, current_dispatch_id FROM tasks WHERE id=?", (waiting,))
        assert row["status"] == "dispatched" and row["current_dispatch_id"]
        assert transport.n == 1
        assert transport.bodies[0]["task_id"] == waiting
    finally:
        e.close()


def test_queued_stall_during_approval_is_not_dispatched(omg_home):
    _policy({"watchdog": "on"})
    transport = Transport()
    e = Engine(transport=transport)
    try:
        jid = _job(e.conn, phase="awaiting_approval")
        waiting = _task(e.conn, jid, role="executor", kind="implement", status="queued")
        _touch(e.conn, waiting, NOW - 1800)
        e.bind_role("executor", "e3dfae0e-9d90-4358-8e90-2e4c6734b092", "Executor",
                    routine_id="routine-executor", routine_name="omg-bus-executor", verified=True, provenance="test")
        set_hook(get_paths(), "executor", "https://hooks.invalid/executor", SECRET_KEY)
        watchdog.tick(e, now=NOW)
        row = e._one("SELECT status, current_dispatch_id FROM tasks WHERE id=?", (waiting,))
        assert row["status"] == "queued" and row["current_dispatch_id"] is None
        assert transport.n == 0
    finally:
        e.close()


@pytest.mark.parametrize("mode", ["off", "shadow", "on"])
@pytest.mark.parametrize("binding", ["absent", "unverified", "disabled"])
def test_hephaestus_hook_without_a_full_binding_stays_local(omg_home, mode, binding):
    _policy({"watchdog": mode})
    e = Engine()
    try:
        set_hook(get_paths(), "hephaestus", "https://hooks.invalid/hephaestus", SECRET_KEY)
        if binding == "unverified":
            e.bind_role("hephaestus", HEPHAESTUS, "Hephaestus", routine_id="routine-hephaestus",
                        routine_name="omg-bus-hephaestus", verified=False, provenance="test")
        elif binding == "disabled":
            e.bind_role("hephaestus", HEPHAESTUS, "Hephaestus", routine_id="routine-hephaestus",
                        routine_name="omg-bus-hephaestus", enabled=False, verified=True, provenance="test")
        jid = _job(e.conn)
        tid = _task(e.conn, jid, status="queued")
        with db.tx(e.conn):
            assert e._dispatch_task(e._one("SELECT * FROM tasks WHERE id=?", (tid,))) == 1
        row = e._one("SELECT status, current_dispatch_id FROM tasks WHERE id=?", (tid,))
        assert row["status"] == "awaiting_resume" and row["current_dispatch_id"]
        channel = e._one("SELECT channel FROM dispatch_outbox WHERE id=?", (row["current_dispatch_id"],))
        assert channel["channel"] == "local"
    finally:
        e.close()


def test_hephaestus_hook_follows_the_normal_dispatch_path(omg_home):
    e = Engine()
    try:
        jid = _job(e.conn)
        bare = _task(e.conn, jid, status="queued")
        with db.tx(e.conn):
            assert e._dispatch_task(e._one("SELECT * FROM tasks WHERE id=?", (bare,))) == 1
        parked = e._one("SELECT status, current_dispatch_id FROM tasks WHERE id=?", (bare,))
        assert parked["status"] == "awaiting_resume"
        assert e._one("SELECT channel FROM dispatch_outbox WHERE id=?",
                      (parked["current_dispatch_id"],))["channel"] == "local"

        set_hook(get_paths(), "hephaestus", "https://hooks.invalid/hephaestus", SECRET_KEY)
        e.bind_role("hephaestus", HEPHAESTUS, "Hephaestus", routine_id="routine-hephaestus",
                    routine_name="omg-bus-hephaestus", verified=True, provenance="test")
        wired = _task(e.conn, jid, kind="integrate", status="queued")
        # the previous integrate task is still awaiting_resume; dispatch the new queued row
        with db.tx(e.conn):
            assert e._dispatch_task(e._one("SELECT * FROM tasks WHERE id=?", (wired,))) == 1
        sent = e._one("SELECT status, current_dispatch_id FROM tasks WHERE id=?", (wired,))
        assert sent["status"] == "dispatched"
        assert e._one("SELECT channel FROM dispatch_outbox WHERE id=?",
                      (sent["current_dispatch_id"],))["channel"] == "webhook"
    finally:
        e.close()


def test_log_rotates_and_redacts(omg_home):
    from oh_my_grok.config import load_policy
    from oh_my_grok.redact import register_secret
    paths = get_paths()
    paths.ensure()
    policy = load_policy(paths.config_dir)
    policy["watchdog_log_max_bytes"] = 180
    policy["watchdog_log_backups"] = 1
    previous_umask = os.umask(0o022)
    try:
        logger = watchdog.configure_logging(paths, policy, force=True)
        register_secret(HOOK_KEY)
        for i in range(30):
            logger.info("tick %s %s", i, "x" * 30)
        logger.info("transport said %s", HOOK_KEY)
        for handler in logger.handlers:
            handler.flush()
    finally:
        os.umask(previous_umask)
    log_path = paths.logs_dir / "watchdog.log"
    rotated = paths.logs_dir / "watchdog.log.1"
    text = log_path.read_text()
    if rotated.exists():
        text += rotated.read_text()
    else:
        raise AssertionError("watchdog log did not rotate")
    assert log_path.stat().st_mode & 0o777 == 0o600
    assert rotated.stat().st_mode & 0o777 == 0o600
    if HOOK_KEY in text:
        raise AssertionError("secret material leaked into watchdog output")


def test_status_reports_alive_until_the_heartbeat_is_stale(omg_home):
    _policy({"watchdog": "on"})
    paths = get_paths()
    paths.ensure()
    lock = watchdog.InstanceLock(paths)
    assert lock.acquire()
    try:
        watchdog._write_heartbeat(paths, {"unix": 1_000.0, "mode": "on", "interval_seconds": 60, "steps": {}})
        fresh = watchdog.status(paths, now=1_060)
        assert fresh["alive"] is True and fresh["detail"] == "alive" and fresh["ok"] is True
        stale = watchdog.status(paths, now=1_000 + 60 * 3 + 1)
        assert stale["alive"] is True and stale["detail"] == "stale" and stale["stale"] is True
    finally:
        lock.release()


def test_doctor_reports_off_stale_and_alive(omg_home):
    migrated = _run(["migrate"])
    assert migrated.returncode == 0, migrated.stderr
    off = json.loads(_run(["doctor", "--json"]).stdout)
    check = next(c for c in off["checks"] if c["check"] == "watchdog")
    assert off["ok"] is True and check["ok"] is True and check["detail"] == "off"

    _policy({"watchdog": "on"})
    down = json.loads(_run(["doctor", "--json"]).stdout)
    check = next(c for c in down["checks"] if c["check"] == "watchdog")
    assert check["ok"] is False and check["detail"] == "stale"
    assert _run(["doctor", "--json"]).returncode == 8

    paths = get_paths()
    lock = watchdog.InstanceLock(paths)
    assert lock.acquire()
    try:
        watchdog._write_heartbeat(paths, {"unix": time.time(), "mode": "on", "interval_seconds": 60, "steps": {}})
        up = _run(["doctor", "--json"])
        body = json.loads(up.stdout)
        check = next(c for c in body["checks"] if c["check"] == "watchdog")
        assert up.returncode == 0, [c for c in body["checks"] if not c["ok"]]
        assert check["detail"] == "alive" and body["info"]["watchdog"]["alive"] is True
    finally:
        lock.release()


def test_daemon_start_is_idempotent_and_ensure_recovers_a_stale_pidfile(omg_home):
    once = _run(["watchdog", "run", "--once", "--json"])
    assert once.returncode == 0, once.stderr
    beat = json.loads(watchdog.heartbeat_path(get_paths()).read_text())
    assert beat["mode"] == "off" and beat["steps"]["reconcile"]["skipped"] is True

    started = _run(["watchdog", "start", "--interval", "3600", "--json"])
    try:
        assert started.returncode == 0, started.stderr + started.stdout
        first = json.loads(started.stdout)
        assert first["started"] is True and first["pid"]
        again = json.loads(_run(["watchdog", "start", "--json"]).stdout)
        assert again["already_running"] is True and again["pid"] == first["pid"]
        ensured = json.loads(_run(["watchdog", "ensure", "--json"]).stdout)
        assert ensured["already_running"] is True and ensured["pid"] == first["pid"]
        status = _run(["watchdog", "status", "--json"])
        assert status.returncode == 0
        assert json.loads(status.stdout)["alive"] is True
    finally:
        _run(["watchdog", "stop"])

    stopped = _run(["watchdog", "status", "--json"])
    assert stopped.returncode == 3 and json.loads(stopped.stdout)["alive"] is False
    assert json.loads(_run(["watchdog", "stop", "--json"]).stdout)["already_stopped"] is True

    watchdog._pid_path(get_paths()).write_text(json.dumps({"pid": 2_100_000_000}))
    try:
        recovered = json.loads(_run(["watchdog", "ensure", "--interval", "3600", "--json"]).stdout)
        assert recovered["ok"] is True and recovered["pid"] != 2_100_000_000
        assert json.loads(watchdog._pid_path(get_paths()).read_text())["pid"] == recovered["pid"]
    finally:
        _run(["watchdog", "stop"])


def test_negative_interval_is_rejected(omg_home):
    assert _run(["watchdog", "run", "--interval", "0"]).returncode == 2
