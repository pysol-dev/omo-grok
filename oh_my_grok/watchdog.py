"""Host watchdog: a self-supervised loop that reconciles, collects failures, and wakes stalled roles.

There is no systemd unit and no crontab on the host this serves. ``serve`` is the foreground loop.
``start`` daemonizes it with a pidfile and an exclusive lock under the state directory. ``ensure`` is the
call a coarse external backstop makes after a restart: it starts the loop only when it is not already alive.

``features.watchdog`` gates the loop. ``off`` writes a heartbeat and does not touch the bus. ``shadow`` runs
reconcile, heal collect, and stall records, and does not wake. ``on`` also wakes.

Wake policy, per stalled task, only when the flag is ``on`` and the role has a hook in the secrets store:
backoff from ``backoff_base_seconds`` / ``backoff_cap_seconds``, at most ``watchdog_wake_cap`` recorded wakes,
and no second POST while a webhook dispatch is still in flight. A role with no hook keeps its current row
(Hephaestus stays ``awaiting_resume``) and gets one ``stall_no_hook`` event. URLs, keys, and headers are never
written to events, the heartbeat, or the log.
"""
from __future__ import annotations

import fcntl
import json
import logging
import logging.handlers
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import db, features, healing
from .config import load_policy
from .engine import PAYLOAD_SCHEMA_VERSION, Engine
from .errors import GateRefused, OmgError
from .hooks import hook_status
from .paths import CODE_ROOT, Paths, get_paths
from .redact import redact, redact_obj

log = logging.getLogger("oh_my_grok.watchdog")
_configured_log_path: str | None = None

_HELD: dict[str, int] = {}
_OPEN_WAKE = ("pending", "sending", "retry_wait")


class _RedactFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return redact(super().format(record))


class _PrivateLogHandler(logging.handlers.RotatingFileHandler):
    """Rotating log that stays mode 0600. ``open`` applies the process umask, so 0600 is set after every create."""

    def _open(self):
        stream = super()._open()
        self._restrict(self.baseFilename)
        return stream

    def doRollover(self) -> None:
        super().doRollover()
        self._restrict(self.baseFilename)
        self._restrict(self.rotation_filename(self.baseFilename + ".1"))

    @staticmethod
    def _restrict(name: str) -> None:
        try:
            os.chmod(name, 0o600)
        except OSError:
            return


def _dir(paths: Paths) -> Path:
    directory = paths.state_dir / "watchdog"
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


def _pid_path(paths: Paths) -> Path:
    return _dir(paths) / "watchdog.pid"


def _lock_path(paths: Paths) -> Path:
    return _dir(paths) / "watchdog.lock"


def heartbeat_path(paths: Paths) -> Path:
    return _dir(paths) / "heartbeat.json"


def _log_path(paths: Paths) -> Path:
    return paths.logs_dir / "watchdog.log"


def _read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _read_pid(paths: Paths) -> int | None:
    data = _read_json(_pid_path(paths))
    if not data:
        return None
    pid = data.get("pid")
    return pid if isinstance(pid, int) and pid > 0 else None


def _write_pid(paths: Paths, pid: int) -> None:
    path = _pid_path(paths)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps({"pid": pid}) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _clear_pidfile(paths: Paths) -> None:
    try:
        _pid_path(paths).unlink()
    except FileNotFoundError:
        return


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace")


def _is_watchdog_process(pid: int) -> bool:
    command = _cmdline(pid)
    return "watchdog" in command and ("oh_my_grok" in command or "omg" in command)


def _lock_busy(paths: Paths) -> bool:
    path = _lock_path(paths)
    if str(path) in _HELD:
        return True
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


class InstanceLock:
    """Exclusive lock plus pidfile. A dead holder's pidfile is replaced on the next acquire."""

    def __init__(self, paths: Paths):
        self.paths = paths
        self._fd: int | None = None

    def acquire(self) -> bool:
        path = _lock_path(self.paths)
        key = str(path)
        if key in _HELD:
            return False
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return False
        _write_pid(self.paths, os.getpid())
        self._fd = fd
        _HELD[key] = fd
        return True

    def release(self) -> None:
        path = _lock_path(self.paths)
        _HELD.pop(str(path), None)
        if _read_pid(self.paths) == os.getpid():
            _clear_pidfile(self.paths)
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def configure_logging(paths: Paths, policy: dict, *, force: bool = False) -> logging.Logger:
    paths.ensure()
    logger = log
    logger.setLevel(logging.INFO)
    logger.propagate = False
    global _configured_log_path
    path = str(_log_path(paths))
    if logger.handlers and not force and _configured_log_path == path:
        return logger
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    file_handler = _PrivateLogHandler(
        _log_path(paths), maxBytes=int(policy["watchdog_log_max_bytes"]),
        backupCount=int(policy["watchdog_log_backups"]))
    file_handler.setFormatter(_RedactFormatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(file_handler)
    _configured_log_path = path
    return logger


def _write_heartbeat(paths: Paths, payload: dict) -> dict:
    body = redact_obj(payload)
    path = heartbeat_path(paths)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(body, sort_keys=True, default=str))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return body


def _step(fn) -> dict:
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - one step must not kill the loop
        return {"ok": False, "error": redact(f"{type(exc).__name__}: {exc}")[:300]}
    if not isinstance(result, dict):
        result = {}
    out = redact_obj(result)
    out["ok"] = True
    return out


def _heal(engine: Engine) -> dict:
    try:
        snap = engine.heal_collect()
    except GateRefused as exc:
        return {"skipped": True, "reason": redact(exc.message)[:200]}
    status = snap.get("status")
    if status not in ("written", "unchanged"):
        status = "written" if snap.get("written", True) else "unchanged"
    return {"snapshot_id": snap["snapshot_id"], "item_count": snap["item_count"], "mode": snap["mode"],
            "written": bool(snap.get("written")), "status": status}


def _tick_label(name: str, step: dict) -> str:
    if not step.get("ok"):
        return f"{name}=fail"
    if name == "heal_collect" and step.get("status") in ("written", "unchanged"):
        return f"{name}={step['status']}"
    return f"{name}=ok"


def _latest(engine: Engine, task_id: str, kind: str) -> dict | None:
    row = engine._one("SELECT data_json FROM events WHERE task_id=? AND kind=? ORDER BY id DESC LIMIT 1",
                      (task_id, kind))
    if row is None or not row["data_json"]:
        return None
    data = json.loads(row["data_json"])
    return data if isinstance(data, dict) else None


def _emit(engine: Engine, kind: str, stall: dict, **extra) -> None:
    fields = {"role": stall["role"], "status": stall["status"], "reason": stall["reason"]}
    if stall.get("dispatch_id"):
        fields["dispatch_id"] = stall["dispatch_id"]
    for key, value in extra.items():
        if value is not None:
            fields[key] = value
    with db.tx(engine.conn):
        engine._ev(kind, stall["job_id"], stall["task_id"], "watchdog", **fields)


def _record_detected(engine: Engine, stall: dict, now: float) -> None:
    previous = _latest(engine, stall["task_id"], "stall_detected")
    if previous and previous.get("reason") == stall["reason"] and previous.get("dispatch_id") == stall.get("dispatch_id"):
        return
    _emit(engine, "stall_detected", stall, threshold_seconds=stall.get("threshold_seconds"), at=now)


def _backoff_seconds(policy: dict, already_sent: int) -> float:
    if already_sent <= 0:
        return 0.0
    base = float(policy["backoff_base_seconds"])
    cap = float(policy["backoff_cap_seconds"])
    return min(base * (2 ** (already_sent - 1)), cap)


def _wake_rows(engine: Engine, task_id: str) -> list:
    return engine._all("SELECT data_json FROM events WHERE task_id=? AND kind='stall_wake' ORDER BY id", (task_id,))


def _send(engine: Engine, stall: dict) -> dict:
    task = engine._one("SELECT * FROM tasks WHERE id=?", (stall["task_id"],))
    if task is None:
        return {"posted": False, "reason": "missing"}
    if task["status"] == "queued" and not task["current_dispatch_id"]:
        # _schedule is the only publisher for queued work: it skips a job that is not running work and a task
        # whose dependencies have not passed. Calling _dispatch_task here would start that task early.
        with db.tx(engine.conn):
            engine._schedule(task["job_id"])
        fresh = engine._one("SELECT status, current_dispatch_id FROM tasks WHERE id=?", (task["id"],))
        if fresh is None or fresh["status"] == "queued" or not fresh["current_dispatch_id"]:
            return {"posted": False, "reason": "deferred"}
        engine.flush_outbox()
        return {"posted": True, "enqueued": True, "dispatch_id": fresh["current_dispatch_id"]}
    dispatch_id = task["current_dispatch_id"]
    if not dispatch_id:
        return {"posted": False, "reason": "no_dispatch"}
    dispatch = engine._one("SELECT * FROM dispatch_outbox WHERE id=?", (dispatch_id,))
    if dispatch is None:
        return {"posted": False, "reason": "no_dispatch"}
    body = {"schema_version": PAYLOAD_SCHEMA_VERSION, "job_id": task["job_id"], "task_id": task["id"],
            "dispatch_id": dispatch["id"], "attempt": dispatch["attempt"]}
    posted = engine.post_role_hook(task["role"], body)
    posted["dispatch_id"] = dispatch["id"]
    return posted


def act_on_stalls(engine: Engine, stalls: list[dict], *, now: float, policy: dict, wake: bool) -> dict:
    """Record every stall. Wake only when ``wake`` is set, the role has a hook, and backoff and cap allow it."""
    counts = {"found": len(stalls), "woken": 0, "no_hook": 0, "capped": 0, "backoff": 0,
              "in_flight": 0, "deferred": 0, "shadow": 0}
    cap = int(policy["watchdog_wake_cap"])
    configured = hook_status(engine.paths)
    for stall in stalls:
        _record_detected(engine, stall, now)
        role = stall["role"]
        if not configured.get(role):
            previous = _latest(engine, stall["task_id"], "stall_no_hook")
            if not (previous and previous.get("dispatch_id") == stall.get("dispatch_id")):
                _emit(engine, "stall_no_hook", stall, at=now)
            counts["no_hook"] += 1
            continue
        if not wake:
            counts["shadow"] += 1
            continue
        sent = _wake_rows(engine, stall["task_id"])
        if len(sent) >= cap:
            if _latest(engine, stall["task_id"], "stall_wake_capped") is None:
                _emit(engine, "stall_wake_capped", stall, wakes=len(sent), cap=cap, at=now)
            counts["capped"] += 1
            continue
        if sent:
            last = json.loads(sent[-1]["data_json"] or "{}")
            last_at = last.get("at")
            if last_at is not None and now < float(last_at) + _backoff_seconds(policy, len(sent)):
                counts["backoff"] += 1
                continue
        inflight = engine._one(
            "SELECT id FROM dispatch_outbox WHERE task_id=? AND channel='webhook' AND superseded=0 "
            "AND status IN ('pending','sending','retry_wait')", (stall["task_id"],))
        if inflight:
            counts["in_flight"] += 1
            continue
        result = _send(engine, stall)
        if not result.get("posted"):
            counts["deferred"] += 1
            continue
        _emit(engine, "stall_wake", stall, at=now, http_status=result.get("http_status"),
              error=result.get("error"), outcome="accepted" if result.get("accepted") else "posted",
              dispatch_id=result.get("dispatch_id") or stall.get("dispatch_id"))
        counts["woken"] += 1
        log.info("stall wake role=%s task=%s outcome=%s", role, stall["task_id"],
                 "accepted" if result.get("accepted") else "posted")
    try:
        engine._flush_projections()
    except OmgError as exc:
        log.error("projection flush failed: %s", redact(exc.message)[:300])
    return counts


def tick(engine: Engine, *, now: float | None = None, interval: float | None = None) -> dict:
    """One iteration. Each step is isolated: a failure is recorded and the later steps still run."""
    policy = load_policy(engine.paths.config_dir)
    engine.policy = policy
    configure_logging(engine.paths, policy)
    mode = policy["features"]["watchdog"]
    moment = time.time() if now is None else now
    step_interval = float(policy["watchdog_interval_seconds"] if interval is None else interval)
    if mode == features.OFF:
        outcomes = {name: {"ok": True, "skipped": True, "reason": "watchdog off"}
                    for name in ("reconcile", "heal_collect", "stalls")}
    else:
        outcomes = {
            "reconcile": _step(lambda: engine.reconcile()),
            "heal_collect": _step(lambda: _heal(engine)),
            "stalls": _step(lambda: _stalls(engine, policy, moment, wake=mode == features.ON)),
        }
    for name, step in outcomes.items():
        if not step.get("ok"):
            log.error("step %s failed: %s", name, step.get("error", ""))
    payload = _write_heartbeat(engine.paths, {
        "unix": moment, "ts": db.utcnow(), "mode": mode, "interval_seconds": step_interval, "steps": outcomes})
    log.info("tick mode=%s %s", mode, " ".join(_tick_label(name, step) for name, step in outcomes.items()))
    return payload


def _stalls(engine: Engine, policy: dict, now: float, *, wake: bool) -> dict:
    stalls = healing.find_stalls(
        engine.conn, now=now, stall_awaiting_resume_seconds=float(policy["stall_awaiting_resume_seconds"]),
        lease_seconds=float(policy["lease_seconds"]))
    return act_on_stalls(engine, stalls, now=now, policy=policy, wake=wake)


def _wait(seconds: float, stop: threading.Event, sleep) -> None:
    if sleep is not time.sleep:
        sleep(seconds)
        return
    deadline = time.monotonic() + seconds
    while not stop.is_set():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.2, remaining))


def serve(paths: Paths | None = None, *, interval: float | None = None, once: bool = False,
          max_ticks: int | None = None, sleep=time.sleep, tick_fn=None) -> dict:
    """Foreground loop. Holds the instance lock until it returns. ``once`` runs a single tick."""
    paths = paths or get_paths()
    paths.ensure()
    lock = InstanceLock(paths)
    if not lock.acquire():
        pid = _read_pid(paths)
        log.warning("watchdog already running pid=%s", pid)
        return {"ok": True, "already_running": True, "pid": pid, "ticks": 0}
    stop = threading.Event()

    def _on_signal(signum, _frame):
        stop.set()
        log.info("signal %s, stopping after the current tick", signum)

    previous = {}
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            previous[sig] = signal.signal(sig, _on_signal)
        except ValueError:
            # Not the main thread. Tests that drive serve() still stop via max_ticks.
            previous = {}
            break
    ticks = 0
    last = None
    limit = 1 if once else max_ticks
    try:
        policy = load_policy(paths.config_dir)
        configure_logging(paths, policy)
        log.info("watchdog loop started pid=%s", os.getpid())
        while not stop.is_set():
            try:
                engine = Engine()
                try:
                    if tick_fn is None:
                        last = tick(engine, interval=interval)
                    else:
                        last = tick_fn(engine)
                finally:
                    engine.close()
            except Exception as exc:  # noqa: BLE001 - the loop survives a bad tick
                log.error("tick failed: %s", redact(f"{type(exc).__name__}: {exc}")[:300])
            ticks += 1
            if limit is not None and ticks >= limit:
                break
            step = interval if interval is not None else float(load_policy(paths.config_dir)["watchdog_interval_seconds"])
            _wait(step, stop, sleep)
        log.info("watchdog loop stopped pid=%s ticks=%s", os.getpid(), ticks)
        return {"ok": True, "already_running": False, "pid": os.getpid(), "ticks": ticks, "last": last}
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        lock.release()


def status(paths: Paths | None = None, *, now: float | None = None) -> dict:
    """Alive when the lock is held (or the pidfile names a live watchdog). Stale when the flag expects a fresh heartbeat."""
    paths = paths or get_paths()
    moment = time.time() if now is None else now
    policy = load_policy(paths.config_dir)
    mode = policy["features"]["watchdog"]
    pid = _read_pid(paths)
    running = _lock_busy(paths) or bool(pid and _pid_alive(pid) and _is_watchdog_process(pid))
    beat = _read_json(heartbeat_path(paths)) if (paths.state_dir / "watchdog").exists() else None
    age = None
    if beat and isinstance(beat.get("unix"), (int, float)):
        age = moment - float(beat["unix"])
    interval = float(beat["interval_seconds"]) if beat and beat.get("interval_seconds") else float(
        policy["watchdog_interval_seconds"])
    heartbeat_stale = age is None or age > interval * float(policy["watchdog_stale_intervals"])
    if mode == features.OFF:
        ok, detail, stale = True, "off", False
    elif running and not heartbeat_stale:
        ok, detail, stale = True, "alive", False
    else:
        ok, detail, stale = False, "stale", True
    return {"ok": ok, "detail": detail, "alive": bool(running), "pid": pid if running else None,
            "stale_pidfile": bool(pid) and not running and not (pid and _pid_alive(pid)),
            "mode": mode, "heartbeat": beat, "heartbeat_age_seconds": age, "stale": stale}


def start(interval: float | None = None, paths: Paths | None = None) -> dict:
    """Daemonize ``watchdog run``. Idempotent when a live instance holds the lock. Recovers a stale pidfile."""
    paths = paths or get_paths()
    paths.ensure()
    current = status(paths)
    if current["alive"]:
        return {"ok": True, "started": False, "already_running": True, "pid": current["pid"]}
    args = [sys.executable, "-m", "oh_my_grok.cli", "watchdog", "run"]
    if interval is not None:
        args.extend(["--interval", str(interval)])
    log_path = _log_path(paths)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(log_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    os.fchmod(log_fd, 0o600)
    with os.fdopen(log_fd, "ab") as handle:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT,
                                start_new_session=True, cwd=str(CODE_ROOT), env=os.environ.copy())
    deadline = time.time() + 15
    while time.time() < deadline:
        current = status(paths)
        if current["alive"] and current["pid"] and current["heartbeat"] is not None:
            return {"ok": True, "started": current["pid"] == proc.pid,
                    "already_running": current["pid"] != proc.pid, "pid": current["pid"]}
        if proc.poll() is not None:
            current = status(paths)
            if current["alive"]:
                return {"ok": True, "started": False, "already_running": True, "pid": current["pid"]}
            return {"ok": False, "started": False, "already_running": False, "exit_code": proc.returncode,
                    "error": "watchdog exited before it was ready"}
        time.sleep(0.05)
    return {"ok": False, "started": False, "already_running": False, "pid": proc.pid,
            "error": "watchdog did not become ready"}


def ensure(interval: float | None = None, paths: Paths | None = None) -> dict:
    """Start the daemon only when it is not alive. Safe to call from a coarse backstop after a host restart."""
    return start(interval=interval, paths=paths)


def stop(paths: Paths | None = None, *, timeout: float = 5.0) -> dict:
    """SIGTERM the pidfile's process when it is this watchdog. A stale or foreign pidfile is cleared, not killed."""
    paths = paths or get_paths()
    pid = _read_pid(paths)
    if not pid or not _pid_alive(pid) or not _is_watchdog_process(pid):
        _clear_pidfile(paths)
        return {"ok": True, "stopped": True, "already_stopped": True, "pid": None}
    os.kill(pid, signal.SIGTERM)
    deadline = time.time() + timeout
    while time.time() < deadline and _pid_alive(pid):
        time.sleep(0.05)
    if _pid_alive(pid):
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.1)
    if _read_pid(paths) == pid:
        _clear_pidfile(paths)
    alive = _pid_alive(pid)
    return {"ok": not alive, "stopped": not alive, "already_stopped": False, "pid": None if not alive else pid}
