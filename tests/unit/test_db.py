"""T02: schema, migrations, pragmas, CAS transition table, backup/restore (§10 item 18 part)."""
import sqlite3

import pytest

from oh_my_grok import db
from oh_my_grok.errors import Conflict
from oh_my_grok.states import (DISPATCH_STATUSES, JOB_PHASES, TASK_STATUSES, check_dispatch, check_job,
                             check_task)


def test_migrations_apply_once_and_record_checksums(tmp_path):
    c = db.connect(tmp_path / "x.sqlite3")
    assert db.migrate(c, dry_run=True) == [1, 2, 3, 4, 5, 6, 7]
    assert db.current_version(c) == 0
    assert db.migrate(c) == [1, 2, 3, 4, 5, 6, 7]
    assert db.migrate(c) == []
    rows = c.execute("SELECT version, checksum FROM schema_migrations").fetchall()
    assert [r[0] for r in rows] == [1, 2, 3, 4, 5, 6, 7] and all(len(r[1]) == 64 for r in rows)
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for t in ["jobs", "tasks", "task_attempts", "artifacts", "plan_revisions", "approvals", "role_bindings",
              "dispatch_outbox", "verifications", "reviews", "events", "hooks_meta", "gate_results",
              "failure_snapshots", "failure_items"]:
        assert t in tables


def test_partial_migration_target(tmp_path):
    c = db.connect(tmp_path / "x.sqlite3")
    assert db.migrate(c, target=1) == [1]
    assert db.current_version(c) == 1
    assert db.migrate(c) == [2, 3, 4, 5, 6, 7]


def test_checksum_mismatch_detected(tmp_path):
    c = db.connect(tmp_path / "x.sqlite3")
    db.migrate(c)
    c.execute("UPDATE schema_migrations SET checksum='bad' WHERE version=1")
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        db.migrate(c)


def test_pragmas(tmp_path):
    p = tmp_path / "x.sqlite3"
    c = db.connect(p)
    assert c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert c.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert c.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000
    assert (p.stat().st_mode & 0o077) == 0


def test_foreign_keys_enforced(tmp_path):
    c = db.connect(tmp_path / "x.sqlite3")
    db.migrate(c)
    with pytest.raises(sqlite3.IntegrityError):
        c.execute("INSERT INTO tasks(id,job_id,kind,role,status,created_at,updated_at) "
                  "VALUES ('t','missing-job','explore','explorer','queued','x','x')")


def test_tx_rolls_back_on_error(tmp_path):
    c = db.connect(tmp_path / "x.sqlite3")
    db.migrate(c)
    with pytest.raises(ValueError):
        with db.tx(c):
            c.execute("INSERT INTO hooks_meta(role,configured,updated_at) VALUES ('x',1,'t')")
            raise ValueError
    assert c.execute("SELECT COUNT(*) FROM hooks_meta").fetchone()[0] == 0


# Expected allowed transitions, written out independently of oh_my_grok.states so that any accidental widening
# (or narrowing) of the engine's table fails this test. Every other (src, dst) pair must raise Conflict.
_TASK_OK = {
    "queued": {"dispatched", "awaiting_resume", "blocked", "cancelled"},
    "dispatched": {"working", "queued", "blocked", "cancelled"},
    "awaiting_resume": {"working", "dispatched", "blocked", "cancelled"},
    "working": {"submitted", "queued", "blocked", "failed", "cancelled"},
    "submitted": {"passed", "rejected", "blocked", "failed", "cancelled"},
    "blocked": {"queued", "cancelled", "failed"},
    "passed": set(), "rejected": set(), "failed": set(), "cancelled": set(),
}
_STOP = {"blocked", "failed", "cancelled"}
_REENTRY = {"research", "analysis"}  # escalation (spec/ADAPTIVE.md 5.4) re-opens the earliest incomplete phase
_JOB_OK = {
    "research": {"analysis"} | _STOP,
    "analysis": {"planning", "research", "done"} | _STOP,  # done: read-only investigations only (SUP-4, engine-guarded)
    "planning": {"plan_review"} | _REENTRY | _STOP,
    "plan_review": {"planning", "awaiting_approval"} | _REENTRY | _STOP,
    "awaiting_approval": {"running", "plan_approved", "planning"} | _REENTRY | _STOP,
    "plan_approved": {"running", "planning"} | _REENTRY | _STOP,
    "running": {"done"} | _REENTRY | _STOP,
    "blocked": {"research", "analysis", "planning", "plan_review", "awaiting_approval", "plan_approved", "running",
                "failed", "cancelled"},
    "done": set(), "failed": set(), "cancelled": set(),
}
_DISPATCH_OK = {
    "pending": {"sending", "failed"},
    "sending": {"accepted", "retry_wait", "failed"},
    "retry_wait": {"sending", "failed"},
    "accepted": set(), "failed": set(),
}


def _matrix(ok, statuses):
    assert set(ok) == set(statuses), "status vocabulary changed; update the expected table deliberately"
    vocab = list(statuses) + ["bogus"]
    return [(s, d, d in ok.get(s, set())) for s in vocab for d in vocab]


@pytest.mark.parametrize("check,ok,statuses", [
    (check_task, _TASK_OK, TASK_STATUSES),
    (check_job, _JOB_OK, JOB_PHASES),
    (check_dispatch, _DISPATCH_OK, DISPATCH_STATUSES),
], ids=["task", "job", "dispatch"])
def test_full_transition_matrix(check, ok, statuses):
    allowed = rejected = 0
    for src, dst, expect_ok in _matrix(ok, statuses):
        if expect_ok:
            check(src, dst)
            allowed += 1
        else:
            with pytest.raises(Conflict):
                check(src, dst)
            rejected += 1
    n = len(statuses) + 1
    assert allowed + rejected == n * n and allowed == sum(len(v) for v in ok.values())


def test_engine_set_task_enforces_matrix_in_db(harness):
    """The CAS writer itself (not only the pure check) refuses an illegal pair and leaves the row unchanged."""
    e = harness.e
    job = harness.submit()["job_id"]
    t = harness.task(job, "explore")
    with pytest.raises(Conflict):
        with db.tx(e.conn):
            e._set_task(t, "passed")
    assert harness.task(job, "explore")["status"] == t["status"]


def test_backup_and_restore_roundtrip(harness, tmp_path):
    e = harness.e
    job = harness.submit()["job_id"]
    harness.research(job)
    before = e.status(job)
    bk = db.backup(e.conn, tmp_path / "bk.sqlite3")
    assert (bk.stat().st_mode & 0o077) == 0
    # damage the live DB state after the backup
    harness.analyze(job)
    with db.tx(e.conn):
        e.conn.execute("DELETE FROM events")
    e.close()
    db.restore(bk, e.paths.db_path)
    from oh_my_grok.engine import Engine
    e2 = Engine(transport=harness.transport, clock=harness.clock)
    after = e2.status(job)
    assert after["phase"] == before["phase"] and after["counts"] == before["counts"]
    assert e2._one("SELECT COUNT(*) c FROM events")["c"] > 0
    assert e2.conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # restored job continues normally
    harness.e = e2
    harness.analyze(job)
    assert e2.status(job)["phase"] == "planning"
    e2.close()


def test_restore_rejects_corrupt_backup(tmp_path):
    bad = tmp_path / "bad.sqlite3"
    bad.write_bytes(b"SQLite format 3\x00" + b"\xff" * 4000)
    from oh_my_grok.errors import IntegrityError_
    with pytest.raises(IntegrityError_):
        db.restore(bad, tmp_path / "target.sqlite3")
    assert not (tmp_path / "target.sqlite3").exists() or (tmp_path / "target.sqlite3").stat().st_size == 0


def test_auto_backup_before_migrating_nonempty_db(omg_home):
    from oh_my_grok.engine import Engine
    from oh_my_grok.paths import get_paths
    p = get_paths()
    p.ensure()
    c = db.connect(p.db_path)
    db.migrate(c, target=1)
    c.close()
    e = Engine()
    assert db.current_version(e.conn) == db.LATEST_VERSION == 7
    assert list(p.backups_dir.glob("pre-migrate-v1-*.sqlite3"))
    e.close()


def test_item18_injected_migration_failure_keeps_prior_version(tmp_path, monkeypatch):
    c = db.connect(tmp_path / "x.sqlite3")
    db.migrate(c)
    v = db.current_version(c)
    bad = (v + 1, "broken", "CREATE TABLE t_new(x INTEGER); INSERT INTO no_such_table VALUES (1)")
    monkeypatch.setattr(db, "MIGRATIONS", [*db.MIGRATIONS, bad])
    with pytest.raises(sqlite3.OperationalError):
        db.migrate(c, target=v + 1)
    assert db.current_version(c) == v
    assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='t_new'").fetchone()  # DDL rolled back too
    good = (v + 1, "fixed", "CREATE TABLE t_new(x INTEGER)")
    monkeypatch.setattr(db, "MIGRATIONS", [*db.MIGRATIONS[:-1], good])
    assert db.migrate(c, target=v + 1) == [v + 1] and db.current_version(c) == v + 1


_SLOW_MIGRATOR = r"""
import sys
sys.path.insert(0, sys.argv[2])
from oh_my_grok import db
c = db.connect(sys.argv[1])
slow = (db.LATEST_VERSION + 1, "slow",
        "CREATE TABLE big AS WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<300000000) "
        "SELECT x FROM n")
db.MIGRATIONS.append(slow)
print("MIGRATING", flush=True)
db.migrate(c, target=slow[0])
print("FINISHED", flush=True)
"""


def test_item18_killed_mid_migration_subprocess(tmp_path):
    import signal
    import subprocess
    import sys
    import time
    from pathlib import Path
    p = tmp_path / "x.sqlite3"
    c = db.connect(p)
    db.migrate(c)
    v = db.current_version(c)
    c.close()
    root = str(Path(__file__).resolve().parents[2])
    proc = subprocess.Popen([sys.executable, "-c", _SLOW_MIGRATOR, str(p), root], stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "MIGRATING"
    time.sleep(1.0)
    assert proc.poll() is None, "migration finished before it could be killed; test would prove nothing"
    proc.send_signal(signal.SIGKILL)
    proc.wait(10)
    assert proc.returncode == -signal.SIGKILL
    c = db.connect(p)
    assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert db.current_version(c) == v
    assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='big'").fetchone()
    quick = (v + 1, "slow-but-quick-now", "CREATE TABLE big(x INTEGER)")
    db.MIGRATIONS.append(quick)
    try:
        assert db.migrate(c, target=v + 1) == [v + 1] and db.current_version(c) == v + 1
    finally:
        db.MIGRATIONS.remove(quick)
