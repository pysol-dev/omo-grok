"""Slice 1 failure collection: a projection of jobs, reviews, and the events log (spec/HEALING.md)."""
import json
import os
import subprocess
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from oh_my_grok import db, features
from oh_my_grok.config import canonical_json, sha256_text
from oh_my_grok.errors import GateRefused, NotFound, ValidationError
from oh_my_grok.healing import RESERVED_SOURCES, collect, show
from oh_my_grok.states import ROLES

ROOT = Path(__file__).resolve().parents[2]
OMG = str(ROOT / "omg")


def _sha(obj) -> str:
    return sha256_text(canonical_json(obj))


def _run(args, env):
    return subprocess.run([OMG, *args], capture_output=True, text=True, env=env, timeout=60, check=False)


def _policy(mode):
    path = Path(os.environ["OMG_CONFIG_DIR"]) / "policy.json"
    data = json.loads(path.read_text())
    data["features"] = {"healing": mode}
    path.write_text(json.dumps(data))


def _job(conn, *, phase="running", repair_cycles=0, failure_reason=None, blocked_from=None, mode="fixture"):
    jid = str(uuid.uuid4())
    now = db.utcnow()
    conn.execute(
        "INSERT INTO jobs(id,idempotency_key,goal,mode,requirements_json,requirements_hash,phase,blocked_from,"
        "version,policies_json,repair_cycles,plan_rounds,failure_reason,created_at,updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,1,'{}',?,?,?,?,?)",
        (jid, "k-" + jid, "goal", mode, '{"goal":"g"}', "h" * 64, phase, blocked_from,
         repair_cycles, 0, failure_reason, now, now))
    return jid


def _task(conn, job_id, kind="code_review", role="code-reviewer", status="passed"):
    tid = str(uuid.uuid4())
    now = db.utcnow()
    conn.execute(
        "INSERT INTO tasks(id,job_id,kind,role,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
        (tid, job_id, kind, role, status, now, now))
    return tid


def _review(conn, job_id, task_id, *, typ="code", findings=None, verdict="reject", revision="ab" * 20,
            invalidated=0):
    rid = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO reviews(id,job_id,task_id,type,reviewer_role,revision,input_hashes_json,findings_json,"
        "verdict,evidence_json,invalidated,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (rid, job_id, task_id, typ, role_for(typ), revision, "[]",
         json.dumps(findings if findings is not None else ["bug: x"]), verdict, "{}", invalidated, db.utcnow()))
    return rid


def role_for(typ):
    return {"plan": "momus", "code": "code-reviewer", "qa": "qa-executor"}[typ]


def _event(conn, job_id, kind, data=None, task_id=None):
    conn.execute(
        "INSERT INTO events(ts,job_id,task_id,kind,actor,data_json) VALUES (?,?,?,?,?,?)",
        (db.utcnow(), job_id, task_id, kind, "engine", json.dumps(data) if data is not None else None))
    return conn.execute("SELECT last_insert_rowid()").fetchone()[0]


def _count(conn, sql, args=()):
    return conn.execute(sql, args).fetchone()[0]


def _dump(conn, table, order):
    return [tuple(r) for r in conn.execute(f"SELECT * FROM {table} ORDER BY {order}")]


@pytest.fixture
def eng(omg_home):
    from oh_my_grok.engine import Engine
    e = Engine()
    yield e
    e.close()


def test_migration_6_creates_snapshot_tables(tmp_path):
    conn = db.connect(tmp_path / "h.sqlite3")
    assert 6 in db.migrate(conn)
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"failure_snapshots", "failure_items"} <= names


def test_migration_7_preserves_existing_duplicate_snapshots(tmp_path):
    conn = db.connect(tmp_path / "h.sqlite3")
    assert db.migrate(conn, target=6) == [1, 2, 3, 4, 5, 6]
    jid = _job(conn, phase="done", repair_cycles=1)
    ids = []
    for seq, stamp in ((1, "2026-01-01T00:00:00.000000Z"), (2, "2026-01-02T00:00:00.000000Z")):
        sid = str(uuid.uuid4())
        ids.append(sid)
        conn.execute(
            "INSERT INTO failure_snapshots(id,seq,mode,item_count,corpus_sha256,created_at) VALUES (?,?,?,?,?,?)",
            (sid, seq, "shadow", 1, "a" * 64, stamp))
        conn.execute(
            "INSERT INTO failure_items(snapshot_id,ordinal,item_sha256,class,source,job_id,payload_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (sid, 0, "b" * 64, "repair", "repair_cycle", jid, '{"class":"repair"}'))
    assert db.migrate(conn) == [7]
    rows = conn.execute(
        "SELECT id, seq, seen_count, last_seen_at, created_at FROM failure_snapshots ORDER BY seq").fetchall()
    assert [r["id"] for r in rows] == ids
    assert [r["seen_count"] for r in rows] == [1, 1]
    assert [r["last_seen_at"] for r in rows] == [r["created_at"] for r in rows]
    assert _count(conn, "SELECT COUNT(*) FROM failure_items") == 2


def test_healing_off_refuses_and_writes_nothing(eng):
    jid = _job(eng.conn, phase="blocked", failure_reason="disk full", blocked_from="running")
    with pytest.raises(GateRefused, match="healing is off"):
        collect(eng.conn, "off")
    with pytest.raises(ValidationError):
        collect(eng.conn, "on")
    assert _count(eng.conn, "SELECT COUNT(*) FROM failure_snapshots") == 0
    assert _count(eng.conn, "SELECT COUNT(*) FROM failure_items") == 0
    assert _count(eng.conn, "SELECT COUNT(*) FROM events WHERE kind='failures_collected'") == 0
    assert tuple(eng.conn.execute("SELECT phase, version FROM jobs WHERE id=?", (jid,)).fetchone()) == ("blocked", 1)


def test_empty_shadow_and_enforce_write_snapshots_without_enqueueing(eng):
    shadow = collect(eng.conn, "shadow")
    assert shadow["written"] is True and shadow["status"] == "written" and shadow["mode"] == "shadow"
    assert shadow["item_count"] == 0 and shadow["items"] == []
    assert shadow["sha256"] == shadow["corpus_sha256"] == shadow["fingerprint"] == _sha([])
    assert shadow["seen_count"] == 1
    enforce = collect(eng.conn, "enforce")
    assert enforce["written"] is False and enforce["status"] == "unchanged"
    assert enforce["snapshot_id"] == shadow["snapshot_id"]
    assert enforce["sha256"] == shadow["sha256"]
    assert enforce["seen_count"] == 2
    assert _count(eng.conn, "SELECT COUNT(*) FROM failure_snapshots") == 1
    assert _count(eng.conn, "SELECT COUNT(*) FROM jobs") == 0
    assert _count(eng.conn, "SELECT COUNT(*) FROM tasks") == 0
    assert _count(eng.conn, "SELECT COUNT(*) FROM dispatch_outbox") == 0
    assert _count(eng.conn, "SELECT COUNT(*) FROM events WHERE kind='failures_collected'") == 1


def _corpus(conn):
    blocked = _job(conn, phase="blocked", failure_reason="repair_budget_exhausted", blocked_from="running")
    done = _job(conn, phase="done", repair_cycles=2)
    quiet = _job(conn, phase="running")
    tid = _task(conn, done)
    review = _review(conn, done, tid, findings=["bug: x", "bug: y"], invalidated=1)
    _review(conn, quiet, _task(conn, quiet), verdict="accept", findings=[])
    e1 = _event(conn, done, "repair_cycle", {"failures": 1, "reason": "verification failed", "max": 3})
    e2 = _event(conn, done, "repair_cycle", {"failures": 2, "reason": "qa rejected", "max": 3})
    _event(conn, blocked, "github_review_bot", {"comment": "nit"})
    return {"blocked": blocked, "done": done, "quiet": quiet, "review": review, "events": (e1, e2)}


def test_sources_are_blocked_repair_review_and_repeated(eng):
    ids = _corpus(eng.conn)
    out = collect(eng.conn, "shadow")
    by_job = {}
    for item in out["items"]:
        assert item["class"] and item["job_id"]
        assert item["sha256"] == _sha(item["payload"])
        assert item["class"] == item["payload"]["class"]
        assert item["job_id"] == item["payload"]["job_id"]
        assert item["source"] != "github_review_bot"
        by_job.setdefault(item["job_id"], []).append(item)
    assert ids["quiet"] not in by_job
    blocked = by_job[ids["blocked"]]
    assert [i["class"] for i in blocked] == ["blocked"]
    assert blocked[0]["payload"]["failure_reason"] == "repair_budget_exhausted"
    assert blocked[0]["payload"]["blocked_from"] == "running"
    kinds = sorted(i["class"] for i in by_job[ids["done"]])
    assert kinds == ["repair", "repair", "repeated", "review"]
    review = next(i for i in by_job[ids["done"]] if i["class"] == "review")
    assert review["payload"]["findings"] == ["bug: x", "bug: y"]
    assert review["payload"]["review_id"] == ids["review"]
    assert review["payload"]["invalidated"] is True
    repeated = next(i for i in by_job[ids["done"]] if i["class"] == "repeated")
    assert repeated["payload"]["count"] == 2
    assert repeated["payload"]["event_ids"] == list(ids["events"])
    assert out["sha256"] == _sha([i["sha256"] for i in out["items"]])


def test_done_job_with_repair_cycles_and_no_event_still_appears(eng):
    jid = _job(eng.conn, phase="done", repair_cycles=1)
    out = collect(eng.conn, "enforce")
    items = [i for i in out["items"] if i["job_id"] == jid]
    assert len(items) == 1
    assert items[0]["class"] == "repair"
    assert items[0]["payload"]["failures"] == 1
    assert items[0]["payload"]["record"] == "jobs.repair_cycles"
    assert eng.conn.execute("SELECT phase FROM jobs WHERE id=?", (jid,)).fetchone()[0] == "done"


def test_event_repair_is_not_duplicated_by_the_counter(eng):
    jid = _job(eng.conn, phase="done", repair_cycles=1)
    eid = _event(conn=eng.conn, job_id=jid, kind="repair_cycle", data={"failures": 1, "reason": "once", "max": 3})
    out = collect(eng.conn, "shadow")
    items = [i for i in out["items"] if i["job_id"] == jid]
    assert len(items) == 1
    assert items[0]["payload"]["event_id"] == eid
    assert "record" not in items[0]["payload"]
    assert items[0]["payload"]["reason"] == "once"


def test_repeated_collect_with_unchanged_state_writes_one_snapshot(eng):
    _corpus(eng.conn)
    first = collect(eng.conn, "shadow")
    second = collect(eng.conn, "shadow")
    third = collect(eng.conn, "shadow")
    assert first["written"] is True and first["status"] == "written" and first["seen_count"] == 1
    assert second["written"] is False and second["status"] == "unchanged"
    assert third["status"] == "unchanged" and third["seen_count"] == 3
    assert first["snapshot_id"] == second["snapshot_id"] == third["snapshot_id"]
    assert first["seq"] == second["seq"]
    assert [i["sha256"] for i in first["items"]] == [i["sha256"] for i in second["items"]]
    assert first["sha256"] == second["sha256"] == second["fingerprint"]
    assert _count(eng.conn, "SELECT COUNT(*) FROM failure_snapshots") == 1
    assert _count(eng.conn, "SELECT COUNT(*) FROM events WHERE kind='failures_collected'") == 1
    latest = show(eng.conn)
    assert latest["snapshot_id"] == first["snapshot_id"]
    assert latest["seen_count"] == 3
    assert latest["last_seen_at"] >= latest["created_at"]
    assert [i["sha256"] for i in latest["items"]] == [i["sha256"] for i in first["items"]]
    earlier = show(eng.conn, first["snapshot_id"])
    assert earlier["snapshot_id"] == first["snapshot_id"]
    n = _count(eng.conn, "SELECT COUNT(*) FROM events")
    show(eng.conn)
    assert _count(eng.conn, "SELECT COUNT(*) FROM events") == n
    with pytest.raises(NotFound):
        show(eng.conn, "00000000-0000-4000-8000-000000000000")
    with pytest.raises(ValidationError):
        show(eng.conn, "not-a-uuid")


def test_changed_item_set_writes_a_new_snapshot(eng):
    jid = _job(eng.conn, phase="done", repair_cycles=1)
    first = collect(eng.conn, "shadow")
    assert first["written"] is True and _count(eng.conn, "SELECT COUNT(*) FROM failure_snapshots") == 1
    _event(eng.conn, jid, "repair_cycle", {"failures": 1, "reason": "verification failed", "max": 3})
    second = collect(eng.conn, "shadow")
    assert second["written"] is True and second["status"] == "written"
    assert second["snapshot_id"] != first["snapshot_id"]
    assert second["seq"] == first["seq"] + 1
    assert second["sha256"] != first["sha256"]
    assert second["seen_count"] == 1
    assert _count(eng.conn, "SELECT COUNT(*) FROM failure_snapshots") == 2
    kept = eng.conn.execute("SELECT seen_count FROM failure_snapshots WHERE id=?", (first["snapshot_id"],)).fetchone()
    assert kept["seen_count"] == 1
    again = collect(eng.conn, "shadow")
    assert again["status"] == "unchanged" and again["snapshot_id"] == second["snapshot_id"]
    assert _count(eng.conn, "SELECT COUNT(*) FROM failure_snapshots") == 2


def _stamp(day: int) -> str:
    return f"2026-01-{day:02d}T00:00:00.000000Z"


def _legacy_snapshot(conn, seq, corpus, job_id, *, seen=1, created_day=1, seen_day=1):
    sid = str(uuid.uuid4())
    created, seen_at = _stamp(created_day), _stamp(seen_day)
    conn.execute(
        "INSERT INTO failure_snapshots(id,seq,mode,item_count,corpus_sha256,created_at,seen_count,last_seen_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (sid, seq, "shadow", 1, corpus, created, seen, seen_at))
    conn.execute(
        "INSERT INTO failure_items(snapshot_id,ordinal,item_sha256,class,source,job_id,payload_json) "
        "VALUES (?,?,?,?,?,?,?)",
        (sid, 0, corpus, "repair", "repair_cycle", job_id, '{"class":"repair","source":"repair_cycle"}'))
    return sid


def _duplicate_run(conn):
    """Consecutive aaa, aaa, aaa, then bbb, then a later aaa. Counts are already above 1."""
    jid = _job(conn, phase="done", repair_cycles=1)
    same, other = "a" * 64, "b" * 64
    ids = [
        _legacy_snapshot(conn, 1, same, jid, seen=2, created_day=1, seen_day=1),
        _legacy_snapshot(conn, 2, same, jid, seen=3, created_day=2, seen_day=2),
        _legacy_snapshot(conn, 3, same, jid, seen=4, created_day=3, seen_day=3),
        _legacy_snapshot(conn, 4, other, jid, seen=1, created_day=4, seen_day=4),
        _legacy_snapshot(conn, 5, same, jid, seen=1, created_day=5, seen_day=5),
    ]
    return jid, ids


def test_prune_dry_run_deletes_nothing(eng):
    from oh_my_grok.healing import prune_duplicates
    _jid, ids = _duplicate_run(eng.conn)
    before_snaps = _dump(eng.conn, "failure_snapshots", "seq")
    before_items = _dump(eng.conn, "failure_items", "snapshot_id, ordinal")
    events = _count(eng.conn, "SELECT COUNT(*) FROM events")
    out = prune_duplicates(eng.conn, apply=False)
    assert out["dry_run"] is True and out["applied"] is False
    assert out["deleted"] == 0 and out["would_delete"] == 2
    assert out["removed_ids"] == [ids[1], ids[2]]
    assert out["snapshots_before"] == out["snapshots_after"] == 5
    assert _dump(eng.conn, "failure_snapshots", "seq") == before_snaps
    assert _dump(eng.conn, "failure_items", "snapshot_id, ordinal") == before_items
    assert _count(eng.conn, "SELECT COUNT(*) FROM events") == events


def test_prune_apply_collapses_consecutive_duplicates(eng):
    from oh_my_grok.healing import prune_duplicates
    _jid, ids = _duplicate_run(eng.conn)
    out = prune_duplicates(eng.conn, apply=True)
    assert out["dry_run"] is False and out["applied"] is True
    assert out["deleted"] == 2 and out["would_delete"] == 2
    assert out["removed_ids"] == [ids[1], ids[2]]
    assert out["snapshots_before"] == 5 and out["snapshots_after"] == 3
    assert out["kept_count"] == 3
    rows = eng.conn.execute(
        "SELECT id, seq, seen_count, last_seen_at FROM failure_snapshots ORDER BY seq").fetchall()
    assert [r["id"] for r in rows] == [ids[0], ids[3], ids[4]]
    assert rows[0]["seen_count"] == 9 and rows[0]["last_seen_at"] == _stamp(3)
    assert rows[1]["seen_count"] == 1 and rows[1]["last_seen_at"] == _stamp(4)
    assert rows[2]["seen_count"] == 1 and rows[2]["last_seen_at"] == _stamp(5)
    left = [r[0] for r in eng.conn.execute("SELECT snapshot_id FROM failure_items ORDER BY snapshot_id")]
    assert left == sorted([ids[0], ids[3], ids[4]])
    assert _count(eng.conn, "SELECT COUNT(*) FROM events") == 0


def test_collect_does_not_prune_older_duplicates(eng):
    jid = _job(eng.conn, phase="done", repair_cycles=1)
    first = collect(eng.conn, "shadow")
    corpus = first["corpus_sha256"]
    dup = str(uuid.uuid4())
    eng.conn.execute(
        "INSERT INTO failure_snapshots(id,seq,mode,item_count,corpus_sha256,created_at,seen_count,last_seen_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (dup, first["seq"] + 1, "shadow", first["item_count"], corpus, db.utcnow(), 1, db.utcnow()))
    for item in eng.conn.execute("SELECT * FROM failure_items WHERE snapshot_id=?", (first["snapshot_id"],)):
        eng.conn.execute(
            "INSERT INTO failure_items(snapshot_id,ordinal,item_sha256,class,source,job_id,task_id,payload_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (dup, item["ordinal"], item["item_sha256"], item["class"], item["source"], item["job_id"],
             item["task_id"], item["payload_json"]))
    again = collect(eng.conn, "shadow")
    assert again["status"] == "unchanged" and again["snapshot_id"] == dup
    assert _count(eng.conn, "SELECT COUNT(*) FROM failure_snapshots") == 2
    assert eng.conn.execute("SELECT id FROM jobs WHERE id=?", (jid,)).fetchone()["id"] == jid


def test_cli_prune_duplicates_is_dry_run_until_apply(omg_home):
    from oh_my_grok.engine import Engine
    _policy("shadow")
    e = Engine()
    _jid, ids = _duplicate_run(e.conn)
    e.close()
    env = os.environ.copy()
    dry = _run(["heal", "prune-duplicates", "--json"], env)
    assert dry.returncode == 0, dry.stderr
    body = json.loads(dry.stdout)
    assert body["dry_run"] is True and body["deleted"] == 0 and body["would_delete"] == 2
    assert "dry-run" in _run(["heal", "prune-duplicates"], env).stdout
    e = Engine()
    try:
        assert _count(e.conn, "SELECT COUNT(*) FROM failure_snapshots") == 5
    finally:
        e.close()
    applied = _run(["heal", "prune-duplicates", "--apply"], env)
    assert applied.returncode == 0, applied.stderr
    assert "deleted 2" in applied.stdout
    checked = json.loads(_run(["heal", "prune-duplicates", "--json"], env).stdout)
    assert checked["would_delete"] == 0 and checked["deleted"] == 0
    e = Engine()
    try:
        left = [r["id"] for r in e.conn.execute("SELECT id FROM failure_snapshots ORDER BY seq")]
        assert left == [ids[0], ids[3], ids[4]]
        assert e.conn.execute("SELECT seen_count FROM failure_snapshots WHERE id=?", (ids[0],)).fetchone()[0] == 9
    finally:
        e.close()


def test_collect_does_not_mutate_jobs_or_append_other_events(eng):
    _corpus(eng.conn)
    before = {name: _dump(eng.conn, name, order) for name, order in (
        ("jobs", "id"), ("tasks", "id"), ("reviews", "id"), ("dispatch_outbox", "id"), ("verifications", "id"))}
    events_before = _dump(eng.conn, "events", "id")
    collect(eng.conn, "enforce")
    for name, rows in before.items():
        assert _dump(eng.conn, name, "id") == rows
    events_after = _dump(eng.conn, "events", "id")
    assert events_after[:-1] == events_before
    kind_at = [row[1] for row in eng.conn.execute("PRAGMA table_info(events)")].index("kind")
    assert events_after[-1][kind_at] == "failures_collected"


def test_prior_snapshot_is_not_read_back(eng):
    jid = _job(eng.conn, phase="blocked", failure_reason="stuck", blocked_from="planning")
    first = collect(eng.conn, "shadow")
    eng.conn.execute("UPDATE failure_items SET payload_json=?, class='tampered' WHERE snapshot_id=?",
                     ('{"class":"tampered"}', first["snapshot_id"]))
    second = collect(eng.conn, "shadow")
    assert [i["sha256"] for i in second["items"]] == [i["sha256"] for i in first["items"]]
    assert second["items"][0]["class"] == "blocked"
    assert second["items"][0]["job_id"] == jid
    assert second["items"][0]["payload"]["failure_reason"] == "stuck"


def test_github_review_bot_alone_is_not_collected(eng):
    jid = _job(eng.conn, phase="done")
    _event(eng.conn, jid, "github_review_bot", {"body": "please fix"})
    out = collect(eng.conn, "shadow")
    assert out["items"] == []
    assert all(i["source"] != "github_review_bot" for i in out["items"])


def test_engine_collect_uses_policy_not_the_frozen_job_flag(eng):
    jid = _job(eng.conn, phase="blocked", failure_reason="nope", blocked_from="planning")
    assert eng._features(eng._job(jid))["healing"] == "off"
    eng.policy["features"] = features.normalize({"healing": "shadow"})
    out = eng.heal_collect()
    assert out["mode"] == "shadow"
    assert any(i["class"] == "blocked" and i["job_id"] == jid for i in out["items"])
    assert eng._dirty == set()
    assert eng._job(jid)["phase"] == "blocked"


def test_cli_off_is_a_refusal_that_writes_nothing(omg_home):
    from oh_my_grok.engine import Engine
    e = Engine()
    e.close()
    env = os.environ.copy()
    refused = _run(["heal", "collect", "--json"], env)
    assert refused.returncode == 5
    body = json.loads(refused.stdout)
    assert body["code"] == "gate_refused" and "healing is off" in body["message"]
    human = _run(["heal", "collect"], env)
    assert human.returncode == 5 and "healing is off" in human.stderr
    missing = _run(["heal", "show", "--json"], env)
    assert missing.returncode == 3
    e = Engine()
    try:
        assert _count(e.conn, "SELECT COUNT(*) FROM failure_snapshots") == 0
        assert _count(e.conn, "SELECT COUNT(*) FROM events WHERE kind='failures_collected'") == 0
    finally:
        e.close()


def test_cli_collect_and_show_print_a_blocked_fixture_snapshot(omg_home):
    from oh_my_grok.engine import Engine
    _policy("shadow")
    e = Engine()
    jid = _job(e.conn, phase="blocked", failure_reason="repair_budget_exhausted", blocked_from="running")
    version = e._job(jid)["version"]
    e.close()
    env = os.environ.copy()
    human = _run(["heal", "collect"], env)
    assert human.returncode == 0, human.stderr
    assert jid in human.stdout and "sha256:" in human.stdout and "blocked" in human.stdout
    assert "written" in human.stdout
    shown = json.loads(_run(["heal", "show", "--json"], env).stdout)
    again_human = _run(["heal", "collect"], env)
    assert again_human.returncode == 0 and "unchanged" in again_human.stdout
    again = json.loads(_run(["heal", "collect", "--json"], env).stdout)
    assert again["written"] is False and again["status"] == "unchanged"
    assert shown["snapshot_id"] == again["snapshot_id"]
    assert again["seen_count"] == 3
    assert [i["sha256"] for i in shown["items"]] == [i["sha256"] for i in again["items"]]
    assert any(i["class"] == "blocked" and i["job_id"] == jid for i in again["items"])
    assert len(again["sha256"]) == 64
    one = json.loads(_run(["heal", "show", shown["snapshot_id"], "--json"], env).stdout)
    assert one["snapshot_id"] == shown["snapshot_id"]
    text = _run(["heal", "show"], env)
    assert again["sha256"] in text.stdout and jid in text.stdout
    e = Engine()
    try:
        row = e._job(jid)
        assert row["phase"] == "blocked" and row["version"] == version and row["mode"] == "fixture"
    finally:
        e.close()


def test_no_healer_role_or_routine():
    assert RESERVED_SOURCES == ("github_review_bot",)
    assert "healer" not in ROLES
    names = {p.name for p in (ROOT / "routines").glob("*.md")}
    assert not any("heal" in name for name in names)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _touch(conn, task_id, ts, **fields):
    cols, args = ["updated_at=?"], [_iso(ts)]
    for key, value in fields.items():
        cols.append(f"{key}=?")
        args.append(value)
    args.append(task_id)
    conn.execute(f"UPDATE tasks SET {', '.join(cols)} WHERE id=?", args)


def _dispatch(conn, job_id, task_id, role, *, now, channel="local", status="accepted", lease_until=None):
    did = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO dispatch_outbox(id,job_id,task_id,attempt,role,channel,idempotency_key,status,"
        "next_attempt_at,lease_until,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (did, job_id, task_id, 1, role, channel, "idem-" + did, status, now, lease_until, _iso(now), _iso(now)))
    conn.execute("UPDATE tasks SET current_dispatch_id=? WHERE id=?", (did, task_id))
    return did


def test_awaiting_resume_uses_a_ten_minute_threshold_and_collect_does_not_wake(eng):
    now = 1_800_000_000.0
    jid = _job(eng.conn, phase="running")
    old = _task(eng.conn, jid, kind="integrate", role="hephaestus", status="awaiting_resume")
    young = _task(eng.conn, jid, kind="plan", role="hephaestus", status="awaiting_resume")
    done = _job(eng.conn, phase="done")
    hidden = _task(eng.conn, done, kind="integrate", role="hephaestus", status="awaiting_resume")
    _touch(eng.conn, old, now - 600)
    _touch(eng.conn, young, now - 599)
    _touch(eng.conn, hidden, now - 86_400)
    before = _dump(eng.conn, "tasks", "id")
    out = collect(eng.conn, "shadow", now=now, stall_awaiting_resume_seconds=600, lease_seconds=1800)
    stalls = [i for i in out["items"] if i["class"] == "stall"]
    assert [i["payload"]["task_id"] for i in stalls] == [old]
    body = stalls[0]["payload"]
    assert body["reason"] == "awaiting_resume" and body["threshold_seconds"] == 600
    assert body["role"] == "hephaestus" and body["source"] == "stall"
    assert "age_seconds" not in body
    assert _dump(eng.conn, "tasks", "id") == before
    assert _count(eng.conn, "SELECT COUNT(*) FROM dispatch_outbox") == 0
    again = collect(eng.conn, "shadow", now=now, stall_awaiting_resume_seconds=600, lease_seconds=1800)
    assert [i["sha256"] for i in again["items"] if i["class"] == "stall"] == [stalls[0]["sha256"]]


def test_healing_off_writes_no_stall_snapshot(eng):
    now = 1_800_000_000.0
    jid = _job(eng.conn, phase="running")
    tid = _task(eng.conn, jid, kind="integrate", role="hephaestus", status="awaiting_resume")
    _touch(eng.conn, tid, now - 3600)
    with pytest.raises(GateRefused, match="healing is off"):
        collect(eng.conn, "off", now=now)
    assert _count(eng.conn, "SELECT COUNT(*) FROM failure_snapshots") == 0


def test_lease_threshold_and_open_dispatch(eng):
    now = 1_800_000_000.0
    jid = _job(eng.conn, phase="running")
    idle = _task(eng.conn, jid, kind="implement", role="executor", status="dispatched")
    fresh = _task(eng.conn, jid, kind="code_review", role="code-reviewer", status="dispatched")
    held = _task(eng.conn, jid, kind="qa", role="qa-executor", status="working")
    expired = _task(eng.conn, jid, kind="explore", role="explorer", status="working")
    stuck = _task(eng.conn, jid, kind="research", role="librarian", status="dispatched")
    _touch(eng.conn, idle, now - 1800)
    _touch(eng.conn, fresh, now - 1799)
    _touch(eng.conn, held, now - 7200, lease_expires_at=now + 10)
    _touch(eng.conn, expired, now - 5, lease_expires_at=now - 1)
    _touch(eng.conn, stuck, now - 5)
    _dispatch(eng.conn, jid, stuck, "librarian", now=now - 5, channel="webhook", status="sending",
              lease_until=now - 1)
    out = collect(eng.conn, "enforce", now=now, stall_awaiting_resume_seconds=600, lease_seconds=1800)
    by_task = {i["payload"]["task_id"]: i["payload"]["reason"] for i in out["items"] if i["class"] == "stall"}
    assert by_task == {idle: "no_progress", expired: "lease_expired", stuck: "dispatch_stuck"}
    assert held not in by_task and fresh not in by_task
