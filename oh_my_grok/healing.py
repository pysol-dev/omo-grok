"""Failure-corpus projection (spec/HEALING.md).

Like the boulder file, a snapshot is derived and is never read back to decide a transition. ``collect`` reads jobs,
rejected reviews, ``repair_cycle`` events, and stalled tasks. It reads ``failure_snapshots`` only to compare the
latest corpus hash: an unchanged item set bumps ``seen_count`` and ``last_seen_at`` on that row instead of inserting
another snapshot. The item set itself is never taken from stored rows. A new snapshot also writes one
``failures_collected`` audit event with a null job id, so no job is marked dirty and no boulder is flushed. An
unchanged collect does not append that event. Stall rows are a projection: collect does not wake a Bot and does not
change a task.

``prune_duplicates`` is an operator command. Collect and the watchdog never call it.

``github_review_bot`` is reserved for a later slice and is not read.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from datetime import UTC, datetime

from . import db, features
from .config import canonical_json, sha256_text
from .errors import GateRefused, NotFound, ValidationError

RESERVED_SOURCES = ("github_review_bot",)
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _keep(fields: dict) -> dict:
    return {k: v for k, v in fields.items() if v is not None}


def _obj(raw) -> dict:
    if not raw:
        return {}
    try:
        val = json.loads(raw)
    except ValueError:
        return {}
    return val if isinstance(val, dict) else {}


def _findings(raw) -> dict:
    try:
        val = json.loads(raw) if raw else []
    except ValueError:
        return {"findings_unparsed": raw}
    return {"findings": val}


def _identity(body: dict) -> str:
    if "event_id" in body:
        return str(body["event_id"])
    if "event_ids" in body:
        return ",".join(str(i) for i in body["event_ids"])
    if "review_id" in body:
        return str(body["review_id"])
    if "record" in body:
        return str(body["record"])
    if "task_id" in body:
        return str(body["task_id"])
    return str(body["job_id"])


def _whole(seconds: float) -> int | float:
    value = float(seconds)
    return int(value) if value.is_integer() else value


def _age_seconds(iso: str | None, now: float) -> float | None:
    """Wall-clock age of a ``db.utcnow`` timestamp. ``None`` when the text is missing or unparseable."""
    if not iso or not isinstance(iso, str):
        return None
    text = iso[:-1] + "+00:00" if iso.endswith("Z") else iso
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return now - parsed.timestamp()


def _dispatch_stuck(row, now: float, lease_seconds: float) -> bool:
    if row["d_status"] not in ("pending", "sending", "retry_wait") or row["d_superseded"]:
        return False
    if row["d_lease_until"] is not None and float(row["d_lease_until"]) <= now:
        return True
    age = _age_seconds(row["d_updated_at"], now)
    return age is not None and age >= float(lease_seconds)


def find_stalls(conn, *, now: float, stall_awaiting_resume_seconds: float, lease_seconds: float) -> list[dict]:
    """Non-terminal tasks with no progress. Read-only.

    ``awaiting_resume`` uses ``stall_awaiting_resume_seconds`` (default 10 minutes). Every other open status uses
    the lease: a working task with an unexpired lease is not a stall; an open dispatch past its lease is
    ``dispatch_stuck``; anything else idle for ``lease_seconds`` is ``no_progress``. Ages are not part of the body,
    so a later collect of the same stall hashes the same.
    """
    rows = conn.execute(
        "SELECT t.id, t.job_id, t.role, t.status, t.updated_at, t.lease_expires_at, t.current_dispatch_id, "
        "d.channel AS d_channel, d.status AS d_status, d.lease_until AS d_lease_until, "
        "d.updated_at AS d_updated_at, d.superseded AS d_superseded "
        "FROM tasks t JOIN jobs j ON j.id=t.job_id "
        "LEFT JOIN dispatch_outbox d ON d.id=t.current_dispatch_id "
        "WHERE t.status IN ('queued','dispatched','awaiting_resume','working','submitted') "
        "AND j.phase NOT IN ('done','failed','cancelled','blocked') ORDER BY t.id").fetchall()
    found = []
    for row in rows:
        status = row["status"]
        age = _age_seconds(row["updated_at"], now)
        if (status == "working" and row["lease_expires_at"] is not None
                and float(row["lease_expires_at"]) > now):
            continue
        reason, threshold = None, None
        if status == "awaiting_resume":
            if age is not None and age >= float(stall_awaiting_resume_seconds):
                reason, threshold = "awaiting_resume", stall_awaiting_resume_seconds
        elif (status == "working" and row["lease_expires_at"] is not None
              and float(row["lease_expires_at"]) <= now):
            reason, threshold = "lease_expired", lease_seconds
        elif _dispatch_stuck(row, now, lease_seconds):
            reason, threshold = "dispatch_stuck", lease_seconds
        elif status != "awaiting_resume" and age is not None and age >= float(lease_seconds):
            reason, threshold = "no_progress", lease_seconds
        if reason is None or threshold is None:
            continue
        found.append(_keep({
            "class": "stall", "source": "stall", "job_id": row["job_id"], "task_id": row["id"],
            "role": row["role"], "status": status, "reason": reason,
            "threshold_seconds": _whole(threshold), "dispatch_id": row["current_dispatch_id"],
            "channel": row["d_channel"]}))
    return found


def _blocked(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT id, phase, blocked_from, failure_reason FROM jobs WHERE phase='blocked' ORDER BY id").fetchall()
    return [_keep({"class": "blocked", "source": "blocked_job", "job_id": r["id"], "phase": r["phase"],
                    "blocked_from": r["blocked_from"], "failure_reason": r["failure_reason"]}) for r in rows]


def _repairs(conn) -> tuple[list[dict], dict[str, list[int]]]:
    rows = conn.execute(
        "SELECT e.id, e.job_id, e.task_id, e.data_json FROM events e JOIN jobs j ON j.id=e.job_id "
        "WHERE e.kind='repair_cycle' ORDER BY e.id").fetchall()
    bodies, by_job, seen = [], {}, set()
    for r in rows:
        data = _obj(r["data_json"])
        bodies.append(_keep({
            "class": "repair", "source": "repair_cycle", "job_id": r["job_id"], "event_id": r["id"],
            "task_id": r["task_id"], "failures": data.get("failures"), "reason": data.get("reason"),
            "max": data.get("max")}))
        by_job.setdefault(r["job_id"], []).append(r["id"])
        seen.add(r["job_id"])
    # The counter is not cleared when a job later succeeds. If the log has no repair_cycle event, the counter
    # itself is the record.
    for r in conn.execute("SELECT id, repair_cycles FROM jobs WHERE repair_cycles>0 ORDER BY id"):
        if r["id"] in seen:
            continue
        bodies.append({"class": "repair", "source": "repair_cycle", "job_id": r["id"],
                        "failures": r["repair_cycles"], "record": "jobs.repair_cycles"})
    return bodies, by_job


def _repeated(by_job: dict[str, list[int]]) -> list[dict]:
    out = []
    for job_id, event_ids in by_job.items():
        if len(event_ids) < 2:
            continue
        ids = sorted(event_ids)
        out.append({"class": "repeated", "source": "repeated_failure", "job_id": job_id,
                     "count": len(ids), "event_ids": ids})
    return out


def _reviews(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT id, job_id, task_id, type, revision, plan_revision_id, findings_json, invalidated "
        "FROM reviews WHERE verdict='reject' ORDER BY id").fetchall()
    out = []
    for r in rows:
        body = _keep({"class": "review", "source": "review_finding", "job_id": r["job_id"], "review_id": r["id"],
                       "task_id": r["task_id"], "type": r["type"], "revision": r["revision"],
                       "plan_revision_id": r["plan_revision_id"], "invalidated": bool(r["invalidated"])})
        body.update(_findings(r["findings_json"]))
        out.append(body)
    return out


def _project(conn, *, now: float, stall_awaiting_resume_seconds: float, lease_seconds: float) -> list[dict]:
    repairs, by_job = _repairs(conn)
    bodies = [*_blocked(conn), *repairs, *_repeated(by_job), *_reviews(conn),
              *find_stalls(conn, now=now, stall_awaiting_resume_seconds=stall_awaiting_resume_seconds,
                           lease_seconds=lease_seconds)]
    bodies.sort(key=lambda b: (b["class"], b["job_id"], b["source"], _identity(b)))
    items = [{"ordinal": n, "sha256": sha256_text(canonical_json(body)), "class": body["class"],
              "source": body["source"], "job_id": body["job_id"], "payload": body} for n, body in enumerate(bodies)]
    reserved = [i["source"] for i in items if i["source"] in RESERVED_SOURCES]
    if reserved:
        raise ValidationError("reserved healing source was collected", sources=sorted(set(reserved)))
    return items


def _corpus(items: list[dict]) -> str:
    return sha256_text(canonical_json([i["sha256"] for i in items]))


def _fingerprint(items: list[dict]) -> str:
    """Stable id of the projected item set.

    Item hashes cover the payload only. Snapshot ids, ``created_at``, ``last_seen_at``, and ``seen_count`` are
    assigned per collect and are not inputs, so a later collect of the same sources hashes the same.
    """
    return _corpus(items)


def _result(row, items: list[dict], corpus: str, *, written: bool, seen_count: int, last_seen_at: str) -> dict:
    status = "written" if written else "unchanged"
    return {"written": written, "unchanged": not written, "status": status, "mode": row["mode"],
            "snapshot_id": row["id"], "seq": row["seq"], "sha256": corpus, "corpus_sha256": corpus,
            "fingerprint": corpus, "item_count": len(items), "items": items, "seen_count": seen_count,
            "last_seen_at": last_seen_at, "created_at": row["created_at"]}


def collect(conn, mode: str, *, now: float | None = None, stall_awaiting_resume_seconds: float = 600,
            lease_seconds: float = 1800) -> dict:
    """Record the current corpus. ``off`` raises and writes nothing. ``shadow`` and ``enforce`` do not enqueue.

    A new snapshot is inserted only when the item-set fingerprint differs from the latest snapshot. The same set
    bumps ``seen_count`` and ``last_seen_at`` on that snapshot and does not append another audit event.

    Stall ages use wall-clock ``now`` (default ``time.time()``), not the engine's test clock, so a harness that
    freezes leases does not mark every fresh task stalled.
    """
    if mode == features.OFF:
        raise GateRefused("healing is off; collect writes nothing")
    if mode not in (features.SHADOW, features.ENFORCE):
        raise ValidationError("healing collect mode must be shadow or enforce", mode=mode)
    if now is None:
        now = time.time()
    with db.tx(conn):
        items = _project(conn, now=now, stall_awaiting_resume_seconds=stall_awaiting_resume_seconds,
                         lease_seconds=lease_seconds)
        corpus = _fingerprint(items)
        latest = conn.execute(
            "SELECT id, seq, mode, corpus_sha256, created_at, seen_count FROM failure_snapshots "
            "ORDER BY seq DESC LIMIT 1").fetchone()
        if latest is not None and latest["corpus_sha256"] == corpus:
            seen = int(latest["seen_count"]) + 1
            seen_at = db.utcnow()
            conn.execute("UPDATE failure_snapshots SET seen_count=?, last_seen_at=? WHERE id=?",
                         (seen, seen_at, latest["id"]))
            return _result(latest, items, corpus, written=False, seen_count=seen, last_seen_at=seen_at)
        seq = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM failure_snapshots").fetchone()[0] + 1
        sid = str(uuid.uuid4())
        created = db.utcnow()
        conn.execute(
            "INSERT INTO failure_snapshots(id,seq,mode,item_count,corpus_sha256,created_at,seen_count,last_seen_at) "
            "VALUES (?,?,?,?,?,?,?,?)", (sid, seq, mode, len(items), corpus, created, 1, created))
        for item in items:
            conn.execute(
                "INSERT INTO failure_items(snapshot_id,ordinal,item_sha256,class,source,job_id,task_id,payload_json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (sid, item["ordinal"], item["sha256"], item["class"], item["source"], item["job_id"],
                 item["payload"].get("task_id"), canonical_json(item["payload"])))
        conn.execute("INSERT INTO events(ts,job_id,task_id,kind,actor,correlation_id,data_json) "
                     "VALUES (?,?,?,?,?,?,?)",
                     (db.utcnow(), None, None, "failures_collected", "engine", sid,
                      canonical_json({"corpus_sha256": corpus, "item_count": len(items), "mode": mode,
                                      "snapshot_id": sid})))
        row = {"id": sid, "seq": seq, "mode": mode, "created_at": created}
    return _result(row, items, corpus, written=True, seen_count=1, last_seen_at=created)


def prune_duplicates(conn, *, apply: bool = False) -> dict:
    """Collapse consecutive snapshots that share a corpus hash, keeping the first of each run.

    Default is a dry run. ``apply=True`` deletes the later rows in each run and their items, and stores the summed
    ``seen_count`` and the latest ``last_seen_at`` on the kept row. A later non-adjacent run of the same hash is
    kept. This is never invoked by ``collect`` or the watchdog.
    """
    def plan():
        rows = list(conn.execute(
            "SELECT id, seq, corpus_sha256, seen_count, last_seen_at, created_at "
            "FROM failure_snapshots ORDER BY seq"))
        groups: list[list] = []
        for row in rows:
            if groups and groups[-1][0]["corpus_sha256"] == row["corpus_sha256"]:
                groups[-1].append(row)
            else:
                groups.append([row])
        collapsed, removed = [], []
        for group in groups:
            if len(group) < 2:
                continue
            stamps = [(r["last_seen_at"] or r["created_at"]) for r in group]
            collapsed.append({
                "snapshot_id": group[0]["id"], "seq": group[0]["seq"],
                "corpus_sha256": group[0]["corpus_sha256"],
                "seen_count": sum(int(r["seen_count"] or 1) for r in group),
                "last_seen_at": max(stamps), "removed": len(group) - 1})
            removed.extend(r["id"] for r in group[1:])
        return rows, collapsed, removed

    def report(rows, collapsed, removed, *, applied: bool) -> dict:
        before = len(rows)
        deleted = len(removed) if applied else 0
        return {"dry_run": not applied, "applied": applied, "would_delete": len(removed), "deleted": deleted,
                "removed_ids": list(removed), "kept_count": before - len(removed),
                "snapshots_before": before, "snapshots_after": before - deleted, "collapsed": collapsed}

    if not apply:
        rows, collapsed, removed = plan()
        return report(rows, collapsed, removed, applied=False)
    with db.tx(conn):
        rows, collapsed, removed = plan()
        for group in collapsed:
            conn.execute("UPDATE failure_snapshots SET seen_count=?, last_seen_at=? WHERE id=?",
                         (group["seen_count"], group["last_seen_at"], group["snapshot_id"]))
        for sid in removed:
            conn.execute("DELETE FROM failure_items WHERE snapshot_id=?", (sid,))
            conn.execute("DELETE FROM failure_snapshots WHERE id=?", (sid,))
        return report(rows, collapsed, removed, applied=True)


def show(conn, snapshot_id: str | None = None) -> dict:
    """Read a snapshot. Does not write. Does not consult the flag: a snapshot already taken stays readable."""
    if snapshot_id is not None and not _UUID.match(snapshot_id):
        raise ValidationError("snapshot_id must be a UUID")
    if snapshot_id is None:
        row = conn.execute("SELECT * FROM failure_snapshots ORDER BY seq DESC LIMIT 1").fetchone()
        if row is None:
            raise NotFound("no failure snapshot")
    else:
        row = conn.execute("SELECT * FROM failure_snapshots WHERE id=?", (snapshot_id,)).fetchone()
        if row is None:
            raise NotFound("failure snapshot not found", snapshot_id=snapshot_id)
    items = []
    for r in conn.execute("SELECT ordinal, item_sha256, class, source, job_id, payload_json FROM failure_items "
                          "WHERE snapshot_id=? ORDER BY ordinal", (row["id"],)):
        items.append({"ordinal": r["ordinal"], "sha256": r["item_sha256"], "class": r["class"],
                      "source": r["source"], "job_id": r["job_id"], "payload": json.loads(r["payload_json"])})
    last_seen = row["last_seen_at"] or row["created_at"]
    return {"snapshot_id": row["id"], "seq": row["seq"], "mode": row["mode"], "sha256": row["corpus_sha256"],
            "corpus_sha256": row["corpus_sha256"], "fingerprint": row["corpus_sha256"],
            "item_count": row["item_count"], "created_at": row["created_at"], "seen_count": row["seen_count"],
            "last_seen_at": last_seen, "items": items}
