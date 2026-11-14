"""SQLite access: WAL, foreign keys, busy timeout, BEGIN IMMEDIATE with bounded retry,
versioned migrations, consistent backup/restore via the sqlite3 backup API."""
from __future__ import annotations

import contextlib
import hashlib
import os
import random
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

BUSY_TIMEOUT_MS = 5000
TX_RETRIES = 8


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def utcnow_minus(seconds: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def now_ts() -> float:
    return time.time()


MIGRATIONS: list[tuple[int, str, str]] = [
    (1, "core_schema", """
CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  goal TEXT NOT NULL,
  repo_path TEXT,
  mode TEXT NOT NULL CHECK (mode IN ('plan_only','implement','fixture')),
  requirements_json TEXT NOT NULL,
  requirements_hash TEXT NOT NULL,
  phase TEXT NOT NULL,
  blocked_from TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  policies_json TEXT NOT NULL DEFAULT '{}',
  verifier_profile TEXT,
  worktree_path TEXT,
  branch TEXT,
  base_revision TEXT,
  candidate_revision TEXT,
  final_result_revision TEXT,
  current_plan_revision_id TEXT,
  repair_cycles INTEGER NOT NULL DEFAULT 0,
  plan_rounds INTEGER NOT NULL DEFAULT 0,
  assurance TEXT,
  failure_reason TEXT,
  cancel_reason TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE tasks (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  kind TEXT NOT NULL,
  role TEXT NOT NULL,
  status TEXT NOT NULL,
  cycle INTEGER NOT NULL DEFAULT 0,
  priority INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  attempt_no INTEGER NOT NULL DEFAULT 0,
  current_attempt_id TEXT,
  lease_token TEXT,
  lease_expires_at REAL,
  current_dispatch_id TEXT,
  rewake_count INTEGER NOT NULL DEFAULT 0,
  plan_revision_id TEXT,
  candidate_revision TEXT,
  result_json TEXT,
  block_reason TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX tasks_job ON tasks(job_id);
CREATE INDEX tasks_status ON tasks(status);
CREATE TABLE task_deps (
  task_id TEXT NOT NULL REFERENCES tasks(id),
  depends_on TEXT NOT NULL REFERENCES tasks(id),
  PRIMARY KEY (task_id, depends_on)
);
CREATE TABLE task_attempts (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id),
  job_id TEXT NOT NULL REFERENCES jobs(id),
  attempt_no INTEGER NOT NULL,
  dispatch_id TEXT,
  claim_token TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('working','completed','expired','superseded','failed','cancelled')),
  binding_id INTEGER,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  lease_expires_at REAL,
  progress_json TEXT,
  evidence_json TEXT,
  error TEXT,
  UNIQUE (task_id, attempt_no)
);
CREATE TABLE artifacts (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  task_id TEXT REFERENCES tasks(id),
  attempt_id TEXT,
  kind TEXT NOT NULL,
  rel_path TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  revision TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (job_id, rel_path)
);
CREATE TABLE task_inputs (
  task_id TEXT NOT NULL REFERENCES tasks(id),
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  PRIMARY KEY (task_id, artifact_id)
);
CREATE TABLE plan_revisions (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  round INTEGER NOT NULL,
  artifact_id TEXT NOT NULL REFERENCES artifacts(id),
  content_hash TEXT NOT NULL,
  author_role TEXT NOT NULL,
  submitted_at TEXT NOT NULL,
  review_status TEXT NOT NULL DEFAULT 'pending' CHECK (review_status IN ('pending','accepted','rejected','superseded')),
  review_id TEXT,
  criteria_json TEXT,
  UNIQUE (job_id, round)
);
CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  plan_revision_id TEXT NOT NULL REFERENCES plan_revisions(id),
  plan_hash TEXT NOT NULL,
  requirements_hash TEXT NOT NULL,
  scope_json TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('soft','synthetic_fixture','strict')),
  actor TEXT NOT NULL,
  evidence TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  revoke_reason TEXT
);
CREATE TABLE role_bindings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role TEXT NOT NULL,
  version INTEGER NOT NULL,
  bot_id TEXT,
  bot_name TEXT,
  routine_id TEXT,
  routine_name TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  max_concurrent INTEGER NOT NULL DEFAULT 1,
  independence_group TEXT,
  verified_at TEXT,
  provenance TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  UNIQUE (role, version)
);
CREATE TABLE dispatch_outbox (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  task_id TEXT NOT NULL REFERENCES tasks(id),
  attempt INTEGER NOT NULL,
  role TEXT NOT NULL,
  binding_id INTEGER REFERENCES role_bindings(id),
  bot_id TEXT,
  channel TEXT NOT NULL CHECK (channel IN ('webhook','local')),
  idempotency_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('pending','sending','accepted','retry_wait','failed')),
  superseded INTEGER NOT NULL DEFAULT 0,
  http_status INTEGER,
  last_error TEXT,
  retry_count INTEGER NOT NULL DEFAULT 0,
  max_retries INTEGER NOT NULL DEFAULT 5,
  next_attempt_at REAL NOT NULL,
  lease_until REAL,
  sent_at REAL,
  accepted_at REAL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX outbox_due ON dispatch_outbox(status, next_attempt_at);
CREATE TABLE verifications (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  task_id TEXT REFERENCES tasks(id),
  purpose TEXT NOT NULL CHECK (purpose IN ('candidate','final')),
  revision TEXT NOT NULL,
  profile_name TEXT NOT NULL,
  profile_hash TEXT NOT NULL,
  argv_json TEXT NOT NULL,
  env_identity TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running','passed','failed','error')),
  exit_code INTEGER,
  timed_out INTEGER NOT NULL DEFAULT 0,
  stdout_artifact_id TEXT,
  stderr_artifact_id TEXT,
  detail TEXT,
  started_at TEXT NOT NULL,
  ended_at TEXT
);
CREATE TABLE reviews (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  task_id TEXT NOT NULL REFERENCES tasks(id),
  type TEXT NOT NULL CHECK (type IN ('plan','code','qa')),
  reviewer_role TEXT NOT NULL,
  binding_id INTEGER,
  bot_id TEXT,
  independence_group TEXT,
  plan_revision_id TEXT,
  revision TEXT,
  input_hashes_json TEXT NOT NULL,
  findings_json TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('accept','reject')),
  evidence_json TEXT NOT NULL,
  invalidated INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  job_id TEXT,
  task_id TEXT,
  kind TEXT NOT NULL,
  actor TEXT,
  correlation_id TEXT,
  data_json TEXT
);
CREATE INDEX events_job ON events(job_id);
"""),
    (2, "hooks_meta_and_gate_results", """
CREATE TABLE hooks_meta (
  role TEXT PRIMARY KEY,
  configured INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
CREATE TABLE gate_results (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  revision TEXT,
  passed INTEGER NOT NULL,
  assurance TEXT NOT NULL,
  checks_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX outbox_task ON dispatch_outbox(task_id);
CREATE INDEX attempts_task ON task_attempts(task_id);
"""),
    (3, "verification_assurance", """
ALTER TABLE verifications ADD COLUMN assurance TEXT NOT NULL DEFAULT 'none';
"""),
    (4, "verification_sandbox_tamper", """
ALTER TABLE verifications ADD COLUMN sandbox TEXT NOT NULL DEFAULT 'none';
ALTER TABLE verifications ADD COLUMN tamper_json TEXT NOT NULL DEFAULT '[]';
"""),
    (5, "adaptive_orchestration", """
ALTER TABLE jobs ADD COLUMN intent TEXT;
ALTER TABLE jobs ADD COLUMN roster_class TEXT;
ALTER TABLE jobs ADD COLUMN scope_json TEXT;
CREATE TABLE escalations (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  seq INTEGER NOT NULL,
  from_class TEXT NOT NULL,
  to_class TEXT NOT NULL,
  reason TEXT NOT NULL,
  actor TEXT NOT NULL,
  automatic INTEGER NOT NULL DEFAULT 0,
  observed_json TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (job_id, seq)
);
CREATE TABLE tool_receipts (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  task_id TEXT,
  kind TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('engine_executed','engine_reverified','engine_delivered')),
  status TEXT NOT NULL,
  revision TEXT,
  tool TEXT NOT NULL,
  tool_version TEXT,
  argv_sha256 TEXT,
  config_sha256 TEXT,
  input_sha256 TEXT,
  output_sha256 TEXT,
  artifact_ids_json TEXT NOT NULL DEFAULT '[]',
  summary_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);
CREATE INDEX receipts_job ON tool_receipts(job_id, kind);
CREATE TABLE work_sessions (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  task_id TEXT NOT NULL REFERENCES tasks(id),
  attempt_id TEXT NOT NULL UNIQUE,
  session_token TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL,
  bot_id TEXT,
  started_at TEXT NOT NULL
);
CREATE INDEX sessions_job ON work_sessions(job_id);
CREATE TABLE boulder_projection (
  job_id TEXT PRIMARY KEY REFERENCES jobs(id),
  generation INTEGER NOT NULL,
  sha256 TEXT,
  pending_sha256 TEXT,
  plan_sha256 TEXT,
  pending_plan_sha256 TEXT,
  status TEXT NOT NULL,
  last_error TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE repo_leases (
  repo_path TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  acquired_at TEXT NOT NULL
);
"""),
    (6, "failure_snapshots", """
CREATE TABLE failure_snapshots (
  id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL UNIQUE,
  mode TEXT NOT NULL CHECK (mode IN ('shadow','enforce')),
  item_count INTEGER NOT NULL,
  corpus_sha256 TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE failure_items (
  snapshot_id TEXT NOT NULL REFERENCES failure_snapshots(id),
  ordinal INTEGER NOT NULL,
  item_sha256 TEXT NOT NULL,
  class TEXT NOT NULL,
  source TEXT NOT NULL,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  task_id TEXT REFERENCES tasks(id),
  payload_json TEXT NOT NULL,
  PRIMARY KEY (snapshot_id, ordinal)
);
CREATE INDEX failure_items_job ON failure_items(job_id);
"""),
    (7, "failure_snapshot_seen", """
ALTER TABLE failure_snapshots ADD COLUMN seen_count INTEGER NOT NULL DEFAULT 1;
ALTER TABLE failure_snapshots ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT '';
UPDATE failure_snapshots SET last_seen_at = created_at WHERE last_seen_at = '';
"""),
]

LATEST_VERSION = MIGRATIONS[-1][0]


def migration_checksum(sql: str) -> str:
    return hashlib.sha256(sql.encode()).hexdigest()


def connect(db_path: Path | str) -> sqlite3.Connection:
    db_path = Path(db_path)
    new = not db_path.exists()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=BUSY_TIMEOUT_MS / 1000, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys=ON")
    mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    if mode.lower() != "wal":  # pragma: no cover - filesystem dependent
        conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=NORMAL")
    if new:
        os.chmod(db_path, 0o600)
    return conn


@contextlib.contextmanager
def tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Short write transaction (BEGIN IMMEDIATE) with bounded retry on SQLITE_BUSY at BEGIN.

    Never hold this across HTTP or subprocess calls."""
    for i in range(TX_RETRIES):
        try:
            conn.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as e:
            if "locked" not in str(e) and "busy" not in str(e):
                raise
            if i == TX_RETRIES - 1:
                raise
            time.sleep(min(0.05 * (2 ** i), 1.0) + random.random() * 0.05)
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def current_version(conn: sqlite3.Connection) -> int:
    conn.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)""")
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    return row[0] or 0


def pending_migrations(conn: sqlite3.Connection, target: int | None = None) -> list[tuple[int, str, str]]:
    cur = current_version(conn)
    target = LATEST_VERSION if target is None else target
    return [m for m in MIGRATIONS if cur < m[0] <= target]


def migrate(conn: sqlite3.Connection, target: int | None = None, dry_run: bool = False) -> list[int]:
    """Apply pending migrations, each in its own IMMEDIATE transaction. Verifies checksums of applied ones."""
    applied = {r["version"]: r["checksum"] for r in conn.execute("SELECT version, checksum FROM schema_migrations")} \
        if current_version(conn) else {}
    for v, _n, sql in MIGRATIONS:
        if v in applied and applied[v] != migration_checksum(sql):
            raise RuntimeError(f"migration {v} checksum mismatch: database was migrated by different code")
    todo = pending_migrations(conn, target)
    if dry_run:
        return [m[0] for m in todo]
    done = []
    for v, name, sql in todo:
        with tx(conn):
            # re-check inside the write lock: another process may have migrated concurrently
            if conn.execute("SELECT 1 FROM schema_migrations WHERE version=?", (v,)).fetchone():
                continue
            for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                conn.execute(stmt)
            conn.execute("INSERT INTO schema_migrations(version,name,checksum,applied_at) VALUES (?,?,?,?)",
                         (v, name, migration_checksum(sql), utcnow()))
        done.append(v)
    return done


def backup(conn: sqlite3.Connection, dest: Path | str) -> Path:
    """Consistent online backup via the sqlite3 backup API; result is integrity-checked."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    out = sqlite3.connect(str(dest))
    try:
        conn.backup(out)
        ok = out.execute("PRAGMA integrity_check").fetchone()[0]
        if ok != "ok":
            raise RuntimeError(f"backup integrity_check failed: {ok}")
    finally:
        out.close()
    os.chmod(dest, 0o600)
    return dest


def restore(backup_path: Path | str, db_path: Path | str) -> None:
    """Restore a backup into db_path using the backup API (destination must not be in use)."""
    from .errors import IntegrityError_
    src = sqlite3.connect(str(backup_path))
    try:
        try:
            ok = src.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        except sqlite3.DatabaseError as e:
            raise IntegrityError_("backup file is not a readable SQLite database", error=type(e).__name__) from None
        if not ok:
            raise IntegrityError_("backup file failed integrity_check")
        dst = sqlite3.connect(str(db_path))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
