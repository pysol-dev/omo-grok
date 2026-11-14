"""Slice 1 against a real fixture job, and the read-only MCP heal tool (no healer binding)."""
import asyncio
import json
import os
import subprocess
from pathlib import Path

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[2]
OMG = str(ROOT / "omg")
PY = str(ROOT / ".venv" / "bin" / "python")
SERVER = str(ROOT / "oh_my_grok" / "mcp_server.py")


def _run(args):
    return subprocess.run([OMG, *args], capture_output=True, text=True, env=os.environ.copy(), timeout=120)


def _policy(mode):
    path = Path(os.environ["OMG_CONFIG_DIR"]) / "policy.json"
    data = json.loads(path.read_text())
    data["features"] = {"healing": mode}
    path.write_text(json.dumps(data))


def _params():
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "OMG_HOME", "OMO_HOME",
                                                        "OMG_CONFIG_DIR", "OMO_CONFIG_DIR")}
    return StdioServerParameters(command=PY, args=[SERVER], env=env)


def test_later_success_with_one_repair_stays_in_the_corpus(harness):
    """A fixture job that failed once and then reached done is still in the corpus. Collect does not touch it."""
    h = harness
    job = h.submit()["job_id"]
    h.to_approval(job)
    h.approve(job)
    h.implement(job, fix="fake")
    assert h.e.status(job)["repair_cycles"] == 1 and h.e.status(job)["phase"] == "running"
    h.implement(job)
    h.review(job, "code_review")
    h.review(job, "qa")
    _, res = h.integrate(job)
    assert res["final_gate"]["passed"] is True
    assert h.e.status(job)["phase"] == "done" and h.e.status(job)["repair_cycles"] == 1
    assert h.e._features(h.e._job(job))["healing"] == "off"
    version = h.e._job(job)["version"]
    before = [r["kind"] for r in h.e._all("SELECT kind FROM events ORDER BY id")]
    _policy("shadow")
    human = _run(["heal", "collect"])
    assert human.returncode == 0, human.stderr
    assert job in human.stdout and "sha256:" in human.stdout
    first = json.loads(_run(["heal", "show", "--json"]).stdout)
    assert len(first["sha256"]) == 64
    own = [i for i in first["items"] if i["job_id"] == job]
    assert len(own) == 1 and own[0]["class"] == "repair"
    second = json.loads(_run(["heal", "collect", "--json"]).stdout)
    assert second["written"] is False and second["status"] == "unchanged"
    assert second["snapshot_id"] == first["snapshot_id"]
    assert second["seen_count"] == 2
    assert [i["sha256"] for i in second["items"]] == [i["sha256"] for i in first["items"]]
    assert "unchanged" in _run(["heal", "collect"]).stdout
    assert second["sha256"] in _run(["heal", "show"]).stdout
    row = h.e._job(job)
    assert row["phase"] == "done" and row["repair_cycles"] == 1 and row["version"] == version
    after = [r["kind"] for r in h.e._all("SELECT kind FROM events ORDER BY id")]
    assert after[:len(before)] == before
    assert after[len(before):] == ["failures_collected"]


def _count_new_work(h, job):
    return h.e._one("SELECT COUNT(*) c FROM tasks WHERE job_id=?", (job,))["c"]


def test_collect_does_not_enqueue_a_fix_for_a_repaired_fixture(harness):
    h = harness
    job = h.submit()["job_id"]
    h.to_approval(job)
    h.approve(job)
    for _ in range(3):
        h.implement(job, fix="fake")
    assert h.e.status(job)["phase"] == "blocked"
    tasks_before = _count_new_work(h, job)
    outbox_before = h.e._one("SELECT COUNT(*) c FROM dispatch_outbox WHERE job_id=?", (job,))["c"]
    _policy("enforce")
    out = json.loads(_run(["heal", "collect", "--json"]).stdout)
    assert out["mode"] == "enforce" and out["written"] is True
    assert any(i["class"] == "blocked" and i["job_id"] == job for i in out["items"])
    assert any(i["class"] == "repair" and i["job_id"] == job for i in out["items"])
    assert any(i["class"] == "repeated" and i["job_id"] == job for i in out["items"])
    assert h.e.status(job)["phase"] == "blocked"
    assert _count_new_work(h, job) == tasks_before
    assert h.e._one("SELECT COUNT(*) c FROM dispatch_outbox WHERE job_id=?", (job,))["c"] == outbox_before


async def _collect(errlog):
    async with stdio_client(_params(), errlog=errlog) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = await s.list_tools()
            heal = next(t for t in tools.tools if t.name == "heal")
            result = await s.call_tool("heal", {"action": "collect"})
            return {t.name for t in tools.tools}, set(heal.input_schema.get("required") or []), result


def _payload(res):
    assert res.content and not res.is_error, res
    return res.structured_content or json.loads(res.content[0].text)


def _blocked_fixture(conn):
    import uuid
    from oh_my_grok import db
    jid = str(uuid.uuid4())
    now = db.utcnow()
    conn.execute(
        "INSERT INTO jobs(id,idempotency_key,goal,mode,requirements_json,requirements_hash,phase,blocked_from,"
        "version,policies_json,repair_cycles,plan_rounds,failure_reason,created_at,updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,1,'{}',?,?,?,?,?)",
        (jid, "k-" + jid, "goal", "fixture", '{"goal":"g"}', "h" * 64, "blocked", "running",
         0, 0, "stuck", now, now))
    return jid


def test_mcp_stdio_lists_heal_and_collects_without_a_healer_binding(omg_home, tmp_path):
    from oh_my_grok.engine import Engine
    _policy("enforce")
    e = Engine()
    jid = _blocked_fixture(e.conn)
    assert all(not b["bound"] for b in e.list_bindings())
    assert e._one("SELECT 1 FROM role_bindings WHERE role='healer'") is None
    version = e._job(jid)["version"]
    e.close()
    with open(tmp_path / "stderr.log", "w") as errlog:
        names, required, res = asyncio.run(_collect(errlog))
    assert "heal" in names
    assert "role" not in required and "binding" not in required
    body = _payload(res)
    assert body["written"] is True and body["mode"] == "enforce"
    assert any(i["class"] == "blocked" and i["job_id"] == jid for i in body["items"])
    e = Engine()
    try:
        assert e._job(jid)["phase"] == "blocked" and e._job(jid)["version"] == version
        assert [r["kind"] for r in e._all("SELECT kind FROM events")] == ["failures_collected"]
    finally:
        e.close()


def test_mcp_heal_off_refuses_without_writing(omg_home, tmp_path):
    from oh_my_grok.engine import Engine
    e = Engine()
    e.close()
    with open(tmp_path / "stderr.log", "w") as errlog:
        _names, _required, res = asyncio.run(_collect(errlog))
    assert res.is_error
    text = res.content[0].text
    assert "healing is off" in text or "gate_refused" in text
    e = Engine()
    try:
        assert e._one("SELECT COUNT(*) c FROM failure_snapshots")["c"] == 0
        assert e._one("SELECT COUNT(*) c FROM events WHERE kind='failures_collected'")["c"] == 0
    finally:
        e.close()
