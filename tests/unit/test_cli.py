"""§10 item 1: CLI starts, has all documented subcommands, no missing imports; argument validation; TTY gates."""
import importlib
import json
import os
import pkgutil
import pty
import select
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
OMG_CLI = str(ROOT / "omg")
DOCUMENTED = [["features"], ["boulder"], ["receipts"], ["docs"], ["attest"], ["lsp", "status"], ["lsp", "canary"], ["lsp", "check"], ["heal", "collect"], ["heal", "show"], ["heal", "prune-duplicates"], ["doctor"], ["migrate"], ["status"], ["submit"], ["plan", "show"], ["approve"], ["deny"], ["cancel"],
              ["watchdog", "run"], ["watchdog", "start"], ["watchdog", "stop"], ["watchdog", "status"], ["watchdog", "ensure"],
              ["reconcile"], ["hook", "set"], ["hook", "check"], ["hook", "list"], ["hook", "serve"], ["test"], ["export"],
              ["resume"], ["backup"], ["restore"], ["roles", "list"], ["roles", "bind"], ["roles", "import"]]


def run(args, env=None, input_=None):
    return subprocess.run([OMG_CLI, *args], capture_output=True, text=True, env=env, input=input_, timeout=120)


def test_omoctl_shim_execs_the_omg_cli():
    shim = subprocess.run([str(ROOT / "omoctl"), "--version"], capture_output=True, text=True, timeout=60)
    direct = subprocess.run([OMG_CLI, "--version"], capture_output=True, text=True, timeout=60)
    assert direct.returncode == 0, direct.stderr
    assert shim.returncode == 0, shim.stderr
    assert direct.stdout == shim.stdout
    assert direct.stdout.startswith("omg ")


def test_every_module_imports():
    import oh_my_grok
    for m in pkgutil.iter_modules(oh_my_grok.__path__):
        importlib.import_module(f"oh_my_grok.{m.name}")


def test_top_level_help_lists_all_subcommands():
    r = run(["--help"])
    assert r.returncode == 0
    for c in ["doctor", "migrate", "status", "submit", "plan", "approve", "deny", "cancel", "reconcile", "hook",
              "test", "export", "watchdog"]:
        assert c in r.stdout


@pytest.mark.parametrize("cmd", DOCUMENTED, ids=lambda c: " ".join(c))
def test_each_subcommand_help(cmd):
    r = run([*cmd, "--help"])
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("args", [["approve", "J"], ["submit"], ["hook", "set", "nobody"], ["bogus"],
                                  ["deny", "J"], ["export", "J"]])
def test_argument_validation_exit_2(args):
    assert run(args).returncode == 2


def test_doctor_and_migrate_in_isolated_home(omg_home):
    env = dict(os.environ)
    r = run(["migrate", "--dry-run", "--json"], env=env)
    assert r.returncode == 0 and json.loads(r.stdout)["pending"] == [1, 2, 3, 4, 5, 6, 7]
    assert run(["migrate"], env=env).returncode == 0
    r = run(["doctor", "--json"], env=env)
    d = json.loads(r.stdout)
    assert r.returncode == 0, [c for c in d["checks"] if not c["ok"]]
    assert "NOT OPERATIONAL" in d["live_status"]


def test_invalid_ids_give_stable_codes(omg_home):
    env = dict(os.environ)
    r = run(["status", "not-a-uuid", "--json"], env=env)
    assert r.returncode == 2 and json.loads(r.stdout)["code"] == "invalid_input"
    r = run(["status", "00000000-0000-4000-8000-000000000000"], env=env)
    assert r.returncode == 3


def test_live_without_fixture_only_refused(omg_home):
    assert run(["test", "live"], env=dict(os.environ)).returncode == 2


def test_live_fixture_only_reports_not_run_without_prereqs(omg_home):
    r = run(["test", "live", "--fixture-only", "--json"], env=dict(os.environ))
    assert r.returncode == 9
    assert json.loads(r.stdout)["result"] == "NOT RUN"


def _pty_run(args, answers, env):
    """Run omg under a real pseudo-terminal, typing answers when prompts appear."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(OMG_CLI, [OMG_CLI, *args], env)
    out = b""
    answers = list(answers)
    deadline = time.time() + 60
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if answers and (out.rstrip().endswith(b":")):
                os.write(fd, answers.pop(0).encode() + b"\n")
                out += b"<ANSWERED>"
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode(errors="replace")


def test_approve_requires_tty_and_records_soft_receipt(harness, omg_home):
    job = harness.submit()["job_id"]
    ph = harness.to_approval(job)
    env = dict(os.environ)
    # piped stdin (no TTY) -> refused, exit 7, nothing recorded
    r = run(["approve", job, "--plan-hash", ph], env=env, input_=ph[:12] + "\n")
    assert r.returncode == 7
    assert harness.e._one("SELECT COUNT(*) c FROM approvals")["c"] == 0
    # wrong confirmation under a TTY -> refused
    code, out = _pty_run(["approve", job, "--plan-hash", ph, "--no-edit"], ["nope"], env)
    assert code == 7
    # correct confirmation under a TTY -> soft approval recorded
    code, out = _pty_run(["approve", job, "--plan-hash", ph, "--no-edit"], [ph[:12]], env)
    assert code == 0, out
    ap = harness.e._one("SELECT * FROM approvals")
    assert ap["mode"] == "soft" and ap["plan_hash"] == ph and "tty" in ap["evidence"].lower()
    assert "SOFT" in out


def test_hook_set_uses_hidden_prompt_and_never_echoes(omg_home):
    env = dict(os.environ)
    secret = "whk_TOPSECRET_abcdef0123456789"
    code, out = _pty_run(["hook", "set", "explorer"], ["https://hooks.invalid/x", secret], env)
    assert code == 0, out
    assert secret not in out
    hooks = Path(omg_home) / "state" / "secrets" / "hooks.json"
    assert oct(hooks.stat().st_mode & 0o777) == "0o600"
    assert oct(hooks.parent.stat().st_mode & 0o777) == "0o700"
    r = run(["hook", "list", "--json"], env=env)
    assert json.loads(r.stdout)["explorer"] is True and secret not in r.stdout and "hooks.invalid" not in r.stdout
    r = run(["hook", "check", "explorer", "--json"], env=env)
    assert r.returncode == 0 and secret not in r.stdout and "hooks.invalid" not in r.stdout


def test_doctor_state_is_derived_from_evidence_and_attest_needs_a_tty(omg_home):
    env = dict(os.environ)
    assert run(["migrate"], env=env).returncode == 0
    d = json.loads(run(["doctor", "--json"], env=env).stdout)
    assert d["live_status"].startswith("NOT OPERATIONAL")
    assert set(d["info"]["operational_criteria"]) == {"real_job_gate_with_lsp_and_git_receipts", "host_cutover",
                                                      "live_smoke", "live_e2e"}
    r = run(["attest", "host_cutover", "--statement", "x"], env=env, input_="ATTEST\n")
    assert r.returncode == 7 and "TTY" in r.stderr, "piped input can never record an attestation"
    assert json.loads(run(["doctor", "--json"], env=env).stdout)["live_status"].startswith("NOT OPERATIONAL")


def test_features_command_shows_defaults_all_off(omg_home):
    env = dict(os.environ)
    assert run(["migrate"], env=env).returncode == 0
    d = json.loads(run(["features", "--json"], env=env).stdout)
    assert set(d["configured"].values()) == {"off"}


# The synthetic calc fixture's real fix is one line in calc/__init__.py.
FIXTURE_SCOPE = {"files_estimate": 1, "new_dependency": False, "external_api": False,
                 "security_sensitive": False, "cross_cutting": False}


def _features(mode_map):
    cfg = Path(os.environ["OMG_CONFIG_DIR"])
    pol = json.loads((cfg / "policy.json").read_text())
    pol["features"] = mode_map
    (cfg / "policy.json").write_text(json.dumps(pol))


def _goal(tmp_path, name="goal.md"):
    p = tmp_path / name
    p.write_text("Fix calc.add so the fixture unittest suite passes.\n")
    return str(p)


def _scope_file(tmp_path, payload, name="scope.json"):
    p = tmp_path / name
    p.write_text(payload if isinstance(payload, str) else json.dumps(payload))
    return str(p)


def _json_error(result):
    assert result.returncode == 2, result.stderr
    assert result.stdout.strip(), result.stderr
    body = json.loads(result.stdout)
    assert body["code"] == "invalid_input"
    return body


def test_submit_without_intent_when_roster_off_keeps_the_original_job(omg_home, tmp_path):
    r = run(["submit", "--goal-file", _goal(tmp_path), "--fixture", "--json",
             "--idempotency-key", "cli-legacy-0001"], env=dict(os.environ))
    assert r.returncode == 0, r.stderr
    body = json.loads(r.stdout)
    assert body["created"] is True and body["mode"] == "fixture" and "intent" not in body
    assert set(body["task_ids"]) == {"explore", "research", "analyze", "plan"}


@pytest.mark.parametrize("mode", ["off", "shadow"])
def test_submit_intent_implementation_when_roster_not_enforced(omg_home, tmp_path, mode):
    if mode != "off":
        _features({"adaptive_roster": mode})
    goal = _goal(tmp_path)
    bare = run(["submit", "--goal-file", goal, "--fixture", "--intent", "implementation", "--json",
                "--idempotency-key", f"cli-impl-{mode}-bare"], env=dict(os.environ))
    assert bare.returncode == 0, bare.stderr + bare.stdout
    body = json.loads(bare.stdout)
    assert body["intent"] == "implementation" and body["roster_class"] == "heavy"
    assert set(body["task_ids"]) == {"explore", "research", "analyze", "plan"}
    scoped = run(["submit", "--goal-file", goal, "--fixture", "--intent", "implementation", "--json",
                  "--scope-file", _scope_file(tmp_path, FIXTURE_SCOPE),
                  "--idempotency-key", f"cli-impl-{mode}-scope"], env=dict(os.environ))
    assert scoped.returncode == 0, scoped.stderr + scoped.stdout
    scoped_body = json.loads(scoped.stdout)
    assert scoped_body["roster_class"] == "heavy" and scoped_body["intent"] == "implementation"


@pytest.mark.parametrize("mode", ["off", "enforce"])
def test_submit_intent_explanation_creates_no_job(omg_home, tmp_path, mode):
    if mode == "enforce":
        _features({"adaptive_roster": "enforce"})
    r = run(["submit", "--goal-file", _goal(tmp_path), "--intent", "explanation",
             "--idempotency-key", f"cli-explain-{mode}-01"], env=dict(os.environ))
    assert r.returncode == 0, r.stderr + r.stdout
    assert "no job" in r.stdout.lower()
    js = run(["submit", "--goal-file", _goal(tmp_path), "--intent", "explanation", "--json",
              "--idempotency-key", f"cli-explain-{mode}-02"], env=dict(os.environ))
    assert js.returncode == 0, js.stderr
    body = json.loads(js.stdout)
    assert body == {"action": "answer_directly", "created": False, "roster_class": "none"}


def test_submit_without_intent_is_refused_when_roster_enforced(omg_home, tmp_path):
    _features({"adaptive_roster": "enforce"})
    r = run(["submit", "--goal-file", _goal(tmp_path), "--fixture", "--json",
             "--idempotency-key", "cli-no-intent-enf"], env=dict(os.environ))
    body = _json_error(r)
    assert "intent is required" in body["message"]


def test_submit_implementation_under_enforce_requires_scope_then_accepts_it(omg_home, tmp_path):
    _features({"adaptive_roster": "enforce"})
    env = dict(os.environ)
    goal = _goal(tmp_path)
    missing = run(["submit", "--goal-file", goal, "--fixture", "--intent", "implementation", "--json",
                   "--idempotency-key", "cli-impl-enf-noscope"], env=env)
    assert "scope attestation is required" in _json_error(missing)["message"]
    ok = run(["submit", "--goal-file", goal, "--fixture", "--intent", "implementation", "--json",
              "--scope-file", _scope_file(tmp_path, FIXTURE_SCOPE),
              "--idempotency-key", "cli-impl-enf-scope"], env=env)
    assert ok.returncode == 0, ok.stderr + ok.stdout
    body = json.loads(ok.stdout)
    assert body["created"] is True and body["intent"] == "implementation"
    assert body["roster_class"] == "quick" and body["mode"] == "fixture"
    assert set(body["task_ids"]) == {"plan"}


def test_submit_roster_class_may_only_raise_the_floor_under_enforce(omg_home, tmp_path):
    _features({"adaptive_roster": "enforce"})
    env = dict(os.environ)
    goal = _goal(tmp_path)
    scope = _scope_file(tmp_path, FIXTURE_SCOPE)
    # quick is the floor for FIXTURE_SCOPE, so naming it is allowed.
    low = run(["submit", "--goal-file", goal, "--fixture", "--intent", "implementation", "--json",
               "--scope-file", scope, "--roster-class", "quick", "--idempotency-key", "cli-floor-low"], env=env)
    assert low.returncode == 0, low.stderr + low.stdout
    assert json.loads(low.stdout)["roster_class"] == "quick"
    heavy_scope = _scope_file(tmp_path, {**FIXTURE_SCOPE, "security_sensitive": True}, name="heavy.json")
    below = run(["submit", "--goal-file", goal, "--fixture", "--intent", "implementation", "--json",
                 "--scope-file", heavy_scope, "--roster-class", "quick",
                 "--idempotency-key", "cli-floor-below"], env=env)
    assert "below the floor" in _json_error(below)["message"]
    raised = run(["submit", "--goal-file", goal, "--fixture", "--intent", "implementation", "--json",
                  "--scope-file", scope, "--roster-class", "standard",
                  "--idempotency-key", "cli-floor-raise"], env=env)
    assert raised.returncode == 0, raised.stderr + raised.stdout
    assert json.loads(raised.stdout)["roster_class"] == "standard"


def test_submit_roster_class_requires_enforce(omg_home, tmp_path):
    r = run(["submit", "--goal-file", _goal(tmp_path), "--fixture", "--intent", "implementation",
             "--roster-class", "quick", "--json", "--idempotency-key", "cli-class-off"], env=dict(os.environ))
    assert "roster_class requires adaptive_roster=enforce" in _json_error(r)["message"]


@pytest.mark.parametrize("payload,fragment", [
    ({**FIXTURE_SCOPE, "surprise": True}, "unknown scope keys"),
    ({"files_estimate": 1}, "scope attestation is incomplete"),
    ("[]", "scope must be an object"),
    ("not-json", "scope file must be a JSON object"),
])
def test_submit_scope_file_is_validated_like_the_mcp_attestation(omg_home, tmp_path, payload, fragment):
    r = run(["submit", "--goal-file", _goal(tmp_path), "--fixture", "--intent", "implementation", "--json",
             "--scope-file", _scope_file(tmp_path, payload, name="bad-scope.json"),
             "--idempotency-key", "cli-bad-scope-01"], env=dict(os.environ))
    assert fragment in _json_error(r)["message"]


def _fail_if_the_harness_waits(_seconds):
    raise AssertionError("live fixture waited")


@pytest.mark.parametrize("mode", ["off", "shadow", "enforce"])
def test_live_fixture_submits_under_adaptive_roster(omg_home, monkeypatch, mode):
    """Submit must succeed under off, shadow, and enforce.

    Bindings are the ordinary harness (verified roles and hooks). The webhook transport and the
    wait are stubbed, and no task is claimed, so the result is not live evidence.
    """
    feats = {"adaptive_roster": mode}
    if mode == "enforce":
        feats.update(boulder="on", lsp="enforce", git_discipline="enforce", docs_evidence="enforce",
                     repo_lease="enforce", healing="shadow")
    _features(feats)
    from helpers import Harness
    from oh_my_grok.engine import Engine
    from oh_my_grok.live import run_live_fixture
    from oh_my_grok.transport import HttpResult

    bound = Harness()
    bound.close()
    monkeypatch.setattr("oh_my_grok.engine.post_json", lambda *a, **k: HttpResult(200, None, None))
    # Patch the harness poll only. ``oh_my_grok.live.time`` is the stdlib module, and
    # subprocess calls ``time.sleep`` while ``git add`` is still running.
    monkeypatch.setattr("oh_my_grok.live._pause", _fail_if_the_harness_waits)
    res = run_live_fixture(timeout=0, poll=30)
    assert res["result"] == "TIMEOUT", res
    assert "NOT RUN" not in res["result"]
    e = Engine()
    try:
        row = e._one("SELECT intent, roster_class, scope_json, phase, mode FROM jobs WHERE id=?", (res["job_id"],))
        assert row["intent"] == "implementation" and row["mode"] == "fixture"
        assert json.loads(row["scope_json"]) == FIXTURE_SCOPE
        kinds = sorted(r["kind"] for r in e._all("SELECT kind FROM tasks WHERE job_id=?", (res["job_id"],)))
        if mode == "enforce":
            assert row["roster_class"] == "quick" and row["phase"] == "planning" and kinds == ["plan"]
        else:
            assert row["roster_class"] == "heavy" and row["phase"] == "research"
            assert kinds == ["analyze", "explore", "plan", "research"]
        shadow = e._all("SELECT data_json FROM events WHERE job_id=? AND kind='roster_shadow'", (res["job_id"],))
        if mode == "shadow":
            assert len(shadow) == 1
            data = json.loads(shadow[0]["data_json"])
            assert data["would_be_class"] == "quick" and data["actual_class"] == "heavy"
        else:
            assert shadow == []
        assert e._one("SELECT COUNT(*) c FROM task_attempts")["c"] == 0
    finally:
        e.close()
