"""Live smoke harness for spec §10 items 20-22 (`omg test live --fixture-only`).

This harness NEVER simulates Bots. It only submits a synthetic fixture job, applies an explicit SYNTHETIC approval
(fixture-only), runs reconcile on an interval and observes the DB. Real progress requires real Grok Bot routines
(bound + verified + webhook configured) that claim/complete via the registered `omg` MCP server, and Hephaestus
resuming its awaiting_resume tasks in chat. If prerequisites are missing it reports NOT RUN and exits non-zero.
"""
from __future__ import annotations

import time
import uuid

from .engine import Engine
from .states import ROLES

ASYNC_ROLES = [r for r in ROLES if r != "hephaestus"]

# Smallest attestation for the synthetic calc fixture. The real fix is one line in calc/__init__.py
# (`return a + b`). No new dependency, no external API, no security-sensitive path, and not
# cross-cutting, so under adaptive_roster=enforce the floor is quick. roster_class is left unset:
# off and shadow keep the original heavy DAG, and a requested class is refused unless the flag is enforce.
FIXTURE_SCOPE = {"files_estimate": 1, "new_dependency": False, "external_api": False,
                 "security_sensitive": False, "cross_cutting": False}


def _pause(seconds: float) -> None:
    """Poll wait. Tests replace this function. Replacing ``time.sleep`` also stops ``subprocess``."""
    time.sleep(seconds)


def prerequisites(e: Engine) -> list[str]:
    missing = []
    for b in e.list_bindings():
        if b["role"] not in ASYNC_ROLES:
            continue
        if not b["bound"]:
            missing.append(f"{b['role']}: no binding")
        elif not b["routine_id"] or not b["verified_at"]:
            missing.append(f"{b['role']}: routine not verified")
        if not b["webhook_configured"]:
            missing.append(f"{b['role']}: webhook not configured (omg hook set {b['role']})")
    return missing


def run_live_fixture(timeout: int = 3600, poll: int = 60) -> dict:
    e = Engine()
    try:
        missing = prerequisites(e)
        if missing:
            return {"result": "NOT RUN", "missing_prerequisites": missing,
                    "summary": "NOT RUN: live prerequisites missing (no live evidence produced):\n  - "
                               + "\n  - ".join(missing)}
        goal = ("SYNTHETIC FIXTURE: fix calc.add so the fixture unittest suite passes. Do not modify tests/. "
                "This is an installation smoke test; it authorizes nothing outside the fixture repo.")
        r = e.submit(goal, f"live-fixture:{uuid.uuid4().hex}", mode="fixture",
                     acceptance_criteria=["python -m unittest discover -s tests exits 0 on the final revision"],
                     actor="omg test live", intent="implementation", scope=FIXTURE_SCOPE)
        job = r["job_id"]
        deadline = time.time() + timeout
        log = []
        while time.time() < deadline:
            e.reconcile(job)
            s = e.status(job)
            if s["phase"] == "awaiting_approval":
                e.record_synthetic_approval(job, s["plan"]["plan_hash"])
                log.append("synthetic fixture approval recorded")
                continue
            if s["phase"] in ("done", "blocked", "failed", "cancelled"):
                break
            if s.get("awaiting_resume"):
                log.append(f"waiting for Hephaestus to resume tasks in chat: {s['awaiting_resume']}")
            _pause(poll)
        s = e.status(job, include_events=True)
        ok = s["phase"] == "done" and any(g["passed"] for g in s["gates"])
        return {"result": "PASSED" if ok else ("TIMEOUT" if s["phase"] not in ("blocked", "failed", "cancelled")
                                               else "FAILED"),
                "job_id": job, "phase": s["phase"], "gates": s["gates"], "log": log[-20:],
                "summary": f"live fixture job {job}: phase={s['phase']} (verify Bot routine run histories too; "
                           "DB events alone are not proof of live delivery)"}
    finally:
        e.close()
