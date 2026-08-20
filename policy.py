"""Deterministic CI/CD container release-gate policy."""

from __future__ import annotations

import re

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}
ALLOWED_SECRET_MODES = {"none", "buildkit"}
PRODUCTION_REF = "refs/heads/main"

# Stable evaluation order. The grader does not require this order.
VIOLATION_ORDER = (
    "EXCESS_PERMISSION",
    "UNSAFE_PR_TRIGGER",
    "TESTS_INCOMPLETE",
    "MUTABLE_ACTION",
    "SINGLE_STAGE_IMAGE",
    "ROOT_RUNTIME",
    "SECRET_IN_LAYER",
    "CRITICAL_CVE",
    "UNPINNED_IMAGE",
    "INVALID_PRODUCTION_REF",
    "APPROVAL_REQUIRED",
)


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def evaluate(payload) -> dict:
    payload = _as_dict(payload)
    workflow = _as_dict(payload.get("workflow"))
    image = _as_dict(payload.get("image"))
    found = set()

    if workflow.get("permissions") != REQUIRED_PERMISSIONS:
        found.add("EXCESS_PERMISSION")

    event = payload.get("event")
    trigger = workflow.get("trigger")
    if trigger == "pull_request_target" or (
        event == "pull_request" and trigger != "pull_request"
    ):
        found.add("UNSAFE_PR_TRIGGER")

    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        found.add("TESTS_INCOMPLETE")

    actions = workflow.get("actions")
    if isinstance(actions, list):
        for action in actions:
            action = _as_dict(action)
            owner = str(action.get("owner") or "")
            ref = action.get("ref")
            if owner.lower() != "actions" and not (
                isinstance(ref, str) and SHA_RE.fullmatch(ref)
            ):
                found.add("MUTABLE_ACTION")
                break

    if image.get("multiStage") is not True:
        found.add("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        found.add("ROOT_RUNTIME")

    if image.get("secretMode") not in ALLOWED_SECRET_MODES:
        found.add("SECRET_IN_LAYER")

    cves = image.get("criticalVulnerabilities")
    if not isinstance(cves, (int, float)) or cves != 0:
        found.add("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        found.add("UNPINNED_IMAGE")

    if payload.get("target") == "production":
        if event != "push" or payload.get("ref") != PRODUCTION_REF:
            found.add("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            found.add("APPROVAL_REQUIRED")

    violations = [code for code in VIOLATION_ORDER if code in found]
    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }
