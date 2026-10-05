"""
FINAL-QA1: Zero Trust OPA policy regression suite.

Runs inside the access-proxy container so it can reach:
    http://opa:8181/v1/data/zerotrust/authz

No third-party test dependency is required.
This suite tests the PDP/policy layer only; it does not mutate database state,
device trust, demo controls, or user accounts.
"""

from __future__ import annotations

import copy
import json
import sys
import urllib.error
import urllib.request
import uuid

OPA_URL = "http://opa:8181/v1/data/zerotrust/authz"


def base_input() -> dict:
    return {
        "authenticated": True,
        "user": {
            "username": "qa-user",
            "role": "analyst",
            "active": True,
        },
        "device": {
            "device_id": "QA-DEVICE",
            "registered": True,
            "trust_status": "trusted",
            "firewall_enabled": True,
            "patch_status": "updated",
            "heartbeat_fresh": True,
            "heartbeat_age_seconds": 5.0,
            "latest_hotfix_id": "KB-QA",
            "patch_age_days": 7.0,
            "pending_reboot": False,
            "patch_reason": "PATCH_COMPLIANT",
        },
        "resource": {
            "id": 3,
            "title": "QA Protected Resource",
            "sensitivity": "HIGH",
            "category": "qa",
        },
        "context": {
            "time_allowed": True,
        },
        "request": {
            "request_id": str(uuid.uuid4()),
            "method": "GET",
            "path": "/protected/resources/3",
        },
    }


def case(name: str, expected_allow: bool, expected_reason: str, mutate) -> dict:
    payload = base_input()
    mutate(payload)
    payload["request"]["request_id"] = str(uuid.uuid4())
    return {
        "name": name,
        "input": payload,
        "expected_allow": expected_allow,
        "expected_reason": expected_reason,
    }


def set_low_degraded(x: dict) -> None:
    x["resource"]["sensitivity"] = "LOW"
    x["device"]["trust_status"] = "untrusted"
    x["device"]["heartbeat_fresh"] = False
    x["device"]["firewall_enabled"] = False
    x["device"]["patch_age_days"] = 120.0
    x["device"]["pending_reboot"] = True


def set_medium_healthy(x: dict) -> None:
    x["resource"]["sensitivity"] = "MEDIUM"


def set_medium_untrusted(x: dict) -> None:
    x["resource"]["sensitivity"] = "MEDIUM"
    x["device"]["trust_status"] = "untrusted"


def set_medium_stale(x: dict) -> None:
    x["resource"]["sensitivity"] = "MEDIUM"
    x["device"]["heartbeat_fresh"] = False


def set_high_viewer(x: dict) -> None:
    x["user"]["role"] = "viewer"


def set_high_firewall_off(x: dict) -> None:
    x["device"]["firewall_enabled"] = False


def set_high_missing_patch(x: dict) -> None:
    x["device"]["latest_hotfix_id"] = None
    x["device"]["patch_age_days"] = None
    x["device"]["pending_reboot"] = None


def set_high_pending_reboot(x: dict) -> None:
    x["device"]["pending_reboot"] = True


def set_high_patch_old(x: dict) -> None:
    x["device"]["patch_age_days"] = 46.0


def set_high_context_denied(x: dict) -> None:
    x["context"]["time_allowed"] = False


def set_invalid_method(x: dict) -> None:
    x["request"]["method"] = "POST"


def set_unknown_sensitivity(x: dict) -> None:
    x["resource"]["sensitivity"] = "CRITICAL"


def set_auth_failed(x: dict) -> None:
    x["authenticated"] = False


CASES = [
    case(
        "LOW allows registered authenticated GET despite degraded trust/posture",
        True,
        "ALLOW",
        set_low_degraded,
    ),
    case(
        "MEDIUM healthy trusted fresh device allows",
        True,
        "ALLOW",
        set_medium_healthy,
    ),
    case(
        "MEDIUM untrusted device denies",
        False,
        "DEVICE_UNTRUSTED",
        set_medium_untrusted,
    ),
    case(
        "MEDIUM stale heartbeat denies",
        False,
        "DEVICE_STALE",
        set_medium_stale,
    ),
    case(
        "HIGH viewer role denies",
        False,
        "ROLE_DENIED_FOR_HIGH_DATA",
        set_high_viewer,
    ),
    case(
        "HIGH firewall disabled denies",
        False,
        "FIREWALL_DISABLED",
        set_high_firewall_off,
    ),
    case(
        "HIGH missing patch evidence denies",
        False,
        "PATCH_EVIDENCE_MISSING",
        set_high_missing_patch,
    ),
    case(
        "HIGH pending reboot denies",
        False,
        "PENDING_REBOOT",
        set_high_pending_reboot,
    ),
    case(
        "HIGH patch older than 45 days denies",
        False,
        "PATCH_TOO_OLD",
        set_high_patch_old,
    ),
    case(
        "HIGH disallowed context denies",
        False,
        "CONTEXT_DENIED",
        set_high_context_denied,
    ),
    case(
        "Invalid request method denies",
        False,
        "REQUEST_DENIED",
        set_invalid_method,
    ),
    case(
        "Unknown resource sensitivity denies",
        False,
        "RESOURCE_SENSITIVITY_UNKNOWN",
        set_unknown_sensitivity,
    ),
    case(
        "Authentication failure denies",
        False,
        "AUTHENTICATION_FAILED",
        set_auth_failed,
    ),
    case(
        "HIGH healthy analyst allows",
        True,
        "ALLOW",
        lambda x: None,
    ),
]


def evaluate(policy_input: dict) -> dict:
    body = json.dumps({"input": policy_input}).encode("utf-8")
    req = urllib.request.Request(
        OPA_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            raw = response.read()
            if response.status != 200:
                raise RuntimeError(f"OPA returned HTTP {response.status}")
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach OPA at {OPA_URL}: {exc}") from exc

    payload = json.loads(raw.decode("utf-8"))
    result = payload.get("result")
    if not isinstance(result, dict):
        raise RuntimeError(f"OPA response has no result object: {payload}")
    return result


def main() -> int:
    print("=" * 74)
    print("FINAL-QA1 - ZERO TRUST POLICY REGRESSION")
    print("=" * 74)
    print(f"OPA: {OPA_URL}")
    print(f"Cases: {len(CASES)}")
    print()

    passed = 0
    failures: list[str] = []

    for index, item in enumerate(CASES, start=1):
        try:
            result = evaluate(item["input"])
            actual_allow = bool(result.get("allow", False))
            actual_reason = result.get("reason")

            ok = (
                actual_allow == item["expected_allow"]
                and actual_reason == item["expected_reason"]
            )

            if ok:
                passed += 1
                print(
                    f"[PASS {index:02d}] {item['name']} "
                    f"-> allow={actual_allow}, reason={actual_reason}"
                )
            else:
                message = (
                    f"[FAIL {index:02d}] {item['name']} "
                    f"expected allow={item['expected_allow']}, "
                    f"reason={item['expected_reason']} | "
                    f"got allow={actual_allow}, reason={actual_reason}"
                )
                failures.append(message)
                print(message)

        except Exception as exc:
            message = f"[ERROR {index:02d}] {item['name']} -> {exc}"
            failures.append(message)
            print(message)

    print()
    print("-" * 74)
    print(f"RESULT: {passed}/{len(CASES)} passed")

    if failures:
        print("FINAL-QA1: FAIL")
        return 1

    print("FINAL-QA1: PASS")
    print("Policy regression is deterministic and does not mutate runtime state.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
