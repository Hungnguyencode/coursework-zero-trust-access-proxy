"""
FINAL-QA1B: Access Proxy / API regression suite.

Run inside the access-proxy container:
    Get-Content .\tests\api_regression.py -Raw |
        docker compose exec -T access-proxy python -

This suite exercises the real FastAPI Access Proxy on 127.0.0.1:8000.
It does NOT change user roles, device trust, demo controls, or posture.
Protected-resource requests do create normal audit/realtime evidence by design.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
import uuid

BASE_URL = "http://127.0.0.1:8000"
ADMIN_KEY = "demo-admin-key"

passed = 0
failed = 0


def http_json(path: str, *, method: str = "GET", token: str | None = None,
              device_id: str | None = None, admin_key: str | None = None,
              body: dict | None = None) -> tuple[int, object, dict]:
    headers = {"Accept": "application/json"}

    if token:
        headers["Authorization"] = f"Bearer {token}"
    if device_id:
        headers["X-Device-ID"] = device_id
    if admin_key:
        headers["X-Admin-Key"] = admin_key

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            raw = response.read()
            status = response.status
            response_headers = dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
        response_headers = dict(exc.headers.items())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach Access Proxy at {BASE_URL}: {exc}") from exc

    if raw:
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {"_raw": raw.decode("utf-8", errors="replace")}
    else:
        payload = None

    return status, payload, response_headers


def detail(payload: object) -> object:
    if isinstance(payload, dict):
        return payload.get("detail")
    return None


def record(name: str, ok: bool, observed: str) -> None:
    global passed, failed
    if ok:
        passed += 1
        print(f"[PASS {passed + failed:02d}] {name} -> {observed}")
    else:
        failed += 1
        print(f"[FAIL {passed + failed:02d}] {name} -> {observed}")


def login(username: str, password: str, device_id: str) -> tuple[int, object]:
    status, payload, _ = http_json(
        "/auth/login",
        method="POST",
        body={
            "username": username,
            "password": password,
            "device_id": device_id,
        },
    )
    return status, payload


def token_from(payload: object) -> str | None:
    if isinstance(payload, dict):
        token = payload.get("access_token")
        if isinstance(token, str) and token:
            return token
    return None


def main() -> int:
    print("=" * 78)
    print("FINAL-QA1B - ACCESS PROXY / API REGRESSION")
    print("=" * 78)
    print(f"Target: {BASE_URL}")
    print()

    # 01 - health
    status, payload, _ = http_json("/health")
    record(
        "Health endpoint",
        status == 200 and isinstance(payload, dict) and payload.get("status") == "ok",
        f"HTTP {status}, body={payload}",
    )

    # 02 - Alice login
    alice_status, alice_payload = login("alice", "alice123", "DEV-001")
    alice_token = token_from(alice_payload)
    alice_ok = (
        alice_status == 200
        and alice_token is not None
        and isinstance(alice_payload, dict)
        and (alice_payload.get("user") or {}).get("role") == "analyst"
        and (alice_payload.get("device") or {}).get("device_id") == "DEV-001"
    )
    record(
        "Alice login fixture",
        alice_ok,
        f"HTTP {alice_status}, role={(alice_payload.get('user') or {}).get('role') if isinstance(alice_payload, dict) else None}",
    )

    # 03 - Bob login
    bob_status, bob_payload = login("bob", "bob123", "DEV-002")
    bob_token = token_from(bob_payload)
    bob_ok = (
        bob_status == 200
        and bob_token is not None
        and isinstance(bob_payload, dict)
        and (bob_payload.get("user") or {}).get("role") == "viewer"
        and (bob_payload.get("device") or {}).get("device_id") == "DEV-002"
    )
    record(
        "Bob login fixture",
        bob_ok,
        f"HTTP {bob_status}, role={(bob_payload.get('user') or {}).get('role') if isinstance(bob_payload, dict) else None}",
    )

    # 04 - SOC login
    soc_status, soc_payload = login("socadmin", "socadmin123", "SOC-001")
    soc_token = token_from(soc_payload)
    soc_ok = (
        soc_status == 200
        and soc_token is not None
        and isinstance(soc_payload, dict)
        and (soc_payload.get("user") or {}).get("role") == "security-admin"
    )
    record(
        "SOC security-admin login fixture",
        soc_ok,
        f"HTTP {soc_status}, role={(soc_payload.get('user') or {}).get('role') if isinstance(soc_payload, dict) else None}",
    )

    # 05 - bad credentials
    bad_status, bad_payload = login("alice", "definitely-wrong", "DEV-001")
    record(
        "Invalid credentials rejected",
        bad_status == 401 and detail(bad_payload) == "Invalid credentials",
        f"HTTP {bad_status}, detail={detail(bad_payload)}",
    )

    # 06 - protected endpoint requires Bearer token
    status, payload, _ = http_json("/protected/resources")
    record(
        "Missing Bearer token rejected",
        status == 401 and detail(payload) == "Missing Bearer token",
        f"HTTP {status}, detail={detail(payload)}",
    )

    # Remaining tests depend on successful fixture logins.
    if not alice_token or not bob_token or not soc_token:
        print()
        print("Cannot continue dependent API cases because one or more fixture logins failed.")
        print("-" * 78)
        print(f"RESULT: {passed}/{passed + failed} passed")
        print("FINAL-QA1B: FAIL")
        return 1

    # 07 - catalog is reachable for authenticated, correctly-bound Alice
    status, payload, _ = http_json(
        "/protected/resources",
        token=alice_token,
        device_id="DEV-001",
    )
    resources = payload.get("resources", []) if isinstance(payload, dict) else []
    observed = {
        item.get("id"): item.get("sensitivity")
        for item in resources
        if isinstance(item, dict)
    }
    record(
        "Protected resource catalog with correct device binding",
        status == 200
        and observed.get(1) == "LOW"
        and observed.get(2) == "MEDIUM"
        and observed.get(3) == "HIGH",
        f"HTTP {status}, resources={observed}",
    )

    # 08 - token/device binding is enforced before protected access
    status, payload, _ = http_json(
        "/protected/resources",
        token=alice_token,
        device_id="DEV-002",
    )
    record(
        "JWT/device mismatch rejected",
        status == 403 and detail(payload) == "Device ID mismatch",
        f"HTTP {status}, detail={detail(payload)}",
    )

    # 09 - business user cannot read Security Center identity administration
    status, payload, _ = http_json(
        "/admin/users",
        token=alice_token,
    )
    record(
        "Business user blocked from security-admin endpoint",
        status == 403 and detail(payload) == "Security Center requires security-admin role",
        f"HTTP {status}, detail={detail(payload)}",
    )

    # 10 - SOC can read managed identities, and role model stays separated
    status, payload, _ = http_json(
        "/admin/users",
        token=soc_token,
    )
    role_model = payload.get("role_model", {}) if isinstance(payload, dict) else {}
    record(
        "SOC can read managed identities with protected role model",
        status == 200
        and role_model.get("default_role") == "viewer"
        and role_model.get("assignable_roles") == ["viewer", "analyst"]
        and role_model.get("protected_role") == "security-admin",
        f"HTTP {status}, role_model={role_model}",
    )

    # 11 - security-admin cannot be assigned through the normal business-role API.
    # Validation rejects before any role mutation.
    status, payload, _ = http_json(
        "/admin/users/alice/role",
        method="PUT",
        token=soc_token,
        admin_key=ADMIN_KEY,
        body={"role": "security-admin"},
    )
    role_reject_detail = detail(payload)
    record(
        "Protected security-admin role is not assignable",
        status == 400
        and isinstance(role_reject_detail, str)
        and "Only viewer or analyst" in role_reject_detail,
        f"HTTP {status}, detail={role_reject_detail}",
    )

    # 12 - LOW data goes through the full protected path and must ALLOW.
    # LOW intentionally does not require trusted/fresh/healthy posture.
    status, payload, _ = http_json(
        "/protected/resources/1",
        token=alice_token,
        device_id="DEV-001",
    )
    allow_request_id = payload.get("request_id") if isinstance(payload, dict) else None
    allow_resource = payload.get("resource", {}) if isinstance(payload, dict) else {}
    valid_allow_uuid = False
    try:
        uuid.UUID(str(allow_request_id))
        valid_allow_uuid = True
    except (ValueError, TypeError, AttributeError):
        pass

    record(
        "LOW protected resource completes full ALLOW path",
        status == 200
        and isinstance(payload, dict)
        and payload.get("decision") == "ALLOW"
        and payload.get("reason") == "ALLOW"
        and allow_resource.get("id") == 1
        and allow_resource.get("sensitivity") == "LOW"
        and valid_allow_uuid,
        f"HTTP {status}, decision={payload.get('decision') if isinstance(payload, dict) else None}, request_id={allow_request_id}",
    )

    # 13 - Decision Inspector proves the ALLOW was audited and that the
    # sensitive upstream fetch happened only after policy ALLOW.
    if valid_allow_uuid:
        status, inspector, _ = http_json(
            f"/decisions/{allow_request_id}",
            token=soc_token,
        )
        evidence = inspector.get("evidence", {}) if isinstance(inspector, dict) else {}
        data_api = inspector.get("data_api", {}) if isinstance(inspector, dict) else {}
        record(
            "ALLOW request has correlated audit + Data API evidence",
            status == 200
            and inspector.get("decision") == "ALLOW"
            and evidence.get("access_log_persisted") is True
            and evidence.get("realtime_correlated") is True
            and evidence.get("sensitive_payload_fetched") is True
            and evidence.get("data_api_request_id_match") is True
            and data_api.get("status") == "FETCHED",
            f"HTTP {status}, evidence={evidence}, data_api_status={data_api.get('status')}",
        )
    else:
        record(
            "ALLOW request has correlated audit + Data API evidence",
            False,
            "Skipped because the prior ALLOW request did not return a valid request_id",
        )

    # 14 - Bob is a VIEWER fixture. HIGH must be denied regardless of whether
    # his current posture is healthy or stale. We intentionally do not require
    # one exact deny reason here; QA1A already validates reason precedence.
    status, payload, _ = http_json(
        "/protected/resources/3",
        token=bob_token,
        device_id="DEV-002",
    )
    deny_detail = detail(payload)
    deny_request_id = deny_detail.get("request_id") if isinstance(deny_detail, dict) else None
    deny_reason = deny_detail.get("reason") if isinstance(deny_detail, dict) else None
    valid_deny_uuid = False
    try:
        uuid.UUID(str(deny_request_id))
        valid_deny_uuid = True
    except (ValueError, TypeError, AttributeError):
        pass

    record(
        "Bob VIEWER is denied HIGH protected data",
        status == 403
        and isinstance(deny_detail, dict)
        and deny_detail.get("decision") == "DENY"
        and valid_deny_uuid
        and isinstance(deny_reason, str)
        and deny_reason != "",
        f"HTTP {status}, reason={deny_reason}, request_id={deny_request_id}",
    )

    # 15 - DENY must not fetch the sensitive payload.
    if valid_deny_uuid:
        status, inspector, _ = http_json(
            f"/decisions/{deny_request_id}",
            token=soc_token,
        )
        evidence = inspector.get("evidence", {}) if isinstance(inspector, dict) else {}
        data_api = inspector.get("data_api", {}) if isinstance(inspector, dict) else {}
        record(
            "DENY request never fetches sensitive Data API payload",
            status == 200
            and inspector.get("decision") == "DENY"
            and evidence.get("access_log_persisted") is True
            and evidence.get("sensitive_payload_fetched") is False
            and data_api.get("status") == "NOT_FETCHED_POLICY_DENY",
            f"HTTP {status}, evidence={evidence}, data_api_status={data_api.get('status')}",
        )
    else:
        record(
            "DENY request never fetches sensitive Data API payload",
            False,
            "Skipped because the prior DENY request did not return a valid request_id",
        )

    print()
    print("-" * 78)
    total = passed + failed
    print(f"RESULT: {passed}/{total} passed")

    if failed:
        print("FINAL-QA1B: FAIL")
        return 1

    print("FINAL-QA1B: PASS")
    print("Access Proxy authentication, authorization, audit, correlation, and enforcement are consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
