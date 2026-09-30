import csv
import json
import math
import os
import statistics
import time
import uuid
import urllib.request
import urllib.error

TOKEN = os.environ["TOKEN"]
SECRET = os.environ["INTERNAL_SHARED_SECRET"]
N = int(os.getenv("BENCH_N", "100"))
WARMUP = int(os.getenv("BENCH_WARMUP", "10"))

BASELINE_URL = "http://internal-api:8000/internal/resources/3"
OPA_URL = os.getenv("OPA_URL", "http://opa:8181/v1/data/zerotrust/authz")
ZERO_TRUST_URL = "http://127.0.0.1:8000/protected/resources/3"

CSV_PATH = "/tmp/zt_benchmark_v14.csv"
SUMMARY_PATH = "/tmp/zt_benchmark_v14_summary.json"

def timed_request(url, method="GET", headers=None, body=None):
    headers = headers or {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers = {**headers, "Content-Type": "application/json"}

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code

    elapsed_ms = (time.perf_counter() - start) * 1000
    return elapsed_ms, status, raw

def baseline_call():
    latency, status, raw = timed_request(
        BASELINE_URL,
        headers={
            "X-Internal-Secret": SECRET,
            "X-Request-ID": str(uuid.uuid4()),
        },
    )
    payload = json.loads(raw.decode("utf-8"))
    ok = status == 200 and payload.get("id") == 3 and payload.get("sensitivity") == "HIGH"
    return latency, status, ok

def opa_call():
    rid = str(uuid.uuid4())
    body = {
        "input": {
            "authenticated": True,
            "user": {"username": "alice", "role": "analyst", "active": True},
            "device": {
                "device_id": "DEV-001",
                "registered": True,
                "trust_status": "trusted",
                "firewall_enabled": True,
                "patch_status": "updated",
                "heartbeat_fresh": True,
                "heartbeat_age_seconds": 5.0,
                "latest_hotfix_id": "KB-BENCHMARK",
                "patch_age_days": 7.0,
                "pending_reboot": False,
                "patch_reason": "PATCH_COMPLIANT",
            },
            "resource": {
                "id": 3,
                "title": "Restricted Security Investigation",
                "sensitivity": "HIGH",
                "category": "security-investigation",
            },
            "context": {"time_allowed": True},
            "request": {
                "request_id": rid,
                "method": "GET",
                "path": "/protected/resources/3",
            },
        }
    }
    latency, status, raw = timed_request(OPA_URL, method="POST", body=body)
    payload = json.loads(raw.decode("utf-8"))
    result = payload.get("result") or {}
    ok = status == 200 and result.get("allow") is True and result.get("reason") == "ALLOW"
    return latency, status, ok

def zero_trust_call():
    latency, status, raw = timed_request(
        ZERO_TRUST_URL,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "X-Device-ID": "DEV-001",
        },
    )
    payload = json.loads(raw.decode("utf-8"))
    ok = status == 200 and payload.get("decision") == "ALLOW" and payload.get("resource", {}).get("id") == 3
    return latency, status, ok

SCENARIOS = {
    "baseline_internal_api": baseline_call,
    "opa_only": opa_call,
    "full_zero_trust": zero_trust_call,
}

def percentile(values, p):
    ordered = sorted(values)
    rank = max(1, math.ceil((p / 100) * len(ordered)))
    return ordered[rank - 1]

def summarize(values):
    return {
        "n": len(values),
        "average_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "p95_ms": percentile(values, 95),
        "min_ms": min(values),
        "max_ms": max(values),
        "stdev_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
    }

print(f"Warming up: {WARMUP} calls per scenario...")
for _ in range(WARMUP):
    for name, fn in SCENARIOS.items():
        latency, status, ok = fn()
        if not ok:
            raise RuntimeError(f"Warmup failed: {name} status={status} latency={latency:.3f} ms")

print(f"Measuring: {N} calls per scenario...")
rows = []
names = list(SCENARIOS.keys())

for i in range(N):
    shift = i % len(names)
    order = names[shift:] + names[:shift]
    for name in order:
        latency, status, ok = SCENARIOS[name]()
        rows.append({
            "iteration": i + 1,
            "scenario": name,
            "latency_ms": latency,
            "http_status": status,
            "success": ok,
        })
        if not ok:
            raise RuntimeError(f"Measured request failed: iteration={i+1} scenario={name} status={status}")

with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["iteration", "scenario", "latency_ms", "http_status", "success"],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, "latency_ms": f"{row['latency_ms']:.6f}"})

scenario_values = {
    name: [r["latency_ms"] for r in rows if r["scenario"] == name]
    for name in SCENARIOS
}
scenarios = {name: summarize(values) for name, values in scenario_values.items()}

base = scenarios["baseline_internal_api"]
opa = scenarios["opa_only"]
zt = scenarios["full_zero_trust"]

summary = {
    "benchmark": "Zero Trust Access Proxy V1.4 Final",
    "method": {
        "warmup_per_scenario": WARMUP,
        "measured_requests_per_scenario": N,
        "execution": "single-client sequential, rotating scenario order",
        "environment": "local Docker Compose",
    },
    "scenarios": scenarios,
    "overhead": {
        "absolute_average_ms": zt["average_ms"] - base["average_ms"],
        "ratio_average": zt["average_ms"] / base["average_ms"],
        "increase_average_pct": ((zt["average_ms"] - base["average_ms"]) / base["average_ms"]) * 100,
        "absolute_p95_ms": zt["p95_ms"] - base["p95_ms"],
        "opa_average_ms": opa["average_ms"],
        "opa_p95_ms": opa["p95_ms"],
    },
}

with open(SUMMARY_PATH, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print()
print("=" * 68)
print("ZERO TRUST V1.4 FINAL BENCHMARK")
print("=" * 68)
for name in ("baseline_internal_api", "opa_only", "full_zero_trust"):
    s = scenarios[name]
    print()
    print(name)
    print("-" * 44)
    print(f"N       : {s['n']}")
    print(f"Average : {s['average_ms']:.3f} ms")
    print(f"Median  : {s['median_ms']:.3f} ms")
    print(f"P95     : {s['p95_ms']:.3f} ms")
    print(f"Min     : {s['min_ms']:.3f} ms")
    print(f"Max     : {s['max_ms']:.3f} ms")
    print(f"Std Dev : {s['stdev_ms']:.3f} ms")

o = summary["overhead"]
print()
print("FULL ZERO TRUST OVERHEAD VS DIRECT INTERNAL API")
print("-" * 44)
print(f"Absolute average overhead : {o['absolute_average_ms']:.3f} ms")
print(f"Average latency ratio     : {o['ratio_average']:.2f}x")
print(f"Relative increase         : {o['increase_average_pct']:.2f}%")
print(f"Absolute P95 overhead     : {o['absolute_p95_ms']:.3f} ms")
print()
print("OPA CONTRIBUTION (MICROBENCHMARK)")
print("-" * 44)
print(f"OPA-only average          : {o['opa_average_ms']:.3f} ms")
print(f"OPA-only P95              : {o['opa_p95_ms']:.3f} ms")
print()
print(f"Raw CSV     : {CSV_PATH}")
print(f"Summary JSON: {SUMMARY_PATH}")
