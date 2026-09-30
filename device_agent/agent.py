import argparse
import json
import platform
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone

import requests


AGENT_VERSION = "0.5.0"

DEFAULT_PATCH_MAX_AGE_DAYS = 45
DEFAULT_PATCH_REFRESH_SECONDS = 300
DEFAULT_CONTROL_POLL_SECONDS = 2


# ============================================================
# WINDOWS HELPERS
# ============================================================

def run_powershell(command: str) -> str:
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "PowerShell command failed: "
            f"{result.stderr.strip()}"
        )

    return result.stdout.strip()


def get_windows_firewall_enabled() -> bool:
    output = run_powershell(
        '@(Get-NetFirewallProfile | '
        'Where-Object { $_.Enabled -eq $false }).Count -eq 0'
    ).lower()

    if output == "true":
        return True

    if output == "false":
        return False

    raise RuntimeError(
        "Unexpected firewall status returned by PowerShell: "
        f"{output}"
    )


def get_device_metadata() -> dict:
    return {
        "hostname": socket.gethostname(),
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "agent_version": AGENT_VERSION,
    }


# ============================================================
# PATCH EVIDENCE
# ============================================================

def collect_windows_patch_evidence(
    patch_max_age_days: int,
) -> dict:
    ps_script = r'''
$latestHotFix =
    Get-HotFix |
    Where-Object { $_.InstalledOn } |
    Sort-Object InstalledOn -Descending |
    Select-Object -First 1

$cbsRebootPending =
    Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'

$windowsUpdateRebootRequired =
    Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'

$pendingFileRenameOperations =
(
    (Get-ItemProperty `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name PendingFileRenameOperations `
        -ErrorAction SilentlyContinue
    ) -ne $null
)

# Only Windows servicing/update reboot evidence is treated
# as security-relevant pending reboot evidence.
$pendingReboot =
    $cbsRebootPending -or
    $windowsUpdateRebootRequired

$result = [pscustomobject]@{
    hotfix_id = if ($latestHotFix) {
        $latestHotFix.HotFixID
    } else {
        $null
    }

    installed_on = if (
        $latestHotFix -and
        $latestHotFix.InstalledOn
    ) {
        $latestHotFix.InstalledOn.ToUniversalTime().ToString('o')
    } else {
        $null
    }

    pending_reboot = [bool]$pendingReboot
}

$result | ConvertTo-Json -Compress
'''

    try:
        raw = run_powershell(
            ps_script
        )

        evidence = json.loads(
            raw
        )

        hotfix_id = evidence.get(
            "hotfix_id"
        )

        installed_on_raw = evidence.get(
            "installed_on"
        )

        pending_reboot = bool(
            evidence.get(
                "pending_reboot",
                False,
            )
        )

        if not installed_on_raw:
            return {
                "patch_status": "outdated",
                "latest_hotfix_id": hotfix_id,
                "latest_hotfix_installed_on": None,
                "patch_age_days": None,
                "pending_reboot": pending_reboot,
                "patch_reason": "NO_HOTFIX_EVIDENCE",
            }

        installed_on = datetime.fromisoformat(
            installed_on_raw.replace(
                "Z",
                "+00:00",
            )
        )

        if installed_on.tzinfo is None:
            installed_on = installed_on.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(
            timezone.utc
        )

        patch_age_days = max(
            0.0,
            (
                now
                - installed_on
            ).total_seconds()
            / 86400.0,
        )

        if pending_reboot:
            patch_status = "outdated"
            patch_reason = "PENDING_REBOOT"

        elif (
            patch_age_days
            > patch_max_age_days
        ):
            patch_status = "outdated"
            patch_reason = "HOTFIX_TOO_OLD"

        else:
            patch_status = "updated"
            patch_reason = "PATCH_COMPLIANT"

        return {
            "patch_status": patch_status,
            "latest_hotfix_id": hotfix_id,
            "latest_hotfix_installed_on": (
                installed_on.isoformat()
            ),
            "patch_age_days": round(
                patch_age_days,
                2,
            ),
            "pending_reboot": pending_reboot,
            "patch_reason": patch_reason,
        }

    except Exception as exc:
        print(
            "[PATCH ERROR] "
            f"{exc}"
        )

        return {
            "patch_status": "outdated",
            "latest_hotfix_id": None,
            "latest_hotfix_installed_on": None,
            "patch_age_days": None,
            "pending_reboot": None,
            "patch_reason": "PATCH_EVALUATION_ERROR",
        }


class PatchCache:
    def __init__(
        self,
        refresh_seconds: int,
        patch_max_age_days: int,
    ):
        self.refresh_seconds = (
            refresh_seconds
        )

        self.patch_max_age_days = (
            patch_max_age_days
        )

        self._cached = None
        self._last_refresh_monotonic = 0.0

    def get(self) -> dict:
        now_monotonic = time.monotonic()

        cache_expired = (
            self._cached is None
            or (
                now_monotonic
                - self._last_refresh_monotonic
                >= self.refresh_seconds
            )
        )

        if cache_expired:
            self._cached = (
                collect_windows_patch_evidence(
                    self.patch_max_age_days
                )
            )

            self._last_refresh_monotonic = (
                now_monotonic
            )

        return dict(
            self._cached
        )


# ============================================================
# DEMO CONTROL
# ============================================================

def default_demo_control() -> dict:
    return {
        "simulate_firewall_disabled": False,
        "simulate_patch_outdated": False,
        "simulate_agent_loss": False,
    }


def control_signature(
    control: dict,
) -> tuple:
    return (
        bool(
            control.get(
                "simulate_firewall_disabled",
                False,
            )
        ),
        bool(
            control.get(
                "simulate_patch_outdated",
                False,
            )
        ),
        bool(
            control.get(
                "simulate_agent_loss",
                False,
            )
        ),
    )


def fetch_demo_control(
    args,
) -> dict:
    response = requests.get(
        (
            f"{args.base_url}"
            f"/admin/demo/devices/"
            f"{args.device_id}/control"
        ),
        headers={
            "X-Admin-Key": (
                args.admin_key
            ),
        },
        timeout=3,
    )

    response.raise_for_status()

    data = response.json()

    return {
        "simulate_firewall_disabled": bool(
            data.get(
                "simulate_firewall_disabled",
                False,
            )
        ),
        "simulate_patch_outdated": bool(
            data.get(
                "simulate_patch_outdated",
                False,
            )
        ),
        "simulate_agent_loss": bool(
            data.get(
                "simulate_agent_loss",
                False,
            )
        ),
    }


def print_control_state(
    control: dict,
) -> None:
    print(
        "[DEMO CONTROL] "
        f"firewall_off="
        f"{control['simulate_firewall_disabled']} "
        f"patch_outdated="
        f"{control['simulate_patch_outdated']} "
        f"agent_loss="
        f"{control['simulate_agent_loss']}"
    )


# ============================================================
# POSTURE BUILDING
# ============================================================

def apply_patch_simulation(
    patch_evidence: dict,
    args,
    control: dict,
) -> dict:
    evidence = dict(
        patch_evidence
    )

    if not control.get(
        "simulate_patch_outdated",
        False,
    ):
        return evidence

    demo_age_days = (
        args.patch_max_age_days
        + 30
    )

    demo_installed_on = (
        datetime.now(
            timezone.utc
        )
        - timedelta(
            days=demo_age_days
        )
    )

    evidence.update(
        {
            "patch_status": "outdated",
            "latest_hotfix_id": (
                "KB-DEMO-OLD"
            ),
            "latest_hotfix_installed_on": (
                demo_installed_on.isoformat()
            ),
            "patch_age_days": float(
                demo_age_days
            ),
            "pending_reboot": False,
            "patch_reason": (
                "HOTFIX_TOO_OLD"
            ),
        }
    )

    return evidence


def build_posture_payload(
    args,
    patch_cache: PatchCache,
    control: dict,
) -> tuple[dict, dict]:
    metadata = get_device_metadata()

    real_patch_evidence = (
        patch_cache.get()
    )

    patch_evidence = (
        apply_patch_simulation(
            real_patch_evidence,
            args,
            control,
        )
    )

    firewall_simulated = (
        args.simulate_firewall_disabled
        or control.get(
            "simulate_firewall_disabled",
            False,
        )
    )

    if firewall_simulated:
        firewall_enabled = False
    else:
        firewall_enabled = (
            get_windows_firewall_enabled()
        )

    payload = {
        "firewall_enabled": (
            firewall_enabled
        ),
        "patch_status": (
            patch_evidence[
                "patch_status"
            ]
        ),
        "latest_hotfix_id": (
            patch_evidence[
                "latest_hotfix_id"
            ]
        ),
        "latest_hotfix_installed_on": (
            patch_evidence[
                "latest_hotfix_installed_on"
            ]
        ),
        "patch_age_days": (
            patch_evidence[
                "patch_age_days"
            ]
        ),
        "pending_reboot": (
            patch_evidence[
                "pending_reboot"
            ]
        ),
        "patch_reason": (
            patch_evidence[
                "patch_reason"
            ]
        ),
        **metadata,
    }

    return (
        payload,
        patch_evidence,
    )


# ============================================================
# POSTURE DELIVERY
# ============================================================

def send_posture(
    args,
    patch_cache: PatchCache,
    control: dict,
) -> None:
    (
        payload,
        patch_evidence,
    ) = build_posture_payload(
        args,
        patch_cache,
        control,
    )

    response = requests.post(
        (
            f"{args.base_url}/device/"
            f"{args.device_id}/posture"
        ),
        headers={
            "X-Admin-Key": (
                args.admin_key
            ),
        },
        json=payload,
        timeout=5,
    )

    print(
        "[DEVICE POSTURE] "
        f"device={args.device_id} "
        f"host={payload['hostname']} "
        f"os={payload['os_name']} "
        f"{payload['os_release']} "
        f"firewall="
        f"{payload['firewall_enabled']} "
        f"patch="
        f"{payload['patch_status']} "
        f"hotfix="
        f"{patch_evidence['latest_hotfix_id']} "
        f"patch_age_days="
        f"{patch_evidence['patch_age_days']} "
        f"pending_reboot="
        f"{patch_evidence['pending_reboot']} "
        f"patch_reason="
        f"{patch_evidence['patch_reason']} "
        f"agent="
        f"{payload['agent_version']} "
        f"status="
        f"{response.status_code}"
    )

    print(
        response.text
    )

    response.raise_for_status()


# ============================================================
# CLI
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Zero Trust Continuous "
            "Device Agent"
        )
    )

    parser.add_argument(
        "--base-url",
        default=(
            "http://localhost:8081/api"
        ),
    )

    parser.add_argument(
        "--device-id",
        default="DEV-001",
    )

    parser.add_argument(
        "--admin-key",
        default="demo-admin-key",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help=(
            "Normal posture reporting "
            "interval in seconds."
        ),
    )

    parser.add_argument(
        "--control-poll-seconds",
        type=float,
        default=DEFAULT_CONTROL_POLL_SECONDS,
        help=(
            "How often the agent polls "
            "the demo control plane."
        ),
    )

    parser.add_argument(
        "--patch-max-age-days",
        type=int,
        default=DEFAULT_PATCH_MAX_AGE_DAYS,
    )

    parser.add_argument(
        "--simulate-firewall-disabled",
        action="store_true",
        help=(
            "Legacy demo flag: report "
            "firewall as disabled without "
            "changing Windows Firewall."
        ),
    )

    parser.add_argument(
        "--patch-refresh-seconds",
        type=int,
        default=(
            DEFAULT_PATCH_REFRESH_SECONDS
        ),
    )

    return parser.parse_args()


# ============================================================
# MAIN LOOP
# ============================================================

def main():
    args = parse_args()

    patch_cache = PatchCache(
        refresh_seconds=(
            args.patch_refresh_seconds
        ),
        patch_max_age_days=(
            args.patch_max_age_days
        ),
    )

    control = (
        default_demo_control()
    )

    previous_signature = (
        control_signature(
            control
        )
    )

    next_control_poll = 0.0
    next_posture_report = 0.0

    agent_loss_active = False

    print(
        "[DEVICE AGENT] Starting "
        f"v{AGENT_VERSION} "
        f"for {args.device_id}"
    )

    print(
        "[DEMO CONTROL] "
        f"poll_seconds="
        f"{args.control_poll_seconds}"
    )

    if (
        args.simulate_firewall_disabled
    ):
        print(
            "[DEMO MODE] Legacy CLI "
            "firewall simulation ENABLED "
            "(real Windows Firewall "
            "is NOT changed)"
        )

    print(
        "[PATCH POLICY] "
        f"max_age_days="
        f"{args.patch_max_age_days} "
        "pending_reboot_required=False "
        f"refresh_seconds="
        f"{args.patch_refresh_seconds}"
    )

    try:
        while True:
            now_monotonic = (
                time.monotonic()
            )

            control_changed = False

            # --------------------------------------------
            # Poll desired demo state.
            # --------------------------------------------

            if (
                now_monotonic
                >= next_control_poll
            ):
                try:
                    new_control = (
                        fetch_demo_control(
                            args
                        )
                    )

                    new_signature = (
                        control_signature(
                            new_control
                        )
                    )

                    if (
                        new_signature
                        != previous_signature
                    ):
                        control = new_control

                        previous_signature = (
                            new_signature
                        )

                        control_changed = True

                        print_control_state(
                            control
                        )

                    else:
                        control = new_control

                except Exception as exc:
                    print(
                        "[CONTROL WARNING] "
                        "Could not refresh "
                        "demo control; keeping "
                        "last known state: "
                        f"{exc}"
                    )

                next_control_poll = (
                    time.monotonic()
                    + max(
                        0.5,
                        args.control_poll_seconds,
                    )
                )

            # --------------------------------------------
            # Simulated agent loss.
            #
            # Agent process stays alive and continues
            # polling Demo Control, but deliberately
            # emits NO posture telemetry.
            # --------------------------------------------

            simulate_agent_loss = bool(
                control.get(
                    "simulate_agent_loss",
                    False,
                )
            )

            if simulate_agent_loss:
                if not agent_loss_active:
                    print(
                        "[DEMO MODE] "
                        "AGENT LOSS ACTIVE - "
                        "posture transmission "
                        "paused; control polling "
                        "continues."
                    )

                    agent_loss_active = True

                time.sleep(
                    0.20
                )

                continue

            # --------------------------------------------
            # Recovery from simulated agent loss.
            # Send posture immediately.
            # --------------------------------------------

            if agent_loss_active:
                print(
                    "[DEMO MODE] "
                    "AGENT LOSS CLEARED - "
                    "posture reporting resumes."
                )

                agent_loss_active = False
                control_changed = True

            # --------------------------------------------
            # Normal posture reporting.
            #
            # Send immediately when demo control changes
            # so the UI reacts without waiting 30 seconds.
            # --------------------------------------------

            if (
                control_changed
                or time.monotonic()
                >= next_posture_report
            ):
                try:
                    send_posture(
                        args,
                        patch_cache,
                        control,
                    )

                except Exception as exc:
                    print(
                        "[HEARTBEAT ERROR] "
                        f"{exc}"
                    )

                next_posture_report = (
                    time.monotonic()
                    + args.interval
                )

            time.sleep(
                0.20
            )

    except KeyboardInterrupt:
        print(
            "\n[DEVICE AGENT] "
            "Shutdown requested."
        )

    print(
        "[DEVICE AGENT] "
        "Stopped safely."
    )


if __name__ == "__main__":
    main()
