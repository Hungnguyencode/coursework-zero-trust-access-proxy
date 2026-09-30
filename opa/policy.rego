package zerotrust.authz

# ============================================================
# ZERO TRUST AUTHORIZATION POLICY v0.6
# Resource-aware ABAC + Continuous Device Trust
# ============================================================

patch_max_age_days := 45

default allow := false


# ============================================================
# COMMON HELPERS
# ============================================================

patch_evidence_present if {
    input.device.latest_hotfix_id != null
    input.device.patch_age_days != null
    input.device.pending_reboot != null
}

patch_compliant if {
    patch_evidence_present
    input.device.pending_reboot == false
    input.device.patch_age_days <= patch_max_age_days
}

authenticated_user if {
    input.authenticated == true
    input.user.active == true
}

registered_device if {
    input.device.registered == true
}

trusted_device if {
    input.device.trust_status == "trusted"
}

fresh_device if {
    input.device.heartbeat_fresh == true
}

privileged_role if {
    input.user.role in {"analyst", "admin"}
}

valid_request if {
    input.request.method == "GET"
}

context_allowed if {
    input.context.time_allowed == true
}


# ============================================================
# SENSITIVITY POLICIES
# ============================================================

low_allowed if {
    input.resource.sensitivity == "LOW"

    authenticated_user
    registered_device
    valid_request
}


medium_allowed if {
    input.resource.sensitivity == "MEDIUM"

    authenticated_user
    registered_device
    trusted_device
    fresh_device
    valid_request
}


high_allowed if {
    input.resource.sensitivity == "HIGH"

    authenticated_user
    registered_device
    privileged_role

    trusted_device
    input.device.firewall_enabled == true
    patch_compliant
    fresh_device

    context_allowed
    valid_request
}


# ============================================================
# FINAL DECISION
# ============================================================

allow if {
    low_allowed
}

allow if {
    medium_allowed
}

allow if {
    high_allowed
}


# ============================================================
# EXPLAINABLE DECISION REASON
# ============================================================

reason := "ALLOW" if {
    allow

} else := "AUTHENTICATION_FAILED" if {
    input.authenticated != true

} else := "USER_INACTIVE" if {
    input.user.active != true

} else := "DEVICE_NOT_REGISTERED" if {
    input.device.registered != true

} else := "RESOURCE_SENSITIVITY_UNKNOWN" if {
    not input.resource.sensitivity in {
        "LOW",
        "MEDIUM",
        "HIGH",
    }

} else := "DEVICE_UNTRUSTED" if {
    input.resource.sensitivity in {"MEDIUM", "HIGH"}
    input.device.trust_status != "trusted"

} else := "DEVICE_STALE" if {
    input.resource.sensitivity in {"MEDIUM", "HIGH"}
    input.device.heartbeat_fresh != true

} else := "ROLE_DENIED_FOR_HIGH_DATA" if {
    input.resource.sensitivity == "HIGH"
    not privileged_role

} else := "FIREWALL_DISABLED" if {
    input.resource.sensitivity == "HIGH"
    input.device.firewall_enabled != true

} else := "PATCH_EVIDENCE_MISSING" if {
    input.resource.sensitivity == "HIGH"
    not patch_evidence_present

} else := "PENDING_REBOOT" if {
    input.resource.sensitivity == "HIGH"
    input.device.pending_reboot == true

} else := "PATCH_TOO_OLD" if {
    input.resource.sensitivity == "HIGH"
    input.device.patch_age_days > patch_max_age_days

} else := "CONTEXT_DENIED" if {
    input.resource.sensitivity == "HIGH"
    input.context.time_allowed != true

} else := "REQUEST_DENIED" if {
    not valid_request

} else := "POLICY_DENIED"