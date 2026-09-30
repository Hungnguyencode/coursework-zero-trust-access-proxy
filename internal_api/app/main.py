import os
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Response


app = FastAPI(
    title="Zero Trust Internal Data API"
)

SHARED_SECRET = os.environ["INTERNAL_SHARED_SECRET"]


# ============================================================
# SYNTHETIC PROTECTED DATA
# ============================================================

RESOURCES = {
    1: {
        "id": 1,
        "customer": "Aurora Retail",
        "title": "Customer Account Summary",
        "sensitivity": "LOW",
        "category": "customer-profile",
        "description": (
            "General customer account information "
            "for internal operations."
        ),
        "data": {
            "region": "APAC",
            "account_status": "ACTIVE",
            "service_tier": "STANDARD",
        },
    },

    2: {
        "id": 2,
        "customer": "BluePeak Finance",
        "title": "Financial Risk Assessment",
        "sensitivity": "MEDIUM",
        "category": "financial-risk",
        "description": (
            "Internal financial and risk-analysis data."
        ),
        "data": {
            "risk_score": 68,
            "credit_band": "B",
            "review_status": "MONITOR",
        },
    },

    3: {
        "id": 3,
        "customer": "NovaSec Industries",
        "title": "Restricted Security Investigation",
        "sensitivity": "HIGH",
        "category": "security-investigation",
        "description": (
            "Restricted incident investigation evidence."
        ),
        "data": {
            "incident_id": "INC-2026-031",
            "exposure_scope": "CONFIDENTIAL",
            "investigation_status": "ACTIVE",
            "forensic_summary": (
                "Synthetic restricted security evidence "
                "for the Zero Trust demonstration."
            ),
        },
    },
}


# ============================================================
# INTERNAL AUTHORIZATION + CORRELATION
# ============================================================

def require_internal_secret(
    x_internal_secret: str | None,
) -> None:
    if x_internal_secret != SHARED_SECRET:
        raise HTTPException(
            status_code=403,
            detail="Direct access denied",
        )


def require_request_id(
    x_request_id: str | None,
) -> str:
    """
    Sensitive payload endpoints require a gateway-generated
    correlation ID. Metadata catalog access does not.
    """
    if not x_request_id:
        raise HTTPException(
            status_code=400,
            detail="Missing X-Request-ID",
        )

    try:
        return str(UUID(x_request_id))
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(
            status_code=400,
            detail="Invalid X-Request-ID",
        )


def log_sensitive_fetch(
    *,
    request_id: str,
    path: str,
    resource_id: str | int,
    sensitivity: str,
) -> None:
    """
    Deliberately visible in `docker compose logs internal-api`.
    This is evidence that the sensitive endpoint was actually hit.
    """
    print(
        "[SENSITIVE_FETCH] "
        f"request_id={request_id} "
        f"path={path} "
        f"resource_id={resource_id} "
        f"sensitivity={sensitivity}",
        flush=True,
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "internal-data-api",
    }


# ============================================================
# RESOURCE CATALOG
#
# Metadata only.
# Sensitive resource content is deliberately excluded.
# A correlation ID is intentionally NOT required here because
# the gateway may inspect metadata before the OPA decision.
# ============================================================

@app.get("/internal/resources")
def list_resources(
    x_internal_secret: str | None = Header(
        default=None
    ),
):
    require_internal_secret(
        x_internal_secret
    )

    return {
        "resources": [
            {
                "id": resource["id"],
                "customer": resource["customer"],
                "title": resource["title"],
                "sensitivity": resource["sensitivity"],
                "category": resource["category"],
                "description": resource["description"],
            }
            for resource in RESOURCES.values()
        ]
    }


# ============================================================
# SINGLE PROTECTED RESOURCE
#
# Full sensitive payload. This endpoint is reached only after
# the Access Proxy has obtained an ALLOW decision from OPA.
# ============================================================

@app.get(
    "/internal/resources/{resource_id}"
)
def get_resource(
    resource_id: int,
    response: Response,
    x_internal_secret: str | None = Header(
        default=None
    ),
    x_request_id: str | None = Header(
        default=None,
        alias="X-Request-ID",
    ),
):
    require_internal_secret(
        x_internal_secret
    )

    request_id = require_request_id(
        x_request_id
    )

    resource = RESOURCES.get(
        resource_id
    )

    if resource is None:
        raise HTTPException(
            status_code=404,
            detail="Resource not found",
        )

    log_sensitive_fetch(
        request_id=request_id,
        path=(
            f"/internal/resources/{resource_id}"
        ),
        resource_id=resource_id,
        sensitivity=resource["sensitivity"],
    )

    # Echo the gateway correlation ID back to the caller.
    # The Access Proxy verifies this before it marks the
    # sensitive fetch as successfully correlated.
    response.headers["X-Request-ID"] = request_id

    return resource


# ============================================================
# LEGACY V1.3 ENDPOINT
#
# Kept temporarily so the existing Security Center remains
# functional while V1.4 is being developed.
# This is still a sensitive payload endpoint, so correlation is
# required here as well.
# ============================================================

@app.get("/internal/data")
def get_internal_data(
    response: Response,
    x_internal_secret: str | None = Header(
        default=None
    ),
    x_request_id: str | None = Header(
        default=None,
        alias="X-Request-ID",
    ),
):
    require_internal_secret(
        x_internal_secret
    )

    request_id = require_request_id(
        x_request_id
    )

    log_sensitive_fetch(
        request_id=request_id,
        path="/internal/data",
        resource_id="legacy-data-bundle",
        sensitivity="HIGH",
    )

    response.headers["X-Request-ID"] = request_id

    return {
        "classification": "INTERNAL",
        "records": [
            {
                "id": resource["id"],
                "customer": resource["customer"],
                "risk": (
                    resource["sensitivity"]
                    .lower()
                ),
            }
            for resource in RESOURCES.values()
        ],
    }
