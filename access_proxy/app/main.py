import json
import os
import select as select_io
import time
import uuid
import psycopg2
from datetime import datetime, timedelta, timezone
import bcrypt
import httpx
import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    create_engine,
    select,
    text,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
# ============================================================
# 1. CONFIGURATION
# ============================================================
DATABASE_URL = os.getenv("DATABASE_URL")
OPA_URL = os.getenv(
    "OPA_URL",
    "http://opa:8181/v1/data/zerotrust/authz",
)
OPA_POLICY_VERSION = "zerotrust-authz-v0.6"
INTERNAL_API_URL = os.getenv(
    "INTERNAL_API_URL",
    "http://internal-api:8000",
)
INTERNAL_SHARED_SECRET = os.environ["INTERNAL_SHARED_SECRET"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = os.getenv(
    "JWT_ALGORITHM",
    "HS256",
)
JWT_EXPIRE_MINUTES = int(
    os.getenv("JWT_EXPIRE_MINUTES", "30")
)
DEMO_ADMIN_KEY = os.getenv(
    "DEMO_ADMIN_KEY",
    "demo-admin-key",
)
HEARTBEAT_STALE_SECONDS = int(
    os.getenv("HEARTBEAT_STALE_SECONDS", "90")
)
REALTIME_CHANNEL = "zt_realtime"
LISTEN_DATABASE_URL = DATABASE_URL.replace(
    "postgresql+psycopg2://",
    "postgresql://",
    1,
)
# ============================================================
# 2. DATABASE MODELS
# ============================================================
class Base(DeclarativeBase):
    pass
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    username: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        String(200),
    )
    role: Mapped[str] = mapped_column(
        String(30),
        default="viewer",
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    device_id: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
    )
    device_name: Mapped[str] = mapped_column(
        String(100),
        default="Demo Laptop",
    )
    registered: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    trust_status: Mapped[str] = mapped_column(
        String(20),
        default="trusted",
    )
    # Cache của posture mới nhất để tương thích với Core v0.1.
    firewall_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
    )
    patch_status: Mapped[str] = mapped_column(
        String(20),
        default="updated",
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
class DevicePosture(Base):
    """
    Append-only time-series telemetry from the Device Agent.
    """
    __tablename__ = "device_postures"
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    device_pk: Mapped[int] = mapped_column(
        ForeignKey("devices.id"),
        index=True,
    )
    hostname: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )
    os_name: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    os_release: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    os_version: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    agent_version: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )
    firewall_enabled: Mapped[bool] = mapped_column(
        Boolean,
    )
    patch_status: Mapped[str] = mapped_column(
        String(20),
    )
    # Patch evidence persisted by migration 001.
    latest_hotfix_id: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    latest_hotfix_installed_on: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    patch_age_days: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )
    pending_reboot: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )
    patch_reason: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
class AccessLog(Base):
    __tablename__ = "access_logs"
    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
    )
    username: Mapped[str] = mapped_column(
        String(50),
    )
    device_id: Mapped[str] = mapped_column(
        String(80),
    )
    method: Mapped[str] = mapped_column(
        String(10),
    )
    path: Mapped[str] = mapped_column(
        String(200),
    )
    decision: Mapped[str] = mapped_column(
        String(10),
    )
    reason: Mapped[str] = mapped_column(
        String(100),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
    # ========================================================
    # V1.4E - REQUEST CORRELATION / DECISION EVIDENCE
    # ========================================================
    request_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
    )
    resource_id: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )
    resource_sensitivity: Mapped[str | None] = mapped_column(
        String(10),
        nullable=True,
    )
    policy_version: Mapped[str | None] = mapped_column(
        String(40),
        nullable=True,
    )
    decision_context: Mapped[dict] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(80),
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(20),
        default="info",
    )
    username: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(80),
        nullable=True,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(50),
    )
    reason: Mapped[str | None] = mapped_column(
        String(120),
        nullable=True,
    )
    old_value: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    new_value: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )
    details: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
class RealtimeEvent(Base):
    """
    Durable realtime event outbox.
    PostgreSQL NOTIFY is only the wake-up signal.
    This table remains the durable source for replay.
    """
    __tablename__ = "realtime_events"
    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(80),
        index=True,
    )
    username: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(80),
        nullable=True,
        index=True,
    )
    payload: Mapped[dict] = mapped_column(
        JSONB,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
class DemoControl(Base):
    """
    Desired demo simulation state.
    This table does NOT represent real device posture.
    The Device Agent reads these values and then reports
    posture through the normal telemetry pipeline.
    """
    __tablename__ = "demo_controls"
    device_id: Mapped[str] = mapped_column(
        String(80),
        primary_key=True,
    )
    simulate_firewall_disabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )
    simulate_patch_outdated: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )
    simulate_agent_loss: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
# ============================================================
# 3. DATABASE CONNECTION
# ============================================================
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# ============================================================
# 4. AUTHENTICATION HELPERS
# ============================================================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt(),
    ).decode()
def verify_password(
    password: str,
    password_hash: str,
) -> bool:
    return bcrypt.checkpw(
        password.encode(),
        password_hash.encode(),
    )
def create_token(
    user: User,
    device_id: str,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.username,
        "role": user.role,
        "device_id": device_id,
        "iat": int(now.timestamp()),
        "exp": int(
            (
                now
                + timedelta(minutes=JWT_EXPIRE_MINUTES)
            ).timestamp()
        ),
    }
    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
def decode_token(
    authorization: str | None,
) -> dict:
    if (
        not authorization
        or not authorization.startswith("Bearer ")
    ):
        raise HTTPException(
            status_code=401,
            detail="Missing Bearer token",
        )
    token = authorization.split(" ", 1)[1]
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
        )
def get_authenticated_user(
    authorization: str | None,
    db: Session,
) -> tuple[dict, User]:
    claims = decode_token(
        authorization
    )
    user = db.scalar(
        select(User).where(
            User.username == claims.get("sub")
        )
    )
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Unknown user",
        )
    if not user.active:
        raise HTTPException(
            status_code=403,
            detail="User is not active",
        )
    return claims, user


def require_security_admin(
    authorization: str | None,
    db: Session,
) -> tuple[dict, User]:
    claims, user = get_authenticated_user(
        authorization,
        db,
    )
    if user.role != "security-admin":
        raise HTTPException(
            status_code=403,
            detail="Security Center requires security-admin role",
        )
    return claims, user


# ============================================================
# 5. SEED DATA
# ============================================================
def seed():
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        alice = db.scalar(
            select(User).where(
                User.username == "alice"
            )
        )
        if alice is None:
            alice = User(
                username="alice",
                password_hash=hash_password("alice123"),
                role="analyst",
                active=True,
            )
            db.add(alice)
            db.flush()
        alice_device = db.scalar(
            select(Device).where(
                Device.device_id == "DEV-001"
            )
        )
        if alice_device is None:
            db.add(
                Device(
                    device_id="DEV-001",
                    user_id=alice.id,
                    device_name="Alice Demo Laptop",
                    registered=True,
                    trust_status="trusted",
                    firewall_enabled=True,
                    patch_status="updated",
                )
            )

        bob = db.scalar(
            select(User).where(
                User.username == "bob"
            )
        )
        if bob is None:
            bob = User(
                username="bob",
                password_hash=hash_password("bob123"),
                role="viewer",
                active=True,
            )
            db.add(bob)
            db.flush()
        bob_device = db.scalar(
            select(Device).where(
                Device.device_id == "DEV-002"
            )
        )
        if bob_device is None:
            db.add(
                Device(
                    device_id="DEV-002",
                    user_id=bob.id,
                    device_name="Bob Demo Laptop",
                    registered=True,
                    trust_status="trusted",
                    firewall_enabled=True,
                    patch_status="updated",
                )
            )

        socadmin = db.scalar(
            select(User).where(
                User.username == "socadmin"
            )
        )
        if socadmin is None:
            socadmin = User(
                username="socadmin",
                password_hash=hash_password("socadmin123"),
                role="security-admin",
                active=True,
            )
            db.add(socadmin)
            db.flush()
        soc_device = db.scalar(
            select(Device).where(
                Device.device_id == "SOC-001"
            )
        )
        if soc_device is None:
            db.add(
                Device(
                    device_id="SOC-001",
                    user_id=socadmin.id,
                    device_name="SOC Admin Console",
                    registered=True,
                    trust_status="trusted",
                    firewall_enabled=True,
                    patch_status="updated",
                )
            )

        db.commit()
# ============================================================
# 6. FASTAPI APP
# ============================================================
app = FastAPI(
    title="Zero Trust Access Proxy",
)
@app.on_event("startup")
def startup():
    seed()
# ============================================================
# 7. REQUEST SCHEMAS
# ============================================================
class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: str
class TrustUpdate(BaseModel):
    trust_status: str
class PostureUpdate(BaseModel):
    firewall_enabled: bool
    patch_status: str
    hostname: str | None = None
    os_name: str | None = None
    os_release: str | None = None
    os_version: str | None = None
    agent_version: str | None = None
    latest_hotfix_id: str | None = None
    latest_hotfix_installed_on: datetime | None = None
    patch_age_days: float | None = None
    pending_reboot: bool | None = None
    patch_reason: str | None = None
class DemoControlUpdate(BaseModel):
    simulate_firewall_disabled: bool | None = None
    simulate_patch_outdated: bool | None = None
    simulate_agent_loss: bool | None = None

# ============================================================
# V1.5 IDENTITY LIFECYCLE SCHEMAS
# ============================================================
class ProvisionUserRequest(BaseModel):
    username: str
    password: str
    device_id: str
    device_name: str | None = None


class RoleUpdate(BaseModel):
    role: str


# ============================================================
# 8. INTERNAL HELPERS
# ============================================================
def demo_control_payload(
    device_id: str,
    control: DemoControl | None,
) -> dict:
    return {
        "device_id": device_id,
        "simulate_firewall_disabled": (
            control.simulate_firewall_disabled
            if control
            else False
        ),
        "simulate_patch_outdated": (
            control.simulate_patch_outdated
            if control
            else False
        ),
        "simulate_agent_loss": (
            control.simulate_agent_loss
            if control
            else False
        ),
        "updated_at": (
            control.updated_at
            if control
            else None
        ),
    }
def get_latest_posture(
    db: Session,
    device: Device | None,
) -> DevicePosture | None:
    if not device:
        return None
    return db.scalar(
        select(DevicePosture)
        .where(
            DevicePosture.device_pk == device.id
        )
        .order_by(
            DevicePosture.id.desc()
        )
        .limit(1)
    )
def get_heartbeat_status(
    latest_posture: DevicePosture | None,
) -> tuple[bool, float | None]:
    if not latest_posture:
        return False, None
    now = datetime.now(timezone.utc)
    reported_at = latest_posture.reported_at
    if reported_at.tzinfo is None:
        reported_at = reported_at.replace(
            tzinfo=timezone.utc
        )
    heartbeat_age_seconds = max(
        0,
        (now - reported_at).total_seconds(),
    )
    heartbeat_fresh = (
        heartbeat_age_seconds
        <= HEARTBEAT_STALE_SECONDS
    )
    return (
        heartbeat_fresh,
        heartbeat_age_seconds,
    )
def emit_realtime_event(
    db: Session,
    *,
    event_type: str,
    username: str | None = None,
    device_id: str | None = None,
    payload: dict | None = None,
    created_at: datetime | None = None,
) -> RealtimeEvent:
    """
    Transactional realtime outbox.
    1. Persist event row.
    2. Flush to obtain event ID.
    3. pg_notify() inside the SAME transaction.
    4. PostgreSQL delivers NOTIFY only after COMMIT.
    Therefore:
    no committed notification points to a missing event row.
    """
    event = RealtimeEvent(
        event_type=event_type,
        username=username,
        device_id=device_id,
        payload=payload or {},
        created_at=(
            created_at
            or datetime.now(timezone.utc)
        ),
    )
    db.add(event)
    db.flush()
    notify_payload = json.dumps(
        {
            "id": event.id,
        }
    )
    db.execute(
        text(
            "SELECT pg_notify("
            ":channel, :payload"
            ")"
        ),
        {
            "channel": REALTIME_CHANNEL,
            "payload": notify_payload,
        },
    )
    return event
def save_access_log(
    db: Session,
    *,
    username: str,
    device_id: str,
    method: str,
    path: str,
    decision: str,
    reason: str,
    request_id: uuid.UUID | None = None,
    resource_id: int | None = None,
    resource_sensitivity: str | None = None,
    policy_version: str | None = None,
    decision_context: dict | None = None,
) -> AccessLog:
    access_log = AccessLog(
        username=username,
        device_id=device_id,
        method=method,
        path=path,
        decision=decision,
        reason=reason,
        request_id=request_id,
        resource_id=resource_id,
        resource_sensitivity=(
            resource_sensitivity
        ),
        policy_version=policy_version,
        decision_context=(
            decision_context or {}
        ),
    )
    db.add(access_log)
    db.flush()
    emit_realtime_event(
        db,
        event_type="ACCESS_DECISION",
        username=username,
        device_id=device_id,
        payload={
            "access_log_id":
                access_log.id,
            "request_id": (
                str(request_id)
                if request_id
                else None
            ),
            "method":
                method,
            "path":
                path,
            "resource_id":
                resource_id,
            "resource_sensitivity":
                resource_sensitivity,
            "policy_version":
                policy_version,
            "decision":
                decision,
            "reason":
                reason,
        },
        created_at=access_log.created_at,
    )
    db.commit()
    return access_log
def update_data_api_evidence(
    db: Session,
    *,
    access_log: AccessLog,
    request_id: uuid.UUID,
    path: str,
    status: str,
    upstream_request_id: str | None = None,
    detail: str | None = None,
) -> AccessLog:
    """Persist post-policy delivery evidence for Decision Inspector.
    The authorization decision is already durable when this helper runs.
    This updates the immutable decision snapshot with what happened next
    at the Data API boundary.
    """
    current_context = dict(
        access_log.decision_context or {}
    )
    data_api = {
        "status": status,
        "path": path,
        "request_id": str(request_id),
        "upstream_request_id": upstream_request_id,
        "request_id_match": (
            upstream_request_id == str(request_id)
            if upstream_request_id is not None
            else None
        ),
    }
    if detail:
        data_api["detail"] = detail
    current_context["data_api"] = data_api
    access_log.decision_context = current_context
    db.add(access_log)
    db.flush()
    if status in {
        "FETCHED",
        "FETCH_FAILED",
    }:
        emit_realtime_event(
            db,
            event_type=(
                "DATA_API_FETCHED"
                if status == "FETCHED"
                else "DATA_API_FETCH_FAILED"
            ),
            username=access_log.username,
            device_id=access_log.device_id,
            payload={
                "access_log_id": access_log.id,
                "request_id": str(request_id),
                "path": path,
                "status": status,
                "upstream_request_id": upstream_request_id,
                "request_id_match": data_api["request_id_match"],
                "detail": detail,
            },
        )
    db.commit()
    db.refresh(access_log)
    return access_log
def add_security_event(
    db: Session,
    *,
    event_type: str,
    severity: str,
    source: str,
    username: str | None = None,
    device_id: str | None = None,
    reason: str | None = None,
    old_value: str | None = None,
    new_value: str | None = None,
    details: dict | None = None,
    created_at: datetime | None = None,
) -> SecurityEvent:
    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        username=username,
        device_id=device_id,
        source=source,
        reason=reason,
        old_value=old_value,
        new_value=new_value,
        details=details or {},
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.add(event)
    db.flush()
    emit_realtime_event(
        db,
        event_type="SECURITY_EVENT",
        username=username,
        device_id=device_id,
        payload={
            "security_event_id": event.id,
            "security_event_type": event.event_type,
            "severity": event.severity,
            "source": event.source,
            "reason": event.reason,
            "old_value": event.old_value,
            "new_value": event.new_value,
        },
        created_at=event.created_at,
    )
    return event
HEARTBEAT_EVENT_TYPES = (
    "DEVICE_HEARTBEAT_STALE",
    "DEVICE_HEARTBEAT_RECOVERED",
)
def get_latest_heartbeat_event(
    db: Session,
    device_id: str,
) -> SecurityEvent | None:
    return db.scalar(
        select(SecurityEvent)
        .where(
            SecurityEvent.device_id == device_id,
            SecurityEvent.event_type.in_(
                HEARTBEAT_EVENT_TYPES
            ),
        )
        .order_by(SecurityEvent.id.desc())
        .limit(1)
    )
def normalized_utc(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )
    return value.astimezone(
        timezone.utc
    )
async def evaluate_with_opa(
    opa_input: dict,
) -> dict:
    async with httpx.AsyncClient(
        timeout=5
    ) as client:
        try:
            response = await client.post(
                OPA_URL,
                json={
                    "input": opa_input,
                },
            )
            response.raise_for_status()
            return response.json().get(
                "result",
                {},
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=f"OPA unavailable: {exc}",
            )
async def fetch_resource_catalog() -> list[dict]:
    async with httpx.AsyncClient(
        timeout=5
    ) as client:
        try:
            response = await client.get(
                (
                    f"{INTERNAL_API_URL}"
                    "/internal/resources"
                ),
                headers={
                    "X-Internal-Secret": (
                        INTERNAL_SHARED_SECRET
                    ),
                },
            )
            response.raise_for_status()
            payload = response.json()
            return payload.get(
                "resources",
                [],
            )
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Internal resource catalog "
                    f"unavailable: {exc}"
                ),
            )
async def fetch_internal_resource(
    resource_id: int,
    request_id: uuid.UUID,
) -> tuple[dict, str]:
    async with httpx.AsyncClient(
        timeout=5
    ) as client:
        try:
            response = await client.get(
                (
                    f"{INTERNAL_API_URL}"
                    f"/internal/resources/{resource_id}"
                ),
                headers={
                    "X-Internal-Secret": (
                        INTERNAL_SHARED_SECRET
                    ),
                    "X-Request-ID": str(
                        request_id
                    ),
                },
            )
            if response.status_code == 404:
                raise HTTPException(
                    status_code=404,
                    detail="Resource not found",
                )
            response.raise_for_status()
            upstream_request_id = (
                response.headers.get(
                    "X-Request-ID"
                )
            )
            if upstream_request_id != str(request_id):
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Internal API correlation mismatch"
                    ),
                )
            return (
                response.json(),
                upstream_request_id,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Internal protected resource "
                    f"unavailable: {exc}"
                ),
            )
async def fetch_legacy_internal_data(
    request_id: uuid.UUID,
) -> tuple[dict, str]:
    async with httpx.AsyncClient(
        timeout=5
    ) as client:
        try:
            response = await client.get(
                (
                    f"{INTERNAL_API_URL}"
                    "/internal/data"
                ),
                headers={
                    "X-Internal-Secret": (
                        INTERNAL_SHARED_SECRET
                    ),
                    "X-Request-ID": str(
                        request_id
                    ),
                },
            )
            response.raise_for_status()
            upstream_request_id = (
                response.headers.get(
                    "X-Request-ID"
                )
            )
            if upstream_request_id != str(request_id):
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Internal API correlation mismatch"
                    ),
                )
            return (
                response.json(),
                upstream_request_id,
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Internal protected data "
                    f"unavailable: {exc}"
                ),
            )
# ============================================================
# 9. HEALTH ENDPOINT
# ============================================================
@app.get("/health")
def health():
    return {
        "status": "ok",
    }
# ============================================================
# 10. AUTH ENDPOINT
# ============================================================
@app.post("/auth/login")
def login(
    payload: LoginRequest,
    db: Session = Depends(get_db),
):
    user = db.scalar(
        select(User).where(
            User.username == payload.username
        )
    )
    if (
        not user
        or not verify_password(
            payload.password,
            user.password_hash,
        )
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )
    device = db.scalar(
        select(Device).where(
            Device.device_id == payload.device_id,
            Device.user_id == user.id,
        )
    )
    if not device:
        raise HTTPException(
            status_code=403,
            detail="Device is not registered to this user",
        )
    return {
        "access_token": create_token(
            user,
            payload.device_id,
        ),
        "token_type": "bearer",
        "expires_in_minutes": JWT_EXPIRE_MINUTES,
        "user": {
            "username": user.username,
            "role": user.role,
        },
        "device": {
            "device_id": device.device_id,
            "trust_status": device.trust_status,
        },
    }

# ============================================================
# V1.5 IDENTITY LIFECYCLE API
#
# Enterprise-style provisioning:
# - New business users always start as VIEWER.
# - New managed devices start REGISTERED but UNTRUSTED.
# - Only security-admin can provision / change business roles.
# - security-admin itself is NOT assignable from this API.
# ============================================================
def _managed_user_payload(
    db: Session,
    user: User,
) -> dict:
    devices = db.scalars(
        select(Device)
        .where(Device.user_id == user.id)
        .order_by(Device.device_id)
    ).all()

    device_rows = []
    for device in devices:
        latest_posture = get_latest_posture(
            db,
            device,
        )
        heartbeat_fresh, heartbeat_age_seconds = (
            get_heartbeat_status(latest_posture)
        )
        device_rows.append(
            {
                "device_id": device.device_id,
                "device_name": device.device_name,
                "registered": device.registered,
                "trust_status": device.trust_status,
                "heartbeat_fresh": heartbeat_fresh,
                "heartbeat_age_seconds": heartbeat_age_seconds,
                "last_seen": (
                    latest_posture.reported_at
                    if latest_posture
                    else device.last_seen
                ),
            }
        )

    return {
        "username": user.username,
        "role": user.role,
        "active": user.active,
        "devices": device_rows,
    }


@app.get("/admin/users")
def list_managed_users(
    authorization: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    require_security_admin(
        authorization,
        db,
    )

    users = db.scalars(
        select(User)
        .where(User.role != "security-admin")
        .order_by(User.username)
    ).all()

    return {
        "users": [
            _managed_user_payload(db, user)
            for user in users
        ],
        "role_model": {
            "default_role": "viewer",
            "assignable_roles": [
                "viewer",
                "analyst",
            ],
            "protected_role": "security-admin",
        },
    }


@app.post(
    "/admin/users",
    status_code=201,
)
def provision_business_user(
    payload: ProvisionUserRequest,
    x_admin_key: str | None = Header(
        default=None
    ),
    authorization: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    _, actor = require_security_admin(
        authorization,
        db,
    )

    if x_admin_key != DEMO_ADMIN_KEY:
        raise HTTPException(
            status_code=403,
            detail="Bad admin key",
        )

    username = payload.username.strip().lower()
    password = payload.password
    device_id = payload.device_id.strip().upper()
    device_name = (
        payload.device_name.strip()
        if payload.device_name
        else f"{username} managed device"
    )

    if not (
        3 <= len(username) <= 32
        and all(
            ch.isalnum() or ch in "._-"
            for ch in username
        )
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Username must be 3-32 characters "
                "using letters, numbers, dot, underscore or hyphen"
            ),
        )

    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must contain at least 8 characters",
        )

    if not (
        3 <= len(device_id) <= 40
        and all(
            ch.isalnum() or ch in "-_"
            for ch in device_id
        )
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Device ID must be 3-40 characters "
                "using letters, numbers, hyphen or underscore"
            ),
        )

    if len(device_name) > 100:
        raise HTTPException(
            status_code=400,
            detail="Device name must be at most 100 characters",
        )

    existing_user = db.scalar(
        select(User).where(
            User.username == username
        )
    )
    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="Username already exists",
        )

    existing_device = db.scalar(
        select(Device).where(
            Device.device_id == device_id
        )
    )
    if existing_device:
        raise HTTPException(
            status_code=409,
            detail="Device ID already exists",
        )

    user = User(
        username=username,
        password_hash=hash_password(password),
        role="viewer",
        active=True,
    )
    db.add(user)
    db.flush()

    device = Device(
        device_id=device_id,
        user_id=user.id,
        device_name=device_name,
        registered=True,
        trust_status="untrusted",
        firewall_enabled=False,
        patch_status="unknown",
    )
    db.add(device)
    db.flush()

    event = add_security_event(
        db,
        event_type="USER_PROVISIONED",
        severity="info",
        source="identity-governance",
        username=username,
        device_id=device_id,
        reason="LEAST_PRIVILEGE_DEFAULT",
        old_value="none",
        new_value="viewer",
        details={
            "actor": actor.username,
            "initial_role": "viewer",
            "initial_trust": "untrusted",
            "security_admin_assignable": False,
        },
    )

    db.commit()
    db.refresh(user)
    db.refresh(device)

    return {
        "status": "PROVISIONED",
        "user": {
            "username": user.username,
            "role": user.role,
            "active": user.active,
        },
        "device": {
            "device_id": device.device_id,
            "device_name": device.device_name,
            "registered": device.registered,
            "trust_status": device.trust_status,
        },
        "security_event_id": event.id,
        "agent_command": (
            "python device_agent\\agent.py "
            f"--device-id {device.device_id}"
        ),
        "note": (
            "New business users start as viewer; "
            "new managed devices start untrusted."
        ),
    }


@app.put("/admin/users/{username}/role")
def update_business_role(
    username: str,
    payload: RoleUpdate,
    x_admin_key: str | None = Header(
        default=None
    ),
    authorization: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    _, actor = require_security_admin(
        authorization,
        db,
    )

    if x_admin_key != DEMO_ADMIN_KEY:
        raise HTTPException(
            status_code=403,
            detail="Bad admin key",
        )

    new_role = payload.role.strip().lower()
    if new_role not in {
        "viewer",
        "analyst",
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "Only viewer or analyst can be assigned here. "
                "security-admin is bootstrap/trusted-admin only."
            ),
        )

    target = db.scalar(
        select(User).where(
            User.username == username.strip().lower()
        )
    )
    if not target:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    if target.role == "security-admin":
        raise HTTPException(
            status_code=403,
            detail=(
                "security-admin is protected from "
                "business-role assignment"
            ),
        )

    old_role = target.role

    if old_role != new_role:
        target.role = new_role

        event = add_security_event(
            db,
            event_type="USER_ROLE_CHANGED",
            severity=(
                "warning"
                if new_role == "analyst"
                else "info"
            ),
            source="identity-governance",
            username=target.username,
            reason=(
                "NEED_TO_KNOW_GRANTED"
                if new_role == "analyst"
                else "LEAST_PRIVILEGE_RESTORED"
            ),
            old_value=old_role,
            new_value=new_role,
            details={
                "actor": actor.username,
                "security_admin_assignable": False,
            },
        )
        security_event_id = event.id
    else:
        security_event_id = None

    db.commit()
    db.refresh(target)

    return {
        "status": "ROLE_UPDATED",
        "user": {
            "username": target.username,
            "role": target.role,
            "active": target.active,
        },
        "old_role": old_role,
        "new_role": target.role,
        "security_event_id": security_event_id,
        "authorization_note": (
            "Protected requests read the current database role, "
            "so the next request is re-evaluated without requiring "
            "a new business login."
        ),
    }


# ============================================================
# 11. DEVICE ENDPOINTS
# ============================================================
@app.get("/devices")
def list_devices(
    authorization: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    claims, user = get_authenticated_user(
        authorization,
        db,
    )
    if user.role == "security-admin":
        devices = db.scalars(
            select(Device)
            .join(
                User,
                Device.user_id == User.id,
            )
            .where(
                User.role != "security-admin"
            )
            .order_by(
                Device.device_id
            )
        ).all()
    else:
        devices = db.scalars(
            select(Device).where(
                Device.user_id == user.id
            )
        ).all()

    result = []
    for device in devices:
        owner = db.scalar(
            select(User).where(
                User.id == device.user_id
            )
        )
        latest_posture = get_latest_posture(
            db,
            device,
        )
        (
            heartbeat_fresh,
            heartbeat_age_seconds,
        ) = get_heartbeat_status(
            latest_posture
        )
        result.append(
            {
                "device_id": device.device_id,
                "device_name": device.device_name,
                "owner_username": (
                    owner.username
                    if owner
                    else None
                ),
                "owner_role": (
                    owner.role
                    if owner
                    else None
                ),
                "registered": device.registered,
                "trust_status": device.trust_status,
                "firewall_enabled": (
                    latest_posture.firewall_enabled
                    if latest_posture
                    else device.firewall_enabled
                ),
                "patch_status": (
                    latest_posture.patch_status
                    if latest_posture
                    else device.patch_status
                ),
                "hostname": (
                    latest_posture.hostname
                    if latest_posture
                    else None
                ),
                "os_name": (
                    latest_posture.os_name
                    if latest_posture
                    else None
                ),
                "os_release": (
                    latest_posture.os_release
                    if latest_posture
                    else None
                ),
                "os_version": (
                    latest_posture.os_version
                    if latest_posture
                    else None
                ),
                "agent_version": (
                    latest_posture.agent_version
                    if latest_posture
                    else None
                ),
                "latest_hotfix_id": (
                    latest_posture.latest_hotfix_id
                    if latest_posture
                    else None
                ),
                "latest_hotfix_installed_on": (
                    latest_posture.latest_hotfix_installed_on
                    if latest_posture
                    else None
                ),
                "patch_age_days": (
                    latest_posture.patch_age_days
                    if latest_posture
                    else None
                ),
                "pending_reboot": (
                    latest_posture.pending_reboot
                    if latest_posture
                    else None
                ),
                "patch_reason": (
                    latest_posture.patch_reason
                    if latest_posture
                    else None
                ),
                "heartbeat_fresh": heartbeat_fresh,
                "heartbeat_age_seconds": heartbeat_age_seconds,
                "last_seen": (
                    latest_posture.reported_at
                    if latest_posture
                    else device.last_seen
                ),
            }
        )
    return result


@app.get(
    "/devices/{device_id}/postures"
)
def posture_history(
    device_id: str,
    authorization: str | None = Header(
        default=None
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    db: Session = Depends(get_db),
):
    claims, user = get_authenticated_user(
        authorization,
        db,
    )
    if user.role == "security-admin":
        device = db.scalar(
            select(Device).where(
                Device.device_id == device_id
            )
        )
    else:
        device = db.scalar(
            select(Device).where(
                Device.device_id == device_id,
                Device.user_id == user.id,
            )
        )
    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )
    rows = db.scalars(
        select(DevicePosture)
        .where(
            DevicePosture.device_pk == device.id
        )
        .order_by(
            DevicePosture.id.desc()
        )
        .limit(limit)
    ).all()
    return [
        {
            "id": row.id,
            "device_id": device.device_id,
            "hostname": row.hostname,
            "os_name": row.os_name,
            "os_release": row.os_release,
            "os_version": row.os_version,
            "agent_version": row.agent_version,
            "firewall_enabled": row.firewall_enabled,
            "patch_status": row.patch_status,
            "latest_hotfix_id": row.latest_hotfix_id,
            "latest_hotfix_installed_on": row.latest_hotfix_installed_on,
            "patch_age_days": row.patch_age_days,
            "pending_reboot": row.pending_reboot,
            "patch_reason": row.patch_reason,
            "reported_at": row.reported_at,
        }
        for row in rows
    ]


@app.put(
    "/admin/devices/{device_id}/trust"
)
def update_trust(
    device_id: str,
    payload: TrustUpdate,
    x_admin_key: str | None = Header(
        default=None
    ),
    authorization: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    require_security_admin(
        authorization,
        db,
    )
    if x_admin_key != DEMO_ADMIN_KEY:
        raise HTTPException(
            status_code=403,
            detail="Bad admin key",
        )
    if payload.trust_status not in {
        "trusted",
        "untrusted",
    }:
        raise HTTPException(
            status_code=400,
            detail="trust_status must be trusted/untrusted",
        )
    device = db.scalar(
        select(Device).where(
            Device.device_id == device_id
        )
    )
    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )
    old_trust_status = device.trust_status
    new_trust_status = payload.trust_status
    device.trust_status = new_trust_status
    owner = db.scalar(
        select(User).where(
            User.id == device.user_id
        )
    )
    security_event = None
    if old_trust_status != new_trust_status:
        security_event = add_security_event(
            db,
            event_type="DEVICE_TRUST_CHANGED",
            severity=(
                "high"
                if new_trust_status == "untrusted"
                else "info"
            ),
            username=(
                owner.username
                if owner
                else None
            ),
            device_id=device.device_id,
            source="admin-control",
            reason="MANUAL_TRUST_OVERRIDE",
            old_value=old_trust_status,
            new_value=new_trust_status,
            details={
                "registered": device.registered,
            },
        )
    db.commit()
    if security_event:
        db.refresh(security_event)
    return {
        "device_id": device.device_id,
        "trust_status": device.trust_status,
        "event": (
            {
                "id": security_event.id,
                "event_type": security_event.event_type,
                "old_value": security_event.old_value,
                "new_value": security_event.new_value,
                "created_at": security_event.created_at,
            }
            if security_event
            else None
        ),
    }
# ============================================================
# DEMO CONTROL PLANE
#
# Desired simulation state only.
# The Device Agent must consume this state and report telemetry
# through the normal posture endpoint.
# ============================================================
@app.get(
    "/admin/demo/devices/{device_id}/control"
)
def get_demo_control(
    device_id: str,
    x_admin_key: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    if x_admin_key != DEMO_ADMIN_KEY:
        raise HTTPException(
            status_code=403,
            detail="Bad admin key",
        )
    device = db.scalar(
        select(Device).where(
            Device.device_id == device_id
        )
    )
    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )
    control = db.get(
        DemoControl,
        device_id,
    )
    return demo_control_payload(
        device_id,
        control,
    )
@app.put(
    "/admin/demo/devices/{device_id}/control"
)
def update_demo_control(
    device_id: str,
    payload: DemoControlUpdate,
    x_admin_key: str | None = Header(
        default=None
    ),
    authorization: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    require_security_admin(
        authorization,
        db,
    )
    if x_admin_key != DEMO_ADMIN_KEY:
        raise HTTPException(
            status_code=403,
            detail="Bad admin key",
        )
    device = db.scalar(
        select(Device).where(
            Device.device_id == device_id
        )
    )
    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )
    updates = {
        "simulate_firewall_disabled":
            payload.simulate_firewall_disabled,
        "simulate_patch_outdated":
            payload.simulate_patch_outdated,
        "simulate_agent_loss":
            payload.simulate_agent_loss,
    }
    updates = {
        key: value
        for key, value in updates.items()
        if value is not None
    }
    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No demo control fields supplied",
        )
    control = db.get(
        DemoControl,
        device_id,
    )
    if control is None:
        control = DemoControl(
            device_id=device_id
        )
        db.add(control)
    for key, value in updates.items():
        setattr(
            control,
            key,
            value,
        )
    control.updated_at = datetime.now(
        timezone.utc
    )
    db.commit()
    db.refresh(control)
    return demo_control_payload(
        device_id,
        control,
    )
@app.post(
    "/device/{device_id}/posture"
)
def update_posture(
    device_id: str,
    payload: PostureUpdate,
    x_admin_key: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    if x_admin_key != DEMO_ADMIN_KEY:
        raise HTTPException(
            status_code=403,
            detail="Bad admin key",
        )
    if payload.patch_status not in {
        "updated",
        "outdated",
    }:
        raise HTTPException(
            status_code=400,
            detail="patch_status must be updated/outdated",
        )
    device = db.scalar(
        select(Device).where(
            Device.device_id == device_id
        )
    )
    if not device:
        raise HTTPException(
            status_code=404,
            detail="Device not found",
        )
    previous_posture = get_latest_posture(
        db,
        device,
    )
    (
        previous_heartbeat_fresh,
        previous_heartbeat_age_seconds,
    ) = get_heartbeat_status(
        previous_posture
    )
    now = datetime.now(timezone.utc)
    # ============================================================
    # Persist security-relevant posture transitions
    # ============================================================
    if previous_posture:
        firewall_changed = (
            previous_posture.firewall_enabled
            != payload.firewall_enabled
        )
        patch_changed = (
            previous_posture.patch_status
            != payload.patch_status
        )
        if firewall_changed or patch_changed:
            posture_owner = db.scalar(
                select(User).where(
                    User.id == device.user_id
                )
            )
            posture_username = (
                posture_owner.username
                if posture_owner
                else None
            )
            # ----------------------------------------------------
            # Firewall transition
            # ----------------------------------------------------
            if firewall_changed:
                firewall_is_bad = (
                    payload.firewall_enabled is False
                )
                add_security_event(
                    db,
                    event_type="DEVICE_FIREWALL_CHANGED",
                    severity=(
                        "high"
                        if firewall_is_bad
                        else "info"
                    ),
                    username=posture_username,
                    device_id=device.device_id,
                    source="device-agent",
                    reason=(
                        "FIREWALL_DISABLED"
                        if firewall_is_bad
                        else "FIREWALL_ENABLED"
                    ),
                    old_value=(
                        "enabled"
                        if previous_posture.firewall_enabled
                        else "disabled"
                    ),
                    new_value=(
                        "enabled"
                        if payload.firewall_enabled
                        else "disabled"
                    ),
                    details={
                        "previous_posture_id": (
                            previous_posture.id
                        ),
                        "agent_version": (
                            payload.agent_version
                        ),
                        "hostname": payload.hostname,
                    },
                    created_at=now,
                )
            # ----------------------------------------------------
            # Patch compliance transition
            # ----------------------------------------------------
            if patch_changed:
                patch_is_bad = (
                    payload.patch_status
                    != "updated"
                )
                add_security_event(
                    db,
                    event_type="DEVICE_PATCH_STATUS_CHANGED",
                    severity=(
                        "high"
                        if patch_is_bad
                        else "info"
                    ),
                    username=posture_username,
                    device_id=device.device_id,
                    source="device-agent",
                    reason=(
                        payload.patch_reason
                        if patch_is_bad
                        else "PATCH_COMPLIANT"
                    ),
                    old_value=(
                        previous_posture.patch_status
                    ),
                    new_value=(
                        payload.patch_status
                    ),
                    details={
                        "previous_posture_id": (
                            previous_posture.id
                        ),
                        "latest_hotfix_id": (
                            payload.latest_hotfix_id
                        ),
                        "patch_age_days": (
                            payload.patch_age_days
                        ),
                        "pending_reboot": (
                            payload.pending_reboot
                        ),
                        "patch_reason": (
                            payload.patch_reason
                        ),
                        "agent_version": (
                            payload.agent_version
                        ),
                    },
                    created_at=now,
                )
    # If the previous telemetry had already exceeded
    # the freshness window, this new posture represents
    # a heartbeat recovery.
    if (
        previous_posture
        and previous_heartbeat_fresh is False
    ):
        owner = db.scalar(
            select(User).where(
                User.id == device.user_id
            )
        )
        previous_reported_at = normalized_utc(
            previous_posture.reported_at
        )
        stale_at = (
            previous_reported_at
            + timedelta(
                seconds=HEARTBEAT_STALE_SECONDS
            )
        )
        latest_heartbeat_event = (
            get_latest_heartbeat_event(
                db,
                device.device_id,
            )
        )
        # Maybe nobody evaluated access while the agent
        # was offline. Persist the missing STALE transition.
        if (
            latest_heartbeat_event is None
            or latest_heartbeat_event.event_type
            != "DEVICE_HEARTBEAT_STALE"
        ):
            add_security_event(
                db,
                event_type="DEVICE_HEARTBEAT_STALE",
                severity="high",
                username=(
                    owner.username
                    if owner
                    else None
                ),
                device_id=device.device_id,
                source="device-monitor",
                reason="HEARTBEAT_TIMEOUT",
                old_value="fresh",
                new_value="stale",
                details={
                    "posture_id": previous_posture.id,
                    "last_reported_at": (
                        previous_reported_at.isoformat()
                    ),
                    "heartbeat_age_seconds": (
                        previous_heartbeat_age_seconds
                    ),
                    "stale_threshold_seconds": (
                        HEARTBEAT_STALE_SECONDS
                    ),
                    "detected_by": (
                        "posture_recovery"
                    ),
                },
                created_at=stale_at,
            )
        # The new agent report means the device is alive again.
        add_security_event(
            db,
            event_type="DEVICE_HEARTBEAT_RECOVERED",
            severity="info",
            username=(
                owner.username
                if owner
                else None
            ),
            device_id=device.device_id,
            source="device-monitor",
            reason="HEARTBEAT_RESUMED",
            old_value="stale",
            new_value="fresh",
            details={
                "previous_posture_id": (
                    previous_posture.id
                ),
                "previous_reported_at": (
                    previous_reported_at.isoformat()
                ),
                "gap_seconds": (
                    previous_heartbeat_age_seconds
                ),
                "stale_threshold_seconds": (
                    HEARTBEAT_STALE_SECONDS
                ),
            },
            created_at=now,
        )
    # Current-state cache.
    device.firewall_enabled = payload.firewall_enabled
    device.patch_status = payload.patch_status
    device.last_seen = now
    # Append-only posture history.
    posture = DevicePosture(
        device_pk=device.id,
        hostname=payload.hostname,
        os_name=payload.os_name,
        os_release=payload.os_release,
        os_version=payload.os_version,
        agent_version=payload.agent_version,
        firewall_enabled=payload.firewall_enabled,
        patch_status=payload.patch_status,
        latest_hotfix_id=payload.latest_hotfix_id,
        latest_hotfix_installed_on=(
            payload.latest_hotfix_installed_on
        ),
        patch_age_days=payload.patch_age_days,
        pending_reboot=payload.pending_reboot,
        patch_reason=payload.patch_reason,
        reported_at=now,
    )
    db.add(posture)
    db.flush()
    posture_owner = db.scalar(
        select(User).where(
            User.id == device.user_id
        )
    )
    emit_realtime_event(
        db,
        event_type="DEVICE_POSTURE_REPORTED",
        username=(
            posture_owner.username
            if posture_owner
            else None
        ),
        device_id=device.device_id,
        payload={
            "posture_id": posture.id,
            "firewall_enabled": (
                posture.firewall_enabled
            ),
            "patch_status": (
                posture.patch_status
            ),
            "patch_age_days": (
                posture.patch_age_days
            ),
            "pending_reboot": (
                posture.pending_reboot
            ),
            "reported_at": (
                posture.reported_at.isoformat()
            ),
        },
        created_at=posture.reported_at,
    )
    db.commit()
    db.refresh(posture)
    return {
        "posture_id": posture.id,
        "device_id": device.device_id,
        "firewall_enabled": posture.firewall_enabled,
        "patch_status": posture.patch_status,
        "hostname": posture.hostname,
        "os_name": posture.os_name,
        "os_release": posture.os_release,
        "os_version": posture.os_version,
        "agent_version": posture.agent_version,
        "latest_hotfix_id": posture.latest_hotfix_id,
        "latest_hotfix_installed_on": (
            posture.latest_hotfix_installed_on
        ),
        "patch_age_days": posture.patch_age_days,
        "pending_reboot": posture.pending_reboot,
        "patch_reason": posture.patch_reason,
        "last_seen": posture.reported_at,
    }
# ============================================================
# 12. AUDIT LOG ENDPOINT
# ============================================================
@app.get("/logs")
def logs(
    authorization: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    require_security_admin(
        authorization,
        db,
    )
    rows = db.scalars(
        select(AccessLog)
        .order_by(
            AccessLog.id.desc()
        )
        .limit(50)
    ).all()
    return [
        {
            "id": row.id,
            "username": row.username,
            "device_id": row.device_id,
            "method": row.method,
            "path": row.path,
            "decision": row.decision,
            "reason": row.reason,
            "request_id": (
                str(row.request_id)
                if row.request_id
                else None
            ),
            "resource_id": row.resource_id,
            "resource_sensitivity": (
                row.resource_sensitivity
            ),
            "policy_version": row.policy_version,
            "created_at": row.created_at,
        }
        for row in rows
    ]
@app.get("/events")
def security_events(
    authorization: str | None = Header(
        default=None
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
    ),
    db: Session = Depends(get_db),
):
    require_security_admin(
        authorization,
        db,
    )
    rows = db.scalars(
        select(SecurityEvent)
        .order_by(
            SecurityEvent.id.desc()
        )
        .limit(limit)
    ).all()
    return [
        {
            "id": row.id,
            "event_type": row.event_type,
            "severity": row.severity,
            "username": row.username,
            "device_id": row.device_id,
            "source": row.source,
            "reason": row.reason,
            "old_value": row.old_value,
            "new_value": row.new_value,
            "details": row.details,
            "created_at": row.created_at,
        }
        for row in rows
    ]
# ============================================================
# 12B. DECISION INSPECTOR API
# ============================================================
@app.get(
    "/decisions/{request_id}"
)
def decision_inspector(
    request_id: uuid.UUID,
    authorization: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    require_security_admin(
        authorization,
        db,
    )
    row = db.scalar(
        select(AccessLog).where(
            AccessLog.request_id == request_id
        )
    )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Decision not found",
        )
    context = row.decision_context or {}
    request_id_text = str(request_id)
    # Keep the query simple and robust for the local demo:
    # fetch recent device events, then correlate by payload UUID.
    recent_events = db.scalars(
        select(RealtimeEvent)
        .where(
            RealtimeEvent.device_id == row.device_id
        )
        .order_by(
            RealtimeEvent.id.desc()
        )
        .limit(500)
    ).all()
    correlated_events = [
        event
        for event in recent_events
        if (
            (event.payload or {}).get("request_id")
            == request_id_text
        )
    ]
    access_decision_event = next(
        (
            event
            for event in correlated_events
            if event.event_type == "ACCESS_DECISION"
        ),
        None,
    )
    data_api_event = next(
        (
            event
            for event in correlated_events
            if event.event_type in {
                "DATA_API_FETCHED",
                "DATA_API_FETCH_FAILED",
            }
        ),
        None,
    )
    data_api = context.get(
        "data_api",
        {},
    )
    return {
        "request_id": request_id_text,
        "created_at": row.created_at,
        "decision": row.decision,
        "reason": row.reason,
        "policy_version": row.policy_version,
        "identity": context.get("identity"),
        "device": context.get("device"),
        "resource": context.get("resource"),
        "context": context.get("context"),
        "request": context.get("request"),
        "opa": context.get("opa"),
        "data_api": data_api,
        "audit": {
            "access_log_id": row.id,
            "username": row.username,
            "device_id": row.device_id,
            "method": row.method,
            "path": row.path,
            "resource_id": row.resource_id,
            "resource_sensitivity": (
                row.resource_sensitivity
            ),
        },
        "realtime": {
            "access_decision_event_id": (
                access_decision_event.id
                if access_decision_event
                else None
            ),
            "data_api_event_id": (
                data_api_event.id
                if data_api_event
                else None
            ),
            "event_types": [
                event.event_type
                for event in correlated_events
            ],
        },
        "evidence": {
            "access_log_persisted": True,
            "realtime_correlated": (
                access_decision_event is not None
            ),
            "sensitive_payload_fetched": (
                data_api.get("status")
                == "FETCHED"
            ),
            "data_api_request_id_match": (
                data_api.get("request_id_match")
            ),
        },
    }
# ============================================================
# 13. ZERO TRUST PROTECTED RESOURCE
# ============================================================
def realtime_event_payload(
    event: RealtimeEvent,
) -> dict:
    return {
        "id": event.id,
        "event_type": event.event_type,
        "username": event.username,
        "device_id": event.device_id,
        "payload": event.payload,
        "created_at": (
            event.created_at.isoformat()
            if event.created_at
            else None
        ),
    }
@app.get("/stream/events")
def stream_events(
    access_token: str = Query(...),
    device_id: str = Query(...),
    after_id: int = Query(
        default=0,
        ge=0,
    ),

    tail: bool = Query(
        default=False,
    ),
    last_event_id: str | None = Header(
        default=None,
        alias="Last-Event-ID",
    ),
    db: Session = Depends(get_db),
):
    # --------------------------------------------------------
    # Authenticate the SSE connection.
    #
    # Native EventSource cannot set Authorization headers,
    # therefore this local demo uses the JWT in the SSE URL.
    # --------------------------------------------------------
    claims = decode_token(
        f"Bearer {access_token}"
    )
    username = claims["sub"]
    token_device_id = claims["device_id"]

    user = db.scalar(
        select(User).where(
            User.username == username
        )
    )

    if not user or not user.active:
        raise HTTPException(
            status_code=403,
            detail="User is not active",
        )

    # Business users remain bound to the device in their JWT.
    # Security Center is different: a security-admin is a control-plane
    # observer and may subscribe read-only to a registered monitored device.
    is_security_admin = (
        user.role == "security-admin"
    )

    if (
        not is_security_admin
        and device_id != token_device_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Device ID mismatch",
        )

    if is_security_admin:
        device = db.scalar(
            select(Device).where(
                Device.device_id == device_id
            )
        )
    else:
        device = db.scalar(
            select(Device).where(
                Device.device_id == device_id,
                Device.user_id == user.id,
            )
        )

    if not device or not device.registered:
        raise HTTPException(
            status_code=403,
            detail="Device is not registered",
        )

    browser_cursor = 0
    if last_event_id:
        try:
            browser_cursor = int(
                last_event_id
            )
        except ValueError:
            browser_cursor = 0
    # Security Center loads authoritative current state via REST first,
    # then listens only for newly committed events. Existing clients keep
    # durable replay semantics because tail defaults to False.
    if (
        tail
        and after_id == 0
        and browser_cursor == 0
    ):
        latest_existing_event = db.scalar(
            select(RealtimeEvent)
            .where(
                RealtimeEvent.device_id == device_id
            )
            .order_by(
                RealtimeEvent.id.desc()
            )
            .limit(1)
        )
        if latest_existing_event:
            browser_cursor = latest_existing_event.id

    starting_id = max(
        after_id,
        browser_cursor,
    )
    token_exp = int(
        claims.get(
            "exp",
            0,
        )
    )
    def event_generator():
        last_sent_id = starting_id
        listen_conn = psycopg2.connect(
            LISTEN_DATABASE_URL
        )
        listen_conn.set_session(
            autocommit=True
        )
        cursor = listen_conn.cursor()
        cursor.execute(
            f"LISTEN {REALTIME_CHANNEL};"
        )
        try:
            # LISTEN is established BEFORE replay.
            #
            # This closes the replay/listen race:
            # events committed during replay are queued
            # by PostgreSQL and then de-duplicated using ID.
            while True:
                # --------------------------------------------
                # JWT lifetime also applies to the stream.
                # --------------------------------------------
                if (
                    token_exp
                    and time.time() >= token_exp
                ):
                    yield (
                        "event: auth_expired\n"
                        'data: {"reason":"TOKEN_EXPIRED"}\n\n'
                    )
                    break
                # --------------------------------------------
                # Durable replay / catch-up.
                # --------------------------------------------
                with SessionLocal() as replay_db:
                    rows = replay_db.scalars(
                        select(RealtimeEvent)
                        .where(
                            RealtimeEvent.id
                            > last_sent_id,
                            RealtimeEvent.device_id
                            == device_id,
                        )
                        .order_by(
                            RealtimeEvent.id.asc()
                        )
                        .limit(200)
                    ).all()
                if rows:
                    for row in rows:
                        payload = (
                            realtime_event_payload(
                                row
                            )
                        )
                        data = json.dumps(
                            payload,
                            separators=(",", ":"),
                        )
                        yield (
                            f"id: {row.id}\n"
                            "event: realtime\n"
                            f"data: {data}\n\n"
                        )
                        last_sent_id = row.id
                    # Immediately check DB again in case
                    # replay backlog is larger than 200.
                    continue
                # --------------------------------------------
                # Nothing pending.
                # Sleep efficiently until PostgreSQL NOTIFY
                # wakes this connection.
                # --------------------------------------------
                readable, _, _ = (
                    select_io.select(
                        [listen_conn],
                        [],
                        [],
                        15,
                    )
                )
                if readable:
                    listen_conn.poll()
                    # We only need NOTIFY as a wake-up.
                    # Durable data is read from realtime_events.
                    while listen_conn.notifies:
                        listen_conn.notifies.pop(0)
                    continue
                # Keep proxies from closing an idle stream.
                yield ": keepalive\n\n"
        finally:
            cursor.close()
            listen_conn.close()
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": (
                "no-cache, no-transform"
            ),
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
@app.get("/protected/resources")
async def protected_resource_catalog(
    authorization: str | None = Header(
        default=None
    ),
    x_device_id: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    claims = decode_token(
        authorization
    )
    token_device_id = claims["device_id"]
    if (
        not x_device_id
        or x_device_id != token_device_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Device ID mismatch",
        )
    username = claims["sub"]
    user = db.scalar(
        select(User).where(
            User.username == username
        )
    )
    if not user or not user.active:
        raise HTTPException(
            status_code=403,
            detail="User is not active",
        )
    device = db.scalar(
        select(Device).where(
            Device.device_id == x_device_id,
            Device.user_id == user.id,
        )
    )
    if not device or not device.registered:
        raise HTTPException(
            status_code=403,
            detail="Device is not registered",
        )
    resources = await fetch_resource_catalog()
    return {
        "resources": resources,
    }
@app.get(
    "/protected/resources/{resource_id}"
)
async def protected_resource(
    resource_id: int,
    authorization: str | None = Header(
        default=None
    ),
    x_device_id: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    # --------------------------------------------------------
    # Step 1: Authenticate
    # --------------------------------------------------------
    claims = decode_token(
        authorization
    )
    username = claims["sub"]
    token_device_id = claims["device_id"]
    # Gateway-generated correlation identifier.
    # One protected request = one request_id.
    request_id = uuid.uuid4()
    # --------------------------------------------------------
    # Step 2: Device binding
    # --------------------------------------------------------
    if (
        not x_device_id
        or x_device_id != token_device_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Device ID mismatch",
        )
    # --------------------------------------------------------
    # Step 3: Current identity + device
    # --------------------------------------------------------
    user = db.scalar(
        select(User).where(
            User.username == username
        )
    )
    device = None
    if user:
        device = db.scalar(
            select(Device).where(
                Device.device_id == x_device_id,
                Device.user_id == user.id,
            )
        )
    if not user or not user.active:
        raise HTTPException(
            status_code=403,
            detail="User is not active",
        )
    if not device or not device.registered:
        raise HTTPException(
            status_code=403,
            detail="Device is not registered",
        )
    # --------------------------------------------------------
    # Step 4: Metadata only
    #
    # No sensitive payload has been fetched yet.
    # --------------------------------------------------------
    catalog = await fetch_resource_catalog()
    resource_metadata = next(
        (
            row
            for row in catalog
            if row.get("id") == resource_id
        ),
        None,
    )
    if resource_metadata is None:
        raise HTTPException(
            status_code=404,
            detail="Resource not found",
        )
    # --------------------------------------------------------
    # Step 5: Current device posture
    # --------------------------------------------------------
    latest_posture = get_latest_posture(
        db,
        device,
    )
    (
        heartbeat_fresh,
        heartbeat_age_seconds,
    ) = get_heartbeat_status(
        latest_posture
    )
    # --------------------------------------------------------
    # Step 6: Persist STALE transition if this request
    # detects it first.
    # --------------------------------------------------------
    if (
        device
        and latest_posture
        and heartbeat_fresh is False
    ):
        latest_heartbeat_event = (
            get_latest_heartbeat_event(
                db,
                device.device_id,
            )
        )
        if (
            latest_heartbeat_event is None
            or latest_heartbeat_event.event_type
            != "DEVICE_HEARTBEAT_STALE"
        ):
            reported_at = normalized_utc(
                latest_posture.reported_at
            )
            stale_at = (
                reported_at
                + timedelta(
                    seconds=HEARTBEAT_STALE_SECONDS
                )
            )
            add_security_event(
                db,
                event_type="DEVICE_HEARTBEAT_STALE",
                severity="high",
                username=(
                    user.username
                    if user
                    else username
                ),
                device_id=device.device_id,
                source="device-monitor",
                reason="HEARTBEAT_TIMEOUT",
                old_value="fresh",
                new_value="stale",
                details={
                    "posture_id": latest_posture.id,
                    "last_reported_at": (
                        reported_at.isoformat()
                    ),
                    "heartbeat_age_seconds": (
                        heartbeat_age_seconds
                    ),
                    "stale_threshold_seconds": (
                        HEARTBEAT_STALE_SECONDS
                    ),
                    "detected_by": (
                        "protected_resource_request"
                    ),
                },
                created_at=stale_at,
            )
            db.commit()
    # --------------------------------------------------------
    # Step 7: Build resource-aware OPA input
    # --------------------------------------------------------
    opa_input = {
        "authenticated": True,
        "user": {
            "username": (
                user.username
                if user
                else username
            ),
            "role": (
                user.role
                if user
                else claims.get("role")
            ),
            "active": bool(
                user
                and user.active
            ),
        },
        "device": {
            "device_id": x_device_id,
            "registered": bool(
                device
                and device.registered
            ),
            "trust_status": (
                device.trust_status
                if device
                else "unknown"
            ),
            "firewall_enabled": bool(
                latest_posture
                and latest_posture.firewall_enabled
            ),
            "patch_status": (
                latest_posture.patch_status
                if latest_posture
                else "unknown"
            ),
            "heartbeat_fresh": (
                heartbeat_fresh
            ),
            "heartbeat_age_seconds": (
                heartbeat_age_seconds
            ),
            "latest_hotfix_id": (
                latest_posture.latest_hotfix_id
                if latest_posture
                else None
            ),
            "patch_age_days": (
                latest_posture.patch_age_days
                if latest_posture
                else None
            ),
            "pending_reboot": (
                latest_posture.pending_reboot
                if latest_posture
                else None
            ),
            "patch_reason": (
                latest_posture.patch_reason
                if latest_posture
                else None
            ),
        },
        "resource": {
            "id": resource_metadata["id"],
            "title": resource_metadata["title"],
            "sensitivity": (
                resource_metadata["sensitivity"]
            ),
            "category": (
                resource_metadata["category"]
            ),
        },
        "context": {
            "time_allowed": True,
        },
        "request": {
            "request_id": str(
                request_id
            ),
            "method": "GET",
            "path": (
                f"/protected/resources/"
                f"{resource_id}"
            ),
        },
    }
    # --------------------------------------------------------
    # Step 8: Central policy decision
    # --------------------------------------------------------
    result = await evaluate_with_opa(
        opa_input
    )
    allowed = bool(
        result.get(
            "allow",
            False,
        )
    )
    reason = result.get(
        "reason",
        "POLICY_DENIED",
    )
    decision_context = {
        "identity": {
            "authenticated":
                opa_input[
                    "authenticated"
                ],
            **opa_input["user"],
        },
        "device":
            opa_input["device"],
        "resource":
            opa_input["resource"],
        "context":
            opa_input["context"],
        "request":
            opa_input["request"],
        "opa": {
            "allow":
                allowed,
            "reason":
                reason,
        },
        "data_api": {
            "status": (
                "PENDING_POLICY_ALLOW"
                if allowed
                else "NOT_FETCHED_POLICY_DENY"
            ),
            "path": (
                f"/internal/resources/{resource_id}"
            ),
            "request_id": str(request_id),
            "upstream_request_id": None,
            "request_id_match": None,
        },
    }
    # --------------------------------------------------------
    # Step 9: Audit decision
    # --------------------------------------------------------
    protected_path = (
        f"/protected/resources/{resource_id}"
    )
    access_log = save_access_log(
        db,
        username=username,
        device_id=x_device_id,
        method="GET",
        path=protected_path,
        decision=(
            "ALLOW"
            if allowed
            else "DENY"
        ),
        reason=reason,
        request_id=request_id,
        resource_id=(
            resource_metadata["id"]
        ),
        resource_sensitivity=(
            resource_metadata[
                "sensitivity"
            ]
        ),
        policy_version=(
            OPA_POLICY_VERSION
        ),
        decision_context=(
            decision_context
        ),
    )
    # --------------------------------------------------------
    # Step 10: Enforce
    # --------------------------------------------------------
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "decision": "DENY",
                "request_id": str(
                    request_id
                ),
                "reason": reason,
                "resource": {
                    "id": (
                        resource_metadata["id"]
                    ),
                    "title": (
                        resource_metadata["title"]
                    ),
                    "sensitivity": (
                        resource_metadata[
                            "sensitivity"
                        ]
                    ),
                },
            },
        )
    # --------------------------------------------------------
    # Step 11:
    # ONLY NOW fetch sensitive payload.
    # --------------------------------------------------------
    try:
        (
            resource,
            upstream_request_id,
        ) = await fetch_internal_resource(
            resource_id,
            request_id,
        )
    except HTTPException as exc:
        update_data_api_evidence(
            db,
            access_log=access_log,
            request_id=request_id,
            path=(
                f"/internal/resources/{resource_id}"
            ),
            status="FETCH_FAILED",
            detail=str(exc.detail),
        )
        raise
    update_data_api_evidence(
        db,
        access_log=access_log,
        request_id=request_id,
        path=(
            f"/internal/resources/{resource_id}"
        ),
        status="FETCHED",
        upstream_request_id=(
            upstream_request_id
        ),
    )
    return {
        "decision": "ALLOW",
        "request_id": str(
            request_id
        ),
        "reason": reason,
        "resource": resource,
    }
@app.get("/protected/data")
async def protected_data(
    authorization: str | None = Header(
        default=None
    ),
    x_device_id: str | None = Header(
        default=None
    ),
    db: Session = Depends(get_db),
):
    # Step 1: Validate JWT.
    claims = decode_token(
        authorization
    )
    username = claims["sub"]
    token_device_id = claims["device_id"]
    # Gateway-generated correlation identifier.
    # One protected request = one request_id.
    request_id = uuid.uuid4()
    # Step 2: Bind request to device inside JWT.
    if (
        not x_device_id
        or x_device_id != token_device_id
    ):
        raise HTTPException(
            status_code=403,
            detail="Device ID mismatch",
        )
    # Step 3: Load current User + Device.
    user = db.scalar(
        select(User).where(
            User.username == username
        )
    )
    device = None
    if user:
        device = db.scalar(
            select(Device).where(
                Device.device_id == x_device_id,
                Device.user_id == user.id,
            )
        )
    # Step 4: Load latest posture telemetry.
    latest_posture = get_latest_posture(
        db,
        device,
    )
    (
        heartbeat_fresh,
        heartbeat_age_seconds,
    ) = get_heartbeat_status(
        latest_posture
    )
    # Persist heartbeat transition when the current request
    # observes that the device has become stale.
    if (
        device
        and latest_posture
        and heartbeat_fresh is False
    ):
        latest_heartbeat_event = get_latest_heartbeat_event(
            db,
            device.device_id,
        )
        if (
            latest_heartbeat_event is None
            or latest_heartbeat_event.event_type
            != "DEVICE_HEARTBEAT_STALE"
        ):
            reported_at = normalized_utc(
                latest_posture.reported_at
            )
            stale_at = (
                reported_at
                + timedelta(
                    seconds=HEARTBEAT_STALE_SECONDS
                )
            )
            add_security_event(
                db,
                event_type="DEVICE_HEARTBEAT_STALE",
                severity="high",
                username=(
                    user.username
                    if user
                    else username
                ),
                device_id=device.device_id,
                source="device-monitor",
                reason="HEARTBEAT_TIMEOUT",
                old_value="fresh",
                new_value="stale",
                details={
                    "posture_id": latest_posture.id,
                    "last_reported_at": (
                        reported_at.isoformat()
                    ),
                    "heartbeat_age_seconds": (
                        heartbeat_age_seconds
                    ),
                    "stale_threshold_seconds": (
                        HEARTBEAT_STALE_SECONDS
                    ),
                    "detected_by": (
                        "protected_request"
                    ),
                },
                created_at=stale_at,
            )
            db.commit()
    firewall_enabled = bool(
        latest_posture
        and latest_posture.firewall_enabled
    )
    patch_status = (
        latest_posture.patch_status
        if latest_posture
        else "unknown"
    )
    # Step 5: Build OPA input.
    opa_input = {
        "authenticated": True,
        "user": {
            "username": (
                user.username
                if user
                else username
            ),
            "role": (
                user.role
                if user
                else claims.get("role")
            ),
            "active": bool(
                user
                and user.active
            ),
        },
        "device": {
            "device_id": x_device_id,
            "registered": bool(
                device
                and device.registered
            ),
            "trust_status": (
                device.trust_status
                if device
                else "unknown"
            ),
            "firewall_enabled": firewall_enabled,
            "patch_status": patch_status,
            "heartbeat_fresh": heartbeat_fresh,
            "heartbeat_age_seconds": heartbeat_age_seconds,
            "hostname": (
                latest_posture.hostname
                if latest_posture
                else None
            ),
            "os_name": (
                latest_posture.os_name
                if latest_posture
                else None
            ),
            "os_release": (
                latest_posture.os_release
                if latest_posture
                else None
            ),
            "os_version": (
                latest_posture.os_version
                if latest_posture
                else None
            ),
            "agent_version": (
                latest_posture.agent_version
                if latest_posture
                else None
            ),
            "latest_hotfix_id": (
                latest_posture.latest_hotfix_id
                if latest_posture
                else None
            ),
            "latest_hotfix_installed_on": (
                latest_posture.latest_hotfix_installed_on.isoformat()
                if (
                    latest_posture
                    and latest_posture.latest_hotfix_installed_on
                )
                else None
            ),
            "patch_age_days": (
                latest_posture.patch_age_days
                if latest_posture
                else None
            ),
            "pending_reboot": (
                latest_posture.pending_reboot
                if latest_posture
                else None
            ),
            "patch_reason": (
                latest_posture.patch_reason
                if latest_posture
                else None
            ),
        },
        "resource": {
            "id": "legacy-data-bundle",
            "title": "Legacy Protected Data Bundle",
            "sensitivity": "HIGH",
            "category": "legacy-internal-data",
        },
        "context": {
            "time_allowed": True,
        },
        "request": {
            "request_id": str(
                request_id
            ),
            "method": "GET",
            "path": "/internal/data",
        },
    }
    # Step 6: Ask OPA.
    result = await evaluate_with_opa(
        opa_input
    )
    allowed = bool(
        result.get(
            "allow",
            False,
        )
    )
    reason = result.get(
        "reason",
        "POLICY_DENIED",
    )
    # Immutable evidence snapshot captured AFTER OPA
    # has returned the actual decision.
    decision_context = {
        "identity": {
            "authenticated":
                opa_input[
                    "authenticated"
                ],
            **opa_input["user"],
        },
        "device":
            opa_input["device"],
        "resource":
            opa_input["resource"],
        "context":
            opa_input["context"],
        "request":
            opa_input["request"],
        "opa": {
            "allow":
                allowed,
            "reason":
                reason,
        },
        "data_api": {
            "status": (
                "PENDING_POLICY_ALLOW"
                if allowed
                else "NOT_FETCHED_POLICY_DENY"
            ),
            "path": "/internal/data",
            "request_id": str(request_id),
            "upstream_request_id": None,
            "request_id_match": None,
        },
    }
    # Step 7: Persist audit event.
    access_log = save_access_log(
        db,
        username=username,
        device_id=x_device_id,
        method="GET",
        path="/internal/data",
        decision=(
            "ALLOW"
            if allowed
            else "DENY"
        ),
        reason=reason,
        request_id=request_id,
        # Legacy bundle has no integer resource ID.
        resource_id=None,
        resource_sensitivity="HIGH",
        policy_version=(
            OPA_POLICY_VERSION
        ),
        decision_context=(
            decision_context
        ),
    )
    # Step 8: Enforce decision.
    if not allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "decision": "DENY",
                "request_id": str(
                    request_id
                ),
                "reason": reason,
            },
        )
    # Step 9: Forward to Internal API.
    try:
        (
            upstream_data,
            upstream_request_id,
        ) = await fetch_legacy_internal_data(
            request_id
        )
    except HTTPException as exc:
        update_data_api_evidence(
            db,
            access_log=access_log,
            request_id=request_id,
            path="/internal/data",
            status="FETCH_FAILED",
            detail=str(exc.detail),
        )
        raise
    update_data_api_evidence(
        db,
        access_log=access_log,
        request_id=request_id,
        path="/internal/data",
        status="FETCHED",
        upstream_request_id=(
            upstream_request_id
        ),
    )
    # Step 10: Return protected data.
    return {
        "decision": "ALLOW",
        "request_id": str(
            request_id
        ),
        "reason": reason,
        "policy_input":
            opa_input,
        "data":
            upstream_data,
    }