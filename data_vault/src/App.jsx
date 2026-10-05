import {
  Activity,
  BadgeCheck,
  Building2,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Database,
  FileLock2,
  Fingerprint,
  Gauge,
  HeartPulse,
  KeyRound,
  LockKeyhole,
  LogOut,
  Moon,
  RefreshCw,
  Sun,
  ServerCog,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  UserRound,
  Wifi,
} from "lucide-react";
import React, { useEffect, useMemo, useState } from "react";
const API = "/api";
const SENSITIVITY = {
  LOW: {
    label: "Baseline policy",
    short: "Auth + registered device",
    icon: Database,
    requirements: [
      "Authenticated identity",
      "Registered device",
      "Valid GET request",
    ],
  },
  MEDIUM: {
    label: "Trusted-device policy",
    short: "Trust + fresh heartbeat",
    icon: ShieldCheck,
    requirements: [
      "Authenticated identity",
      "Registered device",
      "Trusted device",
      "Fresh heartbeat",
      "Valid GET request",
    ],
  },
  HIGH: {
    label: "Restricted policy",
    short: "Privileged + hardened device",
    icon: FileLock2,
    requirements: [
      "Authenticated identity",
      "Registered device",
      "Analyst / admin role",
      "Trusted device",
      "Fresh heartbeat",
      "Firewall enabled",
      "Patch compliant",
      "Allowed request context (lab-fixed)",
      "Valid GET request",
    ],
  },
};
const REASON_COPY = {
  ALLOW: "Policy requirements satisfied.",
  DEVICE_STALE: "The device heartbeat is older than the allowed freshness window.",
  DEVICE_UNTRUSTED: "The device is currently marked untrusted.",
  ROLE_DENIED_FOR_HIGH_DATA: "This identity does not have the role required for HIGH data.",
  FIREWALL_DISABLED: "HIGH data requires an enabled firewall posture signal.",
  PATCH_EVIDENCE_MISSING: "Patch evidence is missing for this device.",
  PATCH_TOO_OLD: "Patch evidence exceeds the policy age threshold.",
  PENDING_REBOOT: "The device requires a Windows servicing reboot before HIGH data is allowed.",
  DEVICE_NOT_REGISTERED: "This device is not registered to the authenticated user.",
  USER_INACTIVE: "The current user is inactive.",
  CONTEXT_DENIED: "The current request context is not allowed.",
  POLICY_DENIED: "The policy engine denied this request.",
};
function apiErrorMessage(payload, fallback = "Request failed") {
  const detail = payload?.detail;
  if (typeof detail === "string") return detail;
  if (detail?.reason) return detail.reason;
  return fallback;
}
async function apiFetch(path, options = {}, session = null) {
  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");
  if (session?.token) {
    headers.set("Authorization", `Bearer ${session.token}`);
  }
  if (session?.deviceId) {
    headers.set("X-Device-ID", session.deviceId);
  }
  const response = await fetch(`${API}${path}`, { ...options, headers });
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const error = new Error(apiErrorMessage(payload, `HTTP ${response.status}`));
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}
function ThemeSwitch({ theme, onChange, login = false }) {
  return (
    <div className={`theme-segment ${login ? "login-theme-segment" : ""}`} role="group" aria-label="Appearance theme">
      <button type="button" className={theme === "light" ? "active" : ""} onClick={() => onChange("light")} aria-pressed={theme === "light"} title="Use light appearance"><Sun size={15} /><span>Light</span></button>
      <button type="button" className={theme === "dark" ? "active" : ""} onClick={() => onChange("dark")} aria-pressed={theme === "dark"} title="Use dark appearance"><Moon size={15} /><span>Dark</span></button>
    </div>
  );
}

function Login({ onLogin, theme, onThemeChange }) {
  const [form, setForm] = useState({ username: "alice", password: "alice123", device_id: "DEV-001" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const preset = (who) => {
    if (who === "alice") {
      setForm({ username: "alice", password: "alice123", device_id: "DEV-001" });
    } else if (who === "bob") {
      setForm({ username: "bob", password: "bob123", device_id: "DEV-002" });
    } else {
      setForm({ username: "", password: "", device_id: "" });
    }
    setError("");
  };
  const submit = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const data = await apiFetch("/auth/login", { method: "POST", body: JSON.stringify(form) });
      const nextSession = {
        token: data.access_token,
        username: data.user.username,
        role: data.user.role,
        deviceId: data.device.device_id,
        trustStatus: data.device.trust_status,
        expiresInMinutes: data.expires_in_minutes,
      };

      // Preload the first authenticated view before switching screens.
      // This avoids the short skeleton/content flash immediately after login.
      let bootstrap = null;
      try {
        const [catalog, devices] = await Promise.all([
          apiFetch("/protected/resources", {}, nextSession),
          apiFetch("/devices", {}, nextSession),
        ]);
        bootstrap = {
          resources: catalog.resources || [],
          device:
            (devices || []).find(
              (item) => item.device_id === nextSession.deviceId
            ) || devices?.[0] || null,
        };
      } catch (bootstrapError) {
        // Authentication already succeeded. If preload fails, enter the
        // vault normally and let its regular loader/error handling take over.
        console.warn("Initial vault preload failed", bootstrapError);
      }

      onLogin(nextSession, bootstrap);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="login-shell">
      <ThemeSwitch theme={theme} onChange={onThemeChange} login />
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <section className="login-copy">
        <div className="brand-mark"><Shield size={24} /><span>ZT</span></div>
        <div className="eyebrow"><Sparkles size={14} /> RESOURCE-AWARE ACCESS</div>
        <h1>Zero Trust<br /><span>Data Vault</span></h1>
        <p>Protected records are released only after identity, device posture, context and data sensitivity are evaluated for the current request.</p>
        <div className="flow-preview">
          <span>Identity</span><ChevronRight size={15} /><span>Device</span><ChevronRight size={15} /><span>OPA</span><ChevronRight size={15} /><strong>Data</strong>
        </div>
        <div className="login-note"><ShieldCheck size={18} /><span>JWT validity alone does not guarantee access.</span></div>
      </section>
      <section className="login-panel glass">
        <div className="panel-head">
          <div>
            <div className="eyebrow">SECURE SESSION</div>
            <h2>Sign in to the vault</h2>
          </div>
          <KeyRound size={24} />
        </div>
        <div className="demo-label">Demo presets · or sign in with a provisioned account</div>
        <div className="demo-presets">
          <button type="button" onClick={() => preset("alice")}>Alice · analyst</button>
          <button type="button" onClick={() => preset("bob")}>Bob · viewer</button>
          <button type="button" onClick={() => preset("custom")}>Custom · provisioned</button>
        </div>
        <form onSubmit={submit} className="login-form">
          <label>Username<input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} autoComplete="username" /></label>
          <label>Password<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} autoComplete="current-password" /></label>
          <label>Device ID<input value={form.device_id} onChange={(e) => setForm({ ...form, device_id: e.target.value })} /></label>
          {error && <div className="form-error"><CircleAlert size={17} />{error}</div>}
          <button className="primary-button" disabled={busy}>{busy ? <><RefreshCw className="spin" size={18} /> Verifying…</> : <><Fingerprint size={18} /> Establish session</>}</button>
        </form>
      </section>
    </main>
  );
}
function StatusPill({ good, label, value, icon: Icon }) {
  return (
    <div className={`status-pill ${good ? "good" : "bad"}`}>
      <Icon size={16} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}
function AccessModal({ state, onClose }) {
  if (!state) return null;
  const { resource, phase, steps = [], result, error } = state;
  const allowed = result?.decision === "ALLOW";
  const reason = error?.payload?.detail?.reason || error?.message;
  const requestId =
    result?.request_id ||
    error?.payload?.detail?.request_id ||
    null;

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="decision-modal glass" onMouseDown={(e) => e.stopPropagation()}>
        <div className="modal-resource">
          <div className={`sensitivity-badge ${resource.sensitivity.toLowerCase()}`}>{resource.sensitivity}</div>
          <div>
            <div className="eyebrow">POLICY EVALUATION</div>
            <h2>{resource.title}</h2>
            <p>Data owner · {resource.customer}</p>
          </div>
        </div>

        {phase === "checking" && (
          <>
            <div className="decision-orb"><Shield className="pulse" size={34} /></div>
            <h3 className="center">Continuous verification in progress</h3>
            <p className="evaluation-note">
              Visual request journey for readability. The animation is illustrative; the final ALLOW/DENY result below comes from the real Access Proxy + OPA response.
            </p>
            <div className="check-list">
              {steps.map((step, index) => (
                <div key={step.label} className={`check-row ${step.status}`}>
                  {step.status === "done"
                    ? <CheckCircle2 size={19} />
                    : step.status === "active"
                      ? <RefreshCw className="spin" size={19} />
                      : <span className="step-dot">{index + 1}</span>}
                  <span>{step.label}</span>
                </div>
              ))}
            </div>
          </>
        )}

        {phase === "done" && allowed && (
          <>
            <div className="decision-banner allow">
              <BadgeCheck size={24} />
              <div><strong>ACCESS GRANTED</strong><span>OPA reason: {result.reason}</span></div>
            </div>
            <div className="delivery-note allow">
              <Database size={17} />
              <span>Sensitive content was returned only after the ALLOW decision.</span>
            </div>
            {requestId && (
              <div className="trace-ref">
                <span>Trace request ID</span>
                <code>{requestId}</code>
              </div>
            )}
            <div className="record-grid">
              {Object.entries(result.resource.data || {}).map(([key, value]) => (
                <div className="record-field" key={key}>
                  <span>{key.replaceAll("_", " ")}</span>
                  <strong>{String(value)}</strong>
                </div>
              ))}
            </div>
          </>
        )}

        {phase === "done" && !allowed && (
          <>
            <div className="decision-banner deny">
              <ShieldAlert size={24} />
              <div><strong>ACCESS DENIED</strong><span>{reason || "POLICY_DENIED"}</span></div>
            </div>
            <p className="deny-copy">
              {REASON_COPY[reason] || "The current request does not satisfy the resource policy."}
            </p>
            <div className="delivery-note deny">
              <ShieldCheck size={17} />
              <span>No protected payload was returned to this portal. Persisted enforcement evidence can be inspected in Security Center.</span>
            </div>
            {requestId && (
              <div className="trace-ref">
                <span>Trace request ID</span>
                <code>{requestId}</code>
              </div>
            )}
            <div className="policy-box">
              <span>Policy requirements for {resource.sensitivity}</span>
              {SENSITIVITY[resource.sensitivity].requirements.map((item) => (
                <div key={item}><CheckCircle2 size={15} />{item}</div>
              ))}
            </div>
          </>
        )}

        {phase === "done" && <button className="modal-close" onClick={onClose}>Close decision</button>}
      </section>
    </div>
  );
}
function Vault({ session, onLogout, initialData = null, theme, onThemeChange }) {
  const [resources, setResources] = useState(
    () => initialData?.resources || []
  );
  const [device, setDevice] = useState(
    () => initialData?.device || null
  );
  const [loading, setLoading] = useState(
    () => !initialData
  );
  const [message, setMessage] = useState("");
  const [decision, setDecision] = useState(null);
  const [streamState, setStreamState] = useState(
  "connecting"
  );
  const [lastRealtimeEvent, setLastRealtimeEvent] =
    useState(null);
  const load = async () => {
    setLoading(true);
    setMessage("");
    try {
      const [catalog, devices] = await Promise.all([
        apiFetch("/protected/resources", {}, session),
        apiFetch("/devices", {}, session),
      ]);
      setResources(catalog.resources || []);
      setDevice((devices || []).find((item) => item.device_id === session.deviceId) || devices?.[0] || null);
    } catch (err) {
      if (err.status === 401) onLogout();
      else setMessage(err.message);
    } finally {
      setLoading(false);
    }
  };
  const refreshDevice = async (
    silent = true
  ) => {
    try {
      const devices = await apiFetch(
        "/devices",
        {},
        session
      );
      const nextDevice = (
        devices || []
      ).find(
        (item) =>
          item.device_id === session.deviceId
      ) || devices?.[0] || null;
      setDevice(nextDevice);
      return nextDevice;
    } catch (err) {
      if (err.status === 401) {
        onLogout();
        return null;
      }
      if (!silent) {
        setMessage(err.message);
      }
      return null;
    }
  };
  useEffect(() => {
    // Normal reloads still bootstrap from the API. A fresh login already
    // supplied authoritative initial data, so do not flash a second loader.
    if (!initialData) {
      load();
    }
  }, []);
  useEffect(() => {
  const cursorKey = (
    `zt-vault-sse-cursor:` +
    `${session.username}:` +
    `${session.deviceId}`
  );
  const savedCursorRaw = sessionStorage.getItem(
    cursorKey
  );
  const savedCursor = Number(
    savedCursorRaw || "0"
  );
  const firstConnectionWithoutCursor = (
    !savedCursorRaw || savedCursor === 0
  );
  const streamStartedAt = Date.now();

  const params = new URLSearchParams({
    access_token: session.token,
    device_id: session.deviceId,
    after_id: String(savedCursor),
  });
  const source = new EventSource(
    `${API}/stream/events?${params.toString()}`
  );
  let refreshTimer = null;
  const scheduleDeviceRefresh = () => {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(
      () => {
        refreshDevice(true);
      },
      120
    );
  };
  setStreamState(
    "connecting"
  );
  source.onopen = () => {
    setStreamState(
      "live"
    );
  };
  source.addEventListener(
    "realtime",
    (event) => {
      try {
        const data = JSON.parse(
          event.data
        );
        const eventId = (
          data.id
          || event.lastEventId
        );
        if (eventId) {
          sessionStorage.setItem(
            cursorKey,
            String(eventId)
          );
        }

        // On the very first SSE connection there is no browser cursor yet,
        // so the durable stream replays older events. Keep advancing the
        // cursor, but do not animate historical posture transitions into the
        // live UI. The authoritative /devices preload already represents the
        // current state.
        const eventCreatedAt = Date.parse(
          data.created_at || ""
        );
        const historicalBootstrapEvent = (
          firstConnectionWithoutCursor
          && Number.isFinite(eventCreatedAt)
          && eventCreatedAt < streamStartedAt
        );
        if (historicalBootstrapEvent) {
          return;
        }

        setLastRealtimeEvent(
          data
        );
        // ---------------------------------
        // Fast optimistic UI update
        // ---------------------------------
        if (
          data.event_type ===
          "DEVICE_POSTURE_REPORTED"
        ) {
          const payload =
            data.payload || {};
          setDevice(
            (current) => {
              if (!current) {
                return current;
              }
              return {
                ...current,
                firewall_enabled:
                  payload.firewall_enabled,
                patch_status:
                  payload.patch_status,
                patch_age_days:
                  payload.patch_age_days,
                pending_reboot:
                  payload.pending_reboot,
                last_seen:
                  payload.reported_at,
                heartbeat_fresh:
                  true,
                heartbeat_age_seconds:
                  0,
              };
            }
          );
          scheduleDeviceRefresh();
          return;
        }
        if (
          data.event_type ===
          "SECURITY_EVENT"
        ) {
          const payload =
            data.payload || {};
          const securityType =
            payload.security_event_type;
          // Trust change
          if (
            securityType ===
            "DEVICE_TRUST_CHANGED"
          ) {
            setDevice(
              (current) => (
                current
                  ? {
                      ...current,
                      trust_status:
                        payload.new_value,
                    }
                  : current
              )
            );
          }
          // Firewall change
          if (
            securityType ===
            "DEVICE_FIREWALL_CHANGED"
          ) {
            setDevice(
              (current) => (
                current
                  ? {
                      ...current,
                      firewall_enabled:
                        payload.new_value
                        === "enabled",
                    }
                  : current
              )
            );
          }
          // Patch change
          if (
            securityType ===
            "DEVICE_PATCH_STATUS_CHANGED"
          ) {
            setDevice(
              (current) => (
                current
                  ? {
                      ...current,
                      patch_status:
                        payload.new_value,
                    }
                  : current
              )
            );
          }
          // Heartbeat stale
          if (
            securityType ===
            "DEVICE_HEARTBEAT_STALE"
          ) {
            setDevice(
              (current) => (
                current
                  ? {
                      ...current,
                      heartbeat_fresh:
                        false,
                    }
                  : current
              )
            );
          }
          // Heartbeat recovery
          if (
            securityType ===
            "DEVICE_HEARTBEAT_RECOVERED"
          ) {
            setDevice(
              (current) => (
                current
                  ? {
                      ...current,
                      heartbeat_fresh:
                        true,
                      heartbeat_age_seconds:
                        0,
                    }
                  : current
              )
            );
          }
          // Reconcile optimistic state
          // with authoritative backend.
          scheduleDeviceRefresh();
        }
      } catch (err) {
        console.error(
          "Realtime event parse failed",
          err
        );
      }
    }
  );
  source.addEventListener(
    "auth_expired",
    () => {
      source.close();
      onLogout();
    }
  );
  source.onerror = () => {
    setStreamState(
      "reconnecting"
    );
  };
  return () => {
    clearTimeout(refreshTimer);
    source.close();
  };
}, [
  session.token,
  session.username,
  session.deviceId,
]);
  useEffect(() => {
      const timer = setInterval(
        () => {
          setDevice(
            (current) => {
              if (
                !current
                || !current.last_seen
              ) {
                return current;
              }
              const lastSeen =
                Date.parse(
                  current.last_seen
                );
              if (
                Number.isNaN(
                  lastSeen
                )
              ) {
                return current;
              }
              const ageSeconds = (
                Date.now()
                - lastSeen
              ) / 1000;
              const fresh = (
                ageSeconds <= 90
              );
              if (
                current.heartbeat_fresh
                === fresh
              ) {
                return current;
              }
              return {
                ...current,
                heartbeat_fresh:
                  fresh,
                heartbeat_age_seconds:
                  ageSeconds,
              };
            }
          );
        },
        1000
      );
    return () => {
      clearInterval(timer);
    };
  }, []);
  const accessResource = async (resource) => {
    const labels = [
      "Bind authenticated identity to the request",
      "Load registered device and latest posture",
      "Read resource sensitivity and request context",
    ];

    if (resource.sensitivity !== "LOW") {
      labels.push("Include trust and heartbeat evidence");
    }

    if (resource.sensitivity === "HIGH") {
      labels.push(
        "Include role, firewall, patch and reboot evidence"
      );
    }

    labels.push(
      "Submit policy input to OPA",
      "Enforce the authoritative gateway decision"
    );

    const steps = labels.map((label, index) => ({
      label,
      status: index === 0 ? "active" : "pending",
    }));

    setDecision({
      resource,
      phase: "checking",
      steps,
      result: null,
      error: null,
    });

    let apiResult = null;
    let apiError = null;

    const request = apiFetch(
      `/protected/resources/${resource.id}`,
      {},
      session
    )
      .then((data) => {
        apiResult = data;
      })
      .catch((err) => {
        apiError = err;
      });

    // Presentation pacing only: this visualizes the request journey.
    // The actual policy result still comes exclusively from the backend.
    for (let index = 0; index < steps.length; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 165));

      setDecision((current) => {
        if (!current) return current;

        return {
          ...current,
          steps: current.steps.map((step, i) => ({
            ...step,
            status:
              i < index + 1
                ? "done"
                : i === index + 1
                  ? "active"
                  : "pending",
          })),
        };
      });
    }

    await request;

    setDecision((current) =>
      current
        ? {
            ...current,
            phase: "done",
            steps: current.steps.map((step) => ({
              ...step,
              status: "done",
            })),
            result: apiResult,
            error: apiError,
          }
        : current
    );

    await refreshDevice(true);
  };

  const postureSummary = useMemo(() => {
    if (!device) {
      return { passed: 0, total: 6 };
    }
    const checks = [
      device.registered,
      device.trust_status === "trusted",
      device.heartbeat_fresh,
      device.firewall_enabled,
      device.patch_status === "updated",
      device.pending_reboot === false,
    ];
    return {
      passed: checks.filter(Boolean).length,
      total: checks.length,
    };
  }, [device]);
  return (
    <main className="vault-shell">
      <header className="topbar">
        <div className="brand-row"><div className="brand-mark small"><Shield size={19} /><span>ZT</span></div><div><strong>Zero Trust Data Vault</strong><span>Resource-aware access portal</span></div></div>
        <div className="top-actions">
          <ThemeSwitch theme={theme} onChange={onThemeChange} />
        <div
          className={
            `live-pill ${streamState}`
          }
          title={
            lastRealtimeEvent
              ? (
                  `Last realtime event: ` +
                  lastRealtimeEvent.event_type
                )
              : "Waiting for realtime event"
          }
        >
          <span className="live-dot" />
          <Wifi size={15} />
          <span>
            {
              streamState === "live"
                ? "LIVE · SSE"
                : streamState ===
                  "reconnecting"
                  ? "RECONNECTING"
                  : "CONNECTING"
            }
          </span>
        </div>
          <a className="ghost-button" href="http://localhost:8081" target="_blank" rel="noreferrer"><ServerCog size={16} /> Security Center</a>
          <button className="ghost-button" onClick={onLogout}><LogOut size={16} /> Sign out</button>
        </div>
      </header>
      <section className="hero">
        <div>
          <div className="eyebrow"><Activity size={14} /> CONTINUOUS ACCESS CONTROL</div>
          <h1>Protected data, released <span>per request.</span></h1>
          <p>Every resource request is evaluated against identity, device posture, context and sensitivity before sensitive content is fetched.</p>
        </div>
        <div className="identity-card glass">
          <div className="avatar"><UserRound size={22} /></div>
          <div><span>Authenticated session</span><strong>{session.username}</strong><small>{device?.owner_role || session.role} · {session.deviceId}</small></div>
          <Fingerprint size={22} className="identity-ok" />
        </div>
      </section>
      <section className="assurance glass">
        <div className="assurance-score">
          <Gauge size={19} />
          <span>Posture signals</span>
          <strong>{postureSummary.passed}/{postureSummary.total}</strong>
          <small>summary only · OPA decides per resource</small>
        </div>
        <div className="status-strip">
          <StatusPill icon={BadgeCheck} label="Registered" good={!!device?.registered} value={device?.registered ? "YES" : "NO"} />
          <StatusPill icon={ShieldCheck} label="Trust" good={device?.trust_status === "trusted"} value={(device?.trust_status || "unknown").toUpperCase()} />
          <StatusPill icon={HeartPulse} label="Heartbeat" good={!!device?.heartbeat_fresh} value={device?.heartbeat_fresh ? "FRESH" : "STALE"} />
          <StatusPill icon={Shield} label="Firewall" good={!!device?.firewall_enabled} value={device?.firewall_enabled ? "ON" : "OFF"} />
          <StatusPill icon={BadgeCheck} label="Patch" good={device?.patch_status === "updated"} value={(device?.patch_status || "unknown").toUpperCase()} />
        </div>
        <button className="icon-button" onClick={load} title="Refresh live posture"><RefreshCw className={loading ? "spin" : ""} size={17} /></button>
      </section>
      {message && <div className="page-alert"><CircleAlert size={17} />{message}</div>}
      <section className="section-head">
        <div><div className="eyebrow">PROTECTED CATALOG</div><h2>Protected resource catalog</h2></div>
        <div className="catalog-hint"><Wifi size={15} /> Metadata only until policy allows content</div>
      </section>
      <section className="policy-legend glass" aria-label="Sensitivity policy legend">
        <div>
          <strong>LOW / MEDIUM / HIGH describe data sensitivity and policy strictness.</strong>
          <span>They are not usernames, user ranks, or a generic security score. Context is fixed ALLOW in this lab build.</span>
        </div>
        <div className="legend-chips">
          <span className="legend-chip low">LOW · baseline</span>
          <span className="legend-chip medium">MEDIUM · trusted + fresh</span>
          <span className="legend-chip high">HIGH · privileged + hardened</span>
        </div>
      </section>
      <section className="resource-grid">
        {loading && resources.length === 0 ? [1,2,3].map((item) => <div key={item} className="resource-card skeleton" />) : resources.map((resource) => {
          const config = SENSITIVITY[resource.sensitivity];
          const Icon = config.icon;
          return (
            <article className={`resource-card ${resource.sensitivity.toLowerCase()}`} key={resource.id}>
              <div className="card-top"><div className="resource-icon"><Icon size={21} /></div><div className={`sensitivity-badge ${resource.sensitivity.toLowerCase()}`}>{resource.sensitivity}</div></div>
              <div className="resource-category">{resource.category.replaceAll("-", " ")}</div>
              <h3>{resource.title}</h3>
              <div className="customer">
                <Building2 size={15} />
                <span className="customer-label">Data owner</span>
                <strong>{resource.customer}</strong>
              </div>
              <p>{resource.description}</p>
              <div className="assurance-label"><LockKeyhole size={15} /><span>{config.label}</span><small>{config.short}</small></div>
              <button onClick={() => accessResource(resource)} className="access-button">Request access <ChevronRight size={17} /></button>
            </article>
          );
        })}
      </section>
      <section className="architecture glass">
        <div><div className="eyebrow">REQUEST PATH</div><h3>Zero Trust enforcement pipeline</h3></div>
        <div className="pipeline">
          <span><UserRound size={16} /> User</span><ChevronRight size={15}/><span><Fingerprint size={16}/> Identity</span><ChevronRight size={15}/><span><ShieldCheck size={16}/> Device</span><ChevronRight size={15}/><span><ServerCog size={16}/> OPA</span><ChevronRight size={15}/><span><Database size={16}/> Data API</span>
        </div>
      </section>
      <AccessModal state={decision} onClose={() => setDecision(null)} />
    </main>
  );
}
export default function App() {
  const [theme, setTheme] = useState(() => {
    let saved = "dark";
    try { saved = localStorage.getItem("zt-data-vault-theme") === "light" ? "light" : "dark"; } catch {}
    document.documentElement.dataset.theme = saved;
    return saved;
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("zt-data-vault-theme", theme); } catch {}
  }, [theme]);
  const changeTheme = (next) => setTheme(next === "light" ? "light" : "dark");
  const [session, setSession] = useState(() => {
    try {
      const raw = sessionStorage.getItem("zt-vault-session");
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  });
  const [bootstrap, setBootstrap] = useState(null);

  const login = (nextSession, nextBootstrap = null) => {
    sessionStorage.setItem("zt-vault-session", JSON.stringify(nextSession));
    setBootstrap(nextBootstrap);
    setSession(nextSession);
  };
  const logout = () => {
    sessionStorage.removeItem("zt-vault-session");
    setBootstrap(null);
    setSession(null);
  };
  return session
    ? <Vault session={session} onLogout={logout} initialData={bootstrap} theme={theme} onThemeChange={changeTheme} />
    : <Login onLogin={login} theme={theme} onThemeChange={changeTheme} />;
}
