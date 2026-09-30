CREATE TABLE IF NOT EXISTS demo_controls (
    device_id VARCHAR(80) PRIMARY KEY,

    simulate_firewall_disabled BOOLEAN NOT NULL DEFAULT FALSE,
    simulate_patch_outdated BOOLEAN NOT NULL DEFAULT FALSE,
    simulate_agent_loss BOOLEAN NOT NULL DEFAULT FALSE,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_demo_controls_updated_at
ON demo_controls (updated_at DESC);