CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,

    event_type VARCHAR(80) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info',

    username VARCHAR(50),
    device_id VARCHAR(80),

    source VARCHAR(50) NOT NULL,
    reason VARCHAR(120),

    old_value VARCHAR(200),
    new_value VARCHAR(200),

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_created_at
    ON security_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_events_device_id
    ON security_events (device_id);

CREATE INDEX IF NOT EXISTS idx_security_events_event_type
    ON security_events (event_type);