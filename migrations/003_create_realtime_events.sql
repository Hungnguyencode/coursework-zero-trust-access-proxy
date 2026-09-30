CREATE TABLE IF NOT EXISTS realtime_events (
    id BIGSERIAL PRIMARY KEY,

    event_type VARCHAR(80) NOT NULL,

    username VARCHAR(50),
    device_id VARCHAR(80),

    payload JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_realtime_events_created_at
    ON realtime_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_realtime_events_device_id
    ON realtime_events (device_id);

CREATE INDEX IF NOT EXISTS idx_realtime_events_event_type
    ON realtime_events (event_type);