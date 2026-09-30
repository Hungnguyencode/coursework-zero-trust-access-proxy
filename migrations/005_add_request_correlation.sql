-- ============================================================
-- V1.4E - Request Correlation + Decision Evidence
-- ============================================================
--
-- Each protected request receives one gateway-generated UUID.
-- The access log stores both the compact audit decision and
-- an immutable snapshot of the context used for that decision.
--
-- Existing V1.3/V1.4 rows remain valid with request_id = NULL.
-- ============================================================


ALTER TABLE access_logs
    ADD COLUMN IF NOT EXISTS request_id UUID,
    ADD COLUMN IF NOT EXISTS resource_id INTEGER,
    ADD COLUMN IF NOT EXISTS resource_sensitivity VARCHAR(10),
    ADD COLUMN IF NOT EXISTS policy_version VARCHAR(40),
    ADD COLUMN IF NOT EXISTS decision_context JSONB
        NOT NULL DEFAULT '{}'::jsonb;


-- ------------------------------------------------------------
-- One request ID must identify at most one access decision.
--
-- Partial index is intentional:
-- historical rows created before V1.4E have request_id = NULL.
-- ------------------------------------------------------------

CREATE UNIQUE INDEX IF NOT EXISTS
    idx_access_logs_request_id
ON access_logs (request_id)
WHERE request_id IS NOT NULL;


-- ------------------------------------------------------------
-- Useful for Decision Inspector / audit filtering.
-- ------------------------------------------------------------

CREATE INDEX IF NOT EXISTS
    idx_access_logs_resource_id
ON access_logs (resource_id);


CREATE INDEX IF NOT EXISTS
    idx_access_logs_resource_sensitivity
ON access_logs (resource_sensitivity);


CREATE INDEX IF NOT EXISTS
    idx_access_logs_created_at_desc
ON access_logs (created_at DESC);


-- ------------------------------------------------------------
-- Only the three current Data Vault sensitivity levels are
-- accepted. NULL remains legal for legacy /internal/data rows.
-- ------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'chk_access_logs_resource_sensitivity'
    ) THEN
        ALTER TABLE access_logs
        ADD CONSTRAINT chk_access_logs_resource_sensitivity
        CHECK (
            resource_sensitivity IS NULL
            OR resource_sensitivity IN ('LOW', 'MEDIUM', 'HIGH')
        );
    END IF;
END
$$;