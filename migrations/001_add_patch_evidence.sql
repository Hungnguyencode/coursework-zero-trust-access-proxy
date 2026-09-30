ALTER TABLE device_postures
    ADD COLUMN IF NOT EXISTS latest_hotfix_id VARCHAR(50);

ALTER TABLE device_postures
    ADD COLUMN IF NOT EXISTS latest_hotfix_installed_on TIMESTAMPTZ;

ALTER TABLE device_postures
    ADD COLUMN IF NOT EXISTS patch_age_days DOUBLE PRECISION;

ALTER TABLE device_postures
    ADD COLUMN IF NOT EXISTS pending_reboot BOOLEAN;

ALTER TABLE device_postures
    ADD COLUMN IF NOT EXISTS patch_reason VARCHAR(100);