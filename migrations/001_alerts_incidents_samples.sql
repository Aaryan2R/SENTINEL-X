-- T-024 minimal PostgreSQL persistence schema. Safe to apply offline (no
-- extensions, network calls, or application-side assumptions).
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    source_ip INET NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS samples (
    sample_id TEXT PRIMARY KEY,
    captured_at TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    incident_id TEXT REFERENCES incidents (incident_id),
    timestamp TIMESTAMPTZ NOT NULL,
    source_ip INET NOT NULL,
    destination_ip INET NOT NULL,
    destination_port INTEGER,
    threat_class TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    payload JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS alerts_timestamp_idx ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS samples_captured_at_idx ON samples (captured_at DESC);
