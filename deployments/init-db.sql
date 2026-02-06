-- Initialize database for Auth Service

-- Tokens table (for tracking, actual JWT is stateless)
CREATE TABLE IF NOT EXISTS tokens (
    id UUID PRIMARY KEY,
    identity VARCHAR(255) NOT NULL,
    policies TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tokens_identity ON tokens(identity);
CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_tokens_revoked ON tokens(revoked_at) WHERE revoked_at IS NULL;

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    identity VARCHAR(255) NOT NULL,
    policies TEXT[] NOT NULL DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_apikeys_identity ON api_keys(identity);
CREATE INDEX IF NOT EXISTS idx_apikeys_keyhash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_apikeys_revoked ON api_keys(revoked_at) WHERE revoked_at IS NULL;

-- Policies table
CREATE TABLE IF NOT EXISTS policies (
    name VARCHAR(255) PRIMARY KEY,
    description TEXT,
    rules JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Insert default policies
INSERT INTO policies (name, description, rules) VALUES
('default', 'Default policy with basic self-service access', '[
    {"path": "auth/token/lookup-self", "capabilities": ["read"]},
    {"path": "auth/token/renew-self", "capabilities": ["update"]},
    {"path": "auth/token/revoke-self", "capabilities": ["update"]}
]'::jsonb),
('admin', 'Full administrative access', '[
    {"path": "*", "capabilities": ["sudo"]}
]'::jsonb)
ON CONFLICT (name) DO NOTHING;

-- Identities table (for entity management)
CREATE TABLE IF NOT EXISTS identities (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    metadata JSONB DEFAULT '{}',
    policies TEXT[] NOT NULL DEFAULT '{}',
    disabled BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identities_name ON identities(name);

-- Audit log table (local buffer before Kafka)
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    service VARCHAR(50) NOT NULL,
    operation VARCHAR(100) NOT NULL,
    identity VARCHAR(255),
    resource VARCHAR(500),
    success BOOLEAN NOT NULL,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    synced_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_service ON audit_log(service);
CREATE INDEX IF NOT EXISTS idx_audit_identity ON audit_log(identity);
CREATE INDEX IF NOT EXISTS idx_audit_synced ON audit_log(synced_at) WHERE synced_at IS NULL;

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers
CREATE TRIGGER update_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_identities_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
