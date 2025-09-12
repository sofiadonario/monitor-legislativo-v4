-- ============================================================================
-- AUTHENTICATION SYSTEM DATABASE SCHEMA - SPRINT 6B (API-002)
-- ============================================================================
-- 
-- Comprehensive database schema for Brazilian Legislative API authentication
-- Supports multi-tier API keys, user management, academic verification,
-- LGPD compliance, and security auditing
-- 
-- Features:
-- - User registration and profile management
-- - API key lifecycle with proper security
-- - Academic institution verification
-- - Rate limiting and usage tracking
-- - LGPD-compliant audit logging
-- - Security event monitoring
-- - Administrative interfaces
-- ============================================================================

-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- USERS AND AUTHENTICATION
-- ============================================================================

-- Users table with comprehensive profile information
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE,
    
    -- Authentication credentials
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    email_verification_expires_at TIMESTAMP,
    email_verification_attempts INTEGER DEFAULT 0,
    
    -- Password authentication (optional, for web interface)
    password_hash VARCHAR(255),
    password_salt VARCHAR(255),
    password_reset_token VARCHAR(255),
    password_reset_expires_at TIMESTAMP,
    
    -- Personal information
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    title VARCHAR(50), -- Dr, Prof, Student, Researcher, etc.
    preferred_language VARCHAR(10) DEFAULT 'pt-BR',
    
    -- Institution information
    institution_name VARCHAR(255),
    institution_country VARCHAR(100) DEFAULT 'Brazil',
    institution_type VARCHAR(50), -- university, research_institute, government, ngo, private
    department VARCHAR(255),
    position VARCHAR(100), -- Professor, Student, Researcher, Analyst, etc.
    
    -- Academic/Research information
    research_field VARCHAR(255),
    research_description TEXT,
    intended_use TEXT NOT NULL,
    academic_level VARCHAR(50), -- undergraduate, graduate, postgraduate, faculty, researcher
    
    -- Account status and verification
    status VARCHAR(20) DEFAULT 'active', -- active, suspended, deleted, pending
    tier VARCHAR(20) DEFAULT 'demo', -- demo, academic, premium
    academic_status VARCHAR(20) DEFAULT 'pending', -- pending, verified, rejected, manual_review
    verification_method VARCHAR(50),
    verification_documents JSONB DEFAULT '[]',
    verified_at TIMESTAMP,
    verified_by VARCHAR(100),
    verification_notes TEXT,
    
    -- LGPD compliance
    consent_data_processing BOOLEAN DEFAULT FALSE,
    consent_email_communication BOOLEAN DEFAULT FALSE,
    consent_academic_verification BOOLEAN DEFAULT FALSE,
    consent_analytics BOOLEAN DEFAULT FALSE,
    consent_given_at TIMESTAMP,
    consent_ip_address INET,
    data_retention_until TIMESTAMP,
    anonymization_requested_at TIMESTAMP,
    deletion_requested_at TIMESTAMP,
    
    -- Security and access control
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login_at TIMESTAMP,
    last_login_ip INET,
    login_count INTEGER DEFAULT 0,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by_ip INET,
    notes TEXT,
    tags JSONB DEFAULT '[]',
    
    -- Constraints
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'deleted', 'pending')),
    CONSTRAINT valid_tier CHECK (tier IN ('demo', 'academic', 'premium')),
    CONSTRAINT valid_academic_status CHECK (academic_status IN ('pending', 'verified', 'rejected', 'manual_review'))
);

-- ============================================================================
-- API KEY MANAGEMENT
-- ============================================================================

-- API Keys table with comprehensive lifecycle management
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Key identification and security
    api_key_hash VARCHAR(256) NOT NULL UNIQUE,
    api_key_prefix VARCHAR(20) NOT NULL,
    api_key_suffix VARCHAR(10) NOT NULL, -- Last few characters for identification
    key_name VARCHAR(100), -- User-friendly name for the key
    
    -- Access control
    tier VARCHAR(20) NOT NULL DEFAULT 'demo',
    status VARCHAR(20) NOT NULL DEFAULT 'active', -- active, suspended, revoked, expired, rotated
    permissions JSONB DEFAULT '[]',
    scopes JSONB DEFAULT '[]', -- Specific API scopes
    
    -- Usage tracking and limits
    total_requests INTEGER DEFAULT 0,
    total_data_transferred BIGINT DEFAULT 0, -- bytes
    last_used_at TIMESTAMP,
    last_used_ip INET,
    last_used_endpoint VARCHAR(200),
    
    -- Rate limiting (current counters)
    hourly_requests INTEGER DEFAULT 0,
    hourly_reset_at TIMESTAMP,
    daily_requests INTEGER DEFAULT 0,
    daily_reset_at TIMESTAMP,
    monthly_requests INTEGER DEFAULT 0,
    monthly_reset_at TIMESTAMP,
    
    -- Key lifecycle
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    rotated_from_key_id INTEGER REFERENCES api_keys(id),
    rotation_scheduled_at TIMESTAMP,
    auto_rotation_enabled BOOLEAN DEFAULT TRUE,
    
    -- Security settings
    ip_whitelist JSONB DEFAULT '[]',
    allowed_origins JSONB DEFAULT '[]',
    allowed_referrers JSONB DEFAULT '[]',
    require_https BOOLEAN DEFAULT TRUE,
    
    -- Failure tracking
    failed_attempts INTEGER DEFAULT 0,
    last_failure_at TIMESTAMP,
    locked_until TIMESTAMP,
    
    -- Purpose and compliance
    purpose_statement TEXT,
    legal_basis VARCHAR(50) DEFAULT 'legitimate_interest',
    data_retention_until TIMESTAMP,
    
    -- Administrative
    created_by VARCHAR(100),
    notes TEXT,
    tags JSONB DEFAULT '[]',
    
    -- Constraints
    CONSTRAINT valid_tier CHECK (tier IN ('demo', 'academic', 'premium')),
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'revoked', 'expired', 'rotated'))
);

-- ============================================================================
-- ACADEMIC INSTITUTIONS AND VERIFICATION
-- ============================================================================

-- Academic institutions reference table
CREATE TABLE IF NOT EXISTS academic_institutions (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE,
    
    -- Institution identification
    name VARCHAR(255) NOT NULL,
    name_en VARCHAR(255), -- English name
    domain VARCHAR(255) UNIQUE,
    country VARCHAR(100) DEFAULT 'Brazil',
    state_province VARCHAR(100),
    city VARCHAR(100),
    
    -- Institution classification
    type VARCHAR(50) NOT NULL, -- university, research_institute, government, ngo, private
    subtype VARCHAR(100), -- federal_university, state_university, private_university, etc.
    accreditation_status VARCHAR(50),
    
    -- Verification settings
    auto_approve BOOLEAN DEFAULT FALSE,
    verification_required BOOLEAN DEFAULT TRUE,
    verification_method VARCHAR(50) DEFAULT 'email_domain',
    require_document_verification BOOLEAN DEFAULT FALSE,
    
    -- Institution metadata
    website VARCHAR(255),
    description TEXT,
    established_year INTEGER,
    student_count INTEGER,
    faculty_count INTEGER,
    
    -- Administrative
    status VARCHAR(20) DEFAULT 'active', -- active, inactive, pending_review
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_by VARCHAR(100),
    notes TEXT,
    
    CONSTRAINT valid_institution_type CHECK (type IN ('university', 'research_institute', 'government', 'ngo', 'private')),
    CONSTRAINT valid_institution_status CHECK (status IN ('active', 'inactive', 'pending_review'))
);

-- User verification documents
CREATE TABLE IF NOT EXISTS user_verification_documents (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Document information
    document_type VARCHAR(50) NOT NULL, -- academic_id, student_id, faculty_letter, enrollment_certificate
    original_filename VARCHAR(255),
    stored_filename VARCHAR(255),
    storage_path VARCHAR(500),
    file_size_bytes INTEGER,
    mime_type VARCHAR(100),
    file_hash VARCHAR(256), -- For integrity verification
    
    -- Verification status
    verification_status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected, requires_review
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP,
    review_notes TEXT,
    
    -- Metadata
    upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    upload_ip INET,
    expiry_date DATE, -- For documents that expire
    
    -- LGPD compliance
    consent_storage BOOLEAN DEFAULT FALSE,
    retention_until TIMESTAMP,
    
    CONSTRAINT valid_document_type CHECK (document_type IN ('academic_id', 'student_id', 'faculty_letter', 'enrollment_certificate', 'other')),
    CONSTRAINT valid_verification_status CHECK (verification_status IN ('pending', 'approved', 'rejected', 'requires_review'))
);

-- ============================================================================
-- USAGE TRACKING AND ANALYTICS
-- ============================================================================

-- API usage log for detailed analytics
CREATE TABLE IF NOT EXISTS api_usage_log (
    id BIGSERIAL PRIMARY KEY,
    
    -- Request identification
    request_id VARCHAR(100),
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Request details
    method VARCHAR(10) NOT NULL,
    endpoint VARCHAR(200) NOT NULL,
    full_path TEXT,
    query_parameters JSONB,
    
    -- Response details
    response_code INTEGER NOT NULL,
    response_time_ms INTEGER,
    request_size_bytes INTEGER,
    response_size_bytes INTEGER,
    
    -- Client information
    ip_address INET,
    user_agent TEXT,
    origin VARCHAR(255),
    referer VARCHAR(255),
    
    -- Geographic information (for analytics)
    country_code VARCHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    
    -- Error information
    error_message TEXT,
    error_type VARCHAR(50),
    
    -- Data accessed (for LGPD compliance)
    data_categories JSONB, -- Categories of data accessed
    record_count INTEGER, -- Number of records returned
    
    -- Performance metrics
    database_time_ms INTEGER,
    cache_hit BOOLEAN,
    
    CONSTRAINT valid_http_method CHECK (method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'))
);

-- Daily usage summaries for performance
CREATE TABLE IF NOT EXISTS api_usage_daily_summary (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    
    -- Request counts
    total_requests INTEGER DEFAULT 0,
    successful_requests INTEGER DEFAULT 0,
    error_requests INTEGER DEFAULT 0,
    
    -- Data transfer
    total_data_transferred BIGINT DEFAULT 0,
    
    -- Endpoint usage
    endpoint_usage JSONB DEFAULT '{}', -- {endpoint: count}
    
    -- Performance metrics
    avg_response_time_ms FLOAT,
    max_response_time_ms INTEGER,
    
    -- Geographic distribution
    country_distribution JSONB DEFAULT '{}',
    
    UNIQUE(user_id, api_key_id, date)
);

-- ============================================================================
-- SECURITY AND AUDIT LOGGING
-- ============================================================================

-- Security events log
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    
    -- Event identification
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium', -- low, medium, high, critical
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Source information
    source_ip INET,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE SET NULL,
    user_agent TEXT,
    
    -- Event details
    description TEXT NOT NULL,
    details JSONB,
    endpoint VARCHAR(200),
    
    -- Response and resolution
    response_action VARCHAR(100), -- blocked, throttled, logged, alerted
    resolved BOOLEAN DEFAULT FALSE,
    resolved_by VARCHAR(100),
    resolved_at TIMESTAMP,
    resolution_notes TEXT,
    
    -- Geographic information
    country_code VARCHAR(2),
    
    CONSTRAINT valid_severity CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

-- Registration attempts (for rate limiting and security)
CREATE TABLE IF NOT EXISTS registration_attempts (
    id SERIAL PRIMARY KEY,
    
    -- Attempt information
    email VARCHAR(255),
    ip_address INET,
    attempt_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Result
    success BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    error_code VARCHAR(50),
    
    -- Client information
    user_agent TEXT,
    origin VARCHAR(255),
    referer VARCHAR(255),
    
    -- Geographic information
    country_code VARCHAR(2),
    
    -- Follow-up actions
    user_created_id INTEGER REFERENCES users(id),
    blocked_by_rate_limit BOOLEAN DEFAULT FALSE
);

-- Login attempts tracking
CREATE TABLE IF NOT EXISTS login_attempts (
    id SERIAL PRIMARY KEY,
    
    -- Attempt information
    email VARCHAR(255),
    ip_address INET,
    attempt_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Result
    success BOOLEAN DEFAULT FALSE,
    failure_reason VARCHAR(100),
    
    -- Client information
    user_agent TEXT,
    session_id VARCHAR(255),
    
    -- User information (if successful)
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    
    -- Geographic information
    country_code VARCHAR(2)
);

-- ============================================================================
-- ADMINISTRATIVE TABLES
-- ============================================================================

-- API key quotas and limits (for flexible tier management)
CREATE TABLE IF NOT EXISTS api_tier_limits (
    id SERIAL PRIMARY KEY,
    tier VARCHAR(20) NOT NULL UNIQUE,
    
    -- Rate limits
    requests_per_hour INTEGER NOT NULL,
    requests_per_day INTEGER NOT NULL,
    requests_per_month INTEGER NOT NULL,
    
    -- Data limits
    max_results_per_request INTEGER NOT NULL,
    max_data_transfer_per_day BIGINT, -- bytes
    
    -- Feature access
    allowed_endpoints JSONB NOT NULL DEFAULT '[]',
    bulk_export_enabled BOOLEAN DEFAULT FALSE,
    priority_support BOOLEAN DEFAULT FALSE,
    advanced_analytics BOOLEAN DEFAULT FALSE,
    
    -- Security features
    ip_whitelisting_enabled BOOLEAN DEFAULT FALSE,
    require_https BOOLEAN DEFAULT TRUE,
    
    -- Pricing (for future premium tiers)
    monthly_cost_usd DECIMAL(10,2) DEFAULT 0.00,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- System configuration
CREATE TABLE IF NOT EXISTS system_config (
    id SERIAL PRIMARY KEY,
    config_key VARCHAR(100) NOT NULL UNIQUE,
    config_value TEXT,
    config_type VARCHAR(20) DEFAULT 'string', -- string, integer, boolean, json
    description TEXT,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(100)
);

-- ============================================================================
-- INDEXES FOR PERFORMANCE
-- ============================================================================

-- Users table indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_tier ON users(tier);
CREATE INDEX IF NOT EXISTS idx_users_academic_status ON users(academic_status);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_users_institution ON users(institution_name);

-- API keys table indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(api_key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_tier ON api_keys(tier);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_last_used ON api_keys(last_used_at);

-- Academic institutions indexes
CREATE INDEX IF NOT EXISTS idx_institutions_domain ON academic_institutions(domain);
CREATE INDEX IF NOT EXISTS idx_institutions_type ON academic_institutions(type);
CREATE INDEX IF NOT EXISTS idx_institutions_country ON academic_institutions(country);

-- Verification documents indexes
CREATE INDEX IF NOT EXISTS idx_verification_docs_user_id ON user_verification_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_verification_docs_status ON user_verification_documents(verification_status);

-- Usage log indexes
CREATE INDEX IF NOT EXISTS idx_usage_log_api_key_id ON api_usage_log(api_key_id);
CREATE INDEX IF NOT EXISTS idx_usage_log_user_id ON api_usage_log(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_log_timestamp ON api_usage_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_usage_log_endpoint ON api_usage_log(endpoint);
CREATE INDEX IF NOT EXISTS idx_usage_log_ip ON api_usage_log(ip_address);

-- Security events indexes
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(source_ip);

-- Registration attempts indexes
CREATE INDEX IF NOT EXISTS idx_registration_attempts_ip ON registration_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_registration_attempts_timestamp ON registration_attempts(attempt_timestamp);
CREATE INDEX IF NOT EXISTS idx_registration_attempts_email ON registration_attempts(email);

-- ============================================================================
-- TRIGGERS FOR AUTOMATED UPDATES
-- ============================================================================

-- Update timestamp trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update timestamp triggers
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_institutions_updated_at BEFORE UPDATE ON academic_institutions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tier_limits_updated_at BEFORE UPDATE ON api_tier_limits
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_config_updated_at BEFORE UPDATE ON system_config
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- DEFAULT DATA
-- ============================================================================

-- Insert default API tier limits
INSERT INTO api_tier_limits (
    tier, requests_per_hour, requests_per_day, requests_per_month,
    max_results_per_request, allowed_endpoints, bulk_export_enabled,
    priority_support, advanced_analytics
) VALUES 
(
    'demo', 100, 1000, 10000, 100,
    '["documents", "search", "statistics"]'::jsonb,
    FALSE, FALSE, FALSE
),
(
    'academic', 1000, 10000, 100000, 1000,
    '["documents", "search", "statistics", "geography", "export"]'::jsonb,
    TRUE, FALSE, TRUE
),
(
    'premium', 2000, 50000, 500000, 5000,
    '["documents", "search", "statistics", "geography", "export", "citations", "analytics"]'::jsonb,
    TRUE, TRUE, TRUE
)
ON CONFLICT (tier) DO UPDATE SET
    requests_per_hour = EXCLUDED.requests_per_hour,
    requests_per_day = EXCLUDED.requests_per_day,
    requests_per_month = EXCLUDED.requests_per_month,
    max_results_per_request = EXCLUDED.max_results_per_request,
    allowed_endpoints = EXCLUDED.allowed_endpoints,
    bulk_export_enabled = EXCLUDED.bulk_export_enabled,
    priority_support = EXCLUDED.priority_support,
    advanced_analytics = EXCLUDED.advanced_analytics,
    updated_at = CURRENT_TIMESTAMP;

-- Insert default academic institutions
INSERT INTO academic_institutions (name, domain, type, auto_approve, verification_required) VALUES
('Universidade de São Paulo', 'usp.br', 'university', TRUE, FALSE),
('Universidade Estadual de Campinas', 'unicamp.br', 'university', TRUE, FALSE),
('Universidade Federal do Rio de Janeiro', 'ufrj.br', 'university', TRUE, FALSE),
('Universidade Federal de Minas Gerais', 'ufmg.br', 'university', TRUE, FALSE),
('Universidade Federal do Rio Grande do Sul', 'ufrgs.br', 'university', TRUE, FALSE),
('Pontifícia Universidade Católica do Rio de Janeiro', 'puc-rio.br', 'university', TRUE, FALSE),
('Fundação Getúlio Vargas', 'fgv.br', 'university', TRUE, FALSE),
('Universidade Presbiteriana Mackenzie', 'mackenzie.br', 'university', TRUE, FALSE),
('Conselho Nacional de Desenvolvimento Científico e Tecnológico', 'cnpq.br', 'research_institute', TRUE, FALSE),
('Coordenação de Aperfeiçoamento de Pessoal de Nível Superior', 'capes.gov.br', 'government', TRUE, FALSE)
ON CONFLICT (domain) DO NOTHING;

-- Insert default system configuration
INSERT INTO system_config (config_key, config_value, config_type, description) VALUES
('max_api_keys_per_user', '5', 'integer', 'Maximum API keys allowed per user'),
('email_verification_required', 'true', 'boolean', 'Whether email verification is required for registration'),
('academic_auto_approval_enabled', 'true', 'boolean', 'Whether academic institutions are auto-approved'),
('security_logging_enabled', 'true', 'boolean', 'Whether security events are logged'),
('lgpd_compliance_enabled', 'true', 'boolean', 'Whether LGPD compliance features are active'),
('rate_limiting_enabled', 'true', 'boolean', 'Whether rate limiting is enforced'),
('emergency_lockout_active', 'false', 'boolean', 'Emergency system lockout status')
ON CONFLICT (config_key) DO NOTHING;

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

-- User summary view
CREATE OR REPLACE VIEW user_summary AS
SELECT 
    u.id,
    u.email,
    u.first_name,
    u.last_name,
    u.institution_name,
    u.tier,
    u.academic_status,
    u.status,
    u.created_at,
    u.last_login_at,
    COUNT(ak.id) as api_key_count,
    COALESCE(SUM(ak.total_requests), 0) as total_requests
FROM users u
LEFT JOIN api_keys ak ON u.id = ak.user_id AND ak.status = 'active'
GROUP BY u.id, u.email, u.first_name, u.last_name, u.institution_name, 
         u.tier, u.academic_status, u.status, u.created_at, u.last_login_at;

-- API key summary view
CREATE OR REPLACE VIEW api_key_summary AS
SELECT 
    ak.id,
    ak.api_key_prefix,
    ak.api_key_suffix,
    ak.key_name,
    ak.tier,
    ak.status,
    ak.total_requests,
    ak.last_used_at,
    ak.expires_at,
    u.email as user_email,
    u.first_name || ' ' || u.last_name as user_name
FROM api_keys ak
JOIN users u ON ak.user_id = u.id;

-- Usage statistics view
CREATE OR REPLACE VIEW usage_statistics AS
SELECT 
    DATE(timestamp) as date,
    COUNT(*) as total_requests,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT api_key_id) as unique_api_keys,
    AVG(response_time_ms) as avg_response_time,
    SUM(CASE WHEN response_code >= 400 THEN 1 ELSE 0 END) as error_count
FROM api_usage_log
GROUP BY DATE(timestamp)
ORDER BY date DESC;

-- Security events summary view
CREATE OR REPLACE VIEW security_events_summary AS
SELECT 
    DATE(timestamp) as date,
    event_type,
    severity,
    COUNT(*) as event_count,
    COUNT(DISTINCT source_ip) as unique_ips
FROM security_events
GROUP BY DATE(timestamp), event_type, severity
ORDER BY date DESC, severity DESC;

-- ============================================================================
-- CLEANUP AND MAINTENANCE FUNCTIONS
-- ============================================================================

-- Function to clean old logs (for LGPD compliance)
CREATE OR REPLACE FUNCTION cleanup_old_logs()
RETURNS void AS $$
BEGIN
    -- Delete old API usage logs (keep 2 years)
    DELETE FROM api_usage_log 
    WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '2 years';
    
    -- Delete old security events (keep 7 years for compliance)
    DELETE FROM security_events 
    WHERE timestamp < CURRENT_TIMESTAMP - INTERVAL '7 years';
    
    -- Delete old registration attempts (keep 1 year)
    DELETE FROM registration_attempts 
    WHERE attempt_timestamp < CURRENT_TIMESTAMP - INTERVAL '1 year';
    
    -- Delete old login attempts (keep 1 year)
    DELETE FROM login_attempts 
    WHERE attempt_timestamp < CURRENT_TIMESTAMP - INTERVAL '1 year';
    
    RAISE NOTICE 'Old logs cleaned up successfully';
END;
$$ LANGUAGE plpgsql;

-- Function to anonymize user data (LGPD compliance)
CREATE OR REPLACE FUNCTION anonymize_user_data(user_id_param INTEGER)
RETURNS void AS $$
BEGIN
    UPDATE users SET
        email = 'anonymized_' || id || '@example.com',
        first_name = 'Anonymized',
        last_name = 'User',
        research_description = 'Anonymized',
        intended_use = 'Anonymized',
        notes = 'User data anonymized on ' || CURRENT_TIMESTAMP,
        anonymization_requested_at = CURRENT_TIMESTAMP
    WHERE id = user_id_param;
    
    RAISE NOTICE 'User % data anonymized', user_id_param;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- GRANTS AND PERMISSIONS
-- ============================================================================

-- Grant appropriate permissions to application user
-- (Adjust as needed based on your database user configuration)

-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO api_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO api_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO api_user;

-- ============================================================================
-- SCHEMA COMPLETION
-- ============================================================================

-- Add comments for documentation
COMMENT ON TABLE users IS 'User accounts with comprehensive profile and verification information';
COMMENT ON TABLE api_keys IS 'API keys with lifecycle management and security features';
COMMENT ON TABLE academic_institutions IS 'Reference table for academic institution verification';
COMMENT ON TABLE api_usage_log IS 'Detailed API usage logging for analytics and compliance';
COMMENT ON TABLE security_events IS 'Security event logging for monitoring and compliance';
COMMENT ON TABLE api_tier_limits IS 'Configurable limits and features for different API tiers';

-- Schema version for migration tracking
INSERT INTO system_config (config_key, config_value, config_type, description) VALUES
('schema_version', '1.0.0', 'string', 'Current authentication schema version')
ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value;

-- Mark schema as initialized
INSERT INTO system_config (config_key, config_value, config_type, description) VALUES
('schema_initialized', 'true', 'boolean', 'Whether the authentication schema has been initialized')
ON CONFLICT (config_key) DO UPDATE SET config_value = EXCLUDED.config_value;

-- Final success message
DO $$
BEGIN
    RAISE NOTICE '✅ Authentication system database schema initialized successfully';
    RAISE NOTICE '📊 Created tables: users, api_keys, academic_institutions, api_usage_log, security_events, and more';
    RAISE NOTICE '🔐 Security features: LGPD compliance, audit logging, rate limiting support';
    RAISE NOTICE '🎓 Academic verification: Institution validation, document verification';
    RAISE NOTICE '📈 Analytics: Usage tracking, performance monitoring, security events';
END $$;