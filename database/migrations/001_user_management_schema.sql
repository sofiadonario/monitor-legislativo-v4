-- OAuth2 Authentication and RBAC Schema for Monitor Legislativo v4
-- LGPD-Compliant User Management System
-- Created: 2025-07-29

-- Users table with LGPD compliance features
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    institutional_affiliation VARCHAR(255),
    oauth_provider VARCHAR(50) NOT NULL CHECK (oauth_provider IN ('google', 'microsoft')),
    oauth_subject_id VARCHAR(255) NOT NULL,
    avatar_url TEXT,
    
    -- LGPD Compliance fields
    consent_version VARCHAR(20) NOT NULL DEFAULT '1.0',
    consent_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    data_processing_consent BOOLEAN NOT NULL DEFAULT FALSE,
    marketing_consent BOOLEAN NOT NULL DEFAULT FALSE,
    last_consent_update TIMESTAMP,
    
    -- Account status
    account_status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (account_status IN ('active', 'suspended', 'deleted')),
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    
    -- LGPD data retention
    data_retention_until TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '7 years'),
    deletion_requested_at TIMESTAMP,
    
    UNIQUE(oauth_provider, oauth_subject_id)
);

-- User roles with Brazilian academic context
CREATE TABLE IF NOT EXISTS user_roles (
    id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL CHECK (role_name IN ('admin', 'researcher', 'policymaker', 'citizen')),
    role_description TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '{}',
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- User role assignments
CREATE TABLE IF NOT EXISTS user_role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES user_roles(id),
    assigned_by UUID REFERENCES users(id),
    assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    
    UNIQUE(user_id, role_id)
);

-- OAuth2 sessions with security features
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Session security
    access_token_hash VARCHAR(255),
    refresh_token_hash VARCHAR(255),
    csrf_token VARCHAR(128) NOT NULL,
    
    -- Session metadata
    ip_address INET,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    
    -- Timing
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    
    -- Security flags
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at TIMESTAMP,
    revoked_reason VARCHAR(100)
);

-- LGPD Audit log for data access tracking
CREATE TABLE IF NOT EXISTS data_access_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id VARCHAR(128) REFERENCES user_sessions(session_id) ON DELETE SET NULL,
    
    -- Access details
    action_type VARCHAR(50) NOT NULL CHECK (action_type IN ('view', 'search', 'export', 'download')),
    resource_type VARCHAR(50) NOT NULL,
    resource_ids TEXT[], -- Array of document IDs accessed
    search_criteria TEXT,
    
    -- LGPD compliance
    legal_basis VARCHAR(100) NOT NULL DEFAULT 'legitimate_interest',
    data_categories TEXT[] NOT NULL DEFAULT '{"legislative_documents"}',
    
    -- Metadata
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Performance tracking
    response_time_ms INTEGER,
    results_count INTEGER
);

-- LGPD Data subject requests
CREATE TABLE IF NOT EXISTS data_subject_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Request details
    request_type VARCHAR(50) NOT NULL CHECK (request_type IN ('access', 'portability', 'correction', 'deletion', 'processing_restriction')),
    request_description TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'rejected')),
    
    -- Processing
    processed_by UUID REFERENCES users(id),
    processor_notes TEXT,
    
    -- Timing (LGPD requires response within 15 days)
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    due_date TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '15 days'),
    completed_at TIMESTAMP,
    
    -- Attachments/exports
    export_file_path TEXT,
    export_generated_at TIMESTAMP
);

-- Brazilian institutional domains for validation
CREATE TABLE IF NOT EXISTS trusted_domains (
    id SERIAL PRIMARY KEY,
    domain VARCHAR(255) UNIQUE NOT NULL,
    institution_name VARCHAR(255) NOT NULL,
    institution_type VARCHAR(50) NOT NULL CHECK (institution_type IN ('university', 'research_center', 'government', 'ngo')),
    verification_status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (verification_status IN ('pending', 'verified', 'rejected')),
    verified_by UUID REFERENCES users(id),
    verified_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_oauth ON users(oauth_provider, oauth_subject_id);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(account_status);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_access_log_user ON data_access_log(user_id);
CREATE INDEX IF NOT EXISTS idx_access_log_timestamp ON data_access_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_data_requests_user ON data_subject_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_data_requests_status ON data_subject_requests(status, due_date);

-- Insert default roles
INSERT INTO user_roles (role_name, role_description, permissions, is_default) VALUES
('admin', 'Administrador do sistema com acesso completo', 
 '{"manage_users": true, "manage_system": true, "export_unlimited": true, "view_analytics": true, "manage_lgpd": true}', 
 false),
 
('researcher', 'Pesquisador acadêmico com acesso avançado', 
 '{"advanced_search": true, "export_data": true, "view_analytics": true, "citation_tools": true, "api_access": true}', 
 false),
 
('policymaker', 'Formulador de políticas com dashboards executivos', 
 '{"executive_dashboard": true, "geographic_analysis": true, "export_reports": true, "trend_analysis": true}', 
 false),
 
('citizen', 'Cidadão com acesso básico à informação pública', 
 '{"basic_search": true, "view_documents": true, "limited_export": true}', 
 true);

-- Insert common Brazilian academic domains
INSERT INTO trusted_domains (domain, institution_name, institution_type, verification_status) VALUES
('usp.br', 'Universidade de São Paulo', 'university', 'verified'),
('unicamp.br', 'Universidade Estadual de Campinas', 'university', 'verified'),
('ufrj.br', 'Universidade Federal do Rio de Janeiro', 'university', 'verified'),
('puc-rio.br', 'Pontifícia Universidade Católica do Rio de Janeiro', 'university', 'verified'),
('mackenzie.br', 'Universidade Presbiteriana Mackenzie', 'university', 'verified'),
('fgv.br', 'Fundação Getulio Vargas', 'university', 'verified'),
('cnpq.br', 'Conselho Nacional de Desenvolvimento Científico e Tecnológico', 'research_center', 'verified'),
('capes.gov.br', 'Coordenação de Aperfeiçoamento de Pessoal de Nível Superior', 'government', 'verified'),
('ipea.gov.br', 'Instituto de Pesquisa Econômica Aplicada', 'research_center', 'verified');

-- Function to automatically assign roles based on email domain
CREATE OR REPLACE FUNCTION assign_default_role()
RETURNS TRIGGER AS $$
DECLARE
    default_role_id INTEGER;
    domain_info RECORD;
BEGIN
    -- Extract domain from email
    SELECT * INTO domain_info 
    FROM trusted_domains 
    WHERE NEW.email LIKE '%@' || domain
    AND verification_status = 'verified'
    LIMIT 1;
    
    -- Assign role based on institution type
    IF domain_info.institution_type IN ('university', 'research_center') THEN
        SELECT id INTO default_role_id FROM user_roles WHERE role_name = 'researcher';
    ELSIF domain_info.institution_type = 'government' THEN
        SELECT id INTO default_role_id FROM user_roles WHERE role_name = 'policymaker';
    ELSE
        SELECT id INTO default_role_id FROM user_roles WHERE is_default = true;
    END IF;
    
    -- Insert role assignment
    INSERT INTO user_role_assignments (user_id, role_id)
    VALUES (NEW.id, default_role_id)
    ON CONFLICT (user_id, role_id) DO NOTHING;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to assign default role
CREATE TRIGGER trigger_assign_default_role
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION assign_default_role();

-- Function to clean expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Mark sessions as inactive and revoked
    UPDATE user_sessions 
    SET is_active = false, 
        revoked_at = CURRENT_TIMESTAMP,
        revoked_reason = 'expired'
    WHERE expires_at < CURRENT_TIMESTAMP 
    AND is_active = true;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Log cleanup
    INSERT INTO data_access_log (action_type, resource_type, legal_basis)
    VALUES ('cleanup', 'sessions', 'data_retention_policy');
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- LGPD compliance: Function to handle data deletion requests
CREATE OR REPLACE FUNCTION process_data_deletion(user_uuid UUID)
RETURNS BOOLEAN AS $$
BEGIN
    -- Anonymize user data instead of hard delete to maintain audit trail
    UPDATE users 
    SET email = 'deleted_' || id::text || '@anonymized.local',
        full_name = 'Dados Removidos - LGPD',
        institutional_affiliation = null,
        avatar_url = null,
        account_status = 'deleted',
        deletion_requested_at = CURRENT_TIMESTAMP
    WHERE id = user_uuid;
    
    -- Revoke all active sessions
    UPDATE user_sessions 
    SET is_active = false,
        revoked_at = CURRENT_TIMESTAMP,
        revoked_reason = 'account_deleted'
    WHERE user_id = user_uuid;
    
    -- Log the deletion for LGPD compliance
    INSERT INTO data_access_log (user_id, action_type, resource_type, legal_basis)
    VALUES (user_uuid, 'deletion', 'user_account', 'data_subject_request');
    
    RETURN true;
END;
$$ LANGUAGE plpgsql;

-- LGPD compliance: Automated data retention cleanup
CREATE OR REPLACE FUNCTION cleanup_expired_data()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
BEGIN
    -- Process users past retention period
    SELECT COUNT(*)::INTEGER INTO deleted_count
    FROM users 
    WHERE data_retention_until < CURRENT_TIMESTAMP
    AND account_status != 'deleted';
    
    -- Anonymize expired user data
    UPDATE users 
    SET email = 'expired_' || id::text || '@anonymized.local',
        full_name = 'Dados Expirados - LGPD',
        institutional_affiliation = null,
        avatar_url = null,
        account_status = 'deleted'
    WHERE data_retention_until < CURRENT_TIMESTAMP
    AND account_status != 'deleted';
    
    -- Clean old access logs (keep for 5 years as per LGPD)
    DELETE FROM data_access_log 
    WHERE timestamp < (CURRENT_TIMESTAMP - INTERVAL '5 years');
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Comments for LGPD compliance documentation
COMMENT ON TABLE users IS 'LGPD-compliant user table with consent management and data retention controls';
COMMENT ON COLUMN users.consent_version IS 'Version of terms and privacy policy user consented to';
COMMENT ON COLUMN users.data_processing_consent IS 'Explicit consent for data processing under LGPD Art. 7';
COMMENT ON COLUMN users.data_retention_until IS 'Automatic data deletion date per LGPD retention policy';
COMMENT ON TABLE data_access_log IS 'LGPD audit trail for data access and processing activities';
COMMENT ON TABLE data_subject_requests IS 'LGPD data subject rights requests management';