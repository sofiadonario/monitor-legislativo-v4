-- Database Schema for Monitor Legislativo v4
-- PostgreSQL-specific optimizations included

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Users and Authentication
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'user' NOT NULL,
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Roles and Permissions
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_roles (
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
    role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, permission_id)
);

-- Document Types
CREATE TYPE document_type_enum AS ENUM (
    'LEI', 'DECRETO', 'PORTARIA', 'RESOLUCAO', 'INSTRUCAO_NORMATIVA',
    'MEDIDA_PROVISORIA', 'EMENDA_CONSTITUCIONAL', 'PARECER', 'PROJETO_LEI'
);

CREATE TYPE document_status_enum AS ENUM (
    'ativo', 'revogado', 'suspenso', 'em_tramitacao', 'arquivado'
);

-- Documents table (partitioned by published_date)
CREATE TABLE documents (
    id BIGSERIAL,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    summary TEXT,
    source VARCHAR(100) NOT NULL,
    document_type document_type_enum NOT NULL,
    document_number VARCHAR(50),
    document_year INTEGER,
    published_date DATE NOT NULL,
    effective_date DATE,
    status document_status_enum DEFAULT 'ativo',
    url TEXT,
    original_url TEXT,
    hash_content VARCHAR(64), -- SHA-256 hash for change detection
    keywords TEXT[], -- PostgreSQL array for keywords
    metadata JSONB, -- Flexible metadata storage
    full_text_search TSVECTOR, -- Full-text search vector
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    indexed_at TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (id, published_date)
) PARTITION BY RANGE (published_date);

-- Create partitions for documents (by year)
CREATE TABLE documents_2023 PARTITION OF documents
    FOR VALUES FROM ('2023-01-01') TO ('2024-01-01');
CREATE TABLE documents_2024 PARTITION OF documents
    FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
CREATE TABLE documents_2025 PARTITION OF documents
    FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');

-- Document revisions (for tracking changes)
CREATE TABLE document_revisions (
    id BIGSERIAL PRIMARY KEY,
    document_id BIGINT NOT NULL,
    revision_number INTEGER NOT NULL,
    content_diff JSONB, -- Store differences
    changed_by INTEGER REFERENCES users(id),
    change_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Monitoring Rules
CREATE TABLE monitoring_rules (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    keywords TEXT[] NOT NULL,
    sources TEXT[],
    document_types document_type_enum[],
    date_range_start DATE,
    date_range_end DATE,
    is_enabled BOOLEAN DEFAULT true,
    trigger_count INTEGER DEFAULT 0,
    last_triggered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Alerts
CREATE TYPE alert_type_enum AS ENUM (
    'DOCUMENT_MATCH', 'KEYWORD_ALERT', 'STATUS_CHANGE', 
    'DEADLINE_REMINDER', 'BULK_UPDATE', 'SYSTEM_ALERT'
);

CREATE TYPE alert_status_enum AS ENUM (
    'PENDING', 'ACTIVE', 'RESOLVED', 'DISMISSED'
);

CREATE TYPE alert_priority_enum AS ENUM (
    'low', 'medium', 'high', 'critical'
);

CREATE TABLE alerts (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    rule_id INTEGER REFERENCES monitoring_rules(id) ON DELETE SET NULL,
    document_id BIGINT,
    alert_type alert_type_enum NOT NULL,
    status alert_status_enum DEFAULT 'PENDING',
    priority alert_priority_enum DEFAULT 'medium',
    title VARCHAR(500) NOT NULL,
    message TEXT NOT NULL,
    metadata JSONB,
    relevance_score DECIMAL(3,2), -- 0.00 to 1.00
    is_read BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE
);

-- User Preferences and Profiles
CREATE TABLE user_profiles (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    interests JSONB, -- topic -> weight mapping
    preferred_sources TEXT[],
    document_type_preferences JSONB,
    notification_settings JSONB,
    activity_pattern JSONB, -- hour -> activity_weight
    feedback_history JSONB[], -- Array of feedback objects
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Search History
CREATE TABLE search_queries (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    query_text TEXT NOT NULL,
    filters JSONB,
    results_count INTEGER,
    execution_time_ms DECIMAL(10,2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    session_id UUID
);

-- Export History
CREATE TABLE export_jobs (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4() UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    format VARCHAR(20) NOT NULL, -- 'csv', 'pdf', 'excel'
    query_params JSONB,
    file_path TEXT,
    file_size BIGINT,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'processing', 'completed', 'failed'
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- System Metrics (for monitoring)
CREATE TABLE system_metrics (
    id BIGSERIAL PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15,4) NOT NULL,
    labels JSONB,
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(50),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    session_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- API Tokens (for external access)
CREATE TABLE api_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    scopes TEXT[],
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance optimization
-- Users table indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_active ON users(is_active) WHERE is_active = true;

-- Documents table indexes (will be inherited by partitions)
CREATE INDEX idx_documents_published_date ON documents(published_date);
CREATE INDEX idx_documents_source ON documents(source);
CREATE INDEX idx_documents_type ON documents(document_type);
CREATE INDEX idx_documents_status ON documents(status);
CREATE INDEX idx_documents_year ON documents(document_year);
CREATE INDEX idx_documents_keywords_gin ON documents USING gin(keywords);
CREATE INDEX idx_documents_metadata_gin ON documents USING gin(metadata);
CREATE INDEX idx_documents_title_trgm ON documents USING gin(title gin_trgm_ops);
CREATE INDEX idx_documents_content_trgm ON documents USING gin(content gin_trgm_ops);
CREATE INDEX idx_documents_fts ON documents USING gin(full_text_search);
CREATE INDEX idx_documents_hash ON documents(hash_content);

-- Alerts table indexes
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_created_at ON alerts(created_at);
CREATE INDEX idx_alerts_user_status ON alerts(user_id, status);
CREATE INDEX idx_alerts_priority ON alerts(priority);
CREATE INDEX idx_alerts_unread ON alerts(user_id, is_read) WHERE is_read = false;

-- Monitoring rules indexes
CREATE INDEX idx_monitoring_rules_user_id ON monitoring_rules(user_id);
CREATE INDEX idx_monitoring_rules_enabled ON monitoring_rules(is_enabled) WHERE is_enabled = true;
CREATE INDEX idx_monitoring_rules_keywords_gin ON monitoring_rules USING gin(keywords);

-- Search queries indexes
CREATE INDEX idx_search_queries_user_id ON search_queries(user_id);
CREATE INDEX idx_search_queries_created_at ON search_queries(created_at);
CREATE INDEX idx_search_queries_text_trgm ON search_queries USING gin(query_text gin_trgm_ops);

-- System metrics indexes (for time-series queries)
CREATE INDEX idx_system_metrics_name_time ON system_metrics(metric_name, recorded_at);
CREATE INDEX idx_system_metrics_time ON system_metrics(recorded_at);

-- Audit logs indexes
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-- Create triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_documents_updated_at BEFORE UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_monitoring_rules_updated_at BEFORE UPDATE ON monitoring_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to update full-text search vector
CREATE OR REPLACE FUNCTION update_document_fts()
RETURNS TRIGGER AS $$
BEGIN
    NEW.full_text_search := to_tsvector('portuguese', 
        COALESCE(NEW.title, '') || ' ' || 
        COALESCE(NEW.content, '') || ' ' ||
        COALESCE(array_to_string(NEW.keywords, ' '), '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_documents_fts BEFORE INSERT OR UPDATE ON documents
    FOR EACH ROW EXECUTE FUNCTION update_document_fts();

-- Function to automatically create new partitions
CREATE OR REPLACE FUNCTION create_document_partition(partition_year INTEGER)
RETURNS VOID AS $$
DECLARE
    partition_name TEXT;
    start_date DATE;
    end_date DATE;
BEGIN
    partition_name := 'documents_' || partition_year;
    start_date := DATE(partition_year || '-01-01');
    end_date := DATE((partition_year + 1) || '-01-01');
    
    EXECUTE format('CREATE TABLE IF NOT EXISTS %I PARTITION OF documents 
                    FOR VALUES FROM (%L) TO (%L)',
                   partition_name, start_date, end_date);
END;
$$ LANGUAGE plpgsql;

-- Insert default roles
INSERT INTO roles (name, description) VALUES
    ('admin', 'System administrator with full access'),
    ('analyst', 'Legislative analyst with advanced search and monitoring'),
    ('user', 'Regular user with basic access'),
    ('readonly', 'Read-only access user')
ON CONFLICT (name) DO NOTHING;

-- Insert default permissions
INSERT INTO permissions (name, description, resource, action) VALUES
    ('documents.read', 'Read documents', 'documents', 'read'),
    ('documents.search', 'Search documents', 'documents', 'search'),
    ('documents.export', 'Export documents', 'documents', 'export'),
    ('alerts.create', 'Create monitoring alerts', 'alerts', 'create'),
    ('alerts.read', 'Read alerts', 'alerts', 'read'),
    ('alerts.update', 'Update alerts', 'alerts', 'update'),
    ('alerts.delete', 'Delete alerts', 'alerts', 'delete'),
    ('users.read', 'Read user information', 'users', 'read'),
    ('users.create', 'Create users', 'users', 'create'),
    ('users.update', 'Update users', 'users', 'update'),
    ('users.delete', 'Delete users', 'users', 'delete'),
    ('system.admin', 'System administration', 'system', 'admin'),
    ('reports.generate', 'Generate reports', 'reports', 'generate')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'admin' -- Admin gets all permissions
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'analyst' AND p.name IN (
    'documents.read', 'documents.search', 'documents.export',
    'alerts.create', 'alerts.read', 'alerts.update', 'alerts.delete',
    'reports.generate'
)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'user' AND p.name IN (
    'documents.read', 'documents.search', 'documents.export',
    'alerts.create', 'alerts.read', 'alerts.update', 'alerts.delete'
)
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'readonly' AND p.name IN (
    'documents.read', 'documents.search'
)
ON CONFLICT DO NOTHING;

-- Create a function for automated partition management
CREATE OR REPLACE FUNCTION maintain_partitions()
RETURNS VOID AS $$
DECLARE
    current_year INTEGER := EXTRACT(YEAR FROM CURRENT_DATE);
    next_year INTEGER := current_year + 1;
BEGIN
    -- Create next year's partition if it doesn't exist
    PERFORM create_document_partition(next_year);
    
    -- Clean up old metrics (keep last 90 days)
    DELETE FROM system_metrics 
    WHERE recorded_at < CURRENT_TIMESTAMP - INTERVAL '90 days';
    
    -- Clean up old search queries (keep last 30 days)
    DELETE FROM search_queries 
    WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '30 days';
    
    -- Clean up resolved alerts older than 1 year
    DELETE FROM alerts 
    WHERE status = 'RESOLVED' 
    AND resolved_at < CURRENT_TIMESTAMP - INTERVAL '1 year';
END;
$$ LANGUAGE plpgsql;

-- Schedule automated maintenance (requires pg_cron extension)
-- SELECT cron.schedule('partition-maintenance', '0 2 * * 0', 'SELECT maintain_partitions();');

-- Create views for common queries
CREATE VIEW active_documents AS
SELECT d.*, 
       ts_rank(d.full_text_search, plainto_tsquery('portuguese', '')) as relevance
FROM documents d
WHERE d.status = 'ativo';

CREATE VIEW user_alert_summary AS
SELECT u.id as user_id,
       u.username,
       COUNT(a.id) as total_alerts,
       COUNT(a.id) FILTER (WHERE a.is_read = false) as unread_alerts,
       COUNT(a.id) FILTER (WHERE a.priority = 'high') as high_priority_alerts,
       MAX(a.created_at) as last_alert_at
FROM users u
LEFT JOIN alerts a ON u.id = a.user_id
GROUP BY u.id, u.username;

-- Performance optimization settings
-- Note: These should be adjusted based on actual hardware and usage patterns
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;

-- Reload configuration
SELECT pg_reload_conf();