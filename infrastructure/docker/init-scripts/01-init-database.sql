-- =============================================================================
-- DATABASE INITIALIZATION SCRIPT FOR LOCAL DEVELOPMENT
-- Brazilian Legislative Monitoring System
-- =============================================================================

-- Create database if it doesn't exist (for local development)
-- This script runs automatically when PostgreSQL container starts

-- Set Brazilian timezone
SET timezone = 'America/Sao_Paulo';

-- Create extensions needed for the application
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create development user with limited privileges
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user WITH LOGIN PASSWORD 'app_password_change_me';
    END IF;
END
$$;

-- Grant necessary permissions
GRANT CONNECT ON DATABASE monitor_legislativo_dev TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT CREATE ON SCHEMA public TO app_user;

-- Create audit table for LGPD compliance
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    table_name VARCHAR(255) NOT NULL,
    operation VARCHAR(10) NOT NULL,
    old_values JSONB,
    new_values JSONB,
    user_id VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT
);

-- Create index for audit queries
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_table_name ON audit_log(table_name);

-- Insert initial system event
INSERT INTO audit_log (table_name, operation, new_values, user_id) 
VALUES ('system', 'INIT', '{"event": "database_initialized", "environment": "development"}', 'system')
ON CONFLICT DO NOTHING;

-- Create health check function
CREATE OR REPLACE FUNCTION health_check()
RETURNS TABLE(status TEXT, timestamp TIMESTAMP WITH TIME ZONE) AS $$
BEGIN
    RETURN QUERY SELECT 'OK'::TEXT, NOW();
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION health_check() IS 'Health check function for application monitoring';

-- Performance optimization for development
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_duration = on;

-- Brazilian locale support
ALTER DATABASE monitor_legislativo_dev SET lc_collate = 'pt_BR.UTF-8';
ALTER DATABASE monitor_legislativo_dev SET lc_ctype = 'pt_BR.UTF-8';

-- Log initialization completion
DO $$
BEGIN
    RAISE NOTICE 'Database initialization completed for Monitor Legislativo development environment';
END
$$;