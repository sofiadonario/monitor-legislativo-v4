-- Performance Monitoring and Real-Time System Health Schema
-- Monitor Legislativo v4 - Phase 2 Enhancement
-- Created: 2025-07-29
-- Purpose: Comprehensive monitoring for Railway deployment with PostgreSQL/Redis

-- System Health Metrics table
CREATE TABLE IF NOT EXISTS system_health_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Railway Platform Metrics
    cpu_usage_percent DECIMAL(5,2),
    memory_usage_mb INTEGER,
    memory_total_mb INTEGER,
    memory_usage_percent DECIMAL(5,2),
    
    -- Disk and Storage
    disk_usage_mb INTEGER,
    disk_total_mb INTEGER,
    disk_usage_percent DECIMAL(5,2),
    
    -- Network Metrics
    network_in_mb DECIMAL(10,2),
    network_out_mb DECIMAL(10,2),
    active_connections INTEGER,
    
    -- Application Status
    app_status VARCHAR(20) NOT NULL DEFAULT 'healthy' CHECK (app_status IN ('healthy', 'degraded', 'unhealthy', 'maintenance')),
    uptime_seconds BIGINT,
    
    -- Timestamps
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    collection_duration_ms INTEGER DEFAULT 0,
    
    -- Environment context
    deployment_env VARCHAR(20) DEFAULT 'production',
    railway_service_id VARCHAR(50),
    
    -- Metadata
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Database Performance Metrics
CREATE TABLE IF NOT EXISTS database_performance_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Connection Pool Health
    pool_active_connections INTEGER,
    pool_idle_connections INTEGER,
    pool_total_connections INTEGER,
    pool_max_connections INTEGER,
    pool_connection_wait_time_ms INTEGER,
    
    -- Query Performance
    active_queries INTEGER,
    slow_queries_count INTEGER, -- Queries > 3 seconds
    avg_query_time_ms DECIMAL(10,2),
    total_queries_per_minute INTEGER,
    
    -- PostgreSQL Specific Metrics
    pg_connections_used INTEGER,
    pg_connections_available INTEGER,
    pg_locks_granted INTEGER,
    pg_locks_waiting INTEGER,
    
    -- Database Size and Storage
    database_size_mb INTEGER,
    total_table_size_mb INTEGER,
    total_index_size_mb INTEGER,
    
    -- Performance Indicators
    cache_hit_ratio DECIMAL(5,2), -- Buffer cache efficiency
    index_hit_ratio DECIMAL(5,2), -- Index usage efficiency
    checkpoint_sync_time_ms INTEGER,
    
    -- Transaction Metrics
    transactions_per_second DECIMAL(10,2),
    rollbacks_per_second DECIMAL(10,2),
    deadlocks_count INTEGER DEFAULT 0,
    
    -- Timing and Context
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    measurement_duration_ms INTEGER DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Application Performance Metrics (R/Shiny specific)
CREATE TABLE IF NOT EXISTS application_performance_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- R/Shiny Session Metrics
    active_sessions INTEGER DEFAULT 0,
    peak_concurrent_sessions INTEGER DEFAULT 0,
    total_sessions_created INTEGER DEFAULT 0,
    avg_session_duration_minutes DECIMAL(10,2),
    
    -- Request Performance
    total_requests INTEGER DEFAULT 0,
    avg_response_time_ms DECIMAL(10,2),
    median_response_time_ms DECIMAL(10,2),
    p95_response_time_ms DECIMAL(10,2),
    slow_requests_count INTEGER DEFAULT 0, -- > 3 seconds
    
    -- R Memory Management
    r_memory_usage_mb INTEGER,
    r_objects_count INTEGER,
    garbage_collection_count INTEGER DEFAULT 0,
    gc_time_ms INTEGER DEFAULT 0,
    
    -- Shiny Specific Metrics
    reactive_invalidations INTEGER DEFAULT 0,
    render_errors INTEGER DEFAULT 0,
    websocket_connections INTEGER DEFAULT 0,
    
    -- Feature Usage
    map_renders INTEGER DEFAULT 0,
    search_operations INTEGER DEFAULT 0,
    data_exports INTEGER DEFAULT 0,
    document_views INTEGER DEFAULT 0,
    
    -- Legislative Data Processing
    documents_processed INTEGER DEFAULT 0,
    search_index_size_mb INTEGER,
    csv_load_time_ms INTEGER,
    
    -- Error Tracking
    total_errors INTEGER DEFAULT 0,
    server_errors INTEGER DEFAULT 0,
    client_errors INTEGER DEFAULT 0,
    timeout_errors INTEGER DEFAULT 0,
    
    -- Timing and Context
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    measurement_window_minutes INTEGER DEFAULT 5,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- User Activity and Analytics (LGPD compliant)
CREATE TABLE IF NOT EXISTS user_activity_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- User Activity Aggregates (no personal data)
    total_active_users INTEGER DEFAULT 0,
    new_users_count INTEGER DEFAULT 0,
    returning_users_count INTEGER DEFAULT 0,
    
    -- Role-based Usage
    admin_sessions INTEGER DEFAULT 0,
    researcher_sessions INTEGER DEFAULT 0,
    policymaker_sessions INTEGER DEFAULT 0,
    citizen_sessions INTEGER DEFAULT 0,
    
    -- Feature Usage by Role
    advanced_search_usage INTEGER DEFAULT 0,
    basic_search_usage INTEGER DEFAULT 0,
    export_operations INTEGER DEFAULT 0,
    dashboard_views INTEGER DEFAULT 0,
    
    -- Geographic Distribution (aggregated)
    sp_users INTEGER DEFAULT 0,
    rj_users INTEGER DEFAULT 0,
    mg_users INTEGER DEFAULT 0,
    other_states_users INTEGER DEFAULT 0,
    international_users INTEGER DEFAULT 0,
    
    -- Content Interaction
    document_type_searches JSONB DEFAULT '{}', -- {"jurisprudencia": 150, "legislacao": 200}
    popular_search_terms JSONB DEFAULT '{}',
    most_viewed_documents JSONB DEFAULT '{}',
    
    -- Performance Impact on Users
    avg_user_session_duration_minutes DECIMAL(10,2),
    bounce_rate_percent DECIMAL(5,2),
    user_satisfaction_score DECIMAL(3,2), -- Based on session completion
    
    -- Authentication Metrics
    oauth_login_success INTEGER DEFAULT 0,
    oauth_login_failures INTEGER DEFAULT 0,
    session_timeouts INTEGER DEFAULT 0,
    
    -- Timing and Context
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    aggregation_period_hours INTEGER DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- LGPD Compliance Note
    privacy_compliance_level VARCHAR(20) DEFAULT 'anonymized'
);

-- Alert Rules and Thresholds
CREATE TABLE IF NOT EXISTS monitoring_alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Rule Definition
    rule_name VARCHAR(100) UNIQUE NOT NULL,
    rule_description TEXT,
    metric_type VARCHAR(50) NOT NULL CHECK (metric_type IN ('system', 'database', 'application', 'user_activity')),
    metric_name VARCHAR(100) NOT NULL,
    
    -- Threshold Configuration
    warning_threshold DECIMAL(15,2),
    critical_threshold DECIMAL(15,2),
    comparison_operator VARCHAR(10) NOT NULL CHECK (comparison_operator IN ('>', '<', '>=', '<=', '=')),
    
    -- Alert Behavior
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    alert_frequency_minutes INTEGER DEFAULT 15, -- Minimum time between alerts
    escalation_after_minutes INTEGER DEFAULT 60,
    
    -- Notification Settings
    notification_channels JSONB DEFAULT '{"email": true, "webhook": false}',
    recipient_roles TEXT[] DEFAULT '{"admin"}',
    
    -- Context
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES users(id)
);

-- Alert History and Events
CREATE TABLE IF NOT EXISTS monitoring_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Alert Details
    rule_id UUID NOT NULL REFERENCES monitoring_alert_rules(id),
    alert_level VARCHAR(20) NOT NULL CHECK (alert_level IN ('warning', 'critical', 'resolved')),
    
    -- Metric Context
    metric_value DECIMAL(15,2) NOT NULL,
    threshold_value DECIMAL(15,2) NOT NULL,
    metric_timestamp TIMESTAMP NOT NULL,
    
    -- Alert Status
    alert_status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (alert_status IN ('active', 'acknowledged', 'resolved', 'suppressed')),
    acknowledged_by UUID REFERENCES users(id),
    acknowledged_at TIMESTAMP,
    resolved_at TIMESTAMP,
    
    -- Response Tracking
    resolution_notes TEXT,
    auto_resolved BOOLEAN DEFAULT FALSE,
    
    -- Notification Status
    notifications_sent JSONB DEFAULT '{}',
    notification_failures JSONB DEFAULT '{}',
    
    -- Timing
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Redis/Cache Performance Monitoring
CREATE TABLE IF NOT EXISTS cache_performance_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Redis Connection Health
    redis_connected BOOLEAN DEFAULT FALSE,
    redis_response_time_ms DECIMAL(10,2),
    redis_connections_active INTEGER DEFAULT 0,
    
    -- Cache Statistics
    cache_hit_rate DECIMAL(5,2),
    cache_miss_rate DECIMAL(5,2),
    total_cache_operations INTEGER DEFAULT 0,
    
    -- Memory Usage
    redis_memory_used_mb INTEGER,
    redis_memory_peak_mb INTEGER,
    redis_memory_fragmentation_ratio DECIMAL(5,2),
    
    -- Key Statistics
    total_keys INTEGER DEFAULT 0,
    expired_keys INTEGER DEFAULT 0,
    evicted_keys INTEGER DEFAULT 0,
    
    -- Performance Impact
    cache_enabled_speedup_factor DECIMAL(5,2), -- How much faster with cache
    data_retrieval_time_ms DECIMAL(10,2),
    
    -- Timing
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Performance Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_system_health_timestamp ON system_health_metrics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_system_health_status ON system_health_metrics(app_status, timestamp);

CREATE INDEX IF NOT EXISTS idx_db_perf_timestamp ON database_performance_metrics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_db_perf_slow_queries ON database_performance_metrics(slow_queries_count, timestamp);

CREATE INDEX IF NOT EXISTS idx_app_perf_timestamp ON application_performance_metrics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_app_perf_errors ON application_performance_metrics(total_errors, timestamp);

CREATE INDEX IF NOT EXISTS idx_user_activity_timestamp ON user_activity_metrics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_user_activity_users ON user_activity_metrics(total_active_users, timestamp);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON monitoring_alerts(alert_status, created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON monitoring_alerts(rule_id, alert_status);

CREATE INDEX IF NOT EXISTS idx_cache_perf_timestamp ON cache_performance_metrics(timestamp DESC);

-- Insert default alert rules for critical system monitoring
INSERT INTO monitoring_alert_rules (rule_name, rule_description, metric_type, metric_name, warning_threshold, critical_threshold, comparison_operator, recipient_roles) VALUES

-- System Health Alerts
('high_cpu_usage', 'CPU usage exceeding safe thresholds', 'system', 'cpu_usage_percent', 80.0, 95.0, '>', '{"admin"}'),
('high_memory_usage', 'Memory usage approaching Railway limits', 'system', 'memory_usage_percent', 85.0, 95.0, '>', '{"admin"}'),
('low_disk_space', 'Disk space running low', 'system', 'disk_usage_percent', 80.0, 90.0, '>', '{"admin"}'),

-- Database Performance Alerts
('database_slow_queries', 'High number of slow database queries', 'database', 'slow_queries_count', 10.0, 25.0, '>', '{"admin"}'),
('database_connection_pool_exhaustion', 'Database connection pool nearly exhausted', 'database', 'pool_active_connections', 80.0, 95.0, '>', '{"admin"}'),
('low_cache_hit_ratio', 'Database cache efficiency degraded', 'database', 'cache_hit_ratio', 80.0, 70.0, '<', '{"admin"}'),

-- Application Performance Alerts
('high_response_time', 'Application response times degraded', 'application', 'avg_response_time_ms', 3000.0, 5000.0, '>', '{"admin"}'),
('high_error_rate', 'Application error rate elevated', 'application', 'total_errors', 20.0, 50.0, '>', '{"admin"}'),
('r_memory_leak', 'R memory usage continuously growing', 'application', 'r_memory_usage_mb', 1024.0, 2048.0, '>', '{"admin"}'),

-- User Experience Alerts
('low_user_satisfaction', 'User satisfaction metrics declining', 'user_activity', 'user_satisfaction_score', 3.5, 3.0, '<', '{"admin"}'),
('high_bounce_rate', 'Users leaving without interaction', 'user_activity', 'bounce_rate_percent', 60.0, 80.0, '>', '{"admin"}');

-- Function to collect system health metrics
CREATE OR REPLACE FUNCTION collect_system_health_metrics()
RETURNS BOOLEAN AS $$
DECLARE
    metric_id UUID;
BEGIN
    -- Insert current system health snapshot
    INSERT INTO system_health_metrics (
        cpu_usage_percent,
        memory_usage_mb,
        memory_usage_percent,
        active_connections,
        app_status,
        uptime_seconds,
        railway_service_id
    ) VALUES (
        -- These will be populated by the R monitoring functions
        NULL, -- CPU will be measured by R system functions
        NULL, -- Memory from R memory.size()
        NULL, -- Calculated percentage
        (SELECT count(*) FROM pg_stat_activity WHERE state = 'active'),
        'healthy', -- Default, will be updated based on thresholds
        EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - pg_postmaster_start_time())),
        current_setting('application_name', true)
    )
    RETURNING id INTO metric_id;
    
    -- Log the collection
    INSERT INTO data_access_log (action_type, resource_type, legal_basis)
    VALUES ('monitoring', 'system_metrics', 'system_administration');
    
    RETURN TRUE;
    
EXCEPTION WHEN OTHERS THEN
    -- Log error but don't fail the application
    INSERT INTO data_access_log (action_type, resource_type, legal_basis, search_criteria)
    VALUES ('monitoring_error', 'system_metrics', 'system_administration', SQLERRM);
    
    RETURN FALSE;
END;
$$ LANGUAGE plpgsql;

-- Function to evaluate alert rules and trigger notifications
CREATE OR REPLACE FUNCTION evaluate_alert_rules()
RETURNS INTEGER AS $$
DECLARE
    rule_record RECORD;
    latest_metric RECORD;
    alert_triggered BOOLEAN := FALSE;
    alerts_created INTEGER := 0;
BEGIN
    -- Loop through active alert rules
    FOR rule_record IN 
        SELECT * FROM monitoring_alert_rules 
        WHERE is_active = true
    LOOP
        -- Get latest metric value based on rule type
        IF rule_record.metric_type = 'system' THEN
            EXECUTE format('SELECT %I as metric_value, timestamp FROM system_health_metrics 
                           WHERE %I IS NOT NULL ORDER BY timestamp DESC LIMIT 1', 
                          rule_record.metric_name, rule_record.metric_name)
            INTO latest_metric;
            
        ELSIF rule_record.metric_type = 'database' THEN
            EXECUTE format('SELECT %I as metric_value, timestamp FROM database_performance_metrics 
                           WHERE %I IS NOT NULL ORDER BY timestamp DESC LIMIT 1', 
                          rule_record.metric_name, rule_record.metric_name)
            INTO latest_metric;
            
        ELSIF rule_record.metric_type = 'application' THEN
            EXECUTE format('SELECT %I as metric_value, timestamp FROM application_performance_metrics 
                           WHERE %I IS NOT NULL ORDER BY timestamp DESC LIMIT 1', 
                          rule_record.metric_name, rule_record.metric_name)
            INTO latest_metric;
            
        END IF;
        
        -- Check if metric exceeds thresholds
        IF latest_metric.metric_value IS NOT NULL THEN
            alert_triggered := FALSE;
            
            -- Check critical threshold
            IF rule_record.critical_threshold IS NOT NULL THEN
                EXECUTE format('SELECT %s %s %s', 
                              latest_metric.metric_value, 
                              rule_record.comparison_operator, 
                              rule_record.critical_threshold)
                INTO alert_triggered;
                
                IF alert_triggered THEN
                    -- Create critical alert
                    INSERT INTO monitoring_alerts (
                        rule_id, alert_level, metric_value, threshold_value, metric_timestamp
                    ) VALUES (
                        rule_record.id, 'critical', latest_metric.metric_value, 
                        rule_record.critical_threshold, latest_metric.timestamp
                    );
                    alerts_created := alerts_created + 1;
                END IF;
            END IF;
            
            -- Check warning threshold if no critical alert
            IF NOT alert_triggered AND rule_record.warning_threshold IS NOT NULL THEN
                EXECUTE format('SELECT %s %s %s', 
                              latest_metric.metric_value, 
                              rule_record.comparison_operator, 
                              rule_record.warning_threshold)
                INTO alert_triggered;
                
                IF alert_triggered THEN
                    -- Create warning alert
                    INSERT INTO monitoring_alerts (
                        rule_id, alert_level, metric_value, threshold_value, metric_timestamp
                    ) VALUES (
                        rule_record.id, 'warning', latest_metric.metric_value, 
                        rule_record.warning_threshold, latest_metric.timestamp
                    );
                    alerts_created := alerts_created + 1;
                END IF;
            END IF;
        END IF;
    END LOOP;
    
    RETURN alerts_created;
    
EXCEPTION WHEN OTHERS THEN
    -- Log error
    INSERT INTO data_access_log (action_type, resource_type, legal_basis, search_criteria)
    VALUES ('alert_evaluation_error', 'monitoring_alerts', 'system_administration', SQLERRM);
    
    RETURN 0;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old monitoring data (LGPD compliance)
CREATE OR REPLACE FUNCTION cleanup_monitoring_data()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER := 0;
    temp_count INTEGER;
BEGIN
    -- Clean system metrics older than 90 days
    DELETE FROM system_health_metrics 
    WHERE timestamp < (CURRENT_TIMESTAMP - INTERVAL '90 days');
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean database metrics older than 90 days
    DELETE FROM database_performance_metrics 
    WHERE timestamp < (CURRENT_TIMESTAMP - INTERVAL '90 days');
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean application metrics older than 90 days
    DELETE FROM application_performance_metrics 
    WHERE timestamp < (CURRENT_TIMESTAMP - INTERVAL '90 days');
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean user activity metrics older than 1 year (aggregated data)
    DELETE FROM user_activity_metrics 
    WHERE timestamp < (CURRENT_TIMESTAMP - INTERVAL '1 year');
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Clean resolved alerts older than 30 days
    DELETE FROM monitoring_alerts 
    WHERE alert_status = 'resolved' 
    AND resolved_at < (CURRENT_TIMESTAMP - INTERVAL '30 days');
    GET DIAGNOSTICS temp_count = ROW_COUNT;
    deleted_count := deleted_count + temp_count;
    
    -- Log cleanup activity
    INSERT INTO data_access_log (action_type, resource_type, legal_basis, search_criteria)
    VALUES ('cleanup', 'monitoring_data', 'data_retention_policy', 
            'Cleaned ' || deleted_count || ' monitoring records');
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON TABLE system_health_metrics IS 'Real-time system health monitoring for Railway deployment';
COMMENT ON TABLE database_performance_metrics IS 'PostgreSQL performance monitoring and optimization metrics';
COMMENT ON TABLE application_performance_metrics IS 'R/Shiny application performance and user experience metrics';
COMMENT ON TABLE user_activity_metrics IS 'LGPD-compliant anonymized user activity analytics';
COMMENT ON TABLE monitoring_alert_rules IS 'Configurable alert rules for proactive monitoring';
COMMENT ON TABLE monitoring_alerts IS 'Alert history and incident tracking';
COMMENT ON TABLE cache_performance_metrics IS 'Redis cache performance and efficiency monitoring';

-- Grant permissions to monitoring functions
GRANT EXECUTE ON FUNCTION collect_system_health_metrics() TO PUBLIC;
GRANT EXECUTE ON FUNCTION evaluate_alert_rules() TO PUBLIC;
GRANT EXECUTE ON FUNCTION cleanup_monitoring_data() TO PUBLIC;