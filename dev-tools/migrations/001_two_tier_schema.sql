-- Monitor Legislativo v4 - Two-Tier Architecture Schema
-- Extends existing schema with collection and analytics tables

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For similarity search
CREATE EXTENSION IF NOT EXISTS "unaccent"; -- For Portuguese text search

-- Search terms management for automated collection
CREATE TABLE IF NOT EXISTS search_terms (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4(),
    term VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    cql_query TEXT,
    description TEXT,
    active BOOLEAN DEFAULT true,
    collection_frequency VARCHAR(20) DEFAULT 'monthly', -- daily, weekly, monthly, custom
    priority INTEGER DEFAULT 1, -- 1=highest, 5=lowest
    next_collection TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),
    updated_by VARCHAR(100),
    
    CONSTRAINT valid_frequency CHECK (collection_frequency IN ('daily', 'weekly', 'monthly', 'custom')),
    CONSTRAINT valid_priority CHECK (priority BETWEEN 1 AND 5)
);

-- Enhanced legislative documents table
CREATE TABLE IF NOT EXISTS legislative_documents (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4(),
    urn VARCHAR(500) UNIQUE NOT NULL, -- URN:LEX identifier
    document_type VARCHAR(100) NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    summary TEXT,
    metadata JSONB,
    search_term_id INTEGER REFERENCES search_terms(id),
    source_api VARCHAR(50), -- lexml, camara, senado, etc.
    language VARCHAR(10) DEFAULT 'pt-BR',
    
    -- Temporal information
    document_date DATE,
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    published_at TIMESTAMP WITH TIME ZONE,
    
    -- Academic and research fields
    citation_count INTEGER DEFAULT 0,
    academic_relevance_score NUMERIC(5,2),
    keywords TEXT[], -- Array of extracted keywords
    
    -- Quality and validation
    validation_status VARCHAR(20) DEFAULT 'pending', -- pending, validated, rejected
    validation_notes TEXT,
    validated_by VARCHAR(100),
    validated_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_validation_status CHECK (validation_status IN ('pending', 'validated', 'rejected'))
);

-- Document versions for change tracking
CREATE TABLE IF NOT EXISTS document_versions (
    id BIGSERIAL PRIMARY KEY,
    document_id BIGINT REFERENCES legislative_documents(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    content TEXT,
    metadata JSONB,
    changes JSONB, -- Detailed change information
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),
    
    UNIQUE(document_id, version_number)
);

-- Collection execution logs
CREATE TABLE IF NOT EXISTS collection_logs (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4(),
    search_term_id INTEGER REFERENCES search_terms(id),
    collection_type VARCHAR(50), -- scheduled, manual, retry
    status VARCHAR(50) NOT NULL, -- running, completed, failed, timeout
    
    -- Execution details
    records_collected INTEGER DEFAULT 0,
    records_new INTEGER DEFAULT 0,
    records_updated INTEGER DEFAULT 0,
    records_skipped INTEGER DEFAULT 0,
    execution_time_ms INTEGER,
    
    -- Error handling
    error_message TEXT,
    error_type VARCHAR(100),
    retry_count INTEGER DEFAULT 0,
    
    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    
    -- API response details
    api_response_size INTEGER,
    api_response_time_ms INTEGER,
    api_rate_limit_remaining INTEGER,
    
    CONSTRAINT valid_status CHECK (status IN ('running', 'completed', 'failed', 'timeout'))
);

-- Performance and analytics tracking
CREATE TABLE IF NOT EXISTS search_analytics (
    id BIGSERIAL PRIMARY KEY,
    query_hash VARCHAR(64) NOT NULL,
    query_params JSONB,
    result_count INTEGER,
    execution_time_ms INTEGER,
    cache_hit BOOLEAN DEFAULT false,
    user_session_id VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- User behavior tracking
    results_clicked INTEGER DEFAULT 0,
    results_exported BOOLEAN DEFAULT false,
    export_format VARCHAR(20),
    time_spent_ms INTEGER
);

-- Academic research datasets and exports
CREATE TABLE IF NOT EXISTS research_datasets (
    id BIGSERIAL PRIMARY KEY,
    uuid UUID DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    doi VARCHAR(100) UNIQUE, -- Digital Object Identifier
    
    -- Dataset composition
    query_criteria JSONB,
    document_count INTEGER,
    date_range DATERANGE,
    
    -- Academic metadata
    created_by_orcid VARCHAR(50), -- ORCID researcher identifier
    created_by_name VARCHAR(255),
    institution VARCHAR(255),
    license VARCHAR(100) DEFAULT 'CC BY 4.0',
    
    -- Publication status
    status VARCHAR(20) DEFAULT 'draft', -- draft, published, archived
    published_at TIMESTAMP WITH TIME ZONE,
    version VARCHAR(10) DEFAULT '1.0',
    
    -- File information
    file_path VARCHAR(500),
    file_size_bytes BIGINT,
    file_format VARCHAR(20),
    checksum VARCHAR(64),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    CONSTRAINT valid_dataset_status CHECK (status IN ('draft', 'published', 'archived'))
);

-- Performance Indexes
-- Full-text search on Portuguese content
CREATE INDEX IF NOT EXISTS idx_documents_content_search 
ON legislative_documents USING GIN (to_tsvector('portuguese', content));

CREATE INDEX IF NOT EXISTS idx_documents_title_search 
ON legislative_documents USING GIN (to_tsvector('portuguese', title));

-- URN and document type indexes
CREATE INDEX IF NOT EXISTS idx_documents_urn ON legislative_documents(urn);
CREATE INDEX IF NOT EXISTS idx_documents_type ON legislative_documents(document_type);
CREATE INDEX IF NOT EXISTS idx_documents_date ON legislative_documents(document_date);
CREATE INDEX IF NOT EXISTS idx_documents_collected ON legislative_documents(collected_at);

-- JSONB metadata indexes
CREATE INDEX IF NOT EXISTS idx_documents_metadata ON legislative_documents USING GIN (metadata);
CREATE INDEX IF NOT EXISTS idx_documents_keywords ON legislative_documents USING GIN (keywords);

-- Search terms and collection indexes
CREATE INDEX IF NOT EXISTS idx_search_terms_active ON search_terms(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_search_terms_next_collection ON search_terms(next_collection) WHERE active = true;

-- Collection logs indexes
CREATE INDEX IF NOT EXISTS idx_collection_logs_term ON collection_logs(search_term_id);
CREATE INDEX IF NOT EXISTS idx_collection_logs_status ON collection_logs(status);
CREATE INDEX IF NOT EXISTS idx_collection_logs_started ON collection_logs(started_at);

-- Analytics indexes
CREATE INDEX IF NOT EXISTS idx_search_analytics_query ON search_analytics(query_hash);
CREATE INDEX IF NOT EXISTS idx_search_analytics_created ON search_analytics(created_at);

-- Performance Views
-- Dashboard summary view (materialized for performance)
CREATE MATERIALIZED VIEW IF NOT EXISTS dashboard_summary AS
SELECT 
    COUNT(*) as total_documents,
    COUNT(*) FILTER (WHERE document_date >= CURRENT_DATE - INTERVAL '30 days') as documents_last_30_days,
    COUNT(*) FILTER (WHERE collected_at >= CURRENT_DATE - INTERVAL '7 days') as new_documents_week,
    COUNT(DISTINCT document_type) as document_types,
    COUNT(DISTINCT source_api) as active_sources,
    AVG(academic_relevance_score) as avg_relevance_score,
    MAX(collected_at) as last_collection,
    COUNT(*) FILTER (WHERE validation_status = 'validated') as validated_documents,
    COUNT(*) FILTER (WHERE validation_status = 'pending') as pending_validation
FROM legislative_documents;

-- Collection performance view
CREATE MATERIALIZED VIEW IF NOT EXISTS collection_performance AS
SELECT 
    st.term,
    st.category,
    COUNT(cl.*) as total_collections,
    COUNT(*) FILTER (WHERE cl.status = 'completed') as successful_collections,
    COUNT(*) FILTER (WHERE cl.status = 'failed') as failed_collections,
    AVG(cl.execution_time_ms) as avg_execution_time,
    SUM(cl.records_collected) as total_records_collected,
    MAX(cl.completed_at) as last_collection
FROM search_terms st
LEFT JOIN collection_logs cl ON st.id = cl.search_term_id
WHERE st.active = true
GROUP BY st.id, st.term, st.category;

-- Search analytics view
CREATE MATERIALIZED VIEW IF NOT EXISTS search_patterns AS
SELECT 
    query_hash,
    COUNT(*) as query_frequency,
    AVG(result_count) as avg_results,
    AVG(execution_time_ms) as avg_execution_time,
    SUM(results_clicked) as total_clicks,
    COUNT(*) FILTER (WHERE cache_hit = true) as cache_hits,
    COUNT(*) FILTER (WHERE results_exported = true) as exports
FROM search_analytics 
WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY query_hash
ORDER BY query_frequency DESC;

-- Triggers for automatic updates
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply update triggers
CREATE TRIGGER update_search_terms_modtime 
    BEFORE UPDATE ON search_terms 
    FOR EACH ROW EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_documents_modtime 
    BEFORE UPDATE ON legislative_documents 
    FOR EACH ROW EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_datasets_modtime 
    BEFORE UPDATE ON research_datasets 
    FOR EACH ROW EXECUTE FUNCTION update_modified_column();

-- Function to refresh materialized views
CREATE OR REPLACE FUNCTION refresh_analytics_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW dashboard_summary;
    REFRESH MATERIALIZED VIEW collection_performance;
    REFRESH MATERIALIZED VIEW search_patterns;
END;
$$ LANGUAGE plpgsql;

-- Insert sample search terms for development
INSERT INTO search_terms (term, category, cql_query, description, collection_frequency, priority) VALUES
('transporte urbano', 'Transport', 'title any "transporte urbano" OR subject any "mobilidade urbana"', 'Urban transportation and mobility legislation', 'weekly', 1),
('mobilidade sustentável', 'Environment', 'title any "mobilidade sustentável" OR subject any "transporte verde"', 'Sustainable mobility and green transportation', 'monthly', 2),
('transporte público', 'Public Policy', 'title any "transporte público" OR subject any "ônibus" OR subject any "metrô"', 'Public transportation systems', 'weekly', 1),
('infraestrutura viária', 'Infrastructure', 'title any "infraestrutura" AND (subject any "rodovia" OR subject any "estrada")', 'Road infrastructure legislation', 'monthly', 3),
('regulamentação ANTT', 'Regulatory', 'autoridade exact "ANTT" OR subject any "agência nacional de transportes"', 'ANTT regulatory framework', 'daily', 1)
ON CONFLICT DO NOTHING;

COMMENT ON TABLE search_terms IS 'Configuration for automated legislative data collection';
COMMENT ON TABLE legislative_documents IS 'Main repository for collected legislative documents with academic metadata';
COMMENT ON TABLE collection_logs IS 'Audit trail for all data collection activities';
COMMENT ON TABLE search_analytics IS 'User search behavior and performance analytics';
COMMENT ON TABLE research_datasets IS 'Academic research datasets with DOI and citation support';