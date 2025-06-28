-- Migration for Periodic LexML Collection System
-- Creates tables for private legislative document database

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "unaccent";

-- Search terms configuration for automated collection
CREATE TABLE IF NOT EXISTS search_terms_config (
    id SERIAL PRIMARY KEY,
    term_name VARCHAR(255) NOT NULL UNIQUE,
    cql_query TEXT NOT NULL,
    description TEXT,
    collection_frequency VARCHAR(20) DEFAULT 'monthly',
    is_active BOOLEAN DEFAULT true,
    priority_level INTEGER DEFAULT 5,
    last_collected TIMESTAMP WITH TIME ZONE,
    next_collection TIMESTAMP WITH TIME ZONE,
    total_documents_collected INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Private legislative documents repository
CREATE TABLE IF NOT EXISTS private_legislative_documents (
    id BIGSERIAL PRIMARY KEY,
    urn VARCHAR(500) UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    document_type VARCHAR(100),
    authority VARCHAR(200),
    locality VARCHAR(200),
    event_type VARCHAR(100),
    event_date DATE,
    publication_date DATE,
    subject_keywords TEXT[],
    full_text_url TEXT,
    source_url TEXT,
    
    -- Collection metadata
    search_term_id INTEGER REFERENCES search_terms_config(id),
    collected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    collection_batch_id UUID,
    
    -- Document analysis
    word_count INTEGER,
    page_count INTEGER,
    language VARCHAR(10) DEFAULT 'pt',
    
    -- State/location analysis for density mapping
    state_code VARCHAR(2),
    state_name VARCHAR(100),
    municipality VARCHAR(200),
    geographic_level VARCHAR(20), -- federal, estadual, municipal
    
    -- Search optimization
    search_vector tsvector,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Collection execution logs
CREATE TABLE IF NOT EXISTS collection_executions (
    id BIGSERIAL PRIMARY KEY,
    batch_id UUID DEFAULT uuid_generate_v4(),
    search_term_id INTEGER REFERENCES search_terms_config(id),
    execution_type VARCHAR(50) DEFAULT 'scheduled', -- scheduled, manual, retry
    status VARCHAR(50) NOT NULL, -- running, completed, failed, partial
    
    -- Execution metrics
    documents_found INTEGER DEFAULT 0,
    documents_new INTEGER DEFAULT 0,
    documents_updated INTEGER DEFAULT 0,
    documents_skipped INTEGER DEFAULT 0,
    
    -- Performance metrics
    execution_time_seconds INTEGER,
    api_calls_made INTEGER,
    api_response_time_avg INTEGER,
    
    -- Error handling
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    
    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    
    CONSTRAINT valid_status CHECK (status IN ('running', 'completed', 'failed', 'partial'))
);

-- Document state density analytics
CREATE TABLE IF NOT EXISTS state_document_density (
    id SERIAL PRIMARY KEY,
    state_code VARCHAR(2) NOT NULL,
    state_name VARCHAR(100) NOT NULL,
    total_documents INTEGER DEFAULT 0,
    documents_last_month INTEGER DEFAULT 0,
    documents_last_year INTEGER DEFAULT 0,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(state_code)
);

-- User search analytics (for dashboard usage)
CREATE TABLE IF NOT EXISTS private_search_analytics (
    id BIGSERIAL PRIMARY KEY,
    search_query TEXT,
    search_filters JSONB,
    results_count INTEGER,
    execution_time_ms INTEGER,
    user_session VARCHAR(100),
    search_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create performance indexes
CREATE INDEX IF NOT EXISTS idx_docs_urn ON private_legislative_documents(urn);
CREATE INDEX IF NOT EXISTS idx_docs_state ON private_legislative_documents(state_code);
CREATE INDEX IF NOT EXISTS idx_docs_type ON private_legislative_documents(document_type);
CREATE INDEX IF NOT EXISTS idx_docs_authority ON private_legislative_documents(authority);
CREATE INDEX IF NOT EXISTS idx_docs_date ON private_legislative_documents(event_date);
CREATE INDEX IF NOT EXISTS idx_docs_collection ON private_legislative_documents(search_term_id, collected_at);
CREATE INDEX IF NOT EXISTS idx_docs_search ON private_legislative_documents USING GIN(search_vector);
CREATE INDEX IF NOT EXISTS idx_docs_keywords ON private_legislative_documents USING GIN(subject_keywords);

-- Geographic indexes for mapping
CREATE INDEX IF NOT EXISTS idx_docs_geo_level ON private_legislative_documents(geographic_level);
CREATE INDEX IF NOT EXISTS idx_state_density ON state_document_density(state_code);

-- Collection execution indexes
CREATE INDEX IF NOT EXISTS idx_executions_batch ON collection_executions(batch_id);
CREATE INDEX IF NOT EXISTS idx_executions_term ON collection_executions(search_term_id);
CREATE INDEX IF NOT EXISTS idx_executions_status ON collection_executions(status);
CREATE INDEX IF NOT EXISTS idx_executions_date ON collection_executions(started_at);

-- Full text search trigger function
CREATE OR REPLACE FUNCTION update_document_search_vector()
RETURNS trigger AS $$
BEGIN
    NEW.search_vector := 
        setweight(to_tsvector('portuguese', COALESCE(NEW.title, '')), 'A') ||
        setweight(to_tsvector('portuguese', COALESCE(NEW.description, '')), 'B') ||
        setweight(to_tsvector('portuguese', array_to_string(NEW.subject_keywords, ' ')), 'C');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to documents table
CREATE TRIGGER update_search_vector_trigger
    BEFORE INSERT OR UPDATE ON private_legislative_documents
    FOR EACH ROW EXECUTE FUNCTION update_document_search_vector();

-- Insert initial search terms for transport legislation
INSERT INTO search_terms_config (term_name, cql_query, description, priority_level) VALUES
('transporte_urbano', 'title any "transporte urbano" OR subject any "mobilidade urbana"', 'Urban transportation legislation', 1),
('transporte_publico', 'title any "transporte público" OR subject any "ônibus" OR subject any "metrô" OR subject any "BRT"', 'Public transportation systems', 1),
('mobilidade_sustentavel', 'title any "mobilidade sustentável" OR subject any "transporte verde" OR subject any "bicicleta"', 'Sustainable mobility legislation', 2),
('infraestrutura_viaria', 'title any "infraestrutura" AND (subject any "rodovia" OR subject any "estrada" OR subject any "ponte")', 'Road infrastructure legislation', 3),
('regulamentacao_antt', 'autoridade any "ANTT" OR subject any "agência nacional de transportes terrestres"', 'ANTT regulatory framework', 1),
('transporte_carga', 'title any "transporte" AND (subject any "carga" OR subject any "frete" OR subject any "logística")', 'Freight transportation legislation', 2),
('acessibilidade_transporte', 'title any "acessibilidade" AND subject any "transporte"', 'Transportation accessibility legislation', 2),
('seguranca_transito', 'title any "segurança" AND (subject any "trânsito" OR subject any "tráfego")', 'Traffic safety legislation', 1)
ON CONFLICT (term_name) DO NOTHING;

-- Comments for documentation
COMMENT ON TABLE search_terms_config IS 'Configuration for automated periodic collection of legislative documents';
COMMENT ON TABLE private_legislative_documents IS 'Private database of collected legislative documents from LexML';
COMMENT ON TABLE collection_executions IS 'Audit log of all collection execution attempts';
COMMENT ON TABLE state_document_density IS 'Analytics table for geographic document distribution visualization';
COMMENT ON TABLE private_search_analytics IS 'User search behavior analytics within private database'; 