-- Migration 003: Enhanced URN Parsing Integration
-- Adds parsed URN components to support both legislation and jurisprudence data

-- Add new columns to private_legislative_documents table for parsed URN components
ALTER TABLE private_legislative_documents 
ADD COLUMN IF NOT EXISTS urn_type VARCHAR(20) DEFAULT 'legislation',
ADD COLUMN IF NOT EXISTS country VARCHAR(100),
ADD COLUMN IF NOT EXISTS state_parsed VARCHAR(100),
ADD COLUMN IF NOT EXISTS municipality_parsed VARCHAR(200), 
ADD COLUMN IF NOT EXISTS justice_type VARCHAR(200),
ADD COLUMN IF NOT EXISTS judicial_region VARCHAR(100),
ADD COLUMN IF NOT EXISTS court_class VARCHAR(300),
ADD COLUMN IF NOT EXISTS document_type_full VARCHAR(300),
ADD COLUMN IF NOT EXISTS promulgation_date DATE,
ADD COLUMN IF NOT EXISTS publication_date_parsed DATE,
ADD COLUMN IF NOT EXISTS document_description TEXT,
ADD COLUMN IF NOT EXISTS urn_parsing_version VARCHAR(10) DEFAULT '1.0';

-- Create index for URN type filtering
CREATE INDEX IF NOT EXISTS idx_docs_urn_type ON private_legislative_documents(urn_type);

-- Create index for justice type filtering (jurisprudence)
CREATE INDEX IF NOT EXISTS idx_docs_justice_type ON private_legislative_documents(justice_type);

-- Create index for judicial region filtering
CREATE INDEX IF NOT EXISTS idx_docs_judicial_region ON private_legislative_documents(judicial_region);

-- Create index for parsed state and municipality
CREATE INDEX IF NOT EXISTS idx_docs_state_parsed ON private_legislative_documents(state_parsed);
CREATE INDEX IF NOT EXISTS idx_docs_municipality_parsed ON private_legislative_documents(municipality_parsed);

-- Create composite index for legislation vs jurisprudence analysis
CREATE INDEX IF NOT EXISTS idx_docs_type_analysis ON private_legislative_documents(urn_type, document_type, geographic_level);

-- Create table for URN parsing statistics and analytics
CREATE TABLE IF NOT EXISTS urn_parsing_analytics (
    id SERIAL PRIMARY KEY,
    analysis_date DATE DEFAULT CURRENT_DATE,
    
    -- Legislation statistics
    total_legislation_docs INTEGER DEFAULT 0,
    legislation_by_state JSONB,
    legislation_by_type JSONB,
    legislation_by_geographic_level JSONB,
    
    -- Jurisprudence statistics  
    total_jurisprudence_docs INTEGER DEFAULT 0,
    jurisprudence_by_justice_type JSONB,
    jurisprudence_by_region JSONB,
    jurisprudence_by_court_class JSONB,
    
    -- Temporal analysis
    legislation_by_year JSONB,
    jurisprudence_by_year JSONB,
    
    -- Quality metrics
    parsing_success_rate DECIMAL(5,2),
    unparsed_urns_count INTEGER DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(analysis_date)
);

-- Create function to update URN parsing analytics
CREATE OR REPLACE FUNCTION update_urn_parsing_analytics()
RETURNS void AS $$
BEGIN
    -- Insert or update analytics for today
    INSERT INTO urn_parsing_analytics (
        analysis_date,
        total_legislation_docs,
        total_jurisprudence_docs,
        legislation_by_state,
        legislation_by_type,
        jurisprudence_by_justice_type,
        jurisprudence_by_region,
        parsing_success_rate,
        unparsed_urns_count
    )
    VALUES (
        CURRENT_DATE,
        (SELECT COUNT(*) FROM private_legislative_documents WHERE urn_type = 'legislation'),
        (SELECT COUNT(*) FROM private_legislative_documents WHERE urn_type = 'jurisprudence'),
        (SELECT jsonb_object_agg(state_parsed, doc_count) 
         FROM (SELECT state_parsed, COUNT(*) as doc_count 
               FROM private_legislative_documents 
               WHERE urn_type = 'legislation' AND state_parsed IS NOT NULL 
               GROUP BY state_parsed) sub),
        (SELECT jsonb_object_agg(document_type, doc_count)
         FROM (SELECT document_type, COUNT(*) as doc_count
               FROM private_legislative_documents
               WHERE urn_type = 'legislation' AND document_type IS NOT NULL
               GROUP BY document_type) sub),
        (SELECT jsonb_object_agg(justice_type, doc_count)
         FROM (SELECT justice_type, COUNT(*) as doc_count
               FROM private_legislative_documents
               WHERE urn_type = 'jurisprudence' AND justice_type IS NOT NULL
               GROUP BY justice_type) sub),
        (SELECT jsonb_object_agg(judicial_region, doc_count)
         FROM (SELECT judicial_region, COUNT(*) as doc_count
               FROM private_legislative_documents
               WHERE urn_type = 'jurisprudence' AND judicial_region IS NOT NULL
               GROUP BY judicial_region) sub),
        (SELECT ROUND(
            (COUNT(*) FILTER (WHERE urn_type IS NOT NULL) * 100.0 / NULLIF(COUNT(*), 0)), 2)
         FROM private_legislative_documents),
        (SELECT COUNT(*) FROM private_legislative_documents WHERE urn_type IS NULL)
    )
    ON CONFLICT (analysis_date) 
    DO UPDATE SET
        total_legislation_docs = EXCLUDED.total_legislation_docs,
        total_jurisprudence_docs = EXCLUDED.total_jurisprudence_docs,
        legislation_by_state = EXCLUDED.legislation_by_state,
        legislation_by_type = EXCLUDED.legislation_by_type,
        jurisprudence_by_justice_type = EXCLUDED.jurisprudence_by_justice_type,
        jurisprudence_by_region = EXCLUDED.jurisprudence_by_region,
        parsing_success_rate = EXCLUDED.parsing_success_rate,
        unparsed_urns_count = EXCLUDED.unparsed_urns_count,
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- Create table for tracking URN parsing performance over time
CREATE TABLE IF NOT EXISTS urn_parsing_performance (
    id SERIAL PRIMARY KEY,
    batch_id UUID,
    records_processed INTEGER,
    records_successfully_parsed INTEGER,
    average_parsing_time_ms DECIMAL(10,2),
    errors_count INTEGER,
    error_details JSONB,
    processing_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Update the search vector function to include new parsed fields
CREATE OR REPLACE FUNCTION update_document_search_vector()
RETURNS trigger AS $$
BEGIN
    NEW.search_vector := 
        setweight(to_tsvector('portuguese', COALESCE(NEW.title, '')), 'A') ||
        setweight(to_tsvector('portuguese', COALESCE(NEW.description, '')), 'B') ||
        setweight(to_tsvector('portuguese', COALESCE(NEW.document_description, '')), 'B') ||
        setweight(to_tsvector('portuguese', array_to_string(NEW.subject_keywords, ' ')), 'C') ||
        setweight(to_tsvector('portuguese', COALESCE(NEW.state_parsed, '')), 'D') ||
        setweight(to_tsvector('portuguese', COALESCE(NEW.municipality_parsed, '')), 'D') ||
        setweight(to_tsvector('portuguese', COALESCE(NEW.justice_type, '')), 'D') ||
        setweight(to_tsvector('portuguese', COALESCE(NEW.court_class, '')), 'D');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Add comments for new columns
COMMENT ON COLUMN private_legislative_documents.urn_type IS 'Type of URN: legislation or jurisprudence';
COMMENT ON COLUMN private_legislative_documents.country IS 'Country extracted from URN (typically Brasil)';
COMMENT ON COLUMN private_legislative_documents.state_parsed IS 'State name parsed from URN (for legislation)';
COMMENT ON COLUMN private_legislative_documents.municipality_parsed IS 'Municipality name parsed from URN (for legislation)';
COMMENT ON COLUMN private_legislative_documents.justice_type IS 'Type of justice system (for jurisprudence): Justiça do Trabalho, Federal, etc.';
COMMENT ON COLUMN private_legislative_documents.judicial_region IS 'Judicial region (for jurisprudence): 1ª região, 2ª região, etc.';
COMMENT ON COLUMN private_legislative_documents.court_class IS 'Court and class information (for jurisprudence): tribunal + turma';
COMMENT ON COLUMN private_legislative_documents.document_type_full IS 'Full document type with region and number';
COMMENT ON COLUMN private_legislative_documents.promulgation_date IS 'Promulgation date for legislation';
COMMENT ON COLUMN private_legislative_documents.publication_date_parsed IS 'Publication date for jurisprudence';
COMMENT ON COLUMN private_legislative_documents.document_description IS 'Human-readable description generated from parsed URN';
COMMENT ON COLUMN private_legislative_documents.urn_parsing_version IS 'Version of URN parsing algorithm used';

COMMENT ON TABLE urn_parsing_analytics IS 'Daily analytics for URN parsing results and statistics';
COMMENT ON TABLE urn_parsing_performance IS 'Performance metrics for URN parsing operations';

-- Create views for easier data analysis
CREATE OR REPLACE VIEW legislation_summary AS
SELECT 
    state_parsed,
    municipality_parsed,
    document_type,
    geographic_level,
    COUNT(*) as document_count,
    MIN(promulgation_date) as earliest_document,
    MAX(promulgation_date) as latest_document,
    AVG(EXTRACT(EPOCH FROM (NOW() - promulgation_date))/86400) as avg_days_since_promulgation
FROM private_legislative_documents 
WHERE urn_type = 'legislation'
GROUP BY state_parsed, municipality_parsed, document_type, geographic_level;

CREATE OR REPLACE VIEW jurisprudence_summary AS
SELECT
    justice_type,
    judicial_region,
    document_type,
    COUNT(*) as decision_count,
    MIN(publication_date_parsed) as earliest_decision,
    MAX(publication_date_parsed) as latest_decision,
    AVG(EXTRACT(EPOCH FROM (NOW() - publication_date_parsed))/86400) as avg_days_since_publication
FROM private_legislative_documents
WHERE urn_type = 'jurisprudence'
GROUP BY justice_type, judicial_region, document_type;

-- Create indexes on the views for better performance
CREATE INDEX IF NOT EXISTS idx_docs_promulgation_date ON private_legislative_documents(promulgation_date);
CREATE INDEX IF NOT EXISTS idx_docs_publication_date_parsed ON private_legislative_documents(publication_date_parsed);

-- Initial analytics population
SELECT update_urn_parsing_analytics(); 