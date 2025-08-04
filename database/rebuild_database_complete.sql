-- COMPLETE DATABASE REBUILD WITH CATEGORIZED DATA
-- This script completely rebuilds the database with the fixed categorized dataset

-- =============================================================================
-- STEP 1: CLEAN SLATE - DROP ALL EXISTING TABLES AND VIEWS
-- =============================================================================

-- Drop all views first (to avoid dependency issues)
DROP VIEW IF EXISTS documents_view CASCADE;
DROP VIEW IF EXISTS documents_summary CASCADE;
DROP VIEW IF EXISTS documents_by_category CASCADE;
DROP VIEW IF EXISTS documents_by_state CASCADE;
DROP VIEW IF EXISTS documents_by_transport CASCADE;
DROP VIEW IF EXISTS lexml_dashboard_view CASCADE;
DROP VIEW IF EXISTS dashboard_metrics CASCADE;

-- Drop all tables and views with CASCADE to handle dependencies
DROP TABLE IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS document_categories CASCADE;
DROP TABLE IF EXISTS transport_modes CASCADE;
DROP TABLE IF EXISTS jurisdictions CASCADE;

-- Drop sequences if they exist
DROP SEQUENCE IF EXISTS documents_id_seq CASCADE;

-- =============================================================================
-- STEP 2: CREATE OPTIMIZED SCHEMA FOR CATEGORIZED DATA
-- =============================================================================

-- Create categories lookup table
CREATE TABLE document_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert known categories
INSERT INTO document_categories (name, description) VALUES
('Jurisprudência', 'Court decisions, case law, and judicial precedents'),
('Legislação', 'Laws, decrees, ordinances, and regulatory texts'),
('Doutrina', 'Legal doctrine, academic writings, and scholarly articles'),
('Outros', 'Other types of legal documents'),
('Proposições', 'Legislative proposals, bills, and draft legislation'),
('geral', 'General legal documents');

-- Create transport modes lookup table
CREATE TABLE transport_modes (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert known transport modes
INSERT INTO transport_modes (name, description) VALUES
('Geral', 'General transport or not transport-specific'),
('Rodoviário', 'Road transport related documents'),
('Aéreo', 'Aviation and air transport related documents'),
('Marítimo', 'Maritime and water transport related documents'),
('Ferroviário', 'Railway and rail transport related documents');

-- Create jurisdictions lookup table
CREATE TABLE jurisdictions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    type VARCHAR(20) CHECK (type IN ('Federal', 'State', 'Municipal', 'Distrital')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert known jurisdictions
INSERT INTO jurisdictions (name, type) VALUES
('Federal', 'Federal'),
('Municipal', 'Municipal'),
('State', 'State'),
('Distrital', 'Distrital');

-- Create main documents table with optimized structure
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    
    -- Core document identification
    titulo TEXT NOT NULL,
    urn VARCHAR(500),
    url TEXT,
    numero VARCHAR(200),
    
    -- Content and metadata
    ementa TEXT,
    assuntos TEXT,
    autor VARCHAR(500),
    tipo VARCHAR(200),
    
    -- Dates
    data DATE,
    data_publicacao DATE,
    data_coleta DATE,
    ano INTEGER,
    
    -- Classification (using lookup tables)
    category_id INTEGER REFERENCES document_categories(id),
    transport_mode_id INTEGER REFERENCES transport_modes(id),
    jurisdiction_id INTEGER REFERENCES jurisdictions(id),
    
    -- Original category fields (for reference)
    categoria_original VARCHAR(200),
    modal_original VARCHAR(200),
    jurisdicao_original VARCHAR(200),
    
    -- Geographic information
    pais VARCHAR(100),
    estado VARCHAR(100),
    municipio VARCHAR(200),
    localidade VARCHAR(300),
    
    -- Additional metadata
    classificacao TEXT,
    autoridade VARCHAR(300),
    fontes_localizacao TEXT,
    termo_busca VARCHAR(200),
    origem VARCHAR(200),
    
    -- Deduplication metadata
    deduplication_source VARCHAR(20) DEFAULT 'single',
    original_count INTEGER DEFAULT 1,
    merged_categories INTEGER,
    merged_transport INTEGER,
    source_file VARCHAR(500),
    
    -- Extracted categories (from fixed processing)
    extracted_category VARCHAR(200),
    extracted_transport_mode VARCHAR(200),
    
    -- Audit fields
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- STEP 3: CREATE INDEXES FOR PERFORMANCE
-- =============================================================================

-- Primary indexes for fast lookups
CREATE INDEX idx_documents_category ON documents(category_id);
CREATE INDEX idx_documents_transport ON documents(transport_mode_id);
CREATE INDEX idx_documents_jurisdiction ON documents(jurisdiction_id);
CREATE INDEX idx_documents_estado ON documents(estado);
CREATE INDEX idx_documents_ano ON documents(ano);
CREATE INDEX idx_documents_data ON documents(data);

-- Text search indexes
CREATE INDEX idx_documents_titulo ON documents USING gin(to_tsvector('portuguese', titulo));
CREATE INDEX idx_documents_ementa ON documents USING gin(to_tsvector('portuguese', ementa));

-- Unique constraint for URN when not null
CREATE UNIQUE INDEX idx_documents_urn_unique ON documents(urn) WHERE urn IS NOT NULL AND urn != '';

-- Composite indexes for dashboard queries
CREATE INDEX idx_documents_category_estado ON documents(category_id, estado);
CREATE INDEX idx_documents_transport_estado ON documents(transport_mode_id, estado);
CREATE INDEX idx_documents_ano_category ON documents(ano, category_id);

-- =============================================================================
-- STEP 4: CREATE DASHBOARD VIEWS
-- =============================================================================

-- Main dashboard summary view
CREATE OR REPLACE VIEW lexml_dashboard_view AS
SELECT 
    d.id,
    d.titulo,
    d.urn,
    d.url,
    d.ementa,
    d.data,
    d.ano,
    d.estado,
    d.municipio,
    dc.name as categoria,
    tm.name as modal,
    j.name as jurisdicao,
    d.extracted_category,
    d.extracted_transport_mode,
    d.deduplication_source,
    d.original_count
FROM documents d
LEFT JOIN document_categories dc ON d.category_id = dc.id
LEFT JOIN transport_modes tm ON d.transport_mode_id = tm.id
LEFT JOIN jurisdictions j ON d.jurisdiction_id = j.id;

-- Documents by category view
CREATE OR REPLACE VIEW documents_by_category AS
SELECT 
    dc.name as categoria,
    dc.description,
    COUNT(*) as total_documents,
    COUNT(DISTINCT d.estado) as states_covered,
    MIN(d.ano) as earliest_year,
    MAX(d.ano) as latest_year,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
FROM documents d
LEFT JOIN document_categories dc ON d.category_id = dc.id
GROUP BY dc.id, dc.name, dc.description
ORDER BY total_documents DESC;

-- Documents by state view
CREATE OR REPLACE VIEW documents_by_state AS
SELECT 
    d.estado,
    COUNT(*) as total_documents,
    COUNT(DISTINCT dc.name) as categories_covered,
    COUNT(DISTINCT tm.name) as transport_modes_covered,
    MIN(d.ano) as earliest_year,
    MAX(d.ano) as latest_year
FROM documents d
LEFT JOIN document_categories dc ON d.category_id = dc.id
LEFT JOIN transport_modes tm ON d.transport_mode_id = tm.id
WHERE d.estado IS NOT NULL AND d.estado != ''
GROUP BY d.estado
ORDER BY total_documents DESC;

-- Documents by transport mode view
CREATE OR REPLACE VIEW documents_by_transport AS
SELECT 
    tm.name as modal,
    tm.description,
    COUNT(*) as total_documents,
    COUNT(DISTINCT d.estado) as states_covered,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
FROM documents d
LEFT JOIN transport_modes tm ON d.transport_mode_id = tm.id
GROUP BY tm.id, tm.name, tm.description
ORDER BY total_documents DESC;

-- Comprehensive dashboard metrics view
CREATE OR REPLACE VIEW dashboard_metrics AS
SELECT 
    (SELECT COUNT(*) FROM documents) as total_documents,
    (SELECT COUNT(DISTINCT estado) FROM documents WHERE estado IS NOT NULL AND estado != '' AND estado != 'Federal') as states_with_documents,
    (SELECT COUNT(DISTINCT category_id) FROM documents WHERE category_id IS NOT NULL) as total_categories,
    (SELECT COUNT(DISTINCT transport_mode_id) FROM documents WHERE transport_mode_id IS NOT NULL) as total_transport_modes,
    (SELECT MIN(ano) FROM documents WHERE ano IS NOT NULL) as earliest_year,
    (SELECT MAX(ano) FROM documents WHERE ano IS NOT NULL) as latest_year,
    (SELECT COUNT(*) FROM documents WHERE deduplication_source = 'merged') as merged_documents,
    (SELECT COUNT(*) FROM documents WHERE deduplication_source = 'single') as single_documents,
    CURRENT_TIMESTAMP as last_updated;

-- =============================================================================
-- STEP 5: CREATE HELPER FUNCTIONS
-- =============================================================================

-- Function to get category ID by name
CREATE OR REPLACE FUNCTION get_category_id(category_name TEXT)
RETURNS INTEGER AS $$
DECLARE
    cat_id INTEGER;
BEGIN
    SELECT id INTO cat_id FROM document_categories WHERE name = category_name;
    IF cat_id IS NULL THEN
        INSERT INTO document_categories (name) VALUES (category_name) RETURNING id INTO cat_id;
    END IF;
    RETURN cat_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get transport mode ID by name
CREATE OR REPLACE FUNCTION get_transport_id(transport_name TEXT)
RETURNS INTEGER AS $$
DECLARE
    trans_id INTEGER;
BEGIN
    SELECT id INTO trans_id FROM transport_modes WHERE name = transport_name;
    IF trans_id IS NULL THEN
        INSERT INTO transport_modes (name) VALUES (transport_name) RETURNING id INTO trans_id;
    END IF;
    RETURN trans_id;
END;
$$ LANGUAGE plpgsql;

-- Function to get jurisdiction ID by name
CREATE OR REPLACE FUNCTION get_jurisdiction_id(jurisdiction_name TEXT)
RETURNS INTEGER AS $$
DECLARE
    juris_id INTEGER;
BEGIN
    SELECT id INTO juris_id FROM jurisdictions WHERE name = jurisdiction_name;
    IF juris_id IS NULL THEN
        INSERT INTO jurisdictions (name) VALUES (jurisdiction_name) RETURNING id INTO juris_id;
    END IF;
    RETURN juris_id;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- STEP 6: CREATE SUMMARY AND VERIFICATION QUERIES
-- =============================================================================

-- Summary of database structure
SELECT 'Database rebuild completed!' as status;

-- Show table sizes
SELECT 
    schemaname,
    tablename,
    attname as column_name,
    n_distinct,
    correlation
FROM pg_stats 
WHERE schemaname = 'public' 
AND tablename IN ('documents', 'document_categories', 'transport_modes', 'jurisdictions')
ORDER BY tablename, attname;

-- Show created indexes
SELECT 
    indexname,
    tablename,
    indexdef
FROM pg_indexes 
WHERE schemaname = 'public' 
AND tablename IN ('documents', 'document_categories', 'transport_modes', 'jurisdictions');

COMMIT;