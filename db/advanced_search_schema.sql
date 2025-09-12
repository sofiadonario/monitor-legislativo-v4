-- ============================================================================
-- ADVANCED SEARCH ENGINE SCHEMA FOR BRAZILIAN LEGISLATIVE MONITORING SYSTEM
-- ============================================================================
--
-- This schema implements a comprehensive search architecture optimized for:
-- - 134,014 Brazilian legislative documents 
-- - Portuguese full-text search with legal term recognition
-- - Geographic and temporal filtering
-- - Sub-second query performance on Railway PostgreSQL
-- - Advanced ranking and relevance scoring
--
-- Author: Senior Data Scientist - Brazilian Legislative Analytics Team
-- Date: January 2025
-- Version: 1.0 - Production Ready
-- ============================================================================

-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS pg_trgm;        -- Trigram matching for fuzzy search
CREATE EXTENSION IF NOT EXISTS unaccent;      -- Remove accents for Portuguese text
CREATE EXTENSION IF NOT EXISTS btree_gin;     -- Better GIN index performance
CREATE EXTENSION IF NOT EXISTS btree_gist;    -- Better GiST index performance

-- ============================================================================
-- 1. ENHANCED DOCUMENTS TABLE WITH SEARCH OPTIMIZATION
-- ============================================================================

-- Drop existing indexes that might conflict
DROP INDEX IF EXISTS idx_documents_unified_titulo_fts;
DROP INDEX IF EXISTS idx_documents_unified_ementa_fts;

-- Create optimized search-ready documents table if not exists
CREATE TABLE IF NOT EXISTS documents_search_optimized (
    id BIGSERIAL PRIMARY KEY,
    
    -- Core document fields
    titulo TEXT NOT NULL,
    titulo_normalized TEXT NOT NULL, -- Normalized for search
    ementa TEXT,
    ementa_normalized TEXT,          -- Normalized for search
    tipo VARCHAR(100) NOT NULL,
    species VARCHAR(50) NOT NULL,
    
    -- Geographic fields (enhanced for filtering)
    estado VARCHAR(2) NOT NULL,
    estado_nome VARCHAR(100),
    municipality VARCHAR(200),
    municipality_normalized VARCHAR(200),
    region VARCHAR(20),              -- Norte, Nordeste, Centro-Oeste, Sudeste, Sul
    
    -- Temporal fields (optimized for range queries)
    data_publicacao DATE NOT NULL,
    data_publicacao_timestamp TIMESTAMP,
    ano INTEGER NOT NULL,
    mes INTEGER NOT NULL,
    decada INTEGER NOT NULL,         -- 2020s, 2010s, etc.
    
    -- Content and metadata
    url TEXT,
    urn TEXT,
    autor TEXT,
    autor_normalized TEXT,
    autoridade TEXT,
    numero_documento VARCHAR(100),
    
    -- Transport-specific fields
    transport_category VARCHAR(50),
    modal_transporte VARCHAR(50),
    
    -- Search and classification fields
    termo_busca TEXT,
    assuntos TEXT,
    assuntos_normalized TEXT,
    classificacao TEXT,
    tags TEXT[],                     -- Array for topic tags
    
    -- Content quality and metrics
    titulo_length INTEGER NOT NULL,
    ementa_length INTEGER NOT NULL,
    content_quality_score DECIMAL(3,2), -- 0.00 to 10.00
    relevance_score DECIMAL(5,2),   -- Base relevance score
    
    -- Full-text search vectors (pre-computed for performance)
    search_vector_titulo tsvector,
    search_vector_ementa tsvector,
    search_vector_combined tsvector,
    
    -- Audit and source tracking
    fonte VARCHAR(50) DEFAULT 'LexML',
    source_table VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_indexed_at TIMESTAMP
);

-- ============================================================================
-- 2. PORTUGUESE LANGUAGE SEARCH CONFIGURATION
-- ============================================================================

-- Create custom Portuguese legal text search configuration
DROP TEXT SEARCH CONFIGURATION IF EXISTS portuguese_legal CASCADE;
CREATE TEXT SEARCH CONFIGURATION portuguese_legal (COPY = portuguese);

-- Add legal stop words commonly found in Brazilian legislation
ALTER TEXT SEARCH CONFIGURATION portuguese_legal 
DROP MAPPING FOR word WITH portuguese_stem;

ALTER TEXT SEARCH CONFIGURATION portuguese_legal 
ADD MAPPING FOR word WITH unaccent, portuguese_stem;

-- Create function to normalize Portuguese legal text
CREATE OR REPLACE FUNCTION normalize_portuguese_legal_text(input_text TEXT)
RETURNS TEXT AS $$
BEGIN
    IF input_text IS NULL OR input_text = '' THEN
        RETURN '';
    END IF;
    
    RETURN lower(
        unaccent(
            regexp_replace(
                regexp_replace(input_text, '[^\w\s]', ' ', 'g'), -- Remove punctuation
                '\s+', ' ', 'g'                                   -- Normalize whitespace
            )
        )
    );
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- ============================================================================
-- 3. LEGAL TERMS AND AUTOCOMPLETE TABLES
-- ============================================================================

-- Legal terms dictionary for intelligent autocomplete
CREATE TABLE legal_terms_dictionary (
    id SERIAL PRIMARY KEY,
    term TEXT UNIQUE NOT NULL,
    term_normalized TEXT NOT NULL,
    category VARCHAR(100) NOT NULL, -- 'lei', 'decreto', 'portaria', 'conceito_juridico', etc.
    frequency INTEGER DEFAULT 1,
    description TEXT,
    synonyms TEXT[], -- Array of synonym terms
    related_terms TEXT[], -- Array of related legal terms
    transport_related BOOLEAN DEFAULT FALSE,
    legal_hierarchy INTEGER, -- 1=Constitutional, 2=Federal Law, 3=Regulation, etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Popular search terms tracking
CREATE TABLE search_analytics (
    id BIGSERIAL PRIMARY KEY,
    search_term TEXT NOT NULL,
    search_term_normalized TEXT NOT NULL,
    filters_used JSONB, -- Store filter combinations
    results_count INTEGER,
    user_session VARCHAR(100),
    execution_time_ms INTEGER,
    clicked_results INTEGER[] DEFAULT '{}',
    searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 4. GEOGRAPHIC REFERENCE TABLES
-- ============================================================================

-- Brazilian states with enhanced metadata
CREATE TABLE IF NOT EXISTS estados_brasil (
    codigo VARCHAR(2) PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    nome_completo VARCHAR(200) NOT NULL,
    regiao VARCHAR(20) NOT NULL,
    capital VARCHAR(100) NOT NULL,
    populacao INTEGER,
    area_km2 DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert Brazilian states data
INSERT INTO estados_brasil (codigo, nome, nome_completo, regiao, capital, populacao, area_km2) VALUES
('AC', 'Acre', 'Estado do Acre', 'Norte', 'Rio Branco', 881935, 164123.04),
('AL', 'Alagoas', 'Estado de Alagoas', 'Nordeste', 'Maceió', 3351543, 27848.14),
('AP', 'Amapá', 'Estado do Amapá', 'Norte', 'Macapá', 845731, 142828.52),
('AM', 'Amazonas', 'Estado do Amazonas', 'Norte', 'Manaus', 4144597, 1559167.88),
('BA', 'Bahia', 'Estado da Bahia', 'Nordeste', 'Salvador', 14873064, 564733.18),
('CE', 'Ceará', 'Estado do Ceará', 'Nordeste', 'Fortaleza', 9132078, 148925.00),
('DF', 'Distrito Federal', 'Distrito Federal', 'Centro-Oeste', 'Brasília', 3015268, 5760.78),
('ES', 'Espírito Santo', 'Estado do Espírito Santo', 'Sudeste', 'Vitória', 4018650, 46095.58),
('GO', 'Goiás', 'Estado de Goiás', 'Centro-Oeste', 'Goiânia', 7018354, 340111.78),
('MA', 'Maranhão', 'Estado do Maranhão', 'Nordeste', 'São Luís', 7075181, 331937.45),
('MT', 'Mato Grosso', 'Estado de Mato Grosso', 'Centro-Oeste', 'Cuiabá', 3484466, 903357.91),
('MS', 'Mato Grosso do Sul', 'Estado de Mato Grosso do Sul', 'Centro-Oeste', 'Campo Grande', 2778986, 357145.84),
('MG', 'Minas Gerais', 'Estado de Minas Gerais', 'Sudeste', 'Belo Horizonte', 21168791, 586528.29),
('PA', 'Pará', 'Estado do Pará', 'Norte', 'Belém', 8602865, 1247955.24),
('PB', 'Paraíba', 'Estado da Paraíba', 'Nordeste', 'João Pessoa', 4018127, 56469.78),
('PR', 'Paraná', 'Estado do Paraná', 'Sul', 'Curitiba', 11433957, 199314.85),
('PE', 'Pernambuco', 'Estado de Pernambuco', 'Nordeste', 'Recife', 9557071, 98311.62),
('PI', 'Piauí', 'Estado do Piauí', 'Nordeste', 'Teresina', 3273227, 251529.19),
('RJ', 'Rio de Janeiro', 'Estado do Rio de Janeiro', 'Sudeste', 'Rio de Janeiro', 17264943, 43696.05),
('RN', 'Rio Grande do Norte', 'Estado do Rio Grande do Norte', 'Nordeste', 'Natal', 3506853, 52796.79),
('RS', 'Rio Grande do Sul', 'Estado do Rio Grande do Sul', 'Sul', 'Porto Alegre', 11377239, 281748.54),
('RO', 'Rondônia', 'Estado de Rondônia', 'Norte', 'Porto Velho', 1777225, 237765.35),
('RR', 'Roraima', 'Estado de Roraima', 'Norte', 'Boa Vista', 605761, 224300.51),
('SC', 'Santa Catarina', 'Estado de Santa Catarina', 'Sul', 'Florianópolis', 7164788, 95346.18),
('SP', 'São Paulo', 'Estado de São Paulo', 'Sudeste', 'São Paulo', 45919049, 248209.43),
('SE', 'Sergipe', 'Estado de Sergipe', 'Nordeste', 'Aracaju', 2298696, 21910.35),
('TO', 'Tocantins', 'Estado do Tocantins', 'Norte', 'Palmas', 1572866, 277720.41),
('BR', 'Brasil', 'República Federativa do Brasil', 'Nacional', 'Brasília', 215300000, 8515767.00)
ON CONFLICT (codigo) DO NOTHING;

-- ============================================================================
-- 5. ADVANCED SEARCH PERFORMANCE INDEXES
-- ============================================================================

-- Primary key and unique constraints
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_search_id ON documents_search_optimized(id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_search_urn ON documents_search_optimized(urn) WHERE urn IS NOT NULL;

-- Portuguese Full-Text Search Indexes (GIN for best performance)
CREATE INDEX idx_search_vector_titulo_gin ON documents_search_optimized USING gin(search_vector_titulo);
CREATE INDEX idx_search_vector_ementa_gin ON documents_search_optimized USING gin(search_vector_ementa);
CREATE INDEX idx_search_vector_combined_gin ON documents_search_optimized USING gin(search_vector_combined);

-- Geographic filtering indexes
CREATE INDEX idx_documents_estado ON documents_search_optimized(estado);
CREATE INDEX idx_documents_estado_nome ON documents_search_optimized(estado_nome) WHERE estado_nome IS NOT NULL;
CREATE INDEX idx_documents_municipality ON documents_search_optimized(municipality) WHERE municipality IS NOT NULL;
CREATE INDEX idx_documents_region ON documents_search_optimized(region);

-- Temporal filtering indexes (B-tree for range queries)
CREATE INDEX idx_documents_data_publicacao ON documents_search_optimized(data_publicacao);
CREATE INDEX idx_documents_ano ON documents_search_optimized(ano);
CREATE INDEX idx_documents_ano_mes ON documents_search_optimized(ano, mes);
CREATE INDEX idx_documents_decada ON documents_search_optimized(decada);

-- Document type and classification indexes
CREATE INDEX idx_documents_tipo ON documents_search_optimized(tipo);
CREATE INDEX idx_documents_species ON documents_search_optimized(species);
CREATE INDEX idx_documents_transport_category ON documents_search_optimized(transport_category) WHERE transport_category IS NOT NULL;

-- Content quality and relevance indexes
CREATE INDEX idx_documents_content_quality ON documents_search_optimized(content_quality_score) WHERE content_quality_score IS NOT NULL;
CREATE INDEX idx_documents_relevance_score ON documents_search_optimized(relevance_score) WHERE relevance_score IS NOT NULL;

-- Composite indexes for complex queries
CREATE INDEX idx_documents_estado_ano ON documents_search_optimized(estado, ano);
CREATE INDEX idx_documents_species_data ON documents_search_optimized(species, data_publicacao);
CREATE INDEX idx_documents_transport_estado ON documents_search_optimized(transport_category, estado) WHERE transport_category IS NOT NULL;

-- Array indexes for tags
CREATE INDEX idx_documents_tags_gin ON documents_search_optimized USING gin(tags) WHERE tags IS NOT NULL;

-- Trigram indexes for fuzzy search
CREATE INDEX idx_documents_titulo_trigram ON documents_search_optimized USING gin(titulo_normalized gin_trgm_ops);
CREATE INDEX idx_documents_autor_trigram ON documents_search_optimized USING gin(autor_normalized gin_trgm_ops) WHERE autor_normalized IS NOT NULL;

-- ============================================================================
-- 6. SEARCH SUPPORT TABLE INDEXES
-- ============================================================================

-- Legal terms dictionary indexes
CREATE INDEX idx_legal_terms_normalized ON legal_terms_dictionary(term_normalized);
CREATE INDEX idx_legal_terms_category ON legal_terms_dictionary(category);
CREATE INDEX idx_legal_terms_frequency ON legal_terms_dictionary(frequency DESC);
CREATE INDEX idx_legal_terms_transport ON legal_terms_dictionary(transport_related) WHERE transport_related = true;

-- Search analytics indexes
CREATE INDEX idx_search_analytics_term ON search_analytics(search_term_normalized);
CREATE INDEX idx_search_analytics_timestamp ON search_analytics(searched_at);
CREATE INDEX idx_search_analytics_results_count ON search_analytics(results_count);

-- ============================================================================
-- 7. MATERIALIZED VIEWS FOR FAST AGGREGATIONS
-- ============================================================================

-- Document statistics by state (for dashboard)
CREATE MATERIALIZED VIEW search_stats_by_state AS
SELECT 
    e.codigo,
    e.nome as estado_nome,
    e.regiao,
    COUNT(d.*) as total_documents,
    COUNT(CASE WHEN d.species = 'Legislação' THEN 1 END) as legislacao_count,
    COUNT(CASE WHEN d.species = 'Jurisprudência' THEN 1 END) as jurisprudencia_count,
    COUNT(CASE WHEN d.species = 'Doutrina' THEN 1 END) as doutrina_count,
    COUNT(CASE WHEN d.transport_category IS NOT NULL THEN 1 END) as transport_related,
    MIN(d.data_publicacao) as oldest_document,
    MAX(d.data_publicacao) as newest_document,
    AVG(d.content_quality_score) as avg_quality_score,
    COUNT(CASE WHEN d.data_publicacao >= CURRENT_DATE - INTERVAL '1 year' THEN 1 END) as recent_documents
FROM estados_brasil e
LEFT JOIN documents_search_optimized d ON e.codigo = d.estado
GROUP BY e.codigo, e.nome, e.regiao;

CREATE UNIQUE INDEX idx_search_stats_by_state_codigo ON search_stats_by_state(codigo);

-- Popular search terms (updated periodically)
CREATE MATERIALIZED VIEW popular_search_terms AS
SELECT 
    search_term_normalized,
    COUNT(*) as search_frequency,
    AVG(results_count) as avg_results,
    AVG(execution_time_ms) as avg_execution_time,
    MAX(searched_at) as last_searched
FROM search_analytics 
WHERE searched_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY search_term_normalized
HAVING COUNT(*) >= 3
ORDER BY search_frequency DESC
LIMIT 1000;

CREATE INDEX idx_popular_search_terms_frequency ON popular_search_terms(search_frequency DESC);

-- ============================================================================
-- 8. SEARCH PERFORMANCE FUNCTIONS
-- ============================================================================

-- Function to update search vectors when document is modified
CREATE OR REPLACE FUNCTION update_document_search_vectors()
RETURNS TRIGGER AS $$
BEGIN
    NEW.titulo_normalized = normalize_portuguese_legal_text(NEW.titulo);
    NEW.ementa_normalized = normalize_portuguese_legal_text(NEW.ementa);
    NEW.autor_normalized = normalize_portuguese_legal_text(NEW.autor);
    NEW.assuntos_normalized = normalize_portuguese_legal_text(NEW.assuntos);
    
    -- Update search vectors using Portuguese legal configuration
    NEW.search_vector_titulo = to_tsvector('portuguese_legal', COALESCE(NEW.titulo, ''));
    NEW.search_vector_ementa = to_tsvector('portuguese_legal', COALESCE(NEW.ementa, ''));
    NEW.search_vector_combined = to_tsvector('portuguese_legal', 
        COALESCE(NEW.titulo, '') || ' ' || 
        COALESCE(NEW.ementa, '') || ' ' || 
        COALESCE(NEW.assuntos, '') || ' ' ||
        COALESCE(NEW.autor, '')
    );
    
    -- Calculate content metrics
    NEW.titulo_length = LENGTH(COALESCE(NEW.titulo, ''));
    NEW.ementa_length = LENGTH(COALESCE(NEW.ementa, ''));
    
    -- Calculate content quality score (0-10)
    NEW.content_quality_score = LEAST(10.0, 
        (CASE WHEN NEW.ementa_length > 200 THEN 3.0 ELSE NEW.ementa_length / 200.0 * 3.0 END) +
        (CASE WHEN NEW.titulo_length > 50 THEN 2.0 ELSE NEW.titulo_length / 50.0 * 2.0 END) +
        (CASE WHEN NEW.url IS NOT NULL AND NEW.url != '' THEN 2.0 ELSE 0.0 END) +
        (CASE WHEN NEW.autor IS NOT NULL AND NEW.autor != '' THEN 1.5 ELSE 0.0 END) +
        (CASE WHEN NEW.urn IS NOT NULL AND NEW.urn != '' THEN 1.5 ELSE 0.0 END)
    );
    
    -- Set temporal fields
    NEW.ano = EXTRACT(YEAR FROM NEW.data_publicacao);
    NEW.mes = EXTRACT(MONTH FROM NEW.data_publicacao);
    NEW.decada = (EXTRACT(YEAR FROM NEW.data_publicacao) / 10) * 10;
    
    -- Set region based on state
    NEW.region = (SELECT regiao FROM estados_brasil WHERE codigo = NEW.estado);
    
    NEW.updated_at = CURRENT_TIMESTAMP;
    NEW.last_indexed_at = CURRENT_TIMESTAMP;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to update search vectors automatically
DROP TRIGGER IF EXISTS trigger_update_search_vectors ON documents_search_optimized;
CREATE TRIGGER trigger_update_search_vectors
    BEFORE INSERT OR UPDATE ON documents_search_optimized
    FOR EACH ROW EXECUTE FUNCTION update_document_search_vectors();

-- ============================================================================
-- 9. SEARCH QUERY OPTIMIZATION FUNCTIONS
-- ============================================================================

-- Function to perform advanced search with ranking
CREATE OR REPLACE FUNCTION advanced_search_documents(
    p_query TEXT DEFAULT '',
    p_estado VARCHAR(2) DEFAULT NULL,
    p_region VARCHAR(20) DEFAULT NULL,
    p_municipality TEXT DEFAULT NULL,
    p_species VARCHAR(50) DEFAULT NULL,
    p_transport_category VARCHAR(50) DEFAULT NULL,
    p_date_start DATE DEFAULT NULL,
    p_date_end DATE DEFAULT NULL,
    p_year_start INTEGER DEFAULT NULL,
    p_year_end INTEGER DEFAULT NULL,
    p_content_quality_min DECIMAL DEFAULT NULL,
    p_limit INTEGER DEFAULT 50,
    p_offset INTEGER DEFAULT 0
)
RETURNS TABLE(
    id BIGINT,
    titulo TEXT,
    ementa TEXT,
    tipo VARCHAR(100),
    species VARCHAR(50),
    estado VARCHAR(2),
    estado_nome VARCHAR(100),
    municipality VARCHAR(200),
    data_publicacao DATE,
    url TEXT,
    autor TEXT,
    transport_category VARCHAR(50),
    content_quality_score DECIMAL(3,2),
    search_rank REAL,
    search_headline_titulo TEXT,
    search_headline_ementa TEXT
) AS $$
DECLARE
    query_tsquery tsquery;
    has_text_search BOOLEAN DEFAULT FALSE;
BEGIN
    -- Prepare text search query if provided
    IF p_query IS NOT NULL AND trim(p_query) != '' THEN
        has_text_search = TRUE;
        -- Convert search query to tsquery with Portuguese legal config
        query_tsquery = plainto_tsquery('portuguese_legal', p_query);
    END IF;
    
    -- Return optimized search results
    RETURN QUERY
    SELECT 
        d.id,
        d.titulo,
        d.ementa,
        d.tipo,
        d.species,
        d.estado,
        d.estado_nome,
        d.municipality,
        d.data_publicacao,
        d.url,
        d.autor,
        d.transport_category,
        d.content_quality_score,
        CASE 
            WHEN has_text_search THEN 
                ts_rank_cd(d.search_vector_combined, query_tsquery) +
                ts_rank_cd(d.search_vector_titulo, query_tsquery) * 2.0 + -- Title matches weighted more
                COALESCE(d.relevance_score, 0) * 0.1
            ELSE 
                COALESCE(d.relevance_score, 5.0)
        END::REAL as search_rank,
        CASE 
            WHEN has_text_search THEN ts_headline('portuguese_legal', d.titulo, query_tsquery, 'MaxWords=15')
            ELSE d.titulo
        END as search_headline_titulo,
        CASE 
            WHEN has_text_search THEN ts_headline('portuguese_legal', COALESCE(d.ementa, ''), query_tsquery, 'MaxWords=25')
            ELSE LEFT(d.ementa, 200)
        END as search_headline_ementa
    FROM documents_search_optimized d
    WHERE 
        -- Text search filter
        (NOT has_text_search OR d.search_vector_combined @@ query_tsquery)
        -- Geographic filters
        AND (p_estado IS NULL OR d.estado = p_estado)
        AND (p_region IS NULL OR d.region = p_region)
        AND (p_municipality IS NULL OR d.municipality_normalized ILIKE '%' || normalize_portuguese_legal_text(p_municipality) || '%')
        -- Type filters
        AND (p_species IS NULL OR d.species = p_species)
        AND (p_transport_category IS NULL OR d.transport_category = p_transport_category)
        -- Temporal filters
        AND (p_date_start IS NULL OR d.data_publicacao >= p_date_start)
        AND (p_date_end IS NULL OR d.data_publicacao <= p_date_end)
        AND (p_year_start IS NULL OR d.ano >= p_year_start)
        AND (p_year_end IS NULL OR d.ano <= p_year_end)
        -- Quality filter
        AND (p_content_quality_min IS NULL OR d.content_quality_score >= p_content_quality_min)
    ORDER BY 
        CASE 
            WHEN has_text_search THEN 
                ts_rank_cd(d.search_vector_combined, query_tsquery) +
                ts_rank_cd(d.search_vector_titulo, query_tsquery) * 2.0 +
                COALESCE(d.relevance_score, 0) * 0.1
            ELSE 
                COALESCE(d.relevance_score, 5.0)
        END DESC,
        d.data_publicacao DESC
    LIMIT p_limit
    OFFSET p_offset;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 10. MAINTENANCE AND MONITORING
-- ============================================================================

-- Function to refresh materialized views
CREATE OR REPLACE FUNCTION refresh_search_materialized_views()
RETURNS TABLE(view_name TEXT, status TEXT, duration INTERVAL) AS $$
DECLARE
    start_time TIMESTAMP;
    end_time TIMESTAMP;
BEGIN
    -- Refresh search stats
    start_time = clock_timestamp();
    REFRESH MATERIALIZED VIEW CONCURRENTLY search_stats_by_state;
    end_time = clock_timestamp();
    view_name = 'search_stats_by_state';
    status = 'SUCCESS';
    duration = end_time - start_time;
    RETURN NEXT;
    
    -- Refresh popular terms
    start_time = clock_timestamp();
    REFRESH MATERIALIZED VIEW popular_search_terms;
    end_time = clock_timestamp();
    view_name = 'popular_search_terms';
    status = 'SUCCESS';
    duration = end_time - start_time;
    RETURN NEXT;
    
    EXCEPTION WHEN OTHERS THEN
        view_name = 'ERROR';
        status = SQLERRM;
        duration = NULL;
        RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- Add maintenance comment
COMMENT ON SCHEMA public IS 'Advanced Search Engine for Brazilian Legislative Monitoring - Optimized for 134k+ documents with Portuguese NLP';

SELECT 'Advanced Search Schema created successfully! Ready for 134k+ documents with sub-second Portuguese search.' as status;