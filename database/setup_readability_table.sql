-- =============================================================================
-- Readability Metrics Database Setup
-- Monitor Legislativo v4
--
-- Purpose: Create table and indexes for storing readability metric scores
-- Author: Monitor Legislativo v4 Team
-- Date: 2025-11-12
-- =============================================================================

-- Drop existing table if needed (uncomment to rebuild)
-- DROP TABLE IF EXISTS readability_metrics CASCADE;

-- Create readability_metrics table
CREATE TABLE IF NOT EXISTS readability_metrics (
    -- Primary key (references documents table)
    id INTEGER PRIMARY KEY,

    -- Readability scores
    flesch_kincaid NUMERIC(5,2) CHECK (flesch_kincaid >= 0 AND flesch_kincaid <= 100),
    fog_index NUMERIC(5,2) CHECK (fog_index >= 0),
    smog_index NUMERIC(5,2) CHECK (smog_index >= 0),

    -- Text statistics
    word_count INTEGER CHECK (word_count >= 0),
    sentence_count INTEGER CHECK (sentence_count >= 0),

    -- Metadata
    calculated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key constraint
    CONSTRAINT fk_readability_document
        FOREIGN KEY (id)
        REFERENCES documents(id)
        ON DELETE CASCADE
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_readability_flesch
    ON readability_metrics(flesch_kincaid);

CREATE INDEX IF NOT EXISTS idx_readability_fog
    ON readability_metrics(fog_index);

CREATE INDEX IF NOT EXISTS idx_readability_smog
    ON readability_metrics(smog_index);

CREATE INDEX IF NOT EXISTS idx_readability_calculated
    ON readability_metrics(calculated_at);

-- Create composite index for sorting by multiple metrics
CREATE INDEX IF NOT EXISTS idx_readability_all_metrics
    ON readability_metrics(flesch_kincaid, fog_index, smog_index);

-- =============================================================================
-- Useful Views
-- =============================================================================

-- View: Documents with readability classification
CREATE OR REPLACE VIEW documents_with_readability AS
SELECT
    d.*,
    rm.flesch_kincaid,
    rm.fog_index,
    rm.smog_index,
    rm.word_count,
    rm.sentence_count,
    rm.calculated_at as readability_calculated_at,

    -- Readability level classification (Flesch-based)
    CASE
        WHEN rm.flesch_kincaid IS NULL THEN 'Não calculado'
        WHEN rm.flesch_kincaid >= 70 THEN 'Fácil'
        WHEN rm.flesch_kincaid >= 50 THEN 'Médio'
        WHEN rm.flesch_kincaid >= 30 THEN 'Difícil'
        ELSE 'Muito Difícil'
    END as nivel_legibilidade,

    -- Education level required (FOG-based)
    CASE
        WHEN rm.fog_index IS NULL THEN 'N/A'
        WHEN rm.fog_index <= 8 THEN 'Ensino Fundamental'
        WHEN rm.fog_index <= 12 THEN 'Ensino Médio'
        WHEN rm.fog_index <= 16 THEN 'Ensino Superior'
        ELSE 'Pós-graduação'
    END as nivel_educacao_necessario

FROM documents d
LEFT JOIN readability_metrics rm ON d.id = rm.id;

-- View: Readability statistics by document type
CREATE OR REPLACE VIEW readability_by_tipo AS
SELECT
    d.tipo,
    COUNT(*) as total_documentos,
    COUNT(rm.id) as documentos_analisados,
    ROUND(AVG(rm.flesch_kincaid)::numeric, 2) as flesch_medio,
    ROUND(STDDEV(rm.flesch_kincaid)::numeric, 2) as flesch_desvio,
    ROUND(AVG(rm.fog_index)::numeric, 2) as fog_medio,
    ROUND(AVG(rm.smog_index)::numeric, 2) as smog_medio,
    ROUND(AVG(rm.word_count)::numeric, 0) as palavras_media,
    ROUND(AVG(rm.sentence_count)::numeric, 0) as sentencas_media
FROM documents d
LEFT JOIN readability_metrics rm ON d.id = rm.id
GROUP BY d.tipo
ORDER BY flesch_medio DESC NULLS LAST;

-- View: Readability statistics by jurisdiction
CREATE OR REPLACE VIEW readability_by_jurisdicao AS
SELECT
    d.jurisdicao,
    COUNT(*) as total_documentos,
    COUNT(rm.id) as documentos_analisados,
    ROUND(AVG(rm.flesch_kincaid)::numeric, 2) as flesch_medio,
    ROUND(AVG(rm.fog_index)::numeric, 2) as fog_medio,
    ROUND(AVG(rm.smog_index)::numeric, 2) as smog_medio
FROM documents d
LEFT JOIN readability_metrics rm ON d.id = rm.id
GROUP BY d.jurisdicao
ORDER BY flesch_medio DESC NULLS LAST;

-- View: Readability statistics by year
CREATE OR REPLACE VIEW readability_by_ano AS
SELECT
    EXTRACT(YEAR FROM d.data_publicacao) as ano,
    COUNT(*) as total_documentos,
    COUNT(rm.id) as documentos_analisados,
    ROUND(AVG(rm.flesch_kincaid)::numeric, 2) as flesch_medio,
    ROUND(AVG(rm.fog_index)::numeric, 2) as fog_medio,
    ROUND(AVG(rm.smog_index)::numeric, 2) as smog_medio
FROM documents d
LEFT JOIN readability_metrics rm ON d.id = rm.id
WHERE d.data_publicacao IS NOT NULL
GROUP BY ano
ORDER BY ano DESC;

-- View: Most and least readable documents
CREATE OR REPLACE VIEW readability_extremes AS
(
    -- Most readable
    SELECT
        'Mais Legível' as categoria,
        d.id,
        d.titulo,
        d.tipo,
        rm.flesch_kincaid,
        rm.fog_index,
        rm.smog_index
    FROM documents d
    JOIN readability_metrics rm ON d.id = rm.id
    WHERE rm.flesch_kincaid IS NOT NULL
    ORDER BY rm.flesch_kincaid DESC
    LIMIT 10
)
UNION ALL
(
    -- Least readable
    SELECT
        'Menos Legível' as categoria,
        d.id,
        d.titulo,
        d.tipo,
        rm.flesch_kincaid,
        rm.fog_index,
        rm.smog_index
    FROM documents d
    JOIN readability_metrics rm ON d.id = rm.id
    WHERE rm.flesch_kincaid IS NOT NULL
    ORDER BY rm.flesch_kincaid ASC
    LIMIT 10
);

-- =============================================================================
-- Useful Functions
-- =============================================================================

-- Function: Get readability interpretation
CREATE OR REPLACE FUNCTION get_readability_interpretation(flesch_score NUMERIC)
RETURNS TEXT AS $$
BEGIN
    IF flesch_score IS NULL THEN
        RETURN 'Não disponível';
    ELSIF flesch_score >= 90 THEN
        RETURN 'Muito fácil (5º ano)';
    ELSIF flesch_score >= 80 THEN
        RETURN 'Fácil (6º ano)';
    ELSIF flesch_score >= 70 THEN
        RETURN 'Razoavelmente fácil (7º ano)';
    ELSIF flesch_score >= 60 THEN
        RETURN 'Padrão (8º-9º ano)';
    ELSIF flesch_score >= 50 THEN
        RETURN 'Razoavelmente difícil (Ensino Médio)';
    ELSIF flesch_score >= 30 THEN
        RETURN 'Difícil (Ensino Superior)';
    ELSE
        RETURN 'Muito difícil (Pós-graduação)';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Function: Get education level from grade
CREATE OR REPLACE FUNCTION get_education_level(grade_level NUMERIC)
RETURNS TEXT AS $$
BEGIN
    IF grade_level IS NULL THEN
        RETURN 'N/A';
    ELSIF grade_level <= 8 THEN
        RETURN 'Ensino Fundamental';
    ELSIF grade_level <= 12 THEN
        RETURN 'Ensino Médio';
    ELSIF grade_level <= 16 THEN
        RETURN 'Ensino Superior';
    ELSE
        RETURN 'Pós-graduação';
    END IF;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- Example Queries
-- =============================================================================

-- Query 1: Summary statistics
/*
SELECT
    COUNT(*) as total_com_metricas,
    ROUND(AVG(flesch_kincaid)::numeric, 2) as flesch_medio,
    ROUND(MIN(flesch_kincaid)::numeric, 2) as flesch_minimo,
    ROUND(MAX(flesch_kincaid)::numeric, 2) as flesch_maximo,
    ROUND(STDDEV(flesch_kincaid)::numeric, 2) as flesch_desvio
FROM readability_metrics;
*/

-- Query 2: Documents needing simplification
/*
SELECT
    d.id,
    d.titulo,
    d.tipo,
    rm.flesch_kincaid,
    get_readability_interpretation(rm.flesch_kincaid) as interpretacao
FROM documents d
JOIN readability_metrics rm ON d.id = rm.id
WHERE rm.flesch_kincaid < 30
ORDER BY rm.flesch_kincaid ASC
LIMIT 20;
*/

-- Query 3: Readability distribution
/*
SELECT
    CASE
        WHEN flesch_kincaid >= 90 THEN '90-100 (Muito fácil)'
        WHEN flesch_kincaid >= 80 THEN '80-90 (Fácil)'
        WHEN flesch_kincaid >= 70 THEN '70-80 (Razoavelmente fácil)'
        WHEN flesch_kincaid >= 60 THEN '60-70 (Padrão)'
        WHEN flesch_kincaid >= 50 THEN '50-60 (Razoavelmente difícil)'
        WHEN flesch_kincaid >= 30 THEN '30-50 (Difícil)'
        ELSE '0-30 (Muito difícil)'
    END as faixa,
    COUNT(*) as quantidade,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1) as percentual
FROM readability_metrics
WHERE flesch_kincaid IS NOT NULL
GROUP BY faixa
ORDER BY MIN(flesch_kincaid) DESC;
*/

-- Query 4: Compare metrics across document types
/*
SELECT * FROM readability_by_tipo
ORDER BY flesch_medio DESC;
*/

-- Query 5: Temporal trends
/*
SELECT * FROM readability_by_ano
ORDER BY ano DESC;
*/

-- Query 6: Documents without metrics (need analysis)
/*
SELECT
    COUNT(*) as sem_metricas,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM documents), 1) as percentual
FROM documents d
LEFT JOIN readability_metrics rm ON d.id = rm.id
WHERE rm.id IS NULL;
*/

-- =============================================================================
-- Data Quality Checks
-- =============================================================================

-- Check for outliers
/*
SELECT
    id,
    flesch_kincaid,
    fog_index,
    smog_index
FROM readability_metrics
WHERE flesch_kincaid < 0 OR flesch_kincaid > 100
   OR fog_index < 0 OR fog_index > 30
   OR smog_index < 0 OR smog_index > 30;
*/

-- Check for missing values
/*
SELECT
    COUNT(*) as total,
    SUM(CASE WHEN flesch_kincaid IS NULL THEN 1 ELSE 0 END) as flesch_nulos,
    SUM(CASE WHEN fog_index IS NULL THEN 1 ELSE 0 END) as fog_nulos,
    SUM(CASE WHEN smog_index IS NULL THEN 1 ELSE 0 END) as smog_nulos
FROM readability_metrics;
*/

-- =============================================================================
-- Maintenance
-- =============================================================================

-- Vacuum and analyze for performance
VACUUM ANALYZE readability_metrics;

-- Update statistics
ANALYZE readability_metrics;

-- =============================================================================
-- Grants (adjust as needed for your security model)
-- =============================================================================

-- Grant read access to application user
-- GRANT SELECT ON readability_metrics TO app_user;
-- GRANT SELECT ON documents_with_readability TO app_user;
-- GRANT SELECT ON readability_by_tipo TO app_user;
-- GRANT SELECT ON readability_by_jurisdicao TO app_user;
-- GRANT SELECT ON readability_by_ano TO app_user;
-- GRANT SELECT ON readability_extremes TO app_user;

-- Grant write access for batch processing
-- GRANT INSERT, UPDATE, DELETE ON readability_metrics TO batch_processor;

-- =============================================================================
-- Verification
-- =============================================================================

-- Verify table creation
SELECT
    table_name,
    table_type
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('readability_metrics', 'documents_with_readability');

-- Verify indexes
SELECT
    indexname,
    indexdef
FROM pg_indexes
WHERE tablename = 'readability_metrics';

-- Verify functions
SELECT
    routine_name,
    routine_type
FROM information_schema.routines
WHERE routine_schema = 'public'
  AND routine_name LIKE '%readability%';

-- Success message
DO $$
BEGIN
    RAISE NOTICE '=======================================================';
    RAISE NOTICE 'Readability Metrics Database Setup Complete!';
    RAISE NOTICE '=======================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'Created:';
    RAISE NOTICE '  ✓ Table: readability_metrics';
    RAISE NOTICE '  ✓ Indexes: 5 indexes for performance';
    RAISE NOTICE '  ✓ Views: 4 analytical views';
    RAISE NOTICE '  ✓ Functions: 2 helper functions';
    RAISE NOTICE '';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '  1. Run: Rscript R/analytics/run_readability_analysis.R';
    RAISE NOTICE '  2. Verify: SELECT COUNT(*) FROM readability_metrics;';
    RAISE NOTICE '  3. Query: SELECT * FROM readability_by_tipo;';
    RAISE NOTICE '';
    RAISE NOTICE 'Documentation: R/analytics/READABILITY_METRICS_GUIDE.md';
    RAISE NOTICE '=======================================================';
END $$;
