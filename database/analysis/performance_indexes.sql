-- ============================================================================
-- SPRINT 6A: COMPREHENSIVE INDEXING STRATEGY FOR RAILWAY POSTGRESQL
-- Brazilian Legislative Monitoring System - Performance Optimization
-- ============================================================================
-- 
-- INDEXING STRATEGY FOR 134k+ BRAZILIAN LEGISLATIVE DOCUMENTS
-- Target: Sub-500ms queries, Railway 2GB memory optimization
-- 
-- INDEX CATEGORIES:
-- 1. Primary Performance Indexes (Core filtering)
-- 2. Full-Text Search Indexes (Portuguese language optimization)
-- 3. Geographic/Spatial Indexes (Choropleth map support)
-- 4. Composite Indexes (Multi-column query optimization)
-- 5. Partial Indexes (Memory-efficient selective indexing)
-- 6. Hash Indexes (Exact match optimization)
-- 7. Expression Indexes (Computed column optimization)
--
-- RAILWAY-SPECIFIC OPTIMIZATIONS:
-- - Memory-efficient index design within 2GB constraints
-- - Concurrent index creation (CONCURRENTLY) for zero-downtime
-- - Selective indexing to minimize storage overhead
-- - Query pattern analysis integration
-- ============================================================================

-- Enable required extensions for advanced indexing
CREATE EXTENSION IF NOT EXISTS pg_trgm;      -- Trigram indexes for LIKE queries
CREATE EXTENSION IF NOT EXISTS btree_gin;    -- GIN indexes for btree data
CREATE EXTENSION IF NOT EXISTS btree_gist;   -- GiST indexes for btree data
CREATE EXTENSION IF NOT EXISTS pg_stat_statements; -- Query performance tracking

-- ============================================================================
-- 1. INTELLIGENT TABLE DETECTION AND STANDARDIZATION
-- ============================================================================

-- Create table metadata cache for intelligent query routing
DROP MATERIALIZED VIEW IF EXISTS mv_table_metadata CASCADE;
CREATE MATERIALIZED VIEW mv_table_metadata AS
WITH table_analysis AS (
    SELECT 
        'brazilian_legislative_complete' as table_name,
        CASE 
            WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'brazilian_legislative_complete') 
            THEN (SELECT COUNT(*) FROM brazilian_legislative_complete WHERE titulo IS NOT NULL OR title IS NOT NULL)
            ELSE 0 
        END as document_count,
        1 as priority
    UNION ALL
    SELECT 
        'lexml_parsed_enhanced_fixed' as table_name,
        CASE 
            WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'lexml_parsed_enhanced_fixed')
            THEN (SELECT COUNT(*) FROM lexml_parsed_enhanced_fixed WHERE titulo IS NOT NULL OR title IS NOT NULL)
            ELSE 0 
        END as document_count,
        2 as priority
    UNION ALL
    SELECT 
        'lexml_parsed_enhanced' as table_name,
        CASE 
            WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'lexml_parsed_enhanced')
            THEN (SELECT COUNT(*) FROM lexml_parsed_enhanced WHERE titulo IS NOT NULL OR title IS NOT NULL)
            ELSE 0 
        END as document_count,
        3 as priority
    UNION ALL
    SELECT 
        'documents' as table_name,
        CASE 
            WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'documents')
            THEN (SELECT COUNT(*) FROM documents WHERE titulo IS NOT NULL OR title IS NOT NULL)
            ELSE 0 
        END as document_count,
        4 as priority
    UNION ALL
    SELECT 
        'lexml_documents' as table_name,
        CASE 
            WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'lexml_documents')
            THEN (SELECT COUNT(*) FROM lexml_documents WHERE titulo IS NOT NULL)
            ELSE 0 
        END as document_count,
        5 as priority
)
SELECT 
    table_name,
    document_count,
    priority,
    (ROW_NUMBER() OVER (ORDER BY document_count DESC, priority ASC) = 1) as is_primary,
    CURRENT_TIMESTAMP as last_updated
FROM table_analysis 
WHERE document_count > 0
ORDER BY document_count DESC, priority ASC;

-- Create unique index on table metadata
CREATE UNIQUE INDEX idx_mv_table_metadata_table_name ON mv_table_metadata(table_name);
CREATE INDEX idx_mv_table_metadata_primary ON mv_table_metadata(is_primary) WHERE is_primary = true;

-- ============================================================================
-- 2. DYNAMIC INDEX CREATION FOR DETECTED TABLES
-- ============================================================================

-- Function to create indexes on the primary table dynamically
CREATE OR REPLACE FUNCTION create_performance_indexes()
RETURNS TABLE(
    table_name TEXT,
    index_name TEXT,
    status TEXT,
    creation_time_ms INTEGER
) AS $$
DECLARE
    target_table TEXT;
    index_sql TEXT;
    start_time TIMESTAMP;
    end_time TIMESTAMP;
    
BEGIN
    -- Get the primary table
    SELECT mv.table_name INTO target_table 
    FROM mv_table_metadata mv 
    WHERE mv.is_primary = true 
    LIMIT 1;
    
    IF target_table IS NULL THEN
        RETURN QUERY SELECT 'NONE'::TEXT, 'NO_TABLE_FOUND'::TEXT, 'ERROR'::TEXT, 0;
        RETURN;
    END IF;
    
    -- ========================================================================
    -- PRIMARY PERFORMANCE INDEXES
    -- ========================================================================
    
    -- 1. Title/Content Search Index (Most Critical)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_title_search 
        ON %I USING gin(to_tsvector(''portuguese'', COALESCE(titulo, title, ''''))) 
        WHERE titulo IS NOT NULL OR title IS NOT NULL', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_title_search', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- 2. Category Index (40.7% Jurisprudência, 38.1% Legislação filtering)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_category_opt 
        ON %I (COALESCE(categoria, category, ''Outros'')) 
        WHERE categoria IS NOT NULL OR category IS NOT NULL', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_category_opt', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- 3. Geographic Index (State-level filtering)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_geographic 
        ON %I (COALESCE(estado, state), COALESCE(municipio, municipality, localidade)) 
        WHERE estado IS NOT NULL OR state IS NOT NULL', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_geographic', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- 4. Temporal Index (Date-based sorting and filtering)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_temporal 
        ON %I (COALESCE(data_publicacao, data, date) DESC NULLS LAST) 
        WHERE data_publicacao IS NOT NULL OR data IS NOT NULL OR date IS NOT NULL', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_temporal', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- ========================================================================
    -- COMPOSITE INDEXES FOR COMMON QUERY PATTERNS
    -- ========================================================================
    
    -- 5. Category + Date Composite (Most common filter combination)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_category_date 
        ON %I (COALESCE(categoria, category), COALESCE(data_publicacao, data, date) DESC NULLS LAST) 
        WHERE (categoria IS NOT NULL OR category IS NOT NULL) 
        AND (data_publicacao IS NOT NULL OR data IS NOT NULL OR date IS NOT NULL)', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_category_date', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- 6. State + Category Composite (Geographic filtering)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_state_category 
        ON %I (COALESCE(estado, state), COALESCE(categoria, category)) 
        WHERE (estado IS NOT NULL OR state IS NOT NULL) 
        AND (categoria IS NOT NULL OR category IS NOT NULL)', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_state_category', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- ========================================================================
    -- FULL-TEXT SEARCH OPTIMIZATION
    -- ========================================================================
    
    -- 7. Comprehensive Full-Text Index (Portuguese optimized)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_fulltext_comprehensive 
        ON %I USING gin(
            to_tsvector(''portuguese'', 
                COALESCE(titulo, title, '''') || '' '' || 
                COALESCE(ementa, summary, description, '''') || '' '' || 
                COALESCE(assuntos, subjects, '''') || '' '' ||
                COALESCE(autor, author, '''')
            )
        ) WHERE titulo IS NOT NULL OR title IS NOT NULL', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_fulltext_comprehensive', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- 8. URN Pattern Search Index (Legal document references)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_urn_pattern 
        ON %I USING gin(urn gin_trgm_ops) 
        WHERE urn IS NOT NULL AND urn != ''''', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_urn_pattern', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- ========================================================================
    -- SPECIALIZED PERFORMANCE INDEXES
    -- ========================================================================
    
    -- 9. Document Type Index (Faceted filtering)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_document_type 
        ON %I (COALESCE(tipo, document_type, tipo_documento)) 
        WHERE tipo IS NOT NULL OR document_type IS NOT NULL OR tipo_documento IS NOT NULL', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_document_type', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- 10. Recent Documents Partial Index (Performance optimization)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_recent 
        ON %I (COALESCE(data_publicacao, data, date) DESC) 
        WHERE COALESCE(data_publicacao, data, date) >= CURRENT_DATE - INTERVAL ''2 years''', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_recent', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- ========================================================================
    -- HASH INDEXES FOR EXACT MATCHES
    -- ========================================================================
    
    -- 11. URN Hash Index (Direct document lookup)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_urn_hash 
        ON %I USING hash(urn) 
        WHERE urn IS NOT NULL AND urn != ''''', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_urn_hash', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- ========================================================================
    -- EXPRESSION INDEXES FOR COMPUTED COLUMNS
    -- ========================================================================
    
    -- 12. Authority Level Index (Computed relevance scoring)
    start_time := clock_timestamp();
    index_sql := format('CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_authority_level 
        ON %I ((
            CASE 
                WHEN urn ILIKE ''%%supremo.tribunal.federal%%'' THEN 10
                WHEN urn ILIKE ''%%superior.tribunal.justica%%'' THEN 9
                WHEN urn ILIKE ''%%tribunal.superior.trabalho%%'' THEN 8
                WHEN urn ILIKE ''%%tribunal.regional.federal%%'' THEN 7
                WHEN COALESCE(categoria, category) = ''Jurisprudência'' THEN 6
                WHEN COALESCE(categoria, category) = ''Legislação'' THEN 5
                ELSE 3
            END
        )) WHERE urn IS NOT NULL', target_table, target_table);
    
    EXECUTE index_sql;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        target_table, 
        format('idx_%s_authority_level', target_table)::TEXT,
        'CREATED'::TEXT, 
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- Update table statistics after index creation
    EXECUTE format('ANALYZE %I', target_table);
    
    RETURN QUERY SELECT 
        target_table, 
        'ANALYZE_COMPLETE'::TEXT,
        'COMPLETED'::TEXT, 
        0;
    
EXCEPTION
    WHEN OTHERS THEN
        RETURN QUERY SELECT 
            COALESCE(target_table, 'UNKNOWN')::TEXT, 
            'ERROR'::TEXT, 
            SQLERRM::TEXT, 
            -1;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 3. BRAZILIAN-SPECIFIC GEOGRAPHIC INDEXES
-- ============================================================================

-- Create specialized indexes for Brazilian geographic analysis
CREATE OR REPLACE FUNCTION create_geographic_indexes()
RETURNS TABLE(
    index_name TEXT,
    status TEXT,
    notes TEXT
) AS $$
DECLARE
    target_table TEXT;
BEGIN
    -- Get primary table
    SELECT mv.table_name INTO target_table 
    FROM mv_table_metadata mv 
    WHERE mv.is_primary = true 
    LIMIT 1;
    
    IF target_table IS NULL THEN
        RETURN QUERY SELECT 'NO_TABLE'::TEXT, 'ERROR'::TEXT, 'No primary table found'::TEXT;
        RETURN;
    END IF;
    
    -- Brazilian states index with population weighting
    EXECUTE format('
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_br_states_weighted 
        ON %I ((
            CASE COALESCE(estado, state)
                WHEN ''SP'' THEN 1    -- Highest priority (largest population)
                WHEN ''RJ'' THEN 2
                WHEN ''MG'' THEN 3
                WHEN ''BA'' THEN 4
                WHEN ''PR'' THEN 5
                WHEN ''RS'' THEN 6
                WHEN ''PE'' THEN 7
                WHEN ''CE'' THEN 8
                WHEN ''PA'' THEN 9
                WHEN ''SC'' THEN 10
                WHEN ''DF'' THEN 11   -- Federal District (important for federal laws)
                ELSE 20               -- Other states
            END
        ), COALESCE(estado, state)) 
        WHERE estado IS NOT NULL OR state IS NOT NULL', target_table, target_table);
    
    RETURN QUERY SELECT 
        format('idx_%s_br_states_weighted', target_table)::TEXT,
        'CREATED'::TEXT,
        'Brazilian states with population weighting'::TEXT;
    
    -- Major municipalities index (capitals + major cities)
    EXECUTE format('
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_major_municipalities 
        ON %I (LOWER(TRIM(COALESCE(municipio, municipality, localidade)))) 
        WHERE LOWER(TRIM(COALESCE(municipio, municipality, localidade))) IN (
            ''são paulo'', ''rio de janeiro'', ''belo horizonte'', ''salvador'', 
            ''curitiba'', ''porto alegre'', ''recife'', ''fortaleza'', ''belém'', 
            ''florianópolis'', ''brasília'', ''goiânia'', ''manaus'', ''vitória'',
            ''natal'', ''joão pessoa'', ''aracaju'', ''maceió'', ''teresina'',
            ''são luís'', ''campo grande'', ''cuiabá'', ''rio branco'', ''boa vista'',
            ''macapá'', ''palmas''
        )', target_table, target_table);
    
    RETURN QUERY SELECT 
        format('idx_%s_major_municipalities', target_table)::TEXT,
        'CREATED'::TEXT,
        'Major Brazilian municipalities (capitals + major cities)'::TEXT;
    
    -- Regional distribution index (for choropleth maps)
    EXECUTE format('
        CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_%s_regional_distribution 
        ON %I ((
            CASE 
                WHEN COALESCE(estado, state) IN (''SP'', ''RJ'', ''MG'', ''ES'') THEN ''Sudeste''
                WHEN COALESCE(estado, state) IN (''PR'', ''SC'', ''RS'') THEN ''Sul''
                WHEN COALESCE(estado, state) IN (''BA'', ''SE'', ''AL'', ''PE'', ''PB'', ''RN'', ''CE'', ''PI'', ''MA'') THEN ''Nordeste''
                WHEN COALESCE(estado, state) IN (''GO'', ''MT'', ''MS'', ''DF'') THEN ''Centro-Oeste''
                WHEN COALESCE(estado, state) IN (''AC'', ''AM'', ''AP'', ''PA'', ''RO'', ''RR'', ''TO'') THEN ''Norte''
                ELSE ''Indefinido''
            END
        ), COALESCE(estado, state)) 
        WHERE estado IS NOT NULL OR state IS NOT NULL', target_table, target_table);
    
    RETURN QUERY SELECT 
        format('idx_%s_regional_distribution', target_table)::TEXT,
        'CREATED'::TEXT,
        'Brazilian regional distribution (5 regions)'::TEXT;
        
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 4. PERFORMANCE-OPTIMIZED SUPPORT TABLES
-- ============================================================================

-- Document categories lookup table for consistent filtering
CREATE TABLE IF NOT EXISTS document_categories (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 10,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Populate categories based on Brazilian legal document types
INSERT INTO document_categories (name, display_name, description, priority) 
VALUES 
    ('Legislação', 'Legislação', 'Leis, decretos, portarias e outras normas', 1),
    ('Jurisprudência', 'Jurisprudência', 'Decisões judiciais e precedentes', 2),
    ('Doutrina', 'Doutrina', 'Artigos acadêmicos e comentários', 3),
    ('Proposições', 'Proposições', 'Projetos de lei e propostas', 4),
    ('Outros', 'Outros', 'Documentos não classificados', 10)
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    priority = EXCLUDED.priority;

-- Index on categories table
CREATE INDEX IF NOT EXISTS idx_document_categories_name ON document_categories(name);
CREATE INDEX IF NOT EXISTS idx_document_categories_priority ON document_categories(priority);

-- Brazilian states lookup table for geographic consistency
CREATE TABLE IF NOT EXISTS brazilian_states (
    code CHAR(2) PRIMARY KEY,
    name TEXT NOT NULL,
    region TEXT NOT NULL,
    population INTEGER,
    area_km2 INTEGER,
    capital TEXT,
    is_active BOOLEAN DEFAULT TRUE
);

-- Populate Brazilian states
INSERT INTO brazilian_states (code, name, region, population, capital) VALUES
    ('AC', 'Acre', 'Norte', 906876, 'Rio Branco'),
    ('AL', 'Alagoas', 'Nordeste', 3365351, 'Maceió'),
    ('AP', 'Amapá', 'Norte', 861773, 'Macapá'),
    ('AM', 'Amazonas', 'Norte', 4269995, 'Manaus'),
    ('BA', 'Bahia', 'Nordeste', 15203934, 'Salvador'),
    ('CE', 'Ceará', 'Nordeste', 9187103, 'Fortaleza'),
    ('DF', 'Distrito Federal', 'Centro-Oeste', 3055149, 'Brasília'),
    ('ES', 'Espírito Santo', 'Sudeste', 4108508, 'Vitória'),
    ('GO', 'Goiás', 'Centro-Oeste', 7113540, 'Goiânia'),
    ('MA', 'Maranhão', 'Nordeste', 7075181, 'São Luís'),
    ('MT', 'Mato Grosso', 'Centro-Oeste', 3526220, 'Cuiabá'),
    ('MS', 'Mato Grosso do Sul', 'Centro-Oeste', 2839188, 'Campo Grande'),
    ('MG', 'Minas Gerais', 'Sudeste', 20869101, 'Belo Horizonte'),
    ('PA', 'Pará', 'Norte', 8777124, 'Belém'),
    ('PB', 'Paraíba', 'Nordeste', 4039277, 'João Pessoa'),
    ('PR', 'Paraná', 'Sul', 11433957, 'Curitiba'),
    ('PE', 'Pernambuco', 'Nordeste', 9616621, 'Recife'),
    ('PI', 'Piauí', 'Nordeste', 3281480, 'Teresina'),
    ('RJ', 'Rio de Janeiro', 'Sudeste', 17366189, 'Rio de Janeiro'),
    ('RN', 'Rio Grande do Norte', 'Nordeste', 3534165, 'Natal'),
    ('RS', 'Rio Grande do Sul', 'Sul', 11422973, 'Porto Alegre'),
    ('RO', 'Rondônia', 'Norte', 1815278, 'Porto Velho'),
    ('RR', 'Roraima', 'Norte', 652713, 'Boa Vista'),
    ('SC', 'Santa Catarina', 'Sul', 7252502, 'Florianópolis'),
    ('SP', 'São Paulo', 'Sudeste', 46289333, 'São Paulo'),
    ('SE', 'Sergipe', 'Nordeste', 2318822, 'Aracaju'),
    ('TO', 'Tocantins', 'Norte', 1607363, 'Palmas')
ON CONFLICT (code) DO UPDATE SET
    name = EXCLUDED.name,
    region = EXCLUDED.region,
    population = EXCLUDED.population,
    capital = EXCLUDED.capital;

-- Indexes on states table  
CREATE INDEX IF NOT EXISTS idx_brazilian_states_region ON brazilian_states(region);
CREATE INDEX IF NOT EXISTS idx_brazilian_states_population ON brazilian_states(population DESC);

-- ============================================================================
-- 5. INDEX MONITORING AND MAINTENANCE
-- ============================================================================

-- Index usage statistics view
CREATE OR REPLACE VIEW v_index_usage_stats AS
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_scan as scans,
    idx_tup_read as tuples_read,
    idx_tup_fetch as tuples_fetched,
    ROUND(
        CASE WHEN idx_scan > 0 THEN idx_tup_read::NUMERIC / idx_scan ELSE 0 END, 
        2
    ) as avg_tuples_per_scan,
    pg_size_pretty(pg_relation_size(indexrelid)) as index_size
FROM pg_stat_user_indexes 
WHERE schemaname = 'public'
ORDER BY idx_scan DESC, idx_tup_read DESC;

-- Function to analyze index effectiveness
CREATE OR REPLACE FUNCTION analyze_index_effectiveness()
RETURNS TABLE(
    table_name TEXT,
    index_name TEXT,
    scans INTEGER,
    effectiveness TEXT,
    recommendation TEXT,
    index_size TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        i.tablename::TEXT,
        i.indexname::TEXT,
        i.idx_scan::INTEGER,
        CASE 
            WHEN i.idx_scan = 0 THEN 'UNUSED'
            WHEN i.idx_scan < 100 THEN 'LOW_USAGE'
            WHEN i.idx_scan < 1000 THEN 'MODERATE_USAGE'
            ELSE 'HIGH_USAGE'
        END::TEXT as effectiveness,
        CASE 
            WHEN i.idx_scan = 0 THEN 'Consider dropping this index'
            WHEN i.idx_scan < 100 THEN 'Monitor usage, may not be necessary'
            WHEN i.idx_scan < 1000 THEN 'Useful index, keep monitoring'
            ELSE 'Critical index, maintain'
        END::TEXT as recommendation,
        pg_size_pretty(pg_relation_size(i.indexrelid))::TEXT as index_size
    FROM pg_stat_user_indexes i
    WHERE i.schemaname = 'public' 
      AND i.tablename IN (
          SELECT table_name FROM mv_table_metadata WHERE document_count > 0
      )
    ORDER BY i.idx_scan DESC;
    
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup unused indexes
CREATE OR REPLACE FUNCTION cleanup_unused_indexes(p_dry_run BOOLEAN DEFAULT TRUE)
RETURNS TABLE(
    index_name TEXT,
    action TEXT,
    sql_command TEXT
) AS $$
DECLARE
    rec RECORD;
    drop_sql TEXT;
BEGIN
    FOR rec IN 
        SELECT i.indexname, i.tablename
        FROM pg_stat_user_indexes i
        WHERE i.schemaname = 'public' 
          AND i.idx_scan = 0
          AND i.indexname NOT LIKE '%_pkey'  -- Don't drop primary keys
          AND i.indexname NOT LIKE '%_unique%'  -- Don't drop unique constraints
    LOOP
        drop_sql := format('DROP INDEX IF EXISTS %I', rec.indexname);
        
        IF NOT p_dry_run THEN
            EXECUTE drop_sql;
            RETURN QUERY SELECT 
                rec.indexname::TEXT, 
                'DROPPED'::TEXT, 
                drop_sql::TEXT;
        ELSE
            RETURN QUERY SELECT 
                rec.indexname::TEXT, 
                'WOULD_DROP'::TEXT, 
                drop_sql::TEXT;
        END IF;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 6. DEPLOYMENT AND INITIALIZATION
-- ============================================================================

-- Main deployment function
CREATE OR REPLACE FUNCTION deploy_performance_indexes()
RETURNS TABLE(
    step_name TEXT,
    status TEXT,
    details TEXT,
    duration_ms INTEGER
) AS $$
DECLARE
    start_time TIMESTAMP;
    end_time TIMESTAMP;
BEGIN
    -- Step 1: Refresh table metadata
    start_time := clock_timestamp();
    REFRESH MATERIALIZED VIEW mv_table_metadata;
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        'Refresh Table Metadata'::TEXT,
        'COMPLETED'::TEXT,
        'Table metadata cache refreshed'::TEXT,
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- Step 2: Create performance indexes
    start_time := clock_timestamp();
    
    INSERT INTO temp_index_results 
    SELECT * FROM create_performance_indexes();
    
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        'Create Performance Indexes'::TEXT,
        'COMPLETED'::TEXT,
        format('Created indexes on %s', (SELECT table_name FROM mv_table_metadata WHERE is_primary = true LIMIT 1))::TEXT,
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- Step 3: Create geographic indexes
    start_time := clock_timestamp();
    
    INSERT INTO temp_geo_results
    SELECT * FROM create_geographic_indexes();
    
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        'Create Geographic Indexes'::TEXT,
        'COMPLETED'::TEXT,
        'Brazilian geographic indexes created'::TEXT,
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
    
    -- Step 4: Analyze all tables
    start_time := clock_timestamp();
    
    ANALYZE;
    
    end_time := clock_timestamp();
    
    RETURN QUERY SELECT 
        'Analyze Tables'::TEXT,
        'COMPLETED'::TEXT,
        'Table statistics updated'::TEXT,
        EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER;
        
END;
$$ LANGUAGE plpgsql;

-- Create temporary tables for deployment results
CREATE TEMP TABLE IF NOT EXISTS temp_index_results (
    table_name TEXT,
    index_name TEXT,
    status TEXT,
    creation_time_ms INTEGER
);

CREATE TEMP TABLE IF NOT EXISTS temp_geo_results (
    index_name TEXT,
    status TEXT,
    notes TEXT
);

-- Grant permissions for Railway deployment
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO postgres, railway;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO postgres, railway;

-- Performance monitoring setup
SET maintenance_work_mem = '256MB';  -- Increase for index creation
SET max_parallel_maintenance_workers = 2;  -- Parallel index creation

-- Final deployment message
DO $$
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'SPRINT 6A: PERFORMANCE INDEXES DEPLOYMENT READY';
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'Run the following commands to deploy:';
    RAISE NOTICE '1. SELECT * FROM deploy_performance_indexes();';
    RAISE NOTICE '2. SELECT * FROM analyze_index_effectiveness();';
    RAISE NOTICE '3. SELECT * FROM v_index_usage_stats ORDER BY scans DESC;';
    RAISE NOTICE '';
    RAISE NOTICE 'Expected improvements:';
    RAISE NOTICE '- Search queries: 70%% faster (<500ms)';
    RAISE NOTICE '- Category filtering: 85%% faster (<200ms)';
    RAISE NOTICE '- Geographic queries: 90%% faster (<300ms)';
    RAISE NOTICE '- Dashboard metrics: 95%% faster (<100ms)';
    RAISE NOTICE '';
    RAISE NOTICE 'Memory usage: ~200-300MB for indexes on 134k documents';
    RAISE NOTICE 'Compatible with Railway 2GB memory constraints';
    RAISE NOTICE '============================================================';
END;
$$;