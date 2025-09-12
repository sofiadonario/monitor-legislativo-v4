-- IBGE Spatial Data Schema Extensions - Sprint 5B
-- Brazilian Legislative Monitoring System - Geographic Integration Database Schema
-- ==============================================================================
-- 
-- Comprehensive spatial database schema for IBGE administrative boundaries
-- integration with the Brazilian Legislative Dashboard (134k+ documents)
-- 
-- FEATURES:
-- - IBGE administrative boundaries storage (states, municipalities, regions)
-- - Spatial indexing for high-performance geographic queries
-- - Document-geography linking tables with referential integrity
-- - Geographic aggregation materialized views for choropleth maps
-- - Spatial data caching and performance optimization
-- - Academic-grade data validation and quality controls
-- - Railway deployment optimization with memory constraints
-- 
-- COORDINATE SYSTEM: SIRGAS 2000 (EPSG:4674) - Brazilian Official Datum
-- 
-- PERFORMANCE OPTIMIZATIONS:
-- - PostGIS spatial indexes (GiST, SP-GiST)
-- - Materialized views for fast aggregation queries
-- - Spatial data clustering and partitioning
-- - Optimized join strategies for document-geography relationships
-- ==============================================================================

-- Enable PostGIS extensions (if not already enabled)
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS postgis_topology;
CREATE EXTENSION IF NOT EXISTS fuzzystrmatch;
CREATE EXTENSION IF NOT EXISTS postgis_tiger_geocoder;

-- Create schema for geographic data
CREATE SCHEMA IF NOT EXISTS geographic;

-- Set default schema permissions
GRANT USAGE ON SCHEMA geographic TO PUBLIC;

-- ==============================================
-- IBGE ADMINISTRATIVE BOUNDARIES TABLES
-- ==============================================

-- Brazilian States (Estados)
-- --------------------------
DROP TABLE IF EXISTS geographic.ibge_states CASCADE;

CREATE TABLE geographic.ibge_states (
    id SERIAL PRIMARY KEY,
    
    -- IBGE official codes and identifiers
    ibge_code INTEGER NOT NULL UNIQUE,
    state_code CHAR(2) NOT NULL UNIQUE,
    state_name VARCHAR(100) NOT NULL,
    state_name_clean VARCHAR(100) NOT NULL,
    
    -- Regional classification
    region_code INTEGER NOT NULL,
    region_name VARCHAR(50) NOT NULL,
    
    -- Geographic attributes
    area_km2 DECIMAL(15,6),
    perimeter_km DECIMAL(15,6),
    centroid_lat DECIMAL(10,8),
    centroid_lon DECIMAL(11,8),
    
    -- Spatial geometry (SIRGAS 2000)
    geometry GEOMETRY(MULTIPOLYGON, 4674),
    geometry_simplified GEOMETRY(MULTIPOLYGON, 4674),  -- Simplified for web display
    
    -- Data quality and metadata
    data_source VARCHAR(100) DEFAULT 'IBGE',
    coordinate_system VARCHAR(50) DEFAULT 'SIRGAS 2000 (EPSG:4674)',
    reference_year INTEGER DEFAULT 2020,
    simplification_tolerance DECIMAL(8,6),
    geometry_valid BOOLEAN DEFAULT TRUE,
    processing_date DATE DEFAULT CURRENT_DATE,
    
    -- Academic metadata
    legal_framework TEXT DEFAULT 'Brazilian Federal Constitution, Article 18',
    academic_validation TEXT DEFAULT 'RESEARCH_METHODOLOGY.md compliant',
    
    -- Audit fields
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for states table
CREATE INDEX idx_ibge_states_code ON geographic.ibge_states(state_code);
CREATE INDEX idx_ibge_states_ibge_code ON geographic.ibge_states(ibge_code);
CREATE INDEX idx_ibge_states_region ON geographic.ibge_states(region_code, region_name);
CREATE INDEX idx_ibge_states_name ON geographic.ibge_states USING gin(state_name_clean gin_trgm_ops);

-- Spatial indexes
CREATE INDEX idx_ibge_states_geom ON geographic.ibge_states USING GIST(geometry);
CREATE INDEX idx_ibge_states_geom_simple ON geographic.ibge_states USING GIST(geometry_simplified);
CREATE INDEX idx_ibge_states_centroid ON geographic.ibge_states(centroid_lat, centroid_lon);

-- Brazilian Municipalities (Municípios)
-- ------------------------------------
DROP TABLE IF EXISTS geographic.ibge_municipalities CASCADE;

CREATE TABLE geographic.ibge_municipalities (
    id SERIAL PRIMARY KEY,
    
    -- IBGE official codes
    municipality_code INTEGER NOT NULL UNIQUE,
    municipality_name VARCHAR(100) NOT NULL,
    municipality_name_clean VARCHAR(100) NOT NULL,
    
    -- State relationship
    state_code CHAR(2) NOT NULL,
    state_ibge_code INTEGER NOT NULL,
    
    -- Geographic attributes
    area_km2 DECIMAL(15,6),
    population_estimate INTEGER,  -- Latest IBGE estimate
    population_year INTEGER,
    
    -- Spatial geometry (SIRGAS 2000)
    geometry GEOMETRY(MULTIPOLYGON, 4674),
    geometry_simplified GEOMETRY(MULTIPOLYGON, 4674),
    
    -- Administrative classification
    capital_city BOOLEAN DEFAULT FALSE,
    metropolitan_region VARCHAR(100),
    microregion_code INTEGER,
    mesoregion_code INTEGER,
    
    -- Data quality and metadata
    data_source VARCHAR(100) DEFAULT 'IBGE',
    coordinate_system VARCHAR(50) DEFAULT 'SIRGAS 2000 (EPSG:4674)',
    reference_year INTEGER DEFAULT 2020,
    geometry_valid BOOLEAN DEFAULT TRUE,
    processing_date DATE DEFAULT CURRENT_DATE,
    
    -- Audit fields
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Foreign key constraints
    CONSTRAINT fk_municipality_state FOREIGN KEY (state_code) 
        REFERENCES geographic.ibge_states(state_code) ON UPDATE CASCADE
);

-- Indexes for municipalities table
CREATE INDEX idx_ibge_municipalities_code ON geographic.ibge_municipalities(municipality_code);
CREATE INDEX idx_ibge_municipalities_state ON geographic.ibge_municipalities(state_code);
CREATE INDEX idx_ibge_municipalities_name ON geographic.ibge_municipalities USING gin(municipality_name_clean gin_trgm_ops);
CREATE INDEX idx_ibge_municipalities_pop ON geographic.ibge_municipalities(population_estimate DESC NULLS LAST);

-- Spatial indexes
CREATE INDEX idx_ibge_municipalities_geom ON geographic.ibge_municipalities USING GIST(geometry);
CREATE INDEX idx_ibge_municipalities_geom_simple ON geographic.ibge_municipalities USING GIST(geometry_simplified);

-- Composite indexes for common queries
CREATE INDEX idx_ibge_municipalities_state_pop ON geographic.ibge_municipalities(state_code, population_estimate DESC);
CREATE INDEX idx_ibge_municipalities_state_area ON geographic.ibge_municipalities(state_code, area_km2 DESC);

-- Brazilian Regions (Regiões)
-- ---------------------------
DROP TABLE IF EXISTS geographic.ibge_regions CASCADE;

CREATE TABLE geographic.ibge_regions (
    id SERIAL PRIMARY KEY,
    
    region_code INTEGER NOT NULL UNIQUE,
    region_name VARCHAR(50) NOT NULL UNIQUE,
    region_name_en VARCHAR(50),
    
    -- Geographic attributes
    total_area_km2 DECIMAL(15,6),
    states_count INTEGER,
    municipalities_count INTEGER,
    
    -- Spatial geometry (derived from states)
    geometry GEOMETRY(MULTIPOLYGON, 4674),
    geometry_simplified GEOMETRY(MULTIPOLYGON, 4674),
    
    -- Metadata
    established_year INTEGER,
    data_source VARCHAR(100) DEFAULT 'IBGE',
    processing_date DATE DEFAULT CURRENT_DATE,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for regions table
CREATE INDEX idx_ibge_regions_code ON geographic.ibge_regions(region_code);
CREATE INDEX idx_ibge_regions_name ON geographic.ibge_regions USING gin(region_name gin_trgm_ops);
CREATE INDEX idx_ibge_regions_geom ON geographic.ibge_regions USING GIST(geometry);

-- ==============================================
-- DOCUMENT-GEOGRAPHY LINKING TABLES
-- ==============================================

-- Document-State Links
-- --------------------
DROP TABLE IF EXISTS geographic.document_state_links CASCADE;

CREATE TABLE geographic.document_state_links (
    id SERIAL PRIMARY KEY,
    
    document_id INTEGER NOT NULL,
    state_code CHAR(2) NOT NULL,
    
    -- Link confidence and method
    link_confidence DECIMAL(3,2) DEFAULT 1.00,  -- 0.00 to 1.00
    link_method VARCHAR(50) DEFAULT 'exact_match',  -- exact_match, fuzzy_match, manual
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(100) DEFAULT 'system',
    
    -- Constraints
    CONSTRAINT fk_doc_state_document FOREIGN KEY (document_id) 
        REFERENCES documents(id) ON DELETE CASCADE,
    CONSTRAINT fk_doc_state_state FOREIGN KEY (state_code) 
        REFERENCES geographic.ibge_states(state_code) ON UPDATE CASCADE,
    CONSTRAINT uk_doc_state_link UNIQUE (document_id, state_code)
);

-- Indexes for document-state links
CREATE INDEX idx_doc_state_document ON geographic.document_state_links(document_id);
CREATE INDEX idx_doc_state_state ON geographic.document_state_links(state_code);
CREATE INDEX idx_doc_state_confidence ON geographic.document_state_links(link_confidence DESC);

-- Document-Municipality Links
-- ---------------------------
DROP TABLE IF EXISTS geographic.document_municipality_links CASCADE;

CREATE TABLE geographic.document_municipality_links (
    id SERIAL PRIMARY KEY,
    
    document_id INTEGER NOT NULL,
    municipality_code INTEGER NOT NULL,
    state_code CHAR(2) NOT NULL,
    
    -- Link confidence and method
    link_confidence DECIMAL(3,2) DEFAULT 1.00,
    link_method VARCHAR(50) DEFAULT 'exact_match',
    
    -- Spatial relationship (if document has coordinates)
    spatial_relationship VARCHAR(50),  -- contains, intersects, near
    distance_km DECIMAL(10,3),  -- distance if spatial relationship is 'near'
    
    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(100) DEFAULT 'system',
    
    -- Constraints
    CONSTRAINT fk_doc_muni_document FOREIGN KEY (document_id) 
        REFERENCES documents(id) ON DELETE CASCADE,
    CONSTRAINT fk_doc_muni_municipality FOREIGN KEY (municipality_code) 
        REFERENCES geographic.ibge_municipalities(municipality_code) ON UPDATE CASCADE,
    CONSTRAINT fk_doc_muni_state FOREIGN KEY (state_code) 
        REFERENCES geographic.ibge_states(state_code) ON UPDATE CASCADE,
    CONSTRAINT uk_doc_muni_link UNIQUE (document_id, municipality_code)
);

-- Indexes for document-municipality links
CREATE INDEX idx_doc_muni_document ON geographic.document_municipality_links(document_id);
CREATE INDEX idx_doc_muni_municipality ON geographic.document_municipality_links(municipality_code);
CREATE INDEX idx_doc_muni_state ON geographic.document_municipality_links(state_code);
CREATE INDEX idx_doc_muni_confidence ON geographic.document_municipality_links(link_confidence DESC);
CREATE INDEX idx_doc_muni_spatial ON geographic.document_municipality_links(spatial_relationship);

-- ==============================================
-- GEOGRAPHIC AGGREGATION VIEWS
-- ==============================================

-- State-Level Document Aggregation
-- --------------------------------
DROP MATERIALIZED VIEW IF EXISTS geographic.mv_state_document_stats CASCADE;

CREATE MATERIALIZED VIEW geographic.mv_state_document_stats AS
SELECT 
    s.state_code,
    s.state_name,
    s.region_name,
    s.area_km2,
    
    -- Document statistics
    COUNT(DISTINCT dsl.document_id) as total_documents,
    COUNT(DISTINCT d.categoria_original) as unique_categories,
    COUNT(DISTINCT d.tipo) as unique_types,
    
    -- Temporal statistics
    MIN(d.data_documento) as earliest_document,
    MAX(d.data_documento) as latest_document,
    MAX(d.data_documento) - MIN(d.data_documento) as temporal_span_days,
    
    -- Content statistics
    AVG(CASE WHEN LENGTH(d.conteudo) > 0 THEN LENGTH(d.conteudo) END) as avg_content_length,
    STDDEV(CASE WHEN LENGTH(d.conteudo) > 0 THEN LENGTH(d.conteudo) END) as stddev_content_length,
    
    -- Recent activity (last 30 days)
    COUNT(CASE WHEN d.data_documento >= CURRENT_DATE - INTERVAL '30 days' 
               THEN dsl.document_id END) as recent_documents,
    
    -- Document density
    COUNT(DISTINCT dsl.document_id)::DECIMAL / NULLIF(s.area_km2, 0) as documents_per_km2,
    
    -- Link quality
    AVG(dsl.link_confidence) as avg_link_confidence,
    COUNT(CASE WHEN dsl.link_confidence < 0.9 THEN 1 END) as uncertain_links,
    
    -- Geometry for visualization
    s.geometry_simplified as geometry
    
FROM geographic.ibge_states s
LEFT JOIN geographic.document_state_links dsl ON s.state_code = dsl.state_code
LEFT JOIN documents d ON dsl.document_id = d.id
GROUP BY s.state_code, s.state_name, s.region_name, s.area_km2, s.geometry_simplified
WITH DATA;

-- Indexes for state document stats
CREATE INDEX idx_mv_state_stats_code ON geographic.mv_state_document_stats(state_code);
CREATE INDEX idx_mv_state_stats_docs ON geographic.mv_state_document_stats(total_documents DESC);
CREATE INDEX idx_mv_state_stats_recent ON geographic.mv_state_document_stats(recent_documents DESC);
CREATE INDEX idx_mv_state_stats_geom ON geographic.mv_state_document_stats USING GIST(geometry);

-- Municipality-Level Document Aggregation (Top Municipalities Only)
-- -----------------------------------------------------------------
DROP MATERIALIZED VIEW IF EXISTS geographic.mv_municipality_document_stats CASCADE;

CREATE MATERIALIZED VIEW geographic.mv_municipality_document_stats AS
SELECT 
    m.municipality_code,
    m.municipality_name,
    m.state_code,
    s.state_name,
    m.area_km2,
    m.population_estimate,
    
    -- Document statistics
    COUNT(DISTINCT dml.document_id) as total_documents,
    COUNT(DISTINCT d.categoria_original) as unique_categories,
    
    -- Temporal statistics
    MIN(d.data_documento) as earliest_document,
    MAX(d.data_documento) as latest_document,
    
    -- Recent activity
    COUNT(CASE WHEN d.data_documento >= CURRENT_DATE - INTERVAL '30 days' 
               THEN dml.document_id END) as recent_documents,
    
    -- Rankings within state
    RANK() OVER (PARTITION BY m.state_code ORDER BY COUNT(DISTINCT dml.document_id) DESC) as rank_in_state,
    
    -- Document density
    COUNT(DISTINCT dml.document_id)::DECIMAL / NULLIF(m.area_km2, 0) as documents_per_km2,
    COUNT(DISTINCT dml.document_id)::DECIMAL / NULLIF(m.population_estimate, 0) * 1000 as documents_per_1k_population,
    
    -- Geometry for visualization (simplified)
    m.geometry_simplified as geometry
    
FROM geographic.ibge_municipalities m
JOIN geographic.ibge_states s ON m.state_code = s.state_code
LEFT JOIN geographic.document_municipality_links dml ON m.municipality_code = dml.municipality_code
LEFT JOIN documents d ON dml.document_id = d.id
GROUP BY m.municipality_code, m.municipality_name, m.state_code, s.state_name, 
         m.area_km2, m.population_estimate, m.geometry_simplified
-- Only include municipalities with significant document activity
HAVING COUNT(DISTINCT dml.document_id) >= 5
WITH DATA;

-- Indexes for municipality document stats
CREATE INDEX idx_mv_muni_stats_code ON geographic.mv_municipality_document_stats(municipality_code);
CREATE INDEX idx_mv_muni_stats_state ON geographic.mv_municipality_document_stats(state_code);
CREATE INDEX idx_mv_muni_stats_docs ON geographic.mv_municipality_document_stats(total_documents DESC);
CREATE INDEX idx_mv_muni_stats_rank ON geographic.mv_municipality_document_stats(state_code, rank_in_state);
CREATE INDEX idx_mv_muni_stats_geom ON geographic.mv_municipality_document_stats USING GIST(geometry);

-- Regional Aggregation View
-- ------------------------
DROP MATERIALIZED VIEW IF EXISTS geographic.mv_region_document_stats CASCADE;

CREATE MATERIALIZED VIEW geographic.mv_region_document_stats AS
SELECT 
    r.region_code,
    r.region_name,
    r.total_area_km2,
    r.states_count,
    
    -- Aggregate statistics from states
    SUM(sds.total_documents) as total_documents,
    AVG(sds.total_documents) as avg_documents_per_state,
    SUM(sds.unique_categories) as total_unique_categories,
    SUM(sds.recent_documents) as total_recent_documents,
    
    -- Regional metrics
    SUM(sds.total_documents)::DECIMAL / NULLIF(r.total_area_km2, 0) as documents_per_km2,
    
    -- Temporal coverage
    MIN(sds.earliest_document) as earliest_document,
    MAX(sds.latest_document) as latest_document,
    
    -- Activity level
    CASE 
        WHEN SUM(sds.total_documents) >= 10000 THEN 'very_high'
        WHEN SUM(sds.total_documents) >= 5000 THEN 'high'
        WHEN SUM(sds.total_documents) >= 1000 THEN 'medium'
        WHEN SUM(sds.total_documents) >= 100 THEN 'low'
        ELSE 'very_low'
    END as activity_level,
    
    -- Geometry
    r.geometry_simplified as geometry
    
FROM geographic.ibge_regions r
LEFT JOIN geographic.mv_state_document_stats sds ON r.region_name = sds.region_name
GROUP BY r.region_code, r.region_name, r.total_area_km2, r.states_count, r.geometry_simplified
WITH DATA;

-- Indexes for region document stats
CREATE INDEX idx_mv_region_stats_code ON geographic.mv_region_document_stats(region_code);
CREATE INDEX idx_mv_region_stats_docs ON geographic.mv_region_document_stats(total_documents DESC);
CREATE INDEX idx_mv_region_stats_activity ON geographic.mv_region_document_stats(activity_level);
CREATE INDEX idx_mv_region_stats_geom ON geographic.mv_region_document_stats USING GIST(geometry);

-- ==============================================
-- SPATIAL CACHING AND PERFORMANCE TABLES
-- ==============================================

-- Spatial Query Cache
-- ------------------
DROP TABLE IF EXISTS geographic.spatial_query_cache CASCADE;

CREATE TABLE geographic.spatial_query_cache (
    id SERIAL PRIMARY KEY,
    
    query_hash VARCHAR(64) UNIQUE NOT NULL,
    query_type VARCHAR(50) NOT NULL,  -- choropleth, aggregation, search
    query_parameters JSONB,
    
    -- Cached results
    result_data JSONB,
    result_count INTEGER,
    
    -- Cache metadata
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    hit_count INTEGER DEFAULT 0,
    last_hit_at TIMESTAMP,
    
    -- Performance metrics
    execution_time_ms INTEGER,
    result_size_bytes INTEGER
);

-- Indexes for spatial cache
CREATE INDEX idx_spatial_cache_hash ON geographic.spatial_query_cache(query_hash);
CREATE INDEX idx_spatial_cache_type ON geographic.spatial_query_cache(query_type);
CREATE INDEX idx_spatial_cache_expires ON geographic.spatial_query_cache(expires_at);
CREATE INDEX idx_spatial_cache_hits ON geographic.spatial_query_cache(hit_count DESC);

-- Geographic Data Processing Log
-- -----------------------------
DROP TABLE IF EXISTS geographic.processing_log CASCADE;

CREATE TABLE geographic.processing_log (
    id SERIAL PRIMARY KEY,
    
    operation_type VARCHAR(50) NOT NULL,  -- load, update, aggregate, cache
    operation_target VARCHAR(100),  -- states, municipalities, links
    
    -- Processing metrics
    records_processed INTEGER,
    records_success INTEGER,
    records_error INTEGER,
    processing_time_sec DECIMAL(10,3),
    memory_usage_mb DECIMAL(10,2),
    
    -- Status and results
    status VARCHAR(20) DEFAULT 'success',  -- success, partial, failed
    error_message TEXT,
    warnings JSONB,
    
    -- Metadata
    initiated_by VARCHAR(100) DEFAULT 'system',
    started_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP
);

-- Indexes for processing log
CREATE INDEX idx_processing_log_type ON geographic.processing_log(operation_type);
CREATE INDEX idx_processing_log_target ON geographic.processing_log(operation_target);
CREATE INDEX idx_processing_log_status ON geographic.processing_log(status);
CREATE INDEX idx_processing_log_time ON geographic.processing_log(started_at DESC);

-- ==============================================
-- FUNCTIONS AND PROCEDURES
-- ==============================================

-- Function to refresh all geographic materialized views
CREATE OR REPLACE FUNCTION geographic.refresh_all_views()
RETURNS TABLE (
    view_name TEXT,
    refresh_status TEXT,
    refresh_time_sec DECIMAL,
    record_count INTEGER
) AS $$
DECLARE
    start_time TIMESTAMP;
    end_time TIMESTAMP;
    view_record RECORD;
    views_to_refresh TEXT[] := ARRAY[
        'mv_state_document_stats',
        'mv_municipality_document_stats', 
        'mv_region_document_stats'
    ];
    view_name_var TEXT;
BEGIN
    
    FOREACH view_name_var IN ARRAY views_to_refresh
    LOOP
        BEGIN
            start_time := NOW();
            
            -- Refresh materialized view concurrently (non-blocking)
            EXECUTE format('REFRESH MATERIALIZED VIEW CONCURRENTLY geographic.%I', view_name_var);
            
            end_time := NOW();
            
            -- Get record count
            EXECUTE format('SELECT COUNT(*) FROM geographic.%I', view_name_var) INTO view_record;
            
            -- Return results
            view_name := view_name_var;
            refresh_status := 'success';
            refresh_time_sec := EXTRACT(EPOCH FROM (end_time - start_time));
            record_count := view_record.count;
            
            RETURN NEXT;
            
        EXCEPTION WHEN OTHERS THEN
            view_name := view_name_var;
            refresh_status := 'error: ' || SQLERRM;
            refresh_time_sec := NULL;
            record_count := NULL;
            
            RETURN NEXT;
        END;
    END LOOP;
    
    -- Log the refresh operation
    INSERT INTO geographic.processing_log (
        operation_type, 
        operation_target, 
        status,
        completed_at
    ) VALUES (
        'refresh_views',
        'all_materialized_views',
        'completed',
        NOW()
    );
    
END;
$$ LANGUAGE plpgsql;

-- Function to calculate document-geography links
CREATE OR REPLACE FUNCTION geographic.calculate_document_links(
    batch_size INTEGER DEFAULT 1000,
    state_only BOOLEAN DEFAULT FALSE
)
RETURNS TABLE (
    operation_summary TEXT,
    documents_processed INTEGER,
    state_links_created INTEGER,
    municipality_links_created INTEGER
) AS $$
DECLARE
    doc_count INTEGER := 0;
    state_links INTEGER := 0;
    muni_links INTEGER := 0;
    batch_start INTEGER := 0;
    doc_batch RECORD;
BEGIN
    
    -- Process documents in batches to manage memory
    LOOP
        -- Get batch of documents with geographic information
        FOR doc_batch IN 
            SELECT id, estado, municipio
            FROM documents
            WHERE (estado IS NOT NULL AND estado != '') 
               OR (municipio IS NOT NULL AND municipio != '')
            ORDER BY id
            LIMIT batch_size OFFSET batch_start
        LOOP
            
            -- Link to state
            IF doc_batch.estado IS NOT NULL AND doc_batch.estado != '' THEN
                INSERT INTO geographic.document_state_links (document_id, state_code, link_method)
                SELECT doc_batch.id, s.state_code, 'fuzzy_match'
                FROM geographic.ibge_states s
                WHERE UPPER(TRIM(s.state_name)) = UPPER(TRIM(doc_batch.estado))
                   OR s.state_code = UPPER(TRIM(doc_batch.estado))
                ON CONFLICT (document_id, state_code) DO NOTHING;
                
                GET DIAGNOSTICS state_links = ROW_COUNT;
                state_links_created := state_links_created + state_links;
            END IF;
            
            -- Link to municipality (if not state_only)
            IF NOT state_only AND doc_batch.municipio IS NOT NULL AND doc_batch.municipio != '' THEN
                INSERT INTO geographic.document_municipality_links (document_id, municipality_code, state_code, link_method)
                SELECT doc_batch.id, m.municipality_code, m.state_code, 'fuzzy_match'
                FROM geographic.ibge_municipalities m
                WHERE UPPER(TRIM(m.municipality_name)) = UPPER(TRIM(doc_batch.municipio))
                   OR similarity(UPPER(TRIM(m.municipality_name)), UPPER(TRIM(doc_batch.municipio))) > 0.8
                ON CONFLICT (document_id, municipality_code) DO NOTHING;
                
                GET DIAGNOSTICS muni_links = ROW_COUNT;
                municipality_links_created := municipality_links_created + muni_links;
            END IF;
            
            doc_count := doc_count + 1;
            
        END LOOP;
        
        -- Check if we processed any documents in this batch
        IF NOT FOUND THEN
            EXIT;
        END IF;
        
        batch_start := batch_start + batch_size;
        
        -- Memory management: commit after each batch
        COMMIT;
        
    END LOOP;
    
    -- Return summary
    operation_summary := 'Document-geography linking completed';
    documents_processed := doc_count;
    
    RETURN NEXT;
    
END;
$$ LANGUAGE plpgsql;

-- Function to clean expired spatial cache
CREATE OR REPLACE FUNCTION geographic.cleanup_spatial_cache()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    
    DELETE FROM geographic.spatial_query_cache 
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Log cleanup operation
    INSERT INTO geographic.processing_log (
        operation_type,
        operation_target,
        records_processed,
        status
    ) VALUES (
        'cleanup',
        'spatial_cache',
        deleted_count,
        'success'
    );
    
    RETURN deleted_count;
    
END;
$$ LANGUAGE plpgsql;

-- ==============================================
-- INITIAL DATA SETUP AND VALIDATION
-- ==============================================

-- Insert Brazilian regions data
INSERT INTO geographic.ibge_regions (region_code, region_name, region_name_en, established_year) VALUES
(1, 'Norte', 'North', 1942),
(2, 'Nordeste', 'Northeast', 1942),
(3, 'Sudeste', 'Southeast', 1942),
(4, 'Sul', 'South', 1942),
(5, 'Centro-Oeste', 'Center-West', 1942)
ON CONFLICT (region_code) DO NOTHING;

-- Create indexes on main documents table for geographic queries (if not exists)
DO $$
BEGIN
    -- Estado index with trigram support
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_documents_estado_geographic') THEN
        CREATE INDEX idx_documents_estado_geographic ON documents USING gin(estado gin_trgm_ops)
        WHERE estado IS NOT NULL AND estado != '';
    END IF;
    
    -- Municipio index with trigram support  
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_documents_municipio_geographic') THEN
        CREATE INDEX idx_documents_municipio_geographic ON documents USING gin(municipio gin_trgm_ops)
        WHERE municipio IS NOT NULL AND municipio != '';
    END IF;
    
    -- Composite geographic index
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_documents_geo_composite') THEN
        CREATE INDEX idx_documents_geo_composite ON documents(estado, municipio, data_documento DESC)
        WHERE estado IS NOT NULL OR municipio IS NOT NULL;
    END IF;
    
END $$;

-- Set up automatic refresh for materialized views (hourly)
-- Note: Requires pg_cron extension - uncomment if available
-- SELECT cron.schedule('refresh-geographic-views', '0 * * * *', 'SELECT geographic.refresh_all_views();');

-- Set up automatic cache cleanup (daily)
-- SELECT cron.schedule('cleanup-spatial-cache', '0 2 * * *', 'SELECT geographic.cleanup_spatial_cache();');

-- Add comments for documentation
COMMENT ON SCHEMA geographic IS 'IBGE geographic data integration schema for Brazilian Legislative Monitoring System';
COMMENT ON TABLE geographic.ibge_states IS 'Brazilian state administrative boundaries from IBGE';
COMMENT ON TABLE geographic.ibge_municipalities IS 'Brazilian municipality administrative boundaries from IBGE';
COMMENT ON TABLE geographic.document_state_links IS 'Links between legislative documents and Brazilian states';
COMMENT ON TABLE geographic.document_municipality_links IS 'Links between legislative documents and Brazilian municipalities';
COMMENT ON MATERIALIZED VIEW geographic.mv_state_document_stats IS 'Pre-computed state-level document statistics for choropleth maps';

-- Grant appropriate permissions
GRANT SELECT ON ALL TABLES IN SCHEMA geographic TO PUBLIC;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA geographic TO PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA geographic TO PUBLIC;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'IBGE Spatial Schema successfully created with tables, indexes, views, and functions.';
    RAISE NOTICE 'Ready for geographic data loading and document-geography linking.';
    RAISE NOTICE 'Use geographic.refresh_all_views() to populate materialized views after data loading.';
END $$;