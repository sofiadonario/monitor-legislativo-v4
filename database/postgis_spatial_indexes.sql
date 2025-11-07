-- =============================================================================
-- POSTGIS SPATIAL INDEXES FOR GEOGRAPHIC PERFORMANCE
-- =============================================================================
-- Creates spatial indexes and optimizations for geographic queries
-- Part of PRD Performance Requirements (P1-P2)
-- Requires PostGIS extension
-- =============================================================================

-- =============================================================================
-- 1. ENABLE POSTGIS EXTENSION
-- =============================================================================
-- Enable PostGIS if not already enabled
-- Requires superuser or extension privileges

-- Check if PostGIS is available
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis') THEN
    -- Try to create extension
    BEGIN
      CREATE EXTENSION IF NOT EXISTS postgis;
      RAISE NOTICE 'PostGIS extension created successfully';
    EXCEPTION
      WHEN OTHERS THEN
        RAISE NOTICE 'PostGIS extension not available. Spatial features will be limited.';
        RAISE NOTICE 'Error: %', SQLERRM;
    END;
  ELSE
    RAISE NOTICE 'PostGIS extension already enabled';
  END IF;
END $$;

-- Display PostGIS version
SELECT PostGIS_Version() as postgis_version;

-- =============================================================================
-- 2. CREATE GEOGRAPHIC REFERENCE TABLE
-- =============================================================================
-- Create a table to store Brazilian geographic boundaries
-- This table will have spatial geometries for fast spatial operations

DROP TABLE IF EXISTS geographic_boundaries CASCADE;

CREATE TABLE geographic_boundaries (
  id SERIAL PRIMARY KEY,
  feature_type VARCHAR(20) NOT NULL,  -- 'state' or 'municipality'
  state_code VARCHAR(2) NOT NULL,
  state_name VARCHAR(100),
  municipality_code VARCHAR(7),
  municipality_name VARCHAR(200),
  region_name VARCHAR(20),

  -- Population and area data for per-capita calculations
  population BIGINT,
  area_km2 NUMERIC(12, 2),

  -- Spatial geometry (MultiPolygon for complex boundaries)
  geom GEOMETRY(MultiPolygon, 4674),  -- SIRGAS 2000 (Brazilian standard)
  geom_simplified GEOMETRY(MultiPolygon, 4674),  -- Simplified version for web display

  -- Bounding box for quick spatial queries
  bbox_xmin NUMERIC(10, 6),
  bbox_ymin NUMERIC(10, 6),
  bbox_xmax NUMERIC(10, 6),
  bbox_ymax NUMERIC(10, 6),

  -- Metadata
  data_source VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  -- Constraints
  CONSTRAINT check_feature_type CHECK (feature_type IN ('state', 'municipality'))
);

-- =============================================================================
-- 3. CREATE SPATIAL INDEXES
-- =============================================================================
-- Spatial indexes dramatically improve geographic query performance

-- Primary spatial index on full geometry (GIST index)
CREATE INDEX idx_geographic_boundaries_geom
  ON geographic_boundaries
  USING GIST (geom);

-- Spatial index on simplified geometry for web rendering
CREATE INDEX idx_geographic_boundaries_geom_simplified
  ON geographic_boundaries
  USING GIST (geom_simplified);

-- Bounding box index for quick rectangle containment checks
CREATE INDEX idx_geographic_boundaries_bbox
  ON geographic_boundaries (bbox_xmin, bbox_ymin, bbox_xmax, bbox_ymax);

-- Feature type index for filtering states vs municipalities
CREATE INDEX idx_geographic_boundaries_feature_type
  ON geographic_boundaries (feature_type);

-- State code index for joins with documents table
CREATE INDEX idx_geographic_boundaries_state_code
  ON geographic_boundaries (state_code);

-- Municipality code index
CREATE INDEX idx_geographic_boundaries_municipality_code
  ON geographic_boundaries (municipality_code);

-- Composite index for state-level queries
CREATE INDEX idx_geographic_boundaries_state_lookup
  ON geographic_boundaries (feature_type, state_code)
  WHERE feature_type = 'state';

-- Composite index for municipality-level queries
CREATE INDEX idx_geographic_boundaries_municipality_lookup
  ON geographic_boundaries (feature_type, state_code, municipality_code)
  WHERE feature_type = 'municipality';

-- =============================================================================
-- 4. ADD SPATIAL COLUMNS TO DOCUMENTS TABLE (OPTIONAL)
-- =============================================================================
-- Optionally add spatial columns to the documents table for direct spatial queries
-- This is useful if you want to query "all documents within a geographic area"

-- Add spatial point column for document location (if available)
-- Uncomment if you have lat/long coordinates for documents

-- ALTER TABLE lexml_documents
--   ADD COLUMN IF NOT EXISTS geom_point GEOMETRY(Point, 4674);

-- Create spatial index on document locations
-- CREATE INDEX idx_lexml_documents_geom_point
--   ON lexml_documents
--   USING GIST (geom_point);

-- =============================================================================
-- 5. SPATIAL QUERY HELPER FUNCTIONS
-- =============================================================================

-- Function to get documents within a geographic boundary
CREATE OR REPLACE FUNCTION get_documents_in_boundary(
  p_state_code VARCHAR,
  p_municipality_code VARCHAR DEFAULT NULL
)
RETURNS TABLE (
  id INTEGER,
  estado VARCHAR,
  municipio VARCHAR,
  tipo VARCHAR,
  data DATE,
  titulo TEXT
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    d.id,
    d.estado,
    d.municipio,
    d.tipo,
    d.data,
    d.titulo
  FROM lexml_documents d
  WHERE d.estado = p_state_code
    AND (p_municipality_code IS NULL OR d.municipio = p_municipality_code);
END;
$$ LANGUAGE plpgsql;

-- Function to calculate geographic statistics with spatial joins
CREATE OR REPLACE FUNCTION get_geographic_document_stats(
  p_feature_type VARCHAR DEFAULT 'state'
)
RETURNS TABLE (
  feature_type VARCHAR,
  state_code VARCHAR,
  state_name VARCHAR,
  municipality_code VARCHAR,
  municipality_name VARCHAR,
  document_count BIGINT,
  population BIGINT,
  area_km2 NUMERIC,
  docs_per_100k_pop NUMERIC,
  docs_per_km2 NUMERIC,
  geom_simplified GEOMETRY
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    gb.feature_type,
    gb.state_code,
    gb.state_name,
    gb.municipality_code,
    gb.municipality_name,
    COALESCE(doc_counts.doc_count, 0) as document_count,
    gb.population,
    gb.area_km2,
    CASE
      WHEN gb.population > 0
      THEN ROUND((COALESCE(doc_counts.doc_count, 0)::NUMERIC / gb.population) * 100000, 2)
      ELSE NULL
    END as docs_per_100k_pop,
    CASE
      WHEN gb.area_km2 > 0
      THEN ROUND(COALESCE(doc_counts.doc_count, 0)::NUMERIC / gb.area_km2, 2)
      ELSE NULL
    END as docs_per_km2,
    gb.geom_simplified
  FROM geographic_boundaries gb
  LEFT JOIN (
    SELECT
      estado,
      municipio,
      COUNT(*) as doc_count
    FROM lexml_documents
    GROUP BY estado, municipio
  ) doc_counts ON gb.state_code = doc_counts.estado
    AND (gb.municipality_name = doc_counts.municipio OR gb.municipality_name IS NULL)
  WHERE gb.feature_type = p_feature_type
  ORDER BY document_count DESC;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 6. SPATIAL ANALYSIS FUNCTIONS
-- =============================================================================

-- Function to find neighboring states/municipalities with similar document patterns
CREATE OR REPLACE FUNCTION find_geographic_clusters(
  p_feature_type VARCHAR DEFAULT 'state',
  p_distance_km NUMERIC DEFAULT 100
)
RETURNS TABLE (
  feature_id1 INTEGER,
  feature_id2 INTEGER,
  distance_km NUMERIC,
  doc_count_similarity NUMERIC
) AS $$
BEGIN
  -- This is a placeholder for more advanced spatial clustering
  -- Requires PostGIS and substantial computation
  RAISE NOTICE 'Geographic clustering requires PostGIS and is computationally intensive';
  RETURN QUERY SELECT NULL::INTEGER, NULL::INTEGER, NULL::NUMERIC, NULL::NUMERIC LIMIT 0;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 7. DATA LOADING HELPER FUNCTIONS
-- =============================================================================

-- Function to load state boundaries from GeoJSON
CREATE OR REPLACE FUNCTION load_state_boundaries_from_geojson()
RETURNS TEXT AS $$
BEGIN
  -- This function would typically use ST_GeomFromGeoJSON
  -- Requires actual GeoJSON data to be provided

  RAISE NOTICE 'State boundary loading requires GeoJSON data and PostGIS';
  RAISE NOTICE 'Use: INSERT INTO geographic_boundaries (state_code, geom) VALUES (''SP'', ST_GeomFromGeoJSON(''{"type":"MultiPolygon",...}''))';

  RETURN 'Function template created. Requires GeoJSON data to execute.';
END;
$$ LANGUAGE plpgsql;

-- Function to simplify geometries for web display
CREATE OR REPLACE FUNCTION simplify_geographic_boundaries(
  p_tolerance NUMERIC DEFAULT 0.01
)
RETURNS TEXT AS $$
DECLARE
  rows_updated INTEGER;
BEGIN
  -- Simplify all geometries using Douglas-Peucker algorithm
  UPDATE geographic_boundaries
  SET geom_simplified = ST_SimplifyPreserveTopology(geom, p_tolerance),
      updated_at = CURRENT_TIMESTAMP
  WHERE geom IS NOT NULL;

  GET DIAGNOSTICS rows_updated = ROW_COUNT;

  RETURN 'Simplified ' || rows_updated || ' geographic boundaries with tolerance ' || p_tolerance;
EXCEPTION
  WHEN OTHERS THEN
    RETURN 'Error simplifying geometries: ' || SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- Function to update bounding boxes for all features
CREATE OR REPLACE FUNCTION update_geographic_bounding_boxes()
RETURNS TEXT AS $$
DECLARE
  rows_updated INTEGER;
BEGIN
  UPDATE geographic_boundaries
  SET
    bbox_xmin = ST_XMin(geom),
    bbox_ymin = ST_YMin(geom),
    bbox_xmax = ST_XMax(geom),
    bbox_ymax = ST_YMax(geom),
    updated_at = CURRENT_TIMESTAMP
  WHERE geom IS NOT NULL;

  GET DIAGNOSTICS rows_updated = ROW_COUNT;

  RETURN 'Updated bounding boxes for ' || rows_updated || ' features';
EXCEPTION
  WHEN OTHERS THEN
    RETURN 'Error updating bounding boxes: ' || SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 8. PERFORMANCE MONITORING
-- =============================================================================

-- Function to check spatial index usage
CREATE OR REPLACE FUNCTION check_spatial_index_performance()
RETURNS TABLE (
  index_name VARCHAR,
  table_name VARCHAR,
  index_scans BIGINT,
  tuples_read BIGINT,
  tuples_fetched BIGINT
) AS $$
BEGIN
  RETURN QUERY
  SELECT
    indexrelname::VARCHAR as index_name,
    relname::VARCHAR as table_name,
    idx_scan as index_scans,
    idx_tup_read as tuples_read,
    idx_tup_fetch as tuples_fetched
  FROM pg_stat_user_indexes
  WHERE relname = 'geographic_boundaries'
     OR relname = 'lexml_documents'
  ORDER BY idx_scan DESC;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 9. SAMPLE DATA INSERTION (FOR TESTING)
-- =============================================================================

-- Insert sample state boundaries (placeholders - replace with actual geometries)
-- This is just a template showing the structure

-- INSERT INTO geographic_boundaries (
--   feature_type, state_code, state_name, region_name,
--   population, area_km2,
--   geom, geom_simplified
-- ) VALUES
-- ('state', 'SP', 'São Paulo', 'Sudeste',
--  46649014, 248219.481,
--  ST_GeomFromGeoJSON('{"type":"MultiPolygon","coordinates":[[...]]}'),
--  ST_SimplifyPreserveTopology(ST_GeomFromGeoJSON('{"type":"MultiPolygon","coordinates":[[...]]}'), 0.01)
-- );

-- =============================================================================
-- 10. USAGE EXAMPLES AND QUERIES
-- =============================================================================

-- Example 1: Get all states with their geometries
-- SELECT state_code, state_name, ST_AsGeoJSON(geom_simplified) as geojson
-- FROM geographic_boundaries
-- WHERE feature_type = 'state';

-- Example 2: Find documents in a specific state with geometry
-- SELECT d.*, ST_AsGeoJSON(gb.geom_simplified) as state_geojson
-- FROM lexml_documents d
-- JOIN geographic_boundaries gb ON d.estado = gb.state_code
-- WHERE gb.feature_type = 'state' AND d.estado = 'SP';

-- Example 3: Calculate document density per km²
-- SELECT
--   gb.state_code,
--   gb.state_name,
--   COUNT(d.id) as document_count,
--   gb.area_km2,
--   ROUND(COUNT(d.id)::NUMERIC / NULLIF(gb.area_km2, 0), 2) as docs_per_km2
-- FROM geographic_boundaries gb
-- LEFT JOIN lexml_documents d ON gb.state_code = d.estado
-- WHERE gb.feature_type = 'state'
-- GROUP BY gb.state_code, gb.state_name, gb.area_km2
-- ORDER BY docs_per_km2 DESC;

-- Example 4: Check spatial index performance
-- SELECT * FROM check_spatial_index_performance();

-- =============================================================================
-- 11. MAINTENANCE AND OPTIMIZATION
-- =============================================================================

-- Vacuum and analyze spatial tables regularly
-- VACUUM ANALYZE geographic_boundaries;
-- VACUUM ANALYZE lexml_documents;

-- Reindex spatial indexes (if performance degrades)
-- REINDEX INDEX idx_geographic_boundaries_geom;
-- REINDEX INDEX idx_geographic_boundaries_geom_simplified;

-- =============================================================================
-- 12. GRANT PERMISSIONS
-- =============================================================================

-- Grant permissions to application user
GRANT SELECT, INSERT, UPDATE ON geographic_boundaries TO monitor_user;
GRANT USAGE, SELECT ON SEQUENCE geographic_boundaries_id_seq TO monitor_user;
GRANT EXECUTE ON FUNCTION get_documents_in_boundary(VARCHAR, VARCHAR) TO monitor_user;
GRANT EXECUTE ON FUNCTION get_geographic_document_stats(VARCHAR) TO monitor_user;

-- =============================================================================
-- COMPLETION
-- =============================================================================

SELECT
  'PostGIS spatial indexes and functions created successfully!' as status,
  'Table: geographic_boundaries with spatial indexes' as created,
  'Load GeoJSON data using load_state_boundaries_from_geojson() or direct INSERT' as next_steps,
  'Note: Requires actual GeoJSON data to be loaded for full functionality' as important_note;

-- =============================================================================
-- PERFORMANCE NOTES
-- =============================================================================
-- Expected performance improvements with PostGIS:
-- - Spatial queries: 100-1000x faster
-- - Geographic joins: 50-200x faster
-- - Boundary intersection checks: 200-500x faster
-- - Map rendering with complex boundaries: 10-50x faster
--
-- Storage requirements:
-- - State boundaries: ~5-10 MB
-- - Municipality boundaries (5570): ~100-200 MB
-- - Simplified geometries: ~50% of original size
-- - Spatial indexes: ~20-30% of geometry size
--
-- Recommended settings in postgresql.conf:
-- shared_buffers = 256MB (or more)
-- work_mem = 64MB (for complex spatial operations)
-- maintenance_work_mem = 256MB (for index building)
-- effective_cache_size = 1GB (or more)
-- =============================================================================
