-- Migration: Add Text Reuse Detection Tables
-- Description: LSH-based text similarity detection infrastructure
-- Date: 2025-01-13
-- Author: Monitor Legislativo Analytics Team

-- ============================================================================
-- TEXT REUSE SIGNATURES TABLE
-- ============================================================================
-- Stores MinHash signatures for each document

CREATE TABLE IF NOT EXISTS text_reuse_signatures (
    id SERIAL PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    signature BYTEA NOT NULL,  -- Serialized MinHash signature (100 integers)
    num_shingles INTEGER NOT NULL,  -- Number of unique shingles in document
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(document_id)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_text_reuse_signatures_doc_id
    ON text_reuse_signatures(document_id);

CREATE INDEX IF NOT EXISTS idx_text_reuse_signatures_created
    ON text_reuse_signatures(created_at);

-- Comment
COMMENT ON TABLE text_reuse_signatures IS
    'MinHash signatures for efficient document similarity detection using LSH';

COMMENT ON COLUMN text_reuse_signatures.signature IS
    'Serialized R object containing 100-dimensional MinHash signature';

COMMENT ON COLUMN text_reuse_signatures.num_shingles IS
    'Number of unique 5-grams extracted from document text';


-- ============================================================================
-- LSH BUCKETS TABLE
-- ============================================================================
-- Stores LSH band hashes for fast candidate retrieval

CREATE TABLE IF NOT EXISTS lsh_buckets (
    id SERIAL PRIMARY KEY,
    band_number INTEGER NOT NULL CHECK (band_number BETWEEN 1 AND 20),
    bucket_hash TEXT NOT NULL,  -- MD5 hash of signature band
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(band_number, bucket_hash, document_id)
);

-- Composite index for bucket lookups (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_lsh_buckets_lookup
    ON lsh_buckets(band_number, bucket_hash);

-- Index for document-based queries
CREATE INDEX IF NOT EXISTS idx_lsh_buckets_doc_id
    ON lsh_buckets(document_id);

-- Index for bucket analysis
CREATE INDEX IF NOT EXISTS idx_lsh_buckets_hash
    ON lsh_buckets(bucket_hash);

-- Comment
COMMENT ON TABLE lsh_buckets IS
    'LSH band buckets for fast similar document candidate retrieval';

COMMENT ON COLUMN lsh_buckets.band_number IS
    'Band number (1-20), each band contains 5 hash values';

COMMENT ON COLUMN lsh_buckets.bucket_hash IS
    'MD5 hash of the 5 signature values in this band';


-- ============================================================================
-- TEXT REUSE PAIRS TABLE
-- ============================================================================
-- Stores detected similar document pairs with Jaccard similarity scores

CREATE TABLE IF NOT EXISTS text_reuse_pairs (
    id SERIAL PRIMARY KEY,
    doc1_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    doc2_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    jaccard_similarity NUMERIC(5,4) NOT NULL CHECK (jaccard_similarity BETWEEN 0 AND 1),
    common_shingles_count INTEGER,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified BOOLEAN DEFAULT FALSE,  -- Manual verification flag
    notes TEXT,  -- Optional analysis notes
    CHECK (doc1_id < doc2_id),  -- Prevent duplicate pairs (always store lower ID first)
    UNIQUE(doc1_id, doc2_id)
);

-- Indexes for different query patterns
CREATE INDEX IF NOT EXISTS idx_text_reuse_pairs_doc1
    ON text_reuse_pairs(doc1_id);

CREATE INDEX IF NOT EXISTS idx_text_reuse_pairs_doc2
    ON text_reuse_pairs(doc2_id);

CREATE INDEX IF NOT EXISTS idx_text_reuse_pairs_similarity
    ON text_reuse_pairs(jaccard_similarity DESC);

CREATE INDEX IF NOT EXISTS idx_text_reuse_pairs_both_docs
    ON text_reuse_pairs(doc1_id, doc2_id);

CREATE INDEX IF NOT EXISTS idx_text_reuse_pairs_detected
    ON text_reuse_pairs(detected_at);

-- Composite index for high-similarity queries
CREATE INDEX IF NOT EXISTS idx_text_reuse_pairs_high_similarity
    ON text_reuse_pairs(jaccard_similarity DESC, detected_at DESC)
    WHERE jaccard_similarity >= 0.7;

-- Comment
COMMENT ON TABLE text_reuse_pairs IS
    'Detected similar document pairs with Jaccard similarity scores';

COMMENT ON COLUMN text_reuse_pairs.jaccard_similarity IS
    'Estimated Jaccard similarity coefficient (0-1) from MinHash signatures';

COMMENT ON COLUMN text_reuse_pairs.verified IS
    'Manual verification flag for quality control';


-- ============================================================================
-- TEXT REUSE CLUSTERS TABLE
-- ============================================================================
-- Stores identified clusters of similar documents

CREATE TABLE IF NOT EXISTS text_reuse_clusters (
    id SERIAL PRIMARY KEY,
    cluster_name TEXT,
    description TEXT,
    min_similarity NUMERIC(5,4),  -- Minimum similarity within cluster
    avg_similarity NUMERIC(5,4),  -- Average similarity within cluster
    cluster_size INTEGER,  -- Number of documents in cluster
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cluster membership junction table
CREATE TABLE IF NOT EXISTS text_reuse_cluster_members (
    id SERIAL PRIMARY KEY,
    cluster_id INTEGER NOT NULL REFERENCES text_reuse_clusters(id) ON DELETE CASCADE,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(cluster_id, document_id)
);

CREATE INDEX IF NOT EXISTS idx_cluster_members_cluster
    ON text_reuse_cluster_members(cluster_id);

CREATE INDEX IF NOT EXISTS idx_cluster_members_document
    ON text_reuse_cluster_members(document_id);

-- Comment
COMMENT ON TABLE text_reuse_clusters IS
    'Groups of documents sharing similar text content';

COMMENT ON TABLE text_reuse_cluster_members IS
    'Documents belonging to each text reuse cluster';


-- ============================================================================
-- MATERIALIZED VIEW: Cross-Jurisdiction Reuse Summary
-- ============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_cross_jurisdiction_reuse AS
SELECT
    d1.nivel as source_nivel,
    d1.uf as source_uf,
    d2.nivel as target_nivel,
    d2.uf as target_uf,
    COUNT(*) as reuse_count,
    AVG(p.jaccard_similarity) as avg_similarity,
    MIN(p.jaccard_similarity) as min_similarity,
    MAX(p.jaccard_similarity) as max_similarity
FROM text_reuse_pairs p
JOIN documents d1 ON p.doc1_id = d1.id
JOIN documents d2 ON p.doc2_id = d2.id
WHERE d1.nivel != d2.nivel
   OR d1.uf != d2.uf
   OR (d1.uf IS NULL AND d2.uf IS NOT NULL)
   OR (d1.uf IS NOT NULL AND d2.uf IS NULL)
GROUP BY d1.nivel, d1.uf, d2.nivel, d2.uf;

CREATE INDEX IF NOT EXISTS idx_mv_cross_jurisdiction_source
    ON mv_cross_jurisdiction_reuse(source_nivel, source_uf);

CREATE INDEX IF NOT EXISTS idx_mv_cross_jurisdiction_target
    ON mv_cross_jurisdiction_reuse(target_nivel, target_uf);

-- Comment
COMMENT ON MATERIALIZED VIEW mv_cross_jurisdiction_reuse IS
    'Summary of text reuse patterns across jurisdictions (refresh periodically)';


-- ============================================================================
-- MATERIALIZED VIEW: Temporal Reuse Patterns
-- ============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS mv_temporal_reuse_patterns AS
SELECT
    d1.ano as source_year,
    d2.ano as target_year,
    d2.ano - d1.ano as year_gap,
    COUNT(*) as reuse_count,
    AVG(p.jaccard_similarity) as avg_similarity
FROM text_reuse_pairs p
JOIN documents d1 ON p.doc1_id = d1.id
JOIN documents d2 ON p.doc2_id = d2.id
WHERE d1.ano IS NOT NULL AND d2.ano IS NOT NULL
GROUP BY d1.ano, d2.ano;

CREATE INDEX IF NOT EXISTS idx_mv_temporal_reuse_years
    ON mv_temporal_reuse_patterns(source_year, target_year);

CREATE INDEX IF NOT EXISTS idx_mv_temporal_reuse_gap
    ON mv_temporal_reuse_patterns(year_gap);

-- Comment
COMMENT ON MATERIALIZED VIEW mv_temporal_reuse_patterns IS
    'Temporal patterns of text reuse across years';


-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

-- Function to refresh materialized views
CREATE OR REPLACE FUNCTION refresh_text_reuse_views()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW mv_cross_jurisdiction_reuse;
    REFRESH MATERIALIZED VIEW mv_temporal_reuse_patterns;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION refresh_text_reuse_views() IS
    'Refresh all text reuse materialized views';


-- Function to get similar documents for a given document
CREATE OR REPLACE FUNCTION get_similar_documents(
    p_document_id INTEGER,
    p_threshold NUMERIC DEFAULT 0.7,
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE(
    similar_doc_id INTEGER,
    similarity NUMERIC,
    titulo TEXT,
    ano INTEGER,
    nivel TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        CASE
            WHEN p.doc1_id = p_document_id THEN p.doc2_id
            ELSE p.doc1_id
        END as similar_doc_id,
        p.jaccard_similarity as similarity,
        d.titulo,
        d.ano,
        d.nivel
    FROM text_reuse_pairs p
    JOIN documents d ON (
        CASE
            WHEN p.doc1_id = p_document_id THEN p.doc2_id
            ELSE p.doc1_id
        END = d.id
    )
    WHERE (p.doc1_id = p_document_id OR p.doc2_id = p_document_id)
        AND p.jaccard_similarity >= p_threshold
    ORDER BY p.jaccard_similarity DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_similar_documents IS
    'Retrieve similar documents for a given document ID';


-- Function to get cluster statistics
CREATE OR REPLACE FUNCTION get_cluster_stats()
RETURNS TABLE(
    total_clusters INTEGER,
    avg_cluster_size NUMERIC,
    largest_cluster_size INTEGER,
    total_clustered_docs INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(DISTINCT c.id)::INTEGER as total_clusters,
        AVG(c.cluster_size)::NUMERIC(10,2) as avg_cluster_size,
        MAX(c.cluster_size)::INTEGER as largest_cluster_size,
        COUNT(DISTINCT m.document_id)::INTEGER as total_clustered_docs
    FROM text_reuse_clusters c
    LEFT JOIN text_reuse_cluster_members m ON c.id = m.cluster_id;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION get_cluster_stats IS
    'Get summary statistics about text reuse clusters';


-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Trigger to update text_reuse_clusters.updated_at
CREATE OR REPLACE FUNCTION update_text_reuse_clusters_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_text_reuse_clusters_timestamp
    BEFORE UPDATE ON text_reuse_clusters
    FOR EACH ROW
    EXECUTE FUNCTION update_text_reuse_clusters_timestamp();


-- Trigger to update cluster size when members change
CREATE OR REPLACE FUNCTION update_cluster_size()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE text_reuse_clusters
        SET cluster_size = cluster_size + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.cluster_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE text_reuse_clusters
        SET cluster_size = cluster_size - 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = OLD.cluster_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_cluster_size
    AFTER INSERT OR DELETE ON text_reuse_cluster_members
    FOR EACH ROW
    EXECUTE FUNCTION update_cluster_size();


-- ============================================================================
-- GRANTS (adjust as needed for your setup)
-- ============================================================================

-- Grant appropriate permissions
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO your_app_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO your_app_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO your_app_user;


-- ============================================================================
-- INITIAL DATA / VACUUM
-- ============================================================================

-- Analyze tables for query optimization
ANALYZE text_reuse_signatures;
ANALYZE lsh_buckets;
ANALYZE text_reuse_pairs;
ANALYZE text_reuse_clusters;
ANALYZE text_reuse_cluster_members;


-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Verify tables were created
DO $$
BEGIN
    RAISE NOTICE 'Text Reuse Detection tables created successfully:';
    RAISE NOTICE '  - text_reuse_signatures';
    RAISE NOTICE '  - lsh_buckets';
    RAISE NOTICE '  - text_reuse_pairs';
    RAISE NOTICE '  - text_reuse_clusters';
    RAISE NOTICE '  - text_reuse_cluster_members';
    RAISE NOTICE '  - mv_cross_jurisdiction_reuse';
    RAISE NOTICE '  - mv_temporal_reuse_patterns';
    RAISE NOTICE 'Helper functions and triggers installed.';
END $$;
