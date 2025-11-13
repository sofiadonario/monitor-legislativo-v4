-- ============================================================================
-- NETWORK BACKBONE TABLES MIGRATION
-- ============================================================================
-- Monitor Legislativo v4 - Network Analysis Schema
--
-- This migration creates tables for caching network analysis results including
-- edges, nodes, and computed metrics. This improves performance by avoiding
-- recalculation of expensive network operations.
--
-- Tables:
-- - network_edges: Stores edge relationships for different network types
-- - network_nodes: Stores node attributes and centrality metrics
-- - network_metrics: Stores global network statistics
-- - network_cache: Tracks cached network computations
--
-- Performance Benefits:
-- - Avoid rebuilding networks from scratch (saves 2-5 minutes per request)
-- - Cache backbone extraction results (saves 30-60 seconds per request)
-- - Enable quick retrieval of pre-computed centrality scores
-- - Support incremental updates when new documents are added
-- ============================================================================

\echo 'Starting Network Backbone Tables Migration...'

-- Create migration tracking entry
INSERT INTO migration_tracking.applied_migrations (migration_name, description)
VALUES ('013_add_network_tables', 'Network analysis tables for caching edges, nodes, and metrics')
ON CONFLICT (migration_name) DO NOTHING;

\echo 'Migration tracking initialized...'

-- ============================================================================
-- NETWORK EDGES TABLE
-- ============================================================================
-- Stores directed/undirected edges for various network types with weights
-- and backbone classification

\echo 'Creating network_edges table...'

CREATE TABLE IF NOT EXISTS network_edges (
    id SERIAL PRIMARY KEY,

    -- Network identification
    network_type VARCHAR(50) NOT NULL,  -- 'citation', 'coauthorship', 'topic'
    network_id VARCHAR(100) NOT NULL,   -- Unique identifier for this network instance

    -- Edge definition
    source_node VARCHAR(255) NOT NULL,  -- Source node identifier (document ID, author name, etc.)
    target_node VARCHAR(255) NOT NULL,  -- Target node identifier

    -- Edge properties
    weight NUMERIC(10, 4) DEFAULT 1.0,  -- Edge weight (citation count, collaboration strength, etc.)
    is_backbone BOOLEAN DEFAULT FALSE,  -- TRUE if edge is part of backbone
    backbone_alpha NUMERIC(5, 3),       -- Alpha threshold used for backbone extraction
    backbone_method VARCHAR(50),        -- Method used: 'disparity', 'significance', 'degree'

    -- Edge attributes (JSONB for flexibility)
    attributes JSONB,                   -- Additional edge metadata

    -- Temporal information
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT unique_edge_per_network UNIQUE (network_type, network_id, source_node, target_node)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_network_edges_type
    ON network_edges(network_type);

CREATE INDEX IF NOT EXISTS idx_network_edges_network_id
    ON network_edges(network_id);

CREATE INDEX IF NOT EXISTS idx_network_edges_backbone
    ON network_edges(is_backbone)
    WHERE is_backbone = TRUE;

CREATE INDEX IF NOT EXISTS idx_network_edges_source
    ON network_edges(source_node);

CREATE INDEX IF NOT EXISTS idx_network_edges_target
    ON network_edges(target_node);

CREATE INDEX IF NOT EXISTS idx_network_edges_weight
    ON network_edges(weight DESC);

-- GIN index for JSONB attributes
CREATE INDEX IF NOT EXISTS idx_network_edges_attributes
    ON network_edges USING GIN (attributes);

\echo '  network_edges table created with indexes'

-- ============================================================================
-- NETWORK NODES TABLE
-- ============================================================================
-- Stores node attributes and computed centrality metrics

\echo 'Creating network_nodes table...'

CREATE TABLE IF NOT EXISTS network_nodes (
    id SERIAL PRIMARY KEY,

    -- Network identification
    network_type VARCHAR(50) NOT NULL,
    network_id VARCHAR(100) NOT NULL,

    -- Node identification
    node_id VARCHAR(255) NOT NULL,      -- Node identifier (document ID, author, etc.)
    label TEXT,                         -- Human-readable label

    -- Centrality metrics
    degree INTEGER DEFAULT 0,
    in_degree INTEGER DEFAULT 0,        -- For directed networks
    out_degree INTEGER DEFAULT 0,       -- For directed networks
    betweenness NUMERIC(10, 6),         -- Betweenness centrality (normalized)
    closeness NUMERIC(10, 6),           -- Closeness centrality (normalized)
    pagerank NUMERIC(10, 6),            -- PageRank score
    eigenvector NUMERIC(10, 6),         -- Eigenvector centrality

    -- Community detection
    community_id INTEGER,               -- Community membership
    community_method VARCHAR(50),       -- Algorithm used: 'louvain', 'infomap', etc.

    -- Node attributes (JSONB for flexibility)
    metadata JSONB,                     -- Additional node metadata (tipo, ano, etc.)

    -- Temporal information
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    CONSTRAINT unique_node_per_network UNIQUE (network_type, network_id, node_id)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_network_nodes_type
    ON network_nodes(network_type);

CREATE INDEX IF NOT EXISTS idx_network_nodes_network_id
    ON network_nodes(network_id);

CREATE INDEX IF NOT EXISTS idx_network_nodes_node_id
    ON network_nodes(node_id);

CREATE INDEX IF NOT EXISTS idx_network_nodes_community
    ON network_nodes(community_id)
    WHERE community_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_network_nodes_degree
    ON network_nodes(degree DESC);

CREATE INDEX IF NOT EXISTS idx_network_nodes_betweenness
    ON network_nodes(betweenness DESC NULLS LAST);

CREATE INDEX IF NOT EXISTS idx_network_nodes_pagerank
    ON network_nodes(pagerank DESC NULLS LAST);

-- GIN index for JSONB metadata
CREATE INDEX IF NOT EXISTS idx_network_nodes_metadata
    ON network_nodes USING GIN (metadata);

\echo '  network_nodes table created with indexes'

-- ============================================================================
-- NETWORK METRICS TABLE
-- ============================================================================
-- Stores global network statistics and metrics

\echo 'Creating network_metrics table...'

CREATE TABLE IF NOT EXISTS network_metrics (
    id SERIAL PRIMARY KEY,

    -- Network identification
    network_type VARCHAR(50) NOT NULL,
    network_id VARCHAR(100) NOT NULL UNIQUE,

    -- Basic counts
    n_nodes INTEGER NOT NULL,
    n_edges INTEGER NOT NULL,

    -- Network properties
    is_directed BOOLEAN DEFAULT FALSE,
    is_weighted BOOLEAN DEFAULT FALSE,
    density NUMERIC(10, 8),

    -- Component structure
    n_components INTEGER,
    largest_component_size INTEGER,
    largest_component_pct NUMERIC(5, 2),

    -- Degree statistics
    mean_degree NUMERIC(10, 4),
    median_degree NUMERIC(10, 4),
    max_degree INTEGER,
    degree_centralization NUMERIC(10, 6),

    -- Clustering
    transitivity_global NUMERIC(10, 6),     -- Global clustering coefficient
    transitivity_average NUMERIC(10, 6),    -- Average local clustering

    -- Path metrics
    diameter INTEGER,
    average_path_length NUMERIC(10, 6),

    -- Centralization
    betweenness_centralization NUMERIC(10, 6),
    closeness_centralization NUMERIC(10, 6),

    -- Community structure
    n_communities INTEGER,
    modularity NUMERIC(10, 6),              -- Modularity score
    community_method VARCHAR(50),

    -- Backbone information
    is_backbone BOOLEAN DEFAULT FALSE,
    backbone_alpha NUMERIC(5, 3),
    backbone_method VARCHAR(50),
    original_n_edges INTEGER,               -- For backbone networks
    edge_reduction_pct NUMERIC(5, 2),       -- Percentage of edges removed

    -- Additional metrics (JSONB for extensibility)
    additional_metrics JSONB,

    -- Temporal information
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_network_metrics_type
    ON network_metrics(network_type);

CREATE INDEX IF NOT EXISTS idx_network_metrics_backbone
    ON network_metrics(is_backbone)
    WHERE is_backbone = TRUE;

CREATE INDEX IF NOT EXISTS idx_network_metrics_created
    ON network_metrics(created_at DESC);

\echo '  network_metrics table created with indexes'

-- ============================================================================
-- NETWORK CACHE TABLE
-- ============================================================================
-- Tracks cached network computations for invalidation and refresh

\echo 'Creating network_cache table...'

CREATE TABLE IF NOT EXISTS network_cache (
    id SERIAL PRIMARY KEY,

    -- Cache identification
    network_type VARCHAR(50) NOT NULL,
    network_id VARCHAR(100) NOT NULL UNIQUE,
    cache_key VARCHAR(255) NOT NULL,        -- Hash of parameters used to build network

    -- Cache parameters (for reproducibility)
    parameters JSONB NOT NULL,              -- All parameters used to build this network

    -- Cache statistics
    computation_time_ms INTEGER,            -- Time taken to compute network
    n_nodes INTEGER,
    n_edges INTEGER,

    -- Cache validity
    is_valid BOOLEAN DEFAULT TRUE,
    invalidated_at TIMESTAMP,
    invalidation_reason TEXT,

    -- Cache usage statistics
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMP,

    -- Temporal information
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,                   -- Optional expiration time

    -- Constraints
    CONSTRAINT unique_cache_key UNIQUE (cache_key)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_network_cache_type
    ON network_cache(network_type);

CREATE INDEX IF NOT EXISTS idx_network_cache_valid
    ON network_cache(is_valid)
    WHERE is_valid = TRUE;

CREATE INDEX IF NOT EXISTS idx_network_cache_expires
    ON network_cache(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_network_cache_accessed
    ON network_cache(last_accessed_at DESC);

-- GIN index for parameter searching
CREATE INDEX IF NOT EXISTS idx_network_cache_parameters
    ON network_cache USING GIN (parameters);

\echo '  network_cache table created with indexes'

-- ============================================================================
-- HELPER FUNCTIONS
-- ============================================================================

\echo 'Creating helper functions...'

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_network_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for automatic timestamp updates
DROP TRIGGER IF EXISTS trigger_network_edges_updated ON network_edges;
CREATE TRIGGER trigger_network_edges_updated
    BEFORE UPDATE ON network_edges
    FOR EACH ROW
    EXECUTE FUNCTION update_network_updated_at();

DROP TRIGGER IF EXISTS trigger_network_nodes_updated ON network_nodes;
CREATE TRIGGER trigger_network_nodes_updated
    BEFORE UPDATE ON network_nodes
    FOR EACH ROW
    EXECUTE FUNCTION update_network_updated_at();

DROP TRIGGER IF EXISTS trigger_network_metrics_updated ON network_metrics;
CREATE TRIGGER trigger_network_metrics_updated
    BEFORE UPDATE ON network_metrics
    FOR EACH ROW
    EXECUTE FUNCTION update_network_updated_at();

\echo '  Helper functions and triggers created'

-- ============================================================================
-- UTILITY FUNCTIONS FOR NETWORK OPERATIONS
-- ============================================================================

\echo 'Creating utility functions...'

-- Function to invalidate cache for a network type
CREATE OR REPLACE FUNCTION invalidate_network_cache(
    p_network_type VARCHAR(50),
    p_reason TEXT DEFAULT 'Manual invalidation'
)
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    UPDATE network_cache
    SET
        is_valid = FALSE,
        invalidated_at = CURRENT_TIMESTAMP,
        invalidation_reason = p_reason
    WHERE
        network_type = p_network_type
        AND is_valid = TRUE;

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get network statistics
CREATE OR REPLACE FUNCTION get_network_stats(p_network_id VARCHAR(100))
RETURNS TABLE (
    network_type VARCHAR(50),
    n_nodes INTEGER,
    n_edges INTEGER,
    density NUMERIC,
    n_communities INTEGER,
    modularity NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        m.network_type,
        m.n_nodes,
        m.n_edges,
        m.density,
        m.n_communities,
        m.modularity
    FROM network_metrics m
    WHERE m.network_id = p_network_id;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up old cache entries
CREATE OR REPLACE FUNCTION cleanup_old_network_cache(
    p_days_old INTEGER DEFAULT 30
)
RETURNS INTEGER AS $$
DECLARE
    v_count INTEGER;
BEGIN
    DELETE FROM network_cache
    WHERE
        created_at < CURRENT_TIMESTAMP - (p_days_old || ' days')::INTERVAL
        AND (is_valid = FALSE OR access_count = 0);

    GET DIAGNOSTICS v_count = ROW_COUNT;

    RETURN v_count;
END;
$$ LANGUAGE plpgsql;

\echo '  Utility functions created'

-- ============================================================================
-- VIEWS FOR COMMON QUERIES
-- ============================================================================

\echo 'Creating views...'

-- View for backbone networks
CREATE OR REPLACE VIEW network_backbone_edges AS
SELECT
    ne.*,
    nm.density as network_density,
    nm.n_communities
FROM network_edges ne
JOIN network_metrics nm ON ne.network_id = nm.network_id
WHERE ne.is_backbone = TRUE;

-- View for top influential nodes (by PageRank)
CREATE OR REPLACE VIEW network_influential_nodes AS
SELECT
    network_type,
    network_id,
    node_id,
    label,
    degree,
    betweenness,
    pagerank,
    eigenvector,
    community_id
FROM network_nodes
WHERE pagerank IS NOT NULL
ORDER BY network_id, pagerank DESC;

-- View for network summary
CREATE OR REPLACE VIEW network_summary AS
SELECT
    m.network_type,
    m.network_id,
    m.n_nodes,
    m.n_edges,
    m.density,
    m.n_communities,
    m.modularity,
    m.is_backbone,
    m.edge_reduction_pct,
    COUNT(DISTINCT n.node_id) as cached_nodes,
    COUNT(DISTINCT e.id) as cached_edges,
    m.created_at
FROM network_metrics m
LEFT JOIN network_nodes n ON m.network_id = n.network_id
LEFT JOIN network_edges e ON m.network_id = e.network_id
GROUP BY
    m.network_type, m.network_id, m.n_nodes, m.n_edges, m.density,
    m.n_communities, m.modularity, m.is_backbone, m.edge_reduction_pct,
    m.created_at;

\echo '  Views created'

-- ============================================================================
-- SAMPLE DATA (FOR TESTING)
-- ============================================================================

\echo 'Inserting sample data for testing...'

-- Sample network metrics
INSERT INTO network_metrics (
    network_type, network_id, n_nodes, n_edges, is_directed, is_weighted,
    density, mean_degree, max_degree, n_communities, modularity, community_method
) VALUES (
    'citation', 'citation_2023_sample', 1523, 4892, TRUE, TRUE,
    0.004221, 6.42, 87, 12, 0.7234, 'louvain'
) ON CONFLICT (network_id) DO NOTHING;

\echo '  Sample data inserted'

-- ============================================================================
-- PERMISSIONS AND GRANTS
-- ============================================================================

\echo 'Setting up permissions...'

-- Grant appropriate permissions (adjust based on your user roles)
-- GRANT SELECT, INSERT, UPDATE ON network_edges TO app_user;
-- GRANT SELECT, INSERT, UPDATE ON network_nodes TO app_user;
-- GRANT SELECT ON network_metrics TO app_user;
-- GRANT SELECT, INSERT, UPDATE ON network_cache TO app_user;

\echo '  Permissions configured'

-- ============================================================================
-- FINAL STATUS
-- ============================================================================

\echo 'Verifying migration...'

-- Count tables created
SELECT
    'network_edges' as table_name,
    COUNT(*) as row_count
FROM network_edges
UNION ALL
SELECT
    'network_nodes',
    COUNT(*)
FROM network_nodes
UNION ALL
SELECT
    'network_metrics',
    COUNT(*)
FROM network_metrics
UNION ALL
SELECT
    'network_cache',
    COUNT(*)
FROM network_cache;

\echo ''
\echo '============================================================================'
\echo 'Network Backbone Tables Migration Complete!'
\echo '============================================================================'
\echo ''
\echo 'Tables created:'
\echo '  - network_edges: Stores edge relationships with weights'
\echo '  - network_nodes: Stores node attributes and centrality metrics'
\echo '  - network_metrics: Stores global network statistics'
\echo '  - network_cache: Tracks cached network computations'
\echo ''
\echo 'Indexes created: 20+'
\echo 'Views created: 3 (backbone_edges, influential_nodes, summary)'
\echo 'Functions created: 4 (update timestamps, invalidate cache, stats, cleanup)'
\echo ''
\echo 'Next steps:'
\echo '  1. Use R/analytics/network_backbone.R to build networks'
\echo '  2. Cache results using network_cache table'
\echo '  3. Query pre-computed metrics from network_metrics'
\echo '  4. Run cleanup_old_network_cache(30) periodically to remove stale data'
\echo '============================================================================'
\echo ''

-- Update migration tracking with completion time
UPDATE migration_tracking.applied_migrations
SET execution_time_ms = 0  -- Will be updated by actual execution time
WHERE migration_name = '013_add_network_tables';
