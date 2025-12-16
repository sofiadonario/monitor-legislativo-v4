# High-Performance Legislative Search Schema

## Overview

Production-ready PostgreSQL schema optimized for **Google Cloud SQL PostgreSQL** with high-performance configuration. Designed to handle **134k+ Brazilian legislative documents** with sub-second search performance.

## Features

### 🚀 Performance Optimizations
- **Full-text search** with Portuguese language support and accent normalization
- **Trigram fuzzy matching** for typo-tolerant searches
- **Pre-computed search vectors** (TSVECTOR) stored in table
- **Composite indexes** for common query patterns
- **Materialized views** for instant analytics
- **Covering indexes** for index-only scans
- **Parallel query execution** (8 workers)

### 📊 Components

#### Tables
1. **legis_docs** - Core legislative documents (134k+ rows)
   - Full-text search with Portuguese + unaccent
   - Jurisdiction filtering (federal/state/municipal)
   - Temporal indexing (date, year)
   - JSONB metadata for flexibility

2. **ingest_control** - Batch tracking and audit trail
   - Track data ingestion batches
   - Monitor import status
   - Enable rollback capability

#### Materialized Views (Pre-aggregated Analytics)
1. **mv_docs_year_juris** - Documents by jurisdiction and year
2. **mv_docs_state_year** - State-level temporal analysis (for maps)
3. **mv_docs_by_type** - Document type distribution

#### Indexes (10 high-performance indexes)
- **idx_fts_docs** - GIN index for full-text search
- **idx_title_trgm** - Trigram index for fuzzy title search
- **idx_docs_date** - Date filtering and sorting
- **idx_docs_jurisdiction** - Jurisdiction filtering
- **idx_docs_state** - State filtering
- **idx_docs_jurisdiction_year** - Composite index
- **idx_docs_state_year** - State + year (partial index)
- **idx_docs_metadata** - JSONB queries
- **idx_docs_covering** - Covering index for dashboard queries

#### Extensions
- **postgis** - Spatial operations (future use)
- **unaccent** - Portuguese accent removal
- **pg_trgm** - Trigram matching
- **btree_gin** - Composite GIN indexes
- **pg_stat_statements** - Query performance monitoring

## Deployment

### Prerequisites
```bash
# Install PostgreSQL client
brew install postgresql@15  # macOS
# apt-get install postgresql-client  # Linux

# Set Cloud SQL database URL (using Cloud SQL Proxy or direct connection)
export DATABASE_URL='postgresql://postgres:PASSWORD@CLOUD_SQL_CONNECTION_NAME/database'
# Or via Unix socket: postgresql://postgres:PASSWORD@/database?host=/cloudsql/CLOUD_SQL_CONNECTION_NAME
```

### Deploy to Cloud SQL
```bash
cd database/migrations

# Deploy via Cloud SQL Proxy or Cloud Shell
psql "$DATABASE_URL" -f high_performance_search_schema.sql
```

### Verify Installation
```bash
# Check tables
psql "$DATABASE_URL" -c "\dt+ legis_docs"

# Check indexes
psql "$DATABASE_URL" -c "\di+"

# Check materialized views
psql "$DATABASE_URL" -c "\dm"

# View performance settings
psql "$DATABASE_URL" -c "SHOW work_mem; SHOW shared_buffers;"
```

## Usage Examples

### 1. Full-Text Search (Portuguese)
```sql
-- Search for "transporte urbano" (with accent tolerance)
SELECT id, title, date, state
FROM legis_docs
WHERE search_vector @@ to_tsquery('portuguese', 'transporte & urbano')
ORDER BY date DESC
LIMIT 100;

-- Expected performance: <50ms on 134k documents
```

### 2. Fuzzy Title Search
```sql
-- Find titles like "mobilidade" (handles typos)
SELECT id, title, similarity(unaccent(title), unaccent('mobilidade')) AS score
FROM legis_docs
WHERE unaccent(title) % unaccent('mobilidade')
ORDER BY score DESC
LIMIT 50;
```

### 3. Filtered Search
```sql
-- Federal legislation in 2024 about "meio ambiente"
SELECT id, title, date, document_type
FROM legis_docs
WHERE jurisdiction = 'federal'
  AND year = 2024
  AND search_vector @@ to_tsquery('portuguese', 'meio & ambiente')
ORDER BY date DESC;

-- Uses composite index: idx_docs_jurisdiction_year + idx_fts_docs
```

### 4. State-Level Analysis (Using Materialized View)
```sql
-- São Paulo legislation trends 2020-2024
SELECT year, n_docs, document_types
FROM mv_docs_state_year
WHERE state = 'SP'
  AND year BETWEEN 2020 AND 2024
ORDER BY year;

-- Instant response (pre-computed)
```

### 5. Geographic Aggregation
```sql
-- Top 10 states by document count
SELECT state, SUM(n_docs) AS total_docs
FROM mv_docs_state_year
GROUP BY state
ORDER BY total_docs DESC
LIMIT 10;
```

## Data Ingest Workflow

### 1. Insert Documents
```sql
INSERT INTO legis_docs (id, title, full_text, jurisdiction, state, date, document_type)
VALUES
  ('urn:lex:br:federal:lei:2024;14521',
   'Lei de Mobilidade Urbana Sustentável',
   'Texto completo da lei sobre mobilidade urbana...',
   'federal', 'DF', '2024-01-15', 'lei');

-- search_vector is auto-generated
-- year is auto-computed from date
```

### 2. Track Ingest Batch
```sql
-- Start batch
INSERT INTO ingest_control (batch_name, source, status)
VALUES ('lexml_2024_import', 'lexml', 'processing')
RETURNING batch_id;

-- Mark complete and refresh analytics
SELECT complete_ingest_batch(123, 5000);
```

### 3. Refresh Materialized Views
```sql
-- Manual refresh (if not using complete_ingest_batch)
SELECT * FROM refresh_all_mv();

-- Or refresh individually
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_year_juris;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_state_year;
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_by_type;
```

## Performance Monitoring

### Check Slow Queries
```sql
SELECT * FROM v_slow_queries;
-- Shows queries slower than 100ms
```

### Monitor Table Sizes
```sql
SELECT * FROM v_table_sizes;
-- Shows table and index sizes
```

### Query Statistics
```sql
-- Most called queries
SELECT query, calls, mean_exec_time
FROM pg_stat_statements
ORDER BY calls DESC
LIMIT 10;

-- Most time-consuming queries
SELECT query, total_exec_time, calls
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 10;
```

## Performance Expectations

With properly configured Cloud SQL instance:

| Operation | Dataset Size | Expected Time |
|-----------|--------------|---------------|
| Full-text search | 134k docs | <50ms |
| Fuzzy title search | 134k docs | <100ms |
| Filtered search | 134k docs | <30ms |
| Aggregation (MV) | Any size | <10ms |
| Index creation | 134k docs | 30-60s |
| MV refresh | 134k docs | 2-5s |

## Rollback

If you need to remove the schema:

```sql
-- WARNING: This drops all data in these tables
DROP MATERIALIZED VIEW IF EXISTS mv_docs_by_type CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_docs_state_year CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_docs_year_juris CASCADE;
DROP TABLE IF EXISTS ingest_control CASCADE;
DROP TABLE IF EXISTS legis_docs CASCADE;
DROP FUNCTION IF EXISTS refresh_all_mv() CASCADE;
DROP FUNCTION IF EXISTS complete_ingest_batch(BIGINT, INTEGER) CASCADE;
DROP FUNCTION IF EXISTS update_modified_column() CASCADE;
```

## Maintenance

### Weekly Tasks
```sql
-- Vacuum and analyze (Railway does this automatically, but you can trigger manually)
VACUUM ANALYZE legis_docs;

-- Refresh materialized views
SELECT * FROM refresh_all_mv();
```

### Monthly Tasks
```sql
-- Reindex for fragmentation
REINDEX TABLE legis_docs;

-- Check for unused indexes
SELECT * FROM pg_stat_user_indexes WHERE idx_scan = 0;
```

## Integration with R Shiny

### Database Connection (R)
```r
library(DBI)
library(RPostgres)

# Option 1: Direct connection (requires allowlisting IPs)
con <- dbConnect(
  RPostgres::Postgres(),
  dbname = "your_database",
  host = "YOUR_INSTANCE_IP",
  port = 5432,
  user = "postgres",
  password = Sys.getenv("POSTGRES_PASSWORD")
)

# Option 2: Via Cloud SQL Proxy (recommended for Cloud Run)
con <- dbConnect(
  RPostgres::Postgres(),
  dbname = "your_database",
  host = "/cloudsql/CLOUD_SQL_CONNECTION_NAME",
  user = "postgres",
  password = Sys.getenv("POSTGRES_PASSWORD")
)

# Query documents
docs <- dbGetQuery(con, "
  SELECT * FROM legis_docs
  WHERE state = 'SP' AND year = 2024
  LIMIT 1000
")

# Query analytics
stats <- dbGetQuery(con, "
  SELECT * FROM mv_docs_state_year
  WHERE year >= 2020
")

dbDisconnect(con)
```

## Support

For issues or questions:
1. Check Cloud SQL logs in Google Cloud Console
2. Review `v_slow_queries` for performance issues
3. Verify extensions: `SELECT * FROM pg_extension;`
4. Check disk space: `SELECT pg_size_pretty(pg_database_size(current_database()));`

## Architecture Notes

- **TSVECTOR Storage**: Pre-computed and stored (not computed on-the-fly)
- **Index Strategy**: GIN for text, B-tree for filters, composite for common patterns
- **MV Refresh**: CONCURRENTLY mode allows queries during refresh
- **Portuguese Config**: Uses built-in Portuguese text search configuration
- **Unaccent**: Handles "são paulo" = "sao paulo" searches
- **Trigram**: Similarity threshold can be adjusted with `SET pg_trgm.similarity_threshold = 0.3;`

---

**Last Updated**: 2025-10-16
**Schema Version**: 1.0
**Target Environment**: Google Cloud SQL PostgreSQL
**Data Scale**: 134k+ documents (50GB+ total)
