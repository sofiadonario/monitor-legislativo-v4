# COMPREHENSIVE DATABASE & DATA STRUCTURE ANALYSIS
## Monitor Legislativo v4 - Brazilian Legislative Monitoring System

**Date:** 2025-11-09
**Analyst:** DevOps & Database Engineering Team
**Dataset:** 134,014 Brazilian Legislative Documents (1829-2025)
**Database:** PostgreSQL on Google Cloud SQL
**Challenge:** Portuguese language data with diacritics (ã, ç, é, ê, õ, etc.)

---

## EXECUTIVE SUMMARY

### Critical Findings

1. **DATA-DOCUMENTATION MISMATCH** ⚠️
   - Documentation references `lexml_unified_dataset.csv` (line 12 in data_current/README.md)
   - **Reality:** File doesn't exist, only Parquet files available
   - **Impact:** Scripts expecting CSV will fail
   - **Action Required:** Generate CSV or update documentation

2. **SCHEMA DISCREPANCY** ⚠️
   - `R/database/queries.R` expects simple schema (12 columns)
   - `db/advanced_search_schema.sql` defines complex schema (34+ columns)
   - **Impact:** Potential column mismatch errors
   - **Action Required:** Unify schemas or create migration

3. **ESTADO FIELD INCONSISTENCY** ⚠️
   - Database stores: 'SP', 'RJ', 'MG', 'Federal', '' (empty strings)
   - GeoJSON expects: State codes only
   - **Impact:** Geographic queries require normalization
   - **Action Required:** Normalize 'Federal' → 'DF' mapping

4. **MISSING INDEXES** ⚠️
   - No full-text search index on Portuguese content
   - Missing composite indexes for common filter combinations
   - No partial indexes for nullable fields
   - **Impact:** Slow queries on 134k+ dataset
   - **Action Required:** Create optimized indexes

5. **ENCODING HANDLING** ✅ (Mostly Good)
   - Parquet files store UTF-8 correctly
   - Portuguese diacritics preserved
   - **Risk:** Database collation not explicitly set to pt_BR
   - **Action Required:** Verify collation configuration

---

## DETAILED ANALYSIS

### 1. DATA STRUCTURE ASSESSMENT

#### Current Parquet Schema (34 columns)
```
✅ CORE FIELDS (Database-mapped):
- titulo (TEXT) - Portuguese with diacritics
- tipo (VARCHAR) - Document type
- data (STRING) - Date as string (needs conversion)
- urn (TEXT) - Unique resource name
- ano (STRING) - Year as string (should be INTEGER)
- estado (STRING) - State code (inconsistent)
- municipio (STRING) - Municipality name

✅ CONTENT FIELDS:
- autor (TEXT) - Author/Agency
- assuntos (TEXT) - Subject matter
- ementa (TEXT) - Legal abstract
- classificacao (TEXT) - Classification

⚠️ QUALITY/METADATA FIELDS (Not in database):
- year_extracted (DOUBLE)
- decade (DOUBLE)
- authority_level (STRING)
- doc_category (STRING)
- transport_theme (STRING)
- has_title (BOOL)
- has_urn (BOOL)
- has_date (BOOL)
- urn_valid (BOOL)
- text_quality (DOUBLE)
- completeness_score (DOUBLE)

❌ MISSING IN DATABASE:
- created_at (TIMESTAMP) - Needed for auditing
- updated_at (TIMESTAMP) - Needed for change tracking
- search_vector (TSVECTOR) - Needed for full-text search
```

#### Database Schema (from queries.R)
```sql
-- Expected by R/database/queries.R
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    urn TEXT,
    titulo TEXT,
    content TEXT,  -- ⚠️ Not in Parquet!
    tipo VARCHAR(50),
    ano INTEGER,
    data_publicacao DATE,
    orgao_emissor TEXT,
    estado VARCHAR(2),
    municipio VARCHAR(100),
    fonte VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

**MAPPING ISSUES:**
- Parquet `data` (string) → Database `data_publicacao` (date) - needs conversion
- Parquet `ano` (string) → Database `ano` (integer) - needs casting
- Parquet `ementa` → Database `content` - field name mismatch
- Missing `orgao_emissor` mapping (could use `autor` or `autoridade`)
- Missing `fonte` in Parquet (could default to 'LexML')

---

### 2. PORTUGUESE LANGUAGE CHALLENGES

#### Character Encoding Analysis
```
✅ PROPERLY STORED DIACRITICS:
- ã (til) - "São Paulo", "Legislação"
- ç (cedilha) - "Educação", "Inovação"
- é, ê (acentos agudos/circunflexos) - "Transporte Público"
- õ, ô (til/circunflexo no o) - "Transporte", "Ônibus"
- á, à (acentos agudos/graves) - "Trânsito", "Pará"

⚠️ COLLATION CONCERNS:
- Database collation not explicitly set to pt_BR.utf8
- Sorting may not follow Portuguese alphabet rules
- String comparison may be case-sensitive when shouldn't be
```

#### Full-Text Search Configuration
```
✅ GOOD: queries.R uses 'portuguese' text search config (line 171)
to_tsvector('portuguese', content)

⚠️ IMPROVEMENTS NEEDED:
1. Enable unaccent extension for accent-insensitive search
2. Create custom Portuguese legal dictionary
3. Add trigram indexing for fuzzy matching
4. Configure stop words for legal terminology
```

---

### 3. INDEX ANALYSIS

#### Current Indexes (likely minimal)
```sql
-- Primary key only (automatic)
CREATE INDEX documents_pkey ON documents(id);

-- No other indexes detected in queries.R
```

#### Required Indexes for Performance
```sql
-- 1. FULL-TEXT SEARCH (Priority: CRITICAL)
CREATE INDEX idx_documents_titulo_fts
ON documents USING gin(to_tsvector('portuguese', titulo));

CREATE INDEX idx_documents_content_fts
ON documents USING gin(to_tsvector('portuguese', content));

-- 2. GEOGRAPHIC FILTERS (Priority: HIGH)
CREATE INDEX idx_documents_estado ON documents(estado);
CREATE INDEX idx_documents_municipio ON documents(municipio)
WHERE municipio IS NOT NULL;

-- 3. TEMPORAL FILTERS (Priority: HIGH)
CREATE INDEX idx_documents_data_publicacao ON documents(data_publicacao);
CREATE INDEX idx_documents_ano ON documents(ano);

-- 4. DOCUMENT TYPE FILTERS (Priority: MEDIUM)
CREATE INDEX idx_documents_tipo ON documents(tipo);

-- 5. COMPOSITE INDEXES (Priority: HIGH)
CREATE INDEX idx_documents_estado_ano ON documents(estado, ano);
CREATE INDEX idx_documents_tipo_data ON documents(tipo, data_publicacao);

-- 6. URN UNIQUENESS (Priority: CRITICAL)
CREATE UNIQUE INDEX idx_documents_urn ON documents(urn);

-- 7. TRIGRAM FUZZY SEARCH (Priority: MEDIUM)
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX idx_documents_titulo_trgm
ON documents USING gin(titulo gin_trgm_ops);
```

**PERFORMANCE IMPACT ESTIMATES:**
- Full-text search: 100x-1000x faster with GIN indexes
- Geographic filters: 50x-100x faster with B-tree indexes
- Date range queries: 20x-50x faster with B-tree indexes
- Fuzzy search: 10x-50x faster with trigram indexes

---

### 4. DATA ORGANIZATION ASSESSMENT

#### Partitioning Strategy Analysis
```
Current: by_authority_decade (Authority Level × Decade)

✅ BENEFITS:
- Good for authority-specific queries (Federal vs State)
- Decade-based partitioning helps temporal queries
- Aligns with academic research patterns

⚠️ LIMITATIONS:
- Not optimal for state-specific queries (most common)
- Decade partitions create many small files for older data
- Geographic queries require scanning multiple partitions

RECOMMENDATION:
- Add state-level partitioning: by_state_year
- Benefits: Direct state filtering, better query performance
- Structure: estado=SP/year=2023/part-0.parquet
```

---

### 5. DATABASE SCHEMA RECOMMENDATIONS

#### Normalized Schema Design
```sql
-- MAIN DOCUMENTS TABLE
CREATE TABLE documents (
    id BIGSERIAL PRIMARY KEY,
    urn TEXT UNIQUE NOT NULL,
    titulo TEXT NOT NULL,
    ementa TEXT,  -- Legal abstract (main content)
    numero VARCHAR(50),

    -- Foreign keys to normalized tables
    tipo_id INTEGER REFERENCES tipos_documento(id),
    estado_id INTEGER REFERENCES estados_brasil(id),
    municipio_id INTEGER REFERENCES municipios_brasil(id),
    orgao_emissor_id INTEGER REFERENCES orgaos_emissores(id),

    -- Temporal fields
    data_publicacao DATE NOT NULL,
    ano INTEGER NOT NULL GENERATED ALWAYS AS (EXTRACT(YEAR FROM data_publicacao)) STORED,
    mes INTEGER GENERATED ALWAYS AS (EXTRACT(MONTH FROM data_publicacao)) STORED,

    -- Full-text search
    search_vector TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('portuguese',
            coalesce(titulo, '') || ' ' || coalesce(ementa, '')
        )
    ) STORED,

    -- Metadata
    fonte VARCHAR(50) DEFAULT 'LexML',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- NORMALIZED REFERENCE TABLES
CREATE TABLE tipos_documento (
    id SERIAL PRIMARY KEY,
    tipo VARCHAR(100) UNIQUE NOT NULL,
    descricao TEXT,
    hierarquia INTEGER  -- Legal hierarchy level
);

CREATE TABLE estados_brasil (
    id SERIAL PRIMARY KEY,
    codigo VARCHAR(2) UNIQUE NOT NULL,  -- SP, RJ, MG
    nome VARCHAR(100) NOT NULL,  -- São Paulo
    regiao VARCHAR(20) NOT NULL,  -- Sudeste
    populacao INTEGER,
    area_km2 NUMERIC(12,2)
);

CREATE TABLE municipios_brasil (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(200) NOT NULL,
    estado_id INTEGER REFERENCES estados_brasil(id),
    codigo_ibge INTEGER UNIQUE,
    populacao INTEGER,
    UNIQUE(nome, estado_id)
);

CREATE TABLE orgaos_emissores (
    id SERIAL PRIMARY KEY,
    nome TEXT UNIQUE NOT NULL,
    tipo VARCHAR(50),  -- Federal, Estadual, Municipal
    esfera VARCHAR(20),  -- Executivo, Legislativo, Judiciário
    estado_id INTEGER REFERENCES estados_brasil(id)
);
```

**NORMALIZATION BENEFITS:**
- Eliminates data redundancy (estado names repeated 134k times)
- Ensures data consistency (no typos in state names)
- Enables cascading updates
- Reduces storage by ~30-40%
- Improves query performance with integer foreign keys

**MIGRATION COMPLEXITY:** Medium (requires data transformation)

---

### 6. QUERY OPTIMIZATION ANALYSIS

#### Current Query Patterns (from queries.R)

**❌ PROBLEMATIC QUERY #1: get_documents()**
```r
# Line 23-25: Unoptimized SELECT
sql_query <- "SELECT id, urn, titulo, content, tipo, ano, data_publicacao,
                     orgao_emissor, estado, municipio, fonte, created_at
              FROM documents"
```

**ISSUES:**
- Selects ALL columns even when not needed
- No explicit index hints
- Uses string concatenation for WHERE clauses (SQL injection risk)
- No query plan caching

**OPTIMIZED VERSION:**
```sql
-- Use prepared statements with placeholders
-- Only select needed columns
-- Add index hints
SELECT
    d.id, d.urn, d.titulo,
    SUBSTRING(d.content, 1, 500) as content_preview,  -- Limit content
    d.tipo, d.ano, d.estado
FROM documents d
WHERE
    (d.estado = $1 OR $1 IS NULL)
    AND (d.tipo = $2 OR $2 IS NULL)
    AND (d.ano BETWEEN $3 AND $4)
ORDER BY d.data_publicacao DESC
LIMIT $5 OFFSET $6;
```

**❌ PROBLEMATIC QUERY #2: search_documents()**
```r
# Line 171-172: Inefficient full-text search
ts_rank(to_tsvector('portuguese', COALESCE(d.content, '') || ' ' || COALESCE(d.titulo, '')),
        plainto_tsquery('portuguese', $1)) as relevance
```

**ISSUES:**
- Creates tsvector on every query (no pre-computed column)
- Scans entire table even with filters
- Concatenation happens at query time

**OPTIMIZED VERSION:**
```sql
-- Use pre-computed search_vector column
SELECT
    d.id, d.titulo, d.ementa,
    ts_rank_cd(d.search_vector, query) as relevance,
    ts_headline('portuguese', d.titulo, query, 'MaxWords=15') as headline
FROM documents d,
     plainto_tsquery('portuguese', $1) query
WHERE
    d.search_vector @@ query
    AND (d.estado = $2 OR $2 IS NULL)
    AND (d.ano >= $3)
ORDER BY relevance DESC, d.data_publicacao DESC
LIMIT $4;
```

**PERFORMANCE GAINS:**
- Pre-computed tsvector: 10x-50x faster
- Index usage: 100x-1000x faster on large datasets
- Headline generation: Only on results (not entire table)

---

### 7. ENCODING VERIFICATION CHECKLIST

```sql
-- ✅ Verify database encoding
SHOW server_encoding;  -- Should return UTF8

-- ✅ Verify collation
SHOW lc_collate;  -- Should return pt_BR.UTF-8 or en_US.UTF-8
SHOW lc_ctype;    -- Should return pt_BR.UTF-8 or en_US.UTF-8

-- ⚠️ Set Brazilian Portuguese collation for sorting
CREATE COLLATION IF NOT EXISTS pt_br (
    provider = 'icu',
    locale = 'pt-BR'
);

-- ✅ Test diacritic handling
SELECT
    'São Paulo' = 'Sao Paulo' as accent_sensitive,  -- Should be FALSE
    unaccent('São Paulo') = 'Sao Paulo' as accent_removed;  -- Should be TRUE

-- ✅ Test Portuguese sorting
SELECT estado
FROM estados_brasil
ORDER BY estado COLLATE "pt_BR";  -- Correct: Acre, Alagoas, Amapá...

-- ❌ Common encoding errors to check
SELECT
    titulo,
    length(titulo) as char_count,
    octet_length(titulo) as byte_count,
    char_count != byte_count as has_multibyte_chars
FROM documents
WHERE titulo LIKE '%ã%' OR titulo LIKE '%ç%'
LIMIT 10;
```

---

### 8. POSTGRESQL EXTENSIONS REQUIRED

```sql
-- Priority: CRITICAL (Required for search)
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- Trigram search
CREATE EXTENSION IF NOT EXISTS unaccent;   -- Accent removal

-- Priority: HIGH (Performance monitoring)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;  -- Query stats

-- Priority: MEDIUM (Advanced indexing)
CREATE EXTENSION IF NOT EXISTS btree_gin;  -- Composite indexes
CREATE EXTENSION IF NOT EXISTS btree_gist; -- Spatial/range queries

-- Priority: LOW (Future features)
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- LGPD encryption
```

---

## ACTIONABLE RECOMMENDATIONS

### IMMEDIATE ACTIONS (Week 1)

#### 1. Fix CSV Documentation Issue
```bash
# Option A: Generate CSV from Parquet (recommended)
python3 database/tools/parquet_to_csv.py

# Option B: Update all documentation to reference Parquet
find . -name "*.md" -exec sed -i 's/lexml_unified_dataset.csv/parquet\/brazilian_legislative_complete.parquet/g' {} \;
```

#### 2. Install Critical Database Extensions
```bash
# Run on Google Cloud SQL via Cloud Shell
psql $DATABASE_URL -f database/000_install_extensions.sql
```

#### 3. Create Essential Indexes
```bash
# Run index creation script (provided in deliverables)
psql $DATABASE_URL -f database/migrations/001_create_essential_indexes.sql
```

#### 4. Normalize Estado Field
```bash
# Run data normalization script
psql $DATABASE_URL -f database/migrations/002_normalize_estado_field.sql
```

### SHORT-TERM ACTIONS (Week 2-4)

#### 5. Schema Migration to Normalized Design
```bash
# Backup current database
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d).sql

# Run schema migration
psql $DATABASE_URL -f database/migrations/003_normalized_schema_migration.sql
```

#### 6. Implement Full-Text Search Optimization
```bash
psql $DATABASE_URL -f database/migrations/004_fulltext_search_optimization.sql
```

#### 7. Data Quality Validation
```bash
# Run Python validation suite
python3 database/tools/validate_data_quality.py --report-path=reports/quality_report.html
```

### LONG-TERM ACTIONS (Month 2-3)

#### 8. Implement Materialized Views for Analytics
```bash
psql $DATABASE_URL -f database/migrations/005_analytics_materialized_views.sql
```

#### 9. Set Up Automated Monitoring
```bash
# Configure pg_stat_statements monitoring
python3 database/tools/setup_monitoring.py --email=alerts@mackenzie.br
```

#### 10. Optimize Parquet Partitioning
```bash
# Repartition by state and year
python3 database/tools/repartition_data.py \
    --strategy=by_state_year \
    --output=data_current/processed/production/parquet/optimized/
```

---

## RISK ASSESSMENT

### HIGH RISK ⚠️
1. **Data Loss Risk**: Schema migration without proper backup
   - **Mitigation**: Automated backup script before any migration

2. **Encoding Corruption**: Improper collation settings
   - **Mitigation**: Test on sample dataset first

3. **Query Performance Degradation**: Missing indexes during migration
   - **Mitigation**: Create indexes before removing old ones

### MEDIUM RISK ⚠️
1. **Application Downtime**: Schema changes breaking queries.R
   - **Mitigation**: Backward-compatible views during transition

2. **Storage Bloat**: Index creation on 134k records
   - **Mitigation**: Use CONCURRENTLY option, monitor disk space

### LOW RISK ✅
1. **UTF-8 Encoding**: Already properly configured in Parquet
2. **Data Quality**: High completeness scores in source data
3. **Portuguese Support**: PostgreSQL 'portuguese' config exists

---

## SUCCESS METRICS

### Performance Targets
- ✅ Full-text search: < 200ms for 90% of queries
- ✅ Geographic filter: < 100ms
- ✅ Date range queries: < 50ms
- ✅ Complex composite queries: < 500ms

### Data Quality Targets
- ✅ Estado field: 100% normalized (no 'Federal' strings)
- ✅ URN uniqueness: 100% (134,014 unique URNs)
- ✅ Date validity: 100% (all dates parseable)
- ✅ Encoding: 100% UTF-8 compliance

### Monitoring Targets
- ✅ Query monitoring: 100% of queries logged
- ✅ Slow query detection: Alerts for queries > 1s
- ✅ Connection pool health: < 5% connection failures
- ✅ Disk usage: < 80% capacity

---

## TOOLS & AUTOMATION PROVIDED

See deliverables folder for:
- ✅ `001_create_essential_indexes.sql` - Critical indexes
- ✅ `002_normalize_estado_field.sql` - Estado normalization
- ✅ `003_normalized_schema_migration.sql` - Full schema migration
- ✅ `parquet_to_csv.py` - CSV generation from Parquet
- ✅ `validate_data_quality.py` - Automated quality checks
- ✅ `setup_monitoring.py` - Performance monitoring
- ✅ `encoding_verification.sql` - UTF-8 validation queries
- ✅ `performance_benchmark.sql` - Before/after comparison

---

**Document Status:** Complete
**Next Review:** After Week 1 actions complete
**Owner:** MackIntegridade DevOps Team
**Contact:** sofia.donario@mackenzie.br
