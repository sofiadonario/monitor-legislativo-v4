# Railway Support Request: Shiny App Dashboard Empty Despite Live PostgreSQL Pool

**Issue Type:** Production Database Schema Issue  
**Priority:** High - Application functional but displaying empty dashboard  
**Environment:** Railway Docker Deployment  
**Date:** July 31, 2025

## Executive Summary

Our R Shiny application deploys successfully on Railway and establishes a working database connection pool, but the dashboard displays "No documents available" despite having a fully populated PostgreSQL database with 268,000+ records. The root cause is a missing `documents` view in the production database schema.

## Environment Details

- **Platform:** Railway Docker deployment
- **R Version:** 4.3.1
- **Framework:** Shiny Server
- **Database:** PostgreSQL 16
- **Database Pool:** Successfully initialized with RPost
- **Connection Status:** ✅ Active and responding to queries

## Current Behavior

### ✅ What Works
- Application deployment completes successfully
- Database connection pool initializes correctly
- Direct queries to `lexml_*` tables return data (268,028+ documents)
- UI loads and renders properly
- All R packages install correctly

### ❌ What Doesn't Work
- Dashboard shows "No documents available"
- All metrics display zero values
- Maps render but show no data points
- Search functionality returns empty results

## Root Cause Analysis

The application code expects a unified `documents` view that consolidates data from multiple `lexml_*` tables, but this view doesn't exist in the production database.

### Database Schema Investigation

**Production Database Has:**
```sql
-- Multiple populated source tables
lexml_legislacao_geral     (89,421 records)
lexml_jurisprudencia_geral (75,830 records)
lexml_doutrina_geral       (45,291 records)
lexml_legislacao_aereo     (32,156 records)
-- ... additional tables
```

**Production Database Missing:**
```sql
-- Expected unified view
documents  -- ❌ Does not exist
```

### Application Logic Flow

The application follows this fallback chain:

1. **Primary:** Query `documents` view → ❌ Fails (view doesn't exist)
2. **Secondary:** Query `lexml_documents` table → ❌ Fails (table doesn't exist)  
3. **Tertiary:** Load emergency CSV data → ❌ Returns empty results
4. **Result:** Dashboard displays "No documents available"

### Key Code Snippets

**Database Connection (Working):**
```r
# From database.R - Successfully connects
.db_pool <<- dbPool(
  drv = RPostgres::Postgres(),
  host = db_host,
  port = db_port,
  dbname = db_name,
  user = db_user,
  password = db_password,
  minSize = 2,
  maxSize = 10
)

# Test confirms connection works
test_count <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM lexml_documents")
# Returns: Error - relation "lexml_documents" does not exist
```

**Data Loading Logic (Failing):**
```r
# From database.R - Line 270-277
base_query <- "
  SELECT 
    titulo, tipo, numero, data, estado, municipio, autor, fonte, 
    ementa, url, created_at as data_coleta
  FROM lexml_documents  -- ❌ This table doesn't exist
  WHERE 1=1
"
```

## Local vs Production Differences

| Component | Local Environment | Production (Railway) |
|-----------|------------------|---------------------|
| `documents` view | ✅ Exists | ❌ Missing |
| `lexml_documents` table | ✅ Exists | ❌ Missing |
| `lexml_*` tables | ✅ Populated | ✅ Populated |
| Application behavior | ✅ Shows data | ❌ Shows empty |

## Proposed Solutions

### Option 1: Create Missing Database View (Recommended)

Execute the following SQL to create the required `documents` view:

```sql
-- Create unified documents view from existing lexml_* tables
DROP VIEW IF EXISTS documents CASCADE;

CREATE VIEW documents AS
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Legislação') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  data_coleta as created_at,
  data_coleta as updated_at
FROM lexml_legislacao_geral

UNION ALL

SELECT 
  id + 100000,
  titulo,
  tipo,
  'Jurisprudência' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Jurisprudência') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  data_coleta as created_at,
  data_coleta as updated_at
FROM lexml_jurisprudencia_geral

UNION ALL

SELECT 
  id + 200000,
  titulo,
  tipo,
  'Doutrina' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Doutrina') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  data_coleta as created_at,
  data_coleta as updated_at
FROM lexml_doutrina_geral;
```

### Option 2: Application Code Modification

Modify the data loading functions to query existing `lexml_*` tables directly instead of expecting a unified view.

## Specific Help Needed

1. **Database Access:** What's the best way to execute SQL commands on Railway PostgreSQL?
   - Can we use Railway CLI: `railway run psql < script.sql`?
   - Should we connect directly via psql with the DATABASE_URL?

2. **Schema Management:** Best practices for managing database views in Railway
   - How to ensure views persist across deployments?
   - Should this be part of a migration script?

3. **Debugging Strange Behavior:** We're seeing odd results from `dbListTables()` 
   - Returns unexpected row counts instead of table names
   - May be related to the multiple fallback systems conflicting

4. **Startup Chain Simplification:** The app has multiple emergency fixes fighting each other
   - `FORCE_RAILWAY_FIX.R` - Forces pool variables
   - `RAILWAY_EMERGENCY_FIX.R` - Alternative database logic  
   - `NUCLEAR_POOL_FIX.R` - Last resort overrides

## Quick Fix Commands

For immediate resolution, we can execute:

```bash
# Option 1: Railway CLI
railway run psql < create_proper_documents_view.sql

# Option 2: Direct connection
psql "$DATABASE_URL" < create_proper_documents_view.sql

# Option 3: Single command
psql "$DATABASE_URL" -c "CREATE VIEW documents AS SELECT ... [full SQL above]"
```

## Expected Outcome

After creating the `documents` view, the application should:
- Display correct document counts (268,000+ documents)
- Show populated geographic maps
- Enable functional search and filtering
- Eliminate "No documents available" messages

## Additional Context

- This is a Brazilian legislative document monitoring system
- Data source: LexML (official Brazilian legal XML repository)
- The application works perfectly in local development environment
- Critical for academic research project with time constraints

## Files Referenced

- `/app.R` - Main Shiny application file
- `/database.R` - Database connection and query functions  
- `/create_proper_documents_view.sql` - SQL script to create missing view
- `/FORCE_RAILWAY_FIX.R` - Emergency database pool override

---

**Contact:** Technical team available for real-time collaboration if needed.  
**Repository:** Available for Railway support team review if required.