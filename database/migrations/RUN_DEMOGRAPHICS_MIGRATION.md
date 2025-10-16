# Quick Start: Bills Per 100K Migration

## TL;DR

```bash
# Run the migration
Rscript database/migrations/add_demographics.R

# Test the API
curl "http://localhost:8000/api/v1/map/choropleth?metric=bills_per_100k&year=2023"
```

## Step-by-Step Instructions

### 1. Set Database Connection

Choose one option:

**Option A: Using DATABASE_URL** (Railway style)
```bash
export DATABASE_URL="postgresql://user:pass@host:port/dbname"
```

**Option B: Using Individual Variables** (Standard PostgreSQL)
```bash
export PGDATABASE="legis"
export PGHOST="localhost"
export PGUSER="postgres"
export PGPASSWORD="your_password"
export PGPORT="5432"
```

### 2. Run Migration

```bash
Rscript database/migrations/add_demographics.R
```

**Expected Output:**
```
================================================================================
ADDING DEMOGRAPHICS AND BILLS PER 100K METRIC
================================================================================

📋 Connecting to PostgreSQL...
✅ Connected to PostgreSQL

📄 Reading migration file...
🔧 Running migration...

✅ Migration completed successfully!

🔍 Verifying migration...
   Demographics table: 135 rows
   Density view: 67 rows

📊 Sample data (top 5 states by bills per 100k in 2023):
  state year n_docs population bills_per_100k
1    DF 2023   1193    2817068          42.35
2    SC 2023   2909    7610361          38.21
3    RO 2023    593    1657996          35.76
4    AC 2023    300     830026          36.14
5    ES 2023   1287    3833712          33.56

================================================================================
MIGRATION COMPLETE
================================================================================
```

### 3. Verify in Database

```bash
# Connect to database
psql $DATABASE_URL

# Check demographics table
SELECT state, year, population FROM demographics WHERE year = 2024 LIMIT 5;

# Check density view
SELECT state, year, n_docs, population, bills_per_100k
FROM mv_docs_state_density
WHERE year = 2023
ORDER BY bills_per_100k DESC
LIMIT 10;
```

### 4. Test API Endpoint

```bash
# Test with curl
curl "http://localhost:8000/api/v1/map/choropleth?metric=bills_per_100k&year=2023" | jq

# Or with httpie
http GET "localhost:8000/api/v1/map/choropleth?metric=bills_per_100k&year=2023"
```

**Expected Response:**
```json
{
  "meta": {
    "geo": "estado",
    "metric": "bills_per_100k",
    "year": 2023
  },
  "features": [
    {"id": "DF", "value": 42.35},
    {"id": "SC", "value": 38.21},
    {"id": "RO", "value": 35.76}
  ]
}
```

## Railway Deployment

The migration will run automatically on Railway if the `demographics` table doesn't exist.

To force recreation on Railway:
```bash
# Add environment variable in Railway dashboard
FORCE_RECREATE=true
```

## Troubleshooting

### "Demographics table already exists"

```bash
# Force recreation
FORCE_RECREATE=true Rscript database/migrations/add_demographics.R
```

### "No database connection details found"

Make sure you set either `DATABASE_URL` or `PGDATABASE`/`PGHOST`:

```bash
export PGDATABASE="legis"
export PGHOST="localhost"
```

### View returns empty data

Check if source views exist:

```sql
-- Check if mv_docs_state_year has data
SELECT COUNT(*) FROM mv_docs_state_year;

-- If empty, refresh base views first
REFRESH MATERIALIZED VIEW mv_docs_year_juris;
REFRESH MATERIALIZED VIEW mv_docs_state_year;
REFRESH MATERIALIZED VIEW mv_docs_state_density;
```

## Maintenance

### Refresh After Data Ingestion

```sql
SELECT refresh_density_view();
```

### Add New Year Data

```sql
-- Add 2025 population
INSERT INTO demographics (state, year, population) VALUES
('SP', 2025, 44500000),
-- ... other states
;

-- Refresh view
SELECT refresh_density_view();
```

## Complete Documentation

For complete documentation, see:
- **DEMOGRAPHICS_README.md** - Full feature documentation
- **add_demographics_and_density.sql** - SQL migration with comments
- **api/README.md** - API endpoint documentation

## Summary

✅ **What you get:**
- Demographics table with 5 years of population data
- Bills per 100k materialized view
- API endpoint for choropleth maps
- Helper function for refreshing data

✅ **What you can do:**
- Compare states fairly regardless of size
- Visualize normalized legislative activity
- Track per-capita trends over time
- Identify states with disproportionate activity

✅ **API Usage:**
```http
GET /api/v1/map/choropleth?metric=bills_per_100k&year=2023
```
