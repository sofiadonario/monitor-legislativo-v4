# Bills Per 100K Population Metric

Complete guide for enabling and using the **bills per 100,000 inhabitants** metric for Brazilian state legislative analysis.

## Overview

This feature adds population demographics for Brazilian states and calculates legislative activity normalized by population, enabling fair comparisons between states of different sizes.

## What's Included

1. **`demographics` table** - Population data for 27 Brazilian states (2020-2024)
2. **`mv_docs_state_density` materialized view** - Pre-calculated bills per 100k metric
3. **API endpoint** - `/api/v1/map/choropleth?metric=bills_per_100k`
4. **Refresh function** - `refresh_density_view()` for easy updates

## Installation

### Option 1: Automatic (Railway Deployment)

The migration runs automatically when deploying to Railway if the demographics table doesn't exist yet.

### Option 2: Manual Execution (Local or Remote)

#### Using R Script (Recommended)

```bash
# Set database connection
export PGDATABASE="legis"
export PGHOST="localhost"
export PGUSER="postgres"
export PGPASSWORD="your_password"
export PGPORT="5432"

# Run migration
Rscript database/migrations/add_demographics.R
```

#### Using psql (Direct SQL)

```bash
psql -d legis -f database/migrations/add_demographics_and_density.sql
```

#### Force Recreation (if table already exists)

```bash
FORCE_RECREATE=true Rscript database/migrations/add_demographics.R
```

## Database Schema

### Demographics Table

```sql
CREATE TABLE demographics (
    state VARCHAR(2) NOT NULL,           -- State code (e.g., 'SP', 'RJ')
    year INTEGER NOT NULL,               -- Year
    population BIGINT NOT NULL,          -- Population count
    source VARCHAR(100) DEFAULT 'IBGE',  -- Data source
    updated_at TIMESTAMP DEFAULT NOW(),  -- Last update
    PRIMARY KEY (state, year)
);
```

**Data Source:** IBGE (Instituto Brasileiro de Geografia e Estatística)

**Coverage:** 2020-2024 (all 27 Brazilian states)

### Materialized View

```sql
CREATE MATERIALIZED VIEW mv_docs_state_density AS
SELECT
    s.state,
    s.year,
    s.n_docs,                           -- Total bills
    d.population,                        -- Population
    ROUND((s.n_docs::numeric / d.population::numeric * 100000), 2) AS bills_per_100k
FROM mv_docs_state_year s
INNER JOIN demographics d ON s.state = d.state AND s.year = d.year
WHERE s.state IS NOT NULL
ORDER BY s.year DESC, bills_per_100k DESC;
```

## API Usage

### Get Bills Per 100K Choropleth Data

```http
GET /api/v1/map/choropleth?metric=bills_per_100k&year=2023
```

**Parameters:**
- `geo`: `estado` or `municipio` (default: `estado`)
- `metric`: `bills_per_100k` or `n_docs` (default: `n_docs`)
- `year`: Filter by specific year (optional)

**Response:**
```json
{
  "meta": {
    "geo": "estado",
    "metric": "bills_per_100k",
    "year": 2023
  },
  "features": [
    {
      "id": "DF",
      "value": 42.35
    },
    {
      "id": "SC",
      "value": 38.21
    }
  ]
}
```

### Example: Compare States by Population-Normalized Activity

```http
GET /api/v1/map/choropleth?metric=bills_per_100k&year=2023
```

This shows which states have the highest legislative activity **relative to their population**, not just raw counts.

## SQL Queries

### View All Density Data

```sql
SELECT * FROM mv_docs_state_density
WHERE year = 2023
ORDER BY bills_per_100k DESC;
```

### Top 10 States by Bills Per Capita

```sql
SELECT
    state,
    year,
    n_docs AS total_bills,
    population,
    bills_per_100k
FROM mv_docs_state_density
WHERE year = 2023
ORDER BY bills_per_100k DESC
LIMIT 10;
```

### Compare Raw vs Normalized Metrics

```sql
SELECT
    state,
    year,
    n_docs AS raw_count,
    bills_per_100k AS normalized_rate,
    RANK() OVER (PARTITION BY year ORDER BY n_docs DESC) AS rank_by_count,
    RANK() OVER (PARTITION BY year ORDER BY bills_per_100k DESC) AS rank_by_rate
FROM mv_docs_state_density
WHERE year = 2023
ORDER BY bills_per_100k DESC;
```

## Maintenance

### Refresh After Data Ingestion

When new legislative documents are ingested, refresh the materialized view:

```sql
-- Using helper function
SELECT refresh_density_view();

-- Or directly
REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_state_density;
```

### Add Population Data for New Year

```sql
-- Add 2025 population estimates
INSERT INTO demographics (state, year, population) VALUES
('AC', 2025, 832000),
('AL', 2025, 3130000),
-- ... (all 27 states)
('TO', 2025, 1513000);

-- Refresh the view
SELECT refresh_density_view();
```

### Update Existing Population Data

```sql
-- Correct a population value
UPDATE demographics
SET population = 44500000, updated_at = CURRENT_TIMESTAMP
WHERE state = 'SP' AND year = 2024;

-- Refresh the view
SELECT refresh_density_view();
```

## Interpretation Guide

### What Does "Bills Per 100K" Mean?

This metric normalizes legislative activity by population:

- **Bills Per 100K = (Total Bills / Population) × 100,000**

### Example:

- **São Paulo (SP)**: 1,000 bills, 44M population = **2.25 bills per 100k**
- **Acre (AC)**: 300 bills, 830k population = **36.14 bills per 100k**

Despite SP having more raw bills, AC has higher legislative activity **relative to its population**.

### Use Cases:

1. **Fair State Comparisons** - Compare legislative productivity regardless of state size
2. **Resource Allocation** - Identify states with disproportionate legislative activity
3. **Trend Analysis** - Track how normalized activity changes over time
4. **Efficiency Metrics** - Assess legislative output relative to constituency size

## Data Sources

### Population Data

**Primary Source:** IBGE (Instituto Brasileiro de Geografia e Estatística)
- 2020-2022: Census and official estimates
- 2023: Official population projections
- 2024: Projected estimates

**Update Frequency:** Annual (typically released in August)

**Reliability:** Official government statistics, used for federal budget allocation

### Updating Population Data

IBGE releases new population estimates annually. To update:

1. Download latest estimates from [IBGE website](https://www.ibge.gov.br/estatisticas/sociais/populacao.html)
2. Add new year to demographics table
3. Refresh materialized view

## Performance

### Query Performance

- **Demographics table lookup**: <1ms (indexed by state and year)
- **Materialized view query**: <5ms (pre-calculated values)
- **API endpoint response**: ~10-20ms (including caching)

### Storage

- Demographics table: ~5KB (27 states × 5 years)
- Materialized view: ~50KB (depends on document count)

### Refresh Time

- Materialized view refresh: 50-200ms (concurrent, non-blocking)

## Troubleshooting

### Migration Fails: "relation already exists"

The table already exists. Use force recreation:

```bash
FORCE_RECREATE=true Rscript database/migrations/add_demographics.R
```

### View Returns No Data

Check if both source tables have data:

```sql
-- Check document counts
SELECT COUNT(*) FROM mv_docs_state_year;

-- Check demographics
SELECT COUNT(*) FROM demographics;

-- Check join results
SELECT s.state, s.year, d.population
FROM mv_docs_state_year s
LEFT JOIN demographics d ON s.state = d.state AND s.year = d.year
WHERE d.population IS NULL;
```

### Bills Per 100K Values Seem Wrong

Verify source data:

```sql
SELECT
    s.state,
    s.year,
    s.n_docs,
    d.population,
    (s.n_docs::numeric / d.population::numeric * 100000) AS calculated_rate,
    v.bills_per_100k AS view_rate
FROM mv_docs_state_year s
JOIN demographics d ON s.state = d.state AND s.year = d.year
JOIN mv_docs_state_density v ON v.state = s.state AND v.year = s.year
WHERE s.year = 2023
LIMIT 5;
```

## Example Visualizations

### Choropleth Map (Recommended)

Use the API endpoint to power a choropleth map showing bills per 100k:

```javascript
fetch('/api/v1/map/choropleth?metric=bills_per_100k&year=2023')
  .then(res => res.json())
  .then(data => {
    // data.features contains [{id: "SP", value: 2.25}, ...]
    renderChoropleth(data.features);
  });
```

### Time Series Comparison

Compare normalized trends over time:

```sql
SELECT
    year,
    AVG(bills_per_100k) AS national_avg,
    MAX(bills_per_100k) AS highest,
    MIN(bills_per_100k) AS lowest
FROM mv_docs_state_density
GROUP BY year
ORDER BY year;
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/sofiadonario/monitor-legislativo-v4/issues
- Database Schema Documentation: `database/migrations/README.md`
- API Documentation: `api/README.md`

## License

Population data: Public domain (IBGE)
Implementation: MIT License - Brazilian Legislative Monitor Project
