# Monitor Legislativo API Endpoints

**Production URL:** https://monitor-legislativo-unified-production.up.railway.app

## Quick Test Commands

### Health Check
```bash
curl https://monitor-legislativo-unified-production.up.railway.app/health
```

### API Information
```bash
curl https://monitor-legislativo-unified-production.up.railway.app/api/v1/ | jq
```

## Search Endpoints

### Full-Text Search
```bash
# Search for "mobilidade"
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/search?q=mobilidade&page_size=10" | jq

# Search with filters
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/search?q=transporte&scope=federal&date_from=2023-01-01&sort=recency" | jq
```

**Parameters:**
- `q` - Search query (required)
- `scope` - federal|state|municipal
- `date_from` - YYYY-MM-DD
- `date_to` - YYYY-MM-DD
- `page` - Page number (default: 1)
- `page_size` - Results per page (default: 25, max: 100)
- `sort` - relevance|recency

## Document Endpoints

### Get Single Document
```bash
# Replace {id} with actual document ID
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/legis/{id}" | jq
```

## Aggregation Endpoints

### Document Counts by Year
```bash
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/agg/counts?group_by=year" | jq
```

### Document Counts by Jurisdiction
```bash
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/agg/counts?group_by=jurisdiction" | jq
```

### Document Counts by State
```bash
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/agg/counts?group_by=state" | jq
```

### With Date Filters
```bash
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/agg/counts?group_by=year&date_from=2020-01-01&date_to=2024-12-31" | jq
```

## Map Endpoints (Choropleth)

### Raw Document Counts by State
```bash
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/map/choropleth?metric=n_docs&year=2023" | jq
```

### Bills Per 100K Population (After Migration)
```bash
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/map/choropleth?metric=bills_per_100k&year=2023" | jq
```

**Parameters:**
- `geo` - estado|municipio (default: estado)
- `metric` - n_docs|bills_per_100k (default: n_docs)
- `year` - Filter by specific year (optional)

## Interactive Documentation

### Swagger UI
```
https://monitor-legislativo-unified-production.up.railway.app/__docs__/
```

Open in browser to see interactive API documentation with try-it-out functionality.

## Example Workflows

### 1. Search and Get Document Details
```bash
# Step 1: Search for documents
RESULTS=$(curl -s "https://monitor-legislativo-unified-production.up.railway.app/api/v1/search?q=mobilidade&page_size=1")

# Step 2: Extract first document ID
DOC_ID=$(echo $RESULTS | jq -r '.items[0].id')

# Step 3: Get full document details
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/legis/$DOC_ID" | jq
```

### 2. Compare States by Legislative Activity
```bash
# Get raw counts
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/agg/counts?group_by=state" | jq '.buckets | sort_by(.count) | reverse | .[0:5]'

# Get normalized by population (after migration)
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/map/choropleth?metric=bills_per_100k&year=2023" | jq '.features | sort_by(.value) | reverse | .[0:5]'
```

### 3. Track Temporal Trends
```bash
# Documents by year
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/agg/counts?group_by=year&date_from=2020-01-01" | jq '.buckets'
```

## Testing Bills Per 100K (After Running Migration)

### Run Migration Remotely
```bash
# Connect to Railway PostgreSQL
# Get DATABASE_URL from Railway dashboard, then:
export DATABASE_URL="postgresql://postgres:..."

# Run migration
Rscript database/migrations/add_demographics.R
```

### Test the Endpoint
```bash
# Should return normalized rates
curl "https://monitor-legislativo-unified-production.up.railway.app/api/v1/map/choropleth?metric=bills_per_100k&year=2023" | jq

# Expected response format:
# {
#   "meta": {
#     "geo": "estado",
#     "metric": "bills_per_100k",
#     "year": 2023
#   },
#   "features": [
#     {"id": "DF", "value": 42.35},
#     {"id": "SC", "value": 38.21},
#     ...
#   ]
# }
```

## Performance Tips

1. **Use pagination** for search results (max 100 items per page)
2. **Cache results** client-side when possible (API sends ETag headers)
3. **Filter by year** for faster aggregations
4. **Use specific scopes** (federal/state/municipal) to reduce result sets

## Response Times (Expected)

- Health check: <10ms
- Search: 50-100ms
- Document retrieval: 20-50ms
- Aggregations: <5ms (materialized views)
- Map/choropleth: 10-20ms

## Error Handling

All endpoints return consistent error format:

```json
{
  "error": "error_type",
  "message": "Human-readable error message",
  "request_id": "optional-request-id"
}
```

**Common HTTP Status Codes:**
- `200` - Success
- `404` - Resource not found
- `422` - Invalid request (validation error)
- `500` - Server error

## Rate Limiting

Currently no rate limiting is enforced. If you need to make bulk requests, please:
1. Use pagination appropriately
2. Add delays between requests (100-200ms)
3. Cache results when possible

## Support

- **GitHub Issues:** https://github.com/sofiadonario/monitor-legislativo-v4/issues
- **API Documentation:** `api/README.md`
- **Database Schema:** `database/migrations/README.md`

## Quick Reference Card

**Base URL:** `https://monitor-legislativo-unified-production.up.railway.app`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/v1/search` | GET | Full-text search |
| `/api/v1/legis/{id}` | GET | Get document |
| `/api/v1/agg/counts` | GET | Aggregated counts |
| `/api/v1/map/choropleth` | GET | Map data |
| `/__docs__/` | GET | Swagger UI |
