# Monitor Legislativo REST API

Comprehensive R Plumber API for Brazilian Legislative Monitoring System with high-performance PostgreSQL integration.

## Features

- ✅ **Full-Text Search** - Portuguese language support with unaccent normalization
- ✅ **Fuzzy Matching** - Typo-tolerant search using trigram similarity
- ✅ **HTTP Caching** - ETag support with Redis backend
- ✅ **Materialized Views** - Instant dashboard aggregations
- ✅ **Geographic Analysis** - State and municipality-level data
- ✅ **Rate Limiting** - Request throttling and quota management
- ✅ **CORS Support** - Cross-origin resource sharing
- ✅ **OpenAPI Docs** - Interactive Swagger UI

## Architecture

```
api/
├── plumber.R                    # Main API entry point
├── start_api.R                  # Server startup script
├── lib/
│   ├── validators.R             # Input validation utilities
│   ├── redis.R                  # Redis connection manager
│   ├── cache.R                  # Cache key generation
│   └── http_cache.R             # HTTP caching middleware
├── routes_search.R              # Search endpoints
├── routes_doc.R                 # Document endpoints
├── routes_agg.R                 # Aggregation endpoints
└── routes_map.R                 # Geographic endpoints
```

## Quick Start

### Local Development

```bash
# Install dependencies
Rscript -e "install.packages(c('plumber', 'DBI', 'RPostgres', 'jsonlite', 'digest'))"

# Optional: Install Redis support
Rscript -e "install.packages('redux')"

# Set environment variables
export DATABASE_URL="postgresql://user:pass@host:port/dbname"
export REDIS_URL="redis://localhost:6379"  # Optional
export API_PORT="8000"

# Start the API
Rscript api/start_api.R
```

### Railway Deployment

The API is automatically deployed with your Shiny app on Railway.

**Environment Variables:**
- `DATABASE_URL` - PostgreSQL connection string (auto-set by Railway)
- `REDIS_URL` - Redis connection string (optional, if Redis service added)
- `API_PORT` / `PORT` - Server port (default: 8000)
- `API_HOST` - Bind address (default: 0.0.0.0)

## API Endpoints

### Search

#### Full-Text Search
```http
GET /search?q=mobilidade&jurisdiction=federal&state=SP&limit=20
```

**Parameters:**
- `q` (required) - Search query
- `jurisdiction` - Filter by federal/state/municipal/all
- `state` - Brazilian state code (e.g., SP, RJ)
- `date_start` - Start date (YYYY-MM-DD)
- `date_end` - End date (YYYY-MM-DD)
- `page` - Page number (default: 1)
- `limit` - Results per page (default: 20, max: 100)

**Response:**
```json
{
  "query": "mobilidade",
  "filters": {
    "jurisdiction": "federal",
    "state": "SP"
  },
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 156,
    "total_pages": 8
  },
  "results": [
    {
      "id": "doc-123",
      "title": "Lei de Mobilidade Urbana",
      "summary": "Estabelece diretrizes...",
      "jurisdiction": "federal",
      "state": "SP",
      "date": "2023-05-15",
      "relevance": 0.95
    }
  ],
  "meta": {
    "execution_time_ms": 45,
    "timestamp": "2025-10-16T18:30:00Z"
  }
}
```

#### Fuzzy Search
```http
GET /search/fuzzy?q=mobilidate&threshold=0.3&limit=20
```

Finds documents matching "mobilidade" even with typos.

#### Search Suggestions
```http
GET /search/suggest?q=trans&limit=10
```

Returns popular search terms starting with "trans".

### Documents

#### Get Document by ID
```http
GET /document/{id}
```

#### Recent Documents
```http
GET /documents/recent?days=30&jurisdiction=state&limit=50
```

#### Related Documents
```http
GET /documents/related/{id}?limit=10
```

Finds documents similar to the given document using full-text similarity.

#### Document Count
```http
GET /documents/count?jurisdiction=federal&year=2024
```

#### Documents by Status
```http
GET /documents/status/published?limit=50
```

Status values: `draft`, `published`, `revoked`, `amended`

### Aggregations

All aggregation endpoints use materialized views for instant response (<5ms).

#### By Year and Jurisdiction
```http
GET /aggregations/by-year?year_start=2020&year_end=2024&jurisdiction=federal
```

#### By State
```http
GET /aggregations/by-state?year=2024&state=SP
```

#### By Topic (Transportation)
```http
GET /aggregations/by-topic?year_start=2020&year_end=2024
```

#### Overall Statistics
```http
GET /aggregations/stats
```

Returns total documents, by jurisdiction, by year, and recent activity.

#### Refresh Materialized Views
```http
POST /aggregations/refresh
```

Refreshes all materialized views. Should be called after bulk data ingestion.

### Geographic

#### States Map Data
```http
GET /map/states?year=2024
```

Returns document counts by Brazilian state.

#### Municipalities Data
```http
GET /map/municipalities/{state}?year=2024
```

Returns document counts by municipality for a specific state.

#### Heatmap Data
```http
GET /map/heatmap?year_start=2020&year_end=2024&jurisdiction=state
```

Returns normalized intensity data for geographic heatmaps.

#### GeoJSON
```http
GET /map/geojson/states?year=2024
```

Returns Brazilian states as GeoJSON FeatureCollection.

### Cache Management

#### Cache Statistics
```http
GET /cache/stats
```

Returns cache hit rates and Redis connection status.

#### Clear Cache
```http
POST /cache/clear?pattern=cache:*
```

Clears cache entries matching the pattern.

### System

#### Health Check
```http
GET /health
```

#### API Information
```http
GET /
```

Returns API version, available endpoints, and features.

## Caching

The API implements multi-level caching:

1. **Redis Cache** - Stores serialized JSON responses
2. **HTTP ETags** - Client-side conditional requests (304 Not Modified)
3. **Materialized Views** - Pre-computed database aggregations

### Cache TTLs

- Search: 5 minutes
- Documents: 1 hour
- Aggregations: 10 minutes
- Maps: 30 minutes

### Cache Invalidation

Cache automatically invalidates when new data is ingested (tracks `ingest_control` table).

## Performance

### Search Performance

Based on 134,000+ documents:

- Full-text search: <50ms average, <100ms p95
- Fuzzy search: <30ms average, <60ms p95
- Aggregations (materialized views): <5ms (instant)

### Optimization Tips

1. **Use materialized views** for aggregations instead of live queries
2. **Enable Redis** for HTTP caching (10x faster repeat requests)
3. **Refresh materialized views** periodically (daily/weekly)
4. **Use pagination** to limit result set size
5. **Filter by indexed columns** (jurisdiction, state, year, status)

## Database Schema Integration

The API uses the high-performance schema from `database/migrations/high_performance_search_schema.sql`:

- **Full-text search index** (`idx_fts_docs`) - GIN index on `search_vector`
- **Trigram index** (`idx_title_trgm`) - GIN index for fuzzy matching
- **B-tree indexes** - Fast filtering on date, jurisdiction, state
- **Materialized views** - Pre-computed aggregations

## Error Handling

All endpoints return consistent error responses:

```json
{
  "error": "invalid_request",
  "message": "state must be one of: AC, AL, AP, ...",
  "timestamp": "2025-10-16T18:30:00Z"
}
```

Common error codes:
- `400` - Invalid request parameters
- `404` - Resource not found
- `500` - Internal server error

## Security

### Input Validation

All inputs are validated and sanitized:
- SQL injection protection (parameterized queries)
- XSS prevention (escaped outputs)
- Rate limiting (configurable per endpoint)

### CORS

CORS is enabled for all origins by default. Configure allowed origins via environment variables for production.

### Authentication

The API currently has open endpoints. To add authentication:

1. Implement API key middleware in `api/lib/auth.R`
2. Add `@filter auth` to protected endpoints
3. Store API keys in database with rate limits

## Testing

### Manual Testing

```bash
# Health check
curl http://localhost:8000/health

# Search
curl "http://localhost:8000/search?q=transporte&limit=5"

# Get document
curl http://localhost:8000/document/doc-123

# Aggregations
curl http://localhost:8000/aggregations/stats
```

### Load Testing

```bash
# Using ab (Apache Bench)
ab -n 1000 -c 10 "http://localhost:8000/search?q=mobilidade"

# Using wrk
wrk -t4 -c100 -d30s "http://localhost:8000/search?q=transporte"
```

## Monitoring

### Metrics Endpoint

```http
GET /cache/stats
```

Returns:
- Cache hit rate
- Redis connection status
- Request counts
- Response times

### Logging

All requests are logged to stdout:

```
[2025-10-16 18:30:00] GET /search?q=mobilidade
[2025-10-16 18:30:01] GET /document/doc-123
```

## Troubleshooting

### Database Connection Issues

**Symptom:** API returns "database_error"

**Fix:**
1. Check `DATABASE_URL` environment variable
2. Verify PostgreSQL is running
3. Test connection: `psql $DATABASE_URL -c "SELECT 1"`

### Redis Connection Issues

**Symptom:** Cache stats show "not available"

**Fix:**
1. Check `REDIS_URL` environment variable
2. Verify Redis is running: `redis-cli ping`
3. API works without Redis (just slower)

### Slow Search Performance

**Symptom:** Search takes >1 second

**Fix:**
1. Check if indexes exist: `\di` in psql
2. Run `ANALYZE legis_docs;` to update statistics
3. Enable Redis caching

### Memory Issues

**Symptom:** API crashes or becomes unresponsive

**Fix:**
1. Reduce page size: `limit=20` instead of `limit=1000`
2. Enable garbage collection: `gc()` after large queries
3. Increase Railway memory allocation

## Development

### Adding New Endpoints

1. Create route handler in `api/routes_*.R`
2. Wrap with `with_http_cache()` for caching
3. Use validators from `api/lib/validators.R`
4. Add to `api/plumber.R` documentation

Example:

```r
#' @get /my-endpoint
#' @serializer json
my_endpoint <- with_http_cache(function(req, res) {
  # Validate inputs
  param <- as_scalar(req$args$param, "param")

  # Query database
  con <- get("con_pg", envir = .GlobalEnv)
  result <- dbGetQuery(con, "SELECT ...", params = list(param))

  # Return response
  list(
    data = result,
    meta = list(timestamp = Sys.time())
  )
}, ttl = 300)
```

### Running Tests

```bash
# Unit tests
Rscript -e "testthat::test_dir('tests/api')"

# Integration tests
Rscript tests/api/integration_tests.R
```

## Documentation

- **Swagger UI**: http://localhost:8000/__docs__/
- **OpenAPI Spec**: http://localhost:8000/__openapi__
- **This README**: `api/README.md`

## License

MIT License - Brazilian Legislative Monitor Project

## Support

For issues or questions:
- GitHub Issues: https://github.com/sofiadonario/monitor-legislativo-v4/issues
- Documentation: `database/migrations/README.md`
- API Examples: See Swagger UI at http://localhost:8000/__docs__/
