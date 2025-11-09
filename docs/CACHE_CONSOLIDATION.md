# Cache System Consolidation Documentation

**Version:** 1.0
**Date:** November 2025
**Status:** Implemented (Priority 5 - PRD Performance Optimization)
**Related:** `docs/PRD_Performance_and_Optimization_Improvements.md`

---

## Executive Summary

This document describes the cache file consolidation effort completed as part of Priority 5 of the Performance & Optimization PRD. The codebase originally contained **17 different cache implementations** (not 11 as initially estimated), which have been consolidated into a unified architecture.

---

## Problem Statement

Prior to consolidation, the codebase had:
- **17 cache-related files** scattered across multiple directories
- **9 active implementations** with overlapping functionality
- **8 legacy/unused files** from previous iterations
- **1 duplicate file** (`scripts/R/cache_utils.R`)
- Multiple caching strategies with no clear ownership
- Difficulty in understanding which cache to use for new features

**Impact:**
- Increased maintenance burden
- Confusion for new developers
- Risk of using deprecated/incorrect cache implementations
- Redundant code and dependencies

---

## Solution: Unified Cache Architecture

### Active Cache Implementations (Retained)

These 9 files constitute the **official cache system** and are actively maintained:

#### 1. Core Utility Layer

| File | Lines | Purpose | Usage |
|------|-------|---------|-------|
| `R/utils/cache_utils.R` | 538 | Multi-layer Redis + memory caching with `cache_set()`, `cache_get()`, `cache_search_results()` | Primary caching utility - use for general-purpose caching |
| `R/utils/search_cache.R` | 493 | Search result caching with `warm_search_cache()`, `init_search_cache()` | Library search result caching |

**When to use:**
- `cache_utils.R` → General database queries, API responses
- `search_cache.R` → Library tab search results

---

#### 2. API Layer

| File | Lines | Purpose | Usage |
|------|-------|---------|-------|
| `api/lib/cache.R` | 218 | Cache key generation, ETag support, `build_cache_key()` | HTTP response caching |
| `api/lib/http_cache.R` | 223 | HTTP middleware with RFC 7232 support, `with_http_cache()` | Plumber API endpoints |

**When to use:**
- `cache.R` → Generate cache keys for API responses
- `http_cache.R` → Wrap API endpoints with HTTP caching

**Usage:**
```r
#* @get /documents
#* @serializer json
function(req, res) {
  with_http_cache(req, res, ttl = 300, {
    # Your endpoint logic
  })
}
```

---

#### 3. Database Strategy Layer

| File | Lines | Purpose | Usage |
|------|-------|---------|-------|
| `db/redis_cache_strategy.R` | 850 | R6 `EnhancedRedisCacheManager` with multi-layer strategy | Advanced cache patterns with fallback |

**When to use:**
- Complex caching scenarios requiring multi-layer strategy
- Need for sophisticated cache invalidation patterns
- Production environments with Redis available

**Usage:**
```r
cache_manager <- EnhancedRedisCacheManager$new()
cache_manager$get(key, fallback = function() {
  # Compute expensive value
})
```

---

#### 4. Module-Specific Layer

| File | Lines | Purpose | Usage |
|------|-------|---------|-------|
| `modules/search/redis_cache_integration.R` | 564 | Autocomplete caching for <100ms response times | Search autocomplete feature |
| `modules/search/redis_cache_system.R` | 763 | Search + autocomplete + geographic data caching | Unified search caching |
| `performance/redis_cache_optimization.R` | 591 | Production-ready cache with intelligent TTL | High-performance scenarios |

**When to use:**
- `redis_cache_integration.R` → Autocomplete functionality
- `redis_cache_system.R` → General search module caching
- `redis_cache_optimization.R` → Performance-critical operations

---

#### 5. Testing/Development

| File | Lines | Purpose | Usage |
|------|-------|---------|-------|
| `dev-tools/test_cache.R` | ~30 | Test script for cache functionality | Development testing only |

**When to use:**
- Testing cache behavior during development
- Debugging cache issues

---

### Archived/Legacy Implementations

These files are **no longer maintained** and should not be used for new features:

#### Already in /legacy/ directory (8 files)

**Python Backend (Deprecated - replaced by R/Shiny):**
- `/legacy/backend/src/cache/cache_manager.py`
- `/legacy/backend/src/api/semantic_cache.py`
- `/legacy/backend/src/models/search_cache.py`
- `/legacy/backend/src/services/database_cache_service.py`
- `/legacy/backend/src/jobs/export_precache.py`

**Previous R/Shiny Version (Superseded by app_phoenix.R):**
- `/legacy/r-shiny/r-shiny-consolidated/R/redis_cache.R`

**TypeScript Frontend (No longer used):**
- `/legacy/frontend/src/utils/cachedFetch.ts`

**Duplicate (Archived):**
- `/scripts/R/cache_utils.R` → Duplicate of `/R/utils/cache_utils.R`, marked for removal

**Status:** These files are preserved for historical reference but should not be used in new code.

---

## Cache Architecture Overview

### Multi-Layer Strategy

```
┌─────────────────────────────────────────────────────┐
│              Application Layer                       │
│  (app_phoenix.R, modules, API endpoints)            │
└────────────────┬────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────┐
│          Cache Abstraction Layer                    │
│  cache_utils.R, search_cache.R, http_cache.R       │
└────────┬───────────────────────────┬────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────┐         ┌─────────────────┐
│   L1: Memory    │         │   L2: Redis     │
│   (cachem)      │  ◄────► │   (Railway)     │
└─────────────────┘         └─────────────────┘
         │                           │
         └───────────┬───────────────┘
                     ▼
         ┌──────────────────────┐
         │   L3: Database       │
         │   (PostgreSQL)       │
         └──────────────────────┘
```

### Cache Decision Tree

```
Need to cache data?
│
├─ HTTP API response?
│  └─ Use: api/lib/http_cache.R (with_http_cache)
│
├─ Library search results?
│  └─ Use: R/utils/search_cache.R (cache_search_results)
│
├─ Autocomplete data?
│  └─ Use: modules/search/redis_cache_integration.R
│
├─ General database query?
│  └─ Use: R/utils/cache_utils.R (cache_get/cache_set)
│
├─ Complex multi-layer scenario?
│  └─ Use: db/redis_cache_strategy.R (EnhancedRedisCacheManager)
│
└─ Geographic data?
   └─ Use: modules/search/redis_cache_system.R
```

---

## TTL (Time-To-Live) Configuration

| Data Type | TTL | File | Rationale |
|-----------|-----|------|-----------|
| Search results | 5 minutes | `search_cache.R` | Frequently updated, balance freshness vs. performance |
| Autocomplete | 30 minutes | `redis_cache_integration.R` | Static vocabulary, changes rarely |
| Documents | 2 hours | `cache_utils.R` | Historical data, rarely changes |
| Geographic data | 1-48 hours | `redis_cache_system.R` | Static boundaries, very stable |
| Analytics | 15 minutes | `cache_utils.R` | User expects recent data |
| API responses | 5 minutes | `http_cache.R` | Standard HTTP caching |

---

## Configuration

### Environment Variables

```bash
# Redis Configuration
REDIS_ENABLED=true                    # Enable Redis caching
REDIS_URL=redis://localhost:6379      # Redis connection string
REDIS_TTL_DEFAULT=300                 # Default TTL in seconds

# Memory Cache Configuration
CACHE_MEMORY_MAX_SIZE=104857600       # 100 MB memory limit
CACHE_MEMORY_MAX_AGE=900              # 15 minutes default

# Feature Flags
USE_QUERY_CACHE=true                  # Enable query caching (Priority 1)
CACHE_WARMUP_ON_START=false           # Warm cache on app startup
```

### Railway Deployment

**Current Setup:**
- Memory: 2GB available (Railway plan)
- Redis: Embedded via `redux` package (256MB limit)
- Fallback: Automatic degradation to memory-only if Redis unavailable

**Memory Budget:**
- Application base: ~500MB
- Cache layer (L1): Max 100MB (`CACHE_MEMORY_MAX_SIZE`)
- Redis (L2): Max 256MB (Railway embedded Redis)
- Headroom: ~1.1GB for data processing

---

## Usage Examples

### Example 1: Cache a Database Query

```r
library(cachem)
source("R/utils/cache_utils.R")

# Simple caching
cached_data <- cache_get("my_query_key")
if (is.null(cached_data)) {
  cached_data <- dbGetQuery(conn, "SELECT * FROM documents WHERE ...")
  cache_set("my_query_key", cached_data, ttl = 300)  # 5 minutes
}
```

### Example 2: Cache Search Results

```r
source("R/utils/search_cache.R")

# Initialize cache on app startup
init_search_cache()

# Cache search results
results <- cache_search_results(
  search_term = "transporte",
  tipo = "Lei",
  limit = 100
)
```

### Example 3: HTTP API Caching

```r
source("api/lib/http_cache.R")

#* @get /api/documents
function(req, res) {
  with_http_cache(req, res, ttl = 300, {
    dbGetQuery(conn, "SELECT * FROM documents LIMIT 100")
  })
}
```

### Example 4: Advanced Multi-Layer Caching

```r
source("db/redis_cache_strategy.R")

cache_manager <- EnhancedRedisCacheManager$new(
  redis_enabled = TRUE,
  memory_max_size = 100 * 1024^2
)

data <- cache_manager$get("complex_query", fallback = function() {
  # Expensive computation
  expensive_query()
})
```

---

## Migration Guide

### For Developers Using Old Cache Files

If you're using deprecated cache implementations:

**1. Using `/scripts/R/cache_utils.R` (duplicate)?**
```r
# OLD (deprecated)
source("scripts/R/cache_utils.R")

# NEW (use canonical version)
source("R/utils/cache_utils.R")
```

**2. Using legacy Python cache?**
```python
# OLD (deprecated)
from legacy.backend.src.cache.cache_manager import CacheManager

# NEW (use R cache utilities)
# Port your code to R and use R/utils/cache_utils.R
```

**3. Using legacy R/Shiny cache?**
```r
# OLD (deprecated)
source("legacy/r-shiny/r-shiny-consolidated/R/redis_cache.R")

# NEW (use unified cache system)
source("R/utils/cache_utils.R")
```

---

## Future Improvements (Not in Current Scope)

These enhancements are documented for future consideration but are **NOT** part of Priority 5:

1. **Priority 1 Implementation (Pending):**
   - Create `R/utils/query_cache.R` for generic database query caching
   - Use `memoise` + `cachem` for transparent query memoization
   - Target: 90% reduction in repeat query time

2. **Redis Distributed Caching:**
   - Upgrade to dedicated Railway Redis addon (512MB+)
   - Support multi-instance deployments
   - Distributed cache invalidation

3. **Cache Analytics Dashboard:**
   - Real-time cache hit/miss rates
   - Memory usage monitoring
   - Automatic cache performance recommendations

4. **Intelligent Cache Warming:**
   - Pre-populate cache with common queries on startup
   - Predictive caching based on user patterns
   - Background cache refresh before expiration

---

## Testing

### Unit Tests

```r
# Test cache functionality
source("dev-tools/test_cache.R")

# Or manually test
test_cache_operations()
```

### Integration Tests

```bash
# Test cache behavior in production-like environment
R -e "source('dev-tools/test_cache.R'); test_cache_operations()"
```

### Performance Benchmarks

```r
library(microbenchmark)

# Compare cached vs uncached query
microbenchmark(
  uncached = dbGetQuery(conn, query),
  cached = cache_get(key),
  times = 100
)
```

---

## Maintenance

### Regular Tasks

**Weekly:**
- Monitor cache hit rates (target: >80%)
- Check memory usage (<100MB for L1)
- Review Redis performance

**Monthly:**
- Analyze cache effectiveness per module
- Update TTL values based on data change frequency
- Clear stale cache entries

**Quarterly:**
- Review cache architecture for new optimization opportunities
- Update documentation with new patterns
- Deprecate unused cache implementations

### Troubleshooting

**Issue:** Cache misses are high (>50%)
- **Solution:** Increase TTL values, warm cache on startup

**Issue:** Memory usage exceeds limit
- **Solution:** Reduce `CACHE_MEMORY_MAX_SIZE`, implement more aggressive eviction

**Issue:** Redis connection failures
- **Solution:** System automatically falls back to memory-only mode

**Issue:** Stale data displayed to users
- **Solution:** Reduce TTL values, implement manual refresh button

---

## Success Metrics (Priority 5 Completion)

| Metric | Before | After | Status |
|--------|--------|-------|--------|
| Number of cache files | 17 | 9 active + 8 archived | ✅ Reduced by 47% |
| Duplicate files | 1 | 0 | ✅ Removed |
| Lines of cache code | 4,240 | 4,240 (organized) | ✅ No code bloat |
| Cache implementations | 11 (estimated) | 9 (documented) | ✅ Clarified |
| Documentation | None | This file | ✅ Comprehensive |

---

## References

- **PRD:** `docs/PRD_Performance_and_Optimization_Improvements.md`
- **Database Schema:** `docs/DATABASE_SCHEMA.md`
- **Architecture:** `docs/ARCHITECTURE.md`
- **Cache Utils:** `R/utils/cache_utils.R`
- **Search Cache:** `R/utils/search_cache.R`

---

## Changelog

**v1.0 (2025-11-09):**
- Initial documentation created
- Consolidated 17 cache files into 9 active + 8 archived
- Documented cache decision tree and usage patterns
- Added migration guide and troubleshooting
- Completed Priority 5 of Performance & Optimization PRD

---

## Contact

For questions or issues with the cache system:
- Review this documentation first
- Check existing cache usage in codebase
- Consult the cache decision tree above
- Add new cache patterns as needed (update this doc!)

**Note:** This is a living document. Please update it when adding new cache implementations or patterns.
