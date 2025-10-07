# Database Setup Guide - Monitor Legislativo v4

## 📋 Setup Order

Run database scripts in this specific order for proper setup:

### 1️⃣ **Extensions** (FIRST - Required)
```sql
\i database/000_install_extensions.sql
```
**OR** Install via Railway PostgreSQL Extensions UI:
- ✅ `pg_trgm` (CRITICAL)
- ✅ `unaccent` (CRITICAL)
- ⭐ `pg_stat_statements` (RECOMMENDED)
- ⭐ `btree_gin` (RECOMMENDED)
- ⚪ `pgcrypto` (OPTIONAL)

### 2️⃣ **Search Configuration**
```sql
\i database/advanced_search_setup.sql
```
Sets up Portuguese full-text search, indexes, and search functions.

### 3️⃣ **Performance Indexes**
```sql
\i database/create_indexes.sql
```
Creates optimized indexes for common query patterns.

### 4️⃣ **Data Migration** (if needed)
```sql
\i database/migrations/REAL_DATA_MIGRATION.sql
```

---

## 🔍 Extension Details

### Critical Extensions (Application will FAIL without these)

#### **pg_trgm** - Trigram Text Search
- **Purpose**: Fuzzy text matching, similarity search
- **Used in**: `advanced_search_setup.sql` line 49
- **Features**:
  - Makes `LIKE '%search%'` queries use indexes
  - Similarity scoring for "did you mean?" suggestions
  - Performance optimization for partial text matching
- **Without it**: Search functionality completely broken

#### **unaccent** - Accent Removal
- **Purpose**: Brazilian Portuguese accent handling
- **Used in**: `advanced_search_setup.sql` line 48, Portuguese text config
- **Features**:
  - "sao paulo" finds "são paulo"
  - "lei organica" finds "lei orgânica"
  - Essential for Brazilian Portuguese search
- **Without it**: Portuguese text search configuration fails

---

### Highly Recommended Extensions

#### **pg_stat_statements** - Query Performance Monitoring
- **Purpose**: Track and analyze query performance
- **Benefits**:
  - Identify slow queries automatically
  - See execution counts and average times
  - Optimize indexes based on real usage
  - Monitor production performance
- **Usage**: `SELECT * FROM v_slow_queries;` (view created by 000_install_extensions.sql)
- **Note**: Requires PostgreSQL restart to enable

#### **btree_gin** - Composite Index Optimization
- **Purpose**: Combine GIN (text) and B-tree (other columns) in one index
- **Benefits**:
  - Single index for `WHERE text_search AND date BETWEEN ...`
  - Reduces index count and maintenance
  - Improves complex query performance
- **Your queries**: Combined text + geographic + temporal filters

---

### Optional Extensions

#### **pgcrypto** - Cryptographic Functions
- **Purpose**: Database-level encryption and hashing
- **Use cases**:
  - LGPD compliance (encrypt sensitive columns)
  - Password hashing at DB level
  - Generate secure tokens
- **Current status**: Application-level encryption sufficient
- **Install if**: You need column-level encryption

---

## 🚀 Quick Start (Railway Production)

### Via Railway UI (Recommended)
1. Go to Railway → Your PostgreSQL service → **Extensions** tab
2. Click **Install** next to:
   - `pg_trgm`
   - `unaccent`
   - `pg_stat_statements`
   - `btree_gin`
3. Run `database/000_install_extensions.sql` to verify
4. Proceed with other setup scripts

### Via SQL Script (Development)
```bash
# Connect to your database
psql $DATABASE_URL

# Run in order:
\i database/000_install_extensions.sql
\i database/advanced_search_setup.sql
\i database/create_indexes.sql
```

---

## ✅ Verification

### Check Installed Extensions
```sql
SELECT extname, extversion
FROM pg_extension
WHERE extname != 'plpgsql'
ORDER BY extname;
```

Expected output:
```
     extname      | extversion
------------------+------------
 btree_gin        | 1.3
 pg_stat_statements | 1.10
 pg_trgm          | 1.6
 pgcrypto         | 1.3
 unaccent         | 1.1
```

### Verify Search Configuration
```sql
-- Check Portuguese text search config exists
\dF+ portuguese_legal

-- Check search function exists
\df search_legislative_documents

-- Test search
SELECT * FROM search_legislative_documents(
    'transporte público',
    filter_estado := 'SP',
    result_limit := 10
);
```

### Check Performance Monitoring
```sql
-- View slowest queries (if pg_stat_statements installed)
SELECT * FROM v_slow_queries LIMIT 10;

-- Check index usage
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read
FROM pg_stat_user_indexes
WHERE schemaname = 'public'
ORDER BY idx_scan DESC;
```

---

## 🔧 Troubleshooting

### "extension does not exist" error
**Problem**: Extension not installed in Railway
**Solution**: Install via Railway PostgreSQL Extensions UI, then re-run script

### "must be owner of extension" error
**Problem**: Trying to create extension without superuser privileges
**Solution**: Use Railway Extensions UI (doesn't require superuser)

### Search queries are slow
**Solutions**:
1. Verify indexes exist: `\d+ documents`
2. Run `ANALYZE documents;`
3. Check `v_slow_queries` for bottlenecks
4. Ensure `btree_gin` extension is installed

### Portuguese accent search not working
**Problem**: `unaccent` not configured properly
**Solution**:
1. Verify extension: `SELECT * FROM pg_extension WHERE extname = 'unaccent';`
2. Re-run `advanced_search_setup.sql`
3. Check text search config: `\dF+ portuguese_legal`

---

## 📊 Performance Targets

With all extensions and indexes properly configured:

- **Simple search**: < 100ms (single keyword)
- **Complex search**: < 2s (multiple filters + text + geographic)
- **Autocomplete**: < 50ms
- **Total documents**: 134,000+
- **Index size**: ~500MB (acceptable for 134k documents)
- **Cache hit rate**: > 95% (with proper Redis integration)

---

## 📝 Maintenance

### Weekly
```sql
-- Update table statistics
ANALYZE documents;
ANALYZE search_result_cache;

-- Refresh materialized views
SELECT refresh_search_filters_cache();
```

### Monthly
```sql
-- Check for bloat and reindex if needed
REINDEX INDEX CONCURRENTLY idx_documents_combined_fulltext;

-- Clean up old search cache
SELECT cleanup_search_cache();

-- Review slow queries
SELECT * FROM v_slow_queries WHERE calls > 100;
```

---

## 🔗 Related Documentation

- [PostgreSQL Full-Text Search](https://www.postgresql.org/docs/current/textsearch.html)
- [pg_trgm Documentation](https://www.postgresql.org/docs/current/pgtrgm.html)
- [Portuguese Snowball Stemmer](https://www.postgresql.org/docs/current/textsearch-dictionaries.html)
- [Railway PostgreSQL Guide](https://docs.railway.app/databases/postgresql)

---

**Last Updated**: 2025-10-03
**Maintainer**: Sofia Donário
**Version**: 4.0.0
