# Database Analysis & Optimization Tools

**Version:** 1.0
**Created:** 2025-11-02
**For:** Monitor Legislativo v4 (Phoenix)

This directory contains comprehensive tools for analyzing, cleaning, and optimizing the PostgreSQL database that powers the Monitor Legislativo application.

---

## Quick Start

### 1. Read the Documentation (5 minutes)

Start with one of these:

- **Quick overview:** Read [QUICK_REFERENCE.md](./QUICK_REFERENCE.md)
- **Executive summary:** Read [ANALYSIS_SUMMARY.md](./ANALYSIS_SUMMARY.md)
- **Full guide:** Read [DATABASE_ANALYSIS_GUIDE.md](./DATABASE_ANALYSIS_GUIDE.md)

### 2. Run the Analysis (5-10 minutes)

**Option A: Using R**
```bash
cd /path/to/monitor_legislativo_v4/db
Rscript analyze_database_quality.R
```

**Option B: Using SQL**
```bash
psql -U postgres -d monitor_legislativo -f analyze_database_quality.sql
```

### 3. Review Results (10-15 minutes)

Look for:
- Data quality issues (duplicates, formatting)
- Performance bottlenecks (slow queries)
- Missing indexes
- Document types not in app filters

### 4. Take Action (1-4 hours)

Based on analysis results:

1. **Clean data** (if needed): Run `clean_data.sql`
2. **Optimize indexes**: Run `optimize_indexes.sql`
3. **Update app code**: Implement recommended changes
4. **Test**: Verify improvements

---

## Files in This Directory

### Documentation

| File | Purpose | Read Time |
|------|---------|-----------|
| [README.md](./README.md) | This file - overview and getting started | 5 min |
| [QUICK_REFERENCE.md](./QUICK_REFERENCE.md) | Quick command reference and common queries | 3 min |
| [ANALYSIS_SUMMARY.md](./ANALYSIS_SUMMARY.md) | Executive summary with findings and recommendations | 15 min |
| [DATABASE_ANALYSIS_GUIDE.md](./DATABASE_ANALYSIS_GUIDE.md) | Complete guide with troubleshooting and advanced topics | 45 min |

### Scripts

| File | Type | Purpose | Runtime |
|------|------|---------|---------|
| [analyze_database_quality.R](./analyze_database_quality.R) | R | Comprehensive database analysis | 1-3 min |
| [analyze_database_quality.sql](./analyze_database_quality.sql) | SQL | Same analysis in SQL | 1-3 min |
| [clean_data.sql](./clean_data.sql) | SQL | Fix data quality issues | 10-30 sec |
| [optimize_indexes.sql](./optimize_indexes.sql) | SQL | Create performance indexes | 10-60 sec |

### Output Files

| File | Created By | Contents |
|------|-----------|----------|
| `analysis_results.rds` | analyze_database_quality.R | Serialized R object with all results |
| `documents_backup_before_cleaning` | clean_data.sql | Backup table (in database) |

---

## What These Tools Do

### Analysis Tools

**Purpose:** Understand the current state of your database

**What they analyze:**

1. **Data Statistics**
   - Total document count
   - Distribution by document type (tipo)
   - Date ranges (oldest to newest documents)
   - Documents per year/month

2. **Data Quality**
   - NULL values and empty strings
   - Text formatting issues (double spaces, etc.)
   - Duplicate documents
   - Inconsistent tipo values

3. **Performance**
   - Existing indexes
   - Query execution times
   - Table and index sizes
   - Impact of loading ALL records vs. limited results

**Output:** Detailed report with statistics and recommendations

---

### Cleaning Tools

**Purpose:** Fix data quality issues identified in analysis

**What they fix:**

1. **Text Formatting**
   - Double spaces → Single space
   - Space before punctuation → Removed
   - Leading/trailing whitespace → Trimmed

2. **Normalization**
   - Inconsistent capitalization → Standardized
   - Whitespace in tipo → Removed

3. **Duplicates** (optional)
   - Duplicate documents → Removed (keeping oldest)

**Safety Features:**
- Creates backup table before any changes
- Runs in transaction (requires manual COMMIT)
- Shows before/after comparison

---

### Optimization Tools

**Purpose:** Improve query performance

**What they create:**

1. **Filter Indexes**
   - B-tree index on `tipo` for fast filtering
   - Composite index on `tipo, data` for filter+sort queries

2. **Sorting Indexes**
   - B-tree index on `data DESC` for date sorting

3. **Search Indexes**
   - GIN index for Portuguese full-text search
   - Optional trigram index for fuzzy search

**Expected Results:**
- Filter queries: **10-100x faster**
- Date sorting: **5-50x faster**
- Text search: **50-500x faster**

---

## Prerequisites

### For R Scripts

**Required:**
- R (version 3.6+)
- R packages: `DBI`, `RPostgres`

**Install packages:**
```r
install.packages(c("DBI", "RPostgres"))
```

### For SQL Scripts

**Required:**
- PostgreSQL client (psql, pgAdmin, DBeaver, or any SQL client)
- Database connection credentials

**Supported versions:**
- PostgreSQL 12+
- PostgreSQL 13-16 recommended

### Database Access

**Environment Variables:**

```bash
# Method 1: Individual variables
export PGHOST=localhost
export PGPORT=5432
export PGDATABASE=monitor_legislativo
export PGUSER=postgres
export PGPASSWORD=your_password

# Method 2: DATABASE_URL (Railway/Cloud format)
export DATABASE_URL=postgresql://user:password@host:port/dbname
```

---

## Step-by-Step Guide

### Step 1: Set Up Environment

**Local development:**
```bash
export PGHOST=localhost
export PGDATABASE=monitor_legislativo
export PGUSER=postgres
export PGPASSWORD=your_password
```

**Railway deployment:**
```bash
# Get DATABASE_URL from Railway dashboard
export DATABASE_URL=postgresql://...
```

**Test connection:**
```bash
psql -U postgres -d monitor_legislativo -c "SELECT COUNT(*) FROM documents"
```

---

### Step 2: Run Analysis

**Using R (recommended):**
```bash
cd /path/to/monitor_legislativo_v4/db
Rscript analyze_database_quality.R
```

**Using SQL:**
```bash
psql -U postgres -d monitor_legislativo -f analyze_database_quality.sql > analysis_report.txt
```

**Review output:**
- Check total document count
- Review document type distribution
- Note any data quality issues
- Check query performance metrics

---

### Step 3: Clean Data (if needed)

**⚠️ IMPORTANT: Create backup first!**

```bash
# Create full database backup
pg_dump -Fc monitor_legislativo > backup_$(date +%Y%m%d_%H%M%S).dump
```

**Run cleaning script:**
```bash
psql -U postgres -d monitor_legislativo -f clean_data.sql
```

**Review changes:**
- Check before/after statistics
- Verify no critical data was lost
- Ensure text formatting looks good

**Commit or rollback:**
```sql
-- Inside psql, after reviewing changes:

-- If satisfied:
COMMIT;

-- If not satisfied:
ROLLBACK;
```

**Clean up:**
```sql
-- After verifying everything works:
VACUUM ANALYZE documents;

-- Optionally remove backup table:
DROP TABLE documents_backup_before_cleaning;
```

---

### Step 4: Optimize Indexes

**Run optimization script:**
```bash
psql -U postgres -d monitor_legislativo -f optimize_indexes.sql
```

**Review query plans:**
- Check EXPLAIN ANALYZE output
- Verify indexes are being used
- Compare execution times before/after

**Commit if satisfied:**
```sql
COMMIT;
```

**Update statistics:**
```sql
ANALYZE documents;
```

---

### Step 5: Update App Code

**Changes needed in `app_phoenix.R`:**

#### Change 1: Add All Document Types to Filter (Line 170)

**Find all document types:**
```sql
SELECT DISTINCT tipo FROM documents ORDER BY tipo;
```

**Update code:**
```r
# OLD:
selectInput("library_tipo", "Tipo de Documento:",
  choices = c("Todos", "Lei", "Decreto", "Projeto de Lei"))

# NEW (example - adjust based on your actual types):
selectInput("library_tipo", "Tipo de Documento:",
  choices = c("Todos", "Lei", "Decreto", "Decreto-Lei", "Lei Complementar",
              "Medida Provisória", "Projeto de Lei", "Resolução"))
```

#### Change 2: Use Full-Text Search (Lines 270-273)

**OLD CODE:**
```r
if (current_search != "") {
  search_term <- gsub("'", "''", current_search)
  conditions <- c(conditions, paste0("titulo ILIKE '%", search_term, "%'"))
}
```

**NEW CODE:**
```r
if (current_search != "") {
  search_term <- gsub("'", "''", current_search)
  conditions <- c(conditions,
    paste0("to_tsvector('portuguese', titulo) @@ plainto_tsquery('portuguese', '", search_term, "')"))
}
```

#### Change 3: Update "Mostrar" Limits (Line 171) - Optional

**OLD:**
```r
selectInput("library_mostrar", "Mostrar:",
  choices = c(100, 500, 1000, 5000, 10000, 999999),
  selected = 100)
```

**NEW (recommended):**
```r
selectInput("library_mostrar", "Mostrar:",
  choices = c(100, 500, 1000, 5000, 10000),  # Remove 999999
  selected = 100)
```

---

### Step 6: Test Changes

**Test filtering:**
1. Open app in browser
2. Try different document types in filter
3. Verify all types from database appear
4. Check query response time (should be < 50ms)

**Test search:**
1. Search for common terms
2. Verify results are relevant
3. Test Portuguese stemming (e.g., "tributário" finds "tributária")
4. Check query response time (should be < 100ms)

**Test performance:**
1. Try different "Mostrar" limits
2. Monitor query execution times
3. Check memory usage
4. Test with multiple concurrent users

---

### Step 7: Deploy to Production

**Staging deployment (recommended):**
1. Deploy to staging environment
2. Run all analysis and optimization scripts
3. Test thoroughly
4. Get user acceptance

**Production deployment:**
1. **Create production backup**
   ```bash
   pg_dump -Fc monitor_legislativo > prod_backup_$(date +%Y%m%d_%H%M%S).dump
   ```

2. **Apply database optimizations**
   ```bash
   psql -U postgres -d monitor_legislativo -f optimize_indexes.sql
   # Review, then COMMIT;
   ```

3. **Deploy app code updates**
   - Update `app_phoenix.R`
   - Test in production
   - Monitor logs and performance

4. **Monitor post-deployment**
   - Check error logs
   - Monitor query performance
   - Verify index usage
   - Gather user feedback

---

## Maintenance

### Daily

**Monitor performance:**
```sql
-- Check slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
WHERE query LIKE '%documents%'
ORDER BY mean_exec_time DESC
LIMIT 10;
```

### Weekly

**Vacuum and analyze:**
```sql
VACUUM ANALYZE documents;
```

**Check index usage:**
```sql
SELECT * FROM pg_stat_user_indexes WHERE tablename = 'documents';
```

### Monthly

**Re-run analysis:**
```bash
Rscript analyze_database_quality.R
```

**Review:**
- Data quality trends
- Performance metrics
- Index usage statistics
- Disk space usage

---

## Troubleshooting

### Can't Connect to Database

**Error:**
```
❌ DATABASE CONNECTION FAILED
Error: could not connect to server
```

**Solutions:**

1. **Check PostgreSQL is running:**
   ```bash
   pg_isready -h localhost -p 5432
   ```

2. **Verify credentials:**
   ```bash
   psql -U postgres -d monitor_legislativo -c "SELECT 1"
   ```

3. **Check environment variables:**
   ```bash
   echo $PGHOST $PGPORT $PGDATABASE $PGUSER
   ```

4. **Check firewall/network:**
   - Ensure port 5432 is not blocked
   - For cloud deployments, check security groups/firewall rules

---

### Indexes Not Being Used

**Symptoms:** Query still slow after creating indexes

**Check query plan:**
```sql
EXPLAIN ANALYZE SELECT id, titulo, tipo, data
FROM documents
WHERE tipo = 'Lei'
ORDER BY data DESC
LIMIT 100;
```

**Look for:** "Index Scan" or "Index Only Scan" (good) vs "Seq Scan" (bad)

**Solutions:**

1. **Update statistics:**
   ```sql
   ANALYZE documents;
   ```

2. **Check index exists:**
   ```sql
   \d documents
   ```

3. **Verify index is valid:**
   ```sql
   SELECT * FROM pg_indexes WHERE tablename = 'documents';
   ```

---

### Full-Text Search Returns No Results

**Symptoms:** After switching to `to_tsvector`, searches return empty

**Test query:**
```sql
SELECT titulo
FROM documents
WHERE to_tsvector('portuguese', titulo) @@ plainto_tsquery('portuguese', 'test')
LIMIT 5;
```

**Solutions:**

1. **Check Portuguese dictionary:**
   ```sql
   SELECT * FROM pg_ts_config WHERE cfgname = 'portuguese';
   ```

2. **Try simple dictionary:**
   ```sql
   -- In optimize_indexes.sql, change:
   to_tsvector('simple', titulo)  -- instead of 'portuguese'
   ```

3. **Verify index was created:**
   ```sql
   SELECT indexname FROM pg_indexes
   WHERE tablename = 'documents' AND indexdef LIKE '%gin%';
   ```

---

## Performance Expectations

### Before Optimization

| Query | Time | User Experience |
|-------|------|-----------------|
| Filter by tipo | 150-500ms | Noticeable lag |
| Text search | 500-2000ms | Very slow |
| Load all records | 1000-3000ms | Unacceptable |
| Sort by date | 100-300ms | Slow |

### After Optimization

| Query | Time | User Experience | Improvement |
|-------|------|-----------------|-------------|
| Filter by tipo | 2-10ms | Instant | 15-250x |
| Text search | 10-50ms | Fast | 50-400x |
| Load 100 records | 2-10ms | Instant | 10-100x |
| Sort by date | 5-20ms | Instant | 5-60x |

---

## FAQ

### Q: Will these changes affect my data?

**A:** The cleaning script modifies data (fixes formatting), but:
- Creates backup table first
- Runs in transaction (you can ROLLBACK)
- Analysis and optimization scripts are read-only (indexes only)

### Q: How long does optimization take?

**A:** For 130k documents:
- Analysis: 1-3 minutes
- Cleaning: 10-30 seconds
- Index creation: 10-60 seconds
- Total: < 5 minutes

### Q: Will this work on Railway/Cloud Run?

**A:** Yes! Just use the `DATABASE_URL` environment variable:
```bash
export DATABASE_URL=postgresql://...
```

### Q: Do I need to run this regularly?

**A:**
- Analysis: Monthly recommended
- Cleaning: As needed (when issues found)
- Indexes: Once (then monitor usage)
- Maintenance: Weekly VACUUM ANALYZE

### Q: What if something goes wrong?

**A:**
1. All scripts use transactions - just ROLLBACK
2. Backups are created automatically
3. Can restore from backup: `pg_restore backup.dump`
4. Indexes can be dropped without data loss

---

## Best Practices

1. **Always backup before modifications**
   ```bash
   pg_dump -Fc dbname > backup.dump
   ```

2. **Test on staging first**
   - Never modify production directly
   - Validate all changes
   - Get user acceptance

3. **Use transactions**
   ```sql
   BEGIN;
   -- changes
   ROLLBACK; -- or COMMIT
   ```

4. **Monitor after changes**
   - Check logs for errors
   - Monitor performance metrics
   - Have rollback plan ready

5. **Document custom changes**
   - Keep notes on modifications
   - Update this documentation
   - Share knowledge with team

---

## Resources

### Documentation
- [PostgreSQL Full-Text Search](https://www.postgresql.org/docs/current/textsearch.html)
- [PostgreSQL Indexes](https://www.postgresql.org/docs/current/indexes.html)
- [Query Optimization](https://www.postgresql.org/docs/current/performance-tips.html)

### Project Files
- Main app: `/app_phoenix.R`
- Database scripts: `/db/` (this directory)
- Environment config: `/.env.example`

### Related Tools
- pgAdmin: GUI for PostgreSQL
- DBeaver: Universal database client
- pg_stat_statements: Query performance extension

---

## Support

**Need help?**

1. **Check documentation:**
   - [DATABASE_ANALYSIS_GUIDE.md](./DATABASE_ANALYSIS_GUIDE.md) - Complete guide
   - [QUICK_REFERENCE.md](./QUICK_REFERENCE.md) - Command reference

2. **Review examples:**
   - All scripts have detailed comments
   - SQL includes sample output

3. **Common issues:**
   - See Troubleshooting section above
   - Check FAQ

4. **Contact:**
   - Create issue in project repository
   - Consult PostgreSQL community resources

---

## Changelog

### Version 1.0 (2025-11-02)

**Initial release:**
- Complete database analysis tools (R and SQL)
- Data cleaning scripts with safety features
- Performance optimization scripts
- Comprehensive documentation
- Quick reference guide
- Troubleshooting guide

---

**Last Updated:** 2025-11-02
**Maintained By:** Monitor Legislativo Team
**For:** Monitor Legislativo v4 (Phoenix)
**License:** Same as main project
