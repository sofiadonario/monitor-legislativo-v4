# Database Optimization Deployment Guide

## Overview

This guide explains how to safely apply database optimizations to the production Cloud SQL instance.

**Important:** Direct connections to Cloud SQL from local machines are blocked by firewall rules (good security practice). Database optimizations should be applied during a scheduled maintenance window.

## Prerequisites

- Access to Google Cloud Console
- Cloud SQL Admin permissions
- Backup confirmation

## Deployment Options

### Option 1: Using Cloud Shell (Recommended)

Cloud Shell has direct access to Cloud SQL instances without firewall restrictions.

1. Open Cloud Shell in Google Cloud Console
2. Clone the repository or upload the SQL file:
   ```bash
   git clone <repository-url>
   cd monitor_legislativo_v4/db
   ```

3. Connect to Cloud SQL:
   ```bash
   gcloud sql connect mackmonitor-db \
     --user=monitor_user \
     --database=monitor_legislativo \
     --project=mackmonitor \
     --quiet
   ```

4. Run the optimization script:
   ```sql
   \i apply_optimizations.sql
   ```

5. Verify the indexes were created:
   ```sql
   \di
   ```

### Option 2: Using Cloud Run Job

Run the optimization script from within the Cloud Run environment (has Cloud SQL access via Unix socket).

1. Deploy a one-time job with the optimization script
2. The script will have access to Cloud SQL via `/cloudsql/` socket
3. Monitor execution in Cloud Run logs

### Option 3: Using Cloud SQL Studio (Web UI)

1. Navigate to Cloud SQL > mackmonitor-db > Cloud SQL Studio
2. Open the `apply_optimizations.sql` file
3. Execute the script
4. Verify results in the output panel

## Pre-Deployment Checklist

- [ ] Schedule maintenance window (recommended: low-traffic period)
- [ ] Notify stakeholders of potential brief performance impact
- [ ] Verify automated backup exists (Cloud SQL automatic backups)
- [ ] Review optimization script one final time
- [ ] Have rollback plan ready (can drop indexes if needed)

## Deployment Steps

### Step 1: Monitor Current Performance (Baseline)

From Cloud Shell or Cloud Run:

```r
# Run performance monitoring script
Rscript db/performance_monitor.R
```

Save the output as your baseline metrics.

### Step 2: Apply Optimizations

Execute `apply_optimizations.sql` using one of the options above.

Expected duration: 10-60 seconds for 130k documents

### Step 3: Verify Indexes Were Created

```sql
SELECT indexname, pg_size_pretty(pg_relation_size(indexrelid)) as size
FROM pg_indexes
JOIN pg_class ON pg_class.relname = indexname
WHERE tablename = 'documents'
ORDER BY indexname;
```

You should see:
- `idx_documents_tipo`
- `idx_documents_data_desc`
- `idx_documents_tipo_data`
- `idx_documents_titulo_gin`

### Step 4: Update Statistics

```sql
ANALYZE documents;
```

### Step 5: Test Query Performance

```sql
-- Test filter query (should use idx_documents_tipo_data)
EXPLAIN ANALYZE
SELECT id, titulo, tipo, data_publicacao
FROM documents
WHERE tipo = 'Lei'
ORDER BY data_publicacao DESC
LIMIT 100;
```

Look for "Index Scan" or "Index Only Scan" in the query plan (not "Seq Scan").

### Step 6: Monitor Post-Deployment Performance

Run the performance monitoring script again:

```r
Rscript db/performance_monitor.R
```

Compare with baseline metrics. Expected improvements:
- Filter queries: 10-100x faster
- Date sorting: 5-50x faster
- Full-text search: 50-500x faster

### Step 7: Monitor Application

1. Check Cloud Run logs for any errors
2. Test Library tab functionality
3. Test search functionality
4. Verify geographic map loads correctly

## Rollback Plan

If issues occur, you can safely drop the new indexes:

```sql
DROP INDEX IF EXISTS idx_documents_tipo;
DROP INDEX IF EXISTS idx_documents_data_desc;
DROP INDEX IF EXISTS idx_documents_tipo_data;
DROP INDEX IF EXISTS idx_documents_titulo_gin;

ANALYZE documents;
```

This will revert performance to pre-optimization state with no data loss.

## Post-Deployment

### Update Application Code (Optional)

For even better performance, consider updating the search query to use full-text search:

**Current code** (app_phoenix.R around line 272):
```r
if (current_search != "") {
  search_term <- gsub("'", "''", current_search)
  conditions <- c(conditions, paste0("titulo ILIKE '%", search_term, "%'"))
}
```

**Optimized code** (uses GIN index):
```r
if (current_search != "") {
  search_term <- gsub("'", "''", current_search)
  conditions <- c(conditions,
    paste0("to_tsvector('portuguese', titulo) @@ plainto_tsquery('portuguese', '", search_term, "')"))
}
```

### Enable Regular Performance Monitoring

Add this to your monitoring routine:

```bash
# Weekly performance check
gcloud run jobs create db-performance-check \
  --image us-central1-docker.pkg.dev/mackmonitor/monitor-repo/mackmonitor:latest \
  --command Rscript \
  --args db/performance_monitor.R \
  --region southamerica-east1 \
  --project mackmonitor

# Schedule weekly execution
gcloud scheduler jobs create http db-weekly-check \
  --schedule="0 2 * * 0" \
  --uri="https://southamerica-east1-run.googleapis.com/..." \
  --http-method=POST
```

## Troubleshooting

### Problem: Indexes not being used

**Solution:**
```sql
-- Update statistics
ANALYZE documents;

-- Check query plan
EXPLAIN ANALYZE SELECT ... ;
```

### Problem: Index creation timeout

**Solution:**
- Increase Cloud SQL instance size temporarily
- Run during lowest traffic period
- Create indexes one at a time

### Problem: Full-text search returns no results

**Solution:**
```sql
-- Verify Portuguese dictionary is available
SELECT * FROM pg_ts_config WHERE cfgname = 'portuguese';

-- Test full-text search manually
SELECT titulo FROM documents
WHERE to_tsvector('portuguese', titulo) @@ plainto_tsquery('portuguese', 'test')
LIMIT 5;
```

## Maintenance

### Weekly
- Run performance monitoring script
- Check index usage statistics:
  ```sql
  SELECT * FROM pg_stat_user_indexes WHERE tablename = 'documents';
  ```

### Monthly
- Review query performance trends
- Check for slow queries in Cloud SQL logs
- Verify automated backups are working

### As Needed
- Run `VACUUM ANALYZE documents;` if table has heavy updates
- Review and drop unused indexes

## Security Notes

- Cloud SQL firewall restrictions are intentional (good security)
- Always use Cloud Shell or Cloud Run for database access
- Never expose database publicly
- Keep credentials in Secret Manager, not in code
- Audit database access logs regularly

## Contact

For issues or questions:
1. Check db/README.md for detailed documentation
2. Review db/DEPLOYMENT_GUIDE.md (this file)
3. Consult PostgreSQL documentation for advanced topics

---

**Last Updated:** 2025-01-05
**For:** Monitor Legislativo v4 (Phoenix)
**Cloud SQL Instance:** mackmonitor-db (southamerica-east1)
