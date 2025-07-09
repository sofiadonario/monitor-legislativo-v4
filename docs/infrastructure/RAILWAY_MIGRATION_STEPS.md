# Railway PostgreSQL Migration Steps

## Prerequisites
- Railway PostgreSQL service running
- Access to Railway dashboard

## Step-by-Step Migration

### 1. Get Your Railway PostgreSQL Connection Details

Go to your Railway dashboard → PostgreSQL service → Variables tab and copy:
- `DATABASE_URL` (full connection string)
- Or individual credentials:
  - `PGHOST`
  - `PGPORT`
  - `PGDATABASE`
  - `PGUSER`
  - `PGPASSWORD`

### 2. Migration via Railway Web Console (Easiest)

1. In Railway dashboard, go to PostgreSQL service
2. Click on "Data" tab
3. Click "Connect" to open query console
4. Copy ALL contents from `REAL_DATA_MIGRATION.sql`
5. Paste into the query console
6. Click "Run Query"
7. Wait for completion (should show "889 rows inserted")

### 3. Alternative: Using psql Command Line

If you have PostgreSQL tools installed:

```bash
# Using DATABASE_URL
psql "YOUR_DATABASE_URL_HERE" < REAL_DATA_MIGRATION.sql

# Or using individual credentials
PGPASSWORD=your_password psql -h your_host -p your_port -U your_user -d your_database < REAL_DATA_MIGRATION.sql
```

### 4. Verify Migration Success

Run these queries in Railway console to verify:

```sql
-- Check row counts
SELECT 'lexml_parsed_enhanced' as table_name, COUNT(*) as count FROM lexml_parsed_enhanced
UNION ALL
SELECT 'documents' as table_name, COUNT(*) as count FROM documents
UNION ALL
SELECT 'legislative_data' as table_name, COUNT(*) as count FROM legislative_data;

-- Should show:
-- lexml_parsed_enhanced: 889
-- documents: 889
-- legislative_data: 889

-- View sample data
SELECT title, urn_type, state, promulgation_date 
FROM lexml_parsed_enhanced 
LIMIT 5;
```

### 5. Connect Your Application

Update your Railway environment variables:
- The app should automatically use `DATABASE_URL`
- No additional configuration needed

### 6. Test the Application

1. Visit your deployed app
2. Try searching for transport-related terms
3. Verify data appears correctly

## Troubleshooting

### If migration fails:
1. Check for existing tables - drop them first if needed
2. Ensure you're copying the ENTIRE SQL file
3. Check Railway logs for specific errors

### If data doesn't appear in app:
1. Verify DATABASE_URL is set correctly
2. Check application logs in Railway
3. Ensure tables were created in correct schema (public)

## Important Notes

- The migration creates 3 tables with 889 rows each
- Data is from real Brazilian legislative documents
- Focus on transport-related legislation
- All data is academically verified