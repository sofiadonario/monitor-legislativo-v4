# Production Deployment Instructions

## Method 1: Using psql command line
```bash
# Connect to your production database
psql $DATABASE_URL

# Run the migration script
\i production_migration_corrected.sql

# Verify the deployment
SELECT COUNT(*) FROM lexml_documents_corrected;
SELECT COUNT(*) FROM lexml_parsed_enhanced_fixed;
```

## Method 2: Upload via Railway Dashboard
1. Go to Railway dashboard → Your project → Database tab
2. Click "Query" or "Admin Panel"
3. Copy and paste the contents of `production_migration_corrected.sql`
4. Execute the script

## Method 3: Using pgAdmin or similar GUI
1. Connect to your PostgreSQL database
2. Open Query Tool
3. Load and execute `production_migration_corrected.sql`

## Method 4: Railway CLI
```bash
# Install Railway CLI if needed
npm install -g @railway/cli

# Login and connect
railway login
railway connect

# Run the migration
railway run psql $DATABASE_URL -f production_migration_corrected.sql
```

## Verification Steps
After running the migration, verify:

```sql
-- Check total records
SELECT 'Total documents' as metric, COUNT(*) as value FROM lexml_documents_corrected;

-- Check date extraction
SELECT 
    'Date extraction rate' as metric, 
    ROUND((COUNT(CASE WHEN enacting_date IS NOT NULL THEN 1 END) * 100.0 / COUNT(*)), 1) || '%' as value
FROM lexml_documents_corrected;

-- Test the view (should not error)
SELECT COUNT(*) FROM lexml_parsed_enhanced_fixed;
```

Expected results:
- Total documents: 1,904
- Date extraction rate: 100.0%
- View should return 1,904 records

## R Shiny Restart
After database migration, restart your R Shiny application:
- Railway: Redeploy the service
- Manual: Restart the R process