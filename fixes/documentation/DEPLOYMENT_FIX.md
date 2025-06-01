# Deployment Fix Instructions

## Issue Summary
The Monitor Legislativo app is failing to deploy on Railway because it's looking for tables that don't exist in your database structure.

**Expected tables (by app):**
- `documents`
- `lexml_parsed_enhanced_fixed`
- `lexml_documents_corrected`

**Actual tables (in your database):**
- `lexml_doutrina_aereo`, `lexml_doutrina_geral`, etc.
- `lexml_jurisprudencia_aereo`, `lexml_jurisprudencia_geral`, etc.
- `lexml_legislacao_aereo`, `lexml_legislacao_geral`, etc.
- `lexml_outros_aereo`, `lexml_outros_geral`, etc.
- `lexml_proposicoes_aereo`, `lexml_proposicoes_geral`, etc.

## Solution Steps

### 1. Create Documents View in Database
First, you need to create a unified view in your Railway PostgreSQL database. Run this SQL:

```bash
# Connect to your Railway database
psql $DATABASE_URL < create_documents_view.sql
```

Or manually run the SQL in `create_documents_view.sql` through Railway's database interface.

### 2. Deploy Updated Application
The application has been updated to:
- Use `database_connection_fixed.R` which properly handles your table structure
- Not hardcode the DATABASE_URL (Railway sets this automatically)
- Fall back gracefully if tables are missing

### 3. Verify Environment Variables
Make sure Railway has the DATABASE_URL environment variable set correctly. This should be automatic when you attach a PostgreSQL database to your service.

### 4. Redeploy
1. Commit and push the changes:
```bash
git add .
git commit -m "fix: update database connection to use actual table structure"
git push
```

2. Railway should automatically redeploy

## Alternative: Direct Table Query
If creating the view doesn't work, the `database_connection_fixed.R` module includes fallback logic that queries the `lexml_*` tables directly without needing the view.

## Testing Locally
To test locally before deploying:
```r
# Set your Railway database URL
Sys.setenv(DATABASE_URL = "your-railway-database-url")

# Run the app
shiny::runApp()
```

## Expected Result
After these fixes, the app should:
1. Connect to your Railway PostgreSQL database
2. Either use the `documents` view or query the `lexml_*` tables directly
3. Display your legislative documents correctly

## Troubleshooting
If it still fails:
1. Check Railway logs for specific error messages
2. Verify the DATABASE_URL is correctly set in Railway
3. Make sure the database user has permissions to create views
4. Try running the SQL commands manually through Railway's database interface