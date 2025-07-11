# Manual Data Migration Commands - Find Table with 889 Rows

Since we don't have direct PostgreSQL client tools, here are the exact commands you need to run to find and migrate the real data from Supabase.

## Database Connection Details

**Supabase PostgreSQL URL:**
```
postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres
```

## Step 1: Find All Tables with Row Counts

Run this command to see all tables and their row counts:

```bash
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "
SELECT 
    schemaname,
    tablename,
    n_live_tup as live_rows
FROM pg_stat_user_tables 
WHERE n_live_tup > 0
ORDER BY n_live_tup DESC;
"
```

## Step 2: Alternative - Check Common Table Names

If the above doesn't work, try these individual commands to find the table with 889 rows:

```bash
# Check documents table
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT COUNT(*) FROM documents;"

# Check processed_documents table  
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT COUNT(*) FROM processed_documents;"

# Check search_results table
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT COUNT(*) FROM search_results;"

# Check lexml_documents table
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT COUNT(*) FROM lexml_documents;"

# Check collection_logs table
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT COUNT(*) FROM collection_logs;"

# Check export_logs table
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT COUNT(*) FROM export_logs;"

# Check data_export_logs table
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT COUNT(*) FROM data_export_logs;"

# Check periodic_collection_logs table
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT COUNT(*) FROM periodic_collection_logs;"
```

## Step 3: List All Tables (if you're not sure of names)

```bash
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "\dt"
```

## Step 4: Once You Find the Table with 889 Rows

Replace `TABLE_NAME` with the actual table name that has 889 rows:

### Get Table Structure:
```bash
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "
SELECT 
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns 
WHERE table_name = 'TABLE_NAME' AND table_schema = 'public'
ORDER BY ordinal_position;
"
```

### Export Real Data:
```bash
pg_dump "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" --table=TABLE_NAME --data-only --inserts > real_data_TABLE_NAME.sql
```

### Create Complete Migration:
```bash
pg_dump "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" --table=TABLE_NAME --schema-only > table_structure.sql
pg_dump "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" --table=TABLE_NAME --data-only --inserts > table_data.sql
```

## Step 5: Execute in Railway PostgreSQL

Once you have the real data SQL file, execute it in Railway PostgreSQL console:

1. Go to Railway dashboard
2. Select your PostgreSQL service
3. Open the "Data" tab
4. Run the SQL commands from the exported file

## Alternative: Using GUI Tools

If command line doesn't work, you can use:

1. **pgAdmin**: Download from https://www.pgadmin.org/
2. **DBeaver**: Download from https://dbeaver.io/
3. **TablePlus**: Download from https://tableplus.com/

Connect using:
- Host: `aws-0-sa-east-1.pooler.supabase.com`
- Port: `5432`
- Database: `postgres`
- Username: `postgres`
- Password: `MonitorLegislativo25`

## Quick Test Commands

To verify connection is working:

```bash
# Test connection
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT version();"

# Show current database
psql "postgresql://postgres:MonitorLegislativo25@aws-0-sa-east-1.pooler.supabase.com:5432/postgres" -c "SELECT current_database();"
```

## What to Do Next

1. **Run the commands above** to find the table with 889 rows
2. **Export the real data** from that table
3. **Create the migration SQL** with the real data
4. **Execute it in Railway PostgreSQL** to replace sample data
5. **Test the Railway application** with real data

Once you find the table name, I can help you create the proper migration SQL file.