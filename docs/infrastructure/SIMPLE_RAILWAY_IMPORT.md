# Simple Railway Import - No CLI Required

Since Railway CLI requires authentication, here's the simplest method:

## 📂 Step 1: Upload CSV File

### Method A: Railway Dashboard Upload
1. Go to your Railway project dashboard
2. Click on your **PostgreSQL service**
3. Go to **Data** tab
4. Click **Upload Files** or **File Manager**
5. Navigate to `/var/lib/postgresql/data/`
6. Upload the file: `data/processed/lexml_parsed_enhanced_fixed.csv`
7. Rename it to: `lexml_parsed_enhanced_fixed.csv` (if needed)

### Method B: Manual File Creation
1. In Railway PostgreSQL **Data** tab
2. Click **Create File**
3. Name it: `lexml_parsed_enhanced_fixed.csv`
4. Copy and paste the contents of `data/processed/lexml_parsed_enhanced_fixed.csv`

## 🗃️ Step 2: Execute SQL Import

1. In Railway PostgreSQL dashboard
2. Go to **Query** tab
3. Copy and paste the contents of `railway_csv_import.sql`
4. Click **Execute** or **Run**

## ✅ Step 3: Verify Success

You should see output like:
```
CSV Import completed successfully!
lexml_parsed_enhanced: 889 records
documents: ~800 records
legislative_data: ~800 records
```

## 🔧 Alternative: Direct Database Connection

If the above doesn't work, you can also:

```bash
# Install PostgreSQL client if not installed
# Windows: Download from https://www.postgresql.org/download/windows/
# Linux: sudo apt-get install postgresql-client
# macOS: brew install postgresql

# Connect directly to Railway PostgreSQL
psql "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway"

# Then run the SQL commands from railway_csv_import.sql
```

## 🎯 What to Expect

After successful import:
- Your R Shiny app will show **889 real legislative records**
- Data includes Brazilian transport legislation from **1976-2025**
- Search and filtering will work with **real government documents**
- No more sample data!

## 🚨 If Upload Fails

1. **File too large**: Split CSV into smaller chunks
2. **Permission denied**: Use Railway CLI with proper authentication
3. **Format issues**: Ensure CSV is UTF-8 encoded

## 📞 Need Help?

If you encounter issues:
1. Check Railway PostgreSQL logs in dashboard
2. Verify file exists in `/var/lib/postgresql/data/`
3. Try running SQL commands section by section
4. Check that CSV file has exactly 890 lines (1 header + 889 data)

The key is getting that CSV file into the PostgreSQL container's `/var/lib/postgresql/data/` directory, then running the import SQL. Railway's web interface should handle this!