# Railway CSV Import Instructions

## Quick 3-Step Solution

### Step 1: Upload CSV to Railway PostgreSQL Volume
1. Go to your Railway PostgreSQL service dashboard
2. Click on "Data" or "Files" tab
3. Navigate to `/var/lib/postgresql/data/`
4. Upload `data/processed/lexml_parsed_enhanced_fixed.csv` to this directory

### Step 2: Execute Import SQL
1. In Railway PostgreSQL dashboard, go to "Query" tab
2. Copy and paste the contents of `railway_csv_import.sql`
3. Execute the SQL commands

### Step 3: Verify Success
- Check that you see "Migration completed! Your R Shiny app now has 889 real legislative records!"
- Visit your R Shiny app to see real data

---

## Alternative Method: Railway CLI

If you have Railway CLI installed:

```bash
# Upload CSV file
railway run --service postgres cp data/processed/lexml_parsed_enhanced_fixed.csv /var/lib/postgresql/data/

# Execute import SQL
railway run --service postgres psql $DATABASE_URL -f railway_csv_import.sql
```

---

## What This Does

1. **Creates 3 tables:**
   - `lexml_parsed_enhanced` (raw CSV data)
   - `documents` (R Shiny compatible format)
   - `legislative_data` (additional compatibility)

2. **Imports 889 real records** from your CSV file using PostgreSQL's native `COPY` command

3. **Transforms data** into formats compatible with your R Shiny app

4. **Creates indexes** for optimal performance

5. **Provides verification** queries to confirm success

---

## Expected Results

After successful import:
- ✅ 889 records in `lexml_parsed_enhanced` table
- ✅ ~800+ records in `documents` table (some duplicates filtered)
- ✅ ~800+ records in `legislative_data` table
- ✅ Your R Shiny app shows real Brazilian legislative data
- ✅ Transport legislation from multiple states and years (1976-2025)

---

## Files Included

- `railway_csv_import.sql` - Complete import script
- `data/processed/lexml_parsed_enhanced_fixed.csv` - Your 889 real records
- This instruction file

The CSV import uses PostgreSQL's native `COPY FROM` command which is much faster than individual INSERT statements. All 889 records will be imported in seconds!

---

## Troubleshooting

**If CSV upload fails:**
- Try using Railway CLI method
- Ensure CSV file is exactly 890 lines (1 header + 889 data)
- Check file is UTF-8 encoded

**If SQL execution fails:**
- Run each section separately (CREATE TABLES, COPY, INSERT, etc.)
- Check PostgreSQL logs in Railway dashboard
- Verify CSV file is in correct location

**If R Shiny app still shows sample data:**
- Check that Railway rebuild completed
- Verify database environment variables are correct
- Test database connection in R Shiny logs