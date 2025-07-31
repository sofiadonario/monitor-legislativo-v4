# Quick Database Fix for Map Rendering

## Option 1: Using Railway CLI (Recommended)

```bash
# Make sure you're in the project directory
cd /mnt/c/Users/Sofia/OneDrive/Doutorado\ Stuff/MackIntegridade/monitor_legislativo_v4

# Run the database fix script
railway run psql "$DATABASE_URL" -f railway_quick_fix.sql
```

## Option 2: Using Direct Database Connection

If you have the DATABASE_URL, you can run:

```bash
psql "postgresql://postgres:password@host:port/railway" -f railway_quick_fix.sql
```

## Option 3: Copy-Paste into Railway Database Console

If Railway has a database console, copy and paste the contents of `railway_quick_fix.sql`

## What This Does:

1. ✅ Adds `estado_codigo` column to documents table
2. ✅ Standardizes all state names to proper codes (AC, AM, BA, etc.)
3. ✅ Ensures all 27 Brazilian states are properly mapped
4. ✅ Shows final state distribution for verification

## Expected Results After Running:

- **Map will display all states correctly**
- **State query will show 27+ states instead of 10**
- **All document counts will be accurate**
- **No more "column estado_codigo does not exist" errors**

## Verification:

After running, check the Railway logs. You should see:
- ✅ `estado_codigo column not found` messages disappear
- ✅ `Current documents loaded:` showing 1,904 instead of 100
- ✅ Map rendering successfully with all states