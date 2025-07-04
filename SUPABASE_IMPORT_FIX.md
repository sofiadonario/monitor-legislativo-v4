# Quick Fix for Supabase Import Error

## The Problem
Supabase is rejecting the timestamp format: `"2025-06-06 12:27:31T00:00:00+00:00"`

## Quick Solution

### Option 1: Use Text Type for date_searched (Easiest)

Modify your Supabase table creation SQL:

```sql
CREATE TABLE legislative_documents (
    id BIGSERIAL PRIMARY KEY,
    search_term TEXT,
    date_searched TEXT,  -- Change from TIMESTAMPTZ to TEXT
    url TEXT,
    title TEXT,
    urn TEXT,
    urn_type TEXT,
    country TEXT,
    state TEXT,
    municipality TEXT,
    justice TEXT,
    region TEXT,
    court_class TEXT,
    document_type_full TEXT,
    promulgation_date DATE,
    document_description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Option 2: Fix the CSV Manually

Open `data/processed/lexml_parsed_enhanced_fixed.csv` in a text editor and:

1. Find: `2025-06-06 12:27:31T00:00:00+00:00`
2. Replace with: `2025-06-06 12:27:31`

### Option 3: Simple SQL Conversion

After importing with TEXT type, convert to timestamp:

```sql
-- After import, convert the column type
ALTER TABLE legislative_documents 
ALTER COLUMN date_searched TYPE TIMESTAMPTZ 
USING date_searched::TIMESTAMPTZ;
```

## Recommended Approach

**Use Option 1** (TEXT type) because:
- ✅ Import will work immediately
- ✅ Your application can still parse the dates
- ✅ No data loss
- ✅ Simpler to implement

## Updated Backend Code

If you use TEXT for date_searched, update the router:

```python
# In src/routers/processed_documents_router.py
# The date_searched field will be a string, which is fine for display
```

## Test the Import

1. **Delete the existing table** (if created):
   ```sql
   DROP TABLE IF EXISTS legislative_documents;
   ```

2. **Create table with TEXT date_searched**:
   ```sql
   CREATE TABLE legislative_documents (
       id BIGSERIAL PRIMARY KEY,
       search_term TEXT,
       date_searched TEXT,  -- TEXT instead of TIMESTAMPTZ
       url TEXT,
       title TEXT,
       urn TEXT,
       urn_type TEXT,
       country TEXT,
       state TEXT,
       municipality TEXT,
       justice TEXT,
       region TEXT,
       court_class TEXT,
       document_type_full TEXT,
       promulgation_date DATE,
       document_description TEXT,
       created_at TIMESTAMPTZ DEFAULT NOW(),
       updated_at TIMESTAMPTZ DEFAULT NOW()
   );
   ```

3. **Import your fixed CSV**: `lexml_parsed_enhanced_fixed.csv`

This should work without any timestamp errors! 🎉 