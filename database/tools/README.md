# Database Tools & Automation Scripts
## Monitor Legislativo v4 - Brazilian Legislative Monitoring System

**Purpose:** Automated tools for database management, data validation, and maintenance
**Target:** 134,014 Brazilian legislative documents with Portuguese encoding
**Database:** PostgreSQL on Google Cloud SQL

---

## Table of Contents

- [Quick Start](#quick-start)
- [Available Tools](#available-tools)
- [Usage Examples](#usage-examples)
- [Maintenance Schedule](#maintenance-schedule)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Prerequisites

```bash
# Python dependencies
pip install pandas pyarrow

# PostgreSQL client
# Ubuntu/Debian:
sudo apt-get install postgresql-client

# macOS:
brew install postgresql
```

### Initial Setup

```bash
# 1. Set database credentials
export DATABASE_URL="postgresql://user:password@host:port/database"

# 2. Test database connection
psql $DATABASE_URL -c "SELECT version();"

# 3. Run initial data quality check
python3 validate_data_quality.py
```

---

## Available Tools

### 1. parquet_to_csv.py

**Purpose:** Generate CSV from Parquet files (fixes documentation mismatch)

**Features:**
- UTF-8 encoding preservation for Portuguese characters
- Memory-efficient chunked processing
- Automatic column mapping (Parquet → Database schema)
- Data validation during conversion
- Progress reporting

**Usage:**

```bash
# Default: Convert production Parquet to CSV
python3 parquet_to_csv.py

# Custom input/output
python3 parquet_to_csv.py \
    --input /path/to/input.parquet \
    --output /path/to/output.csv

# Large dataset optimization
python3 parquet_to_csv.py --chunk-size 50000

# Skip encoding validation (faster)
python3 parquet_to_csv.py --no-validate
```

**Output:**
- CSV file: `data_current/processed/production/lexml_unified_dataset.csv`
- UTF-8 encoded, ready for R/Python scripts
- Column-mapped to database schema

**Example:**
```bash
$ python3 parquet_to_csv.py

================================================================================
PARQUET TO CSV CONVERTER
Brazilian Legislative Documents - Monitor Legislativo v4
================================================================================

✅ Parquet file valid: 134,014 rows
📝 Mapped columns: {'data': 'data_publicacao', 'ementa': 'content'}

🔄 Converting Parquet to CSV...
   Progress: 134,014 / 134,014 (100.0%) - Chunk 14
✅ Conversion complete: 134,014 rows written

🔍 Validating UTF-8 encoding...
   ✅ Portuguese diacritics found in titulo
   ✅ Portuguese diacritics found in content
✅ UTF-8 encoding validation passed

================================================================================
CONVERSION SUMMARY
================================================================================
Rows:   134,014
Parquet size: 45.32 MB
CSV size:     89.67 MB
Compression:  49.5% (Parquet vs CSV)
```

---

### 2. validate_data_quality.py

**Purpose:** Comprehensive data quality validation for 134k+ documents

**Validation Tests:**
1. UTF-8 Encoding - Verify Portuguese diacritics preservation
2. Data Completeness - Check critical fields (titulo, urn, data, tipo, estado)
3. URN Uniqueness - Ensure no duplicate documents
4. Date Validation - Verify date formats and ranges (1829-2025)
5. Estado Field - Check state codes consistency
6. Portuguese Text - Validate legal terminology

**Usage:**

```bash
# Run all validations on production data
python3 validate_data_quality.py

# Validate specific file
python3 validate_data_quality.py \
    --input /path/to/data.parquet

# Custom report location
python3 validate_data_quality.py \
    --report-path /path/to/report.txt
```

**Output:**
- Console summary (pass/fail/warnings)
- Detailed text report with statistics
- Error and warning lists for remediation

**Example Output:**

```
================================================================================
RUNNING DATA QUALITY VALIDATION
================================================================================
📂 Loading data from brazilian_legislative_complete.parquet...
✅ Loaded 134,014 rows × 34 columns

🔍 Validating UTF-8 encoding...
   ✅ Found Portuguese diacritics: ã (til a), ç (cedilha), é (acento agudo e)

🔍 Validating data completeness...
   ✅ titulo: 99.2% complete
   ✅ urn: 98.7% complete
   ✅ data: 99.5% complete
   ✅ tipo: 95.3% complete
   ✅ estado: 78.4% complete

🔍 Validating URN uniqueness...
   ✅ All 132,314 URNs are unique

🔍 Validating date fields...
   ✅ 99.5% of dates are valid
   📅 Date range: 1829-01-15 to 2025-10-30

🔍 Validating estado field...
   ❌ Found 1,234 'Federal' values (should be 'DF')
   ⚠️  Found 89 invalid estado values

🔍 Validating Portuguese text quality...
   ✅ Found 8,542 instances of common legal terms

================================================================================
VALIDATION SUMMARY
================================================================================
Total Tests: 6
Passed: 4 ✅
Warnings: 1 ⚠️
Failed: 1 ❌

❌ VALIDATION FAILED - Fix errors before using data

📄 Report saved to: reports/data_quality_report_20251109_153045.txt
```

---

### 3. encoding_verification.sql

**Purpose:** Verify UTF-8 encoding and Portuguese character handling in database

**Tests:**
1. Database encoding settings (UTF-8, collation)
2. Portuguese characters storage test
3. Actual data verification (sample documents)
4. Diacritics frequency analysis
5. Common Portuguese legal terms
6. Accent-insensitive search (if unaccent available)
7. Collation test (Portuguese sorting)
8. Byte length analysis
9. Geographic names with diacritics
10. Summary and recommendations

**Usage:**

```bash
# Run verification on production database
psql $DATABASE_URL -f encoding_verification.sql

# Save output to file
psql $DATABASE_URL -f encoding_verification.sql > encoding_report.txt 2>&1

# Run specific sections
psql $DATABASE_URL -c "SELECT ..." # (copy queries from file)
```

**Output:**

```
============================================================================
UTF-8 ENCODING VERIFICATION
============================================================================

1. DATABASE ENCODING SETTINGS
-------------------------------------
 setting         | value          | status
-----------------+----------------+------------------------
 Server Encoding | UTF8           | ✅ CORRECT
 Client Encoding | UTF8           | ✅ CORRECT
 LC_COLLATE      | en_US.UTF-8    | ✅ UTF-8 compatible
 LC_CTYPE        | en_US.UTF-8    | ✅ UTF-8 compatible

4. PORTUGUESE DIACRITICS FREQUENCY
-------------------------------------
 diacritic           | count_in_titulo | count_in_content | status
---------------------+-----------------+------------------+----------
 ã (til a)           | 12,345          | 45,678           | ✅ Found
 ç (cedilha)         | 23,456          | 67,890           | ✅ Found
 é (acento agudo e)  | 34,567          | 89,012           | ✅ Found
 ...

============================================================================
ENCODING VERIFICATION SUMMARY
============================================================================
Total Documents: 134,014
Documents with Portuguese Diacritics: 98,765 (73.7%)

✅ ENCODING VERIFICATION PASSED

Key Points:
  ✅ Database encoding is UTF-8
  ✅ Portuguese diacritics are properly stored
  ✅ Data is ready for production use

Recommendations:
  1. Use UTF-8 encoding for all data imports
  2. Install unaccent extension for accent-insensitive search
  3. Consider pt_BR collation for proper Portuguese sorting
  4. Test search queries with Portuguese characters
```

---

## Usage Examples

### Example 1: Fresh Data Import

```bash
# 1. Generate CSV from Parquet
python3 parquet_to_csv.py

# 2. Validate data quality
python3 validate_data_quality.py

# 3. If validation passes, import to database
psql $DATABASE_URL < /path/to/import_script.sql

# 4. Verify encoding in database
psql $DATABASE_URL -f encoding_verification.sql

# 5. Create indexes
psql $DATABASE_URL -f ../migrations/001_create_essential_indexes.sql

# 6. Normalize estado field
psql $DATABASE_URL -f ../migrations/002_normalize_estado_field.sql
```

### Example 2: Troubleshooting Encoding Issues

```bash
# 1. Check Parquet encoding
python3 -c "
import pandas as pd
df = pd.read_parquet('data.parquet')
print(df['titulo'].head(10))
# Should show Portuguese characters correctly
"

# 2. Check CSV encoding
python3 -c "
import pandas as pd
df = pd.read_csv('data.csv', encoding='utf-8')
print(df['titulo'].head(10))
# Should show Portuguese characters correctly
"

# 3. Check database encoding
psql $DATABASE_URL -f encoding_verification.sql

# 4. If issues found, reconvert with explicit encoding
python3 parquet_to_csv.py --chunk-size 10000
```

### Example 3: Production Data Validation

```bash
# Weekly validation schedule
# Add to crontab: 0 2 * * 1 /path/to/weekly_validation.sh

#!/bin/bash
# weekly_validation.sh

DATE=$(date +%Y%m%d)
REPORT_DIR="/var/reports/data_quality"
mkdir -p $REPORT_DIR

# 1. Validate data quality
python3 /path/to/validate_data_quality.py \
    --report-path "$REPORT_DIR/quality_report_$DATE.txt"

# 2. Check encoding
psql $DATABASE_URL -f /path/to/encoding_verification.sql \
    > "$REPORT_DIR/encoding_report_$DATE.txt" 2>&1

# 3. Send alerts if issues found
if grep -q "FAILED" "$REPORT_DIR/quality_report_$DATE.txt"; then
    mail -s "Data Quality Alert" admin@example.com < "$REPORT_DIR/quality_report_$DATE.txt"
fi

# 4. Cleanup old reports (keep 30 days)
find $REPORT_DIR -name "*.txt" -mtime +30 -delete
```

---

## Maintenance Schedule

### Daily Tasks
- **Automatic:** None (tools run on-demand)
- **Manual:** Check application error logs for data issues

### Weekly Tasks
```bash
# Run data quality validation
python3 validate_data_quality.py --report-path weekly_report.txt
```

### Monthly Tasks
```bash
# 1. Full data quality check
python3 validate_data_quality.py

# 2. Encoding verification
psql $DATABASE_URL -f encoding_verification.sql > monthly_encoding.txt

# 3. Review and clean up reports
ls -lh reports/
```

### Quarterly Tasks
```bash
# 1. Rebuild indexes to reduce bloat
psql $DATABASE_URL -c "REINDEX TABLE CONCURRENTLY documents;"

# 2. Update table statistics
psql $DATABASE_URL -c "ANALYZE documents;"

# 3. Vacuum database
psql $DATABASE_URL -c "VACUUM ANALYZE documents;"
```

### Ad-hoc Tasks
- **After data import:** Run full validation suite
- **After schema changes:** Run encoding verification
- **Before major releases:** Complete validation + performance tests
- **After encoding issues:** Run encoding_verification.sql

---

## Troubleshooting

### Issue: CSV file has wrong encoding

**Symptoms:**
- Portuguese characters show as �� or ??? in CSV
- Database import fails with encoding errors

**Solution:**
```bash
# 1. Reconvert with explicit UTF-8
python3 parquet_to_csv.py

# 2. Verify output
head -20 data_current/processed/production/lexml_unified_dataset.csv

# 3. Check for proper characters
grep -i "são paulo" data_current/processed/production/lexml_unified_dataset.csv
```

### Issue: Database has wrong collation

**Symptoms:**
- Portuguese sorting is incorrect (Ávila before Acre)
- Case-sensitive queries when shouldn't be

**Solution:**
```sql
-- Check current collation
SHOW lc_collate;

-- Create Portuguese collation (PostgreSQL 14+)
CREATE COLLATION IF NOT EXISTS pt_br (
    provider = 'icu',
    locale = 'pt-BR'
);

-- Use in queries
SELECT * FROM documents
ORDER BY titulo COLLATE "pt_br";
```

### Issue: Validation finds duplicates

**Symptoms:**
- validate_data_quality.py reports duplicate URNs
- Database insert fails with uniqueness constraint

**Solution:**
```bash
# 1. Identify duplicates
python3 -c "
import pandas as pd
df = pd.read_parquet('data.parquet')
dupes = df[df['urn'].duplicated(keep=False)]
print(dupes[['id', 'urn', 'titulo']].to_string())
"

# 2. Remove duplicates (keep first occurrence)
python3 -c "
import pandas as pd
df = pd.read_parquet('data.parquet')
df_clean = df.drop_duplicates(subset='urn', keep='first')
df_clean.to_parquet('data_deduped.parquet')
print(f'Removed {len(df) - len(df_clean)} duplicates')
"

# 3. Re-validate
python3 validate_data_quality.py --input data_deduped.parquet
```

### Issue: Memory error during conversion

**Symptoms:**
- parquet_to_csv.py crashes with MemoryError
- System becomes unresponsive

**Solution:**
```bash
# Use smaller chunk size
python3 parquet_to_csv.py --chunk-size 5000

# Or process partitioned files individually
for file in data_current/processed/production/parquet/partitioned/**/*.parquet; do
    python3 parquet_to_csv.py --input "$file" --output "${file%.parquet}.csv"
done
```

---

## Tool Reference

### Command-Line Options

#### parquet_to_csv.py

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Input Parquet file path | `brazilian_legislative_complete.parquet` |
| `--output` | `-o` | Output CSV file path | `lexml_unified_dataset.csv` |
| `--chunk-size` | `-c` | Rows per chunk | 10000 |
| `--no-validate` | | Skip UTF-8 validation | False |
| `--help` | `-h` | Show help message | |

#### validate_data_quality.py

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--input` | `-i` | Input data file | `brazilian_legislative_complete.parquet` |
| `--report-path` | `-r` | Output report path | Auto-generated |
| `--help` | `-h` | Show help message | |

### Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Success | Continue with workflow |
| 1 | Validation failed | Fix errors before proceeding |
| 2 | File not found | Check input path |
| 3 | Encoding error | Verify UTF-8 encoding |

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Data Quality Check

on:
  push:
    paths:
      - 'data_current/**'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          pip install pandas pyarrow

      - name: Validate data quality
        run: |
          python3 database/tools/validate_data_quality.py

      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v2
        with:
          name: quality-report
          path: reports/
```

---

## Additional Resources

- **Database Schema:** `../migrations/README.md`
- **Performance Optimization:** `../migrations/001_create_essential_indexes.sql`
- **Estado Normalization:** `../migrations/002_normalize_estado_field.sql`
- **Comprehensive Analysis:** `../analysis/COMPREHENSIVE_DATABASE_ANALYSIS.md`

---

**Maintained by:** MackIntegridade DevOps Team
**Last Updated:** 2025-11-09
**Contact:** sofia.donario@mackenzie.br
