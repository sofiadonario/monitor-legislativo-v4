# Analysis Tools - Monitor Legislativo v4

This directory contains analysis and research tools for the Monitor Legislativo platform.

## Directory Structure

```
analysis/
└── urn_parsing/              # URN parsing and pattern analysis tools
    ├── improved_urn_parser.py        # Production URN parser (11/11 tests passed)
    ├── urn_pattern_analysis.py       # Pattern investigation and validation
    ├── urn_pattern_analysis.R        # Statistical URN analysis
    └── urn_pattern_queries.sql       # SQL queries for pattern detection
```

## URN Parsing Tools

### improved_urn_parser.py
Production-ready URN parser for extracting geographic information from Brazilian LexML URN structures.

**Features:**
- 6-priority hierarchical matching system
- Handles federal, state, and municipal documents
- 11/11 validation tests passed
- Confidence scoring (HIGH, MEDIUM, LOW, UNKNOWN)

**Usage:**
```python
from analysis.urn_parsing.improved_urn_parser import parse_urn_geography

estado, confidence = parse_urn_geography("urn:lex:br:federal:lei:2020-03-01;13.979")
# Returns: ('Nacional', 'HIGH')
```

### urn_pattern_analysis.py
Investigation and validation tool for URN patterns across the document database.

**Capabilities:**
- Pattern frequency analysis
- Regex validation
- Geographic coverage reporting
- Test case generation

### urn_pattern_analysis.R
Statistical analysis of URN patterns using R.

**Functions:**
- Distribution analysis
- Coverage metrics
- Visualization generation
- Statistical summaries

### urn_pattern_queries.sql
SQL queries for database-level pattern detection and analysis.

**Queries:**
- Pattern identification
- Coverage analysis
- Missing data detection
- Quality validation

## Results

**Database Coverage (as of 2025-11-11):**
- Legislative documents: 118,920 (100% geographic coverage)
- Bibliographic materials: 15,094 (marked as "Bibliografia")
- Total documents: 134,014

## Related Documentation

- `/docs/FILE_ORGANIZATION_MAP.md` - Complete file inventory
- `/docs/ORGANIZATION_PLAN.md` - Reorganization strategy
- `/database/migrations/010_improved_urn_parser.sql` - Production migration
- `/infrastructure/cloudbuild/migrations/` - Migration execution configs

## Archive

Historical one-off scripts have been moved to `/.archive/analysis/`:
- `EXECUTE_THESE_QUERIES.sql`
- `export_urn_samples.sh`
- `quick_urn_analysis.R`
- `deep-urn-investigation.sql`
