# File Organization Map - Monitor Legislativo v4

Generated: 2025-11-11

## Current Scattered Files Analysis

### Category 1: Cloud Build Configurations (29 files)

**Migration Runners (Production - Keep):**
- ✅ `cloudbuild-run-migration-009.yaml` - COMMITTED - Backup estado_mapeado
- ✅ `cloudbuild-run-migration-010.yaml` - COMMITTED - URN parser
- ✅ `cloudbuild-mark-bibliografia.yaml` - COMMITTED - Bibliography classification

**Migration Runners (Historical - Archive or Delete):**
- `cloudbuild-run-migration-004.yaml` - Populate from URN (old)
- `cloudbuild-run-migration-005.yaml` - Extract URN fields (old)
- `cloudbuild-run-migration-005a.yaml` - Add columns (old)
- `cloudbuild-run-migration-005a2.yaml` - Populate nivel (old version)
- `cloudbuild-run-migration-005a2-IMPROVED.yaml` - Populate nivel (improved version)
- `cloudbuild-run-migration-005b.yaml` - Populate autoridade_poder
- `cloudbuild-run-migration-005c.yaml` - Populate poder (old version)
- `cloudbuild-run-migration-005c-FIXED.yaml` - Populate poder (fixed)
- `cloudbuild-run-migration-005d.yaml` - Populate mes
- `cloudbuild-run-migration-005e.yaml` - Populate categoria_documento
- `cloudbuild-run-migration-005f.yaml` - Populate additional fields
- `cloudbuild-run-migration-005f-add-columns.yaml` - Add columns
- `cloudbuild-run-migration-005f1.yaml` - Populate tipo_documento
- `cloudbuild-run-migration-005f2.yaml` - Populate corte
- `cloudbuild-run-migration-005f3.yaml` - Populate regiao_judicial
- `cloudbuild-run-migration-006.yaml` - Enhance numero extraction
- `cloudbuild-run-migration-007.yaml` - Populate ano
- `cloudbuild-run-migration-008a.yaml` - Create TRT regioes
- `cloudbuild-run-migration-008b.yaml` - Populate estado_mapeado

**Investigation/Verification Tools (Keep for Reference):**
- ✅ `cloudbuild-investigate-null-urns.yaml` - COMMITTED - NULL URN investigation
- ✅ `cloudbuild-analyze-null-records.yaml` - COMMITTED - NULL records analysis
- ✅ `cloudbuild-compare-tipo-distribution.yaml` - COMMITTED - Document type comparison
- `cloudbuild-check-backup.yaml` - Backup verification
- `cloudbuild-verify-010.yaml` - Migration 010 verification
- `cloudbuild-schema-investigation.yaml` - Schema investigation

**Municipal Investigation (Archive):**
- `cloudbuild-municipal-investigation.yaml` - Municipal investigation v1
- `cloudbuild-municipal-investigation2.yaml` - Municipal investigation v2
- `cloudbuild-final-municipal-report.yaml` - Final municipal report
- `cloudbuild-final-report-inline.yaml` - Final report inline

### Category 2: Database Migrations (19 files)

**Location:** `database/migrations/`

**Executed/Production Migrations:**
- `004_populate_from_urn.sql` - Populate tipo, ano, numero from URN
- `005_extract_additional_urn_fields.sql` - Extract additional URN fields
- `005a_add_columns.sql` - Add new columns
- `005a2_populate_nivel.sql` - Populate nivel field (old)
- `005a2_populate_nivel_IMPROVED.sql` - Populate nivel field (improved)
- `005b_populate_autoridade_poder.sql` - Populate autoridade and poder
- `005c_populate_poder.sql` - Populate poder (old)
- `005c_populate_poder_FIXED.sql` - Populate poder (fixed)
- `005d_populate_mes.sql` - Populate mes field
- `005e_populate_categoria_documento.sql` - Populate categoria
- `005f_add_columns.sql` - Add additional columns
- `005f_populate_additional_fields.sql` - Populate additional fields
- `005f1_populate_tipo_documento.sql` - Populate tipo_documento
- `005f2_populate_corte.sql` - Populate corte field
- `005f3_populate_regiao_judicial.sql` - Populate regiao judicial
- `006_enhance_numero_extraction.sql` - Enhanced numero extraction
- `007_populate_ano.sql` - Populate ano field
- `008a_create_trt_regioes.sql` - Create TRT regioes table
- `008b_populate_estado_mapeado.sql` - Initial estado_mapeado population

**Script:**
- `RUN_FIXED_MIGRATIONS.sh` - Migration runner script

### Category 3: Analysis Tools (4 files)

**Location:** `analysis/`

**Production Tools (Keep):**
- ✅ `improved_urn_parser.py` - COMMITTED - Production URN parser (11/11 tests)
- ✅ `urn_pattern_analysis.py` - COMMITTED - Pattern analysis tool
- ✅ `urn_pattern_analysis.R` - COMMITTED - Statistical analysis
- ✅ `urn_pattern_queries.sql` - COMMITTED - SQL pattern queries

**Investigation Tools (Archive or Delete):**
- `EXECUTE_THESE_QUERIES.sql` - One-off query collection
- `export_urn_samples.sh` - URN sample export script
- `quick_urn_analysis.R` - Quick analysis script

### Category 4: Root Level Files (1 file)

- `deep-urn-investigation.sql` - Deep URN investigation queries

## Summary Statistics

- **Total Scattered Files:** 52
- **Already Committed:** 10 files
- **Need Organization:** 42 files

**Breakdown by Status:**
- Cloud Build configs to archive: 23 files
- Cloud Build configs to keep: 6 files
- Migration SQL files: 19 files
- Analysis tools to archive: 3 files
- Root level files: 1 file

## Recommended Organization Structure

```
monitor_legislativo_v4/
├── .archive/                          # Historical/old files
│   ├── cloudbuild/
│   │   ├── migrations/                # Old migration runners
│   │   │   ├── 004-007/              # Migrations 004-007
│   │   │   └── 008/                  # Migration 008
│   │   └── investigations/           # Completed investigations
│   │       └── municipal/            # Municipal investigation files
│   └── database/
│       └── migrations/               # Old migration SQL files
│           ├── 004-007/             # Historical migrations
│           └── 008/                 # Initial estado_mapeado work
│
├── infrastructure/                    # Active infrastructure configs
│   └── cloudbuild/
│       ├── migrations/               # Current migration runners
│       │   ├── 009-backup-estado-mapeado.yaml
│       │   ├── 010-urn-parser.yaml
│       │   └── 011-mark-bibliografia.yaml
│       └── tools/                    # Investigation/verification tools
│           ├── check-backup.yaml
│           ├── verify-migration.yaml
│           ├── investigate-null-urns.yaml
│           ├── analyze-null-records.yaml
│           └── compare-tipo-distribution.yaml
│
├── database/
│   └── migrations/                   # Only active/recent migrations
│       ├── 009_backup_estado_mapeado.sql (from /migrations)
│       └── 010_improved_urn_parser.sql (from /migrations)
│
├── analysis/                          # Analysis tools (current)
│   ├── urn_parsing/                  # URN parsing tools
│   │   ├── improved_urn_parser.py
│   │   ├── urn_pattern_analysis.py
│   │   ├── urn_pattern_analysis.R
│   │   └── urn_pattern_queries.sql
│   └── archived/                     # Old analysis scripts
│       ├── EXECUTE_THESE_QUERIES.sql
│       ├── export_urn_samples.sh
│       ├── quick_urn_analysis.R
│       └── deep-urn-investigation.sql
│
└── migrations/                        # REMOVE - move to database/migrations/
    ├── 009_backup_estado_mapeado.sql → database/migrations/
    └── 010_improved_urn_parser.sql   → database/migrations/
```

## File Disposition Recommendations

### KEEP (Move to Organized Structure):
1. Current migration configs (009, 010, bibliografia)
2. Investigation tools (null-urns, analyze, compare)
3. Production analysis tools (improved_urn_parser, pattern analysis)
4. Active migrations (009, 010)

### ARCHIVE (.archive/):
1. All historical migration configs (004-008)
2. Municipal investigation files
3. Old migration SQL files (004-008)
4. One-off analysis scripts

### DELETE (if not needed):
1. Temporary verification configs
2. Duplicate/superseded files
3. Development/test artifacts

## Next Steps

1. Create `.archive/` directory structure
2. Move historical files to archive
3. Create `infrastructure/cloudbuild/` structure
4. Move current configs to proper locations
5. Consolidate `migrations/` into `database/migrations/`
6. Reorganize `analysis/` with subdirectories
7. Update `.gitignore` for new structure
8. Create `MIGRATIONS.md` documenting all database changes
9. Create `INFRASTRUCTURE.md` documenting Cloud Build configs
10. Commit organized structure
