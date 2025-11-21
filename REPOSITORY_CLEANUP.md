execute it# Repository Cleanup Plan
## Monitor Legislativo v4 - Pre-bslib Migration

**Date**: 2025-10-26
**Purpose**: Systematic cleanup and organization before bslib migration
**Estimated Time**: 30-45 minutes

---

## Executive Summary

The repository currently contains:
- **124 markdown files** in root directory
- **117 R script files** in root directory
- **31 shell/Python/SQL scripts** in root directory
- **13 backup/deprecated files** in root directory
- **Multiple duplicate folders**: `archive`, `docs`, `docs_backup`, `documentation`, `legacy`
- **Test/debug scripts scattered throughout**

**Goal**: Organize the repository into a clean, professional structure with all legacy/obsolete content properly archived and ignored by git.

---

## Phase 0: Pre-Cleanup Safety

### 0.1 Create Complete Backup

```bash
cd "/Users/sofiadonario/Library/CloudStorage/OneDrive-Personal/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4"

# Create timestamped backup
BACKUP_DIR="../monitor_legislativo_v4_backup_before_cleanup_$(date +%Y%m%d_%H%M%S)"
cp -r . "$BACKUP_DIR"
echo "Backup created at: $BACKUP_DIR"
```

### 0.2 Commit Current State

```bash
git add -A
git commit -m "checkpoint: before repository cleanup (pre-bslib migration)"
git push origin main
```

---

## Phase 1: Create Legacy Archive Structure (5 min)

### 1.1 Create Legacy Directory Structure

```bash
mkdir -p _legacy/{documentation,scripts,backups,test_debug,obsolete_code,media,environments}
```

**Structure Explanation**:
- `_legacy/documentation/` - All outdated markdown docs, reports, summaries
- `_legacy/scripts/` - Old test scripts, debug files, one-off utilities
- `_legacy/backups/` - All .backup, .bak, .deprecated files
- `_legacy/test_debug/` - Test files, debug scripts, diagnostic tools
- `_legacy/obsolete_code/` - Deprecated R files, old app versions
- `_legacy/media/` - Old screenshots, PNGs, generated visualizations
- `_legacy/environments/` - Old Python environments (check_env, lexml_env, etc.)

### 1.2 Update .gitignore

```bash
cat >> .gitignore << 'EOF'

# === LEGACY FILES (IGNORED) ===
_legacy/
**/backup_*/
**/*.backup
**/*.bak
**/*.bak2
**/*.deprecated
**/*.old
**/temp_venv/

# === GENERATED VISUALIZATIONS ===
**/*.png
**/*.jpg
**/*.jpeg
!docs/images/*.png
!www/images/*.png

# === TEMPORARY/DEBUG FILES ===
**/debug_*.R
**/test_*.R
!tests/**/*.R
**/*.html
!www/**/*.html
!docs/**/*.html

# === OLD ENVIRONMENTS ===
check_env/
lexml_env/
reload_env/
renv/
Lib/

# === NODE MODULES (if applicable) ===
node_modules/
**/node_modules/

EOF
```

---

## Phase 2: Move Documentation (10 min)

### 2.1 Obsolete Sprint/Week Documentation

**Files to Move** (v46-v60 debugging phase is over, keep only DEBUGGING_LOG.md and MIGRATION_PLAN.md):

```bash
# Move all SPRINT/WEEK documentation to legacy
mv SPRINT_*.md _legacy/documentation/
mv WEEK_*.md _legacy/documentation/
mv WEEK*.md _legacy/documentation/
mv PHASE*.md _legacy/documentation/

# Move obsolete implementation summaries
mv ADVANCED_*.md _legacy/documentation/
mv ENHANCED_*.md _legacy/documentation/
mv *_IMPLEMENTATION_*.md _legacy/documentation/
mv *_DEPLOYMENT_*.md _legacy/documentation/
mv *_COMPLETION_*.md _legacy/documentation/
mv *_SUMMARY*.md _legacy/documentation/
mv *_REPORT*.md _legacy/documentation/

# Keep these critical docs in root:
# - README.md
# - DEBUGGING_LOG.md
# - MIGRATION_PLAN.md
# - REPOSITORY_CLEANUP.md (this file)
```

### 2.2 Consolidate Documentation Folders

The repository has **four** separate documentation folders:
- `docs/`
- `docs_backup/`
- `documentation/`
- `legacy/`

**Action**:

```bash
# Move docs_backup content into _legacy
mv docs_backup _legacy/documentation/docs_backup

# Move legacy folder content into _legacy
mv legacy _legacy/documentation/legacy_old

# Consolidate documentation/ into docs/
rsync -av documentation/ docs/
rm -rf documentation/

# Keep only docs/ for active documentation
```

---

## Phase 3: Move Backup & Deprecated Files (5 min)

### 3.1 Backup Files

```bash
# Root-level backup files
mv *.backup _legacy/backups/
mv *.bak _legacy/backups/
mv *.bak2 _legacy/backups/
mv *.deprecated _legacy/backups/
mv *_backup.R _legacy/backups/
mv *_original_backup.R _legacy/backups/

# Specific backup files identified
mv app.R.backup_before_fix _legacy/backups/
mv app.R.backup_pre_auth _legacy/backups/
mv app.R.deprecated _legacy/backups/
mv app_backup.R _legacy/backups/
mv app_original_backup.R _legacy/backups/
mv global.R.backup _legacy/backups/
mv global.R.deprecated _legacy/backups/
mv Dockerfile.backup _legacy/backups/
mv server.R.bak _legacy/backups/
mv server.R.bak2 _legacy/backups/

# Backup directories
mv backup_20250924_130430 _legacy/backups/
mv backup_before_credential_cleanup_20250819_112108 _legacy/backups/
```

### 3.2 Optimized/Variant Files

```bash
# These are old optimization attempts
mv app_optimized.R _legacy/obsolete_code/
mv app_integrated.R _legacy/obsolete_code/
mv app_modular.R _legacy/obsolete_code/
mv global_optimized.R _legacy/obsolete_code/
mv server_optimized.R _legacy/obsolete_code/
mv Dockerfile.optimized _legacy/obsolete_code/
mv Dockerfile.production _legacy/obsolete_code/

# Minimal test variants (from v46-v60 debugging)
mv app_absolute_minimal.R _legacy/test_debug/
mv app_test_no_global.R _legacy/test_debug/
mv test_minimal.R _legacy/test_debug/
mv ui_minimal_tabs.R _legacy/test_debug/
```

---

## Phase 4: Move Test & Debug Scripts (10 min)

### 4.1 Test Scripts

```bash
# Move ALL test_* files to legacy (except tests/ directory)
find . -maxdepth 1 -name "test_*.R" -exec mv {} _legacy/test_debug/ \;
find . -maxdepth 1 -name "test_*.py" -exec mv {} _legacy/test_debug/ \;
find . -maxdepth 1 -name "test_*.sh" -exec mv {} _legacy/test_debug/ \;

# Specific test files
mv run_all_tests.R _legacy/test_debug/
mv run_integration_tests.R _legacy/test_debug/
mv run_tests.R _legacy/test_debug/
```

### 4.2 Debug Scripts

```bash
# Debug scripts from root
find . -maxdepth 1 -name "debug_*.R" -exec mv {} _legacy/test_debug/ \;
mv diagnose_*.R _legacy/test_debug/
mv check_*.R _legacy/test_debug/
mv simple_*.R _legacy/test_debug/
```

### 4.3 One-off Utility Scripts

```bash
# Database population scripts (keep populate_cloud_sql.R, move rest)
mv populate_database.R _legacy/scripts/
mv populate_database_base.R _legacy/scripts/
mv populate_db.R _legacy/scripts/
mv populate_full_database.R _legacy/scripts/

# Deployment test scripts
mv deploy_sprint7b_test.R _legacy/scripts/
mv lightweight_sprint7b_validation.R _legacy/scripts/
mv comprehensive_sprint7b_test.R _legacy/scripts/
mv quick_sprint7b_validation.R _legacy/scripts/

# Analysis scripts (old)
mv comprehensive_municipality_search.R _legacy/scripts/
mv municipality_summary_analysis.R _legacy/scripts/
mv temporal_analysis*.R _legacy/scripts/
mv temporal_visualizations.R _legacy/scripts/

# Cleanup/migration scripts (already executed)
mv migrate_to_clean.sh _legacy/scripts/
mv cleanup_emergency_files.sh _legacy/scripts/
mv commit_changes.sh _legacy/scripts/
mv rebase_commits.sh _legacy/scripts/
mv nuclear_git_cleanup.sh _legacy/scripts/
mv simple_nuclear_cleanup.sh _legacy/scripts/
mv remove_dangerous_file.sh _legacy/scripts/
```

---

## Phase 5: Move Media & Generated Files (5 min)

### 5.1 Generated Visualizations

```bash
# PNG files (generated charts - not source images)
mkdir -p _legacy/media/visualizations
mv *.png _legacy/media/visualizations/

# Keep README images if you have them
# mkdir -p docs/images
# (manually move any needed images back)
```

### 5.2 Generated HTML Files

```bash
# Debug HTML outputs (very large files ~76MB each)
mv debug_choropleth.html _legacy/media/
mv test_choropleth_direct.html _legacy/media/
mv debug_choropleth_files _legacy/media/
mv test_choropleth_direct_files _legacy/media/
```

### 5.3 Other Media

```bash
# PDF files
mv "Monitor Legislativo v4 – System Diagnostic Audit.pdf" _legacy/media/
mv "Relatório Parcial MACKPESQUISA.docx" _legacy/media/
```

---

## Phase 6: Move Old Environments (3 min)

```bash
# Python virtual environments
mv check_env _legacy/environments/
mv lexml_env _legacy/environments/
mv reload_env _legacy/environments/
mv Lib _legacy/environments/

# R environment (renv - currently disabled)
mv renv _legacy/environments/
mv renv.lock _legacy/environments/

# Node modules (if any)
if [ -d "dev-tools/node_modules" ]; then
    mv dev-tools/node_modules _legacy/environments/
fi
```

---

## Phase 7: Consolidate Remaining Folders (5 min)

### 7.1 Archive Folder

The `archive/` folder already exists and contains:
- app_development_versions
- backup_files
- config_files
- database_fixes
- debug_files
- diagnostic_files
- legacy_data
- legacy_environments
- media
- miscellaneous
- old-files
- old_analysis_scripts
- temp_files
- temporary

**Action**: Move entire archive/ to _legacy:

```bash
mv archive _legacy/archive_old
```

### 7.2 Fixes Folder

The `fixes/` folder contains database fixes and documentation from earlier debugging.

**Action**: Keep if relevant to v61+ or move to legacy:

```bash
# Review fixes folder - if all fixes are for old versions, move:
mv fixes _legacy/fixes_old

# OR keep if some fixes are still relevant:
# Leave it as is
```

### 7.3 Cache Folder

```bash
# Check if cache contains any critical data
ls -la cache/

# If all generated cache, move to _legacy:
mv cache _legacy/cache_old

# OR clear cache and keep empty folder:
# rm -rf cache/*
```

---

## Phase 8: Clean Up Root Directory (5 min)

### 8.1 Files to KEEP in Root

**Essential Application Files**:
- `app.R` - Main application entry point
- `ui.R` - UI definition (will be migrated to bslib)
- `server.R` - Server logic
- `global_integrated.R` - Global configuration
- `Dockerfile` - Container definition

**Essential Config Files**:
- `.gitignore` - Git ignore rules
- `.dockerignore` - Docker ignore rules
- `.env.example` - Environment variable template
- `docker-compose.yml` - Local development setup
- `cloudbuild.yaml` - GCP build configuration
- `pyproject.toml` - Python project config
- `.lintr` - R linting configuration

**Essential Documentation**:
- `README.md` - Project overview
- `DEBUGGING_LOG.md` - v46-v60 debugging history
- `MIGRATION_PLAN.md` - bslib migration guide
- `REPOSITORY_CLEANUP.md` - This cleanup documentation

**Essential Scripts**:
- `deploy.sh` - Deployment script
- `gcp_deploy.sh` - GCP-specific deployment
- `check_logs.sh` - Log checking utility
- `populate_cloud_sql.R` - Database population (active)

### 8.2 Root Directory Structure After Cleanup

```
monitor_legislativo_v4/
├── app.R                       # Main app entry
├── ui.R                        # UI definition
├── server.R                    # Server logic
├── global_integrated.R         # Global config
├── Dockerfile                  # Container definition
│
├── README.md                   # Project overview
├── DEBUGGING_LOG.md            # Debugging history
├── MIGRATION_PLAN.md           # bslib migration guide
├── REPOSITORY_CLEANUP.md       # This file
│
├── .gitignore                  # Git rules
├── .dockerignore               # Docker rules
├── .env.example                # Env template
├── docker-compose.yml          # Local dev setup
├── cloudbuild.yaml             # GCP build config
│
├── deploy.sh                   # Deployment
├── gcp_deploy.sh               # GCP deploy
├── check_logs.sh               # Log utility
├── populate_cloud_sql.R        # DB population
│
├── R/                          # R source code
│   ├── modules/                # Shiny modules
│   ├── ui/                     # UI components
│   ├── utils/                  # Utility functions
│   ├── services/               # Business logic
│   └── ...
│
├── api/                        # API endpoints
├── database/                   # DB migrations & schemas
├── docs/                       # Active documentation
├── tests/                      # Test suite
├── www/                        # Static assets
│
├── data_current/               # Current datasets
├── scripts/                    # Active utility scripts
├── config/                     # Configuration files
│
└── _legacy/                    # Archived content (gitignored)
    ├── documentation/
    ├── scripts/
    ├── backups/
    ├── test_debug/
    ├── obsolete_code/
    ├── media/
    └── environments/
```

### 8.3 Remove Obsolete Files

```bash
# JSON/log files from debugging
mv csv_municipality_*.json _legacy/scripts/
mv *_results.rds _legacy/test_debug/
mv security_scan_output.log _legacy/scripts/
mv prod.log _legacy/scripts/
mv prod_fixed.log _legacy/scripts/

# SQL scripts (keep only active migrations in database/)
mv *.sql _legacy/scripts/
mv *_municipality_*.sql _legacy/scripts/

# Python analysis scripts
mv *_municipality_*.py _legacy/scripts/
mv quick_*.py _legacy/scripts/

# Shell scripts (keep only deploy scripts in root)
mv import_real_dataset*.sh _legacy/scripts/
mv create_sample_data.sh _legacy/scripts/
mv force_full_dataset.R _legacy/scripts/
mv show_csv_error.R _legacy/scripts/

# Config files for discontinued tools
mv claude_desktop_config.json _legacy/scripts/
mv .mcp-scan.json _legacy/scripts/
mv .mcp.json _legacy/scripts/
```

---

## Phase 9: Update .dockerignore

```bash
cat >> .dockerignore << 'EOF'

# === LEGACY & BACKUPS (NEVER INCLUDE IN BUILDS) ===
_legacy/
**/backup_*/
**/*.backup
**/*.bak
**/*.deprecated

# === TEST FILES ===
**/test_*.R
**/debug_*.R
tests/

# === DOCUMENTATION (NOT NEEDED IN PRODUCTION) ===
docs/
*.md
!README.md

# === MEDIA FILES ===
**/*.png
**/*.jpg
**/*.pdf
**/*.docx

# === ENVIRONMENTS ===
check_env/
lexml_env/
reload_env/
renv/
Lib/
node_modules/
**/venv/

# === DEVELOPMENT TOOLS ===
.vscode/
.claude/
dev-tools/

# === GIT ===
.git/
.github/

EOF
```

---

## Phase 10: Final Verification & Commit

### 10.1 Verify Directory Structure

```bash
# Check root is clean
ls -1 | wc -l
# Should be ~30 items or less

# Check _legacy was created properly
ls -la _legacy/
```

### 10.2 Update README.md

Add a section about the repository structure:

```markdown
## Repository Structure

```
monitor_legislativo_v4/
├── app.R                  # Main application entry point
├── ui.R / server.R        # Shiny UI and server logic
├── global_integrated.R    # Global configuration
│
├── R/                     # R source code
│   ├── modules/           # Shiny modules
│   ├── ui/                # UI tab components
│   ├── utils/             # Utility functions
│   └── services/          # Business logic
│
├── database/              # Database migrations and schemas
├── docs/                  # Documentation
├── tests/                 # Test suite
├── www/                   # Static web assets (CSS, JS, images)
│
└── _legacy/               # Archived legacy content (gitignored)
```

For historical context, see `_legacy/documentation/` for sprint summaries, implementation reports, and debugging logs from v1-v60.
```

### 10.3 Create Cleanup Summary

```bash
cat > _legacy/LEGACY_ARCHIVE_INDEX.md << 'EOF'
# Legacy Archive Index

This folder contains all archived content from the Monitor Legislativo v4 project cleanup performed on 2025-10-26 before the bslib migration (v61).

## Structure

- **documentation/** - 124 markdown files (sprint summaries, implementation reports, deployment guides from v1-v60)
- **scripts/** - Test scripts, debug utilities, one-off analysis tools
- **backups/** - All .backup, .bak, .deprecated files from development
- **test_debug/** - Debug scripts, diagnostic tools, minimal test apps
- **obsolete_code/** - Old app versions, optimization attempts, deprecated implementations
- **media/** - Generated visualizations, debug HTML outputs, PDFs
- **environments/** - Old Python/R environments (check_env, lexml_env, renv)

## Why These Files Were Archived

All files here were moved during the pre-bslib migration cleanup to:
1. Reduce repository noise and complexity
2. Improve developer onboarding experience
3. Maintain professional repository appearance
4. Keep git history clean while preserving historical context

## Retrieval

If you need to reference any archived content:

1. **Documentation**: Check `documentation/` for historical implementation details
2. **Old Code**: Check `obsolete_code/` and `backups/` for previous implementations
3. **Debug Tools**: Check `test_debug/` for diagnostic scripts

## Permanent Deletion

⚠️ This folder is gitignored. It exists only in your local checkout.

If you're confident this content is no longer needed, you can delete the entire `_legacy/` folder:

```bash
rm -rf _legacy/
```

**Note**: Once deleted, this content cannot be recovered unless you have a backup.
EOF
```

### 10.4 Git Add & Commit

```bash
cd "/Users/sofiadonario/Library/CloudStorage/OneDrive-Personal/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4"

# Add all changes (respecting .gitignore - _legacy will NOT be committed)
git add -A

# Commit the cleanup
git commit -m "cleanup: systematic repository reorganization before bslib migration (v61)

- Moved 124 obsolete markdown docs to _legacy/documentation/
- Moved 117 test/debug R scripts to _legacy/test_debug/
- Moved all backup files (.backup, .bak, .deprecated) to _legacy/backups/
- Moved old app variants to _legacy/obsolete_code/
- Moved generated visualizations to _legacy/media/
- Moved old environments to _legacy/environments/
- Consolidated documentation folders (docs_backup, documentation → docs)
- Archived entire archive/ and fixes/ folders to _legacy/
- Updated .gitignore to exclude _legacy/ permanently
- Updated .dockerignore to exclude test/debug files from builds
- Root directory now contains only essential files (~30 items vs. 400+)

This cleanup prepares the repository for the bslib migration (v61) with a clean, professional structure.

See REPOSITORY_CLEANUP.md for complete cleanup documentation.
See _legacy/LEGACY_ARCHIVE_INDEX.md for archived content index.
"

# Push to remote
git push origin main
```

---

## Phase 11: Update MIGRATION_PLAN.md

Add cleanup as a prerequisite to the migration plan:

```markdown
## Phase 0: Repository Cleanup (PREREQUISITE)

**IMPORTANT**: Before starting the bslib migration, ensure the repository is cleaned up.

✅ **Status**: Complete (if you see this, cleanup was already done)

**Actions Taken**:
- Moved all legacy documentation, test scripts, and backup files to `_legacy/` folder
- Consolidated documentation into single `docs/` directory
- Root directory reduced from 400+ items to ~30 essential files
- Updated .gitignore and .dockerignore to exclude legacy content

**Verification**:
```bash
# Root should have ~30 items
ls -1 | wc -l

# _legacy should exist but be gitignored
ls -la _legacy/
```

If cleanup was NOT performed, run:
```bash
# See REPOSITORY_CLEANUP.md for complete instructions
# Or run the automated cleanup script:
bash scripts/cleanup_repository.sh
```

Then proceed with Phase 1: Preparation.
```

---

## Automated Cleanup Script (Optional)

Create an automated script for quick execution:

```bash
cat > scripts/cleanup_repository.sh << 'EOF'
#!/bin/bash
# Automated Repository Cleanup Script
# Run from repository root: bash scripts/cleanup_repository.sh

set -e  # Exit on error

echo "=== Monitor Legislativo v4 - Repository Cleanup ==="
echo "This will move legacy files to _legacy/ folder"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleanup cancelled."
    exit 1
fi

# Create _legacy structure
echo "Creating _legacy directory structure..."
mkdir -p _legacy/{documentation,scripts,backups,test_debug,obsolete_code,media,environments}

# Move documentation
echo "Moving obsolete documentation..."
find . -maxdepth 1 -name "SPRINT_*.md" -exec mv {} _legacy/documentation/ \; 2>/dev/null || true
find . -maxdepth 1 -name "WEEK_*.md" -exec mv {} _legacy/documentation/ \; 2>/dev/null || true
find . -maxdepth 1 -name "*_IMPLEMENTATION_*.md" -exec mv {} _legacy/documentation/ \; 2>/dev/null || true
find . -maxdepth 1 -name "*_DEPLOYMENT_*.md" -exec mv {} _legacy/documentation/ \; 2>/dev/null || true
find . -maxdepth 1 -name "*_SUMMARY*.md" -exec mv {} _legacy/documentation/ \; 2>/dev/null || true
find . -maxdepth 1 -name "*_REPORT*.md" -exec mv {} _legacy/documentation/ \; 2>/dev/null || true

# Move backups
echo "Moving backup files..."
find . -maxdepth 1 \( -name "*.backup" -o -name "*.bak" -o -name "*.bak2" -o -name "*.deprecated" \) -exec mv {} _legacy/backups/ \; 2>/dev/null || true
find . -maxdepth 1 -name "*_backup.R" -exec mv {} _legacy/backups/ \; 2>/dev/null || true

# Move test/debug scripts
echo "Moving test and debug scripts..."
find . -maxdepth 1 -name "test_*.R" -exec mv {} _legacy/test_debug/ \; 2>/dev/null || true
find . -maxdepth 1 -name "debug_*.R" -exec mv {} _legacy/test_debug/ \; 2>/dev/null || true

# Move generated media
echo "Moving generated visualizations..."
find . -maxdepth 1 -name "*.png" -exec mv {} _legacy/media/visualizations/ \; 2>/dev/null || true
find . -maxdepth 1 -name "*.html" -exec mv {} _legacy/media/ \; 2>/dev/null || true

# Move old environments
echo "Moving old environments..."
[ -d "check_env" ] && mv check_env _legacy/environments/ || true
[ -d "lexml_env" ] && mv lexml_env _legacy/environments/ || true
[ -d "reload_env" ] && mv reload_env _legacy/environments/ || true
[ -d "renv" ] && mv renv _legacy/environments/ || true

# Move archive folder
echo "Moving archive folder..."
[ -d "archive" ] && mv archive _legacy/archive_old || true

# Update .gitignore
echo "Updating .gitignore..."
cat >> .gitignore << 'GITIGNORE_EOF'

# === LEGACY FILES (CLEANUP 2025-10-26) ===
_legacy/
**/backup_*/
**/*.backup
**/*.bak
**/*.deprecated
check_env/
lexml_env/
reload_env/
renv/
Lib/
GITIGNORE_EOF

echo ""
echo "=== Cleanup Complete ==="
echo "Files moved to _legacy/ (gitignored)"
echo ""
echo "Next steps:"
echo "1. Review _legacy/ folder to ensure nothing critical was moved"
echo "2. git add -A && git commit -m 'cleanup: repository reorganization'"
echo "3. Proceed with bslib migration (see MIGRATION_PLAN.md)"
EOF

chmod +x scripts/cleanup_repository.sh
```

---

## Summary

### What Was Cleaned Up

| Category | Count | Destination |
|----------|-------|-------------|
| Markdown documentation | ~124 files | `_legacy/documentation/` |
| Test/debug R scripts | ~117 files | `_legacy/test_debug/` |
| Backup files | ~13 files | `_legacy/backups/` |
| Shell/Python/SQL scripts | ~31 files | `_legacy/scripts/` |
| Generated visualizations (PNG) | ~20 files | `_legacy/media/` |
| Generated HTML outputs | ~2 files (76MB each) | `_legacy/media/` |
| Old environments | 4 folders | `_legacy/environments/` |
| Archive folders | 3 folders | `_legacy/archive_old/` |

### Files Remaining in Root

**~30 essential files**:
- Application code (app.R, ui.R, server.R, global_integrated.R)
- Build config (Dockerfile, docker-compose.yml, cloudbuild.yaml)
- Git config (.gitignore, .dockerignore, .lintr)
- Documentation (README.md, DEBUGGING_LOG.md, MIGRATION_PLAN.md, this file)
- Deployment scripts (deploy.sh, gcp_deploy.sh, check_logs.sh)
- Database utilities (populate_cloud_sql.R)

### Benefits

1. **Professional Appearance**: Clean repository structure for new developers
2. **Reduced Cognitive Load**: Essential files easy to find, no clutter
3. **Preserved History**: All legacy content archived locally, retrievable if needed
4. **Git Performance**: Smaller repository size (legacy files gitignored)
5. **Docker Performance**: Faster builds (.dockerignore excludes legacy)
6. **Migration Ready**: Clean slate for bslib implementation (v61)

---

## Next Steps

After completing this cleanup:

1. ✅ Verify `_legacy/` folder exists and contains archived content
2. ✅ Verify root directory has ~30 items
3. ✅ Commit cleanup changes to git
4. ✅ Push to remote repository
5. ➡️  **Proceed with MIGRATION_PLAN.md - Phase 1: Preparation**

---

**Questions or Issues?**

If you accidentally moved something critical:
1. Check `_legacy/` folders for the file
2. Move it back to the appropriate location
3. Update .gitignore if needed to track it

If you need to completely undo the cleanup:
```bash
# Restore from backup
cd "/Users/sofiadonario/Library/CloudStorage/OneDrive-Personal/Doutorado Stuff/MackIntegridade"
rm -rf monitor_legislativo_v4
cp -r monitor_legislativo_v4_backup_before_cleanup_* monitor_legislativo_v4
```
