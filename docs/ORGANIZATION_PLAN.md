# File Organization Plan - Monitor Legislativo v4

## Executive Summary

**Problem:** 52 scattered files across the repository root, with unclear organization and mixed historical/current artifacts.

**Solution:** Consolidate into clear directory structure with archived historical files and organized current infrastructure.

**Impact:**
- Improved maintainability
- Clear separation of active vs. historical files
- Better onboarding for new developers
- Easier CI/CD management

---

## Proposed Directory Structure

```
monitor_legislativo_v4/
│
├── .archive/                              # NEW - Historical artifacts
│   ├── cloudbuild/
│   │   ├── migrations/                    # 23 old migration configs
│   │   └── investigations/                # 4 completed investigation configs
│   ├── database/
│   │   └── migrations/                    # 19 old SQL migration files
│   └── analysis/                          # 4 one-off analysis scripts
│
├── infrastructure/                        # NEW - Active infrastructure
│   └── cloudbuild/
│       ├── migrations/                    # Active migration runners
│       │   ├── 009-backup-estado-mapeado.yaml
│       │   ├── 010-urn-parser.yaml
│       │   └── 011-mark-bibliografia.yaml
│       └── tools/                         # Investigation/diagnostic tools
│           ├── investigate-null-urns.yaml
│           ├── analyze-null-records.yaml
│           ├── compare-tipo-distribution.yaml
│           ├── check-backup.yaml
│           └── verify-migration.yaml
│
├── database/
│   ├── migrations/                        # CONSOLIDATE HERE
│   │   ├── 001_*.sql (existing)
│   │   ├── 002_*.sql (existing)
│   │   ├── 003_*.sql (existing)
│   │   ├── 009_backup_estado_mapeado.sql  # MOVE from /migrations
│   │   └── 010_improved_urn_parser.sql    # MOVE from /migrations
│   └── docs/
│       └── MIGRATIONS.md                  # NEW - Migration documentation
│
├── analysis/
│   ├── urn_parsing/                       # NEW - Organized by topic
│   │   ├── improved_urn_parser.py
│   │   ├── urn_pattern_analysis.py
│   │   ├── urn_pattern_analysis.R
│   │   └── urn_pattern_queries.sql
│   └── README.md                          # NEW - Analysis tools docs
│
├── docs/                                  # NEW or EXISTING
│   ├── INFRASTRUCTURE.md                  # NEW - Cloud Build docs
│   ├── FILE_ORGANIZATION_MAP.md           # MOVE from root
│   └── ORGANIZATION_PLAN.md               # MOVE from root (this file)
│
└── migrations/                            # REMOVE - duplicate location
    └── (delete directory after moving files)
```

---

## Detailed Migration Plan

### Phase 1: Create New Directory Structure

```bash
# Create archive structure
mkdir -p .archive/cloudbuild/migrations
mkdir -p .archive/cloudbuild/investigations
mkdir -p .archive/database/migrations
mkdir -p .archive/analysis

# Create infrastructure structure
mkdir -p infrastructure/cloudbuild/migrations
mkdir -p infrastructure/cloudbuild/tools

# Create docs structure
mkdir -p docs
mkdir -p database/docs

# Create analysis structure
mkdir -p analysis/urn_parsing
```

### Phase 2: Move Historical Files to Archive

**2.1 Archive Old Migration Configs (23 files)**
```bash
mv cloudbuild-run-migration-004.yaml .archive/cloudbuild/migrations/
mv cloudbuild-run-migration-005*.yaml .archive/cloudbuild/migrations/
mv cloudbuild-run-migration-006.yaml .archive/cloudbuild/migrations/
mv cloudbuild-run-migration-007.yaml .archive/cloudbuild/migrations/
mv cloudbuild-run-migration-008*.yaml .archive/cloudbuild/migrations/
```

**2.2 Archive Investigation Configs (4 files)**
```bash
mv cloudbuild-municipal-investigation*.yaml .archive/cloudbuild/investigations/
mv cloudbuild-final-*.yaml .archive/cloudbuild/investigations/
mv cloudbuild-schema-investigation.yaml .archive/cloudbuild/investigations/
```

**2.3 Archive Old Migration SQL Files (19 files)**
```bash
mv database/migrations/004_*.sql .archive/database/migrations/
mv database/migrations/005*.sql .archive/database/migrations/
mv database/migrations/006_*.sql .archive/database/migrations/
mv database/migrations/007_*.sql .archive/database/migrations/
mv database/migrations/008*.sql .archive/database/migrations/
mv database/migrations/RUN_FIXED_MIGRATIONS.sh .archive/database/migrations/
```

**2.4 Archive One-Off Analysis Scripts (4 files)**
```bash
mv analysis/EXECUTE_THESE_QUERIES.sql .archive/analysis/
mv analysis/export_urn_samples.sh .archive/analysis/
mv analysis/quick_urn_analysis.R .archive/analysis/
mv deep-urn-investigation.sql .archive/analysis/
```

### Phase 3: Organize Active Files

**3.1 Move Current Migration Configs**
```bash
mv cloudbuild-run-migration-009.yaml infrastructure/cloudbuild/migrations/009-backup-estado-mapeado.yaml
mv cloudbuild-run-migration-010.yaml infrastructure/cloudbuild/migrations/010-urn-parser.yaml
mv cloudbuild-mark-bibliografia.yaml infrastructure/cloudbuild/migrations/011-mark-bibliografia.yaml
```

**3.2 Move Investigation/Tool Configs**
```bash
mv cloudbuild-investigate-null-urns.yaml infrastructure/cloudbuild/tools/
mv cloudbuild-analyze-null-records.yaml infrastructure/cloudbuild/tools/
mv cloudbuild-compare-tipo-distribution.yaml infrastructure/cloudbuild/tools/
mv cloudbuild-check-backup.yaml infrastructure/cloudbuild/tools/
mv cloudbuild-verify-010.yaml infrastructure/cloudbuild/tools/verify-migration.yaml
```

**3.3 Consolidate Migration SQL Files**
```bash
# Move from /migrations to /database/migrations
mv migrations/009_backup_estado_mapeado.sql database/migrations/
mv migrations/010_improved_urn_parser.sql database/migrations/
rmdir migrations/  # Remove now-empty directory
```

**3.4 Organize Analysis Tools**
```bash
mv analysis/improved_urn_parser.py analysis/urn_parsing/
mv analysis/urn_pattern_analysis.py analysis/urn_parsing/
mv analysis/urn_pattern_analysis.R analysis/urn_parsing/
mv analysis/urn_pattern_queries.sql analysis/urn_parsing/
```

**3.5 Organize Documentation**
```bash
mv FILE_ORGANIZATION_MAP.md docs/
mv ORGANIZATION_PLAN.md docs/
```

### Phase 4: Update Configuration Files

**4.1 Update .gitignore**
```bash
# Add to .gitignore:
.archive/
*.log
*.tmp
```

**4.2 Create Documentation Files**
- `database/docs/MIGRATIONS.md` - Document all migrations
- `docs/INFRASTRUCTURE.md` - Document Cloud Build configs
- `analysis/README.md` - Document analysis tools

### Phase 5: Update References

**5.1 Update any scripts/configs that reference moved files**
- Check for hardcoded paths in scripts
- Update any CI/CD references
- Update documentation links

### Phase 6: Commit and Push

```bash
git add .archive/ infrastructure/ database/migrations/ analysis/ docs/
git add .gitignore
git commit -m "refactor: Organize project file structure"
git push origin main
```

---

## Risk Assessment

### Low Risk:
- Moving files to .archive (not tracked by git)
- Creating new directories
- Moving committed files (git handles renames)

### Medium Risk:
- Renaming Cloud Build configs (need to update any CI/CD references)
- Consolidating migrations directory

### Mitigation:
1. Test all moves in a branch first
2. Keep .archive/ for rollback capability
3. Update all references before deployment
4. Document all changes

---

## Rollback Plan

If issues arise:
1. All archived files remain in `.archive/` directory
2. Git history preserves all committed file locations
3. Can restore from `.archive/` if needed
4. Can revert commit if organizational structure causes issues

---

## Post-Organization Tasks

1. ✅ Verify all active Cloud Build configs work
2. ✅ Update team documentation
3. ✅ Update README.md with new structure
4. ✅ Create CONTRIBUTING.md with file organization guidelines
5. ✅ Update onboarding documentation
6. ✅ Test migrations from new locations
7. ✅ Update any deployment scripts

---

## Decision Required

**Option A: Execute Full Plan (Recommended)**
- Cleanest solution
- Clear separation of concerns
- Better long-term maintainability
- Requires updating references

**Option B: Minimal Organization**
- Only move to .archive/
- Keep current active files where they are
- Less disruption
- Doesn't solve root clutter

**Option C: Gradual Migration**
- Phase 1: Archive only
- Phase 2: Organize infrastructure (next sprint)
- Phase 3: Consolidate migrations (future)
- Lowest risk, longer timeline

---

**Recommendation:** Execute Option A now. Project is in good state post-migration, perfect time for housekeeping.

Would you like me to proceed with Option A?
