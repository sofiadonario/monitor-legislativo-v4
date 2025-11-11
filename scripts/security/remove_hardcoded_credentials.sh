#!/bin/bash

# Script to safely remove files with hardcoded credentials
# This script will backup files before deletion for safety

echo "========================================="
echo "CREDENTIAL CLEANUP SCRIPT"
echo "========================================="
echo ""

# Create backup directory with timestamp
BACKUP_DIR="backup_before_credential_cleanup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Creating backup in: $BACKUP_DIR"
echo ""

# List of files to remove (containing hardcoded credentials)
FILES_TO_REMOVE=(
    "RAILWAY_PRODUCTION_DB_FIX.R"
    "diagnose_library_issue.R"
    "municipality_investigation.py"
    "municipality_deep_investigation.R"
    "municipality_visualizations.R"
    "municipality_report.R"
    "municipality_analysis.R"
    "fixes/legacy/apply_data_fixes.py"
    "fixes/legacy/apply_fixes_direct.py"
    "fixes/legacy/EMERGENCY_DATABASE_FIX.R"
    "fixes/legacy/run_database_fix.sh"
    "fixes/legacy/fix_remaining_camelcase.py"
    "fixes/legacy/verify_camelcase_fixes.py"
    "fixes/legacy/fix_all_camelcase.py"
    "fixes/legacy/fix_title_dates.py"
    "fixes/legacy/fix_municipality_spacing.py"
    "fixes/legacy/deploy_fix.py"
    "dev-tools/railway_database_diagnostic.R"
    "dev-tools/check_railway_deployment.R"
    "dev-tools/scripts/auto_migrate_to_railway.py"
    "dev-tools/scripts/migrate_supabase_direct.py"
    "dev-tools/scripts/migrate_real_data.py"
    "dev-tools/scripts/setup_sample_data.py"
    "dev-tools/scripts/migrate_supabase_to_railway.py"
    "dev-tools/scripts/connect_railway_db.py"
    "dev-tools/scripts/run_migration.py"
    "database/migrations/migrate_auto.py"
    "database/migrations/migrate_csv_batch.py"
    "database/migrations/migrate_from_csv.py"
    "database/migrations/migrate_to_railway.py"
    "database/migrations/verify_migration.py"
    "archive/database_fixes/RAILWAY_DATABASE_FINAL_FIX.R"
    "archive/database_fixes/RAILWAY_DATABASE_CONNECTION_FIX.R"
    "archive/database_fixes/RAILWAY_DATABASE_FIX_CORRECTED.R"
    "archive/database_fixes/RAILWAY_STARTUP_FIX.R"
    "archive/database_fixes/RAILWAY_DATABASE_FIX.R"
    "archive/diagnostic_files/startup_diagnostics.R"
    "archive/diagnostic_files/fixed_table_analysis.py"
    "archive/diagnostic_files/detailed_table_analysis.py"
    "archive/diagnostic_files/database_analysis.py"
    "archive/diagnostic_files/database_analysis_with_setup.R"
    "archive/diagnostic_files/database_analysis.R"
    "archive/diagnostic_files/railway_connection_diagnostics.R"
    "scripts/python/complete_database_rebuild.py"
    "scripts/python/complete_database_population.py"
    "scripts/python/monitor_population_progress.py"
    "scripts/python/test_database_connection.py"
    "scripts/python/database_rebuild_fixed_duplicates.py"
    "scripts/python/populate_database_categorized.py"
    "scripts/python/test_railway_connection.py"
    "scripts/python/bulk_import_optimized.py"
    "scripts/python/check_import_status.py"
    "scripts/python/fast_import.py"
    "scripts/python/import_data.py"
    "scripts/python/deep_search_camelcase.py"
    "scripts/python/find_camelcase_patterns.py"
    "scripts/python/restore_ponte_nova_titles.py"
    "scripts/python/analyze_municipality_names.py"
    "scripts/python/analyze_data_issues.py"
    "scripts/python/load_data_batch.py"
    "scripts/python/load_data_to_railway.py"
    "scripts/python/check_railway_tables.py"
    "scripts/python/update_database_simple.py"
    "scripts/python/simple_update.py"
    "scripts/python/test_connection.py"
    "scripts/python/reload_db_direct.py"
    "scripts/python/reload_db_simple.py"
    "scripts/python/verify_db.py"
    "scripts/python/execute_sql_batch.py"
    "scripts/python/execute_sql.py"
    "scripts/python/reload_csv_simple.py"
    "scripts/python/reload_csv_to_db.py"
    "scripts/python/import_lexml_to_db.py"
    "scripts/R/start_app.R"
    "scripts/R/database_dashboard_integration.R"
    "scripts/R/database_connection_fixed.R"
    "scripts/R/FORCE_REBUILD_DEBUG.R"
    "scripts/R/check_db_structure.R"
    "scripts/R/setup_database.R"
    "scripts/shell/run_deployment.sh"
    "scripts/shell/deploy_background.sh"
    "implementation/complete_migration.py"
    "RAILWAY_DEPLOYMENT_CHECKLIST.md"
)

# Counter for removed files
REMOVED_COUNT=0
BACKED_UP_COUNT=0

echo "Processing ${#FILES_TO_REMOVE[@]} files..."
echo ""

# Process each file
for FILE in "${FILES_TO_REMOVE[@]}"; do
    if [ -f "$FILE" ]; then
        # Create directory structure in backup
        DIR=$(dirname "$FILE")
        mkdir -p "$BACKUP_DIR/$DIR"
        
        # Backup the file
        cp "$FILE" "$BACKUP_DIR/$FILE"
        if [ $? -eq 0 ]; then
            echo "✓ Backed up: $FILE"
            BACKED_UP_COUNT=$((BACKED_UP_COUNT + 1))
            
            # Remove the file
            rm "$FILE"
            if [ $? -eq 0 ]; then
                echo "  → Removed: $FILE"
                REMOVED_COUNT=$((REMOVED_COUNT + 1))
            else
                echo "  ✗ Failed to remove: $FILE"
            fi
        else
            echo "✗ Failed to backup: $FILE (skipping removal)"
        fi
    else
        echo "- File not found: $FILE (already removed?)"
    fi
done

echo ""
echo "========================================="
echo "CLEANUP SUMMARY"
echo "========================================="
echo "Files backed up: $BACKED_UP_COUNT"
echo "Files removed: $REMOVED_COUNT"
echo "Backup location: $BACKUP_DIR"
echo ""
echo "IMPORTANT NEXT STEPS:"
echo "1. Rotate the database password in Railway dashboard"
echo "2. Update DATABASE_URL environment variable with new password"
echo "3. Test the application with secure connection module"
echo "4. Delete the backup directory after confirming everything works"
echo ""
echo "To restore files if needed:"
echo "cp -r $BACKUP_DIR/* ."
echo "========================================="