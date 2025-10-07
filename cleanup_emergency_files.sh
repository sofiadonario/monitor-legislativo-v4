#!/bin/bash
# Cleanup script to remove emergency patches and fix files
# =========================================================
# This script removes all emergency and fix files as part of refactoring

echo "Monitor Legislativo v4 - Emergency Files Cleanup"
echo "================================================="
echo ""

# Define files to remove
EMERGENCY_FILES=(
  "emergency_data.R"
  "CRITICAL_CHART_FIXES.R"
  "CRITICAL_ZERO_RESULTS_FIX.R"
  "analytics_data_fixed_csv.R"
  "fix_analytics_data_function.R"
  "fix_analytics_data_reactive.R"
  "fix_chart_rendering_pipeline.R"
  "fix_choropleth.R"
  "fix_choropleth_simple.R"
  "fix_dashboard_metrics_function.R"
  "fix_document_display.R"
  "fix_railway_database_connection.R"
  "geospatial_packages_fix.R"
  "get_library_documents_FIXED.R"
  "load_chart_fixes.R"
  "railway_deployment_fix.R"
  "railway_log_collector_fix.R"
  "simple_choropleth_fix.R"
  "test_choropleth_fix.R"
  "test_csv_fix.R"
  "test_deployment_fixes.R"
  "test_fixed_loading.R"
  "test_railway_database_fixes.R"
  "test_ui_fixes.R"
  "verify_all_fixes.R"
  "verify_fix_deployment.R"
)

# Remove diagnostic and startup files
DIAGNOSTIC_FILES=(
  "RAILWAY_DIAGNOSTIC_TEST.R"
  "railway_start_production.R"
  "railway_basic_startup.R"
  "railway_full_app.R"
  "railway_chart_diagnostics.R"
  "railway_emergency_startup.R"
  "railway_unified_startup.R"
  "railway_deployment_test.R"
)

# Remove fixes directory contents
FIX_DIRS=(
  "fixes/legacy"
  "fixes/active"
  "fixes/tests"
)

echo "Removing emergency files..."
for file in "${EMERGENCY_FILES[@]}"; do
  if [ -f "$file" ]; then
    echo "  Removing: $file"
    rm -f "$file"
  fi
done

echo ""
echo "Removing diagnostic files..."
for file in "${DIAGNOSTIC_FILES[@]}"; do
  if [ -f "$file" ]; then
    echo "  Removing: $file"
    rm -f "$file"
  fi
done

echo ""
echo "Removing fix directories..."
for dir in "${FIX_DIRS[@]}"; do
  if [ -d "$dir" ]; then
    echo "  Removing directory: $dir"
    rm -rf "$dir"
  fi
done

echo ""
echo "Cleanup complete!"
echo ""
echo "Next steps:"
echo "1. Review global_clean.R and app_clean.R"
echo "2. Test the application locally"
echo "3. Replace global.R with global_clean.R"
echo "4. Replace app.R with app_clean.R"
echo "5. Commit and deploy the cleaned version"