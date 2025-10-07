#!/bin/bash
# Migration script to transition to clean architecture
# ====================================================

echo "Monitor Legislativo v4 - Clean Architecture Migration"
echo "====================================================="
echo ""

# Create backup directory with timestamp
BACKUP_DIR="backup_$(date +%Y%m%d_%H%M%S)"
echo "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Backup current files
echo "Backing up current files..."
cp global.R "$BACKUP_DIR/" 2>/dev/null
cp app.R "$BACKUP_DIR/" 2>/dev/null

# Copy emergency files to backup (for reference)
echo "Backing up emergency files..."
mkdir -p "$BACKUP_DIR/emergency_files"
cp emergency_data.R "$BACKUP_DIR/emergency_files/" 2>/dev/null
cp *fix*.R "$BACKUP_DIR/emergency_files/" 2>/dev/null
cp *CRITICAL*.R "$BACKUP_DIR/emergency_files/" 2>/dev/null
cp -r fixes "$BACKUP_DIR/" 2>/dev/null

echo ""
echo "Migrating to clean architecture..."

# Replace main files
if [ -f "global_clean.R" ]; then
  echo "  Replacing global.R with clean version..."
  cp global_clean.R global.R
fi

if [ -f "app_clean.R" ]; then
  echo "  Replacing app.R with clean version..."
  cp app_clean.R app.R
fi

echo ""
echo "Migration complete!"
echo ""
echo "Backup created at: $BACKUP_DIR"
echo ""
echo "To test the clean version:"
echo "  1. Run: Rscript -e 'shiny::runApp()'"
echo "  2. Check application functionality"
echo "  3. Monitor logs for any errors"
echo ""
echo "To rollback if needed:"
echo "  cp $BACKUP_DIR/global.R ."
echo "  cp $BACKUP_DIR/app.R ."
echo ""
echo "Once verified, run cleanup:"
echo "  ./cleanup_emergency_files.sh"