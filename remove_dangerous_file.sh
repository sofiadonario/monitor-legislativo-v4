#!/bin/bash

# ============================================================================
# REMOVE DANGEROUS DATABASE FILE SCRIPT
# ============================================================================
# 
# This script safely removes the dangerous RAILWAY_PRODUCTION_DB_FIX.R file
# that contains hardcoded database credentials.
# 
# Usage: ./remove_dangerous_file.sh
# ============================================================================

echo "🚨 REMOVING DANGEROUS DATABASE FILE"
echo "===================================="
echo ""

DANGEROUS_FILE="RAILWAY_PRODUCTION_DB_FIX.R"

# Check if file exists
if [ -f "$DANGEROUS_FILE" ]; then
    echo "⚠️  Found dangerous file: $DANGEROUS_FILE"
    echo "📄 This file contains hardcoded database credentials and is a security risk"
    echo ""
    
    # Create backup in secure location (optional)
    echo "🔧 Creating secure backup for audit purposes..."
    mkdir -p "archive/security_audit"
    cp "$DANGEROUS_FILE" "archive/security_audit/REMOVED_$(date +%Y%m%d_%H%M%S)_$DANGEROUS_FILE"
    echo "✅ Backup created in archive/security_audit/"
    echo ""
    
    # Remove the dangerous file
    echo "🗑️  Removing dangerous file..."
    rm "$DANGEROUS_FILE"
    
    if [ ! -f "$DANGEROUS_FILE" ]; then
        echo "✅ SUCCESS: Dangerous file removed successfully"
    else
        echo "❌ ERROR: Failed to remove dangerous file"
        exit 1
    fi
else
    echo "✅ GOOD: Dangerous file not found - already removed or never existed"
fi

echo ""

# Verify secure connection file exists
if [ -f "db/connection.R" ]; then
    echo "✅ VERIFIED: Secure connection file exists at db/connection.R"
else
    echo "❌ WARNING: Secure connection file not found at db/connection.R"
    echo "🔧 Please ensure the secure database connection is properly implemented"
fi

echo ""

# Check for any other potential credential files
echo "🔍 Scanning for other potential credential files..."
POTENTIAL_CREDENTIAL_FILES=(
    "database_credentials.R"
    "db_config.R" 
    "production_db.R"
    "railway_db.R"
    ".env"
    "credentials.txt"
)

FOUND_FILES=()
for file in "${POTENTIAL_CREDENTIAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        FOUND_FILES+=("$file")
    fi
done

if [ ${#FOUND_FILES[@]} -gt 0 ]; then
    echo "⚠️  Found other potential credential files:"
    for file in "${FOUND_FILES[@]}"; do
        echo "   - $file"
    done
    echo "🔧 Please review these files for hardcoded credentials"
else
    echo "✅ No other obvious credential files found"
fi

echo ""

# Final security reminder
echo "🔒 SECURITY REMINDERS"
echo "===================="
echo "1. ✅ Dangerous hardcoded credential file removed"
echo "2. 🔧 Ensure environment variables are configured in Railway"
echo "3. 🛡️  Use the new secure connection: source('db/connection.R')"
echo "4. 📋 Follow the migration guide: SECURE_DATABASE_MIGRATION_GUIDE.md"
echo "5. 🧪 Test with: Rscript test_secure_connection.R"
echo ""
echo "🎯 Next steps: Configure environment variables and test the secure connection"