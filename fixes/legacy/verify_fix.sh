#!/bin/bash
# Verify municipality-state fix

echo "🔍 Checking database state..."

# Total records
echo -e "
📊 Total LexML records:"
psql "$1" -c "SELECT COUNT(*) FROM documents WHERE fonte = 'LexML';"

# Records with proper separation
echo -e "
📊 Records with municipality-state separation:"
psql "$1" -c "SELECT COUNT(*) FROM documents WHERE fonte = 'LexML' AND estado != '' AND municipality != '';"

# Catanduva examples
echo -e "
🔍 Catanduva examples (should show SP/Catanduva):"
psql "$1" -c "SELECT estado, municipality, titulo FROM documents WHERE fonte = 'LexML' AND municipality ILIKE '%catanduva%' LIMIT 3;"

# Problematic records
echo -e "
📊 Remaining problematic records:"
psql "$1" -c "SELECT COUNT(*) FROM documents WHERE fonte = 'LexML' AND estado LIKE '%-%';"
