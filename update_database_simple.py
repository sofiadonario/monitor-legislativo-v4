#!/usr/bin/env python3
"""
Simple database update script - just load the CSV data as-is into the database
"""

import csv
import json
from datetime import datetime

# Database URL
DB_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

print("🚀 Simple Database Update Script")
print("=" * 60)

# Step 1: Read all CSV files and prepare SQL
print("\n📋 Reading CSV files...")

all_inserts = []
csv_files = [
    "data_current/processed/Geral.csv",
    "data_current/processed/Legislação___Geral.csv",
    "data_current/processed/Legislação___Rodoviário.csv",
    "data_current/processed/Jurisprudência___Geral.csv",
    "data_current/processed/Outros___Geral.csv"
]

total_records = 0

for csv_file in csv_files:
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Skip empty rows
                if not row.get('Urn', '').strip():
                    continue
                
                # Prepare values
                urn = row.get('Urn', '').replace("'", "''")
                title = row.get('Title', '').replace("'", "''")
                url = row.get('Url', '').replace("'", "''")
                state = row.get('State', '').replace("'", "''")
                municipality = row.get('Municipality', '').replace("'", "''")
                
                # Map document type
                urn_type = row.get('Urn_type', '')
                tipo_map = {
                    'legislation': 'lei',
                    'jurisprudence': 'jurisprudencia',
                    'doutrina': 'doutrina',
                    'library': 'doutrina'
                }
                tipo = tipo_map.get(urn_type, 'outro')
                
                # Parse date
                date_str = row.get('Enacting_date', '')
                if date_str and ' ' in date_str:
                    date_str = date_str.split(' ')[0]
                if not date_str or date_str == 'NULL':
                    date_val = 'NULL'
                else:
                    date_val = f"'{date_str}'"
                
                # Create INSERT statement
                insert = f"""
INSERT INTO documents (
    urn, titulo, url, data_publicacao, estado, municipality,
    tipo, fonte, created_at, updated_at
) VALUES (
    '{urn}',
    '{title}',
    '{url}',
    {date_val},
    '{state}',
    '{municipality}',
    '{tipo}',
    'LexML',
    NOW(),
    NOW()
) ON CONFLICT (urn) DO UPDATE SET
    titulo = EXCLUDED.titulo,
    estado = EXCLUDED.estado,
    municipality = EXCLUDED.municipality,
    updated_at = NOW();"""
                
                all_inserts.append(insert)
                total_records += 1
                
        print(f"✅ Processed {csv_file}: {len([i for i in all_inserts if csv_file in str(i)])} records")
        
    except Exception as e:
        print(f"❌ Error processing {csv_file}: {e}")

print(f"\n📊 Total records to update: {total_records}")

# Step 2: Generate SQL file
print("\n📋 Generating SQL file...")

with open('update_municipality_state.sql', 'w', encoding='utf-8') as f:
    f.write("-- Simple Municipality-State Update\n")
    f.write("-- Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
    f.write("-- Clear existing LexML data\n")
    f.write("DELETE FROM documents WHERE fonte = 'LexML';\n\n")
    f.write("-- Insert updated data\n")
    
    for insert in all_inserts:
        f.write(insert + "\n")
    
    f.write("\n-- Verification queries\n")
    f.write("SELECT COUNT(*) as total FROM documents WHERE fonte = 'LexML';\n")
    f.write("SELECT estado, municipality, COUNT(*) as count FROM documents WHERE fonte = 'LexML' AND estado != '' GROUP BY estado, municipality ORDER BY count DESC LIMIT 10;\n")

print("✅ Created update_municipality_state.sql")

# Step 3: Create a verification script
verification = """#!/bin/bash
# Verify municipality-state fix

echo "🔍 Checking database state..."

# Total records
echo -e "\n📊 Total LexML records:"
psql "$1" -c "SELECT COUNT(*) FROM documents WHERE fonte = 'LexML';"

# Records with proper separation
echo -e "\n📊 Records with municipality-state separation:"
psql "$1" -c "SELECT COUNT(*) FROM documents WHERE fonte = 'LexML' AND estado != '' AND municipality != '';"

# Catanduva examples
echo -e "\n🔍 Catanduva examples (should show SP/Catanduva):"
psql "$1" -c "SELECT estado, municipality, titulo FROM documents WHERE fonte = 'LexML' AND municipality ILIKE '%catanduva%' LIMIT 3;"

# Problematic records
echo -e "\n📊 Remaining problematic records:"
psql "$1" -c "SELECT COUNT(*) FROM documents WHERE fonte = 'LexML' AND estado LIKE '%-%';"
"""

with open('verify_fix.sh', 'w') as f:
    f.write(verification)

import os
os.chmod('verify_fix.sh', 0o755)

print("✅ Created verify_fix.sh")

print("\n🎯 NEXT STEPS:")
print("1. Run the update:")
print(f'   psql "{DB_URL}" -f update_municipality_state.sql')
print("\n2. Verify the fix:")
print(f'   ./verify_fix.sh "{DB_URL}"')
print("\n✅ Files created:")
print("   - update_municipality_state.sql (main update file)")
print("   - verify_fix.sh (verification script)")