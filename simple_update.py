#!/usr/bin/env python3
"""
Simple script to update municipality-state in database from fixed CSV files
"""

import os
import sys

print("Checking what needs to be done...")

# First, let's see what CSV files we have
csv_dir = "data_current/processed"
csv_files = [f for f in os.listdir(csv_dir) if f.endswith('.csv')]

print(f"\nFound {len(csv_files)} CSV files in {csv_dir}")

# Check a sample to see if municipality-state is already fixed
import csv

sample_file = os.path.join(csv_dir, "Geral.csv")
with open(sample_file, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    print("\nSample records from Geral.csv:")
    count = 0
    has_separated_data = False
    
    for i, row in enumerate(reader):
        if i < 5:
            state = row.get('State', '')
            municipality = row.get('Municipality', '')
            print(f"Row {i+1}: State='{state}', Municipality='{municipality}'")
            
            if state and municipality:
                has_separated_data = True
        count += 1
    
    print(f"\nTotal records in Geral.csv: {count}")
    
if has_separated_data:
    print("\n✅ CSV files already have municipality-state properly separated!")
    print("\nNext step: Update the database with this corrected data")
else:
    print("\n❌ CSV files need municipality-state parsing fix")

# Create a simple update script
update_script = """
-- Simple SQL to check current database state
SELECT COUNT(*) as total_records FROM documents WHERE fonte = 'LexML';

-- Check for records with municipality-state issues
SELECT COUNT(*) as problematic_records 
FROM documents 
WHERE fonte = 'LexML' 
AND estado LIKE '%-%' 
AND estado NOT LIKE '%--%';

-- Sample problematic records
SELECT estado, municipality, titulo 
FROM documents 
WHERE fonte = 'LexML' 
AND estado LIKE '%-%'
LIMIT 5;
"""

with open('check_database.sql', 'w') as f:
    f.write(update_script)

print("\n📋 Created check_database.sql")
print("Run this to check database state:")
print('psql "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway" -f check_database.sql')