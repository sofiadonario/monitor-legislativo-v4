#!/usr/bin/env python3
"""
Script to fix municipality-state parsing in CSV files.
Separates combined municipality-state values like "Catanduva - SP" into separate columns.
"""

import csv
import re
import os
from pathlib import Path

def parse_municipality_state(value):
    """
    Parse municipality-state format into separate municipality and state.
    
    Args:
        value (str): Input string like "Catanduva - SP"
        
    Returns:
        tuple: (municipality, state) or (original_value, "") if no match
    """
    if not value or value.strip() == "":
        return "", ""
    
    # Pattern to match "Municipality - ST" format
    pattern = r'^(.+)\s*-\s*([A-Z]{2})$'
    match = re.match(pattern, value.strip())
    
    if match:
        municipality = match.group(1).strip()
        state = match.group(2).strip()
        return municipality, state
    else:
        # If no match, return original value as municipality and empty state
        return value.strip(), ""

def fix_csv_file(file_path):
    """
    Fix municipality-state parsing in a single CSV file.
    
    Args:
        file_path (str): Path to the CSV file
    """
    print(f"Processing {file_path}")
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        rows = list(reader)
    
    # Check if State column exists
    if 'State' not in reader.fieldnames:
        print(f"  Warning: No 'State' column found in {file_path}")
        return
    
    # Process each row
    fixed_count = 0
    for row in rows:
        state_value = row.get('State', '')
        
        # Check if this looks like a combined municipality-state value
        if state_value and ' - ' in state_value:
            municipality, state = parse_municipality_state(state_value)
            
            # Update the row
            row['Municipality'] = municipality
            row['State'] = state
            fixed_count += 1
    
    if fixed_count > 0:
        # Write the fixed data back
        with open(file_path, 'w', encoding='utf-8', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=reader.fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"  Fixed {fixed_count} rows in {file_path}")
    else:
        print(f"  No fixes needed in {file_path}")

def main():
    """Main function to process all CSV files."""
    # Files that need fixing based on our analysis
    files_to_fix = [
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Doutrina___Geral.csv",
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Doutrina___Marítimo.csv",
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Doutrina___Rodoviário.csv",
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Geral.csv",
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Jurisprudência___Geral.csv",
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Legislação___Geral.csv",
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Legislação___Rodoviário.csv",
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Outros___Aéreo.csv",
        "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/Outros___Geral.csv"
    ]
    
    print("Starting municipality-state parsing fix...")
    
    for file_path in files_to_fix:
        if os.path.exists(file_path):
            fix_csv_file(file_path)
        else:
            print(f"Warning: File not found: {file_path}")
    
    print("Fix completed!")

if __name__ == "__main__":
    main()