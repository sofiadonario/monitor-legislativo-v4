#!/usr/bin/env python3
"""
Final validation and date conversion check
"""

import csv
import pandas as pd
import re
from datetime import datetime, timedelta

def check_corrected_file():
    input_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao_CORRECTED.csv"
    
    print("="*60)
    print("FINAL VALIDATION AND ANALYSIS")
    print("="*60)
    
    # Check header and find date columns
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        
        print(f"Total columns: {len(header)}")
        print("All columns:")
        for i, col in enumerate(header):
            print(f"  {i:2d}: {col}")
        
        # Look for date-related columns
        date_columns = []
        for i, col in enumerate(header):
            if 'data' in col.lower() or 'date' in col.lower():
                date_columns.append((i, col))
        
        print(f"\nDate-related columns found: {len(date_columns)}")
        for idx, col in date_columns:
            print(f"  Column {idx}: {col}")
    
    # Sample first few rows to check data
    print("\n" + "="*60)
    print("SAMPLE DATA (first 5 rows)")
    print("="*60)
    
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        
        for i, row in enumerate(reader):
            if i >= 5:
                break
            print(f"\nRow {i+1}:")
            for j, (col_name, value) in enumerate(zip(header, row)):
                if 'data' in col_name.lower() or j < 5:  # Show first 5 columns and all date columns
                    print(f"  {col_name}: {value[:100]}..." if len(value) > 100 else f"  {col_name}: {value}")
    
    # Check for Excel serial dates in data column
    print("\n" + "="*60)
    print("DATE COLUMN ANALYSIS")
    print("="*60)
    
    data_col_idx = None
    for i, col in enumerate(header):
        if col.lower() == 'data':
            data_col_idx = i
            break
    
    if data_col_idx is not None:
        print(f"Found 'data' column at index {data_col_idx}")
        
        # Sample date values
        date_samples = []
        with open(input_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            
            for i, row in enumerate(reader):
                if i >= 1000:  # Sample first 1000 rows
                    break
                if len(row) > data_col_idx and row[data_col_idx]:
                    date_samples.append(row[data_col_idx])
        
        print(f"Sampled {len(date_samples)} date values")
        
        # Analyze date formats
        excel_dates = 0
        standard_dates = 0
        other_formats = 0
        
        for date_val in date_samples[:100]:  # Check first 100
            if re.match(r'^\d+(\.\d+)?$', date_val.strip()):
                try:
                    float_val = float(date_val)
                    if 1 <= float_val <= 100000:
                        excel_dates += 1
                    else:
                        other_formats += 1
                except:
                    other_formats += 1
            elif re.match(r'\d{4}-\d{2}-\d{2}', date_val):
                standard_dates += 1
            else:
                other_formats += 1
        
        print(f"Date format analysis (sample of 100):")
        print(f"  Excel serial dates: {excel_dates}")
        print(f"  Standard YYYY-MM-DD: {standard_dates}")
        print(f"  Other formats: {other_formats}")
        
        print(f"\nSample date values:")
        for i, val in enumerate(date_samples[:10]):
            print(f"  {i+1}: {val}")
    
    # Count total rows
    print("\n" + "="*60)
    print("ROW COUNT VERIFICATION")
    print("="*60)
    
    total_rows = 0
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            total_rows += 1
    
    print(f"Total lines in corrected file: {total_rows:,}")
    print(f"Data rows (excluding header): {total_rows-1:,}")
    print(f"Expected rows: 786,013")
    print(f"Difference: {786013 - (total_rows-1):,}")
    
    if total_rows-1 < 786013:
        print("WARNING: Some rows may have been lost during processing")
    else:
        print("SUCCESS: All expected rows are present")

if __name__ == "__main__":
    check_corrected_file()