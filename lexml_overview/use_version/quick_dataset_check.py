#!/usr/bin/env python3
"""
Quick check of the LexML dataset structure
"""

import pandas as pd
import os
import sys

def quick_check():
    filepath = "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/lexml_overview/use_version/dataset_14072025.xlsx"
    
    print(f"Checking file: {filepath}")
    print(f"File exists: {os.path.exists(filepath)}")
    
    if not os.path.exists(filepath):
        print("File not found!")
        return
    
    try:
        # Just check sheet names first
        excel_file = pd.ExcelFile(filepath)
        print(f"\nSheets found: {len(excel_file.sheet_names)}")
        for i, sheet in enumerate(excel_file.sheet_names, 1):
            print(f"{i}. {sheet}")
        
        # Load first sheet to check structure
        print(f"\nLoading first sheet: {excel_file.sheet_names[0]}")
        df_first = pd.read_excel(filepath, sheet_name=excel_file.sheet_names[0], nrows=5)
        print(f"Columns: {list(df_first.columns)}")
        print(f"Shape: {df_first.shape}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    quick_check()