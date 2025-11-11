#!/usr/bin/env python3
"""
Convert Excel sheets to CSV files for analysis
"""

import pandas as pd
import os
import sys

def convert_excel_to_csv():
    """Convert Excel sheets to individual CSV files"""
    
    excel_path = "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/lexml_overview/use_version/dataset_14072025.xlsx"
    
    print(f"Converting Excel file: {excel_path}")
    
    try:
        # Read Excel file
        excel_file = pd.ExcelFile(excel_path)
        print(f"Found {len(excel_file.sheet_names)} sheets")
        
        # Convert each sheet to CSV
        for sheet_name in excel_file.sheet_names:
            print(f"Converting sheet: {sheet_name}")
            
            # Read sheet
            df = pd.read_excel(excel_path, sheet_name=sheet_name)
            
            # Clean sheet name for filename
            clean_name = sheet_name.replace(' ', '_').replace('-', '_').replace('/', '_')
            csv_filename = f"{clean_name}.csv"
            
            # Save as CSV
            df.to_csv(csv_filename, index=False, encoding='utf-8-sig')
            print(f"  ✓ Saved {csv_filename} ({len(df)} rows)")
        
        print(f"\n✅ All sheets converted successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Error converting Excel: {str(e)}")
        return False

if __name__ == "__main__":
    convert_excel_to_csv()