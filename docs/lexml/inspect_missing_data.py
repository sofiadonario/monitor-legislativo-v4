#!/usr/bin/env python3
"""
Script to inspect missing data patterns in lexml_consolidated_3.csv
"""

import pandas as pd
import numpy as np

def inspect_missing_data():
    print("="*60)
    print("INSPECTING MISSING DATA PATTERNS")
    print("="*60)
    
    # Load the data
    df = pd.read_csv("lexml_consolidated_3.csv")
    print(f"Total rows: {len(df)}")
    print(f"Total columns: {len(df.columns)}")
    
    # Check missing values for each column
    print("\nMissing values per column:")
    print("-" * 40)
    for col in df.columns:
        missing_count = df[col].isna().sum()
        missing_pct = (missing_count / len(df)) * 100
        print(f"{col:20} | {missing_count:5} | {missing_pct:5.1f}%")
    
    # Check specific critical columns
    print("\nCritical columns analysis:")
    print("-" * 40)
    critical_cols = ['title', 'urn', 'url', 'document_description']
    
    for col in critical_cols:
        if col in df.columns:
            missing_count = df[col].isna().sum()
            empty_count = (df[col] == '').sum()
            total_issues = missing_count + empty_count
            print(f"{col:20} | Missing: {missing_count:4} | Empty: {empty_count:4} | Total issues: {total_issues:4}")
    
    # Check rows that would be dropped by our cleaning
    print("\nRows that would be dropped by current cleaning:")
    print("-" * 40)
    
    # Current cleaning: dropna(subset=['title', 'urn'])
    missing_title = df['title'].isna().sum()
    missing_urn = df['urn'].isna().sum()
    
    # Check for empty strings too
    empty_title = (df['title'] == '').sum()
    empty_urn = (df['urn'] == '').sum()
    
    print(f"Missing title: {missing_title}")
    print(f"Empty title: {empty_title}")
    print(f"Missing URN: {missing_urn}")
    print(f"Empty URN: {empty_urn}")
    
    # Show some examples of problematic rows
    print("\nSample rows with missing title or URN:")
    print("-" * 40)
    
    problematic_rows = df[(df['title'].isna()) | (df['urn'].isna()) | (df['title'] == '') | (df['urn'] == '')]
    
    if len(problematic_rows) > 0:
        print(f"Found {len(problematic_rows)} problematic rows")
        print("\nFirst 5 problematic rows:")
        for idx, row in problematic_rows.head().iterrows():
            print(f"\nRow {idx}:")
            print(f"  Search term: {row.get('search_term', 'N/A')}")
            print(f"  Title: '{row.get('title', 'N/A')}'")
            print(f"  URN: '{row.get('urn', 'N/A')}'")
            print(f"  URL: '{row.get('url', 'N/A')}'")
    else:
        print("No problematic rows found!")
    
    # Check what the script actually processed
    print("\n" + "="*60)
    print("COMPARISON WITH PROCESSING SCRIPT")
    print("="*60)
    
    # Simulate the cleaning process
    df_cleaned = df.dropna(subset=['title', 'urn'])
    df_cleaned = df_cleaned[df_cleaned['title'] != '']
    df_cleaned = df_cleaned[df_cleaned['urn'] != '']
    
    print(f"Original rows: {len(df)}")
    print(f"After cleaning: {len(df_cleaned)}")
    print(f"Rows dropped: {len(df) - len(df_cleaned)}")
    print(f"Drop percentage: {((len(df) - len(df_cleaned)) / len(df)) * 100:.1f}%")
    
    # Check if there are other issues
    print("\nAdditional cleaning issues:")
    print("-" * 40)
    
    # Check for 'nan' strings
    nan_title = (df['title'] == 'nan').sum()
    nan_urn = (df['urn'] == 'nan').sum()
    
    print(f"Title = 'nan': {nan_title}")
    print(f"URN = 'nan': {nan_urn}")
    
    # Show distribution of document types
    print("\nDocument type distribution:")
    print("-" * 40)
    if 'urn_type' in df.columns:
        print(df['urn_type'].value_counts())
    
    # Show search term distribution
    print("\nTop search terms:")
    print("-" * 40)
    print(df['search_term'].value_counts().head(10))

if __name__ == "__main__":
    inspect_missing_data() 