#!/usr/bin/env python3
"""
Script to analyze the discrepancy between original results and processed data
"""

import pandas as pd
import os

def analyze_discrepancy():
    print("="*60)
    print("ANALYZING DATA DISCREPANCY")
    print("="*60)
    
    # Check the consolidated file
    print("\n1. CONSOLIDATED FILE ANALYSIS")
    print("-" * 40)
    
    if os.path.exists("lexml_latest_results.csv"):
        df_consolidated = pd.read_csv("lexml_latest_results.csv")
        print(f"Consolidated file: {len(df_consolidated)} documents")
        print(f"Columns: {list(df_consolidated.columns)}")
        
        # Check for duplicates
        duplicates = df_consolidated.duplicated(subset=['urn']).sum()
        print(f"Duplicate URNs: {duplicates}")
        
        # Check unique search terms
        unique_terms = df_consolidated['search_term'].nunique()
        print(f"Unique search terms: {unique_terms}")
        
        # Show search term distribution
        print("\nTop search terms in consolidated file:")
        print(df_consolidated['search_term'].value_counts().head(10))
    
    # Check partial files
    print("\n2. PARTIAL FILES ANALYSIS")
    print("-" * 40)
    
    partial_files = [f for f in os.listdir("partial_files/") if f.endswith('.csv')]
    print(f"Number of partial files: {len(partial_files)}")
    
    total_partial_docs = 0
    partial_terms = set()
    
    for file in partial_files[:5]:  # Check first 5 files
        try:
            df_partial = pd.read_csv(f"partial_files/{file}")
            docs_in_file = len(df_partial)
            total_partial_docs += docs_in_file
            partial_terms.update(df_partial['search_term'].unique())
            print(f"  {file}: {docs_in_file} documents")
        except Exception as e:
            print(f"  {file}: Error reading - {e}")
    
    print(f"Total documents in first 5 partial files: {total_partial_docs}")
    print(f"Unique search terms in partial files: {len(partial_terms)}")
    
    # Check if there are other CSV files
    print("\n3. OTHER CSV FILES")
    print("-" * 40)
    
    all_csv_files = [f for f in os.listdir(".") if f.endswith('.csv')]
    print(f"CSV files in current directory: {all_csv_files}")
    
    # Check if there are other consolidated files
    print("\n4. SEARCHING FOR OTHER CONSOLIDATED FILES")
    print("-" * 40)
    
    # Look for files that might contain the full dataset
    potential_files = []
    for file in os.listdir("."):
        if 'consolidated' in file.lower() or 'lexml' in file.lower():
            if file.endswith('.csv'):
                potential_files.append(file)
    
    print(f"Potential consolidated files found: {potential_files}")
    
    for file in potential_files:
        if file != "lexml_latest_results.csv":
            try:
                df = pd.read_csv(file)
                print(f"  {file}: {len(df)} documents")
            except Exception as e:
                print(f"  {file}: Error reading - {e}")
    
    # Check the parent directory
    print("\n5. CHECKING PARENT DIRECTORY")
    print("-" * 40)
    
    parent_csv_files = [f for f in os.listdir("..") if f.endswith('.csv')]
    lexml_parent_files = [f for f in parent_csv_files if 'lexml' in f.lower()]
    print(f"LexML CSV files in parent directory: {lexml_parent_files}")
    
    for file in lexml_parent_files:
        try:
            df = pd.read_csv(f"../{file}")
            print(f"  {file}: {len(df)} documents")
        except Exception as e:
            print(f"  {file}: Error reading - {e}")

if __name__ == "__main__":
    analyze_discrepancy() 