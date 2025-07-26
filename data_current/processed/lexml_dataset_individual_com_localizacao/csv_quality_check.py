#!/usr/bin/env python3
import os
import csv
import pandas as pd
from collections import defaultdict
import json

def analyze_csv(filepath):
    issues = defaultdict(list)
    filename = os.path.basename(filepath)
    stats = {}
    
    try:
        # Try to read with pandas first
        df = pd.read_csv(filepath, nrows=5000, on_bad_lines='skip')
        
        # Basic statistics
        stats['total_rows'] = len(pd.read_csv(filepath, usecols=[0]))
        stats['columns'] = len(df.columns)
        stats['column_names'] = list(df.columns)
        
        print(f'\n=== {filename} ===')
        print(f'Total rows: {stats["total_rows"]}')
        print(f'Columns: {stats["columns"]}')
        print(f'Column names: {", ".join(stats["column_names"][:5])}...')
        
        # Check for missing values
        missing = df.isnull().sum()
        missing_pct = (missing / len(df) * 100).round(2)
        high_missing = missing_pct[missing_pct > 50]
        if not high_missing.empty:
            issues['high_missing_values'] = high_missing.to_dict()
            
        # Check for completely empty columns
        empty_cols = df.columns[df.isnull().all()].tolist()
        if empty_cols:
            issues['empty_columns'] = empty_cols
            
        # Check for duplicate rows
        duplicates = df.duplicated().sum()
        if duplicates > 0:
            issues['duplicate_rows'] = f'{duplicates} duplicates in sample'
            
        # Check data types and content issues
        for col in df.columns:
            if df[col].dtype == 'object':
                # Check for leading/trailing whitespace
                if df[col].notna().any():
                    sample = df[col].dropna().astype(str)
                    whitespace = (sample != sample.str.strip()).sum()
                    if whitespace > 0:
                        issues['whitespace'].append(f'{col}: {whitespace} rows')
                        
                # Check for newlines in data
                newlines = sample.str.contains('\n|\r', regex=True).sum()
                if newlines > 0:
                    issues['embedded_newlines'].append(f'{col}: {newlines} rows')
                    
        # Check delimiter consistency by reading raw
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [f.readline() for _ in range(100)]
            comma_counts = [line.count(',') for line in lines if line.strip()]
            if len(set(comma_counts)) > 2:  # Allow some variation
                issues['delimiter_inconsistency'] = f'Variable comma counts: min={min(comma_counts)}, max={max(comma_counts)}'
                
        # Check for quote issues
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            sample_text = f.read(10000)
            unmatched_quotes = sample_text.count('"') % 2
            if unmatched_quotes != 0:
                issues['quote_issues'] = 'Potentially unmatched quotes detected'
                
    except pd.errors.ParserError as e:
        issues['parser_error'] = str(e)[:100]
    except Exception as e:
        issues['read_error'] = str(e)[:100]
    
    return stats, issues

# Analyze all CSV files
all_issues = {}
all_stats = {}

for file in sorted(os.listdir('.')):
    if file.endswith('.csv'):
        stats, issues = analyze_csv(file)
        all_stats[file] = stats
        if issues:
            all_issues[file] = dict(issues)
            print(f'\nISSUES FOUND:')
            for issue_type, details in issues.items():
                if isinstance(details, list):
                    print(f'  - {issue_type}:')
                    for item in details[:3]:  # Show first 3
                        print(f'    * {item}')
                    if len(details) > 3:
                        print(f'    * ... and {len(details)-3} more')
                else:
                    print(f'  - {issue_type}: {details}')

# Summary
print(f'\n\n=== SUMMARY ===')
print(f'Total files analyzed: {len(all_stats)}')
print(f'Files with issues: {len(all_issues)}')

if all_issues:
    print('\nIssues by type:')
    issue_counts = defaultdict(int)
    for file_issues in all_issues.values():
        for issue_type in file_issues:
            issue_counts[issue_type] += 1
    
    for issue_type, count in sorted(issue_counts.items(), key=lambda x: x[1], reverse=True):
        print(f'  - {issue_type}: {count} files')

# Save detailed report
with open('csv_quality_report.json', 'w', encoding='utf-8') as f:
    json.dump({'stats': all_stats, 'issues': all_issues}, f, indent=2, ensure_ascii=False)
print('\nDetailed report saved to csv_quality_report.json')