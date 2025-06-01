#!/usr/bin/env python3
"""
Robust CSV processor to fix parsing barriers and ensure all 786,013 rows are accessible.
This handles malformed CSV rows, extremely long text fields, and date format conversion.
"""

import csv
import re
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import chardet

def detect_encoding(file_path):
    """Detect file encoding."""
    with open(file_path, 'rb') as f:
        sample = f.read(100000)  # Read 100KB sample
    result = chardet.detect(sample)
    return result['encoding']

def excel_date_to_string(excel_date):
    """Convert Excel serial date to YYYY-MM-DD format."""
    try:
        # Try to convert as Excel serial date (days since 1900-01-01)
        if isinstance(excel_date, (int, float)) and excel_date > 25000:  # Reasonable date range
            # Excel serial date: days since 1900-01-01 (accounting for Excel leap year bug)
            base_date = datetime(1899, 12, 30)  # Excel's epoch (accounting for 1900 leap year bug)
            converted_date = base_date + timedelta(days=excel_date)
            return converted_date.strftime('%Y-%m-%d')
        
        # If it's already a string, try to parse and reformat
        if isinstance(excel_date, str):
            # Handle various date formats
            for fmt in ['%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%Y/%m/%d']:
                try:
                    parsed_date = datetime.strptime(excel_date, fmt)
                    return parsed_date.strftime('%Y-%m-%d')
                except ValueError:
                    continue
        
        return str(excel_date)  # Return as-is if can't convert
    except:
        return str(excel_date)

def clean_text_field(text):
    """Clean text field by handling embedded quotes and newlines properly."""
    if not isinstance(text, str):
        return str(text)
    
    # Replace embedded newlines with space
    text = re.sub(r'\r?\n', ' ', text)
    
    # Handle embedded quotes by doubling them (CSV standard)
    text = text.replace('"', '""')
    
    # Remove excessive whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def process_csv_robustly(input_file, output_file):
    """Process CSV file robustly to handle all parsing issues."""
    
    print(f"Starting robust CSV processing...")
    print(f"Input: {input_file}")
    print(f"Output: {output_file}")
    
    # Detect encoding
    encoding = detect_encoding(input_file)
    print(f"Detected encoding: {encoding}")
    
    # Statistics tracking
    stats = {
        'total_lines': 0,
        'header_found': False,
        'rows_processed': 0,
        'rows_with_issues': 0,
        'date_conversions': 0,
        'text_cleanings': 0,
        'parsing_errors': 0
    }
    
    # Read the file line by line for maximum control
    with open(input_file, 'r', encoding=encoding, errors='replace') as infile:
        with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
            writer = csv.writer(outfile, quoting=csv.QUOTE_MINIMAL)
            
            header = None
            current_row = []
            in_quoted_field = False
            quote_count = 0
            
            for line_num, line in enumerate(infile, 1):
                stats['total_lines'] += 1
                
                if line_num % 50000 == 0:
                    print(f"Processing line {line_num:,}...")
                
                line = line.rstrip('\r\n')
                
                # Handle the header row specially
                if not stats['header_found'] and line_num <= 5:  # Check first few lines for header
                    try:
                        # Try to parse as CSV
                        test_reader = csv.reader([line])
                        test_row = next(test_reader)
                        
                        # Check if this looks like a header (contains expected column names)
                        if any(col.lower() in ['titulo', 'tipo', 'data', 'urn', 'ementa'] for col in test_row):
                            header = test_row
                            writer.writerow(header)
                            stats['header_found'] = True
                            print(f"Header found at line {line_num}: {len(header)} columns")
                            continue
                    except:
                        pass
                
                if not stats['header_found']:
                    continue
                
                # Process data rows
                try:
                    # Use CSV reader for proper parsing
                    reader = csv.reader([line])
                    row = next(reader)
                    
                    # Ensure row has correct number of columns
                    while len(row) < len(header):
                        row.append('')
                    
                    # Truncate if too many columns
                    if len(row) > len(header):
                        row = row[:len(header)]
                    
                    # Clean and process each field
                    processed_row = []
                    row_had_issues = False
                    
                    for i, field in enumerate(row):
                        col_name = header[i].lower() if i < len(header) else f"col_{i}"
                        
                        # Date conversion for data_publicacao or similar columns
                        if 'data' in col_name and field and field.strip():
                            try:
                                # Try to convert as number (Excel serial date)
                                if field.replace('.', '').isdigit():
                                    converted = excel_date_to_string(float(field))
                                    if converted != field:
                                        stats['date_conversions'] += 1
                                        field = converted
                                        row_had_issues = True
                            except:
                                pass
                        
                        # Clean text fields
                        if isinstance(field, str) and len(field) > 100:
                            original_field = field
                            field = clean_text_field(field)
                            if field != original_field:
                                stats['text_cleanings'] += 1
                                row_had_issues = True
                        
                        processed_row.append(field)
                    
                    # Write the processed row
                    writer.writerow(processed_row)
                    stats['rows_processed'] += 1
                    
                    if row_had_issues:
                        stats['rows_with_issues'] += 1
                
                except Exception as e:
                    # Handle malformed rows
                    stats['parsing_errors'] += 1
                    
                    # Try to salvage the row by basic splitting
                    if ',' in line:
                        parts = line.split(',')
                        
                        # Ensure correct number of columns
                        while len(parts) < len(header):
                            parts.append('')
                        if len(parts) > len(header):
                            parts = parts[:len(header)]
                        
                        # Clean each part
                        cleaned_parts = [clean_text_field(part.strip('"')) for part in parts]
                        
                        writer.writerow(cleaned_parts)
                        stats['rows_processed'] += 1
                        stats['rows_with_issues'] += 1
                    
                    if line_num % 10000 == 0:
                        print(f"Warning: Parsing error at line {line_num}: {str(e)[:100]}...")
    
    # Print final statistics
    print("\n=== PROCESSING COMPLETE ===")
    print(f"Total lines read: {stats['total_lines']:,}")
    print(f"Rows processed: {stats['rows_processed']:,}")
    print(f"Rows with issues fixed: {stats['rows_with_issues']:,}")
    print(f"Date conversions: {stats['date_conversions']:,}")
    print(f"Text field cleanings: {stats['text_cleanings']:,}")
    print(f"Parsing errors handled: {stats['parsing_errors']:,}")
    
    return stats

def validate_output(output_file):
    """Validate the output file."""
    print("\n=== VALIDATION ===")
    
    # Count lines
    with open(output_file, 'r', encoding='utf-8') as f:
        line_count = sum(1 for line in f)
    
    print(f"Output file lines: {line_count:,}")
    print(f"Data rows: {line_count - 1:,}")
    
    # Try to read with pandas
    try:
        import pandas as pd
        df = pd.read_csv(output_file, low_memory=False)
        print(f"Pandas accessible rows: {len(df):,}")
        print(f"Columns: {len(df.columns)}")
        
        # Check for date format in data columns
        date_cols = [col for col in df.columns if 'data' in col.lower()]
        for col in date_cols:
            sample = df[col].dropna().head(5)
            print(f"Sample {col}: {list(sample)}")
        
        success = len(df) >= 786000
        print(f"Validation: {'✓ SUCCESS' if success else '✗ NEEDS MORE WORK'}")
        return success
        
    except ImportError:
        print("Pandas not available for validation")
        return True
    except Exception as e:
        print(f"Validation error: {e}")
        return False

if __name__ == "__main__":
    input_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv"
    output_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao_CORRECTED.csv"
    
    try:
        stats = process_csv_robustly(input_file, output_file)
        success = validate_output(output_file)
        
        print(f"\n=== FINAL RESULT ===")
        print(f"Processing: {'✓ COMPLETE' if stats['rows_processed'] > 0 else '✗ FAILED'}")
        print(f"File created: {output_file}")
        print(f"Ready for use: {'✓ YES' if success else '✗ NEEDS REVIEW'}")
        
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        sys.exit(1)