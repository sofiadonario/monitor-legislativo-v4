#!/usr/bin/env python3
"""
Comprehensive CSV Analysis and Correction Tool
Critical file: lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv
Objective: Fix parsing barriers preventing access to all 786,013 rows
"""

import csv
import os
import sys
import chardet
import re
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict, Any, Tuple
import io
import traceback

class CSVAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_size = 0
        self.encoding = None
        self.delimiter = None
        self.quote_char = None
        self.line_terminator = None
        self.header = None
        self.total_rows = 0
        self.parsing_barrier_row = None
        self.issues = []
        self.corrections_applied = []
        
    def detect_encoding(self, sample_size: int = 1024 * 1024) -> str:
        """Detect file encoding using chardet"""
        print("Detecting file encoding...")
        with open(self.file_path, 'rb') as f:
            raw_data = f.read(sample_size)
            result = chardet.detect(raw_data)
            confidence = result['confidence']
            encoding = result['encoding']
            print(f"Detected encoding: {encoding} (confidence: {confidence:.2f})")
            return encoding
    
    def get_file_info(self):
        """Get basic file information"""
        self.file_size = os.path.getsize(self.file_path)
        print(f"File size: {self.file_size:,} bytes ({self.file_size / (1024*1024):.2f} MB)")
        
    def detect_csv_format(self) -> Dict[str, Any]:
        """Detect CSV format parameters"""
        print("Detecting CSV format...")
        
        # Read first few lines to detect format
        with open(self.file_path, 'r', encoding=self.encoding, errors='replace') as f:
            sample = f.read(10240)  # Read first 10KB
            
        # Use csv.Sniffer to detect format
        sniffer = csv.Sniffer()
        try:
            dialect = sniffer.sniff(sample, delimiters=',;\t|')
            self.delimiter = dialect.delimiter
            self.quote_char = dialect.quotechar
            self.line_terminator = dialect.lineterminator
            
            print(f"Detected delimiter: '{self.delimiter}'")
            print(f"Detected quote char: '{self.quote_char}'")
            print(f"Detected line terminator: '{repr(self.line_terminator)}'")
            
        except Exception as e:
            print(f"Auto-detection failed, using defaults: {e}")
            self.delimiter = ','
            self.quote_char = '"'
            self.line_terminator = '\n'
            
        return {
            'delimiter': self.delimiter,
            'quote_char': self.quote_char,
            'line_terminator': self.line_terminator
        }
    
    def count_total_lines(self) -> int:
        """Count total lines in file using binary reading for speed"""
        print("Counting total lines...")
        line_count = 0
        with open(self.file_path, 'rb') as f:
            buffer = bytearray(2048)
            readline = f.readline
            while readline():
                line_count += 1
        
        print(f"Total lines in file: {line_count:,}")
        return line_count
    
    def find_parsing_barrier(self) -> Tuple[int, str]:
        """Find where CSV parsing starts failing"""
        print("Searching for parsing barriers...")
        
        row_count = 0
        problematic_rows = []
        
        try:
            with open(self.file_path, 'r', encoding=self.encoding, errors='replace') as f:
                reader = csv.reader(f, delimiter=self.delimiter, quotechar=self.quote_char)
                
                # Get header
                try:
                    self.header = next(reader)
                    row_count += 1
                    print(f"Header columns: {len(self.header)}")
                    print(f"Header: {self.header[:5]}..." if len(self.header) > 5 else f"Header: {self.header}")
                except Exception as e:
                    print(f"Failed to read header: {e}")
                    return 0, "Header parsing failed"
                
                # Process rows
                for i, row in enumerate(reader):
                    row_count += 1
                    
                    # Check for common issues
                    if len(row) != len(self.header):
                        problematic_rows.append({
                            'row_num': row_count,
                            'issue': f'Column count mismatch: expected {len(self.header)}, got {len(row)}',
                            'row_preview': str(row)[:200] + '...' if len(str(row)) > 200 else str(row)
                        })
                    
                    # Check for extremely long fields
                    for field_idx, field in enumerate(row):
                        if len(field) > 10000:  # Fields longer than 10KB
                            problematic_rows.append({
                                'row_num': row_count,
                                'issue': f'Extremely long field in column {field_idx}: {len(field)} characters',
                                'row_preview': field[:200] + '...'
                            })
                    
                    # Progress reporting
                    if row_count % 50000 == 0:
                        print(f"Processed {row_count:,} rows...")
                        
                    # Stop if we find too many issues in a short span
                    if len(problematic_rows) > 100 and row_count < 200000:
                        print(f"Too many issues found early, stopping analysis at row {row_count}")
                        break
                        
        except Exception as e:
            print(f"Parsing failed at row {row_count}: {e}")
            self.parsing_barrier_row = row_count
            return row_count, str(e)
            
        print(f"Successfully read {row_count:,} rows")
        
        # Report problematic rows
        if problematic_rows:
            print(f"\nFound {len(problematic_rows)} problematic rows:")
            for issue in problematic_rows[:10]:  # Show first 10
                print(f"  Row {issue['row_num']}: {issue['issue']}")
                
        return row_count, "No parsing barrier found" if not problematic_rows else f"{len(problematic_rows)} issues detected"
    
    def analyze_text_fields(self) -> Dict[str, Any]:
        """Analyze text fields for problematic characters"""
        print("Analyzing text field content...")
        
        text_analysis = {
            'max_field_length': 0,
            'fields_with_newlines': 0,
            'fields_with_quotes': 0,
            'fields_with_special_chars': 0,
            'extremely_long_fields': []
        }
        
        row_count = 0
        try:
            with open(self.file_path, 'r', encoding=self.encoding, errors='replace') as f:
                # Read line by line to avoid CSV parsing issues
                for line_num, line in enumerate(f):
                    row_count += 1
                    
                    # Analyze line characteristics
                    if len(line) > 50000:  # Lines longer than 50KB
                        text_analysis['extremely_long_fields'].append({
                            'line_num': line_num + 1,
                            'length': len(line),
                            'preview': line[:200] + '...'
                        })
                    
                    if len(line) > text_analysis['max_field_length']:
                        text_analysis['max_field_length'] = len(line)
                    
                    if '\n' in line[:-1]:  # Newlines within the line (not just at end)
                        text_analysis['fields_with_newlines'] += 1
                    
                    if line.count('"') % 2 != 0:  # Unbalanced quotes
                        text_analysis['fields_with_quotes'] += 1
                    
                    # Check for special characters that might cause issues
                    if re.search(r'[^\x20-\x7E\n\r\t]', line):
                        text_analysis['fields_with_special_chars'] += 1
                    
                    if row_count % 100000 == 0:
                        print(f"Analyzed {row_count:,} lines...")
                        
                    if row_count >= 1000000:  # Limit analysis for performance
                        break
                        
        except Exception as e:
            print(f"Text analysis failed at line {row_count}: {e}")
            
        print(f"Text analysis completed for {row_count:,} lines")
        print(f"Max field length: {text_analysis['max_field_length']:,} characters")
        print(f"Lines with embedded newlines: {text_analysis['fields_with_newlines']:,}")
        print(f"Lines with unbalanced quotes: {text_analysis['fields_with_quotes']:,}")
        print(f"Lines with special characters: {text_analysis['fields_with_special_chars']:,}")
        print(f"Extremely long fields found: {len(text_analysis['extremely_long_fields'])}")
        
        return text_analysis
    
    def check_date_formats(self) -> Dict[str, Any]:
        """Check date formats in data_publicacao column"""
        print("Analyzing date formats...")
        
        date_analysis = {
            'total_dates': 0,
            'excel_serial_dates': 0,
            'standard_dates': 0,
            'invalid_dates': 0,
            'sample_values': []
        }
        
        # Find data_publicacao column index
        data_pub_col = None
        if self.header:
            for i, col in enumerate(self.header):
                if 'data_publicacao' in col.lower():
                    data_pub_col = i
                    break
        
        if data_pub_col is None:
            print("data_publicacao column not found")
            return date_analysis
            
        print(f"Found data_publicacao column at index {data_pub_col}")
        
        row_count = 0
        try:
            with open(self.file_path, 'r', encoding=self.encoding, errors='replace') as f:
                reader = csv.reader(f, delimiter=self.delimiter, quotechar=self.quote_char)
                next(reader)  # Skip header
                
                for row in reader:
                    row_count += 1
                    
                    if len(row) > data_pub_col:
                        date_value = row[data_pub_col].strip()
                        if date_value:
                            date_analysis['total_dates'] += 1
                            
                            # Check if it's an Excel serial date (numeric)
                            try:
                                float_val = float(date_value)
                                if 1 <= float_val <= 100000:  # Reasonable Excel date range
                                    date_analysis['excel_serial_dates'] += 1
                                    if len(date_analysis['sample_values']) < 10:
                                        date_analysis['sample_values'].append(('excel', date_value))
                            except ValueError:
                                # Check if it's already a standard date format
                                if re.match(r'\d{4}-\d{2}-\d{2}', date_value):
                                    date_analysis['standard_dates'] += 1
                                    if len(date_analysis['sample_values']) < 10:
                                        date_analysis['sample_values'].append(('standard', date_value))
                                else:
                                    date_analysis['invalid_dates'] += 1
                                    if len(date_analysis['sample_values']) < 10:
                                        date_analysis['sample_values'].append(('invalid', date_value))
                    
                    if row_count >= 10000:  # Sample first 10k rows for performance
                        break
                        
        except Exception as e:
            print(f"Date analysis failed: {e}")
            
        print(f"Date analysis results:")
        print(f"  Total dates analyzed: {date_analysis['total_dates']:,}")
        print(f"  Excel serial dates: {date_analysis['excel_serial_dates']:,}")
        print(f"  Standard format dates: {date_analysis['standard_dates']:,}")
        print(f"  Invalid dates: {date_analysis['invalid_dates']:,}")
        print(f"  Sample values: {date_analysis['sample_values']}")
        
        return date_analysis
    
    def run_comprehensive_analysis(self) -> Dict[str, Any]:
        """Run complete file analysis"""
        print("="*60)
        print("COMPREHENSIVE CSV ANALYSIS")
        print("="*60)
        
        # Basic file info
        self.get_file_info()
        
        # Detect encoding
        self.encoding = self.detect_encoding()
        
        # Detect CSV format
        csv_format = self.detect_csv_format()
        
        # Count total lines
        total_lines = self.count_total_lines()
        
        # Find parsing barriers
        parsed_rows, barrier_info = self.find_parsing_barrier()
        
        # Analyze text fields
        text_analysis = self.analyze_text_fields()
        
        # Check date formats
        date_analysis = self.check_date_formats()
        
        # Compile analysis results
        analysis_results = {
            'file_info': {
                'path': self.file_path,
                'size_bytes': self.file_size,
                'size_mb': self.file_size / (1024*1024),
                'encoding': self.encoding
            },
            'csv_format': csv_format,
            'row_info': {
                'total_lines': total_lines,
                'parsed_rows': parsed_rows,
                'expected_rows': 786013,
                'parsing_barrier': barrier_info,
                'parsing_success_rate': (parsed_rows / 786013) * 100 if parsed_rows else 0
            },
            'text_analysis': text_analysis,
            'date_analysis': date_analysis,
            'header': self.header
        }
        
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        print(f"File size: {analysis_results['file_info']['size_mb']:.2f} MB")
        print(f"Encoding: {analysis_results['file_info']['encoding']}")
        print(f"Delimiter: '{analysis_results['csv_format']['delimiter']}'")
        print(f"Total lines: {analysis_results['row_info']['total_lines']:,}")
        print(f"Successfully parsed rows: {analysis_results['row_info']['parsed_rows']:,}")
        print(f"Expected rows: {analysis_results['row_info']['expected_rows']:,}")
        print(f"Parsing success rate: {analysis_results['row_info']['parsing_success_rate']:.1f}%")
        print(f"Parsing barrier: {analysis_results['row_info']['parsing_barrier']}")
        print(f"Max field length: {analysis_results['text_analysis']['max_field_length']:,} chars")
        print(f"Excel serial dates found: {analysis_results['date_analysis']['excel_serial_dates']:,}")
        
        return analysis_results

def main():
    file_path = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv"
    
    if not os.path.exists(file_path):
        print(f"ERROR: File not found: {file_path}")
        return
    
    analyzer = CSVAnalyzer(file_path)
    results = analyzer.run_comprehensive_analysis()
    
    return results

if __name__ == "__main__":
    main()