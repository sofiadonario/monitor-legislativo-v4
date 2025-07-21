#!/usr/bin/env python3
"""
Rejoin broken CSV lines - The CSV data has multi-line entries split across file lines
This happens when the Document_summary field contains actual line breaks
"""

import csv
import re
from pathlib import Path

def rejoin_broken_csv_lines(input_path, output_path):
    """Rejoin CSV lines that were broken by multi-line text fields"""
    print(f"🔧 Rejoining broken lines in {input_path}...")
    
    with open(input_path, 'r', encoding='utf-8-sig') as f:
        lines = f.readlines()
    
    print(f"   📊 Processing {len(lines)} file lines...")
    
    rejoined_lines = []
    current_line = ""
    expected_columns = 16
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        if not line:
            continue
            
        # Skip filter artifacts
        if line in ['Filtros', 'legislation', 'doutrina', 'other', 'jurisprudence']:
            continue
        if re.match(r'^,+$', line):
            continue
            
        # If this is the header line, handle it specially
        if 'Search_term' in line and 'Date_searched' in line:
            rejoined_lines.append(line)
            continue
        
        # Add this line to current line
        if current_line:
            current_line += " " + line
        else:
            current_line = line
        
        # Try to parse the current line to see if it's complete
        try:
            test_reader = csv.reader([current_line])
            test_row = next(test_reader)
            
            # If we have the expected number of columns, this line is complete
            if len(test_row) >= expected_columns:
                rejoined_lines.append(current_line)
                current_line = ""
            elif len(test_row) > expected_columns + 3:  # Too many columns, probably wrong
                # This might be multiple entries concatenated, try to split
                # For now, just save what we have if it looks reasonable
                if len(test_row) >= expected_columns:
                    rejoined_lines.append(current_line)
                current_line = ""
            # Otherwise, keep accumulating lines
                
        except Exception as e:
            # Parsing failed, keep accumulating
            # But don't let lines get too long (probably corrupted data)
            if len(current_line) > 2000:
                current_line = ""
    
    # Don't forget the last line
    if current_line:
        try:
            test_reader = csv.reader([current_line])
            test_row = next(test_reader)
            if len(test_row) >= expected_columns:
                rejoined_lines.append(current_line)
        except:
            pass
    
    print(f"   ✅ Rejoined into {len(rejoined_lines)} complete entries")
    
    # Write the rejoined CSV
    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        for line in rejoined_lines:
            f.write(line + '\n')
    
    # Verify the result
    try:
        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            verify_rows = list(reader)
            
        print(f"   🧪 Verification: {len(verify_rows)} rows parsed successfully")
        
        if len(verify_rows) > 1:
            print(f"   📊 Columns in data: {len(verify_rows[1])}")
            print(f"   📋 Sample entry: {verify_rows[1][3][:50]}..." if len(verify_rows[1]) > 3 else "")
            
        return len(verify_rows) - 1  # Subtract header
        
    except Exception as e:
        print(f"   ❌ Verification failed: {e}")
        return 0

def main():
    """Rejoin all broken CSV files"""
    files_to_fix = [
        'Geral.csv',
        'Legislação___Geral.csv',
        'Jurisprudência___Geral.csv'
    ]
    
    processed_dir = Path("./data_current/processed")
    
    print("🔧 REJOINING BROKEN CSV LINES")
    print("=" * 50)
    
    total_docs = 0
    
    for filename in files_to_fix:
        input_path = processed_dir / filename
        output_path = processed_dir / f"{filename.replace('.csv', '_REJOINED.csv')}"
        
        if input_path.exists():
            doc_count = rejoin_broken_csv_lines(input_path, output_path)
            total_docs += doc_count
            print(f"   ✅ {filename}: {doc_count} complete documents\n")
        else:
            print(f"   ❌ {filename}: File not found\n")
    
    print("=" * 50)
    print(f"🎉 TOTAL DOCUMENTS RECOVERED: {total_docs}")
    
    if total_docs > 3000:
        print("🎊 SUCCESS! We recovered most of the data!")
        print("\n🔄 Next steps:")
        print("1. Test the rejoined files")
        print("2. Replace original files if satisfied")
        print("3. Update dashboard to use rejoined data")
    else:
        print("⚠️  Still missing data, may need manual inspection")

if __name__ == "__main__":
    main()