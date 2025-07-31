#!/usr/bin/env python3
"""
FINAL CSV FIX - Fix the unbalanced quotes issue to access all 5,763 documents
Issue: 388 lines have unbalanced quotes breaking CSV parsing
Solution: Fix quotes and reconstruct proper CSV structure
"""

import re
import csv
from pathlib import Path

def fix_unbalanced_quotes(line):
    """Fix unbalanced quotes in a CSV line"""
    # If the line has an odd number of quotes, we need to balance them
    quote_count = line.count('"')
    
    if quote_count % 2 == 0:
        return line  # Already balanced
    
    # Strategy: Find the problematic quote and either escape it or balance it
    # Most issues seem to be unescaped quotes within text fields
    
    # Common patterns to fix:
    # 1. Quotes within URLs or text that should be escaped
    # 2. Missing closing quotes at end of fields
    
    # Split by commas first, then examine each field
    parts = []
    current_part = ""
    in_quotes = False
    i = 0
    
    while i < len(line):
        char = line[i]
        
        if char == '"':
            if in_quotes:
                # Check if this is an escaped quote (should be "")
                if i + 1 < len(line) and line[i + 1] == '"':
                    current_part += '""'
                    i += 2
                    continue
                else:
                    # End of quoted field
                    in_quotes = False
                    current_part += char
            else:
                # Start of quoted field
                in_quotes = True
                current_part += char
        elif char == ',' and not in_quotes:
            # Field separator
            parts.append(current_part)
            current_part = ""
        else:
            current_part += char
        
        i += 1
    
    # Add the last part
    if current_part:
        parts.append(current_part)
    
    # If we're still in quotes at the end, add a closing quote
    if in_quotes:
        parts[-1] += '"'
    
    return ','.join(parts)

def fix_csv_file_complete(input_path, output_path):
    """Fix CSV file by handling all unbalanced quotes"""
    print(f"🔧 Fixing all quotes in {input_path}...")
    
    fixed_lines = []
    error_count = 0
    
    with open(input_path, 'r', encoding='utf-8-sig') as f:
        lines = f.readlines()
    
    print(f"   📊 Processing {len(lines)} lines...")
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
            
        # Skip obvious junk lines
        if line in ['Filtros', 'legislation', 'doutrina', 'other', 'jurisprudence']:
            continue
        if re.match(r'^,+$', line):
            continue
            
        try:
            # Fix unbalanced quotes
            fixed_line = fix_unbalanced_quotes(line)
            
            # Verify the fix worked by trying to parse it
            test_reader = csv.reader([fixed_line])
            test_row = next(test_reader)
            
            # Should have 16 columns for our data
            if len(test_row) >= 15:  # Allow some flexibility
                fixed_lines.append(fixed_line)
            else:
                # Try alternative fixing
                # Sometimes the issue is just missing quotes around text fields
                alt_line = line
                # Add quotes around text fields that might need them
                alt_line = re.sub(r',([^,]+(?:ementa|assunto|resumo|classificação)[^,]*),', r',"\1",', alt_line, flags=re.IGNORECASE)
                
                try:
                    test_reader = csv.reader([alt_line])
                    test_row = next(test_reader)
                    if len(test_row) >= 15:
                        fixed_lines.append(alt_line)
                    else:
                        error_count += 1
                        if error_count <= 10:
                            print(f"   ⚠️  Line {i+1}: Could not fix ({len(test_row)} columns)")
                except:
                    error_count += 1
                    
        except Exception as e:
            error_count += 1
            if error_count <= 10:
                print(f"   ❌ Line {i+1}: {str(e)[:50]}...")
    
    print(f"   ✅ Fixed {len(fixed_lines)} lines")
    print(f"   ❌ Could not fix {error_count} lines")
    
    # Write the fixed CSV
    with open(output_path, 'w', encoding='utf-8', newline='') as f:
        for line in fixed_lines:
            f.write(line + '\n')
    
    # Verify the result
    try:
        with open(output_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            verify_rows = list(reader)
            print(f"   🧪 Verification: {len(verify_rows)} rows can be parsed as CSV")
            return len(verify_rows) - 1  # Subtract header
    except Exception as e:
        print(f"   ❌ Verification failed: {e}")
        return 0

def main():
    """Fix the main CSV files"""
    files_to_fix = [
        'Geral.csv',
        'Legislação___Geral.csv',
        'Jurisprudência___Geral.csv'
    ]
    
    processed_dir = Path("./data_current/processed")
    
    print("🚨 FINAL CSV FIX - Handling unbalanced quotes issue")
    print("=" * 60)
    
    total_fixed = 0
    
    for filename in files_to_fix:
        input_path = processed_dir / filename
        output_path = processed_dir / f"{filename.replace('.csv', '_FIXED.csv')}"
        
        if input_path.exists():
            fixed_count = fix_csv_file_complete(input_path, output_path)
            total_fixed += fixed_count
            print(f"   ✅ {filename}: {fixed_count} documents\n")
        else:
            print(f"   ❌ {filename}: File not found\n")
    
    print("=" * 60)
    print(f"🎉 TOTAL FIXED DOCUMENTS: {total_fixed}")
    print("\n🔄 Next: Replace original files with fixed versions")
    print("   mv Geral_FIXED.csv Geral.csv")
    print("   mv Legislação___Geral_FIXED.csv Legislação___Geral.csv") 
    print("   mv Jurisprudência___Geral_FIXED.csv Jurisprudência___Geral.csv")

if __name__ == "__main__":
    main()