#!/usr/bin/env python3
"""
Diagnose exactly what's wrong with the CSV file
"""

import csv
from pathlib import Path

def diagnose_csv(filepath):
    """Diagnose CSV parsing issues"""
    print(f"🔍 Diagnosing {filepath}")
    
    # Count actual lines
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        lines = f.readlines()
    print(f"   📊 Total lines in file: {len(lines)}")
    
    # Try different CSV reading approaches
    approaches = [
        ("Standard", {}),
        ("No quoting", {"quoting": csv.QUOTE_NONE}),
        ("Minimal quoting", {"quoting": csv.QUOTE_MINIMAL}),
        ("All quoting", {"quoting": csv.QUOTE_ALL}),
        ("Different delimiter", {"delimiter": "|"}),
    ]
    
    for name, kwargs in approaches:
        try:
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                reader = csv.reader(f, **kwargs)
                rows = list(reader)
                print(f"   {name}: {len(rows)} rows parsed")
                if len(rows) > 1:
                    print(f"     Sample row length: {len(rows[1])} columns")
        except Exception as e:
            print(f"   {name}: Failed - {str(e)[:100]}...")
    
    # Check for specific problematic patterns
    print("\n🔍 Checking for problematic patterns...")
    
    problematic_lines = 0
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
                
            # Check for unbalanced quotes
            quote_count = line.count('"')
            if quote_count % 2 != 0:
                problematic_lines += 1
                if problematic_lines <= 5:  # Show first 5 examples
                    print(f"     Line {i}: Unbalanced quotes ({quote_count} quotes)")
                    print(f"       {line[:100]}...")
    
    print(f"   📊 Lines with unbalanced quotes: {problematic_lines}")
    
    # Try manual parsing with error handling
    print("\n🔧 Attempting manual parsing with error handling...")
    
    parsed_rows = 0
    error_lines = []
    
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            try:
                if len(row) >= 10:  # Should have at least 10 columns
                    parsed_rows += 1
                else:
                    error_lines.append(i+1)
                    
                if i > 10000:  # Don't go through entire file
                    break
                    
            except Exception as e:
                error_lines.append(i+1)
                if len(error_lines) <= 10:
                    print(f"     Parse error at row {i+1}: {e}")
    
    print(f"   ✅ Successfully parsed: {parsed_rows} rows")
    print(f"   ❌ Error lines: {len(error_lines)} lines")
    
    return parsed_rows

def main():
    filepath = Path("./data_current/processed/Geral.csv")
    if filepath.exists():
        parsed_count = diagnose_csv(filepath)
        print(f"\n💡 The file has 5,764 lines but only {parsed_count} can be parsed cleanly")
        print("   This suggests severe data corruption in the CSV structure")
    else:
        print("❌ File not found")

if __name__ == "__main__":
    main()