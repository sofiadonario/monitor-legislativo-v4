#!/usr/bin/env python3
"""
CSV Files Cleaner - Fix malformed CSV files in ./data_current/processed/
Fixes: multi-line text entries, unescaped quotes, line breaks in fields
"""

import os
import csv
import re
from pathlib import Path

def clean_text_field(text):
    """Clean text field by removing line breaks and fixing quotes"""
    if not text:
        return text
    
    # Replace multiple line breaks with single space
    text = re.sub(r'\n+', ' ', text)
    text = re.sub(r'\r+', ' ', text)
    
    # Replace multiple spaces with single space
    text = re.sub(r'\s+', ' ', text)
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text

def fix_csv_file(input_path, output_path):
    """Fix a single CSV file by cleaning text fields"""
    print(f"🔧 Fixing {input_path}...")
    
    try:
        # Read the problematic CSV with more robust settings
        rows = []
        with open(input_path, 'r', encoding='utf-8-sig', newline='') as f:
            # Try to read line by line and handle malformed entries
            content = f.read()
            
            # Fix obvious multi-line issues in the content
            # Replace line breaks within quoted fields
            content = re.sub(r'"\s*\n+\s*([^"]*?)\n+\s*"', r'"\1"', content, flags=re.DOTALL)
            
            # Split into lines but handle quotes properly
            lines = content.split('\n')
            current_row = ""
            quote_count = 0
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                # Count quotes to determine if we're inside a quoted field
                quote_count += line.count('"')
                
                if current_row:
                    current_row += " " + line
                else:
                    current_row = line
                
                # If quotes are balanced, we have a complete row
                if quote_count % 2 == 0:
                    if current_row:
                        rows.append(current_row)
                    current_row = ""
                    quote_count = 0
        
        print(f"   📊 Read {len(rows)} raw rows")
        
        # Process rows with CSV parser
        processed_rows = []
        for i, row in enumerate(rows):
            try:
                # Parse the row
                reader = csv.reader([row])
                parsed_row = next(reader)
                
                # Clean text fields (especially Document_summary and Document_description)
                cleaned_row = []
                for j, field in enumerate(parsed_row):
                    if j >= 14:  # Document_description and Document_summary are typically at the end
                        cleaned_field = clean_text_field(field)
                    else:
                        cleaned_field = field.strip() if field else field
                    cleaned_row.append(cleaned_field)
                
                processed_rows.append(cleaned_row)
                
            except Exception as e:
                print(f"   ⚠️  Row {i+1} parsing error: {str(e)[:100]}...")
                continue
        
        print(f"   ✅ Processed {len(processed_rows)} clean rows")
        
        # Write the cleaned CSV
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            for row in processed_rows:
                writer.writerow(row)
        
        print(f"   💾 Saved to {output_path}")
        return len(processed_rows)
        
    except Exception as e:
        print(f"   ❌ Error fixing {input_path}: {e}")
        return 0

def main():
    """Fix all CSV files in ./data_current/processed/"""
    processed_dir = Path("./data_current/processed")
    
    if not processed_dir.exists():
        print("❌ Directory ./data_current/processed/ not found")
        return
    
    csv_files = list(processed_dir.glob("*.csv"))
    print(f"🔍 Found {len(csv_files)} CSV files to fix")
    
    results = {}
    
    for csv_file in csv_files:
        input_path = csv_file
        output_path = csv_file.with_stem(csv_file.stem + "_fixed")
        
        rows_count = fix_csv_file(input_path, output_path)
        results[csv_file.name] = rows_count
    
    print("\n📊 Cleaning Results:")
    total_rows = 0
    for filename, count in results.items():
        print(f"   {filename}: {count} rows")
        total_rows += count
    
    print(f"\n✅ Total rows processed: {total_rows}")
    print("\n🔄 Next steps:")
    print("1. Verify the fixed files look correct")
    print("2. Replace original files with fixed versions")
    print("3. Test data loading with full dataset")

if __name__ == "__main__":
    main()