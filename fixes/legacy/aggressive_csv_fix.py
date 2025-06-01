#!/usr/bin/env python3
"""
Aggressive CSV Cleaner - Handle severely corrupted CSV files
"""

import pandas as pd
import re
import csv
from pathlib import Path

def aggressive_csv_fix(input_file, output_file):
    """Aggressively fix corrupted CSV by reading all data and reconstructing properly"""
    print(f"🚨 Aggressive fixing: {input_file}")
    
    try:
        # Read the entire file as text
        with open(input_file, 'r', encoding='utf-8-sig', errors='ignore') as f:
            content = f.read()
        
        # Clean up the content
        print("   🧹 Cleaning content...")
        
        # Remove completely empty lines
        lines = [line for line in content.split('\n') if line.strip()]
        
        # Filter out obviously bad lines
        valid_lines = []
        header_found = False
        
        for line in lines:
            line = line.strip()
            
            # Skip empty lines
            if not line:
                continue
                
            # Skip filter artifacts at the end
            if line in ['Filtros', 'legislation', 'doutrina', 'other', 'jurisprudence']:
                continue
                
            # Skip lines that are just commas
            if re.match(r'^,+$', line):
                continue
                
            # Keep the header
            if 'Search_term' in line and 'Date_searched' in line:
                valid_lines.append(line)
                header_found = True
                continue
            
            # Skip lines before header is found
            if not header_found:
                continue
                
            # Clean the line
            # Fix multi-line breaks within the line
            clean_line = re.sub(r'\s+', ' ', line)
            
            # Only keep lines that have reasonable content
            if clean_line.count(',') >= 10:  # Should have at least 10 commas for 16 columns
                valid_lines.append(clean_line)
        
        print(f"   📊 Kept {len(valid_lines)} valid lines (including header)")
        
        # Try to parse with pandas for better handling
        from io import StringIO
        csv_content = '\n'.join(valid_lines)
        
        # Use pandas to read and clean
        df = pd.read_csv(StringIO(csv_content), encoding='utf-8', on_bad_lines='skip')
        
        print(f"   ✅ Pandas parsed: {len(df)} rows")
        
        # Clean text columns
        text_columns = ['Document_description', 'Document_summary', 'Title']
        for col in text_columns:
            if col in df.columns:
                df[col] = df[col].astype(str).apply(lambda x: re.sub(r'\s+', ' ', x).strip() if pd.notna(x) else '')
        
        # Remove rows with all NaN values
        df = df.dropna(how='all')
        
        # Save the cleaned file
        df.to_csv(output_file, index=False, encoding='utf-8')
        
        print(f"   💾 Saved {len(df)} rows to {output_file}")
        return len(df)
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        
        # Fallback: try basic line-by-line approach
        try:
            print("   🔄 Trying fallback approach...")
            
            with open(input_file, 'r', encoding='utf-8-sig') as f:
                lines = f.readlines()
            
            # Find header and clean lines
            clean_lines = []
            header_found = False
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                    
                if 'Search_term' in line:
                    clean_lines.append(line)
                    header_found = True
                elif header_found and line.count(',') >= 10:
                    # Clean the line
                    clean_line = re.sub(r'\n+', ' ', line)
                    clean_line = re.sub(r'\s+', ' ', clean_line)
                    clean_lines.append(clean_line)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(clean_lines))
            
            print(f"   💾 Fallback saved {len(clean_lines)-1} rows")
            return len(clean_lines) - 1
            
        except Exception as e2:
            print(f"   ❌ Fallback failed: {e2}")
            return 0

def main():
    """Fix the main problematic files"""
    files_to_fix = [
        'Geral.csv',
        'Legislação___Geral.csv', 
        'Jurisprudência___Geral.csv'
    ]
    
    processed_dir = Path("./data_current/processed")
    
    total_rows = 0
    for filename in files_to_fix:
        input_path = processed_dir / filename
        output_path = processed_dir / f"{filename.replace('.csv', '_clean.csv')}"
        
        if input_path.exists():
            rows = aggressive_csv_fix(input_path, output_path)
            total_rows += rows
        else:
            print(f"❌ File not found: {input_path}")
    
    print(f"\n✅ Total clean rows: {total_rows}")
    
    # Test loading with pandas
    print("\n🧪 Testing cleaned files...")
    for filename in files_to_fix:
        clean_path = processed_dir / f"{filename.replace('.csv', '_clean.csv')}"
        if clean_path.exists():
            try:
                test_df = pd.read_csv(clean_path)
                print(f"   ✅ {filename.replace('.csv', '_clean.csv')}: {len(test_df)} rows loaded successfully")
            except Exception as e:
                print(f"   ❌ {filename.replace('.csv', '_clean.csv')}: Failed to load - {e}")

if __name__ == "__main__":
    main()