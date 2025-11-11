#!/usr/bin/env python3
"""
QUICK FIX: Update existing deduplicated file with proper categories
This script fixes the existing deduplicated file by using the 'categoria' field
"""

import pandas as pd
import json
from datetime import datetime

def fix_categories_in_existing_file():
    """Fix categories in the existing deduplicated file"""
    print("🔧 FIXING CATEGORIES IN EXISTING DEDUPLICATED FILE...")
    
    # Load existing file
    input_file = "./data_current/processed/deduplicated/lexml_unified_deduplicated.csv"
    print(f"📄 Loading existing file: {input_file}")
    
    try:
        df = pd.read_csv(input_file, encoding='utf-8')
        print(f"✅ Loaded {len(df):,} rows")
    except Exception as e:
        print(f"❌ Error loading file: {e}")
        return
    
    # Fix the _extracted_category field using the existing 'categoria' field
    print("🔧 Fixing _extracted_category field...")
    
    # Use the existing 'categoria' field instead of the broken filename-based extraction
    df['_extracted_category'] = df['categoria'].fillna('Outros')
    
    # Also fix transport mode using 'modal' field if available
    if 'modal' in df.columns:
        df['_extracted_transport_mode'] = df['modal'].fillna('Geral')
        print("✅ Also fixed _extracted_transport_mode using 'modal' field")
    
    # Show the fixed distribution
    category_counts = df['_extracted_category'].value_counts()
    print("\n📊 FIXED CATEGORY DISTRIBUTION:")
    total_docs = len(df)
    for category, count in category_counts.items():
        percentage = (count / total_docs) * 100
        print(f"   {category}: {count:,} documents ({percentage:.1f}%)")
    
    # Save the fixed file
    output_file = "./data_current/processed/deduplicated/lexml_unified_deduplicated_FIXED.csv"
    df.to_csv(output_file, index=False, encoding='utf-8')
    print(f"💾 Saved fixed file: {output_file}")
    
    # Create analysis
    analysis = {
        "total_documents": len(df),
        "categories": df['_extracted_category'].value_counts().to_dict(),
        "transport_modes": df['_extracted_transport_mode'].value_counts().to_dict() if '_extracted_transport_mode' in df.columns else {},
        "fix_timestamp": datetime.now().isoformat(),
        "fix_method": "used_existing_categoria_field",
        "improvement": f"Changed from 100% 'Unknown' to {len(category_counts)} distinct categories"
    }
    
    # Save analysis
    analysis_file = "./data_current/processed/deduplicated/categories_FIXED_analysis.json" 
    with open(analysis_file, 'w', encoding='utf-8') as f:
        json.dump(analysis, f, indent=2, ensure_ascii=False)
    print(f"📊 Saved analysis: {analysis_file}")
    
    print("✅ CATEGORIES FIXED SUCCESSFULLY!")
    print(f"🎯 Result: {len(category_counts)} distinct categories instead of 100% 'Unknown'")
    return output_file

if __name__ == "__main__":
    fixed_file = fix_categories_in_existing_file()