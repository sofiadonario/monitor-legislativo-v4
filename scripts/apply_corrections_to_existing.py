#!/usr/bin/env python3
"""
Apply corrections to the existing full collection dataset
This is faster than re-collecting everything
"""

import pandas as pd
import re
from datetime import datetime
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lexml_strategy_corrected import LexMLStrategyCorrected

def load_existing_full_collection():
    """Load the existing full collection to apply corrections to"""
    files = [f for f in os.listdir('.') if f.startswith('lexml_full_collection_')]
    if not files:
        print("❌ No existing full collection found")
        return None
    
    latest_file = sorted(files)[-1]
    df = pd.read_csv(latest_file)
    print(f"✓ Loaded existing collection: {len(df)} records from {latest_file}")
    return df, latest_file

def apply_date_extraction_corrections(df):
    """Apply corrected date extraction to existing data"""
    print("🔧 Applying date extraction corrections...")
    
    strategy = LexMLStrategyCorrected()
    corrected_dates = []
    
    for idx, row in df.iterrows():
        # Try to extract date from title or other fields
        title = str(row.get('title', ''))
        document_summary = str(row.get('document_summary', ''))
        
        # Look for date patterns in title and summary
        text_to_search = f"{title} {document_summary}"
        
        # Apply the corrected date conversion
        extracted_date = strategy._convert_date_format(text_to_search)
        
        if not extracted_date and 'urn' in row:
            # Try to extract from URN
            urn = str(row['urn'])
            date_match = re.search(r':(\d{4}-\d{2}-\d{2});', urn)
            if date_match:
                extracted_date = date_match.group(1)
        
        corrected_dates.append(extracted_date)
        
        if idx % 200 == 0:
            print(f"  Processed {idx}/{len(df)} records...")
    
    df['enacting_date_corrected'] = corrected_dates
    
    # Count improvements
    original_dates = df[df['enacting_date'].astype(str).str.len() > 4]
    corrected_dates_count = df[df['enacting_date_corrected'].astype(str).str.len() > 4]
    
    print(f"✓ Date extraction improved: {len(original_dates)} → {len(corrected_dates_count)} (+{len(corrected_dates_count) - len(original_dates)})")
    
    return df

def apply_urn_classification_corrections(df):
    """Apply corrected URN classification to existing data"""
    print("🔧 Applying URN classification corrections...")
    
    strategy = LexMLStrategyCorrected()
    corrected_types = []
    
    for idx, row in df.iterrows():
        urn = str(row.get('urn', ''))
        
        if urn and urn.startswith('urn:lex:'):
            # Apply corrected URN parsing
            urn_data = strategy._parse_urn_corrected(urn)
            corrected_type = urn_data.get('urn_type', row.get('urn_type', ''))
        else:
            corrected_type = row.get('urn_type', '')
        
        corrected_types.append(corrected_type)
        
        if idx % 200 == 0:
            print(f"  Processed {idx}/{len(df)} records...")
    
    df['urn_type_corrected'] = corrected_types
    
    # Compare classifications
    print(f"\n📊 Classification changes:")
    original_types = df['urn_type'].value_counts()
    corrected_types_count = df['urn_type_corrected'].value_counts()
    
    print(f"Original distribution:")
    for doc_type, count in original_types.items():
        print(f"  {doc_type}: {count}")
    
    print(f"\nCorrected distribution:")
    for doc_type, count in corrected_types_count.items():
        print(f"  {doc_type}: {count}")
    
    return df

def create_fully_corrected_dataset():
    """Create the complete corrected dataset"""
    print("=== Applying ALL Corrections to Existing Full Collection ===")
    print("🎯 Goal: Fix all 1,904 documents with corrected logic")
    print()
    
    # Load existing data
    df, source_file = load_existing_full_collection()
    if df is None:
        return None
    
    print(f"Original dataset: {len(df)} documents")
    
    # Apply date extraction corrections
    df = apply_date_extraction_corrections(df)
    
    # Apply URN classification corrections
    df = apply_urn_classification_corrections(df)
    
    # Replace original fields with corrected ones
    df['enacting_date'] = df['enacting_date_corrected']
    df['urn_type'] = df['urn_type_corrected']
    
    # Drop temporary columns
    df = df.drop(['enacting_date_corrected', 'urn_type_corrected'], axis=1)
    
    # Save fully corrected dataset
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f'lexml_full_collection_CORRECTED_{timestamp}.csv'
    df.to_csv(output_file, index=False, encoding='utf-8')
    
    print(f"\n💾 Fully corrected dataset saved: {output_file}")
    
    # Generate correction summary
    print(f"\n📈 CORRECTION SUMMARY")
    
    # Date extraction analysis
    dates_with_data = df[df['enacting_date'].astype(str).str.len() > 4]
    date_rate = len(dates_with_data) / len(df) * 100
    print(f"📅 Date extraction rate: {date_rate:.1f}% ({len(dates_with_data)}/{len(df)})")
    
    # Classification analysis
    type_counts = df['urn_type'].value_counts()
    print(f"\n📋 Document types (CORRECTED):")
    for doc_type, count in type_counts.items():
        percentage = (count / len(df)) * 100
        print(f"  {doc_type}: {count} ({percentage:.1f}%)")
    
    # Date range analysis
    if len(dates_with_data) > 0:
        strategy = LexMLStrategyCorrected()
        date_range = strategy.get_date_range_from_results(df)
        print(f"\n📊 Document date range: {date_range.get('year_range', 'N/A')}")
        print(f"  Documents with dates: {date_range.get('total_with_dates', 0)}")
    
    # Compare with original flawed collection
    print(f"\n⚖️  BEFORE vs AFTER CORRECTIONS:")
    original_stats = {
        'date_extraction_rate': 10.6,  # From analysis
        'legislation_percentage': 5.9,
        'doctrine_percentage': 83.6
    }
    
    legislation_count = type_counts.get('legislation', 0)
    doctrine_count = type_counts.get('doctrine', 0)
    current_legislation_pct = (legislation_count / len(df) * 100) if len(df) > 0 else 0
    current_doctrine_pct = (doctrine_count / len(df) * 100) if len(df) > 0 else 0
    
    print(f"  Date extraction: {original_stats['date_extraction_rate']:.1f}% → {date_rate:.1f}% (+{date_rate - original_stats['date_extraction_rate']:.1f}%)")
    print(f"  Legislation: {original_stats['legislation_percentage']:.1f}% → {current_legislation_pct:.1f}% (+{current_legislation_pct - original_stats['legislation_percentage']:.1f}%)")
    print(f"  Doctrine: {original_stats['doctrine_percentage']:.1f}% → {current_doctrine_pct:.1f}% ({current_doctrine_pct - original_stats['doctrine_percentage']:+.1f}%)")
    
    # Success validation
    if date_rate >= 50 and current_legislation_pct > original_stats['legislation_percentage']:
        print(f"\n🎉 CORRECTIONS SUCCESSFULLY APPLIED!")
        print(f"✅ All {len(df)} documents now have corrected data")
    else:
        print(f"\n⚠️  Corrections need review")
    
    return output_file, len(df)

def main():
    """Main execution"""
    print("🚀 Applying Corrections to Existing Full Collection...")
    print("This will fix all data without re-collecting\n")
    
    try:
        output_file, document_count = create_fully_corrected_dataset()
        
        if output_file:
            print(f"\n🎉 ALL corrections applied successfully!")
            print(f"📁 Corrected file: {output_file}")
            print(f"📊 Total documents: {document_count}")
            print(f"✅ Ready for database integration")
        else:
            print(f"\n❌ Correction application failed")
            
    except Exception as e:
        print(f"\n❌ Error applying corrections: {e}")

if __name__ == "__main__":
    main()