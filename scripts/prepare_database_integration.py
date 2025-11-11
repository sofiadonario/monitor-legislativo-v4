#!/usr/bin/env python3
"""
Prepare enhanced LexML data for database integration
"""

import pandas as pd
import os
from datetime import datetime
import re

def load_enhanced_data():
    """Load the latest enhanced collection results"""
    # Check for corrected collection first, then full collection, then priority collection
    corrected_files = [f for f in os.listdir('.') if f.startswith('lexml_full_collection_CORRECTED_')]
    full_files = [f for f in os.listdir('.') if f.startswith('lexml_full_collection_')]
    priority_files = [f for f in os.listdir('.') if f.startswith('lexml_priority_results_')]
    
    if corrected_files:
        latest_file = sorted(corrected_files)[-1]
        df = pd.read_csv(latest_file)
        print(f"✓ Loaded CORRECTED collection data: {len(df)} records from {latest_file}")
        return df
    elif full_files:
        latest_file = sorted(full_files)[-1]
        df = pd.read_csv(latest_file)
        print(f"✓ Loaded FULL collection data: {len(df)} records from {latest_file}")
        return df
    elif priority_files:
        latest_file = sorted(priority_files)[-1]
        df = pd.read_csv(latest_file)
        print(f"✓ Loaded priority collection data: {len(df)} records from {latest_file}")
        return df
    else:
        print("❌ No enhanced results files found")
        return None

def clean_and_standardize_data(df):
    """Clean and standardize data for database integration"""
    print("🧹 Cleaning and standardizing data...")
    
    # Make a copy to avoid modifying original
    cleaned_df = df.copy()
    
    # 1. Standardize date formats
    if 'date_searched' in cleaned_df.columns:
        cleaned_df['date_searched'] = pd.to_datetime(cleaned_df['date_searched'], errors='coerce')
        cleaned_df['date_searched'] = cleaned_df['date_searched'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    if 'enacting_date' in cleaned_df.columns:
        # Clean enacting_date - remove extra text, keep only date
        def clean_date(date_str):
            if pd.isna(date_str):
                return None
            # Extract date patterns like YYYY-MM-DD or DD/MM/YYYY
            date_patterns = [
                r'(\d{4}-\d{2}-\d{2})',  # YYYY-MM-DD
                r'(\d{2}/\d{2}/\d{4})',  # DD/MM/YYYY
                r'(\d{2}-\d{2}-\d{4})',  # DD-MM-YYYY
                r'(\d{4})'               # Just year
            ]
            
            for pattern in date_patterns:
                match = re.search(pattern, str(date_str))
                if match:
                    return match.group(1)
            return date_str
        
        cleaned_df['enacting_date'] = cleaned_df['enacting_date'].apply(clean_date)
    
    # 2. Clean text fields
    text_fields = ['title', 'document_summary', 'document_description']
    
    for field in text_fields:
        if field in cleaned_df.columns:
            # Remove excessive whitespace and normalize
            cleaned_df[field] = cleaned_df[field].astype(str).str.strip()
            cleaned_df[field] = cleaned_df[field].str.replace(r'\s+', ' ', regex=True)
            
            # Replace 'nan' string with actual NaN
            cleaned_df[field] = cleaned_df[field].replace('nan', pd.NA)
    
    # 3. Standardize URN format
    if 'urn' in cleaned_df.columns:
        cleaned_df['urn'] = cleaned_df['urn'].astype(str).str.strip()
        # Ensure URNs start with 'urn:lex:'
        mask = cleaned_df['urn'].notna() & ~cleaned_df['urn'].str.startswith('urn:lex:', na=False)
        if mask.any():
            print(f"⚠ Found {mask.sum()} URNs not starting with 'urn:lex:' - will be cleaned")
    
    # 4. Standardize document types
    if 'urn_type' in cleaned_df.columns:
        # Map common variations
        type_mapping = {
            'doctrine': 'doutrina',
            'legislation': 'legislacao',
            'jurisprudence': 'jurisprudencia'
        }
        cleaned_df['urn_type'] = cleaned_df['urn_type'].replace(type_mapping)
    
    # 5. Clean source_type
    if 'source_type' in cleaned_df.columns:
        cleaned_df['source_type'] = cleaned_df['source_type'].str.replace('.', ' ').str.title()
    
    # 6. Ensure all required fields exist
    required_fields = [
        'search_term', 'date_searched', 'url', 'title', 'urn', 'urn_type',
        'country', 'state', 'municipality', 'justice', 'region', 'court_class',
        'document_type_full', 'enacting_date', 'document_description', 'document_summary'
    ]
    
    for field in required_fields:
        if field not in cleaned_df.columns:
            cleaned_df[field] = pd.NA
    
    # 7. Reorder columns for consistency
    column_order = [
        'search_term', 'date_searched', 'url', 'title', 'urn', 'urn_type',
        'country', 'state', 'municipality', 'justice', 'region', 'court_class',
        'document_type_full', 'enacting_date', 'document_description', 
        'document_summary', 'source_type'
    ]
    
    # Only include columns that exist
    existing_columns = [col for col in column_order if col in cleaned_df.columns]
    cleaned_df = cleaned_df[existing_columns]
    
    print(f"✓ Data cleaned: {len(cleaned_df)} records, {len(cleaned_df.columns)} columns")
    return cleaned_df

def validate_data_quality(df):
    """Validate data quality for database integration"""
    print("🔍 Validating data quality...")
    
    issues = []
    
    # Check for required fields
    critical_fields = ['search_term', 'title', 'urn']
    for field in critical_fields:
        if field in df.columns:
            null_count = df[field].isna().sum()
            if null_count > 0:
                issues.append(f"Missing {field}: {null_count} records")
    
    # Check URN format
    if 'urn' in df.columns:
        invalid_urns = ~df['urn'].str.startswith('urn:lex:', na=False)
        if invalid_urns.any():
            issues.append(f"Invalid URN format: {invalid_urns.sum()} records")
    
    # Check for duplicates
    if 'urn' in df.columns:
        duplicates = df['urn'].duplicated().sum()
        if duplicates > 0:
            issues.append(f"Duplicate URNs: {duplicates} records")
    
    # Check date formats
    if 'date_searched' in df.columns:
        try:
            pd.to_datetime(df['date_searched'], errors='raise')
        except:
            issues.append("Invalid date_searched format")
    
    if issues:
        print("⚠ Data quality issues found:")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("✓ Data quality validation passed")
    
    return issues

def generate_database_summary(df):
    """Generate summary for database integration"""
    summary = {
        'total_records': len(df),
        'unique_urns': df['urn'].nunique() if 'urn' in df.columns else 0,
        'document_types': df['urn_type'].value_counts().to_dict() if 'urn_type' in df.columns else {},
        'search_terms': df['search_term'].nunique() if 'search_term' in df.columns else 0,
        'date_range': {
            'earliest': df['date_searched'].min() if 'date_searched' in df.columns else None,
            'latest': df['date_searched'].max() if 'date_searched' in df.columns else None
        },
        'data_completeness': {}
    }
    
    # Calculate completeness for key fields
    key_fields = ['title', 'document_summary', 'document_description', 'url', 'source_type']
    for field in key_fields:
        if field in df.columns:
            completeness = (df[field].notna().sum() / len(df)) * 100
            summary['data_completeness'][field] = f"{completeness:.1f}%"
    
    return summary

def prepare_for_database():
    """Main function to prepare data for database integration"""
    print("=== Preparing Enhanced Data for Database Integration ===")
    
    # Load data
    df = load_enhanced_data()
    if df is None:
        return None
    
    # Clean and standardize
    cleaned_df = clean_and_standardize_data(df)
    
    # Validate quality
    issues = validate_data_quality(cleaned_df)
    
    # Generate summary
    summary = generate_database_summary(cleaned_df)
    
    # Save cleaned data
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f'lexml_enhanced_database_ready_{timestamp}.csv'
    cleaned_df.to_csv(output_file, index=False, encoding='utf-8')
    
    # Save metadata/summary
    summary_file = f'database_integration_summary_{timestamp}.txt'
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("LexML Enhanced Data - Database Integration Summary\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n\n")
        
        f.write(f"Total Records: {summary['total_records']}\n")
        f.write(f"Unique URNs: {summary['unique_urns']}\n")
        f.write(f"Search Terms: {summary['search_terms']}\n\n")
        
        f.write("Document Types:\n")
        for doc_type, count in summary['document_types'].items():
            f.write(f"  {doc_type}: {count}\n")
        
        f.write("\nData Completeness:\n")
        for field, percentage in summary['data_completeness'].items():
            f.write(f"  {field}: {percentage}\n")
        
        f.write(f"\nDate Range: {summary['date_range']['earliest']} to {summary['date_range']['latest']}\n")
        
        if issues:
            f.write(f"\nData Quality Issues:\n")
            for issue in issues:
                f.write(f"  - {issue}\n")
        else:
            f.write(f"\nData Quality: ✓ All validations passed\n")
    
    print(f"\n✅ Database integration preparation complete!")
    print(f"📄 Clean data file: {output_file}")
    print(f"📊 Summary file: {summary_file}")
    print(f"📈 Records prepared: {summary['total_records']}")
    
    return output_file, summary

if __name__ == "__main__":
    output_file, summary = prepare_for_database()
    
    if output_file:
        print(f"\n🎉 Ready for database integration!")
        print(f"📁 File: {output_file}")
        print(f"📊 Records: {summary['total_records']}")
        print(f"🔍 Quality: {'✓ Validated' if not validate_data_quality(pd.read_csv(output_file)) else '⚠ Issues found'}")
    else:
        print(f"\n❌ Database preparation failed")