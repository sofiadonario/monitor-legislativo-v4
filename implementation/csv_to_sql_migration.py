#!/usr/bin/env python3
"""
Convert corrected CSV to SQL migration script for production deployment
"""

import pandas as pd
import sys
from datetime import datetime
import re

def sanitize_sql_value(value):
    """Sanitize values for SQL insertion"""
    if pd.isna(value) or value is None or value == '':
        return 'NULL'
    
    # Convert to string and escape single quotes
    str_value = str(value).replace("'", "''")
    return f"'{str_value}'"

def convert_date(date_str):
    """Convert date string to SQL format"""
    if pd.isna(date_str) or date_str is None or date_str == '':
        return 'NULL'
    
    try:
        # Handle ISO format dates
        if 'T' in str(date_str):
            dt = datetime.fromisoformat(str(date_str).replace('Z', '+00:00'))
            return f"'{dt.strftime('%Y-%m-%d %H:%M:%S')}'"
        # Handle date-only format
        elif len(str(date_str)) == 10:
            return f"'{date_str}'"
        else:
            return 'NULL'
    except:
        return 'NULL'

def main():
    csv_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/scripts/lexml_full_corrected_collection_20250712_173918.csv"
    
    print("🔄 Converting corrected CSV to SQL migration script...")
    
    # Load CSV
    df = pd.read_csv(csv_file)
    print(f"📊 Loaded {len(df)} records from CSV")
    
    # Generate SQL migration script
    sql_content = f"""-- Production Database Migration - Corrected LexML Data
-- Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
-- Source: {csv_file}
-- Records: {len(df)}

-- ============================================================================
-- CREATE CORRECTED TABLE AND VIEW
-- ============================================================================

-- Drop existing corrected table if exists
DROP TABLE IF EXISTS lexml_documents_corrected CASCADE;

-- Create corrected documents table
CREATE TABLE lexml_documents_corrected (
    id SERIAL PRIMARY KEY,
    search_term TEXT,
    date_searched TIMESTAMP,
    url TEXT,
    title TEXT,
    urn TEXT UNIQUE,
    urn_type TEXT,
    country TEXT,
    state TEXT,
    municipality TEXT,
    justice TEXT,
    region TEXT,
    court_class TEXT,
    document_type_full TEXT,
    enacting_date DATE,
    document_description TEXT,
    document_summary TEXT,
    source_type TEXT,
    document_number TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create performance indexes
CREATE INDEX IF NOT EXISTS idx_corrected_urn ON lexml_documents_corrected(urn);
CREATE INDEX IF NOT EXISTS idx_corrected_type ON lexml_documents_corrected(urn_type);
CREATE INDEX IF NOT EXISTS idx_corrected_date ON lexml_documents_corrected(enacting_date);
CREATE INDEX IF NOT EXISTS idx_corrected_search ON lexml_documents_corrected(search_term);
CREATE INDEX IF NOT EXISTS idx_corrected_state ON lexml_documents_corrected(state, country);

-- Create view for R Shiny compatibility (fixes production error)
CREATE OR REPLACE VIEW lexml_parsed_enhanced_fixed AS
SELECT 
    id,
    search_term,
    date_searched,
    url,
    title,
    urn,
    urn_type,
    country,
    state,
    municipality,
    justice,
    region,
    court_class,
    document_type_full,
    enacting_date as promulgation_date,
    document_description,
    document_summary,
    created_at,
    updated_at
FROM lexml_documents_corrected;

-- ============================================================================
-- INSERT CORRECTED DATA
-- ============================================================================

"""
    
    # Generate insert statements in batches
    batch_size = 50
    total_batches = (len(df) + batch_size - 1) // batch_size
    
    for batch_num in range(total_batches):
        start_idx = batch_num * batch_size
        end_idx = min((batch_num + 1) * batch_size, len(df))
        batch_df = df.iloc[start_idx:end_idx]
        
        sql_content += f"\n-- Batch {batch_num + 1}: Records {start_idx + 1}-{end_idx}\n"
        
        for _, row in batch_df.iterrows():
            # Prepare values with proper escaping
            values = [
                sanitize_sql_value(row.get('search_term')),
                convert_date(row.get('date_searched')),
                sanitize_sql_value(row.get('url')),
                sanitize_sql_value(row.get('title')),
                sanitize_sql_value(row.get('urn')),
                sanitize_sql_value(row.get('urn_type')),
                sanitize_sql_value(row.get('country')),
                sanitize_sql_value(row.get('state')),
                sanitize_sql_value(row.get('municipality')),
                sanitize_sql_value(row.get('justice')),
                sanitize_sql_value(row.get('region')),
                sanitize_sql_value(row.get('court_class')),
                sanitize_sql_value(row.get('document_type_full')),
                convert_date(row.get('enacting_date')),
                sanitize_sql_value(row.get('document_description')),
                sanitize_sql_value(row.get('document_summary')),
                'NULL',  # source_type
                'NULL'   # document_number
            ]
            
            sql_content += f"INSERT INTO lexml_documents_corrected (search_term, date_searched, url, title, urn, urn_type, country, state, municipality, justice, region, court_class, document_type_full, enacting_date, document_description, document_summary, source_type, document_number) VALUES ({', '.join(values)});\n"
    
    # Add validation queries
    sql_content += f"""

-- ============================================================================
-- VALIDATION QUERIES
-- ============================================================================

-- Check total count
SELECT 'Total records' as metric, COUNT(*) as value FROM lexml_documents_corrected;

-- Check date extraction rate
SELECT 
    'Date extraction rate' as metric, 
    ROUND((COUNT(CASE WHEN enacting_date IS NOT NULL THEN 1 END) * 100.0 / COUNT(*)), 1) || '%' as value
FROM lexml_documents_corrected;

-- Check document type distribution
SELECT 
    urn_type,
    COUNT(*) as count,
    ROUND((COUNT(*) * 100.0 / (SELECT COUNT(*) FROM lexml_documents_corrected)), 1) || '%' as percentage
FROM lexml_documents_corrected
GROUP BY urn_type
ORDER BY count DESC;

-- Test the view (fixes production error)
SELECT 'View accessibility' as metric, COUNT(*) as value FROM lexml_parsed_enhanced_fixed;

-- Show date range
SELECT 
    'Date range' as metric,
    MIN(enacting_date) || ' to ' || MAX(enacting_date) as value
FROM lexml_documents_corrected
WHERE enacting_date IS NOT NULL;

"""
    
    # Write SQL file
    output_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/implementation/production_migration_corrected.sql"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(sql_content)
    
    print(f"✅ SQL migration script generated: {output_file}")
    print(f"📊 {len(df)} records converted to SQL insert statements")
    print(f"🔧 Creates lexml_documents_corrected table with proper indexes")
    print(f"👁️ Creates lexml_parsed_enhanced_fixed view for R Shiny compatibility")
    print(f"✅ Fixes production error: 'relation lexml_parsed_enhanced_fixed does not exist'")
    
    # Show quick stats
    date_count = df['enacting_date'].notna().sum()
    date_rate = (date_count / len(df)) * 100
    type_dist = df['urn_type'].value_counts()
    
    print(f"\n📈 Data Quality Summary:")
    print(f"  • Total documents: {len(df):,}")
    print(f"  • Date extraction: {date_rate:.1f}% ({date_count:,}/{len(df):,})")
    print(f"  • Document types:")
    for doc_type, count in type_dist.head(3).items():
        pct = (count / len(df)) * 100
        print(f"    - {doc_type}: {count:,} ({pct:.1f}%)")

if __name__ == "__main__":
    main()