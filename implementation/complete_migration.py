#!/usr/bin/env python3
"""
Complete the full migration by inserting remaining records
Resume from where the previous migration stopped
"""

import pandas as pd
import sys
import os
from datetime import datetime

def main():
    csv_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/scripts/lexml_full_corrected_collection_20250712_173918.csv"
    database_url = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"
    
    print("🔄 Completing full migration...")
    
    # Load CSV to check total count
    df = pd.read_csv(csv_file)
    total_records = len(df)
    print(f"📊 Total records in CSV: {total_records}")
    
    # Create a simple completion script that skips existing URNs
    completion_sql = f"""-- Complete Migration Script
-- Resume migration by inserting remaining records

-- Check current count
SELECT 'Current count' as status, COUNT(*) as records FROM lexml_documents_corrected;

-- Insert remaining records (using INSERT ON CONFLICT DO NOTHING to skip existing)
"""
    
    # Generate insert statements for remaining records (starting from record 507)
    batch_size = 100
    start_from = 506  # We have 506 records already
    
    for batch_num in range(start_from // batch_size, (total_records + batch_size - 1) // batch_size):
        start_idx = batch_num * batch_size
        end_idx = min((batch_num + 1) * batch_size, total_records)
        batch_df = df.iloc[start_idx:end_idx]
        
        completion_sql += f"\n-- Batch {batch_num + 1}: Records {start_idx + 1}-{end_idx}\n"
        
        for _, row in batch_df.iterrows():
            # Sanitize values
            def sanitize_sql_value(value):
                if pd.isna(value) or value is None or value == '':
                    return 'NULL'
                str_value = str(value).replace("'", "''")
                return f"'{str_value}'"
            
            def convert_date(date_str):
                if pd.isna(date_str) or date_str is None or date_str == '':
                    return 'NULL'
                try:
                    if 'T' in str(date_str):
                        dt = datetime.fromisoformat(str(date_str).replace('Z', '+00:00'))
                        return f"'{dt.strftime('%Y-%m-%d %H:%M:%S')}'"
                    elif len(str(date_str)) == 10:
                        return f"'{date_str}'"
                    else:
                        return 'NULL'
                except:
                    return 'NULL'
            
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
            
            completion_sql += f"INSERT INTO lexml_documents_corrected (search_term, date_searched, url, title, urn, urn_type, country, state, municipality, justice, region, court_class, document_type_full, enacting_date, document_description, document_summary, source_type, document_number) VALUES ({', '.join(values)}) ON CONFLICT (urn) DO NOTHING;\n"
    
    # Add final verification
    completion_sql += f"""

-- ============================================================================
-- FINAL VERIFICATION
-- ============================================================================

-- Check final count
SELECT 'Final count' as status, COUNT(*) as records FROM lexml_documents_corrected;

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

-- Verify the view works
SELECT 'View accessibility' as metric, COUNT(*) as value FROM lexml_parsed_enhanced_fixed;

COMMIT;
"""
    
    # Write completion script
    output_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/implementation/complete_migration.sql"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(completion_sql)
    
    print(f"✅ Completion script generated: {output_file}")
    print(f"📊 Will insert remaining {total_records - 506} records")
    print(f"🔧 Uses ON CONFLICT DO NOTHING to avoid duplicates")
    print(f"🎯 Target: {total_records} total records with 100% date extraction")

if __name__ == "__main__":
    main()