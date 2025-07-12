#!/usr/bin/env python3
"""
Re-import CSV with ALL fields properly mapped
Update the database with complete CSV data including missing fields
"""

import pandas as pd
import sys
from datetime import datetime

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
    
    print("🔄 Re-importing CSV with ALL fields...")
    
    # Load CSV
    df = pd.read_csv(csv_file)
    print(f"📊 Loaded {len(df)} records from CSV")
    print(f"📋 CSV columns: {list(df.columns)}")
    
    # Generate SQL update script
    sql_content = f"""-- Complete CSV Re-import with ALL Fields
-- Update lexml_documents_corrected table with missing CSV fields

-- First, add the missing columns if they don't exist
ALTER TABLE lexml_documents_corrected 
ADD COLUMN IF NOT EXISTS locality TEXT,
ADD COLUMN IF NOT EXISTS authority TEXT,
ADD COLUMN IF NOT EXISTS authority_level TEXT;

-- Update existing records with missing field data
"""
    
    # Generate update statements for each record
    for _, row in df.iterrows():
        urn = sanitize_sql_value(row.get('urn')).strip("'")
        locality = sanitize_sql_value(row.get('locality'))
        authority = sanitize_sql_value(row.get('authority'))
        authority_level = sanitize_sql_value(row.get('authority_level'))
        state = sanitize_sql_value(row.get('state'))
        municipality = sanitize_sql_value(row.get('municipality'))
        
        sql_content += f"""UPDATE lexml_documents_corrected SET 
    locality = {locality},
    authority = {authority},
    authority_level = {authority_level},
    state = COALESCE({state}, state),
    municipality = COALESCE({municipality}, municipality)
WHERE urn = '{urn}';
"""
    
    # Add comprehensive documents table update
    sql_content += """

-- Now update documents table with complete mapping
UPDATE documents SET
    -- Geographic data with proper locality mapping
    estado = COALESCE(
        ldc.locality,
        ldc.state,
        CASE 
            WHEN ldc.authority LIKE '%São Paulo%' OR ldc.authority LIKE '%SP%' THEN 'São Paulo'
            WHEN ldc.authority LIKE '%Rio de Janeiro%' OR ldc.authority LIKE '%RJ%' THEN 'Rio de Janeiro'
            WHEN ldc.authority LIKE '%Minas Gerais%' OR ldc.authority LIKE '%MG%' THEN 'Minas Gerais'
            WHEN ldc.authority LIKE '%Rio Grande do Sul%' OR ldc.authority LIKE '%RS%' THEN 'Rio Grande do Sul'
            WHEN ldc.authority LIKE '%Bahia%' OR ldc.authority LIKE '%BA%' THEN 'Bahia'
            WHEN ldc.authority LIKE '%Paraná%' OR ldc.authority LIKE '%PR%' THEN 'Paraná'
            WHEN ldc.authority LIKE '%Santa Catarina%' OR ldc.authority LIKE '%SC%' THEN 'Santa Catarina'
            WHEN ldc.authority LIKE '%Distrito Federal%' OR ldc.authority LIKE '%DF%' THEN 'Distrito Federal'
            WHEN ldc.authority LIKE '%Federal%' OR ldc.authority LIKE '%Congresso%' OR ldc.authority LIKE '%Senado%' THEN 'Federal'
            ELSE 'Federal'
        END
    ),
    
    municipality = ldc.municipality,
    locality = ldc.locality,
    authority = ldc.authority,
    authority_level = ldc.authority_level,
    autor = COALESCE(ldc.authority, ldc.document_type_full, documents.autor),
    
    -- Update metadata with ALL CSV fields
    metadata = jsonb_build_object(
        'search_term', ldc.search_term,
        'date_searched', ldc.date_searched,
        'country', ldc.country,
        'state', ldc.state,
        'municipality', ldc.municipality,
        'locality', ldc.locality,
        'justice', ldc.justice,
        'region', ldc.region,
        'court_class', ldc.court_class,
        'document_type_full', ldc.document_type_full,
        'authority', ldc.authority,
        'authority_level', ldc.authority_level,
        'source_type', 'complete_csv_mapping',
        'geographic_level', CASE 
            WHEN ldc.municipality IS NOT NULL AND ldc.municipality != '' THEN 'municipal'
            WHEN ldc.locality IS NOT NULL AND ldc.locality != '' THEN 'state'
            WHEN ldc.justice IS NOT NULL AND ldc.justice != '' THEN 'judicial'
            ELSE 'federal'
        END,
        'all_csv_fields_mapped', true
    )
FROM lexml_documents_corrected ldc
WHERE documents.urn = ldc.urn;

-- Final verification with ALL fields
SELECT 'COMPLETE CSV MAPPING VERIFICATION' as status;

SELECT 
    'Total documents' as metric,
    COUNT(*) as count
FROM documents;

SELECT 
    'Documents with locality' as metric,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE locality IS NOT NULL AND locality != '';

SELECT 
    'Documents with authority' as metric,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE authority IS NOT NULL AND authority != '';

SELECT 
    'Documents with municipalities' as metric,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE municipality IS NOT NULL AND municipality != '';

-- Authority distribution
SELECT 'Authority distribution (top 10)' as status;
SELECT authority, COUNT(*) as count 
FROM documents 
WHERE authority IS NOT NULL AND authority != ''
GROUP BY authority 
ORDER BY count DESC 
LIMIT 10;

-- Locality distribution  
SELECT 'Locality/State distribution' as status;
SELECT locality, COUNT(*) as count 
FROM documents 
WHERE locality IS NOT NULL AND locality != ''
GROUP BY locality 
ORDER BY count DESC 
LIMIT 10;

COMMIT;
"""
    
    # Write update script
    output_file = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/implementation/reimport_complete_csv.sql"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(sql_content)
    
    print(f"✅ Complete CSV re-import script generated: {output_file}")
    print(f"📊 Will update all {len(df)} records with missing fields")
    print(f"🔧 Includes: locality, authority, authority_level, state, municipality")
    print(f"🎯 Target: Complete CSV field mapping for all documents")

if __name__ == "__main__":
    main()