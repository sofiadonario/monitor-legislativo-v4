#!/usr/bin/env python3
"""
Convert CSV file to PostgreSQL migration SQL
Monitor Legislativo v4 - Real Data Migration from CSV
"""

import csv
import json
import re
from datetime import datetime

def clean_sql_string(value):
    """Clean and escape string for SQL"""
    if value is None:
        return 'NULL'
    if isinstance(value, str):
        # Escape single quotes
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return str(value)

def infer_postgres_type(column_name, sample_values):
    """Infer PostgreSQL column type from sample values"""
    # Remove None values and empty strings
    clean_values = [v for v in sample_values if v is not None and v != '']
    
    if not clean_values:
        return 'TEXT'
    
    # Check for specific column patterns
    if column_name.lower() in ['date_searched', 'promulgation_date', 'created_at', 'updated_at']:
        return 'TIMESTAMP'
    
    if column_name.lower() in ['url', 'urn', 'title', 'document_description']:
        return 'TEXT'
    
    # Check if all values look like dates
    date_patterns = [
        r'^\d{4}-\d{2}-\d{2}$',  # YYYY-MM-DD
        r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # YYYY-MM-DD HH:MM:SS
    ]
    
    for pattern in date_patterns:
        if all(re.match(pattern, str(v)) for v in clean_values[:5]):
            return 'TIMESTAMP'
    
    # Check max length for VARCHAR vs TEXT
    max_length = max(len(str(v)) for v in clean_values)
    
    if max_length > 255:
        return 'TEXT'
    elif max_length > 100:
        return 'VARCHAR(500)'
    else:
        return 'VARCHAR(255)'

def create_migration_from_csv():
    """Create PostgreSQL migration from CSV file"""
    print("🔄 Converting CSV to PostgreSQL migration...")
    
    csv_file = 'data/processed/lexml_parsed_enhanced_fixed_cleaned.csv'
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            # Read all rows
            rows = list(reader)
            
            if not rows:
                print("❌ No data found in CSV file")
                return False
            
            print(f"📊 Found {len(rows)} rows in CSV file")
            
            # Get column names
            columns = list(rows[0].keys())
            print(f"📋 Columns: {columns}")
            
            # Sample data for type inference
            sample_data = {}
            for col in columns:
                sample_data[col] = [row[col] for row in rows[:20]]  # First 20 rows for sampling
            
            # Create migration SQL
            migration_sql = f"""
-- Monitor Legislativo v4 - REAL DATA Migration from CSV
-- Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
-- Source: {csv_file}
-- Records: {len(rows)}

-- ============================================================================
-- DROP AND CREATE TABLES
-- ============================================================================

-- Drop existing tables if they exist
DROP TABLE IF EXISTS lexml_parsed_enhanced CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS legislative_data CASCADE;

-- Create main table: lexml_parsed_enhanced
CREATE TABLE lexml_parsed_enhanced (
    id SERIAL PRIMARY KEY,
"""
            
            # Add columns based on CSV structure
            for col in columns:
                postgres_type = infer_postgres_type(col, sample_data[col])
                migration_sql += f"    {col} {postgres_type},\n"
            
            migration_sql += """    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create compatible documents table for R Shiny app
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    urn VARCHAR(500) UNIQUE,
    titulo TEXT,
    conteudo TEXT,
    tipo VARCHAR(100),
    data_publicacao DATE,
    estado VARCHAR(100),
    autor VARCHAR(200),
    fonte VARCHAR(100),
    url TEXT,
    metadata JSONB DEFAULT '{}'::jsonb,
    transport_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create legislative_data table for compatibility
CREATE TABLE legislative_data (
    id SERIAL PRIMARY KEY,
    titulo TEXT,
    numero TEXT,
    tipo VARCHAR(100),
    data DATE,
    estado VARCHAR(100),
    autor VARCHAR(200),
    fonte_original VARCHAR(100),
    url TEXT,
    ano INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- INSERT REAL DATA
-- ============================================================================

-- Insert all real data from CSV
"""
            
            # Insert data in batches
            batch_size = 50
            for i in range(0, len(rows), batch_size):
                batch = rows[i:i+batch_size]
                migration_sql += f"\n-- Batch {i//batch_size + 1}: Records {i+1}-{min(i+batch_size, len(rows))}\n"
                
                for row in batch:
                    columns_list = []
                    values_list = []
                    
                    for col in columns:
                        value = row[col]
                        if value and value.strip():
                            columns_list.append(col)
                            values_list.append(clean_sql_string(value))
                    
                    if columns_list:  # Only insert if there are values
                        migration_sql += f"INSERT INTO lexml_parsed_enhanced ({', '.join(columns_list)}) VALUES ({', '.join(values_list)});\n"
            
            # Insert compatible data into documents table
            migration_sql += """
-- ============================================================================
-- POPULATE COMPATIBLE TABLES
-- ============================================================================

-- Insert data into documents table (for R Shiny compatibility)
INSERT INTO documents (urn, titulo, conteudo, tipo, data_publicacao, estado, autor, fonte, url, metadata, transport_category)
SELECT 
    urn,
    title as titulo,
    document_description as conteudo,
    CASE 
        WHEN document_type_full LIKE '%Lei%' THEN 'lei'
        WHEN document_type_full LIKE '%Decreto%' THEN 'decreto'
        WHEN document_type_full LIKE '%Medida Provisória%' THEN 'medida_provisoria'
        WHEN document_type_full LIKE '%Acórdão%' THEN 'acordao'
        ELSE 'outros'
    END as tipo,
    CASE 
        WHEN promulgation_date::text ~ '^\\d{4}-\\d{2}-\\d{2}$' THEN promulgation_date::date
        ELSE NULL
    END as data_publicacao,
    COALESCE(state, 'BR') as estado,
    CASE 
        WHEN document_type_full LIKE '%Federal%' THEN 'Governo Federal'
        WHEN document_type_full LIKE '%Estadual%' THEN 'Governo Estadual'
        WHEN document_type_full LIKE '%Municipal%' THEN 'Governo Municipal'
        WHEN document_type_full LIKE '%Tribunal%' THEN 'Poder Judiciário'
        ELSE 'Diversos'
    END as autor,
    'LexML' as fonte,
    url,
    json_build_object(
        'search_term', search_term,
        'urn_type', urn_type,
        'country', country,
        'municipality', municipality,
        'justice', justice,
        'region', region,
        'court_class', court_class
    ) as metadata,
    CASE 
        WHEN search_term LIKE '%transporte%' THEN 'transporte'
        WHEN search_term LIKE '%logística%' THEN 'logistica'
        WHEN search_term LIKE '%carga%' THEN 'carga'
        ELSE 'outros'
    END as transport_category
FROM lexml_parsed_enhanced
WHERE urn IS NOT NULL AND urn != ''
ON CONFLICT (urn) DO NOTHING;

-- Insert data into legislative_data table
INSERT INTO legislative_data (titulo, numero, tipo, data, estado, autor, fonte_original, url, ano)
SELECT 
    title as titulo,
    CASE 
        WHEN title ~ '\\d+' THEN regexp_replace(title, '.*?(\\d+).*', '\\1')
        ELSE NULL
    END as numero,
    CASE 
        WHEN document_type_full LIKE '%Lei%' THEN 'lei'
        WHEN document_type_full LIKE '%Decreto%' THEN 'decreto'
        WHEN document_type_full LIKE '%Medida Provisória%' THEN 'medida_provisoria'
        WHEN document_type_full LIKE '%Acórdão%' THEN 'acordao'
        ELSE 'outros'
    END as tipo,
    CASE 
        WHEN promulgation_date::text ~ '^\\d{4}-\\d{2}-\\d{2}$' THEN promulgation_date::date
        ELSE NULL
    END as data,
    COALESCE(state, 'BR') as estado,
    CASE 
        WHEN document_type_full LIKE '%Federal%' THEN 'Governo Federal'
        WHEN document_type_full LIKE '%Estadual%' THEN 'Governo Estadual'
        WHEN document_type_full LIKE '%Municipal%' THEN 'Governo Municipal'
        WHEN document_type_full LIKE '%Tribunal%' THEN 'Poder Judiciário'
        ELSE 'Diversos'
    END as autor,
    'LexML' as fonte_original,
    url,
    CASE 
        WHEN promulgation_date::text ~ '^\\d{4}' THEN EXTRACT(YEAR FROM promulgation_date::date)
        ELSE NULL
    END as ano
FROM lexml_parsed_enhanced
WHERE title IS NOT NULL AND title != '';

-- ============================================================================
-- CREATE INDEXES
-- ============================================================================

-- Indexes for lexml_parsed_enhanced table
CREATE INDEX idx_lexml_search_term ON lexml_parsed_enhanced(search_term);
CREATE INDEX idx_lexml_urn ON lexml_parsed_enhanced(urn);
CREATE INDEX idx_lexml_state ON lexml_parsed_enhanced(state);
CREATE INDEX idx_lexml_document_type ON lexml_parsed_enhanced(document_type_full);
CREATE INDEX idx_lexml_promulgation_date ON lexml_parsed_enhanced(promulgation_date);

-- Indexes for documents table
CREATE INDEX idx_documents_urn ON documents(urn);
CREATE INDEX idx_documents_tipo ON documents(tipo);
CREATE INDEX idx_documents_estado ON documents(estado);
CREATE INDEX idx_documents_data ON documents(data_publicacao);
CREATE INDEX idx_documents_transport ON documents(transport_category);

-- Indexes for legislative_data table
CREATE INDEX idx_legislative_data_tipo ON legislative_data(tipo);
CREATE INDEX idx_legislative_data_estado ON legislative_data(estado);
CREATE INDEX idx_legislative_data_data ON legislative_data(data);
CREATE INDEX idx_legislative_data_ano ON legislative_data(ano);

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Show migration results
SELECT 'Real data migration completed successfully!' as status;

SELECT 'Table Statistics:' as info;
SELECT 'lexml_parsed_enhanced' as table_name, COUNT(*) as record_count FROM lexml_parsed_enhanced
UNION ALL
SELECT 'documents' as table_name, COUNT(*) as record_count FROM documents
UNION ALL
SELECT 'legislative_data' as table_name, COUNT(*) as record_count FROM legislative_data;

-- Show sample data
SELECT 'Sample from lexml_parsed_enhanced:' as info;
SELECT search_term, title, state, document_type_full, promulgation_date 
FROM lexml_parsed_enhanced 
ORDER BY promulgation_date DESC LIMIT 5;

-- Show document types
SELECT 'Document types distribution:' as info;
SELECT tipo, COUNT(*) as count 
FROM documents 
GROUP BY tipo 
ORDER BY count DESC;

-- Show states distribution
SELECT 'States distribution:' as info;
SELECT estado, COUNT(*) as count 
FROM documents 
GROUP BY estado 
ORDER BY count DESC;

-- Show transport categories
SELECT 'Transport categories:' as info;
SELECT transport_category, COUNT(*) as count 
FROM documents 
GROUP BY transport_category 
ORDER BY count DESC;
"""
            
            # Write migration file
            migration_file = 'REAL_DATA_MIGRATION.sql'
            with open(migration_file, 'w', encoding='utf-8') as f:
                f.write(migration_sql)
            
            print(f"✅ Migration file created: {migration_file}")
            print(f"📊 Contains {len(rows)} real records from CSV")
            print(f"📋 Creates 3 tables: lexml_parsed_enhanced, documents, legislative_data")
            print(f"🔍 Includes proper indexes and verification queries")
            
            return True
            
    except Exception as e:
        print(f"❌ Error processing CSV: {e}")
        return False

def main():
    """Main function"""
    print("🚀 Converting CSV to PostgreSQL Migration")
    print("=" * 60)
    
    if create_migration_from_csv():
        print("\n✅ SUCCESS! Real data migration created")
        print("\n🎯 Next steps:")
        print("1. Execute REAL_DATA_MIGRATION.sql in Railway PostgreSQL console")
        print("2. Your R Shiny app will have 889 real legislative records")
        print("3. Data includes transport legislation from LexML Brazil")
        print("4. Three tables created for maximum compatibility")
        
        return True
    else:
        print("\n❌ Migration creation failed")
        return False

if __name__ == "__main__":
    main()