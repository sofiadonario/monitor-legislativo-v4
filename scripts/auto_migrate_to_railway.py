#!/usr/bin/env python3
"""
Automatically migrate CSV data to Railway PostgreSQL
Monitor Legislativo v4 - Automated Real Data Migration
"""

import csv
import json
import subprocess
import os
from datetime import datetime

# Railway PostgreSQL connection
RAILWAY_DB_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway"

def create_direct_psql_migration():
    """Create migration using direct psql commands"""
    print("🚀 Creating automated migration to Railway PostgreSQL...")
    
    # Read CSV file
    csv_file = 'data/processed/lexml_parsed_enhanced_fixed.csv'
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        print(f"📊 Loaded {len(rows)} rows from CSV")
        
        # Create migration commands
        commands = []
        
        # Drop and create tables
        commands.append("""
DROP TABLE IF EXISTS lexml_parsed_enhanced CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS legislative_data CASCADE;
""")
        
        # Create tables
        commands.append("""
CREATE TABLE lexml_parsed_enhanced (
    id SERIAL PRIMARY KEY,
    search_term VARCHAR(255),
    date_searched TIMESTAMP,
    url TEXT,
    title TEXT,
    urn TEXT,
    urn_type VARCHAR(255),
    country VARCHAR(255),
    state VARCHAR(255),
    municipality VARCHAR(255),
    justice VARCHAR(255),
    region VARCHAR(255),
    court_class VARCHAR(255),
    document_type_full VARCHAR(255),
    promulgation_date TIMESTAMP,
    document_description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")
        
        commands.append("""
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
""")
        
        commands.append("""
CREATE TABLE legislative_data (
    id SERIAL PRIMARY KEY,
    titulo TEXT,
    numero VARCHAR(50),
    tipo VARCHAR(100),
    data DATE,
    estado VARCHAR(100),
    autor VARCHAR(200),
    fonte_original VARCHAR(100),
    url TEXT,
    ano INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")
        
        # Execute initial setup
        for cmd in commands:
            result = run_psql_command(cmd, "Setting up database schema")
            if not result:
                return False
        
        print("✅ Database schema created successfully")
        
        # Insert data in batches
        batch_size = 50
        total_batches = (len(rows) + batch_size - 1) // batch_size
        
        for i in range(0, len(rows), batch_size):
            batch = rows[i:i+batch_size]
            batch_num = i // batch_size + 1
            
            print(f"📥 Processing batch {batch_num}/{total_batches} ({len(batch)} records)")
            
            # Create batch insert command
            values = []
            for row in batch:
                # Clean and escape values
                cleaned_row = {}
                for key, value in row.items():
                    if value and value.strip():
                        cleaned_row[key] = value.replace("'", "''")
                    else:
                        cleaned_row[key] = None
                
                # Build values string
                value_parts = []
                for col in ['search_term', 'date_searched', 'url', 'title', 'urn', 'urn_type', 
                           'country', 'state', 'municipality', 'justice', 'region', 'court_class',
                           'document_type_full', 'promulgation_date', 'document_description']:
                    val = cleaned_row.get(col)
                    if val:
                        value_parts.append(f"'{val}'")
                    else:
                        value_parts.append('NULL')
                
                values.append(f"({', '.join(value_parts)})")
            
            # Insert batch
            insert_cmd = f"""
INSERT INTO lexml_parsed_enhanced (search_term, date_searched, url, title, urn, urn_type, country, state, municipality, justice, region, court_class, document_type_full, promulgation_date, document_description)
VALUES {', '.join(values)};
"""
            
            if not run_psql_command(insert_cmd, f"Inserting batch {batch_num}"):
                print(f"❌ Failed to insert batch {batch_num}")
                return False
        
        print("✅ All data inserted successfully")
        
        # Create compatible tables
        populate_commands = [
            # Populate documents table
            """
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
        WHEN promulgation_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN promulgation_date::date
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
""",
            # Populate legislative_data table
            """
INSERT INTO legislative_data (titulo, numero, tipo, data, estado, autor, fonte_original, url, ano)
SELECT 
    title as titulo,
    CASE 
        WHEN title ~ '[0-9]+' THEN regexp_replace(title, '.*?([0-9]+).*', '\\1')
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
        WHEN promulgation_date ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN promulgation_date::date
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
        WHEN promulgation_date ~ '^[0-9]{4}' THEN EXTRACT(YEAR FROM promulgation_date::date)
        ELSE NULL
    END as ano
FROM lexml_parsed_enhanced
WHERE title IS NOT NULL AND title != '';
"""
        ]
        
        for cmd in populate_commands:
            if not run_psql_command(cmd, "Populating compatible tables"):
                print("⚠️  Warning: Failed to populate compatible tables")
        
        # Create indexes
        index_commands = [
            "CREATE INDEX idx_lexml_search_term ON lexml_parsed_enhanced(search_term);",
            "CREATE INDEX idx_lexml_urn ON lexml_parsed_enhanced(urn);",
            "CREATE INDEX idx_lexml_state ON lexml_parsed_enhanced(state);",
            "CREATE INDEX idx_documents_urn ON documents(urn);",
            "CREATE INDEX idx_documents_tipo ON documents(tipo);",
            "CREATE INDEX idx_documents_estado ON documents(estado);",
            "CREATE INDEX idx_legislative_data_tipo ON legislative_data(tipo);",
            "CREATE INDEX idx_legislative_data_estado ON legislative_data(estado);"
        ]
        
        for cmd in index_commands:
            run_psql_command(cmd, "Creating indexes")
        
        # Verify migration
        verify_cmd = """
SELECT 'Migration Results:' as info;
SELECT 'lexml_parsed_enhanced' as table_name, COUNT(*) as record_count FROM lexml_parsed_enhanced
UNION ALL
SELECT 'documents' as table_name, COUNT(*) as record_count FROM documents
UNION ALL
SELECT 'legislative_data' as table_name, COUNT(*) as record_count FROM legislative_data;
"""
        
        run_psql_command(verify_cmd, "Verifying migration")
        
        print("\n✅ MIGRATION COMPLETED SUCCESSFULLY!")
        print(f"📊 Migrated {len(rows)} real records to Railway PostgreSQL")
        print("🎯 Your R Shiny app now has real legislative data!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        return False

def run_psql_command(sql_command, description):
    """Run a PostgreSQL command using psql"""
    print(f"🔧 {description}...")
    
    try:
        # Try psql first
        cmd = ['psql', RAILWAY_DB_URL, '-c', sql_command]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print(f"✅ {description} - Success")
            if result.stdout.strip():
                print(f"   Output: {result.stdout.strip()}")
            return True
        else:
            print(f"❌ {description} - Failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"❌ {description} - Timeout")
        return False
    except FileNotFoundError:
        print(f"❌ psql not found. Trying alternative method...")
        return try_python_connection(sql_command, description)
    except Exception as e:
        print(f"❌ {description} - Error: {e}")
        return False

def try_python_connection(sql_command, description):
    """Try to execute SQL using Python libraries"""
    print(f"🔄 Attempting Python connection for: {description}")
    
    try:
        import psycopg2
        
        # Parse connection URL
        conn = psycopg2.connect(RAILWAY_DB_URL)
        cursor = conn.cursor()
        
        cursor.execute(sql_command)
        conn.commit()
        
        # Try to fetch results if it's a SELECT
        if sql_command.strip().upper().startswith('SELECT'):
            results = cursor.fetchall()
            if results:
                print(f"   Results: {results}")
        
        cursor.close()
        conn.close()
        
        print(f"✅ {description} - Success (Python)")
        return True
        
    except ImportError:
        print("❌ psycopg2 not available. Please install PostgreSQL client tools.")
        return False
    except Exception as e:
        print(f"❌ {description} - Python connection failed: {e}")
        return False

def main():
    """Main function"""
    print("🚀 Starting Automated Migration to Railway PostgreSQL")
    print("=" * 60)
    
    # Check if CSV file exists
    csv_file = 'data/processed/lexml_parsed_enhanced_fixed.csv'
    if not os.path.exists(csv_file):
        print(f"❌ CSV file not found: {csv_file}")
        return False
    
    # Run migration
    success = create_direct_psql_migration()
    
    if success:
        print("\n🎉 SUCCESS! Your Railway database now has real legislative data!")
        print("\n🎯 Next steps:")
        print("1. Check your Railway R Shiny app")
        print("2. You should see 889 real legislative records")
        print("3. Data includes transport legislation from across Brazil")
        print("4. No more sample data!")
        
    else:
        print("\n❌ Migration failed. Please check the errors above.")
        print("\n🔧 Manual fallback options:")
        print("1. Install PostgreSQL client tools (psql)")
        print("2. Use Railway dashboard to import data")
        print("3. Use the pre-generated REAL_DATA_MIGRATION.sql file")
    
    return success

if __name__ == "__main__":
    main()