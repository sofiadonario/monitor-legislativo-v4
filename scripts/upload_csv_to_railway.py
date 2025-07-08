#!/usr/bin/env python3
"""
Upload CSV to Railway PostgreSQL using HTTP/Web interface
Monitor Legislativo v4 - Web-based CSV Upload
"""

import json
import os
import base64
from datetime import datetime

def create_railway_upload_instructions():
    """Create instructions for Railway web upload"""
    print("📋 Creating Railway Web Upload Instructions...")
    
    csv_file = 'data/processed/lexml_parsed_enhanced_fixed.csv'
    
    if not os.path.exists(csv_file):
        print(f"❌ CSV file not found: {csv_file}")
        return False
    
    # Read CSV file
    with open(csv_file, 'r', encoding='utf-8') as f:
        csv_content = f.read()
    
    # Get file stats
    file_size = os.path.getsize(csv_file)
    line_count = len(csv_content.splitlines())
    
    print(f"📊 CSV file stats:")
    print(f"   Size: {file_size:,} bytes")
    print(f"   Lines: {line_count:,}")
    print(f"   Records: {line_count - 1:,} (excluding header)")
    
    # Create upload instructions
    instructions = f"""
# Railway Web Upload Instructions

## File Information
- **File**: {csv_file}
- **Size**: {file_size:,} bytes
- **Records**: {line_count - 1:,} legislative documents

## Upload Steps

### 1. Railway Dashboard Upload
1. Go to: https://railway.app/dashboard
2. Select your project: **Monitor Legislativo v4**
3. Click on **PostgreSQL** service
4. Go to **Data** or **Files** tab
5. Navigate to directory: `/var/lib/postgresql/data/`
6. Upload file: `{csv_file}`
7. Ensure filename is: `lexml_parsed_enhanced_fixed.csv`

### 2. Execute SQL Import
1. In PostgreSQL service, go to **Query** tab
2. Copy and paste this SQL command:

```sql
-- Test if file exists
SELECT pg_read_file('/var/lib/postgresql/data/lexml_parsed_enhanced_fixed.csv', 0, 1000);
```

3. If file exists, run the full import from `railway_csv_import.sql`

### 3. Verify Success
Run this query to check results:
```sql
SELECT COUNT(*) FROM lexml_parsed_enhanced;
SELECT COUNT(*) FROM documents;
SELECT COUNT(*) FROM legislative_data;
```

## Alternative: Copy-Paste Method

If file upload doesn't work, you can create the file manually:

1. In PostgreSQL **Query** tab, run:
```sql
-- Create temporary table for manual data entry
CREATE TEMP TABLE csv_data (content TEXT);
INSERT INTO csv_data VALUES ('paste_csv_content_here');
```

2. Then process the data with custom SQL commands.

## File Content Preview (first 5 lines):
```
{csv_content.splitlines()[0]}
{csv_content.splitlines()[1] if len(csv_content.splitlines()) > 1 else ''}
{csv_content.splitlines()[2] if len(csv_content.splitlines()) > 2 else ''}
{csv_content.splitlines()[3] if len(csv_content.splitlines()) > 3 else ''}
{csv_content.splitlines()[4] if len(csv_content.splitlines()) > 4 else ''}
```

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
    
    # Write instructions
    with open('railway_upload_instructions.txt', 'w', encoding='utf-8') as f:
        f.write(instructions)
    
    print("✅ Upload instructions created: railway_upload_instructions.txt")
    return True

def create_sql_with_embedded_data():
    """Create SQL file with embedded CSV data for copy-paste"""
    print("🔧 Creating SQL with embedded CSV data...")
    
    csv_file = 'data/processed/lexml_parsed_enhanced_fixed.csv'
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Remove header
        data_lines = lines[1:]  # Skip header
        
        print(f"📊 Processing {len(data_lines)} data lines...")
        
        # Create SQL with embedded INSERT statements
        sql_content = """
-- Monitor Legislativo v4 - SQL with Embedded Data
-- Generated with CSV data embedded as INSERT statements

-- Drop and create tables
DROP TABLE IF EXISTS lexml_parsed_enhanced CASCADE;
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS legislative_data CASCADE;

-- Create main table
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
    promulgation_date VARCHAR(255),
    document_description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert data (batch of 50)
"""
        
        # Process in batches
        batch_size = 50
        for i in range(0, len(data_lines), batch_size):
            batch = data_lines[i:i+batch_size]
            
            sql_content += f"\n-- Batch {i//batch_size + 1}: Records {i+1}-{min(i+batch_size, len(data_lines))}\n"
            
            for line in batch:
                # Parse CSV line
                fields = line.strip().split(',')
                if len(fields) >= 15:  # Ensure we have all fields
                    # Escape single quotes and format for SQL
                    escaped_fields = []
                    for field in fields:
                        if field and field.strip():
                            escaped_field = field.strip().replace("'", "''").replace('"', '')
                            escaped_fields.append(f"'{escaped_field}'")
                        else:
                            escaped_fields.append('NULL')
                    
                    sql_content += f"INSERT INTO lexml_parsed_enhanced (search_term, date_searched, url, title, urn, urn_type, country, state, municipality, justice, region, court_class, document_type_full, promulgation_date, document_description) VALUES ({', '.join(escaped_fields)});\n"
        
        # Add the rest of the import logic
        sql_content += """
-- Create compatible tables (same as railway_csv_import.sql)
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

-- Populate documents table
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
    'LexML' as fonte,
    url,
    json_build_object('search_term', search_term, 'urn_type', urn_type) as metadata,
    CASE 
        WHEN search_term LIKE '%transporte%' THEN 'transporte'
        WHEN search_term LIKE '%logística%' THEN 'logistica'
        WHEN search_term LIKE '%carga%' THEN 'carga'
        ELSE 'outros'
    END as transport_category
FROM lexml_parsed_enhanced
WHERE urn IS NOT NULL AND urn != ''
ON CONFLICT (urn) DO NOTHING;

-- Verification
SELECT 'Import completed!' as status;
SELECT COUNT(*) FROM lexml_parsed_enhanced;
SELECT COUNT(*) FROM documents;
"""
        
        # Write SQL file
        with open('railway_import_embedded.sql', 'w', encoding='utf-8') as f:
            f.write(sql_content)
        
        print("✅ SQL with embedded data created: railway_import_embedded.sql")
        print(f"📊 Contains {len(data_lines)} INSERT statements")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating embedded SQL: {e}")
        return False

def main():
    """Main function"""
    print("🚀 Creating Railway Upload Solutions")
    print("=" * 50)
    
    # Create upload instructions
    create_railway_upload_instructions()
    
    # Create SQL with embedded data as backup
    create_sql_with_embedded_data()
    
    print("\n✅ Created multiple upload solutions:")
    print("📋 1. railway_upload_instructions.txt - Web upload guide")
    print("📋 2. railway_import_embedded.sql - SQL with embedded data")
    print("📋 3. railway_csv_import.sql - Original CSV import")
    
    print("\n🎯 Choose your method:")
    print("   Method 1: Upload CSV file via Railway dashboard")
    print("   Method 2: Copy-paste SQL with embedded data")
    print("   Method 3: Manual entry (if other methods fail)")
    
    return True

if __name__ == "__main__":
    main()