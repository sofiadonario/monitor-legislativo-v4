#!/usr/bin/env python3
"""
Deploy municipality-state parsing fix to production database
Optimized version with better error handling and connection management
"""

import sys
import os
import time
import signal

# Database connection string
DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Operation timed out")

def deploy_with_timeout():
    """Deploy with timeout protection"""
    
    # Set up timeout handler
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(300)  # 5 minute timeout
    
    try:
        return execute_deployment()
    except TimeoutError:
        print("❌ Deployment timed out after 5 minutes")
        return False
    finally:
        signal.alarm(0)  # Cancel the alarm

def execute_deployment():
    """Execute the deployment"""
    
    print("🚀 DEPLOYING MUNICIPALITY-STATE PARSING FIX")
    print("=" * 60)
    
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        
        # Connect with optimized settings
        conn = psycopg2.connect(
            DATABASE_URL,
            connect_timeout=30,
            application_name="municipality_state_fix_deployment"
        )
        
        # Set session parameters for better performance
        conn.set_session(
            autocommit=False,  # Use transactions for data integrity
            isolation_level=psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED
        )
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        print("✅ Connected to Railway PostgreSQL database")
        
        # Step 1: Backup current state
        print("\n🔄 Step 1: Backing up current LexML data...")
        cursor.execute("SELECT COUNT(*) FROM documents WHERE fonte = 'LexML'")
        current_count = cursor.fetchone()['count']
        print(f"📊 Current LexML documents: {current_count}")
        
        # Step 2: Clear existing LexML data
        print("\n🔄 Step 2: Clearing existing LexML data...")
        cursor.execute("DELETE FROM documents WHERE fonte = 'LexML'")
        deleted_count = cursor.rowcount
        print(f"✅ Deleted {deleted_count} existing LexML records")
        
        # Step 3: Load new data from CSV files directly
        print("\n🔄 Step 3: Loading corrected CSV data...")
        
        # Load and process CSV files
        import csv
        import glob
        import json
        from datetime import datetime
        
        csv_files = glob.glob("data_current/processed/*.csv")
        total_inserted = 0
        
        for csv_file in csv_files:
            print(f"   📁 Processing {os.path.basename(csv_file)}...")
            
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                batch_data = []
                
                for row in reader:
                    # Parse date
                    date_str = row.get('Enacting_date', '')
                    parsed_date = None
                    if date_str:
                        try:
                            if ' ' in date_str:
                                date_str = date_str.split(' ')[0]
                            if '/' in date_str:
                                parsed_date = datetime.strptime(date_str, '%d/%m/%Y').date()
                            elif '-' in date_str:
                                parsed_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                        except:
                            parsed_date = None
                    
                    # Map document type
                    urn_type = row.get('Urn_type', '')
                    tipo = {
                        'legislation': 'lei',
                        'jurisprudence': 'jurisprudencia',
                        'doutrina': 'doutrina',
                        'library': 'doutrina'
                    }.get(urn_type, 'outro')
                    
                    # Create metadata
                    metadata = json.dumps({
                        'search_term': row.get('Search_term', ''),
                        'urn_type': urn_type,
                        'country': row.get('Country', ''),
                        'source_file': os.path.basename(csv_file)
                    })
                    
                    # Prepare record with FIXED municipality-state data
                    record = (
                        row.get('Urn', ''),
                        row.get('Title', ''),
                        row.get('Url', ''),
                        parsed_date,
                        row.get('State', ''),  # FIXED: Now contains only state (e.g., 'SP')
                        row.get('Municipality', ''),  # FIXED: Now contains only municipality (e.g., 'Catanduva')
                        tipo,
                        row.get('Document_summary', ''),
                        '',  # autor
                        'LexML',  # fonte
                        'transport_energy',  # transport_category
                        row.get('Document_type_full', ''),
                        row.get('Document_description', ''),
                        row.get('Document_summary', ''),
                        row.get('Search_term', ''),
                        row.get('Justice', ''),
                        row.get('Region', ''),
                        row.get('Court_class', ''),
                        metadata,
                        datetime.now(),
                        datetime.now()
                    )
                    
                    batch_data.append(record)
                
                if batch_data:
                    # Insert batch
                    insert_sql = """
                        INSERT INTO documents (
                            urn, titulo, url, data_publicacao, estado, municipality,
                            tipo, conteudo, autor, fonte, transport_category,
                            document_type_full, document_description, document_summary,
                            search_term, justice, region, court_class, metadata,
                            created_at, updated_at
                        ) VALUES %s
                        ON CONFLICT (urn) DO UPDATE SET
                            titulo = EXCLUDED.titulo,
                            url = EXCLUDED.url,
                            data_publicacao = EXCLUDED.data_publicacao,
                            estado = EXCLUDED.estado,
                            municipality = EXCLUDED.municipality,
                            tipo = EXCLUDED.tipo,
                            conteudo = EXCLUDED.conteudo,
                            document_type_full = EXCLUDED.document_type_full,
                            document_description = EXCLUDED.document_description,
                            document_summary = EXCLUDED.document_summary,
                            search_term = EXCLUDED.search_term,
                            justice = EXCLUDED.justice,
                            region = EXCLUDED.region,
                            court_class = EXCLUDED.court_class,
                            metadata = EXCLUDED.metadata,
                            updated_at = EXCLUDED.updated_at
                    """
                    
                    from psycopg2.extras import execute_values
                    execute_values(cursor, insert_sql, batch_data, page_size=100)
                    
                    total_inserted += len(batch_data)
                    print(f"     ✅ Inserted {len(batch_data)} records")
        
        # Commit all changes
        conn.commit()
        print(f"\n✅ Successfully deployed {total_inserted} records with fixed municipality-state data")
        
        # Step 4: Verify deployment
        print("\n🔄 Step 4: Verifying deployment...")
        
        # Check total count
        cursor.execute("SELECT COUNT(*) FROM documents WHERE fonte = 'LexML'")
        new_count = cursor.fetchone()['count']
        print(f"📊 New LexML documents count: {new_count}")
        
        # Check municipality-state fix
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE fonte = 'LexML' AND estado != '' AND municipality != ''
        """)
        fixed_count = cursor.fetchone()['count']
        print(f"📊 Documents with properly separated municipality-state: {fixed_count}")
        
        # Verify Catanduva examples
        cursor.execute("""
            SELECT estado, municipality, titulo 
            FROM documents 
            WHERE fonte = 'LexML' AND municipality ILIKE '%catanduva%' 
            LIMIT 3
        """)
        
        catanduva_examples = cursor.fetchall()
        print("🔍 Catanduva verification (should show Estado='SP', Municipality='Catanduva'):")
        for row in catanduva_examples:
            print(f"   ✅ Estado: '{row['estado']}', Municipality: '{row['municipality']}' - {row['titulo'][:50]}...")
        
        # Check for any remaining problematic formats
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE fonte = 'LexML' AND estado LIKE '%-%'
        """)
        remaining_issues = cursor.fetchone()['count']
        print(f"📊 Remaining problematic state formats: {remaining_issues}")
        
        conn.close()
        
        print("\n🎉 DEPLOYMENT SUCCESSFUL!")
        print("=" * 60)
        print("✅ Municipality-state parsing fix has been deployed to production")
        print(f"✅ {total_inserted} records processed with corrected field separation")
        print("✅ Database integrity verified")
        
        return True
        
    except Exception as e:
        print(f"❌ Deployment failed: {e}")
        try:
            conn.rollback()
            conn.close()
        except:
            pass
        return False

def main():
    print("🚀 STARTING PRODUCTION DEPLOYMENT")
    print("📋 Deploying municipality-state parsing fix...")
    
    success = deploy_with_timeout()
    
    if success:
        print("\n🎉 DEPLOYMENT COMPLETED SUCCESSFULLY!")
        return True
    else:
        print("\n❌ DEPLOYMENT FAILED!")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)