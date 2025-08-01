#!/usr/bin/env python3
"""
POPULATE DATABASE WITH CATEGORIZED DATA
This script populates the rebuilt database with the fixed categorized dataset
"""

import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
import logging
from datetime import datetime
import numpy as np
from pathlib import Path

# Database connection
DB_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('./data_current/processed/database_population.log'),
        logging.StreamHandler()
    ]
)

class DatabasePopulator:
    def __init__(self, db_url: str):
        self.db_url = db_url
        self.conn = None
        
    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(self.db_url)
            self.conn.autocommit = False
            logging.info("✅ Connected to PostgreSQL database")
            return True
        except Exception as e:
            logging.error(f"❌ Database connection failed: {e}")
            return False
    
    def execute_schema_script(self, script_path: str):
        """Execute the database schema creation script"""
        try:
            with open(script_path, 'r', encoding='utf-8') as f:
                schema_sql = f.read()
            
            with self.conn.cursor() as cur:
                cur.execute(schema_sql)
                self.conn.commit()
                logging.info("✅ Database schema created successfully")
                return True
        except Exception as e:
            logging.error(f"❌ Schema creation failed: {e}")
            self.conn.rollback()
            return False
    
    def get_lookup_ids(self):
        """Get lookup table mappings for foreign keys"""
        lookups = {
            'categories': {},
            'transport_modes': {},
            'jurisdictions': {}
        }
        
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Get categories
                cur.execute("SELECT id, name FROM document_categories")
                for row in cur.fetchall():
                    lookups['categories'][row['name']] = row['id']
                
                # Get transport modes
                cur.execute("SELECT id, name FROM transport_modes")
                for row in cur.fetchall():
                    lookups['transport_modes'][row['name']] = row['id']
                
                # Get jurisdictions
                cur.execute("SELECT id, name FROM jurisdictions")
                for row in cur.fetchall():
                    lookups['jurisdictions'][row['name']] = row['id']
                
                logging.info(f"✅ Loaded lookup tables: {len(lookups['categories'])} categories, {len(lookups['transport_modes'])} transport modes, {len(lookups['jurisdictions'])} jurisdictions")
                return lookups
        except Exception as e:
            logging.error(f"❌ Failed to load lookup tables: {e}")
            return None
    
    def clean_and_prepare_data(self, df: pd.DataFrame, lookups: dict):
        """Clean and prepare data for database insertion"""
        logging.info(f"🔧 Cleaning and preparing {len(df)} rows for database insertion...")
        
        prepared_data = []
        errors = []
        
        for idx, row in df.iterrows():
            try:
                # Handle dates
                data_date = None
                if pd.notna(row.get('data')):
                    try:
                        data_date = pd.to_datetime(row['data']).date()
                    except:
                        pass
                
                data_publicacao = None
                if pd.notna(row.get('data_publicacao')):
                    try:
                        data_publicacao = pd.to_datetime(row['data_publicacao']).date()
                    except:
                        pass
                
                data_coleta = None
                if pd.notna(row.get('data_coleta')):
                    try:
                        data_coleta = pd.to_datetime(row['data_coleta']).date()
                    except:
                        pass
                
                # Handle year
                ano = None
                if pd.notna(row.get('ano')):
                    try:
                        ano = int(row['ano'])
                        if ano < 1500 or ano > 2030:  # Sanity check
                            ano = None
                    except:
                        pass
                
                # Get foreign key IDs
                category_id = None
                if pd.notna(row.get('_extracted_category')):
                    category_name = str(row['_extracted_category']).strip()
                    category_id = lookups['categories'].get(category_name)
                
                transport_mode_id = None
                if pd.notna(row.get('_extracted_transport_mode')):
                    transport_name = str(row['_extracted_transport_mode']).strip()
                    transport_mode_id = lookups['transport_modes'].get(transport_name)
                
                jurisdiction_id = None
                if pd.notna(row.get('jurisdicao')):
                    jurisdiction_name = str(row['jurisdicao']).strip()
                    jurisdiction_id = lookups['jurisdictions'].get(jurisdiction_name)
                
                # Handle deduplication metadata
                original_count = 1
                if pd.notna(row.get('_original_count')):
                    try:
                        original_count = int(row['_original_count'])
                    except:
                        pass
                
                merged_categories = None
                if pd.notna(row.get('_merged_categories')):
                    try:
                        merged_categories = int(row['_merged_categories'])
                    except:
                        pass
                
                merged_transport = None
                if pd.notna(row.get('_merged_transport')):
                    try:
                        merged_transport = int(row['_merged_transport'])
                    except:
                        pass
                
                # Helper function to safely get string values
                def safe_str(value, max_length=None):
                    if pd.isna(value) or value is None:
                        return None
                    result = str(value).strip()
                    if not result:
                        return None
                    if max_length and len(result) > max_length:
                        result = result[:max_length]
                    return result
                
                # Prepare row data
                row_data = (
                    safe_str(row.get('titulo')),  # titulo - required
                    safe_str(row.get('urn'), 500),  # urn
                    safe_str(row.get('url')),  # url
                    safe_str(row.get('numero'), 200),  # numero
                    safe_str(row.get('ementa')),  # ementa
                    safe_str(row.get('assuntos')),  # assuntos
                    safe_str(row.get('autor'), 500),  # autor
                    safe_str(row.get('tipo'), 200),  # tipo
                    data_date,  # data
                    data_publicacao,  # data_publicacao
                    data_coleta,  # data_coleta
                    ano,  # ano
                    category_id,  # category_id
                    transport_mode_id,  # transport_mode_id
                    jurisdiction_id,  # jurisdiction_id
                    safe_str(row.get('categoria'), 200),  # categoria_original
                    safe_str(row.get('modal'), 200),  # modal_original
                    safe_str(row.get('jurisdicao'), 200),  # jurisdicao_original
                    safe_str(row.get('pais'), 100),  # pais
                    safe_str(row.get('estado'), 100),  # estado
                    safe_str(row.get('municipio'), 200),  # municipio
                    safe_str(row.get('localidade'), 300),  # localidade
                    safe_str(row.get('classificacao')),  # classificacao
                    safe_str(row.get('autoridade'), 300),  # autoridade
                    safe_str(row.get('fontes_localizacao')),  # fontes_localizacao
                    safe_str(row.get('termo_busca'), 200),  # termo_busca
                    safe_str(row.get('origem'), 200),  # origem
                    safe_str(row.get('_deduplication_source', 'single'), 20),  # deduplication_source
                    original_count,  # original_count
                    merged_categories,  # merged_categories
                    merged_transport,  # merged_transport
                    safe_str(row.get('_source_file'), 500),  # source_file
                    safe_str(row.get('_extracted_category'), 200),  # extracted_category
                    safe_str(row.get('_extracted_transport_mode'), 200)  # extracted_transport_mode
                )
                
                # Skip rows without title (required field)
                if not row_data[0]:
                    errors.append(f"Row {idx}: Missing title")
                    continue
                
                prepared_data.append(row_data)
                
            except Exception as e:
                errors.append(f"Row {idx}: {e}")
                continue
        
        logging.info(f"✅ Prepared {len(prepared_data)} rows for insertion")
        if errors:
            logging.warning(f"⚠️ {len(errors)} rows had errors and were skipped")
            for error in errors[:10]:  # Log first 10 errors
                logging.warning(f"   {error}")
        
        return prepared_data
    
    def insert_documents(self, prepared_data: list):
        """Insert documents into database using batch processing"""
        if not prepared_data:
            logging.error("❌ No data to insert")
            return False
        
        insert_sql = """
        INSERT INTO documents (
            titulo, urn, url, numero, ementa, assuntos, autor, tipo,
            data, data_publicacao, data_coleta, ano,
            category_id, transport_mode_id, jurisdiction_id,
            categoria_original, modal_original, jurisdicao_original,
            pais, estado, municipio, localidade,
            classificacao, autoridade, fontes_localizacao, termo_busca, origem,
            deduplication_source, original_count, merged_categories, merged_transport,
            source_file, extracted_category, extracted_transport_mode
        ) VALUES %s
        """
        
        try:
            with self.conn.cursor() as cur:
                logging.info(f"🚀 Inserting {len(prepared_data)} documents in batches...")
                
                # Insert in batches of 1000
                batch_size = 1000
                total_inserted = 0
                
                for i in range(0, len(prepared_data), batch_size):
                    batch = prepared_data[i:i + batch_size]
                    execute_values(cur, insert_sql, batch, page_size=batch_size)
                    total_inserted += len(batch)
                    
                    if i % 5000 == 0:  # Log progress every 5000 rows
                        logging.info(f"   Inserted {total_inserted}/{len(prepared_data)} rows...")
                
                self.conn.commit()
                logging.info(f"✅ Successfully inserted {total_inserted} documents")
                return True
                
        except Exception as e:
            logging.error(f"❌ Failed to insert documents: {e}")
            self.conn.rollback()
            return False
    
    def verify_insertion(self):
        """Verify the data was inserted correctly"""
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Get basic counts
                cur.execute("SELECT COUNT(*) as total FROM documents")
                total_docs = cur.fetchone()['total']
                
                # Get category distribution
                cur.execute("""
                    SELECT dc.name, COUNT(*) as count
                    FROM documents d
                    LEFT JOIN document_categories dc ON d.category_id = dc.id
                    GROUP BY dc.name
                    ORDER BY count DESC
                """)
                categories = cur.fetchall()
                
                # Get transport distribution
                cur.execute("""
                    SELECT tm.name, COUNT(*) as count
                    FROM documents d
                    LEFT JOIN transport_modes tm ON d.transport_mode_id = tm.id
                    GROUP BY tm.name
                    ORDER BY count DESC
                """)
                transport = cur.fetchall()
                
                # Get state distribution
                cur.execute("""
                    SELECT estado, COUNT(*) as count
                    FROM documents
                    WHERE estado IS NOT NULL AND estado != ''
                    GROUP BY estado
                    ORDER BY count DESC
                    LIMIT 10
                """)
                states = cur.fetchall()
                
                logging.info("📊 DATABASE POPULATION VERIFICATION:")
                logging.info(f"   Total documents: {total_docs:,}")
                logging.info("   Category distribution:")
                for cat in categories:
                    if cat['name']:
                        percentage = (cat['count'] / total_docs) * 100
                        logging.info(f"      {cat['name']}: {cat['count']:,} ({percentage:.1f}%)")
                
                logging.info("   Transport mode distribution:")
                for trans in transport:
                    if trans['name']:
                        percentage = (trans['count'] / total_docs) * 100
                        logging.info(f"      {trans['name']}: {trans['count']:,} ({percentage:.1f}%)")
                
                logging.info("   Top 10 states:")
                for state in states:
                    logging.info(f"      {state['estado']}: {state['count']:,}")
                
                return True
                
        except Exception as e:
            logging.error(f"❌ Verification failed: {e}")
            return False
    
    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logging.info("✅ Database connection closed")

def main():
    """Main execution function"""
    print("🚀 STARTING DATABASE POPULATION WITH CATEGORIZED DATA")
    print("="*80)
    
    # Initialize populator
    populator = DatabasePopulator(DB_URL)
    
    try:
        # Connect to database
        if not populator.connect():
            return
        
        # Execute schema creation script
        schema_script = "./rebuild_database_complete.sql"
        if not Path(schema_script).exists():
            logging.error(f"❌ Schema script not found: {schema_script}")
            return
        
        logging.info("🔧 Creating database schema...")
        if not populator.execute_schema_script(schema_script):
            return
        
        # Load lookup tables
        lookups = populator.get_lookup_ids()
        if not lookups:
            return
        
        # Load the fixed categorized dataset
        data_file = "./data_current/processed/deduplicated/lexml_unified_deduplicated_FIXED.csv"
        if not Path(data_file).exists():
            logging.error(f"❌ Categorized dataset not found: {data_file}")
            return
        
        logging.info(f"📄 Loading categorized dataset: {data_file}")
        df = pd.read_csv(data_file, encoding='utf-8', low_memory=False)
        logging.info(f"✅ Loaded dataset: {len(df):,} rows, {len(df.columns)} columns")
        
        # Clean and prepare data
        prepared_data = populator.clean_and_prepare_data(df, lookups)
        if not prepared_data:
            return
        
        # Insert documents
        if not populator.insert_documents(prepared_data):
            return
        
        # Verify insertion
        if not populator.verify_insertion():
            return
        
        print("✅ DATABASE POPULATION COMPLETED SUCCESSFULLY!")
        print(f"📊 Populated with {len(prepared_data):,} categorized documents")
        print("🎯 Database is ready for dashboard integration!")
        
    except Exception as e:
        logging.error(f"❌ Critical error: {e}")
        raise
    finally:
        populator.close()

if __name__ == "__main__":
    main()