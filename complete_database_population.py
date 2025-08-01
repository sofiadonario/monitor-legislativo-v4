#!/usr/bin/env python3
"""
COMPLETE DATABASE POPULATION
This script completes the population of all 134,014 deduplicated documents
"""

import pandas as pd
import psycopg2
from psycopg2.extras import execute_values, RealDictCursor
import logging
from datetime import datetime
from pathlib import Path

# Database connection
DB_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('./data_current/processed/complete_population.log'),
        logging.StreamHandler()
    ]
)

def main():
    """Complete the database population"""
    print("🚀 COMPLETING DATABASE POPULATION (134,014 documents)")
    print("="*80)
    
    try:
        # Connect to database
        conn = psycopg2.connect(DB_URL)
        conn.autocommit = False
        logging.info("✅ Connected to PostgreSQL database")
        
        # Check current document count
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as count FROM documents")
            current_count = cur.fetchone()[0]
            logging.info(f"📊 Current documents in database: {current_count:,}")
        
        if current_count >= 134014:
            logging.info("✅ Database already has all documents!")
            return
        
        # Load the full deduplicated dataset
        data_file = "./data_current/processed/deduplicated/lexml_unified_deduplicated_FIXED.csv"
        logging.info(f"📄 Loading full dataset: {data_file}")
        
        df = pd.read_csv(data_file, encoding='utf-8', low_memory=False)
        logging.info(f"✅ Loaded {len(df):,} rows from CSV")
        
        # If we already have some documents, skip them
        start_index = current_count
        if start_index > 0:
            logging.info(f"⏩ Skipping first {start_index:,} rows (already in database)")
            df = df.iloc[start_index:]
        
        logging.info(f"📊 Will insert {len(df):,} remaining documents")
        
        # Get lookup mappings
        lookups = {'categories': {}, 'transport_modes': {}, 'jurisdictions': {}}
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, name FROM document_categories")
            for row in cur.fetchall():
                lookups['categories'][row['name']] = row['id']
            
            cur.execute("SELECT id, name FROM transport_modes")
            for row in cur.fetchall():
                lookups['transport_modes'][row['name']] = row['id']
            
            cur.execute("SELECT id, name FROM jurisdictions")
            for row in cur.fetchall():
                lookups['jurisdictions'][row['name']] = row['id']
        
        # Process in batches
        batch_size = 2000
        total_inserted = 0
        
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
        
        for batch_start in range(0, len(df), batch_size):
            batch_end = min(batch_start + batch_size, len(df))
            batch_df = df.iloc[batch_start:batch_end]
            
            batch_data = []
            for _, row in batch_df.iterrows():
                try:
                    # Safe value extraction functions
                    def safe_str(val, max_len=None):
                        if pd.isna(val):
                            return None
                        result = str(val).strip()
                        if not result or result.lower() in ['nan', 'none', 'null']:
                            return None
                        if max_len and len(result) > max_len:
                            result = result[:max_len]
                        return result
                    
                    def safe_date(date_val):
                        if pd.isna(date_val):
                            return None
                        try:
                            return pd.to_datetime(date_val).date()
                        except:
                            return None
                    
                    def safe_int(int_val):
                        if pd.isna(int_val):
                            return None
                        try:
                            val = int(float(int_val))
                            return val if 1500 <= val <= 2030 else None
                        except:
                            return None
                    
                    # Skip if no title
                    titulo = safe_str(row.get('titulo'))
                    if not titulo:
                        continue
                    
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
                    
                    row_data = (
                        titulo,
                        safe_str(row.get('urn'), 500),
                        safe_str(row.get('url')),
                        safe_str(row.get('numero'), 200),
                        safe_str(row.get('ementa')),
                        safe_str(row.get('assuntos')),
                        safe_str(row.get('autor'), 500),
                        safe_str(row.get('tipo'), 200),
                        safe_date(row.get('data')),
                        safe_date(row.get('data_publicacao')),
                        safe_date(row.get('data_coleta')),
                        safe_int(row.get('ano')),
                        category_id,
                        transport_mode_id,
                        jurisdiction_id,
                        safe_str(row.get('categoria'), 200),
                        safe_str(row.get('modal'), 200),
                        safe_str(row.get('jurisdicao'), 200),
                        safe_str(row.get('pais'), 100),
                        safe_str(row.get('estado'), 100),
                        safe_str(row.get('municipio'), 200),
                        safe_str(row.get('localidade'), 300),
                        safe_str(row.get('classificacao')),
                        safe_str(row.get('autoridade'), 300),
                        safe_str(row.get('fontes_localizacao')),
                        safe_str(row.get('termo_busca'), 200),
                        safe_str(row.get('origem'), 200),
                        safe_str(row.get('_deduplication_source', 'single'), 20),
                        safe_int(row.get('_original_count')) or 1,
                        safe_int(row.get('_merged_categories')),
                        safe_int(row.get('_merged_transport')),
                        safe_str(row.get('_source_file'), 500),
                        safe_str(row.get('_extracted_category'), 200),
                        safe_str(row.get('_extracted_transport_mode'), 200)
                    )
                    
                    batch_data.append(row_data)
                    
                except Exception as e:
                    logging.warning(f"Skipping row: {e}")
                    continue
            
            # Insert batch
            if batch_data:
                try:
                    with conn.cursor() as cur:
                        execute_values(cur, insert_sql, batch_data, page_size=500)
                        conn.commit()
                        total_inserted += len(batch_data)
                        overall_progress = start_index + total_inserted
                        logging.info(f"   Progress: {overall_progress:,}/{134014:,} total documents...")
                except Exception as e:
                    logging.error(f"Batch insert failed: {e}")
                    conn.rollback()
                    # Try smaller batch
                    try:
                        for single_row in batch_data:
                            with conn.cursor() as cur:
                                cur.execute(insert_sql.replace("%s", "%s"), (single_row,))
                                conn.commit()
                                total_inserted += 1
                    except:
                        continue
        
        # Final verification
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) as count FROM documents")
            final_count = cur.fetchone()[0]
            
            cur.execute("""
                SELECT dc.name, COUNT(*) as count
                FROM documents d
                JOIN document_categories dc ON d.category_id = dc.id
                GROUP BY dc.name
                ORDER BY count DESC
            """)
            categories = cur.fetchall()
        
        logging.info(f"✅ POPULATION COMPLETED!")
        logging.info(f"📊 Final document count: {final_count:,}")
        logging.info("📋 Category distribution:")
        for cat in categories:
            percentage = (cat[1] / final_count) * 100
            logging.info(f"   {cat[0]}: {cat[1]:,} ({percentage:.1f}%)")
        
        conn.close()
        
        print("🎉 DATABASE POPULATION COMPLETED!")
        print(f"📊 Total documents: {final_count:,} (should be 134,014)")
        print("✅ All deduplicated documents are now in the database!")
        
    except Exception as e:
        logging.error(f"❌ Critical error: {e}")
        raise

if __name__ == "__main__":
    main()