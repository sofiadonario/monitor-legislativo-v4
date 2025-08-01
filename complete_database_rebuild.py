#!/usr/bin/env python3
"""
COMPLETE DATABASE REBUILD SCRIPT
This script handles the complete database cleanup and rebuild process
"""

import psycopg2
import pandas as pd
from psycopg2.extras import RealDictCursor, execute_values
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
        logging.FileHandler('./data_current/processed/complete_rebuild.log'),
        logging.StreamHandler()
    ]
)

def execute_sql_file(conn, file_path: str, description: str = "SQL script"):
    """Execute a SQL file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        with conn.cursor() as cur:
            cur.execute(sql_content)
            conn.commit()
            logging.info(f"✅ {description} executed successfully")
            return True
    except Exception as e:
        logging.error(f"❌ {description} failed: {e}")
        conn.rollback()
        return False

def main():
    """Complete database rebuild process"""
    print("🚀 STARTING COMPLETE DATABASE REBUILD")
    print("="*80)
    
    try:
        # Connect to database
        conn = psycopg2.connect(DB_URL)
        conn.autocommit = False
        logging.info("✅ Connected to PostgreSQL database")
        
        # Step 1: Complete cleanup
        logging.info("🧹 Step 1: Complete database cleanup...")
        if not execute_sql_file(conn, "./clean_database_completely.sql", "Database cleanup"):
            return
        
        # Step 2: Create new schema
        logging.info("🏗️ Step 2: Creating new database schema...")
        schema_sql = """
        -- =============================================================================
        -- CREATE OPTIMIZED SCHEMA FOR CATEGORIZED DATA
        -- =============================================================================
        
        -- Create categories lookup table
        CREATE TABLE document_categories (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Insert known categories
        INSERT INTO document_categories (name, description) VALUES
        ('Jurisprudência', 'Court decisions, case law, and judicial precedents'),
        ('Legislação', 'Laws, decrees, ordinances, and regulatory texts'),
        ('Doutrina', 'Legal doctrine, academic writings, and scholarly articles'),
        ('Outros', 'Other types of legal documents'),
        ('Proposições', 'Legislative proposals, bills, and draft legislation'),
        ('geral', 'General legal documents');
        
        -- Create transport modes lookup table
        CREATE TABLE transport_modes (
            id SERIAL PRIMARY KEY,
            name VARCHAR(50) UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Insert known transport modes
        INSERT INTO transport_modes (name, description) VALUES
        ('Geral', 'General transport or not transport-specific'),
        ('Rodoviário', 'Road transport related documents'),
        ('Aéreo', 'Aviation and air transport related documents'),
        ('Marítimo', 'Maritime and water transport related documents'),
        ('Ferroviário', 'Railway and rail transport related documents');
        
        -- Create jurisdictions lookup table
        CREATE TABLE jurisdictions (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) UNIQUE NOT NULL,
            type VARCHAR(20) CHECK (type IN ('Federal', 'State', 'Municipal', 'Distrital')),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Insert known jurisdictions
        INSERT INTO jurisdictions (name, type) VALUES
        ('Federal', 'Federal'),
        ('Municipal', 'Municipal'),
        ('State', 'State'),
        ('Distrital', 'Distrital');
        
        -- Create main documents table with optimized structure
        CREATE TABLE documents (
            id SERIAL PRIMARY KEY,
            
            -- Core document identification
            titulo TEXT NOT NULL,
            urn VARCHAR(500),
            url TEXT,
            numero VARCHAR(200),
            
            -- Content and metadata
            ementa TEXT,
            assuntos TEXT,
            autor VARCHAR(500),
            tipo VARCHAR(200),
            
            -- Dates
            data DATE,
            data_publicacao DATE,
            data_coleta DATE,
            ano INTEGER,
            
            -- Classification (using lookup tables)
            category_id INTEGER REFERENCES document_categories(id),
            transport_mode_id INTEGER REFERENCES transport_modes(id),
            jurisdiction_id INTEGER REFERENCES jurisdictions(id),
            
            -- Original category fields (for reference)
            categoria_original VARCHAR(200),
            modal_original VARCHAR(200),
            jurisdicao_original VARCHAR(200),
            
            -- Geographic information
            pais VARCHAR(100),
            estado VARCHAR(100),
            municipio VARCHAR(200),
            localidade VARCHAR(300),
            
            -- Additional metadata
            classificacao TEXT,
            autoridade VARCHAR(300),
            fontes_localizacao TEXT,
            termo_busca VARCHAR(200),
            origem VARCHAR(200),
            
            -- Deduplication metadata
            deduplication_source VARCHAR(20) DEFAULT 'single',
            original_count INTEGER DEFAULT 1,
            merged_categories INTEGER,
            merged_transport INTEGER,
            source_file VARCHAR(500),
            
            -- Extracted categories (from fixed processing)
            extracted_category VARCHAR(200),
            extracted_transport_mode VARCHAR(200),
            
            -- Audit fields
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        with conn.cursor() as cur:
            cur.execute(schema_sql)
            conn.commit()
            logging.info("✅ Database schema created successfully")
        
        # Step 3: Create indexes
        logging.info("📊 Step 3: Creating performance indexes...")
        indexes_sql = """
        -- Primary indexes for fast lookups
        CREATE INDEX idx_documents_category ON documents(category_id);
        CREATE INDEX idx_documents_transport ON documents(transport_mode_id);
        CREATE INDEX idx_documents_jurisdiction ON documents(jurisdiction_id);
        CREATE INDEX idx_documents_estado ON documents(estado);
        CREATE INDEX idx_documents_ano ON documents(ano);
        CREATE INDEX idx_documents_data ON documents(data);
        
        -- Text search indexes
        CREATE INDEX idx_documents_titulo ON documents USING gin(to_tsvector('portuguese', titulo));
        CREATE INDEX idx_documents_ementa ON documents USING gin(to_tsvector('portuguese', ementa));
        
        -- Unique constraint for URN when not null
        CREATE UNIQUE INDEX idx_documents_urn_unique ON documents(urn) WHERE urn IS NOT NULL AND urn != '';
        
        -- Composite indexes for dashboard queries
        CREATE INDEX idx_documents_category_estado ON documents(category_id, estado);
        CREATE INDEX idx_documents_transport_estado ON documents(transport_mode_id, estado);
        CREATE INDEX idx_documents_ano_category ON documents(ano, category_id);
        """
        
        with conn.cursor() as cur:
            cur.execute(indexes_sql)
            conn.commit()
            logging.info("✅ Indexes created successfully")
        
        # Step 4: Load and insert data
        logging.info("📄 Step 4: Loading categorized dataset...")
        data_file = "./data_current/processed/deduplicated/lexml_unified_deduplicated_FIXED.csv"
        
        if not Path(data_file).exists():
            logging.error(f"❌ Categorized dataset not found: {data_file}")
            return
        
        df = pd.read_csv(data_file, encoding='utf-8', low_memory=False)
        logging.info(f"✅ Loaded dataset: {len(df):,} rows")
        
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
        
        logging.info("🔧 Step 5: Preparing data for insertion...")
        
        # Prepare data in smaller batches
        batch_size = 5000
        total_inserted = 0
        
        for start_idx in range(0, len(df), batch_size):
            end_idx = min(start_idx + batch_size, len(df))
            batch_df = df.iloc[start_idx:end_idx]
            
            batch_data = []
            for _, row in batch_df.iterrows():
                try:
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
                    
                    # Handle dates safely
                    def safe_date(date_val):
                        if pd.isna(date_val):
                            return None
                        try:
                            return pd.to_datetime(date_val).date()
                        except:
                            return None
                    
                    # Handle integers safely
                    def safe_int(int_val):
                        if pd.isna(int_val):
                            return None
                        try:
                            val = int(int_val)
                            return val if 1500 <= val <= 2030 else None  # Sanity check for years
                        except:
                            return None
                    
                    # Safe string extraction
                    def safe_str(val, max_len=None):
                        if pd.isna(val):
                            return None
                        result = str(val).strip()
                        if not result:
                            return None
                        if max_len and len(result) > max_len:
                            result = result[:max_len]
                        return result
                    
                    # Skip if no title
                    titulo = safe_str(row.get('titulo'))
                    if not titulo:
                        continue
                    
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
                
                with conn.cursor() as cur:
                    execute_values(cur, insert_sql, batch_data, page_size=1000)
                    conn.commit()
                    total_inserted += len(batch_data)
                    logging.info(f"   Inserted batch: {total_inserted:,}/{len(df):,} rows...")
        
        logging.info(f"✅ Successfully inserted {total_inserted:,} documents")
        
        # Step 6: Create views
        logging.info("🎯 Step 6: Creating dashboard views...")
        views_sql = """
        -- Main dashboard summary view
        CREATE OR REPLACE VIEW lexml_dashboard_view AS
        SELECT 
            d.id,
            d.titulo,
            d.urn,
            d.url,
            d.ementa,
            d.data,
            d.ano,
            d.estado,
            d.municipio,
            dc.name as categoria,
            tm.name as modal,
            j.name as jurisdicao,
            d.extracted_category,
            d.extracted_transport_mode,
            d.deduplication_source,
            d.original_count
        FROM documents d
        LEFT JOIN document_categories dc ON d.category_id = dc.id
        LEFT JOIN transport_modes tm ON d.transport_mode_id = tm.id
        LEFT JOIN jurisdictions j ON d.jurisdiction_id = j.id;
        
        -- Documents by category view
        CREATE OR REPLACE VIEW documents_by_category AS
        SELECT 
            dc.name as categoria,
            dc.description,
            COUNT(*) as total_documents,
            COUNT(DISTINCT d.estado) as states_covered,
            MIN(d.ano) as earliest_year,
            MAX(d.ano) as latest_year,
            ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
        FROM documents d
        LEFT JOIN document_categories dc ON d.category_id = dc.id
        GROUP BY dc.id, dc.name, dc.description
        ORDER BY total_documents DESC;
        
        -- Dashboard metrics view
        CREATE OR REPLACE VIEW dashboard_metrics AS
        SELECT 
            (SELECT COUNT(*) FROM documents) as total_documents,
            (SELECT COUNT(DISTINCT estado) FROM documents WHERE estado IS NOT NULL AND estado != '' AND estado != 'Federal') as states_with_documents,
            (SELECT COUNT(DISTINCT category_id) FROM documents WHERE category_id IS NOT NULL) as total_categories,
            (SELECT COUNT(DISTINCT transport_mode_id) FROM documents WHERE transport_mode_id IS NOT NULL) as total_transport_modes,
            (SELECT MIN(ano) FROM documents WHERE ano IS NOT NULL) as earliest_year,
            (SELECT MAX(ano) FROM documents WHERE ano IS NOT NULL) as latest_year,
            (SELECT COUNT(*) FROM documents WHERE deduplication_source = 'merged') as merged_documents,
            (SELECT COUNT(*) FROM documents WHERE deduplication_source = 'single') as single_documents,
            CURRENT_TIMESTAMP as last_updated;
        """
        
        with conn.cursor() as cur:
            cur.execute(views_sql)
            conn.commit()
            logging.info("✅ Dashboard views created successfully")
        
        # Step 7: Verification
        logging.info("🔍 Step 7: Verifying database population...")
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get basic stats
            cur.execute("SELECT * FROM dashboard_metrics")
            metrics = cur.fetchone()
            
            # Get category distribution
            cur.execute("SELECT * FROM documents_by_category ORDER BY total_documents DESC")
            categories = cur.fetchall()
            
            logging.info("📊 DATABASE POPULATION VERIFICATION:")
            logging.info(f"   Total documents: {metrics['total_documents']:,}")
            logging.info(f"   States with documents: {metrics['states_with_documents']}")
            logging.info(f"   Categories: {metrics['total_categories']}")
            logging.info(f"   Transport modes: {metrics['total_transport_modes']}")
            logging.info(f"   Year range: {metrics['earliest_year']}-{metrics['latest_year']}")
            
            logging.info("   Category distribution:")
            for cat in categories:
                if cat['categoria']:
                    logging.info(f"      {cat['categoria']}: {cat['total_documents']:,} ({cat['percentage']:.1f}%)")
        
        conn.close()
        logging.info("✅ Database connection closed")
        
        print("🎉 DATABASE REBUILD COMPLETED SUCCESSFULLY!")
        print(f"📊 Populated with {total_inserted:,} categorized documents")
        print("🚀 Database is ready for dashboard integration!")
        
    except Exception as e:
        logging.error(f"❌ Critical error: {e}")
        raise

if __name__ == "__main__":
    main()