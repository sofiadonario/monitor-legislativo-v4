#!/usr/bin/env python3
"""
RAILWAY POSTGRESQL BULK IMPORT SCRIPT
=====================================

This script imports the complete 134k+ document dataset from CSV into Railway PostgreSQL.
Optimized for large datasets with proper error handling and performance optimization.

Features:
- Railway PostgreSQL connection with SSL support
- Bulk COPY operations for maximum performance 
- Progress tracking and error handling
- Data validation and type conversion
- Automatic table creation with proper schema
- Memory-efficient streaming for large files

Usage:
    python railway_bulk_import.py [--test-connection] [--create-tables] [--import-data] [--all]
"""

import os
import sys
import csv
import logging
import psycopg2
import psycopg2.extras
from psycopg2 import sql
import argparse
from datetime import datetime
from pathlib import Path
import io

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('railway_import.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class RailwayBulkImporter:
    def __init__(self):
        """Initialize the Railway bulk importer with database connection."""
        self.connection = None
        self.cursor = None
        self.total_records = 0
        self.imported_records = 0
        self.errors = []
        
        # Railway connection parameters
        self.db_config = {
            'host': 'nozomi.proxy.rlwy.net',
            'port': 44844,
            'database': 'railway',
            'user': 'postgres',
            'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY',
            'sslmode': 'prefer'
        }
        
        # CSV file paths - prioritize largest datasets
        self.csv_files = [
            'data_current/processed/production/lexml_unified_dataset.csv',
            'data_current/processed/production/lexml_enhanced_simple.csv',
            'data_current/processed/archive/legacy_versions/deduplicated/lexml_unified_deduplicated_FIXED.csv'
        ]
    
    def connect_to_database(self):
        """Establish connection to Railway PostgreSQL database."""
        try:
            logger.info("🔄 Connecting to Railway PostgreSQL database...")
            
            self.connection = psycopg2.connect(**self.db_config)
            self.connection.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            self.cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Test connection
            self.cursor.execute("SELECT version(), current_setting('ssl') as ssl_status;")
            result = self.cursor.fetchone()
            
            logger.info("✅ Connected to Railway PostgreSQL successfully")
            logger.info(f"📊 PostgreSQL Version: {result['version'][:50]}")
            logger.info(f"🔒 SSL Status: {result['ssl_status']}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to connect to Railway PostgreSQL: {e}")
            return False
    
    def create_documents_table(self):
        """Create the main documents table with proper schema for the CSV data."""
        try:
            logger.info("🔄 Creating documents table...")
            
            # Drop existing table if it exists
            drop_table_sql = "DROP TABLE IF EXISTS documents CASCADE;"
            self.cursor.execute(drop_table_sql)
            logger.info("🗑️ Dropped existing documents table")
            
            # Create documents table with optimized schema
            create_table_sql = """
            CREATE TABLE documents (
                id SERIAL PRIMARY KEY,
                titulo TEXT NOT NULL,
                tipo VARCHAR(200),
                data DATE,
                urn TEXT UNIQUE,
                autor TEXT,
                assuntos TEXT,
                classificacao TEXT,
                jurisdicao VARCHAR(100),
                autoridade TEXT,
                ementa TEXT,
                url TEXT,
                localidade VARCHAR(300),
                numero VARCHAR(100),
                ano INTEGER,
                termo_busca VARCHAR(500),
                data_coleta TIMESTAMP,
                origem VARCHAR(200),
                categoria VARCHAR(100),
                modal VARCHAR(100),
                pais VARCHAR(100),
                estado VARCHAR(50),
                municipio VARCHAR(300),
                fontes_localizacao VARCHAR(500),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            
            self.cursor.execute(create_table_sql)
            logger.info("✅ Documents table created successfully")
            
            # Create indexes for performance
            indexes = [
                "CREATE INDEX idx_documents_titulo ON documents USING GIN (to_tsvector('portuguese', titulo));",
                "CREATE INDEX idx_documents_categoria ON documents(categoria);",
                "CREATE INDEX idx_documents_estado ON documents(estado);", 
                "CREATE INDEX idx_documents_data ON documents(data);",
                "CREATE INDEX idx_documents_jurisdicao ON documents(jurisdicao);",
                "CREATE INDEX idx_documents_modal ON documents(modal);",
                "CREATE INDEX idx_documents_termo_busca ON documents(termo_busca);",
                "CREATE INDEX idx_documents_ementa ON documents USING GIN (to_tsvector('portuguese', ementa));"
            ]
            
            for index_sql in indexes:
                try:
                    self.cursor.execute(index_sql)
                    logger.info(f"✅ Created index: {index_sql.split()[2]}")
                except Exception as e:
                    logger.warning(f"⚠️ Index creation failed: {e}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create documents table: {e}")
            return False
    
    def find_csv_file(self):
        """Find the largest available CSV file."""
        for csv_file in self.csv_files:
            full_path = Path(csv_file)
            if full_path.exists():
                size_mb = full_path.stat().st_size / (1024 * 1024)
                logger.info(f"📁 Found CSV file: {csv_file} ({size_mb:.1f} MB)")
                return str(full_path)
        
        # Fallback to sample file
        sample_file = 'data_current/processed/production/lexml_sample_for_railway.csv'
        if Path(sample_file).exists():
            logger.warning(f"⚠️ Using sample file: {sample_file}")
            return sample_file
            
        logger.error("❌ No CSV file found!")
        return None
    
    def validate_and_convert_row(self, row):
        """Validate and convert CSV row data to appropriate types."""
        try:
            # Convert empty strings to None for proper NULL handling
            for key, value in row.items():
                if value == '':
                    row[key] = None
            
            # Convert date fields
            if row.get('data'):
                try:
                    # Handle various date formats
                    date_str = row['data']
                    if len(date_str) == 10:  # YYYY-MM-DD
                        datetime.strptime(date_str, '%Y-%m-%d')
                    elif len(date_str) == 4:  # Just year
                        row['data'] = f"{date_str}-01-01"
                    else:
                        row['data'] = None
                except:
                    row['data'] = None
            
            # Convert ano to integer
            if row.get('ano'):
                try:
                    row['ano'] = int(row['ano'])
                except:
                    row['ano'] = None
            
            # Convert data_coleta to timestamp
            if row.get('data_coleta'):
                try:
                    # Handle timestamp format: 2025-07-22 00:37:06
                    datetime.strptime(row['data_coleta'], '%Y-%m-%d %H:%M:%S')
                except:
                    row['data_coleta'] = None
            
            # Ensure titulo is not empty (required field)
            if not row.get('titulo') or row['titulo'].strip() == '':
                return None
                
            return row
            
        except Exception as e:
            logger.warning(f"⚠️ Row validation failed: {e}")
            return None
    
    def bulk_import_csv(self, csv_file):
        """Import CSV data using efficient COPY operations."""
        try:
            logger.info(f"🔄 Starting bulk import from {csv_file}")
            
            # Count total rows first
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                self.total_records = sum(1 for _ in reader) 
                logger.info(f"📊 Total records to import: {self.total_records:,}")
            
            # Prepare COPY statement
            columns = [
                'titulo', 'tipo', 'data', 'urn', 'autor', 'assuntos', 'classificacao',
                'jurisdicao', 'autoridade', 'ementa', 'url', 'localidade', 'numero', 
                'ano', 'termo_busca', 'data_coleta', 'origem', 'categoria', 'modal',
                'pais', 'estado', 'municipio', 'fontes_localizacao'
            ]
            
            copy_sql = f"COPY documents ({', '.join(columns)}) FROM STDIN WITH CSV HEADER NULL ''"
            
            # Use StringIO for in-memory CSV processing
            csv_data = io.StringIO()
            
            # Process CSV file in chunks for memory efficiency
            chunk_size = 10000
            processed = 0
            
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                # Write header
                csv_data.write(','.join(columns) + '\n')
                
                rows_in_chunk = 0
                
                for row in reader:
                    validated_row = self.validate_and_convert_row(row)
                    if validated_row:
                        # Write row to in-memory CSV
                        row_values = []
                        for col in columns:
                            value = validated_row.get(col, '')
                            if value is None:
                                value = ''
                            # Escape CSV special characters
                            value = str(value).replace('"', '""')
                            if ',' in value or '"' in value or '\n' in value:
                                value = f'"{value}"'
                            row_values.append(value)
                        
                        csv_data.write(','.join(row_values) + '\n')
                        rows_in_chunk += 1
                        processed += 1
                        
                        # Process in chunks to manage memory
                        if rows_in_chunk >= chunk_size:
                            self._execute_copy(copy_sql, csv_data, rows_in_chunk)
                            csv_data = io.StringIO()
                            csv_data.write(','.join(columns) + '\n')
                            rows_in_chunk = 0
                            
                            if processed % 50000 == 0:
                                logger.info(f"📈 Processed {processed:,} records ({processed/self.total_records*100:.1f}%)")
                
                # Process remaining rows
                if rows_in_chunk > 0:
                    self._execute_copy(copy_sql, csv_data, rows_in_chunk)
            
            self.imported_records = processed
            logger.info(f"✅ Bulk import completed: {processed:,} records imported")
            
            # Verify import
            self.cursor.execute("SELECT COUNT(*) as count FROM documents;")
            count_result = self.cursor.fetchone()
            logger.info(f"📊 Documents in database: {count_result['count']:,}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Bulk import failed: {e}")
            return False
    
    def _execute_copy(self, copy_sql, csv_data, row_count):
        """Execute COPY operation with the CSV data."""
        try:
            csv_data.seek(0)
            self.cursor.copy_expert(copy_sql, csv_data)
            logger.debug(f"✅ Copied {row_count:,} rows")
            
        except Exception as e:
            logger.error(f"❌ COPY operation failed: {e}")
            raise
    
    def create_additional_tables(self):
        """Create additional support tables for the dashboard."""
        try:
            logger.info("🔄 Creating additional support tables...")
            
            # Document categories table
            categories_sql = """
            CREATE TABLE IF NOT EXISTS document_categories (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            self.cursor.execute(categories_sql)
            
            # Insert standard categories
            categories_data = [
                ('Legislação', 'Leis, decretos, portarias e outras normas jurídicas'),
                ('Jurisprudência', 'Decisões judiciais e acórdãos'),
                ('Doutrina', 'Artigos, livros e textos acadêmicos'),
                ('Proposições', 'Projetos de lei e outras proposições legislativas')
            ]
            
            for name, desc in categories_data:
                try:
                    self.cursor.execute(
                        "INSERT INTO document_categories (name, description) VALUES (%s, %s) ON CONFLICT (name) DO NOTHING;",
                        (name, desc)
                    )
                except:
                    pass
            
            logger.info("✅ Additional tables created successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create additional tables: {e}")
            return False
    
    def optimize_database(self):
        """Optimize database after bulk import."""
        try:
            logger.info("🔄 Optimizing database...")
            
            # Analyze tables for query planner
            self.cursor.execute("ANALYZE documents;")
            self.cursor.execute("ANALYZE document_categories;")
            
            # Update table statistics
            self.cursor.execute("VACUUM ANALYZE documents;")
            
            logger.info("✅ Database optimization completed")
            return True
            
        except Exception as e:
            logger.error(f"❌ Database optimization failed: {e}")
            return False
    
    def get_import_summary(self):
        """Get summary of the import operation."""
        try:
            self.cursor.execute("""
                SELECT 
                    COUNT(*) as total_documents,
                    COUNT(DISTINCT categoria) as categories,
                    COUNT(DISTINCT estado) as states,
                    COUNT(DISTINCT municipio) as municipalities,
                    MIN(data) as earliest_date,
                    MAX(data) as latest_date
                FROM documents 
                WHERE titulo IS NOT NULL;
            """)
            
            summary = self.cursor.fetchone()
            
            logger.info("📊 IMPORT SUMMARY:")
            logger.info(f"   Total Documents: {summary['total_documents']:,}")
            logger.info(f"   Categories: {summary['categories']:,}")
            logger.info(f"   States: {summary['states']:,}")
            logger.info(f"   Municipalities: {summary['municipalities']:,}")
            logger.info(f"   Date Range: {summary['earliest_date']} to {summary['latest_date']}")
            
            return summary
            
        except Exception as e:
            logger.error(f"❌ Failed to get import summary: {e}")
            return None
    
    def close_connection(self):
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()
        logger.info("🔌 Database connection closed")

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description='Railway PostgreSQL Bulk Import')
    parser.add_argument('--test-connection', action='store_true', help='Test database connection only')
    parser.add_argument('--create-tables', action='store_true', help='Create tables only')
    parser.add_argument('--import-data', action='store_true', help='Import data only')
    parser.add_argument('--all', action='store_true', help='Run complete import process')
    
    args = parser.parse_args()
    
    if not any([args.test_connection, args.create_tables, args.import_data, args.all]):
        args.all = True  # Default to complete process
    
    importer = RailwayBulkImporter()
    
    try:
        # Step 1: Connect to database
        if not importer.connect_to_database():
            logger.error("❌ Cannot proceed without database connection")
            return 1
        
        if args.test_connection:
            logger.info("✅ Database connection test successful")
            return 0
        
        # Step 2: Create tables
        if args.create_tables or args.all:
            if not importer.create_documents_table():
                logger.error("❌ Cannot proceed without creating tables")
                return 1
                
            if not importer.create_additional_tables():
                logger.warning("⚠️ Additional tables creation failed, continuing...")
        
        # Step 3: Import data
        if args.import_data or args.all:
            csv_file = importer.find_csv_file()
            if not csv_file:
                logger.error("❌ No CSV file found for import")
                return 1
            
            if not importer.bulk_import_csv(csv_file):
                logger.error("❌ Data import failed")
                return 1
            
            # Step 4: Optimize database
            if not importer.optimize_database():
                logger.warning("⚠️ Database optimization failed, continuing...")
            
            # Step 5: Show summary
            importer.get_import_summary()
        
        logger.info("🎉 Railway bulk import completed successfully!")
        return 0
        
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        return 1
        
    finally:
        importer.close_connection()

if __name__ == "__main__":
    exit(main())