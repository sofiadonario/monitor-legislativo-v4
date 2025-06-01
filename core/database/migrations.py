"""
Database migration management for Monitor Legislativo
Handles schema creation, updates, and data migrations
"""

import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy import create_engine, text, MetaData, Table, inspect
from sqlalchemy.exc import SQLAlchemyError
from core.config.config import get_config
from core.models.models import Base, Document, Alert, User, SearchQuery, ExportRequest

logger = logging.getLogger(__name__)

class DatabaseMigrationManager:
    """Manages database schema migrations and data seeding"""
    
    def __init__(self):
        self.config = get_config()
        self.engine = create_engine(
            self.config.DATABASE_URL,
            echo=self.config.DEBUG,
            pool_pre_ping=True,
            pool_recycle=3600
        )
        self.metadata = MetaData()
        self.migration_history_table = 'migration_history'
        
    def initialize_database(self) -> bool:
        """Initialize database with all tables and migration tracking"""
        try:
            logger.info("Initializing database...")
            
            # Create migration history table first
            self._create_migration_history_table()
            
            # Create all tables from models
            Base.metadata.create_all(self.engine)
            
            # Record initial migration
            self._record_migration('001_initial_schema', 'Initial database schema creation')
            
            logger.info("Database initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            return False
    
    def _create_migration_history_table(self):
        """Create migration history tracking table"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS migration_history (
            id SERIAL PRIMARY KEY,
            migration_name VARCHAR(255) NOT NULL UNIQUE,
            description TEXT,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            rollback_sql TEXT,
            checksum VARCHAR(64)
        )
        """
        
        with self.engine.connect() as conn:
            conn.execute(text(create_table_sql))
            conn.commit()
    
    def _record_migration(self, name: str, description: str, rollback_sql: str = None):
        """Record a migration in the history table"""
        insert_sql = """
        INSERT INTO migration_history (migration_name, description, rollback_sql)
        VALUES (:name, :description, :rollback_sql)
        ON CONFLICT (migration_name) DO NOTHING
        """
        
        with self.engine.connect() as conn:
            conn.execute(text(insert_sql), {
                'name': name,
                'description': description,
                'rollback_sql': rollback_sql
            })
            conn.commit()
    
    def get_applied_migrations(self) -> List[str]:
        """Get list of applied migrations"""
        try:
            with self.engine.connect() as conn:
                result = conn.execute(text(
                    "SELECT migration_name FROM migration_history ORDER BY applied_at"
                ))
                return [row[0] for row in result]
        except:
            return []
    
    def apply_migrations(self) -> bool:
        """Apply all pending migrations"""
        try:
            applied_migrations = self.get_applied_migrations()
            migrations = self._get_available_migrations()
            
            for migration in migrations:
                if migration['name'] not in applied_migrations:
                    logger.info(f"Applying migration: {migration['name']}")
                    if self._apply_migration(migration):
                        logger.info(f"Migration {migration['name']} applied successfully")
                    else:
                        logger.error(f"Failed to apply migration: {migration['name']}")
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Migration process failed: {e}")
            return False
    
    def _get_available_migrations(self) -> List[Dict[str, Any]]:
        """Get list of available migrations"""
        return [
            {
                'name': '002_add_indexes',
                'description': 'Add performance indexes',
                'sql': self._get_index_migration_sql(),
                'rollback_sql': self._get_index_rollback_sql()
            },
            {
                'name': '003_add_search_optimization',
                'description': 'Add search optimization columns',
                'sql': self._get_search_optimization_sql(),
                'rollback_sql': self._get_search_optimization_rollback_sql()
            },
            {
                'name': '004_add_audit_fields',
                'description': 'Add audit fields to all tables',
                'sql': self._get_audit_fields_sql(),
                'rollback_sql': self._get_audit_fields_rollback_sql()
            }
        ]
    
    def _apply_migration(self, migration: Dict[str, Any]) -> bool:
        """Apply a single migration"""
        try:
            with self.engine.connect() as conn:
                # Execute migration SQL
                for statement in migration['sql'].split(';'):
                    if statement.strip():
                        conn.execute(text(statement))
                
                # Record migration
                self._record_migration(
                    migration['name'],
                    migration['description'],
                    migration.get('rollback_sql')
                )
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to apply migration {migration['name']}: {e}")
            return False
    
    def _get_index_migration_sql(self) -> str:
        """SQL for creating performance indexes"""
        return """
        -- Document indexes
        CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(type);
        CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at);
        CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status);
        CREATE INDEX IF NOT EXISTS idx_documents_source ON documents(source);
        CREATE INDEX IF NOT EXISTS idx_documents_title_gin ON documents USING gin(to_tsvector('portuguese', title));
        CREATE INDEX IF NOT EXISTS idx_documents_content_gin ON documents USING gin(to_tsvector('portuguese', content));
        
        -- Alert indexes
        CREATE INDEX IF NOT EXISTS idx_alerts_user_id ON alerts(user_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_active ON alerts(active);
        CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
        
        -- Search query indexes
        CREATE INDEX IF NOT EXISTS idx_search_queries_user_id ON search_queries(user_id);
        CREATE INDEX IF NOT EXISTS idx_search_queries_created_at ON search_queries(created_at);
        
        -- Export request indexes
        CREATE INDEX IF NOT EXISTS idx_export_requests_user_id ON export_requests(user_id);
        CREATE INDEX IF NOT EXISTS idx_export_requests_status ON export_requests(status);
        CREATE INDEX IF NOT EXISTS idx_export_requests_created_at ON export_requests(created_at);
        """
    
    def _get_index_rollback_sql(self) -> str:
        """SQL for removing performance indexes"""
        return """
        DROP INDEX IF EXISTS idx_documents_type;
        DROP INDEX IF EXISTS idx_documents_created_at;
        DROP INDEX IF EXISTS idx_documents_status;
        DROP INDEX IF EXISTS idx_documents_source;
        DROP INDEX IF EXISTS idx_documents_title_gin;
        DROP INDEX IF EXISTS idx_documents_content_gin;
        DROP INDEX IF EXISTS idx_alerts_user_id;
        DROP INDEX IF EXISTS idx_alerts_active;
        DROP INDEX IF EXISTS idx_alerts_created_at;
        DROP INDEX IF EXISTS idx_search_queries_user_id;
        DROP INDEX IF EXISTS idx_search_queries_created_at;
        DROP INDEX IF EXISTS idx_export_requests_user_id;
        DROP INDEX IF EXISTS idx_export_requests_status;
        DROP INDEX IF EXISTS idx_export_requests_created_at;
        """
    
    def _get_search_optimization_sql(self) -> str:
        """SQL for search optimization features"""
        return """
        -- Add search vector column to documents
        ALTER TABLE documents ADD COLUMN IF NOT EXISTS search_vector tsvector;
        
        -- Create function to update search vector
        CREATE OR REPLACE FUNCTION update_document_search_vector()
        RETURNS trigger AS $$
        BEGIN
            NEW.search_vector := to_tsvector('portuguese', 
                COALESCE(NEW.title, '') || ' ' || 
                COALESCE(NEW.content, '') || ' ' ||
                COALESCE(NEW.summary, '')
            );
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        
        -- Create trigger to auto-update search vector
        DROP TRIGGER IF EXISTS update_search_vector_trigger ON documents;
        CREATE TRIGGER update_search_vector_trigger
            BEFORE INSERT OR UPDATE ON documents
            FOR EACH ROW EXECUTE FUNCTION update_document_search_vector();
        
        -- Update existing documents
        UPDATE documents SET search_vector = to_tsvector('portuguese', 
            COALESCE(title, '') || ' ' || 
            COALESCE(content, '') || ' ' ||
            COALESCE(summary, '')
        );
        
        -- Create GIN index on search vector
        CREATE INDEX IF NOT EXISTS idx_documents_search_vector ON documents USING gin(search_vector);
        """
    
    def _get_search_optimization_rollback_sql(self) -> str:
        """Rollback SQL for search optimization"""
        return """
        DROP TRIGGER IF EXISTS update_search_vector_trigger ON documents;
        DROP FUNCTION IF EXISTS update_document_search_vector();
        DROP INDEX IF EXISTS idx_documents_search_vector;
        ALTER TABLE documents DROP COLUMN IF EXISTS search_vector;
        """
    
    def _get_audit_fields_sql(self) -> str:
        """SQL for adding audit fields"""
        return """
        -- Add audit fields to documents
        ALTER TABLE documents ADD COLUMN IF NOT EXISTS created_by INTEGER;
        ALTER TABLE documents ADD COLUMN IF NOT EXISTS updated_by INTEGER;
        ALTER TABLE documents ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
        
        -- Add audit fields to alerts
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS created_by INTEGER;
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS updated_by INTEGER;
        ALTER TABLE alerts ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
        
        -- Add audit fields to users
        ALTER TABLE users ADD COLUMN IF NOT EXISTS created_by INTEGER;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_by INTEGER;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP;
        ALTER TABLE users ADD COLUMN IF NOT EXISTS login_count INTEGER DEFAULT 0;
        """
    
    def _get_audit_fields_rollback_sql(self) -> str:
        """Rollback SQL for audit fields"""
        return """
        ALTER TABLE documents DROP COLUMN IF EXISTS created_by;
        ALTER TABLE documents DROP COLUMN IF EXISTS updated_by;
        ALTER TABLE documents DROP COLUMN IF EXISTS version;
        ALTER TABLE alerts DROP COLUMN IF EXISTS created_by;
        ALTER TABLE alerts DROP COLUMN IF EXISTS updated_by;
        ALTER TABLE alerts DROP COLUMN IF EXISTS version;
        ALTER TABLE users DROP COLUMN IF EXISTS created_by;
        ALTER TABLE users DROP COLUMN IF EXISTS updated_by;
        ALTER TABLE users DROP COLUMN IF EXISTS version;
        ALTER TABLE users DROP COLUMN IF EXISTS last_login_at;
        ALTER TABLE users DROP COLUMN IF EXISTS login_count;
        """
    
    def seed_initial_data(self) -> bool:
        """Seed database with initial data"""
        try:
            logger.info("Seeding initial data...")
            
            # Create admin user
            self._create_admin_user()
            
            # Create sample data for development/testing
            if self.config.ENVIRONMENT in ['development', 'testing']:
                self._create_sample_data()
            
            logger.info("Initial data seeding completed")
            return True
            
        except Exception as e:
            logger.error(f"Data seeding failed: {e}")
            return False
    
    def _create_admin_user(self):
        """Create default admin user"""
        from werkzeug.security import generate_password_hash
        
        admin_sql = """
        INSERT INTO users (username, email, password_hash, role, active, created_at)
        VALUES (:username, :email, :password_hash, :role, :active, :created_at)
        ON CONFLICT (email) DO NOTHING
        """
        
        admin_password = os.getenv('ADMIN_PASSWORD', 'admin123')
        password_hash = generate_password_hash(admin_password)
        
        with self.engine.connect() as conn:
            conn.execute(text(admin_sql), {
                'username': 'admin',
                'email': 'admin@monitor-legislativo.gov.br',
                'password_hash': password_hash,
                'role': 'admin',
                'active': True,
                'created_at': datetime.utcnow()
            })
            conn.commit()
    
    def _create_sample_data(self):
        """Create sample data for development"""
        # Sample documents
        sample_documents_sql = """
        INSERT INTO documents (title, content, summary, type, source, status, created_at)
        VALUES 
        (:title1, :content1, :summary1, :type1, :source1, :status1, :created_at),
        (:title2, :content2, :summary2, :type2, :source2, :status2, :created_at),
        (:title3, :content3, :summary3, :type3, :source3, :status3, :created_at)
        ON CONFLICT DO NOTHING
        """
        
        with self.engine.connect() as conn:
            conn.execute(text(sample_documents_sql), {
                'title1': 'PL 1234/2024 - Lei de Proteção de Dados',
                'content1': 'Projeto de lei que estabelece diretrizes para proteção de dados pessoais...',
                'summary1': 'Lei que regulamenta proteção de dados no setor público',
                'type1': 'projeto_lei',
                'source1': 'camara',
                'status1': 'tramitando',
                'title2': 'Decreto 5678/2024 - Transparência Governamental',
                'content2': 'Decreto que estabelece normas para transparência de dados governamentais...',
                'summary2': 'Normas para transparência de dados do governo',
                'type2': 'decreto',
                'source2': 'planalto',
                'status2': 'publicado',
                'title3': 'PEC 90/2024 - Reforma Tributária',
                'content3': 'Proposta de emenda constitucional sobre reforma do sistema tributário...',
                'summary3': 'Proposta de reforma do sistema tributário nacional',
                'type3': 'pec',
                'source3': 'senado',
                'status3': 'em_votacao',
                'created_at': datetime.utcnow()
            })
            conn.commit()
    
    def health_check(self) -> Dict[str, Any]:
        """Perform database health check"""
        try:
            with self.engine.connect() as conn:
                # Test basic connectivity
                conn.execute(text("SELECT 1"))
                
                # Check table existence
                inspector = inspect(self.engine)
                tables = inspector.get_table_names()
                
                # Check migration status
                applied_migrations = self.get_applied_migrations()
                
                return {
                    'status': 'healthy',
                    'tables_count': len(tables),
                    'applied_migrations': len(applied_migrations),
                    'last_migration': applied_migrations[-1] if applied_migrations else None,
                    'timestamp': datetime.utcnow().isoformat()
                }
                
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def backup_database(self, backup_path: str) -> bool:
        """Create database backup"""
        try:
            import subprocess
            
            # Extract database connection details
            db_url = self.config.DATABASE_URL
            # Parse DATABASE_URL to get components
            # postgresql://user:password@host:port/database
            
            cmd = [
                'pg_dump',
                db_url,
                '--no-password',
                '--format=custom',
                '--file', backup_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info(f"Database backup created: {backup_path}")
                return True
            else:
                logger.error(f"Backup failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Backup process failed: {e}")
            return False


def run_migrations():
    """Entry point for running migrations"""
    migration_manager = DatabaseMigrationManager()
    
    # Initialize database if needed
    if not migration_manager.get_applied_migrations():
        migration_manager.initialize_database()
    
    # Apply pending migrations
    migration_manager.apply_migrations()
    
    # Seed initial data
    migration_manager.seed_initial_data()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    run_migrations()