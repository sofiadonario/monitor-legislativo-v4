#!/usr/bin/env python3
"""
Database Migration Runner for Monitor Legislativo v4
Runs all SQL migrations in order to set up the database schema
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import List, Dict
import asyncpg
from sqlalchemy import text
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.database.supabase_config import get_database_manager
from src.config.env_loader import EnvironmentConfig, validate_environment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MigrationRunner:
    """Handles database migration execution"""
    
    def __init__(self):
        self.migrations_dir = Path(__file__).parent.parent.parent / "migrations"
        self.db_manager = None
        
    async def initialize(self):
        """Initialize database connection"""
        self.db_manager = await get_database_manager()
        if not self.db_manager:
            raise Exception("Failed to initialize database manager")
        
        # Test connection
        connected = await self.db_manager.test_connection()
        if not connected:
            raise Exception("Failed to connect to database")
        
        logger.info("Database connection established")
        
    async def create_migrations_table(self):
        """Create migrations tracking table if it doesn't exist"""
        async with self.db_manager.session_factory() as session:
            await session.execute(text("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id SERIAL PRIMARY KEY,
                    filename VARCHAR(255) UNIQUE NOT NULL,
                    executed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    checksum VARCHAR(64),
                    success BOOLEAN DEFAULT true,
                    error_message TEXT
                )
            """))
            await session.commit()
            logger.info("Migrations table ready")
    
    async def get_executed_migrations(self) -> List[str]:
        """Get list of already executed migrations"""
        async with self.db_manager.session_factory() as session:
            result = await session.execute(
                text("SELECT filename FROM schema_migrations WHERE success = true ORDER BY filename")
            )
            return [row[0] for row in result.fetchall()]
    
    def get_migration_files(self) -> List[Path]:
        """Get all migration files in order"""
        if not self.migrations_dir.exists():
            logger.warning(f"Migrations directory not found: {self.migrations_dir}")
            return []
        
        files = sorted([
            f for f in self.migrations_dir.glob("*.sql")
            if f.is_file()
        ])
        
        return files
    
    def calculate_checksum(self, content: str) -> str:
        """Calculate checksum for migration content"""
        import hashlib
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _split_sql_statements(self, content: str) -> List[str]:
        """Split SQL content into statements while preserving PostgreSQL functions"""
        # Simple approach: execute the entire migration as individual executable blocks
        # Split on double newlines or specific patterns
        
        import re
        
        # Remove comments first
        content = re.sub(r'--.*$', '', content, flags=re.MULTILINE)
        
        # Split into statements at semicolons that are followed by newlines
        # But preserve function definitions
        statements = []
        current_statement = ""
        in_dollar_quote = False
        dollar_tag = None
        
        i = 0
        while i < len(content):
            char = content[i]
            
            # Handle dollar quoting
            if char == '$' and not in_dollar_quote:
                # Look for dollar quote start
                end_pos = content.find('$', i + 1)
                if end_pos != -1:
                    tag = content[i:end_pos + 1]
                    dollar_tag = tag
                    in_dollar_quote = True
                    current_statement += content[i:end_pos + 1]
                    i = end_pos + 1
                    continue
            elif char == '$' and in_dollar_quote and dollar_tag:
                # Look for matching dollar quote end
                if content[i:].startswith(dollar_tag):
                    in_dollar_quote = False
                    current_statement += dollar_tag
                    i += len(dollar_tag)
                    continue
            
            current_statement += char
            
            # Check for statement end
            if char == ';' and not in_dollar_quote:
                # Look ahead for newline or end of content
                j = i + 1
                while j < len(content) and content[j] in ' \t':
                    j += 1
                
                if j >= len(content) or content[j] == '\n':
                    # This is a statement end
                    statements.append(current_statement.strip())
                    current_statement = ""
            
            i += 1
        
        # Add any remaining statement
        if current_statement.strip():
            statements.append(current_statement.strip())
        
        # Filter out empty statements and clean up
        cleaned_statements = []
        for stmt in statements:
            stmt = stmt.strip()
            if stmt and not stmt.isspace() and stmt != ';':
                cleaned_statements.append(stmt)
        
        return cleaned_statements
    
    async def execute_migration(self, file_path: Path) -> Dict[str, any]:
        """Execute a single migration file"""
        filename = file_path.name
        logger.info(f"Executing migration: {filename}")
        
        try:
            # Read migration content
            content = file_path.read_text(encoding='utf-8')
            checksum = self.calculate_checksum(content)
            
            # Split statements while preserving PostgreSQL functions
            statements = self._split_sql_statements(content)
            
            # Execute within transaction
            async with self.db_manager.session_factory() as session:
                # Execute each statement
                for i, statement in enumerate(statements):
                    if statement:
                        logger.debug(f"Executing statement {i+1}/{len(statements)}")
                        await session.execute(text(statement))
                
                # Record successful migration
                await session.execute(
                    text("""
                        INSERT INTO schema_migrations (filename, checksum, success)
                        VALUES (:filename, :checksum, true)
                        ON CONFLICT (filename) DO UPDATE
                        SET executed_at = NOW(), checksum = :checksum, success = true
                    """),
                    {"filename": filename, "checksum": checksum}
                )
                
                await session.commit()
                
            logger.info(f"✓ Migration {filename} completed successfully")
            return {"success": True, "filename": filename}
            
        except Exception as e:
            logger.error(f"✗ Migration {filename} failed: {e}")
            
            # Record failed migration
            try:
                async with self.db_manager.session_factory() as session:
                    await session.execute(
                        text("""
                            INSERT INTO schema_migrations (filename, success, error_message)
                            VALUES (:filename, false, :error)
                            ON CONFLICT (filename) DO UPDATE
                            SET executed_at = NOW(), success = false, error_message = :error
                        """),
                        {"filename": filename, "error": str(e)}
                    )
                    await session.commit()
            except:
                pass
            
            return {"success": False, "filename": filename, "error": str(e)}
    
    async def run_migrations(self):
        """Run all pending migrations"""
        logger.info("Starting migration process...")
        
        # Get migration files
        migration_files = self.get_migration_files()
        if not migration_files:
            logger.info("No migration files found")
            return
        
        logger.info(f"Found {len(migration_files)} migration files")
        
        # Get already executed migrations
        executed = await self.get_executed_migrations()
        logger.info(f"{len(executed)} migrations already executed")
        
        # Filter pending migrations
        pending = [f for f in migration_files if f.name not in executed]
        
        if not pending:
            logger.info("All migrations are up to date")
            return
        
        logger.info(f"Running {len(pending)} pending migrations...")
        
        # Execute pending migrations
        results = []
        for migration_file in pending:
            result = await self.execute_migration(migration_file)
            results.append(result)
            
            # Stop on failure
            if not result["success"]:
                logger.error("Migration failed, stopping process")
                break
        
        # Summary
        successful = sum(1 for r in results if r["success"])
        failed = sum(1 for r in results if not r["success"])
        
        logger.info(f"\nMigration Summary:")
        logger.info(f"  Total: {len(results)}")
        logger.info(f"  Successful: {successful}")
        logger.info(f"  Failed: {failed}")
        
        if failed > 0:
            logger.error("Some migrations failed. Please check the errors above.")
            sys.exit(1)
        else:
            logger.info("All migrations completed successfully!")

async def main():
    """Main execution function"""
    logger.info("Monitor Legislativo v4 - Database Migration Runner")
    logger.info("=" * 60)
    
    # Validate environment
    env_validation = validate_environment()
    if not env_validation["valid"]:
        logger.error("Environment validation failed:")
        for error in env_validation["errors"]:
            logger.error(f"  - {error}")
        sys.exit(1)
    
    # Run migrations
    runner = MigrationRunner()
    
    try:
        await runner.initialize()
        await runner.create_migrations_table()
        await runner.run_migrations()
        
    except Exception as e:
        logger.error(f"Migration process failed: {e}")
        sys.exit(1)
    finally:
        if runner.db_manager:
            await runner.db_manager.close()

if __name__ == "__main__":
    asyncio.run(main())