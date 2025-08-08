"""
Database Integration Module for Brazilian Legislative Monitoring System
======================================================================

This module provides comprehensive database integration capabilities for
managing Brazilian legislative document data with PostgreSQL backend.

Features:
---------
- PostgreSQL connection management with pooling
- Data models for legislative documents and metadata
- Efficient batch operations for large datasets (134k+ documents)
- Query optimization and indexing strategies
- Data validation and integrity checking
- Migration and schema management
- Analytics query builders
- Backup and recovery utilities

Components:
-----------
- DatabaseManager: Main database connection and operation manager
- DocumentModel: Data models for legislative documents
- QueryBuilder: Advanced query builder for analytics
- MigrationManager: Database schema migrations
- DataValidator: Data quality and integrity validation
- AnalyticsQueries: Pre-built analytical queries
- BackupManager: Database backup and recovery

Usage:
------
Basic database operations:
    >>> from lexml_refinado.database import DatabaseManager
    >>> db = DatabaseManager(connection_string)
    >>> db.connect()
    >>> documents = db.get_documents(limit=100)

Advanced querying:
    >>> from lexml_refinado.database import QueryBuilder
    >>> query = QueryBuilder()
    >>> result = query.select_documents().where_date_range('2023-01-01', '2023-12-31').execute()

Data validation:
    >>> from lexml_refinado.database import DataValidator
    >>> validator = DataValidator(db)
    >>> issues = validator.validate_document_integrity()
"""

from typing import Dict, List, Any, Optional, Union
import warnings

# Core database components
try:
    from .database_manager import DatabaseManager
    from .models import DocumentModel, CategoryModel, SearchTermModel
    from .query_builder import QueryBuilder
    from .data_validator import DataValidator
except ImportError as e:
    warnings.warn(f"Core database components could not be imported: {e}", ImportWarning)

# Advanced database components (optional)
_advanced_components = {}

try:
    from .migration_manager import MigrationManager
    _advanced_components['migrations'] = True
except ImportError:
    _advanced_components['migrations'] = False

try:
    from .analytics_queries import AnalyticsQueries
    _advanced_components['analytics'] = True
except ImportError:
    _advanced_components['analytics'] = False

try:
    from .backup_manager import BackupManager
    _advanced_components['backup'] = True
except ImportError:
    _advanced_components['backup'] = False

try:
    from .connection_pool import ConnectionPoolManager
    _advanced_components['connection_pool'] = True
except ImportError:
    _advanced_components['connection_pool'] = False

# Export main components
__all__ = [
    # Core components
    'DatabaseManager',
    'DocumentModel',
    'CategoryModel', 
    'SearchTermModel',
    'QueryBuilder',
    'DataValidator',
    
    # Advanced components (conditionally available)
    'MigrationManager',
    'AnalyticsQueries',
    'BackupManager',
    'ConnectionPoolManager',
    
    # Utility functions
    'get_database_capabilities',
    'create_database_connection',
    'validate_connection_string',
]

def get_database_capabilities() -> Dict[str, bool]:
    """
    Get information about available database capabilities.
    
    Returns:
        Dict mapping component names to availability status
    """
    capabilities = {
        'database_manager': True,
        'models': True,
        'query_builder': True,
        'data_validator': True,
    }
    capabilities.update(_advanced_components)
    return capabilities

def create_database_connection(
    connection_string: Optional[str] = None,
    pool_size: int = 5,
    max_overflow: int = 10
) -> 'DatabaseManager':
    """
    Create a configured database connection.
    
    Args:
        connection_string: PostgreSQL connection string
        pool_size: Connection pool size
        max_overflow: Maximum connection overflow
        
    Returns:
        Configured DatabaseManager instance
    """
    return DatabaseManager(
        connection_string=connection_string,
        pool_size=pool_size,
        max_overflow=max_overflow
    )

def validate_connection_string(connection_string: str) -> bool:
    """
    Validate PostgreSQL connection string format.
    
    Args:
        connection_string: Connection string to validate
        
    Returns:
        True if valid, False otherwise
    """
    import re
    
    # Basic PostgreSQL connection string pattern
    postgres_pattern = r'postgresql:\/\/[^:]+:[^@]+@[^:]+:\d+\/\w+'
    
    return bool(re.match(postgres_pattern, connection_string))