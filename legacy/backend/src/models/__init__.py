from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# Import models to register them with Base.metadata
# This ensures they're included when generating migrations
from .search_cache import SearchCache
from .schema_migrations import SchemaMigrations

__all__ = ['Base', 'SearchCache', 'SchemaMigrations']