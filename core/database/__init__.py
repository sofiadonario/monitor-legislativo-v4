"""
Database package for Monitor Legislativo
Provides database connection, migrations, and management utilities
"""

from .migrations import DatabaseMigrationManager, run_migrations

__all__ = ['DatabaseMigrationManager', 'run_migrations']