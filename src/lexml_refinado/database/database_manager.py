#!/usr/bin/env python3
"""
Database Manager for Brazilian Legislative Monitoring System
============================================================

Comprehensive database management system for handling Brazilian legislative
document data with PostgreSQL backend. Optimized for large-scale datasets
(134k+ documents) with efficient querying and batch operations.

Features:
---------
- Connection pooling and management
- Batch insert/update operations
- Query optimization
- Transaction management
- Error handling and recovery
- Data integrity validation
- Performance monitoring

Author: MackIntegridade Research Team
Date: 2025-08-08
Version: 2.0.0
"""

import logging
import os
from typing import Dict, List, Any, Optional, Union, Tuple, Generator
from dataclasses import dataclass
from datetime import datetime, date
from contextlib import contextmanager
import json

import pandas as pd
import numpy as np
from sqlalchemy import create_engine, text, MetaData, Table, Column, Integer, String, Text, DateTime, Float, Boolean
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from sqlalchemy.dialects.postgresql import insert

try:
    import psycopg2
    from psycopg2.extras import execute_values
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class DatabaseConfig:
    """Configuration for database connections."""
    
    # Connection settings
    host: str = 'localhost'
    port: int = 5432
    database: str = 'monitor_legislativo'
    username: str = 'postgres'
    password: str = ''
    
    # Pool settings
    pool_size: int = 5
    max_overflow: int = 10
    pool_timeout: int = 30
    pool_recycle: int = 3600
    
    # Query settings
    query_timeout: int = 300
    batch_size: int = 1000
    
    # SSL settings
    use_ssl: bool = False
    ssl_mode: str = 'prefer'


@dataclass
class QueryResult:
    """Container for query results with metadata."""
    
    data: Union[pd.DataFrame, List[Dict[str, Any]]]
    row_count: int
    execution_time: float
    query: str
    success: bool
    error_message: Optional[str] = None


class DatabaseManager:
    """
    Comprehensive database manager for Brazilian legislative documents.
    """
    
    def __init__(
        self,
        connection_string: Optional[str] = None,
        config: Optional[DatabaseConfig] = None
    ):
        """
        Initialize the database manager.
        
        Args:
            connection_string: PostgreSQL connection string
            config: Database configuration object
        """
        self.config = config or DatabaseConfig()
        
        # Set connection string
        if connection_string:
            self.connection_string = connection_string
        else:
            self.connection_string = self._build_connection_string()
        
        # Initialize components
        self.engine = None
        self.SessionLocal = None
        self.metadata = MetaData()
        
        # Performance tracking
        self.query_stats = {
            'total_queries': 0,
            'total_execution_time': 0,
            'failed_queries': 0,
            'last_query_time': None
        }
        
        logger.info("DatabaseManager initialized")
    
    def _build_connection_string(self) -> str:
        """Build connection string from config."""
        return (
            f"postgresql://{self.config.username}:{self.config.password}@"
            f"{self.config.host}:{self.config.port}/{self.config.database}"
        )
    
    def connect(self) -> bool:
        """
        Establish database connection with pool.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Create engine with connection pooling
            self.engine = create_engine(
                self.connection_string,
                poolclass=QueuePool,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                pool_recycle=self.config.pool_recycle,
                echo=False  # Set to True for SQL debugging
            )
            
            # Create session factory
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            # Test connection
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            logger.info("Database connection established successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    def disconnect(self) -> None:
        """Close database connections and dispose engine."""
        if self.engine:
            self.engine.dispose()
            logger.info("Database connections closed")
    
    @contextmanager
    def get_session(self):
        """Get database session with automatic cleanup."""
        if not self.SessionLocal:
            raise RuntimeError("Database not connected. Call connect() first.")
        
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def execute_query(
        self,
        query: str,
        params: Optional[Dict[str, Any]] = None,
        return_dataframe: bool = True
    ) -> QueryResult:
        """
        Execute SQL query with error handling and performance tracking.
        
        Args:
            query: SQL query string
            params: Query parameters
            return_dataframe: Whether to return pandas DataFrame
            
        Returns:
            QueryResult object with data and metadata
        """
        start_time = datetime.now()
        
        try:
            with self.engine.connect() as conn:
                if params:
                    result = conn.execute(text(query), params)
                else:
                    result = conn.execute(text(query))
                
                # Fetch results if it's a SELECT query
                if query.strip().upper().startswith('SELECT'):
                    if return_dataframe:
                        data = pd.read_sql_query(text(query), conn, params=params)
                        row_count = len(data)
                    else:
                        rows = result.fetchall()
                        columns = result.keys()
                        data = [dict(zip(columns, row)) for row in rows]
                        row_count = len(data)
                else:
                    # For INSERT/UPDATE/DELETE queries
                    row_count = result.rowcount
                    data = pd.DataFrame() if return_dataframe else []
                
                execution_time = (datetime.now() - start_time).total_seconds()
                
                # Update stats
                self._update_query_stats(execution_time, success=True)
                
                return QueryResult(
                    data=data,
                    row_count=row_count,
                    execution_time=execution_time,
                    query=query,
                    success=True
                )
                
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self._update_query_stats(execution_time, success=False)
            
            logger.error(f"Query execution failed: {e}")
            
            return QueryResult(
                data=pd.DataFrame() if return_dataframe else [],
                row_count=0,
                execution_time=execution_time,
                query=query,
                success=False,
                error_message=str(e)
            )
    
    def bulk_insert(
        self,
        table_name: str,
        data: Union[pd.DataFrame, List[Dict[str, Any]]],
        on_conflict: str = 'ignore',
        batch_size: Optional[int] = None
    ) -> bool:
        """
        Perform bulk insert operation with conflict resolution.
        
        Args:
            table_name: Target table name
            data: Data to insert (DataFrame or list of dicts)
            on_conflict: Conflict resolution strategy ('ignore', 'update', 'error')
            batch_size: Batch size for insertion
            
        Returns:
            True if successful, False otherwise
        """
        if batch_size is None:
            batch_size = self.config.batch_size
        
        try:
            # Convert to DataFrame if needed
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = data.copy()
            
            # Remove NaN values and convert types
            df = df.where(pd.notnull(df), None)
            
            # Process in batches
            total_rows = len(df)
            processed_rows = 0
            
            with self.get_session() as session:
                for i in range(0, total_rows, batch_size):
                    batch_df = df.iloc[i:i + batch_size]
                    batch_records = batch_df.to_dict('records')
                    
                    if on_conflict == 'ignore':
                        # Use INSERT ... ON CONFLICT DO NOTHING
                        stmt = insert(Table(table_name, self.metadata, autoload_with=self.engine))
                        stmt = stmt.on_conflict_do_nothing()
                        session.execute(stmt, batch_records)
                    
                    elif on_conflict == 'update':
                        # Use INSERT ... ON CONFLICT DO UPDATE
                        # This requires knowing the conflict columns - using 'urn' as common unique column
                        stmt = insert(Table(table_name, self.metadata, autoload_with=self.engine))
                        stmt = stmt.on_conflict_do_update(
                            index_elements=['urn'],
                            set_=dict(stmt.excluded)
                        )
                        session.execute(stmt, batch_records)
                    
                    else:
                        # Regular insert (will fail on conflicts)
                        for record in batch_records:
                            session.execute(
                                text(f"INSERT INTO {table_name} ({', '.join(record.keys())}) "
                                     f"VALUES ({', '.join([f':{k}' for k in record.keys()])})"),
                                record
                            )
                    
                    processed_rows += len(batch_records)
                    
                    if processed_rows % (batch_size * 10) == 0:
                        logger.info(f"Inserted {processed_rows}/{total_rows} rows")
                
                session.commit()
            
            logger.info(f"Successfully inserted {total_rows} rows into {table_name}")
            return True
            
        except Exception as e:
            logger.error(f"Bulk insert failed: {e}")
            return False
    
    def bulk_update(
        self,
        table_name: str,
        data: Union[pd.DataFrame, List[Dict[str, Any]]],
        key_columns: List[str],
        batch_size: Optional[int] = None
    ) -> bool:
        """
        Perform bulk update operation.
        
        Args:
            table_name: Target table name
            data: Data with updates
            key_columns: Columns to use for matching records
            batch_size: Batch size for updates
            
        Returns:
            True if successful, False otherwise
        """
        if batch_size is None:
            batch_size = self.config.batch_size
        
        try:
            # Convert to DataFrame if needed
            if isinstance(data, list):
                df = pd.DataFrame(data)
            else:
                df = data.copy()
            
            # Process in batches
            total_rows = len(df)
            processed_rows = 0
            
            with self.get_session() as session:
                for i in range(0, total_rows, batch_size):
                    batch_df = df.iloc[i:i + batch_size]
                    
                    for _, row in batch_df.iterrows():
                        # Build WHERE clause
                        where_conditions = [f"{col} = :{col}" for col in key_columns]
                        where_clause = " AND ".join(where_conditions)
                        
                        # Build SET clause (exclude key columns)
                        update_columns = [col for col in df.columns if col not in key_columns]
                        set_conditions = [f"{col} = :{col}" for col in update_columns]
                        set_clause = ", ".join(set_conditions)
                        
                        # Execute update
                        update_query = f"UPDATE {table_name} SET {set_clause} WHERE {where_clause}"
                        session.execute(text(update_query), row.to_dict())
                    
                    processed_rows += len(batch_df)
                    
                    if processed_rows % (batch_size * 10) == 0:
                        logger.info(f"Updated {processed_rows}/{total_rows} rows")
                
                session.commit()
            
            logger.info(f"Successfully updated {total_rows} rows in {table_name}")
            return True
            
        except Exception as e:
            logger.error(f"Bulk update failed: {e}")
            return False
    
    def get_documents(
        self,
        limit: Optional[int] = None,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
        order_by: str = 'date_searched DESC'
    ) -> pd.DataFrame:
        """
        Retrieve documents with filtering and pagination.
        
        Args:
            limit: Maximum number of documents to return
            offset: Number of documents to skip
            filters: Dictionary of filter conditions
            order_by: ORDER BY clause
            
        Returns:
            DataFrame with documents
        """
        # Build base query
        query = "SELECT * FROM lexml_documents"
        params = {}
        
        # Add filters
        if filters:
            where_conditions = []
            for key, value in filters.items():
                if isinstance(value, list):
                    # Handle IN clause
                    placeholders = [f":filter_{key}_{i}" for i in range(len(value))]
                    where_conditions.append(f"{key} IN ({', '.join(placeholders)})")
                    for i, v in enumerate(value):
                        params[f"filter_{key}_{i}"] = v
                elif isinstance(value, dict) and 'min' in value:
                    # Handle range filters
                    if 'min' in value:
                        where_conditions.append(f"{key} >= :filter_{key}_min")
                        params[f"filter_{key}_min"] = value['min']
                    if 'max' in value:
                        where_conditions.append(f"{key} <= :filter_{key}_max")
                        params[f"filter_{key}_max"] = value['max']
                else:
                    where_conditions.append(f"{key} = :filter_{key}")
                    params[f"filter_{key}"] = value
            
            if where_conditions:
                query += " WHERE " + " AND ".join(where_conditions)
        
        # Add ordering
        query += f" ORDER BY {order_by}"
        
        # Add pagination
        if limit:
            query += f" LIMIT :limit"
            params['limit'] = limit
        
        if offset > 0:
            query += f" OFFSET :offset"
            params['offset'] = offset
        
        result = self.execute_query(query, params)
        return result.data if result.success else pd.DataFrame()
    
    def get_document_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics about the document collection."""
        
        stats_queries = {
            'total_documents': "SELECT COUNT(*) as count FROM lexml_documents",
            'documents_by_type': """
                SELECT document_type_full, COUNT(*) as count 
                FROM lexml_documents 
                WHERE document_type_full IS NOT NULL 
                GROUP BY document_type_full 
                ORDER BY count DESC
            """,
            'documents_by_year': """
                SELECT EXTRACT(YEAR FROM enacting_date::date) as year, COUNT(*) as count 
                FROM lexml_documents 
                WHERE enacting_date IS NOT NULL AND enacting_date != '' 
                GROUP BY EXTRACT(YEAR FROM enacting_date::date) 
                ORDER BY year DESC
            """,
            'documents_by_state': """
                SELECT state, COUNT(*) as count 
                FROM lexml_documents 
                WHERE state IS NOT NULL AND state != '' 
                GROUP BY state 
                ORDER BY count DESC 
                LIMIT 10
            """,
            'recent_activity': """
                SELECT DATE(date_searched) as search_date, COUNT(*) as count 
                FROM lexml_documents 
                WHERE date_searched IS NOT NULL 
                GROUP BY DATE(date_searched) 
                ORDER BY search_date DESC 
                LIMIT 30
            """
        }
        
        statistics = {}
        
        for stat_name, query in stats_queries.items():
            result = self.execute_query(query)
            if result.success:
                if stat_name == 'total_documents':
                    statistics[stat_name] = result.data.iloc[0]['count'] if not result.data.empty else 0
                else:
                    statistics[stat_name] = result.data.to_dict('records')
            else:
                statistics[stat_name] = None
        
        return statistics
    
    def search_documents(
        self,
        search_term: str,
        search_fields: List[str] = None,
        limit: int = 100
    ) -> pd.DataFrame:
        """
        Full-text search across document fields.
        
        Args:
            search_term: Search term or phrase
            search_fields: Fields to search in
            limit: Maximum results to return
            
        Returns:
            DataFrame with search results
        """
        if search_fields is None:
            search_fields = ['title', 'document_description', 'document_summary']
        
        # Build search conditions
        search_conditions = []
        params = {'search_term': f"%{search_term}%"}
        
        for field in search_fields:
            search_conditions.append(f"{field} ILIKE :search_term")
        
        query = f"""
            SELECT *, 
                   CASE 
                       WHEN title ILIKE :search_term THEN 3
                       WHEN document_summary ILIKE :search_term THEN 2
                       ELSE 1
                   END as relevance_score
            FROM lexml_documents 
            WHERE {' OR '.join(search_conditions)}
            ORDER BY relevance_score DESC, date_searched DESC
            LIMIT :limit
        """
        
        params['limit'] = limit
        result = self.execute_query(query, params)
        
        return result.data if result.success else pd.DataFrame()
    
    def _update_query_stats(self, execution_time: float, success: bool) -> None:
        """Update query performance statistics."""
        self.query_stats['total_queries'] += 1
        self.query_stats['total_execution_time'] += execution_time
        self.query_stats['last_query_time'] = datetime.now().isoformat()
        
        if not success:
            self.query_stats['failed_queries'] += 1
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get database performance statistics."""
        stats = self.query_stats.copy()
        
        if stats['total_queries'] > 0:
            stats['average_query_time'] = stats['total_execution_time'] / stats['total_queries']
            stats['failure_rate'] = stats['failed_queries'] / stats['total_queries'] * 100
        else:
            stats['average_query_time'] = 0
            stats['failure_rate'] = 0
        
        return stats
    
    def health_check(self) -> Dict[str, Any]:
        """Perform database health check."""
        health = {
            'status': 'unknown',
            'connection': False,
            'query_test': False,
            'table_count': 0,
            'last_document_date': None,
            'error_message': None
        }
        
        try:
            # Test connection
            with self.engine.connect() as conn:
                health['connection'] = True
                
                # Test basic query
                result = conn.execute(text("SELECT 1"))
                health['query_test'] = result.scalar() == 1
                
                # Get table count
                result = conn.execute(text("""
                    SELECT COUNT(*) 
                    FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """))
                health['table_count'] = result.scalar()
                
                # Get last document date
                result = conn.execute(text("""
                    SELECT MAX(date_searched) 
                    FROM lexml_documents 
                    WHERE date_searched IS NOT NULL
                """))
                last_date = result.scalar()
                if last_date:
                    health['last_document_date'] = last_date.isoformat()
                
                health['status'] = 'healthy'
                
        except Exception as e:
            health['status'] = 'error'
            health['error_message'] = str(e)
            logger.error(f"Health check failed: {e}")
        
        return health