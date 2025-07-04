"""
URN Parser Service for Monitor Legislativo v4

Provides backend services for parsing LexML URNs and integrating with the database.
Handles both legislation and jurisprudence URN structures.
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
import json
import uuid
from pathlib import Path
import sys

import asyncpg
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
import pandas as pd

# Add scripts directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent / "scripts"))

try:
    from parse_urn_structure import parse_urn, format_document_description
except ImportError as e:
    logging.error(f"Failed to import URN parser: {e}")
    # Fallback stub functions
    def parse_urn(urn: str) -> Dict[str, Optional[str]]:
        return {'urn_type': None, 'country': None, 'state': None, 'municipality': None, 
               'justice': None, 'region': None, 'court_class': None, 
               'document_type_full': None, 'promulgation_date': None, 'original_urn': urn}
    
    def format_document_description(parsed_urn: Dict[str, Optional[str]]) -> str:
        return f"URN: {parsed_urn.get('original_urn', 'Unknown')}"

logger = logging.getLogger(__name__)


class URNParserService:
    """
    Service for parsing URNs and integrating with the legislative documents database
    """
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.engine = None
        self.async_engine = None
        self.session_factory = None
        
    async def initialize(self):
        """Initialize database connections"""
        try:
            self.async_engine = create_async_engine(self.database_url)
            self.session_factory = sessionmaker(
                self.async_engine, class_=AsyncSession, expire_on_commit=False
            )
            logger.info("URN Parser Service initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize URN Parser Service: {e}")
            return False
    
    async def parse_single_urn(self, urn: str) -> Dict[str, Any]:
        """
        Parse a single URN and return structured components
        
        Args:
            urn: LexML URN string
            
        Returns:
            Dictionary with parsed components and metadata
        """
        start_time = time.time()
        
        try:
            # Parse the URN
            parsed = parse_urn(urn)
            
            # Generate description
            description = format_document_description(parsed)
            
            # Calculate processing time
            processing_time = (time.time() - start_time) * 1000  # milliseconds
            
            # Prepare result
            result = {
                'success': True,
                'urn': urn,
                'parsed_components': parsed,
                'description': description,
                'processing_time_ms': processing_time,
                'parsed_at': datetime.now().isoformat()
            }
            
            logger.debug(f"Successfully parsed URN: {urn} (type: {parsed.get('urn_type')})")
            return result
            
        except Exception as e:
            logger.error(f"Error parsing URN {urn}: {e}")
            return {
                'success': False,
                'urn': urn,
                'error': str(e),
                'processing_time_ms': (time.time() - start_time) * 1000,
                'parsed_at': datetime.now().isoformat()
            }
    
    async def parse_batch_urns(self, urns: List[str], batch_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse a batch of URNs efficiently
        
        Args:
            urns: List of URN strings
            batch_id: Optional batch identifier
            
        Returns:
            Batch processing results with statistics
        """
        if not batch_id:
            batch_id = str(uuid.uuid4())
        
        start_time = time.time()
        results = []
        successful_parses = 0
        failed_parses = 0
        
        logger.info(f"Starting batch URN parsing: {len(urns)} URNs (batch: {batch_id})")
        
        # Process URNs in parallel batches to avoid overwhelming the system
        batch_size = 100
        for i in range(0, len(urns), batch_size):
            batch_urns = urns[i:i + batch_size]
            
            # Parse current batch
            batch_tasks = [self.parse_single_urn(urn) for urn in batch_urns]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # Process results
            for result in batch_results:
                if isinstance(result, Exception):
                    failed_parses += 1
                    results.append({
                        'success': False,
                        'error': str(result),
                        'urn': 'unknown'
                    })
                else:
                    if result.get('success'):
                        successful_parses += 1
                    else:
                        failed_parses += 1
                    results.append(result)
            
            # Progress logging
            if len(urns) > 100:
                logger.info(f"Processed {min(i + batch_size, len(urns))}/{len(urns)} URNs")
        
        total_time = time.time() - start_time
        avg_time_per_urn = (total_time * 1000) / len(urns) if urns else 0
        
        # Log performance metrics
        await self._log_batch_performance(
            batch_id, len(urns), successful_parses, failed_parses, 
            total_time * 1000, avg_time_per_urn
        )
        
        return {
            'batch_id': batch_id,
            'total_processed': len(urns),
            'successful_parses': successful_parses,
            'failed_parses': failed_parses,
            'success_rate': (successful_parses / len(urns) * 100) if urns else 0,
            'total_time_ms': total_time * 1000,
            'average_time_per_urn_ms': avg_time_per_urn,
            'results': results
        }
    
    async def update_database_with_parsed_data(self, batch_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update database with parsed URN components
        
        Args:
            batch_results: Results from parse_batch_urns
            
        Returns:
            Update statistics
        """
        if not self.session_factory:
            raise RuntimeError("Service not initialized")
        
        logger.info(f"Updating database with parsed data for batch: {batch_results['batch_id']}")
        
        updated_records = 0
        failed_updates = 0
        
        async with self.session_factory() as session:
            try:
                for result in batch_results['results']:
                    if not result.get('success'):
                        failed_updates += 1
                        continue
                    
                    urn = result['urn']
                    parsed = result['parsed_components']
                    description = result['description']
                    
                    # Map parsed components to database columns
                    update_data = {
                        'urn_type': parsed.get('urn_type'),
                        'country': parsed.get('country'),
                        'state_parsed': parsed.get('state'),
                        'municipality_parsed': parsed.get('municipality'),
                        'justice_type': parsed.get('justice'),
                        'judicial_region': parsed.get('region'),
                        'court_class': parsed.get('court_class'),
                        'document_type_full': parsed.get('document_type_full'),
                        'document_description': description,
                        'urn_parsing_version': '1.0'
                    }
                    
                    # Handle dates
                    if parsed.get('promulgation_date'):
                        try:
                            # Parse date string to date object
                            date_str = parsed['promulgation_date']
                            if '-' in date_str:
                                # DD-MM-YYYY format
                                day, month, year = date_str.split('-')
                                date_obj = datetime(int(year), int(month), int(day)).date()
                                
                                if parsed.get('urn_type') == 'jurisprudence':
                                    update_data['publication_date_parsed'] = date_obj
                                else:
                                    update_data['promulgation_date'] = date_obj
                        except Exception as e:
                            logger.warning(f"Failed to parse date {parsed.get('promulgation_date')}: {e}")
                    
                    # Filter out None values
                    update_data = {k: v for k, v in update_data.items() if v is not None}
                    
                    if update_data:
                        # Build update query
                        set_clause = ', '.join([f"{k} = :{k}" for k in update_data.keys()])
                        query = text(f"""
                            UPDATE private_legislative_documents 
                            SET {set_clause}, updated_at = NOW()
                            WHERE urn = :urn
                        """)
                        
                        # Execute update
                        await session.execute(query, {**update_data, 'urn': urn})
                        updated_records += 1
                
                await session.commit()
                
                # Update analytics
                await self._update_analytics(session)
                
                logger.info(f"Database update completed: {updated_records} records updated, {failed_updates} failed")
                
                return {
                    'batch_id': batch_results['batch_id'],
                    'updated_records': updated_records,
                    'failed_updates': failed_updates,
                    'update_success_rate': (updated_records / (updated_records + failed_updates) * 100) if (updated_records + failed_updates) > 0 else 0
                }
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Error updating database: {e}")
                raise
    
    async def process_existing_urns(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        Process existing URNs in the database that haven't been parsed yet
        
        Args:
            limit: Maximum number of URNs to process (None for all)
            
        Returns:
            Processing results
        """
        if not self.session_factory:
            raise RuntimeError("Service not initialized")
        
        logger.info("Starting processing of existing URNs in database")
        
        async with self.session_factory() as session:
            # Get URNs that need parsing
            query = text("""
                SELECT urn FROM private_legislative_documents 
                WHERE urn_type IS NULL OR urn_parsing_version IS NULL
                ORDER BY collected_at DESC
            """)
            
            if limit:
                query = text(f"{query} LIMIT {limit}")
            
            result = await session.execute(query)
            urns = [row[0] for row in result.fetchall()]
            
            if not urns:
                logger.info("No URNs found that need parsing")
                return {
                    'message': 'No URNs need parsing',
                    'processed': 0
                }
            
            logger.info(f"Found {len(urns)} URNs that need parsing")
            
            # Parse the URNs
            batch_results = await self.parse_batch_urns(urns)
            
            # Update database
            update_results = await self.update_database_with_parsed_data(batch_results)
            
            return {
                'urns_found': len(urns),
                'parsing_results': batch_results,
                'update_results': update_results
            }
    
    async def get_parsing_analytics(self, days_back: int = 30) -> Dict[str, Any]:
        """
        Get URN parsing analytics and statistics
        
        Args:
            days_back: Number of days to look back for analytics
            
        Returns:
            Analytics data
        """
        if not self.session_factory:
            raise RuntimeError("Service not initialized")
        
        async with self.session_factory() as session:
            # Get latest analytics
            analytics_query = text("""
                SELECT * FROM urn_parsing_analytics 
                WHERE analysis_date >= CURRENT_DATE - INTERVAL '%s days'
                ORDER BY analysis_date DESC
            """)
            
            analytics_result = await session.execute(analytics_query, (days_back,))
            analytics_data = [dict(row._mapping) for row in analytics_result.fetchall()]
            
            # Get performance data
            performance_query = text("""
                SELECT 
                    DATE(processing_timestamp) as date,
                    SUM(records_processed) as total_processed,
                    SUM(records_successfully_parsed) as total_successful,
                    AVG(average_parsing_time_ms) as avg_parsing_time,
                    SUM(errors_count) as total_errors
                FROM urn_parsing_performance 
                WHERE processing_timestamp >= CURRENT_DATE - INTERVAL '%s days'
                GROUP BY DATE(processing_timestamp)
                ORDER BY date DESC
            """)
            
            performance_result = await session.execute(performance_query, (days_back,))
            performance_data = [dict(row._mapping) for row in performance_result.fetchall()]
            
            # Get current status
            status_query = text("""
                SELECT 
                    COUNT(*) as total_documents,
                    COUNT(*) FILTER (WHERE urn_type = 'legislation') as legislation_count,
                    COUNT(*) FILTER (WHERE urn_type = 'jurisprudence') as jurisprudence_count,
                    COUNT(*) FILTER (WHERE urn_type IS NULL) as unparsed_count,
                    ROUND(COUNT(*) FILTER (WHERE urn_type IS NOT NULL) * 100.0 / COUNT(*), 2) as parsing_coverage
                FROM private_legislative_documents
            """)
            
            status_result = await session.execute(status_query)
            status_data = dict(status_result.fetchone()._mapping)
            
            return {
                'current_status': status_data,
                'daily_analytics': analytics_data,
                'performance_history': performance_data,
                'generated_at': datetime.now().isoformat()
            }
    
    async def _log_batch_performance(self, batch_id: str, total: int, successful: int, 
                                   failed: int, total_time_ms: float, avg_time_ms: float):
        """Log batch performance metrics to database"""
        if not self.session_factory:
            return
        
        try:
            async with self.session_factory() as session:
                query = text("""
                    INSERT INTO urn_parsing_performance 
                    (batch_id, records_processed, records_successfully_parsed, 
                     average_parsing_time_ms, errors_count)
                    VALUES (:batch_id, :total, :successful, :avg_time, :failed)
                """)
                
                await session.execute(query, {
                    'batch_id': batch_id,
                    'total': total,
                    'successful': successful,
                    'avg_time': avg_time_ms,
                    'failed': failed
                })
                
                await session.commit()
                
        except Exception as e:
            logger.error(f"Failed to log batch performance: {e}")
    
    async def _update_analytics(self, session: AsyncSession):
        """Update URN parsing analytics"""
        try:
            await session.execute(text("SELECT update_urn_parsing_analytics()"))
        except Exception as e:
            logger.error(f"Failed to update analytics: {e}")


# API Endpoints for Flask/FastAPI integration
class URNParserAPI:
    """
    API wrapper for URN Parser Service
    """
    
    def __init__(self, database_url: str):
        self.service = URNParserService(database_url)
    
    async def initialize(self):
        """Initialize the service"""
        return await self.service.initialize()
    
    async def parse_urn_endpoint(self, urn: str) -> Dict[str, Any]:
        """
        API endpoint: Parse single URN
        POST /api/urn/parse
        """
        try:
            result = await self.service.parse_single_urn(urn)
            return {
                'status': 'success' if result['success'] else 'error',
                'data': result
            }
        except Exception as e:
            logger.error(f"API error parsing URN: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def parse_batch_endpoint(self, urns: List[str]) -> Dict[str, Any]:
        """
        API endpoint: Parse batch of URNs
        POST /api/urn/parse-batch
        """
        try:
            if len(urns) > 1000:
                return {
                    'status': 'error',
                    'error': 'Batch size too large (max 1000 URNs)'
                }
            
            result = await self.service.parse_batch_urns(urns)
            return {
                'status': 'success',
                'data': result
            }
        except Exception as e:
            logger.error(f"API error parsing batch: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def process_existing_endpoint(self, limit: Optional[int] = None) -> Dict[str, Any]:
        """
        API endpoint: Process existing URNs in database
        POST /api/urn/process-existing
        """
        try:
            result = await self.service.process_existing_urns(limit)
            return {
                'status': 'success',
                'data': result
            }
        except Exception as e:
            logger.error(f"API error processing existing URNs: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }
    
    async def analytics_endpoint(self, days_back: int = 30) -> Dict[str, Any]:
        """
        API endpoint: Get parsing analytics
        GET /api/urn/analytics
        """
        try:
            result = await self.service.get_parsing_analytics(days_back)
            return {
                'status': 'success',
                'data': result
            }
        except Exception as e:
            logger.error(f"API error getting analytics: {e}")
            return {
                'status': 'error',
                'error': str(e)
            }


# CLI interface for standalone usage
async def main():
    """CLI interface for testing and manual operations"""
    import argparse
    
    parser = argparse.ArgumentParser(description='URN Parser Service CLI')
    parser.add_argument('--database-url', required=True, help='Database connection URL')
    parser.add_argument('--action', choices=['parse', 'process-existing', 'analytics'], 
                       required=True, help='Action to perform')
    parser.add_argument('--urn', help='Single URN to parse')
    parser.add_argument('--csv-file', help='CSV file with URN column')
    parser.add_argument('--limit', type=int, help='Limit for processing existing URNs')
    
    args = parser.parse_args()
    
    # Initialize service
    service = URNParserService(args.database_url)
    await service.initialize()
    
    if args.action == 'parse':
        if args.urn:
            result = await service.parse_single_urn(args.urn)
            print(json.dumps(result, indent=2, default=str))
        elif args.csv_file:
            df = pd.read_csv(args.csv_file)
            if 'urn' not in df.columns:
                print("Error: CSV file must have 'urn' column")
                return
            
            urns = df['urn'].dropna().tolist()
            result = await service.parse_batch_urns(urns)
            print(json.dumps(result, indent=2, default=str))
        else:
            print("Error: Must provide --urn or --csv-file for parse action")
    
    elif args.action == 'process-existing':
        result = await service.process_existing_urns(args.limit)
        print(json.dumps(result, indent=2, default=str))
    
    elif args.action == 'analytics':
        result = await service.get_parsing_analytics()
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main()) 