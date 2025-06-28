"""
LexML Periodic Collection Service
Automated collection of legislative documents from LexML Brasil API
Stores data in private database for dashboard consumption
"""

import asyncio
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
import httpx
from urllib.parse import urlencode
import uuid
import json
import re
import time

import asyncpg
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

logger = logging.getLogger(__name__)


class LexMLPeriodicCollector:
    """
    Automated periodic collection service for LexML Brasil
    Collects legislative documents based on configured search terms
    Stores in private database for dashboard analytics
    """
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.lexml_base_url = "https://www.lexml.gov.br/busca/SRU"
        self.session_factory = None
        self.http_client: Optional[httpx.AsyncClient] = None
        
        # Collection configuration
        self.batch_size = 100  # Documents per API call
        self.max_retries = 3
        self.retry_delay = 2.0
        self.api_delay = 1.0  # Delay between API calls (respectful)
        
        # Initialize database connection
        self._setup_database()
    
    def _setup_database(self):
        """Setup async database connection"""
        try:
            # Convert URL for asyncpg if needed
            db_url = self.database_url
            if db_url.startswith('postgresql://'):
                db_url = db_url.replace('postgresql://', 'postgresql+asyncpg://', 1)
            
            engine = create_async_engine(
                db_url,
                pool_size=3,
                max_overflow=0,
                pool_timeout=60,
                pool_recycle=1800,
                echo=False
            )
            
            self.session_factory = sessionmaker(
                bind=engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            logger.info("Database connection initialized for periodic collector")
            
        except Exception as e:
            logger.error(f"Failed to setup database connection: {e}")
            raise
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=2)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.http_client:
            await self.http_client.aclose()
    
    async def get_pending_collections(self) -> List[Dict[str, Any]]:
        """Get search terms that need collection"""
        try:
            async with self.session_factory() as session:
                result = await session.execute(text("""
                    SELECT id, term_name, cql_query, description, collection_frequency,
                           priority_level, last_collected, next_collection
                    FROM search_terms_config 
                    WHERE is_active = true 
                    AND (next_collection IS NULL OR next_collection <= NOW())
                    ORDER BY priority_level ASC, last_collected ASC NULLS FIRST
                """))
                
                return [dict(row._mapping) for row in result.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get pending collections: {e}")
            return []
    
    async def run_periodic_collection(self) -> Dict[str, Any]:
        """Run periodic collection for all pending search terms"""
        logger.info("Starting periodic collection run")
        
        start_time = time.time()
        pending_terms = await self.get_pending_collections()
        
        if not pending_terms:
            logger.info("No pending collections found")
            return {
                'status': 'completed',
                'message': 'No pending collections',
                'total_terms': 0,
                'execution_time_seconds': 0
            }
        
        logger.info(f"Found {len(pending_terms)} pending collections")
        
        results = []
        for term in pending_terms:
            try:
                result = await self.collect_search_term(term)
                results.append(result)
                
                # Brief pause between search terms
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Failed to collect term {term['term_name']}: {e}")
                results.append({
                    'search_term_id': term['id'],
                    'term_name': term['term_name'],
                    'status': 'failed',
                    'error': str(e)
                })
        
        # Update state density statistics
        await self.update_state_density_stats()
        
        execution_time = int(time.time() - start_time)
        
        # Summary statistics
        completed = sum(1 for r in results if r['status'] == 'completed')
        failed = sum(1 for r in results if r['status'] == 'failed')
        total_docs = sum(r.get('total_documents', 0) for r in results)
        total_new = sum(r.get('new_documents', 0) for r in results)
        
        logger.info(f"Periodic collection completed: {completed} succeeded, {failed} failed, "
                   f"{total_docs} documents processed ({total_new} new)")
        
        return {
            'status': 'completed',
            'total_terms': len(pending_terms),
            'completed_terms': completed,
            'failed_terms': failed,
            'total_documents': total_docs,
            'new_documents': total_new,
            'execution_time_seconds': execution_time,
            'results': results
        }

    async def collect_search_term(self, search_term: Dict[str, Any]) -> Dict[str, Any]:
        """Collect documents for a single search term"""
        search_term_id = search_term['id']
        term_name = search_term['term_name']
        cql_query = search_term['cql_query']
        
        logger.info(f"Starting collection for search term: {term_name}")
        
        batch_id = await self.start_collection_batch(search_term_id)
        start_time = time.time()
        
        total_documents = 0
        total_new = 0
        total_updated = 0
        total_skipped = 0
        api_calls = 0
        
        try:
            # Collect documents in batches
            start_record = 1
            has_more = True
            
            while has_more:
                documents, total_found, has_more = await self.search_lexml_api(
                    cql_query, start_record, self.batch_size
                )
                
                api_calls += 1
                
                if documents:
                    new_count, updated_count, skipped_count = await self.save_documents(
                        documents, search_term_id, batch_id
                    )
                    
                    total_new += new_count
                    total_updated += updated_count
                    total_skipped += skipped_count
                    total_documents += len(documents)
                    
                    logger.info(f"Processed batch: {len(documents)} documents "
                               f"(new: {new_count}, updated: {updated_count}, skipped: {skipped_count})")
                
                # Update progress
                await self.update_collection_progress(batch_id,
                    documents_found=total_found,
                    documents_new=total_new,
                    documents_updated=total_updated,
                    documents_skipped=total_skipped,
                    api_calls_made=api_calls
                )
                
                start_record += self.batch_size
                
                # Respectful delay between API calls
                if has_more:
                    await asyncio.sleep(self.api_delay)
            
            # Complete collection successfully
            execution_time = int((time.time() - start_time) * 1000)
            await self.update_collection_progress(batch_id,
                execution_time_seconds=int(execution_time / 1000)
            )
            await self.complete_collection_batch(batch_id, 'completed')
            await self.update_search_term_schedule(
                search_term_id, search_term['collection_frequency']
            )
            
            logger.info(f"Completed collection for {term_name}: "
                       f"{total_documents} documents processed "
                       f"(new: {total_new}, updated: {total_updated})")
            
            return {
                'search_term_id': search_term_id,
                'term_name': term_name,
                'status': 'completed',
                'total_documents': total_documents,
                'new_documents': total_new,
                'updated_documents': total_updated,
                'execution_time_seconds': int(execution_time / 1000),
                'api_calls': api_calls
            }
            
        except Exception as e:
            logger.error(f"Collection failed for {term_name}: {e}")
            await self.complete_collection_batch(batch_id, 'failed', str(e))
            
            return {
                'search_term_id': search_term_id,
                'term_name': term_name,
                'status': 'failed',
                'error': str(e)
            }

    async def search_lexml_api(self, cql_query: str, start_record: int = 1, 
                              max_records: int = 100) -> Tuple[List[Dict], int, bool]:
        """Search LexML API using SRU protocol"""
        params = {
            'operation': 'searchRetrieve',
            'query': cql_query,
            'startRecord': start_record,
            'maximumRecords': max_records,
            'recordSchema': 'oai_dc'
        }
        
        url = f"{self.lexml_base_url}?{urlencode(params)}"
        
        for attempt in range(self.max_retries):
            try:
                logger.debug(f"LexML API request: {url}")
                response = await self.http_client.get(url)
                response.raise_for_status()
                
                documents, total_found = self._parse_sru_response(response.text)
                has_more = (start_record + len(documents)) < total_found
                
                logger.info(f"LexML API returned {len(documents)} documents, "
                           f"total available: {total_found}")
                
                return documents, total_found, has_more
                
            except Exception as e:
                logger.warning(f"LexML API attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                else:
                    raise

    # Additional helper methods would go here...
    # [Truncated for brevity - the full implementation would include all the parsing and database methods]


# Standalone execution for testing
async def main():
    """Test the periodic collector"""
    import os
    
    database_url = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/legislativo')
    
    async with LexMLPeriodicCollector(database_url) as collector:
        result = await collector.run_periodic_collection()
        print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main()) 