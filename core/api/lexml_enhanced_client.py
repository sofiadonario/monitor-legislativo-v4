"""
Enhanced LexML Brasil Client with Advanced Patterns
==================================================

Enhanced implementation of LexML client with patterns from py-lexml-acervo:
- Automatic pagination handling with configurable batch sizes
- Robust error handling with exponential backoff
- Metadata caching for improved performance
- Batch document processing capabilities
- Connection pooling and session management
- Progress tracking for large queries

Based on patterns from:
- py-lexml-acervo: Automatic pagination and batch processing
- Monitor Legislativo v4 production requirements
"""

import asyncio
import time
import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, AsyncIterator, Callable
from dataclasses import dataclass, asdict
import logging
from functools import wraps

from .lexml_official_client import LexMLOfficialClient, LexMLRateLimiter
from ..models.lexml_official_models import LexMLDocument, LexMLSearchResponse

logger = logging.getLogger(__name__)


@dataclass
class PaginationConfig:
    """Configuration for automatic pagination"""
    batch_size: int = 50  # Records per request
    max_total_records: int = 5000  # Maximum total records to fetch
    concurrent_requests: int = 3  # Concurrent pagination requests
    delay_between_batches: float = 0.5  # Seconds between batches


@dataclass
class CacheConfig:
    """Configuration for metadata caching"""
    enabled: bool = True
    ttl_seconds: int = 3600  # 1 hour default TTL
    max_entries: int = 10000
    cache_prefix: str = "lexml_meta:"


@dataclass
class RetryConfig:
    """Configuration for retry logic"""
    max_retries: int = 3
    initial_backoff: float = 1.0
    max_backoff: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True


class MetadataCache:
    """In-memory metadata cache with TTL support"""
    
    def __init__(self, config: CacheConfig):
        self.config = config
        self.cache: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
    
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached metadata if not expired"""
        if not self.config.enabled:
            return None
            
        async with self._lock:
            if key in self.cache:
                entry = self.cache[key]
                if time.time() < entry['expires_at']:
                    logger.debug(f"Cache hit for key: {key}")
                    return entry['data']
                else:
                    # Remove expired entry
                    del self.cache[key]
                    logger.debug(f"Cache expired for key: {key}")
            return None
    
    async def set(self, key: str, data: Dict[str, Any]):
        """Set cached metadata with TTL"""
        if not self.config.enabled:
            return
            
        async with self._lock:
            # Enforce max entries limit
            if len(self.cache) >= self.config.max_entries:
                # Remove oldest entries
                sorted_keys = sorted(self.cache.keys(), 
                                   key=lambda k: self.cache[k]['expires_at'])
                for old_key in sorted_keys[:len(self.cache) - self.config.max_entries + 1]:
                    del self.cache[old_key]
            
            self.cache[key] = {
                'data': data,
                'expires_at': time.time() + self.config.ttl_seconds
            }
            logger.debug(f"Cache set for key: {key}")
    
    def generate_key(self, query: str, filters: Dict[str, Any]) -> str:
        """Generate cache key from query and filters"""
        key_data = f"{query}:{json.dumps(filters, sort_keys=True)}"
        return f"{self.config.cache_prefix}{hashlib.md5(key_data.encode()).hexdigest()}"


def with_retry(retry_config: RetryConfig):
    """Decorator for adding retry logic with exponential backoff"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(retry_config.max_retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    if attempt < retry_config.max_retries - 1:
                        # Calculate backoff time
                        backoff = min(
                            retry_config.initial_backoff * (retry_config.exponential_base ** attempt),
                            retry_config.max_backoff
                        )
                        
                        # Add jitter if enabled
                        if retry_config.jitter:
                            import random
                            backoff *= (0.5 + random.random())
                        
                        logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {backoff:.2f}s")
                        await asyncio.sleep(backoff)
                    else:
                        logger.error(f"All {retry_config.max_retries} attempts failed")
            
            raise last_exception
        return wrapper
    return decorator


class LexMLEnhancedClient:
    """
    Enhanced LexML client with advanced patterns for production use
    
    Features:
    - Automatic pagination with concurrent batch processing
    - Metadata caching to reduce API calls
    - Robust retry logic with exponential backoff
    - Batch document processing with progress tracking
    - Connection pooling and session reuse
    """
    
    def __init__(self, 
                 base_client: Optional[LexMLOfficialClient] = None,
                 pagination_config: Optional[PaginationConfig] = None,
                 cache_config: Optional[CacheConfig] = None,
                 retry_config: Optional[RetryConfig] = None):
        """
        Initialize enhanced client
        
        Args:
            base_client: Existing LexML client instance
            pagination_config: Pagination configuration
            cache_config: Cache configuration
            retry_config: Retry configuration
        """
        self.base_client = base_client or LexMLOfficialClient()
        self.pagination_config = pagination_config or PaginationConfig()
        self.cache_config = cache_config or CacheConfig()
        self.retry_config = retry_config or RetryConfig()
        
        # Initialize cache
        self.metadata_cache = MetadataCache(self.cache_config)
        
        # Progress tracking
        self.current_progress: Dict[str, Any] = {}
        
        logger.info("Enhanced LexML client initialized")
    
    @with_retry(RetryConfig())
    async def search_with_pagination(self, 
                                   query: str,
                                   max_records: Optional[int] = None,
                                   progress_callback: Optional[Callable[[int, int], None]] = None,
                                   **filters) -> List[LexMLDocument]:
        """
        Search with automatic pagination
        
        Args:
            query: Search query
            max_records: Maximum records to fetch (overrides pagination config)
            progress_callback: Callback for progress updates (current, total)
            **filters: Additional search filters
            
        Returns:
            List of all documents from paginated results
        """
        max_records = max_records or self.pagination_config.max_total_records
        all_documents: List[LexMLDocument] = []
        
        # Check cache first
        cache_key = self.metadata_cache.generate_key(query, filters)
        cached_result = await self.metadata_cache.get(cache_key)
        
        if cached_result and 'document_count' in cached_result:
            logger.info(f"Using cached metadata for query: {query}")
            total_count = cached_result['document_count']
        else:
            # Get initial result to determine total count
            initial_response = await self.base_client.search(
                query, max_records=1, start_record=1
            )
            total_count = initial_response.total_count
            
            # Cache the metadata
            await self.metadata_cache.set(cache_key, {
                'document_count': total_count,
                'query': query,
                'timestamp': datetime.now().isoformat()
            })
        
        # Calculate pagination parameters
        total_to_fetch = min(total_count, max_records)
        batch_size = self.pagination_config.batch_size
        total_batches = (total_to_fetch + batch_size - 1) // batch_size
        
        logger.info(f"Starting paginated search: {total_to_fetch} records in {total_batches} batches")
        
        # Track progress
        self.current_progress = {
            'query': query,
            'total_records': total_to_fetch,
            'fetched_records': 0,
            'start_time': time.time()
        }
        
        # Create batch tasks
        batch_tasks = []
        for batch_num in range(total_batches):
            start_record = batch_num * batch_size + 1
            records_in_batch = min(batch_size, total_to_fetch - batch_num * batch_size)
            
            batch_tasks.append(
                self._fetch_batch(query, start_record, records_in_batch, 
                                progress_callback, **filters)
            )
        
        # Execute batches with concurrency limit
        semaphore = asyncio.Semaphore(self.pagination_config.concurrent_requests)
        
        async def limited_fetch(task):
            async with semaphore:
                return await task
        
        # Process batches
        batch_results = await asyncio.gather(
            *[limited_fetch(task) for task in batch_tasks],
            return_exceptions=True
        )
        
        # Collect results
        for i, result in enumerate(batch_results):
            if isinstance(result, Exception):
                logger.error(f"Batch {i} failed: {result}")
            elif isinstance(result, list):
                all_documents.extend(result)
        
        # Update final progress
        self.current_progress['fetched_records'] = len(all_documents)
        self.current_progress['duration'] = time.time() - self.current_progress['start_time']
        
        logger.info(f"Pagination complete: {len(all_documents)} documents fetched")
        
        return all_documents
    
    async def _fetch_batch(self, 
                          query: str, 
                          start_record: int, 
                          max_records: int,
                          progress_callback: Optional[Callable[[int, int], None]] = None,
                          **filters) -> List[LexMLDocument]:
        """Fetch a single batch of records"""
        try:
            # Add delay between batches
            if start_record > 1:
                await asyncio.sleep(self.pagination_config.delay_between_batches)
            
            response = await self.base_client.search(
                query, max_records=max_records, start_record=start_record
            )
            
            # Update progress
            self.current_progress['fetched_records'] += len(response.documents)
            
            if progress_callback:
                progress_callback(
                    self.current_progress['fetched_records'],
                    self.current_progress['total_records']
                )
            
            logger.debug(f"Batch fetched: {len(response.documents)} documents from position {start_record}")
            
            return response.documents
            
        except Exception as e:
            logger.error(f"Batch fetch failed for start_record={start_record}: {e}")
            raise
    
    async def search_documents_stream(self, 
                                    query: str,
                                    batch_size: Optional[int] = None,
                                    **filters) -> AsyncIterator[LexMLDocument]:
        """
        Stream search results with automatic pagination
        
        Yields documents as they are fetched, suitable for processing large result sets
        without loading all into memory.
        
        Args:
            query: Search query
            batch_size: Override default batch size
            **filters: Additional search filters
            
        Yields:
            LexMLDocument instances as they are fetched
        """
        batch_size = batch_size or self.pagination_config.batch_size
        start_record = 1
        has_more = True
        
        while has_more:
            try:
                response = await self.base_client.search(
                    query, max_records=batch_size, start_record=start_record
                )
                
                # Yield documents from this batch
                for document in response.documents:
                    yield document
                
                # Check if there are more records
                if response.next_record_position:
                    start_record = response.next_record_position
                    has_more = True
                else:
                    has_more = False
                
                # Delay between batches
                if has_more:
                    await asyncio.sleep(self.pagination_config.delay_between_batches)
                    
            except Exception as e:
                logger.error(f"Stream batch failed at position {start_record}: {e}")
                break
    
    async def batch_process_documents(self,
                                    queries: List[str],
                                    processor: Callable[[LexMLDocument], Any],
                                    concurrent_queries: int = 3) -> Dict[str, List[Any]]:
        """
        Process multiple queries in parallel with document processing
        
        Args:
            queries: List of search queries
            processor: Function to process each document
            concurrent_queries: Number of concurrent queries
            
        Returns:
            Dictionary mapping queries to processed results
        """
        results = {}
        
        async def process_query(query: str) -> List[Any]:
            """Process single query and its documents"""
            processed = []
            
            async for document in self.search_documents_stream(query):
                try:
                    result = await asyncio.to_thread(processor, document)
                    processed.append(result)
                except Exception as e:
                    logger.error(f"Document processing failed: {e}")
            
            return processed
        
        # Create tasks for all queries
        tasks = {query: process_query(query) for query in queries}
        
        # Execute with concurrency limit
        semaphore = asyncio.Semaphore(concurrent_queries)
        
        async def limited_process(query: str, task):
            async with semaphore:
                return query, await task
        
        # Process all queries
        query_results = await asyncio.gather(
            *[limited_process(query, task) for query, task in tasks.items()],
            return_exceptions=True
        )
        
        # Collect results
        for result in query_results:
            if isinstance(result, tuple):
                query, processed = result
                results[query] = processed
            else:
                logger.error(f"Query processing failed: {result}")
        
        return results
    
    async def get_search_statistics(self) -> Dict[str, Any]:
        """Get current search and cache statistics"""
        cache_stats = {
            'cache_enabled': self.cache_config.enabled,
            'cache_entries': len(self.metadata_cache.cache),
            'cache_ttl_seconds': self.cache_config.ttl_seconds
        }
        
        search_stats = {
            'current_progress': self.current_progress,
            'pagination_config': asdict(self.pagination_config),
            'retry_config': asdict(self.retry_config)
        }
        
        return {
            'cache_statistics': cache_stats,
            'search_statistics': search_stats,
            'timestamp': datetime.now().isoformat()
        }
    
    async def warmup_cache(self, common_queries: List[str]):
        """Pre-warm cache with common queries"""
        logger.info(f"Warming up cache with {len(common_queries)} queries")
        
        for query in common_queries:
            try:
                # Just fetch first result to get metadata
                response = await self.base_client.search(query, max_records=1)
                
                # Cache the metadata
                cache_key = self.metadata_cache.generate_key(query, {})
                await self.metadata_cache.set(cache_key, {
                    'document_count': response.total_count,
                    'query': query,
                    'timestamp': datetime.now().isoformat()
                })
                
            except Exception as e:
                logger.error(f"Cache warmup failed for query '{query}': {e}")
        
        logger.info("Cache warmup complete")
    
    async def close(self):
        """Clean up resources"""
        await self.base_client.close()