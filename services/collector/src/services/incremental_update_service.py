"""
Incremental update service for efficient document collection
Manages smart scheduling, priority-based updates, and delta synchronization
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from enum import Enum

from .deduplication_service import get_deduplication_service, ChangeType
from .database_service import CollectionDatabaseService
from .lexml_client import MultiSourceCollector
from ..utils.monitoring import collection_metrics, performance_tracker
from ..utils.retry_handler import execute_with_api_retry

logger = logging.getLogger(__name__)


class UpdateStrategy(Enum):
    """Strategies for incremental updates"""
    FULL_SCAN = "full_scan"  # Full collection for new terms
    INCREMENTAL = "incremental"  # Only check for recent changes
    PRIORITY_BASED = "priority_based"  # Focus on high-priority terms
    SMART_DELTA = "smart_delta"  # Intelligent change detection


@dataclass
class UpdatePlan:
    """Plan for incremental updates"""
    search_term_id: int
    search_term: str
    strategy: UpdateStrategy
    priority: int
    last_update: Optional[datetime]
    expected_changes: int
    estimated_duration_minutes: int
    sources_to_check: List[str]
    max_records: int


class IncrementalUpdateService:
    """Service for managing incremental document updates"""
    
    def __init__(self):
        self.db_service: Optional[CollectionDatabaseService] = None
        self.dedup_service = None
        self.collector = MultiSourceCollector()
        
        # Configuration
        self.incremental_window_hours = 24  # Look for changes in last 24 hours
        self.priority_boost_factor = 2  # Boost frequency for high-priority terms
        self.max_concurrent_updates = 3
        self.smart_delta_threshold = 0.1  # Minimum change rate to trigger updates
        
    async def initialize(self):
        """Initialize the incremental update service"""
        self.db_service = CollectionDatabaseService()
        await self.db_service.initialize()
        self.dedup_service = await get_deduplication_service(self.db_service)
        
        logger.info("Incremental update service initialized")
    
    async def create_update_plan(self) -> List[UpdatePlan]:
        """Create an intelligent update plan based on term characteristics"""
        try:
            # Get all active search terms with their metadata
            search_terms = await self._get_search_terms_with_metadata()
            
            update_plans = []
            
            for term_data in search_terms:
                strategy = await self._determine_update_strategy(term_data)
                plan = await self._create_term_update_plan(term_data, strategy)
                
                if plan:
                    update_plans.append(plan)
            
            # Sort plans by priority and expected efficiency
            update_plans.sort(key=lambda p: (p.priority, -p.expected_changes), reverse=True)
            
            logger.info(f"Created update plan for {len(update_plans)} search terms")
            return update_plans
            
        except Exception as e:
            logger.error(f"Error creating update plan: {e}")
            return []
    
    async def execute_incremental_updates(self, max_terms: int = 10) -> Dict[str, Any]:
        """Execute incremental updates for multiple search terms"""
        execution_start = datetime.now()
        
        stats = {
            'execution_start': execution_start.isoformat(),
            'terms_processed': 0,
            'terms_updated': 0,
            'total_documents_collected': 0,
            'total_documents_new': 0,
            'total_documents_updated': 0,
            'total_execution_time_ms': 0,
            'strategy_breakdown': {},
            'source_breakdown': {},
            'errors': []
        }
        
        try:
            # Create update plan
            update_plans = await self.create_update_plan()
            
            # Limit to max_terms
            limited_plans = update_plans[:max_terms]
            
            # Execute updates with concurrency control
            semaphore = asyncio.Semaphore(self.max_concurrent_updates)
            
            tasks = []
            for plan in limited_plans:
                task = self._execute_single_update_with_semaphore(semaphore, plan)
                tasks.append(task)
            
            # Wait for all updates to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    error_info = {
                        'search_term_id': limited_plans[i].search_term_id,
                        'error': str(result),
                        'timestamp': datetime.now().isoformat()
                    }
                    stats['errors'].append(error_info)
                    logger.error(f"Update failed for term {limited_plans[i].search_term_id}: {result}")
                else:
                    # Aggregate statistics
                    stats['terms_processed'] += 1
                    if result.get('documents_collected', 0) > 0:
                        stats['terms_updated'] += 1
                    
                    stats['total_documents_collected'] += result.get('documents_collected', 0)
                    stats['total_documents_new'] += result.get('documents_new', 0)
                    stats['total_documents_updated'] += result.get('documents_updated', 0)
                    
                    # Track strategy usage
                    strategy = result.get('strategy')
                    if strategy:
                        stats['strategy_breakdown'][strategy] = stats['strategy_breakdown'].get(strategy, 0) + 1
                    
                    # Track source usage
                    for source in result.get('sources_used', []):
                        stats['source_breakdown'][source] = stats['source_breakdown'].get(source, 0) + 1
            
            stats['total_execution_time_ms'] = int((datetime.now() - execution_start).total_seconds() * 1000)
            
            logger.info(f"Incremental update completed: {stats}")
            return stats
            
        except Exception as e:
            stats['total_execution_time_ms'] = int((datetime.now() - execution_start).total_seconds() * 1000)
            stats['errors'].append({
                'error': f"Global execution error: {str(e)}",
                'timestamp': datetime.now().isoformat()
            })
            logger.error(f"Error in incremental updates execution: {e}")
            return stats
    
    async def _execute_single_update_with_semaphore(self, semaphore: asyncio.Semaphore, 
                                                   plan: UpdatePlan) -> Dict[str, Any]:
        """Execute single update with concurrency control"""
        async with semaphore:
            return await self._execute_single_update(plan)
    
    async def _execute_single_update(self, plan: UpdatePlan) -> Dict[str, Any]:
        """Execute update for a single search term according to plan"""
        update_start = datetime.now()
        operation_id = f"incremental_update_{plan.search_term_id}"
        
        performance_tracker.start_operation(operation_id, "incremental_update")
        
        result = {
            'search_term_id': plan.search_term_id,
            'search_term': plan.search_term,
            'strategy': plan.strategy.value,
            'documents_collected': 0,
            'documents_new': 0,
            'documents_updated': 0,
            'sources_used': [],
            'execution_time_ms': 0,
            'change_detection_stats': {}
        }
        
        try:
            logger.info(f"Starting incremental update for term '{plan.search_term}' using {plan.strategy.value}")
            
            # Collect documents based on strategy
            if plan.strategy == UpdateStrategy.INCREMENTAL:
                documents = await self._collect_incremental_documents(plan)
            elif plan.strategy == UpdateStrategy.SMART_DELTA:
                documents = await self._collect_smart_delta_documents(plan)
            else:
                documents = await self._collect_full_documents(plan)
            
            if documents:
                # Process with deduplication service
                dedup_stats = await self.dedup_service.process_document_batch(
                    documents, plan.search_term_id, "incremental_update"
                )
                
                result['documents_collected'] = len(documents)
                result['documents_new'] = dedup_stats.get('new_documents', 0)
                result['documents_updated'] = dedup_stats.get('updated_documents', 0)
                result['change_detection_stats'] = dedup_stats
                
                # Update search term's last collection time
                await self._update_search_term_timestamp(plan.search_term_id)
                
                # Track metrics
                collection_metrics.complete_collection(
                    "incremental_update",
                    result['documents_collected'],
                    int((datetime.now() - update_start).total_seconds() * 1000)
                )
            
            result['execution_time_ms'] = int((datetime.now() - update_start).total_seconds() * 1000)
            performance_tracker.end_operation(operation_id, "completed")
            
            logger.info(f"Incremental update completed for '{plan.search_term}': {result['documents_collected']} docs")
            
        except Exception as e:
            result['execution_time_ms'] = int((datetime.now() - update_start).total_seconds() * 1000)
            performance_tracker.end_operation(operation_id, "failed")
            logger.error(f"Error in incremental update for '{plan.search_term}': {e}")
            raise
        
        return result
    
    async def _collect_incremental_documents(self, plan: UpdatePlan) -> List[Dict[str, Any]]:
        """Collect documents using incremental strategy (recent changes only)"""
        documents = []
        
        # Calculate date range for incremental collection
        end_date = datetime.now()
        start_date = plan.last_update or (end_date - timedelta(hours=self.incremental_window_hours))
        
        try:
            # Build query with date filter
            base_query = plan.search_term
            date_filter = f" AND dc.date >= \"{start_date.strftime('%Y-%m-%d')}\""
            
            # Collect from prioritized sources
            for source in plan.sources_to_check[:3]:  # Limit to top 3 sources
                try:
                    if source == 'lexml':
                        client = self.collector.clients[source]
                        source_docs = await client.collect_documents(
                            base_query + date_filter,
                            max_records=plan.max_records // len(plan.sources_to_check)
                        )
                    else:
                        async with self.collector.clients[source]:
                            source_docs = await self.collector.clients[source].search(
                                base_query,
                                limit=plan.max_records // len(plan.sources_to_check)
                            )
                    
                    if source_docs:
                        # Add source information
                        for doc in source_docs:
                            doc['source_api'] = source
                        documents.extend(source_docs)
                        
                except Exception as e:
                    logger.warning(f"Error collecting from {source} for incremental update: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"Error in incremental collection: {e}")
        
        return documents
    
    async def _collect_smart_delta_documents(self, plan: UpdatePlan) -> List[Dict[str, Any]]:
        """Collect documents using smart delta strategy (change-aware sampling)"""
        documents = []
        
        try:
            # Sample a small number of recent documents to check for changes
            sample_size = min(50, plan.max_records // 4)
            
            # Get recent sample from primary source
            primary_source = plan.sources_to_check[0] if plan.sources_to_check else 'lexml'
            
            if primary_source == 'lexml':
                client = self.collector.clients[primary_source]
                sample_docs = await client.collect_documents(
                    plan.search_term,
                    max_records=sample_size
                )
            else:
                async with self.collector.clients[primary_source]:
                    sample_docs = await self.collector.clients[primary_source].search(
                        plan.search_term,
                        limit=sample_size
                    )
            
            if sample_docs:
                # Analyze change patterns in sample
                change_rate = await self._analyze_change_rate(sample_docs, plan.search_term_id)
                
                # If significant changes detected, do a broader collection
                if change_rate > self.smart_delta_threshold:
                    logger.info(f"High change rate ({change_rate:.2f}) detected, expanding collection")
                    
                    # Collect more documents from multiple sources
                    for source in plan.sources_to_check:
                        try:
                            if source == 'lexml':
                                client = self.collector.clients[source]
                                source_docs = await client.collect_documents(
                                    plan.search_term,
                                    max_records=plan.max_records // len(plan.sources_to_check)
                                )
                            else:
                                async with self.collector.clients[source]:
                                    source_docs = await self.collector.clients[source].search(
                                        plan.search_term,
                                        limit=plan.max_records // len(plan.sources_to_check)
                                    )
                            
                            if source_docs:
                                for doc in source_docs:
                                    doc['source_api'] = source
                                documents.extend(source_docs)
                                
                        except Exception as e:
                            logger.warning(f"Error collecting from {source}: {e}")
                            continue
                else:
                    # Low change rate, just use the sample
                    for doc in sample_docs:
                        doc['source_api'] = primary_source
                    documents = sample_docs
            
        except Exception as e:
            logger.error(f"Error in smart delta collection: {e}")
        
        return documents
    
    async def _collect_full_documents(self, plan: UpdatePlan) -> List[Dict[str, Any]]:
        """Collect documents using full strategy (complete collection)"""
        documents = []
        
        try:
            # Use multi-source collector
            results = await self.collector.collect_from_all_sources(
                plan.search_term,
                max_records_per_source=plan.max_records // len(plan.sources_to_check)
            )
            
            # Flatten results and add source information
            for source, source_docs in results.items():
                for doc in source_docs:
                    doc['source_api'] = source
                documents.extend(source_docs)
            
        except Exception as e:
            logger.error(f"Error in full collection: {e}")
        
        return documents
    
    async def _analyze_change_rate(self, sample_docs: List[Dict[str, Any]], 
                                 search_term_id: int) -> float:
        """Analyze change rate in sample documents"""
        if not sample_docs:
            return 0.0
        
        try:
            # Quick deduplication analysis on sample
            temp_stats = await self.dedup_service.process_document_batch(
                sample_docs[:10],  # Small sample for analysis
                search_term_id,
                "change_analysis"
            )
            
            total_docs = temp_stats.get('total_processed', 1)
            changed_docs = (temp_stats.get('new_documents', 0) + 
                          temp_stats.get('updated_documents', 0) +
                          temp_stats.get('content_changes', 0))
            
            change_rate = changed_docs / total_docs if total_docs > 0 else 0.0
            return change_rate
            
        except Exception as e:
            logger.error(f"Error analyzing change rate: {e}")
            return 0.5  # Default to moderate change rate
    
    async def _get_search_terms_with_metadata(self) -> List[Dict[str, Any]]:
        """Get search terms with collection metadata"""
        try:
            async with self.db_service.pool.acquire() as conn:
                rows = await conn.fetch("""
                    SELECT 
                        st.id, st.term, st.category, st.cql_query,
                        st.collection_frequency, st.priority, st.active,
                        st.last_collection, st.next_collection,
                        COUNT(ld.id) as total_documents,
                        AVG(CASE WHEN cl.status = 'completed' THEN 1.0 ELSE 0.0 END) as success_rate,
                        MAX(cl.completed_at) as last_successful_collection,
                        AVG(cl.execution_time_ms) as avg_execution_time
                    FROM search_terms st
                    LEFT JOIN legislative_documents ld ON st.id = ld.search_term_id
                    LEFT JOIN collection_logs cl ON st.id = cl.search_term_id 
                        AND cl.completed_at >= NOW() - INTERVAL '30 days'
                    WHERE st.active = true
                    GROUP BY st.id, st.term, st.category, st.cql_query,
                             st.collection_frequency, st.priority, st.active,
                             st.last_collection, st.next_collection
                    ORDER BY st.priority ASC, st.last_collection ASC NULLS FIRST
                """)
                
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting search terms metadata: {e}")
            return []
    
    async def _determine_update_strategy(self, term_data: Dict[str, Any]) -> UpdateStrategy:
        """Determine the best update strategy for a search term"""
        last_collection = term_data.get('last_collection')
        total_documents = term_data.get('total_documents', 0)
        success_rate = term_data.get('success_rate', 0.0)
        priority = term_data.get('priority', 5)
        
        # New terms get full scan
        if not last_collection or total_documents == 0:
            return UpdateStrategy.FULL_SCAN
        
        # High priority terms get more frequent updates
        if priority <= 2:
            return UpdateStrategy.PRIORITY_BASED
        
        # Terms with good success rate and recent data get smart delta
        days_since_collection = (datetime.now() - last_collection).days if last_collection else 999
        if success_rate > 0.8 and days_since_collection <= 7:
            return UpdateStrategy.SMART_DELTA
        
        # Default to incremental for most terms
        return UpdateStrategy.INCREMENTAL
    
    async def _create_term_update_plan(self, term_data: Dict[str, Any], 
                                     strategy: UpdateStrategy) -> Optional[UpdatePlan]:
        """Create update plan for a specific term"""
        try:
            search_term_id = term_data['id']
            search_term = term_data['term']
            priority = term_data.get('priority', 5)
            last_collection = term_data.get('last_collection')
            total_documents = term_data.get('total_documents', 0)
            
            # Estimate expected changes based on historical data
            expected_changes = await self._estimate_expected_changes(term_data, strategy)
            
            # Determine sources to check
            sources_to_check = await self._select_optimal_sources(term_data)
            
            # Calculate max records based on strategy
            if strategy == UpdateStrategy.FULL_SCAN:
                max_records = 500
            elif strategy == UpdateStrategy.PRIORITY_BASED:
                max_records = 200
            elif strategy == UpdateStrategy.SMART_DELTA:
                max_records = 100
            else:  # INCREMENTAL
                max_records = 150
            
            # Estimate duration
            estimated_duration = max(5, max_records // 30)  # Rough estimate
            
            return UpdatePlan(
                search_term_id=search_term_id,
                search_term=search_term,
                strategy=strategy,
                priority=priority,
                last_update=last_collection,
                expected_changes=expected_changes,
                estimated_duration_minutes=estimated_duration,
                sources_to_check=sources_to_check,
                max_records=max_records
            )
            
        except Exception as e:
            logger.error(f"Error creating update plan for term {term_data.get('id')}: {e}")
            return None
    
    async def _estimate_expected_changes(self, term_data: Dict[str, Any], 
                                       strategy: UpdateStrategy) -> int:
        """Estimate expected number of changes for a term"""
        total_documents = term_data.get('total_documents', 0)
        days_since_collection = 7  # Default
        
        if term_data.get('last_collection'):
            days_since_collection = (datetime.now() - term_data['last_collection']).days
        
        # Base rate of change per day (varies by strategy)
        if strategy == UpdateStrategy.FULL_SCAN:
            daily_change_rate = 0.1  # 10% of documents might be new/changed daily
        elif strategy == UpdateStrategy.PRIORITY_BASED:
            daily_change_rate = 0.05  # 5% for priority terms
        else:
            daily_change_rate = 0.02  # 2% for incremental
        
        expected_changes = int(total_documents * daily_change_rate * min(days_since_collection, 30))
        return max(1, expected_changes)
    
    async def _select_optimal_sources(self, term_data: Dict[str, Any]) -> List[str]:
        """Select optimal sources for a search term based on category and performance"""
        category = term_data.get('category', '').lower()
        
        # Category-based source selection
        if 'transport' in category:
            return ['lexml', 'antt', 'anac', 'antaq', 'camara', 'senado']
        elif 'energy' in category or 'energia' in category:
            return ['lexml', 'aneel', 'anp', 'camara', 'senado']
        elif 'health' in category or 'saude' in category:
            return ['lexml', 'anvisa', 'ans', 'camara', 'senado']
        elif 'telecom' in category:
            return ['lexml', 'anatel', 'camara', 'senado']
        else:
            # Default sources for general terms
            return ['lexml', 'camara', 'senado', 'antt']
    
    async def _update_search_term_timestamp(self, search_term_id: int):
        """Update the last collection timestamp for a search term"""
        try:
            async with self.db_service.pool.acquire() as conn:
                await conn.execute("""
                    UPDATE search_terms 
                    SET last_collection = NOW(), updated_at = NOW()
                    WHERE id = $1
                """, search_term_id)
                
        except Exception as e:
            logger.error(f"Error updating search term timestamp: {e}")
    
    async def get_incremental_update_stats(self) -> Dict[str, Any]:
        """Get statistics about incremental update performance"""
        try:
            stats = await self.dedup_service.get_deduplication_stats() if self.dedup_service else {}
            
            # Add service-specific stats
            stats['service_status'] = 'active'
            stats['incremental_window_hours'] = self.incremental_window_hours
            stats['max_concurrent_updates'] = self.max_concurrent_updates
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting incremental update stats: {e}")
            return {}


# Global instance
incremental_service = None

async def get_incremental_service():
    """Get or create global incremental update service"""
    global incremental_service
    if incremental_service is None:
        incremental_service = IncrementalUpdateService()
        await incremental_service.initialize()
    return incremental_service