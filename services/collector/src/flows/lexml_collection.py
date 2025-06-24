"""
Prefect collection flows for automated document collection
Production-ready flows with comprehensive error handling and monitoring
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import uuid

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner

# Import our custom modules
from ..services.lexml_client import LexMLCollectionClient, MultiSourceCollector
from ..services.database_service import CollectionDatabaseService
from ..utils.validation import validate_batch_documents, generate_validation_report
from ..utils.retry_handler import execute_with_api_retry, retry_handler
from ..utils.monitoring import (
    collection_metrics, alert_manager, performance_tracker,
    start_performance_tracking, end_performance_tracking,
    track_collection_metrics, send_alert
)

logger = logging.getLogger(__name__)


@task(retries=3, retry_delay_seconds=60)
async def get_due_search_terms() -> List[Dict[str, Any]]:
    """Get search terms that are due for collection"""
    operation_id = str(uuid.uuid4())
    start_performance_tracking(operation_id, 'database_query')
    
    try:
        db_service = CollectionDatabaseService()
        await db_service.initialize()
        
        terms = await db_service.get_terms_due_for_collection()
        
        end_performance_tracking(operation_id, 'completed')
        logger.info(f"Found {len(terms)} terms due for collection")
        
        return terms
        
    except Exception as e:
        end_performance_tracking(operation_id, 'failed')
        logger.error(f"Failed to get due search terms: {e}")
        raise
    finally:
        if 'db_service' in locals():
            await db_service.close()


@task(retries=2, retry_delay_seconds=30)
async def collect_from_lexml(search_term: Dict[str, Any], max_records: int = 100) -> Dict[str, Any]:
    """Collect documents from LexML for a specific search term"""
    term_id = search_term['id']
    query = search_term['cql_query'] or search_term['term']
    
    operation_id = f"lexml_collection_{term_id}_{uuid.uuid4().hex[:8]}"
    start_performance_tracking(operation_id, 'lexml_search')
    
    logger = get_run_logger()
    logger.info(f"Starting LexML collection for term: {search_term['term']}")
    
    collection_start = datetime.now()
    documents = []
    
    try:
        # Use retry handler for API calls
        async def collect_documents():
            client = LexMLCollectionClient()
            return await client.collect_documents(
                query=query,
                max_records=max_records,
                date_from=(datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
            )
        
        documents = await execute_with_api_retry(collect_documents, 'lexml')
        
        execution_time_ms = int((datetime.now() - collection_start).total_seconds() * 1000)
        
        # Track metrics
        await track_collection_metrics(
            source='lexml',
            search_term=search_term['term'],
            documents_collected=len(documents),
            documents_validated=len(documents),  # Will be validated later
            execution_time_ms=execution_time_ms
        )
        
        end_performance_tracking(operation_id, 'completed')
        
        return {
            'search_term_id': term_id,
            'search_term': search_term['term'],
            'source': 'lexml',
            'documents': documents,
            'execution_time_ms': execution_time_ms,
            'collection_status': 'success'
        }
        
    except Exception as e:
        execution_time_ms = int((datetime.now() - collection_start).total_seconds() * 1000)
        
        # Track failed collection
        collection_metrics.fail_collection('lexml', str(e))
        end_performance_tracking(operation_id, 'failed')
        
        logger.error(f"LexML collection failed for term {search_term['term']}: {e}")
        
        # Send alert for critical errors
        await send_alert(
            level='warning',
            message=f"LexML collection failed for term: {search_term['term']}",
            details={
                'term_id': term_id,
                'error': str(e),
                'execution_time_ms': execution_time_ms
            }
        )
        
        return {
            'search_term_id': term_id,
            'search_term': search_term['term'],
            'source': 'lexml',
            'documents': [],
            'execution_time_ms': execution_time_ms,
            'collection_status': 'failed',
            'error': str(e)
        }


@task(retries=2, retry_delay_seconds=30)
async def collect_from_multi_source(search_term: Dict[str, Any], 
                                  max_records_per_source: int = 25) -> Dict[str, Any]:
    """Collect documents from multiple government APIs"""
    term_id = search_term['id']
    query = search_term['term']  # Use simpler term for government APIs
    
    operation_id = f"multi_source_collection_{term_id}_{uuid.uuid4().hex[:8]}"
    start_performance_tracking(operation_id, 'api_request')
    
    logger = get_run_logger()
    logger.info(f"Starting multi-source collection for term: {search_term['term']}")
    
    collection_start = datetime.now()
    all_documents = []
    
    try:
        # Use retry handler for API calls
        async def collect_from_apis():
            collector = MultiSourceCollector()
            return await collector.collect_from_all_sources(
                query=query,
                max_records_per_source=max_records_per_source
            )
        
        source_results = await execute_with_api_retry(collect_from_apis, 'government_apis')
        
        # Aggregate all documents
        for source, documents in source_results.items():
            if documents:
                # Add source information to each document
                for doc in documents:
                    doc['source_api'] = source
                all_documents.extend(documents)
        
        execution_time_ms = int((datetime.now() - collection_start).total_seconds() * 1000)
        
        # Track metrics for each source
        for source, documents in source_results.items():
            await track_collection_metrics(
                source=source,
                search_term=search_term['term'],
                documents_collected=len(documents),
                documents_validated=len(documents),
                execution_time_ms=execution_time_ms // len(source_results)  # Approximate per source
            )
        
        end_performance_tracking(operation_id, 'completed')
        
        return {
            'search_term_id': term_id,
            'search_term': search_term['term'],
            'source': 'multi_source',
            'documents': all_documents,
            'source_breakdown': {source: len(docs) for source, docs in source_results.items()},
            'execution_time_ms': execution_time_ms,
            'collection_status': 'success'
        }
        
    except Exception as e:
        execution_time_ms = int((datetime.now() - collection_start).total_seconds() * 1000)
        
        collection_metrics.fail_collection('multi_source', str(e))
        end_performance_tracking(operation_id, 'failed')
        
        logger.error(f"Multi-source collection failed for term {search_term['term']}: {e}")
        
        await send_alert(
            level='warning',
            message=f"Multi-source collection failed for term: {search_term['term']}",
            details={
                'term_id': term_id,
                'error': str(e),
                'execution_time_ms': execution_time_ms
            }
        )
        
        return {
            'search_term_id': term_id,
            'search_term': search_term['term'],
            'source': 'multi_source',
            'documents': [],
            'execution_time_ms': execution_time_ms,
            'collection_status': 'failed',
            'error': str(e)
        }


@task(retries=2, retry_delay_seconds=15)
async def validate_and_store_documents(collection_result: Dict[str, Any]) -> Dict[str, Any]:
    """Validate collected documents and store in database"""
    if collection_result['collection_status'] != 'success' or not collection_result['documents']:
        return {
            'search_term_id': collection_result['search_term_id'],
            'validation_status': 'skipped',
            'storage_stats': {'new': 0, 'updated': 0, 'skipped': 0}
        }
    
    operation_id = f"validation_storage_{collection_result['search_term_id']}_{uuid.uuid4().hex[:8]}"
    start_performance_tracking(operation_id, 'document_storage')
    
    logger = get_run_logger()
    documents = collection_result['documents']
    
    try:
        # Validate documents
        validation_results = validate_batch_documents(documents)
        valid_documents = validation_results['valid']
        
        logger.info(f"Validation: {len(valid_documents)} valid out of {len(documents)} documents")
        
        if validation_results['invalid']:
            validation_report = generate_validation_report(validation_results)
            logger.warning(f"Validation issues found:\n{validation_report}")
        
        # Store valid documents
        storage_stats = {'new': 0, 'updated': 0, 'skipped': 0}
        
        if valid_documents:
            db_service = CollectionDatabaseService()
            await db_service.initialize()
            
            try:
                # Group documents by source for efficient storage
                source_api = collection_result.get('source', 'unknown')
                storage_stats = await db_service.store_collected_documents(
                    documents=valid_documents,
                    search_term_id=collection_result['search_term_id'],
                    source_api=source_api
                )
                
                # Update collection metrics
                collection_metrics.record_storage(
                    new_docs=storage_stats['new'],
                    updated_docs=storage_stats['updated'],
                    skipped_docs=storage_stats['skipped']
                )
                
                # Log collection execution
                log_data = {
                    'search_term_id': collection_result['search_term_id'],
                    'collection_type': 'automated',
                    'status': 'completed',
                    'records_collected': len(documents),
                    'records_new': storage_stats['new'],
                    'records_updated': storage_stats['updated'],
                    'records_skipped': storage_stats['skipped'] + len(validation_results['invalid']),
                    'execution_time_ms': collection_result['execution_time_ms'],
                    'started_at': datetime.now() - timedelta(milliseconds=collection_result['execution_time_ms']),
                    'completed_at': datetime.now(),
                    'api_response_time_ms': collection_result['execution_time_ms']
                }
                
                await db_service.log_collection_execution(log_data)
                
                # Update next collection time
                await db_service.update_next_collection_time(collection_result['search_term_id'])
                
            finally:
                await db_service.close()
        
        end_performance_tracking(operation_id, 'completed')
        
        return {
            'search_term_id': collection_result['search_term_id'],
            'validation_status': 'completed',
            'storage_stats': storage_stats,
            'validation_summary': validation_results['stats']
        }
        
    except Exception as e:
        end_performance_tracking(operation_id, 'failed')
        logger.error(f"Validation/storage failed for term {collection_result['search_term_id']}: {e}")
        
        await send_alert(
            level='error',
            message=f"Document validation/storage failed",
            details={
                'search_term_id': collection_result['search_term_id'],
                'error': str(e),
                'document_count': len(documents)
            }
        )
        raise


@task
async def update_collection_schedule(search_term_id: int) -> bool:
    """Update the next collection schedule for a search term"""
    try:
        db_service = CollectionDatabaseService()
        await db_service.initialize()
        
        success = await db_service.update_next_collection_time(search_term_id)
        await db_service.close()
        
        return success
        
    except Exception as e:
        logger.error(f"Failed to update collection schedule for term {search_term_id}: {e}")
        return False


@flow(name="daily-collection-flow", task_runner=ConcurrentTaskRunner())
async def daily_collection_flow() -> Dict[str, Any]:
    """
    Daily automated collection flow
    Collects documents from all due search terms using both LexML and government APIs
    """
    flow_start = datetime.now()
    logger = get_run_logger()
    logger.info("🚀 Starting daily collection flow")
    
    try:
        # Get search terms due for collection
        due_terms = await get_due_search_terms()
        
        if not due_terms:
            logger.info("No search terms due for collection")
            return {
                'status': 'completed',
                'message': 'No terms due for collection',
                'execution_time_ms': int((datetime.now() - flow_start).total_seconds() * 1000)
            }
        
        logger.info(f"Processing {len(due_terms)} search terms")
        
        # Process each search term concurrently
        collection_tasks = []
        
        for term in due_terms:
            # Collect from both LexML and government APIs
            lexml_task = collect_from_lexml(term, max_records=100)
            multi_source_task = collect_from_multi_source(term, max_records_per_source=25)
            
            collection_tasks.extend([lexml_task, multi_source_task])
        
        # Execute all collection tasks concurrently
        collection_results = await asyncio.gather(*collection_tasks, return_exceptions=True)
        
        # Process results and store documents
        storage_tasks = []
        successful_collections = 0
        failed_collections = 0
        
        for result in collection_results:
            if isinstance(result, Exception):
                logger.error(f"Collection task failed: {result}")
                failed_collections += 1
                continue
            
            if result['collection_status'] == 'success':
                successful_collections += 1
                # Queue for validation and storage
                storage_tasks.append(validate_and_store_documents(result))
            else:
                failed_collections += 1
        
        # Execute storage tasks
        if storage_tasks:
            storage_results = await asyncio.gather(*storage_tasks, return_exceptions=True)
            
            # Process storage results
            total_new = 0
            total_updated = 0
            total_skipped = 0
            
            for storage_result in storage_results:
                if isinstance(storage_result, Exception):
                    logger.error(f"Storage task failed: {storage_result}")
                    continue
                
                if storage_result['validation_status'] == 'completed':
                    stats = storage_result['storage_stats']
                    total_new += stats['new']
                    total_updated += stats['updated']
                    total_skipped += stats['skipped']
        
        # Check metrics and send alerts if needed
        metrics = collection_metrics.get_metrics()
        await alert_manager.check_and_send_alerts(metrics)
        
        execution_time_ms = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        summary = {
            'status': 'completed',
            'terms_processed': len(due_terms),
            'successful_collections': successful_collections,
            'failed_collections': failed_collections,
            'documents_stored': {
                'new': total_new,
                'updated': total_updated,
                'skipped': total_skipped
            },
            'execution_time_ms': execution_time_ms
        }
        
        logger.info(f"✅ Daily collection completed: {summary}")
        return summary
        
    except Exception as e:
        execution_time_ms = int((datetime.now() - flow_start).total_seconds() * 1000)
        logger.error(f"❌ Daily collection flow failed: {e}")
        
        await send_alert(
            level='critical',
            message="Daily collection flow failed",
            details={
                'error': str(e),
                'execution_time_ms': execution_time_ms
            }
        )
        
        return {
            'status': 'failed',
            'error': str(e),
            'execution_time_ms': execution_time_ms
        }


@flow(name="manual-collection-flow")
async def manual_collection_flow(search_term_ids: List[int], 
                                sources: List[str] = None,
                                max_records: int = 100) -> Dict[str, Any]:
    """
    Manual collection flow for specific search terms
    Allows targeted collection with custom parameters
    """
    flow_start = datetime.now()
    logger = get_run_logger()
    logger.info(f"🎯 Starting manual collection for terms: {search_term_ids}")
    
    sources = sources or ['lexml', 'multi_source']
    
    try:
        # Get specific search terms
        db_service = CollectionDatabaseService()
        await db_service.initialize()
        
        search_terms = await db_service.get_search_terms(search_term_ids)
        await db_service.close()
        
        if not search_terms:
            return {
                'status': 'completed',
                'message': 'No valid search terms found',
                'execution_time_ms': int((datetime.now() - flow_start).total_seconds() * 1000)
            }
        
        logger.info(f"Processing {len(search_terms)} search terms from sources: {sources}")
        
        # Process each term and source combination
        collection_tasks = []
        
        for term in search_terms:
            if 'lexml' in sources:
                collection_tasks.append(collect_from_lexml(term, max_records))
            
            if 'multi_source' in sources:
                collection_tasks.append(collect_from_multi_source(term, max_records // 4))
        
        # Execute collection tasks
        collection_results = await asyncio.gather(*collection_tasks, return_exceptions=True)
        
        # Process and store results
        storage_tasks = []
        successful_collections = 0
        failed_collections = 0
        
        for result in collection_results:
            if isinstance(result, Exception):
                logger.error(f"Manual collection task failed: {result}")
                failed_collections += 1
                continue
            
            if result['collection_status'] == 'success':
                successful_collections += 1
                storage_tasks.append(validate_and_store_documents(result))
            else:
                failed_collections += 1
        
        # Execute storage tasks
        storage_results = []
        if storage_tasks:
            storage_results = await asyncio.gather(*storage_tasks, return_exceptions=True)
        
        # Calculate totals
        total_new = 0
        total_updated = 0
        total_skipped = 0
        
        for storage_result in storage_results:
            if isinstance(storage_result, Exception):
                logger.error(f"Manual storage task failed: {storage_result}")
                continue
            
            if storage_result['validation_status'] == 'completed':
                stats = storage_result['storage_stats']
                total_new += stats['new']
                total_updated += stats['updated']
                total_skipped += stats['skipped']
        
        execution_time_ms = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        summary = {
            'status': 'completed',
            'terms_processed': len(search_terms),
            'sources_used': sources,
            'successful_collections': successful_collections,
            'failed_collections': failed_collections,
            'documents_stored': {
                'new': total_new,
                'updated': total_updated,
                'skipped': total_skipped
            },
            'execution_time_ms': execution_time_ms
        }
        
        logger.info(f"✅ Manual collection completed: {summary}")
        return summary
        
    except Exception as e:
        execution_time_ms = int((datetime.now() - flow_start).total_seconds() * 1000)
        logger.error(f"❌ Manual collection flow failed: {e}")
        
        await send_alert(
            level='error',
            message="Manual collection flow failed",
            details={
                'search_term_ids': search_term_ids,
                'error': str(e),
                'execution_time_ms': execution_time_ms
            }
        )
        
        return {
            'status': 'failed',
            'error': str(e),
            'execution_time_ms': execution_time_ms
        }


@flow(name="health-check-flow")
async def health_check_flow() -> Dict[str, Any]:
    """
    Health check flow to verify system components
    """
    logger = get_run_logger()
    logger.info("🔍 Starting health check flow")
    
    health_status = {
        'timestamp': datetime.now().isoformat(),
        'overall_status': 'healthy',
        'components': {}
    }
    
    try:
        # Check database connectivity
        db_service = CollectionDatabaseService()
        await db_service.initialize()
        db_health = await db_service.health_check()
        await db_service.close()
        
        health_status['components']['database'] = db_health
        
        # Check API connectivity
        lexml_client = LexMLCollectionClient()
        try:
            # Test with a simple query
            test_docs = await lexml_client.collect_documents("transporte", max_records=1)
            health_status['components']['lexml_api'] = {
                'status': 'healthy',
                'test_query_successful': len(test_docs) >= 0
            }
        except Exception as e:
            health_status['components']['lexml_api'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
        
        # Check circuit breaker states
        retry_stats = retry_handler.get_all_stats()
        health_status['components']['circuit_breakers'] = retry_stats
        
        # Get collection metrics
        metrics_summary = collection_metrics.get_summary()
        health_status['components']['collection_metrics'] = metrics_summary
        
        # Determine overall status
        unhealthy_components = [
            name for name, component in health_status['components'].items()
            if isinstance(component, dict) and component.get('status') == 'unhealthy'
        ]
        
        if unhealthy_components:
            health_status['overall_status'] = 'degraded'
            if len(unhealthy_components) >= len(health_status['components']) / 2:
                health_status['overall_status'] = 'unhealthy'
        
        logger.info(f"Health check completed: {health_status['overall_status']}")
        return health_status
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        health_status['overall_status'] = 'unhealthy'
        health_status['error'] = str(e)
        return health_status


# Export flows for Prefect deployment
if __name__ == "__main__":
    # This allows testing flows locally
    import asyncio
    
    async def test_flows():
        print("Testing health check flow...")
        health_result = await health_check_flow()
        print(f"Health check result: {health_result}")
        
        print("\nTesting manual collection flow...")
        manual_result = await manual_collection_flow([1], sources=['lexml'], max_records=5)
        print(f"Manual collection result: {manual_result}")
    
    asyncio.run(test_flows())