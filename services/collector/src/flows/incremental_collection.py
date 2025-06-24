"""
Prefect flows for incremental data collection and updates
Integrates deduplication service with the main collection workflow
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner

from ..services.incremental_update_service import get_incremental_service
from ..services.database_service import CollectionDatabaseService
from ..utils.monitoring import collection_metrics, performance_tracker
from ..utils.validation import validate_collection_params

logger = logging.getLogger(__name__)


@task(name="initialize_incremental_service", retries=2)
async def initialize_incremental_service():
    """Initialize the incremental update service"""
    try:
        service = await get_incremental_service()
        logger.info("Incremental update service initialized successfully")
        return service
    except Exception as e:
        logger.error(f"Failed to initialize incremental service: {e}")
        raise


@task(name="execute_incremental_updates", retries=1)
async def execute_incremental_updates_task(service, max_terms: int = 10) -> Dict[str, Any]:
    """Execute incremental updates for search terms"""
    try:
        logger.info(f"Starting incremental updates for up to {max_terms} terms")
        stats = await service.execute_incremental_updates(max_terms)
        
        # Log key metrics
        logger.info(f"Incremental update completed: {stats['terms_processed']} terms processed, "
                   f"{stats['total_documents_new']} new documents, "
                   f"{stats['total_documents_updated']} updated documents")
        
        return stats
    except Exception as e:
        logger.error(f"Error in incremental updates task: {e}")
        raise


@task(name="cleanup_old_fingerprints", retries=1)
async def cleanup_old_fingerprints_task(service, days_old: int = 90):
    """Clean up old document fingerprints"""
    try:
        if hasattr(service, 'dedup_service') and service.dedup_service:
            deleted_count = await service.dedup_service.cleanup_old_fingerprints(days_old)
            logger.info(f"Cleaned up {deleted_count} old fingerprints")
            return deleted_count
        return 0
    except Exception as e:
        logger.error(f"Error cleaning up fingerprints: {e}")
        return 0


@task(name="generate_incremental_stats", retries=1)
async def generate_incremental_stats_task(service) -> Dict[str, Any]:
    """Generate statistics about incremental update performance"""
    try:
        stats = await service.get_incremental_update_stats()
        logger.info(f"Generated incremental update stats: {len(stats)} metrics")
        return stats
    except Exception as e:
        logger.error(f"Error generating incremental stats: {e}")
        return {}


@flow(
    name="incremental_collection_flow",
    description="Execute incremental document collection with deduplication",
    task_runner=ConcurrentTaskRunner()
)
async def incremental_collection_flow(
    max_terms: int = 10,
    cleanup_old_data: bool = True,
    cleanup_days: int = 90
) -> Dict[str, Any]:
    """
    Main flow for incremental document collection
    
    Args:
        max_terms: Maximum number of search terms to process
        cleanup_old_data: Whether to clean up old fingerprints
        cleanup_days: Age threshold for cleanup (days)
    
    Returns:
        Dict with flow execution statistics
    """
    flow_logger = get_run_logger()
    flow_start = datetime.now()
    
    flow_stats = {
        'flow_name': 'incremental_collection_flow',
        'execution_start': flow_start.isoformat(),
        'max_terms': max_terms,
        'cleanup_enabled': cleanup_old_data,
        'status': 'started'
    }
    
    try:
        flow_logger.info(f"Starting incremental collection flow for {max_terms} terms")
        
        # Initialize incremental service
        service = await initialize_incremental_service()
        
        # Execute incremental updates
        update_stats = await execute_incremental_updates_task(service, max_terms)
        flow_stats['update_results'] = update_stats
        
        # Optional cleanup
        if cleanup_old_data:
            cleanup_count = await cleanup_old_fingerprints_task(service, cleanup_days)
            flow_stats['cleanup_count'] = cleanup_count
        
        # Generate performance statistics
        performance_stats = await generate_incremental_stats_task(service)
        flow_stats['performance_stats'] = performance_stats
        
        # Mark flow as successful
        flow_stats['status'] = 'completed'
        flow_stats['execution_time_ms'] = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        flow_logger.info(f"Incremental collection flow completed successfully: "
                        f"{update_stats.get('terms_processed', 0)} terms processed")
        
        return flow_stats
        
    except Exception as e:
        flow_stats['status'] = 'failed'
        flow_stats['error'] = str(e)
        flow_stats['execution_time_ms'] = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        flow_logger.error(f"Incremental collection flow failed: {e}")
        raise


@flow(
    name="priority_incremental_flow", 
    description="Execute incremental updates for high-priority terms only"
)
async def priority_incremental_flow(priority_threshold: int = 3) -> Dict[str, Any]:
    """
    Flow for processing only high-priority search terms
    
    Args:
        priority_threshold: Only process terms with priority <= this value
    
    Returns:
        Dict with execution results
    """
    flow_logger = get_run_logger()
    
    try:
        flow_logger.info(f"Starting priority incremental flow (priority <= {priority_threshold})")
        
        service = await get_incremental_service()
        
        # Create update plan and filter by priority
        update_plans = await service.create_update_plan()
        priority_plans = [plan for plan in update_plans if plan.priority <= priority_threshold]
        
        if not priority_plans:
            flow_logger.info("No high-priority terms found for update")
            return {'status': 'completed', 'terms_processed': 0}
        
        # Execute updates for priority terms
        stats = {'terms_processed': 0, 'total_documents_new': 0, 'total_documents_updated': 0}
        
        for plan in priority_plans[:5]:  # Limit to top 5 priority terms
            try:
                result = await service._execute_single_update(plan)
                stats['terms_processed'] += 1
                stats['total_documents_new'] += result.get('documents_new', 0)
                stats['total_documents_updated'] += result.get('documents_updated', 0)
            except Exception as e:
                flow_logger.error(f"Error processing priority term {plan.search_term}: {e}")
                continue
        
        flow_logger.info(f"Priority incremental flow completed: {stats}")
        return {'status': 'completed', **stats}
        
    except Exception as e:
        flow_logger.error(f"Priority incremental flow failed: {e}")
        return {'status': 'failed', 'error': str(e)}


@flow(
    name="smart_delta_flow",
    description="Execute smart delta updates with change rate analysis"
)
async def smart_delta_flow(change_rate_threshold: float = 0.1) -> Dict[str, Any]:
    """
    Flow for smart delta updates based on change rate analysis
    
    Args:
        change_rate_threshold: Minimum change rate to trigger full collection
    
    Returns:
        Dict with execution results
    """
    flow_logger = get_run_logger()
    
    try:
        flow_logger.info(f"Starting smart delta flow (change threshold: {change_rate_threshold})")
        
        service = await get_incremental_service()
        service.smart_delta_threshold = change_rate_threshold
        
        # Execute with smart delta strategy preference
        stats = await service.execute_incremental_updates(max_terms=15)
        
        # Filter results for smart delta strategy
        smart_delta_count = stats.get('strategy_breakdown', {}).get('smart_delta', 0)
        
        flow_logger.info(f"Smart delta flow completed: {smart_delta_count} terms used smart delta strategy")
        return {'status': 'completed', 'smart_delta_terms': smart_delta_count, **stats}
        
    except Exception as e:
        flow_logger.error(f"Smart delta flow failed: {e}")
        return {'status': 'failed', 'error': str(e)}


# Scheduled flows can be added here for automation
if __name__ == "__main__":
    # Example of running the flow directly
    import asyncio
    asyncio.run(incremental_collection_flow())