"""
Prefect flows for automated data export generation
Handles scheduled exports, format conversion, and file management
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner

from ..services.export_service import get_export_service, ExportFormat
from ..utils.monitoring import performance_tracker
from ..utils.validation import validate_export_params

logger = logging.getLogger(__name__)


@task(name="initialize_export_service", retries=2)
async def initialize_export_service():
    """Initialize the export service"""
    try:
        service = await get_export_service()
        logger.info("Export service initialized successfully")
        return service
    except Exception as e:
        logger.error(f"Failed to initialize export service: {e}")
        raise


@task(name="generate_scheduled_exports", retries=1)
async def generate_scheduled_exports_task(service) -> Dict[str, Any]:
    """Generate all scheduled exports"""
    try:
        logger.info("Starting scheduled export generation")
        stats = await service.generate_scheduled_exports()
        
        logger.info(f"Scheduled exports completed: {stats['exports_generated']} exports generated, "
                   f"{stats['total_records_exported']} records exported")
        
        return stats
    except Exception as e:
        logger.error(f"Error in scheduled exports task: {e}")
        raise


@task(name="export_collection_summary", retries=1)
async def export_collection_summary_task(service, export_format: str = ExportFormat.JSON) -> Dict[str, Any]:
    """Export collection summary"""
    try:
        logger.info(f"Generating collection summary export in {export_format} format")
        result = await service.export_collection_summary(export_format)
        
        if result.get('status') == 'success':
            logger.info(f"Collection summary exported: {result['record_count']} records, "
                       f"file size: {result['file_size_bytes']} bytes")
        
        return result
    except Exception as e:
        logger.error(f"Error exporting collection summary: {e}")
        raise


@task(name="export_priority_terms", retries=1)
async def export_priority_terms_task(service, priority_threshold: int = 3) -> List[Dict[str, Any]]:
    """Export data for high-priority search terms"""
    try:
        logger.info(f"Exporting priority terms (priority <= {priority_threshold})")
        
        # Get priority terms
        priority_terms = await service._get_exportable_search_terms()
        priority_terms = [term for term in priority_terms if term.get('priority', 5) <= priority_threshold]
        
        if not priority_terms:
            logger.info("No priority terms found for export")
            return []
        
        # Export each priority term
        export_results = []
        for term in priority_terms[:5]:  # Limit to top 5 priority terms
            try:
                # Export in multiple formats for priority terms
                for format_type in [ExportFormat.CSV, ExportFormat.JSON]:
                    result = await service.export_search_term_data(
                        term['id'], format_type
                    )
                    if result.get('status') == 'success':
                        export_results.append(result)
            except Exception as e:
                logger.error(f"Error exporting priority term {term.get('term')}: {e}")
                continue
        
        logger.info(f"Priority terms export completed: {len(export_results)} exports generated")
        return export_results
        
    except Exception as e:
        logger.error(f"Error in priority terms export: {e}")
        return []


@task(name="cleanup_old_exports", retries=1)
async def cleanup_old_exports_task(service, days_old: int = 30) -> int:
    """Clean up old export files"""
    try:
        cleaned_count = await service._cleanup_old_exports(days_old)
        logger.info(f"Cleaned up {cleaned_count} old export files")
        return cleaned_count
    except Exception as e:
        logger.error(f"Error cleaning up old exports: {e}")
        return 0


@flow(
    name="automated_export_flow",
    description="Generate automated exports for all configured search terms",
    task_runner=ConcurrentTaskRunner()
)
async def automated_export_flow(
    include_summary: bool = True,
    include_priority_export: bool = True,
    cleanup_old_files: bool = True,
    cleanup_days: int = 30
) -> Dict[str, Any]:
    """
    Main flow for automated data export generation
    
    Args:
        include_summary: Whether to generate collection summary
        include_priority_export: Whether to export priority terms separately
        cleanup_old_files: Whether to clean up old export files
        cleanup_days: Age threshold for cleanup (days)
    
    Returns:
        Dict with flow execution statistics
    """
    flow_logger = get_run_logger()
    flow_start = datetime.now()
    
    flow_stats = {
        'flow_name': 'automated_export_flow',
        'execution_start': flow_start.isoformat(),
        'include_summary': include_summary,
        'include_priority_export': include_priority_export,
        'cleanup_enabled': cleanup_old_files,
        'status': 'started'
    }
    
    try:
        flow_logger.info("Starting automated export flow")
        
        # Initialize export service
        service = await initialize_export_service()
        
        # Generate scheduled exports
        export_stats = await generate_scheduled_exports_task(service)
        flow_stats['scheduled_exports'] = export_stats
        
        # Optional: Generate collection summary
        if include_summary:
            summary_result = await export_collection_summary_task(service)
            flow_stats['summary_export'] = summary_result
        
        # Optional: Export priority terms
        if include_priority_export:
            priority_results = await export_priority_terms_task(service)
            flow_stats['priority_exports'] = priority_results
        
        # Optional: Cleanup old files
        if cleanup_old_files:
            cleanup_count = await cleanup_old_exports_task(service, cleanup_days)
            flow_stats['cleanup_count'] = cleanup_count
        
        # Mark flow as successful
        flow_stats['status'] = 'completed'
        flow_stats['execution_time_ms'] = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        total_exports = export_stats.get('exports_generated', 0)
        if include_priority_export:
            total_exports += len(flow_stats.get('priority_exports', []))
        
        flow_logger.info(f"Automated export flow completed successfully: "
                        f"{total_exports} exports generated")
        
        return flow_stats
        
    except Exception as e:
        flow_stats['status'] = 'failed'
        flow_stats['error'] = str(e)
        flow_stats['execution_time_ms'] = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        flow_logger.error(f"Automated export flow failed: {e}")
        raise


@flow(
    name="custom_export_flow",
    description="Generate custom exports with specific parameters"
)
async def custom_export_flow(
    search_term_ids: List[int],
    export_formats: List[str] = [ExportFormat.CSV],
    date_filter: Optional[str] = None,
    max_records: Optional[int] = None
) -> Dict[str, Any]:
    """
    Flow for generating custom exports with specific parameters
    
    Args:
        search_term_ids: List of search term IDs to export
        export_formats: List of export formats to generate
        date_filter: Optional date filter ('last_week', 'last_month', 'last_year')
        max_records: Maximum number of records per export
    
    Returns:
        Dict with export results
    """
    flow_logger = get_run_logger()
    
    try:
        flow_logger.info(f"Starting custom export flow for {len(search_term_ids)} search terms")
        
        service = await get_export_service()
        
        export_results = []
        
        for search_term_id in search_term_ids:
            for export_format in export_formats:
                try:
                    result = await service.export_search_term_data(
                        search_term_id, export_format, date_filter, max_records
                    )
                    if result.get('status') == 'success':
                        export_results.append(result)
                        flow_logger.info(f"Exported search term {search_term_id} in {export_format} format")
                except Exception as e:
                    flow_logger.error(f"Error exporting search term {search_term_id}: {e}")
                    continue
        
        flow_logger.info(f"Custom export flow completed: {len(export_results)} exports generated")
        
        return {
            'status': 'completed',
            'exports_generated': len(export_results),
            'export_results': export_results
        }
        
    except Exception as e:
        flow_logger.error(f"Custom export flow failed: {e}")
        return {'status': 'failed', 'error': str(e)}


@flow(
    name="export_validation_flow",
    description="Validate and test export functionality"
)
async def export_validation_flow() -> Dict[str, Any]:
    """
    Flow for validating export functionality and data integrity
    
    Returns:
        Dict with validation results
    """
    flow_logger = get_run_logger()
    
    try:
        flow_logger.info("Starting export validation flow")
        
        service = await get_export_service()
        
        validation_results = {
            'service_initialized': False,
            'export_directory_exists': False,
            'sample_export_successful': False,
            'summary_export_successful': False,
            'formats_tested': []
        }
        
        # Test service initialization
        validation_results['service_initialized'] = service is not None
        
        # Test export directory
        validation_results['export_directory_exists'] = service.export_directory.exists()
        
        # Test sample export (if we have data)
        try:
            exportable_terms = await service._get_exportable_search_terms()
            if exportable_terms:
                sample_term = exportable_terms[0]
                
                # Test different formats
                for test_format in [ExportFormat.CSV, ExportFormat.JSON]:
                    try:
                        result = await service.export_search_term_data(
                            sample_term['id'], test_format, max_records=10
                        )
                        if result.get('status') == 'success':
                            validation_results['formats_tested'].append(test_format)
                            if not validation_results['sample_export_successful']:
                                validation_results['sample_export_successful'] = True
                    except Exception as e:
                        flow_logger.warning(f"Sample export failed for format {test_format}: {e}")
                        continue
        except Exception as e:
            flow_logger.warning(f"Sample export test failed: {e}")
        
        # Test summary export
        try:
            summary_result = await service.export_collection_summary()
            validation_results['summary_export_successful'] = summary_result.get('status') == 'success'
        except Exception as e:
            flow_logger.warning(f"Summary export test failed: {e}")
        
        # Overall validation status
        validation_results['overall_status'] = 'passed' if all([
            validation_results['service_initialized'],
            validation_results['export_directory_exists'],
            len(validation_results['formats_tested']) > 0
        ]) else 'failed'
        
        flow_logger.info(f"Export validation completed: {validation_results}")
        
        return validation_results
        
    except Exception as e:
        flow_logger.error(f"Export validation flow failed: {e}")
        return {'overall_status': 'failed', 'error': str(e)}


# Scheduled flows can be added here for automation
if __name__ == "__main__":
    # Example of running the flow directly
    import asyncio
    asyncio.run(automated_export_flow())