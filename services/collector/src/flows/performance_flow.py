"""
Prefect flows for performance optimization and load testing
Handles automated performance monitoring, optimization, and stress testing
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from prefect import flow, task, get_run_logger
from prefect.task_runners import ConcurrentTaskRunner

from ..services.performance_optimizer import get_performance_optimizer
from ..services.alerting_service import get_alerting_service
from ..services.database_service import CollectionDatabaseService
from ..services.lexml_client import MultiSourceCollector
from ..utils.monitoring import performance_tracker

logger = logging.getLogger(__name__)


@task(name="initialize_performance_services", retries=2)
async def initialize_performance_services():
    """Initialize performance optimization services"""
    try:
        optimizer = await get_performance_optimizer()
        alerting_service = await get_alerting_service()
        
        logger.info("Performance services initialized successfully")
        return {'optimizer': optimizer, 'alerting': alerting_service}
    except Exception as e:
        logger.error(f"Failed to initialize performance services: {e}")
        raise


@task(name="run_performance_analysis", retries=1)
async def run_performance_analysis_task(services: Dict[str, Any]) -> Dict[str, Any]:
    """Run comprehensive performance analysis"""
    try:
        optimizer = services['optimizer']
        logger.info("Starting performance analysis")
        
        analysis_results = await optimizer.run_performance_analysis()
        
        logger.info(f"Performance analysis completed: {analysis_results['status']} "
                   f"(score: {analysis_results.get('overall_score', 0):.2f})")
        
        return analysis_results
    except Exception as e:
        logger.error(f"Error in performance analysis task: {e}")
        raise


@task(name="optimize_database_performance", retries=1)
async def optimize_database_performance_task(services: Dict[str, Any]) -> Dict[str, Any]:
    """Optimize database performance"""
    try:
        optimizer = services['optimizer']
        logger.info("Starting database optimization")
        
        optimization_results = await optimizer.optimize_database_performance()
        
        logger.info(f"Database optimization completed: {optimization_results['status']}")
        logger.info(f"Total improvements: {optimization_results.get('total_improvements', 0):.1f}%")
        
        return optimization_results
    except Exception as e:
        logger.error(f"Error in database optimization task: {e}")
        raise


@task(name="load_test_collection_system", retries=1)
async def load_test_collection_system_task(
    concurrent_collections: int = 5,
    test_duration_minutes: int = 10,
    search_terms: Optional[List[str]] = None
) -> Dict[str, Any]:
    """Perform load testing on the collection system"""
    try:
        logger.info(f"Starting load test: {concurrent_collections} concurrent collections for {test_duration_minutes} minutes")
        
        # Initialize collector
        collector = MultiSourceCollector()
        
        # Default search terms for testing
        if not search_terms:
            search_terms = [
                "transporte público",
                "rodovia federal",
                "aviação civil",
                "transporte aquaviário",
                "mobilidade urbana"
            ]
        
        load_test_results = {
            'test_config': {
                'concurrent_collections': concurrent_collections,
                'test_duration_minutes': test_duration_minutes,
                'search_terms': search_terms,
                'start_time': datetime.now().isoformat()
            },
            'collections_completed': 0,
            'collections_failed': 0,
            'total_documents_collected': 0,
            'avg_response_time_ms': 0,
            'max_response_time_ms': 0,
            'min_response_time_ms': float('inf'),
            'response_times': [],
            'errors': [],
            'throughput_per_minute': 0,
            'system_stability': 'unknown'
        }
        
        # Run concurrent collections
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=test_duration_minutes)
        
        tasks = []
        
        async def single_collection_test(term: str, iteration: int):
            """Single collection test iteration"""
            try:
                collection_start = datetime.now()
                
                # Perform collection
                results = await collector.collect_from_all_sources(
                    term, 
                    max_records_per_source=50  # Limit for load testing
                )
                
                collection_time = (datetime.now() - collection_start).total_seconds() * 1000
                
                # Count total documents
                total_docs = sum(len(docs) for docs in results.values())
                
                return {
                    'success': True,
                    'response_time_ms': collection_time,
                    'documents_collected': total_docs,
                    'search_term': term,
                    'iteration': iteration
                }
                
            except Exception as e:
                collection_time = (datetime.now() - collection_start).total_seconds() * 1000
                return {
                    'success': False,
                    'response_time_ms': collection_time,
                    'error': str(e),
                    'search_term': term,
                    'iteration': iteration
                }
        
        # Create load test tasks
        iteration = 0
        while datetime.now() < end_time:
            # Create batch of concurrent tasks
            batch_tasks = []
            for i in range(concurrent_collections):
                term = search_terms[iteration % len(search_terms)]
                task = single_collection_test(term, iteration)
                batch_tasks.append(task)
                iteration += 1
            
            # Execute batch
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # Process results
            for result in batch_results:
                if isinstance(result, Exception):
                    load_test_results['collections_failed'] += 1
                    load_test_results['errors'].append(str(result))
                elif result['success']:
                    load_test_results['collections_completed'] += 1
                    load_test_results['total_documents_collected'] += result['documents_collected']
                    response_time = result['response_time_ms']
                    load_test_results['response_times'].append(response_time)
                    load_test_results['max_response_time_ms'] = max(load_test_results['max_response_time_ms'], response_time)
                    load_test_results['min_response_time_ms'] = min(load_test_results['min_response_time_ms'], response_time)
                else:
                    load_test_results['collections_failed'] += 1
                    load_test_results['errors'].append(result.get('error', 'Unknown error'))
            
            # Small delay between batches
            await asyncio.sleep(1)
        
        # Calculate final statistics
        total_collections = load_test_results['collections_completed'] + load_test_results['collections_failed']
        test_duration_actual = (datetime.now() - start_time).total_seconds() / 60
        
        if load_test_results['response_times']:
            load_test_results['avg_response_time_ms'] = sum(load_test_results['response_times']) / len(load_test_results['response_times'])
        
        if load_test_results['min_response_time_ms'] == float('inf'):
            load_test_results['min_response_time_ms'] = 0
        
        load_test_results['throughput_per_minute'] = total_collections / test_duration_actual if test_duration_actual > 0 else 0
        load_test_results['success_rate'] = load_test_results['collections_completed'] / total_collections if total_collections > 0 else 0
        load_test_results['actual_duration_minutes'] = test_duration_actual
        
        # Determine system stability
        success_rate = load_test_results['success_rate']
        avg_response = load_test_results['avg_response_time_ms']
        
        if success_rate >= 0.95 and avg_response < 10000:  # 95% success, under 10s avg
            load_test_results['system_stability'] = 'excellent'
        elif success_rate >= 0.9 and avg_response < 20000:  # 90% success, under 20s avg
            load_test_results['system_stability'] = 'good'
        elif success_rate >= 0.8 and avg_response < 30000:  # 80% success, under 30s avg
            load_test_results['system_stability'] = 'acceptable'
        else:
            load_test_results['system_stability'] = 'poor'
        
        logger.info(f"Load test completed: {load_test_results['collections_completed']}/{total_collections} successful "
                   f"({success_rate:.1%} success rate), {load_test_results['system_stability']} stability")
        
        return load_test_results
        
    except Exception as e:
        logger.error(f"Error in load testing: {e}")
        return {
            'error': str(e),
            'collections_completed': 0,
            'collections_failed': 1,
            'system_stability': 'error'
        }


@task(name="database_stress_test", retries=1)
async def database_stress_test_task(
    concurrent_queries: int = 10,
    test_duration_minutes: int = 5
) -> Dict[str, Any]:
    """Perform stress testing on the database"""
    try:
        logger.info(f"Starting database stress test: {concurrent_queries} concurrent queries for {test_duration_minutes} minutes")
        
        db_service = CollectionDatabaseService()
        await db_service.initialize()
        
        stress_test_results = {
            'test_config': {
                'concurrent_queries': concurrent_queries,
                'test_duration_minutes': test_duration_minutes,
                'start_time': datetime.now().isoformat()
            },
            'queries_completed': 0,
            'queries_failed': 0,
            'avg_query_time_ms': 0,
            'max_query_time_ms': 0,
            'min_query_time_ms': float('inf'),
            'query_times': [],
            'errors': [],
            'database_stability': 'unknown'
        }
        
        # Test queries of varying complexity
        test_queries = [
            "SELECT COUNT(*) FROM legislative_documents",
            "SELECT COUNT(*) FROM search_terms WHERE active = true",
            """
            SELECT st.term, COUNT(ld.id) as doc_count 
            FROM search_terms st 
            LEFT JOIN legislative_documents ld ON st.id = ld.search_term_id 
            GROUP BY st.term 
            ORDER BY doc_count DESC 
            LIMIT 10
            """,
            """
            SELECT source_api, COUNT(*) as collections, AVG(execution_time_ms) as avg_time
            FROM collection_logs 
            WHERE completed_at >= NOW() - INTERVAL '24 hours'
            GROUP BY source_api
            """,
            """
            SELECT date_trunc('hour', collection_date) as hour, COUNT(*) as docs
            FROM legislative_documents 
            WHERE collection_date >= NOW() - INTERVAL '7 days'
            GROUP BY hour 
            ORDER BY hour
            """
        ]
        
        async def single_query_test(query: str, iteration: int):
            """Single database query test"""
            try:
                query_start = datetime.now()
                
                async with db_service.pool.acquire() as conn:
                    await conn.fetchall(query)
                
                query_time = (datetime.now() - query_start).total_seconds() * 1000
                
                return {
                    'success': True,
                    'query_time_ms': query_time,
                    'iteration': iteration
                }
                
            except Exception as e:
                query_time = (datetime.now() - query_start).total_seconds() * 1000
                return {
                    'success': False,
                    'query_time_ms': query_time,
                    'error': str(e),
                    'iteration': iteration
                }
        
        # Run stress test
        start_time = datetime.now()
        end_time = start_time + timedelta(minutes=test_duration_minutes)
        
        iteration = 0
        while datetime.now() < end_time:
            # Create batch of concurrent queries
            batch_tasks = []
            for i in range(concurrent_queries):
                query = test_queries[iteration % len(test_queries)]
                task = single_query_test(query, iteration)
                batch_tasks.append(task)
                iteration += 1
            
            # Execute batch
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # Process results
            for result in batch_results:
                if isinstance(result, Exception):
                    stress_test_results['queries_failed'] += 1
                    stress_test_results['errors'].append(str(result))
                elif result['success']:
                    stress_test_results['queries_completed'] += 1
                    query_time = result['query_time_ms']
                    stress_test_results['query_times'].append(query_time)
                    stress_test_results['max_query_time_ms'] = max(stress_test_results['max_query_time_ms'], query_time)
                    stress_test_results['min_query_time_ms'] = min(stress_test_results['min_query_time_ms'], query_time)
                else:
                    stress_test_results['queries_failed'] += 1
                    stress_test_results['errors'].append(result.get('error', 'Unknown error'))
            
            # Small delay between batches
            await asyncio.sleep(0.1)
        
        # Calculate final statistics
        total_queries = stress_test_results['queries_completed'] + stress_test_results['queries_failed']
        
        if stress_test_results['query_times']:
            stress_test_results['avg_query_time_ms'] = sum(stress_test_results['query_times']) / len(stress_test_results['query_times'])
        
        if stress_test_results['min_query_time_ms'] == float('inf'):
            stress_test_results['min_query_time_ms'] = 0
        
        success_rate = stress_test_results['queries_completed'] / total_queries if total_queries > 0 else 0
        avg_query_time = stress_test_results['avg_query_time_ms']
        
        # Determine database stability
        if success_rate >= 0.99 and avg_query_time < 500:  # 99% success, under 500ms avg
            stress_test_results['database_stability'] = 'excellent'
        elif success_rate >= 0.95 and avg_query_time < 1000:  # 95% success, under 1s avg
            stress_test_results['database_stability'] = 'good'
        elif success_rate >= 0.9 and avg_query_time < 2000:  # 90% success, under 2s avg
            stress_test_results['database_stability'] = 'acceptable'
        else:
            stress_test_results['database_stability'] = 'poor'
        
        stress_test_results['success_rate'] = success_rate
        
        logger.info(f"Database stress test completed: {stress_test_results['queries_completed']}/{total_queries} successful "
                   f"({success_rate:.1%} success rate), {stress_test_results['database_stability']} stability")
        
        return stress_test_results
        
    except Exception as e:
        logger.error(f"Error in database stress testing: {e}")
        return {
            'error': str(e),
            'queries_completed': 0,
            'queries_failed': 1,
            'database_stability': 'error'
        }


@task(name="generate_performance_report", retries=1)
async def generate_performance_report_task(
    analysis_results: Dict[str, Any],
    optimization_results: Dict[str, Any],
    load_test_results: Dict[str, Any],
    stress_test_results: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate comprehensive performance report"""
    try:
        logger.info("Generating performance report")
        
        report = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'report_type': 'performance_optimization',
                'version': '1.0'
            },
            'executive_summary': {},
            'detailed_analysis': {
                'performance_analysis': analysis_results,
                'optimization_results': optimization_results,
                'load_test_results': load_test_results,
                'stress_test_results': stress_test_results
            },
            'recommendations': [],
            'action_items': []
        }
        
        # Generate executive summary
        overall_score = analysis_results.get('overall_score', 0)
        system_stability = load_test_results.get('system_stability', 'unknown')
        db_stability = stress_test_results.get('database_stability', 'unknown')
        
        report['executive_summary'] = {
            'overall_performance_score': overall_score,
            'system_stability': system_stability,
            'database_stability': db_stability,
            'optimization_improvements': optimization_results.get('total_improvements', 0),
            'load_test_success_rate': load_test_results.get('success_rate', 0),
            'database_test_success_rate': stress_test_results.get('success_rate', 0)
        }
        
        # Generate recommendations
        recommendations = []
        action_items = []
        
        # Based on performance analysis
        if overall_score < 0.7:
            recommendations.append("Performance score is below optimal - implement suggested optimizations")
            action_items.append("Review and implement database optimization recommendations")
        
        # Based on load testing
        if load_test_results.get('success_rate', 0) < 0.9:
            recommendations.append(f"Load test success rate ({load_test_results.get('success_rate', 0):.1%}) is below 90%")
            action_items.append("Investigate collection system failures and implement fixes")
        
        avg_response = load_test_results.get('avg_response_time_ms', 0)
        if avg_response > 10000:
            recommendations.append(f"Average response time ({avg_response:.0f}ms) is too high")
            action_items.append("Optimize API response times and implement caching")
        
        # Based on database stress testing
        if stress_test_results.get('success_rate', 0) < 0.95:
            recommendations.append(f"Database stress test success rate ({stress_test_results.get('success_rate', 0):.1%}) is below 95%")
            action_items.append("Optimize database queries and connection pooling")
        
        # Based on optimization results
        optimization_status = optimization_results.get('status', 'unknown')
        if optimization_status != 'completed':
            recommendations.append("Not all database optimizations completed successfully")
            action_items.append("Review failed optimizations and retry manually")
        
        # General recommendations
        if not recommendations:
            recommendations.append("System performance is within acceptable parameters")
            action_items.append("Continue regular monitoring and maintenance")
        
        report['recommendations'] = recommendations
        report['action_items'] = action_items
        
        logger.info(f"Performance report generated: {len(recommendations)} recommendations, {len(action_items)} action items")
        return report
        
    except Exception as e:
        logger.error(f"Error generating performance report: {e}")
        return {
            'error': str(e),
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'status': 'error'
            }
        }


@flow(
    name="performance_optimization_flow",
    description="Comprehensive performance optimization with analysis and testing",
    task_runner=ConcurrentTaskRunner()
)
async def performance_optimization_flow(
    run_load_test: bool = True,
    run_stress_test: bool = True,
    load_test_duration: int = 10,
    stress_test_duration: int = 5,
    concurrent_collections: int = 5,
    concurrent_queries: int = 10
) -> Dict[str, Any]:
    """
    Main flow for performance optimization and testing
    
    Args:
        run_load_test: Whether to run collection load testing
        run_stress_test: Whether to run database stress testing
        load_test_duration: Duration of load test in minutes
        stress_test_duration: Duration of stress test in minutes
        concurrent_collections: Number of concurrent collections for load test
        concurrent_queries: Number of concurrent queries for stress test
    
    Returns:
        Dict with optimization results and performance report
    """
    flow_logger = get_run_logger()
    flow_start = datetime.now()
    
    flow_results = {
        'flow_name': 'performance_optimization_flow',
        'execution_start': flow_start.isoformat(),
        'config': {
            'run_load_test': run_load_test,
            'run_stress_test': run_stress_test,
            'load_test_duration': load_test_duration,
            'stress_test_duration': stress_test_duration,
            'concurrent_collections': concurrent_collections,
            'concurrent_queries': concurrent_queries
        },
        'status': 'started'
    }
    
    try:
        flow_logger.info("Starting performance optimization flow")
        
        # Initialize services
        services = await initialize_performance_services()
        
        # Run performance analysis
        analysis_results = await run_performance_analysis_task(services)
        
        # Run database optimization
        optimization_results = await optimize_database_performance_task(services)
        
        # Run load testing (if enabled)
        load_test_results = {}
        if run_load_test:
            load_test_results = await load_test_collection_system_task(
                concurrent_collections=concurrent_collections,
                test_duration_minutes=load_test_duration
            )
        
        # Run stress testing (if enabled)
        stress_test_results = {}
        if run_stress_test:
            stress_test_results = await database_stress_test_task(
                concurrent_queries=concurrent_queries,
                test_duration_minutes=stress_test_duration
            )
        
        # Generate comprehensive report
        performance_report = await generate_performance_report_task(
            analysis_results,
            optimization_results,
            load_test_results,
            stress_test_results
        )
        
        # Store results
        flow_results['analysis_results'] = analysis_results
        flow_results['optimization_results'] = optimization_results
        flow_results['load_test_results'] = load_test_results
        flow_results['stress_test_results'] = stress_test_results
        flow_results['performance_report'] = performance_report
        
        # Determine overall flow status
        overall_score = analysis_results.get('overall_score', 0)
        optimization_status = optimization_results.get('status', 'unknown')
        
        if overall_score >= 0.8 and optimization_status == 'completed':
            flow_results['status'] = 'excellent'
        elif overall_score >= 0.6 and optimization_status in ['completed', 'partially_completed']:
            flow_results['status'] = 'good'
        elif overall_score >= 0.4:
            flow_results['status'] = 'needs_improvement'
        else:
            flow_results['status'] = 'critical'
        
        flow_results['execution_time_ms'] = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        flow_logger.info(f"Performance optimization flow completed: {flow_results['status']}")
        return flow_results
        
    except Exception as e:
        flow_results['status'] = 'failed'
        flow_results['error'] = str(e)
        flow_results['execution_time_ms'] = int((datetime.now() - flow_start).total_seconds() * 1000)
        
        flow_logger.error(f"Performance optimization flow failed: {e}")
        raise


# Scheduled flows can be added here for automation
if __name__ == "__main__":
    # Example of running the flow directly
    import asyncio
    asyncio.run(performance_optimization_flow())