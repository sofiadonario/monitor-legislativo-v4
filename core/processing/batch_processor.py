"""
Batch Document Processing Service
Advanced batch processing with AI enhancement and parallel execution
"""
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import asyncio
import uuid
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import logging
from pathlib import Path

from core.config.config import Config
from core.utils.logger import Logger
from core.models.legislative_data import LegislativeDocument
from core.ai.entity_extractor import EntityExtractor
from core.ai.knowledge_graph import KnowledgeGraphBuilder
from core.ai.pattern_detector import PatternDetector
from core.data_processing.government_standards import GovernmentStandardsProcessor
from core.services.spatial_analysis import SpatialAnalysisService

logger = Logger()


class ProcessingStatus(Enum):
    """Processing status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class ProcessingPriority(Enum):
    """Processing priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4


@dataclass
class ProcessingTask:
    """Individual processing task."""
    task_id: str
    document_id: str
    processing_steps: List[str]
    priority: ProcessingPriority
    status: ProcessingStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    progress: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class BatchJob:
    """Batch processing job containing multiple tasks."""
    job_id: str
    name: str
    description: str
    tasks: List[ProcessingTask]
    status: ProcessingStatus
    priority: ProcessingPriority
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_documents: int = 0
    processed_documents: int = 0
    failed_documents: int = 0
    estimated_completion: Optional[datetime] = None
    processing_options: Dict[str, Any] = field(default_factory=dict)
    export_options: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessingResult:
    """Result of document processing."""
    document_id: str
    task_id: str
    processing_time: float
    success: bool
    error_message: Optional[str] = None
    extracted_entities: Optional[Dict] = None
    knowledge_graph_data: Optional[Dict] = None
    detected_patterns: Optional[Dict] = None
    spatial_analysis: Optional[Dict] = None
    government_standards_validation: Optional[Dict] = None
    ai_analysis: Optional[Dict] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProcessingStatistics:
    """Processing statistics and metrics."""
    total_jobs: int
    active_jobs: int
    completed_jobs: int
    failed_jobs: int
    total_documents_processed: int
    average_processing_time: float
    success_rate: float
    queue_length: int
    estimated_queue_time: float
    resource_utilization: Dict[str, float]
    hourly_throughput: float


class BatchDocumentProcessor:
    """Advanced batch document processing service with AI enhancement."""
    
    def __init__(self, max_workers: int = 4, max_concurrent_jobs: int = 2):
        self.config = Config()
        self.max_workers = max_workers
        self.max_concurrent_jobs = max_concurrent_jobs
        
        # Initialize AI services
        self.entity_extractor = EntityExtractor()
        self.knowledge_graph_builder = KnowledgeGraphBuilder()
        self.pattern_detector = PatternDetector()
        self.government_processor = GovernmentStandardsProcessor()
        self.spatial_analyzer = SpatialAnalysisService()
        
        # Job management
        self.active_jobs: Dict[str, BatchJob] = {}
        self.job_history: List[BatchJob] = []
        self.processing_queue: List[BatchJob] = []
        self.task_executors: Dict[str, ThreadPoolExecutor] = {}
        
        # Processing functions mapping
        self.processing_functions = {
            'entity_extraction': self._process_entity_extraction,
            'knowledge_graph': self._process_knowledge_graph,
            'pattern_detection': self._process_pattern_detection,
            'spatial_analysis': self._process_spatial_analysis,
            'government_standards': self._process_government_standards,
            'ai_enhancement': self._process_ai_enhancement,
            'export_generation': self._process_export_generation
        }
        
        # Statistics tracking
        self.processing_stats = {
            'total_processed': 0,
            'total_time': 0.0,
            'success_count': 0,
            'failure_count': 0,
            'start_time': datetime.now()
        }
        
    async def create_batch_job(self, name: str, documents: List[LegislativeDocument],
                              processing_steps: List[str], 
                              priority: ProcessingPriority = ProcessingPriority.NORMAL,
                              processing_options: Optional[Dict[str, Any]] = None,
                              export_options: Optional[Dict[str, Any]] = None) -> BatchJob:
        """Create a new batch processing job."""
        try:
            job_id = f"batch_{uuid.uuid4().hex[:8]}"
            
            # Create tasks for each document
            tasks = []
            for doc in documents:
                task_id = f"task_{uuid.uuid4().hex[:8]}"
                task = ProcessingTask(
                    task_id=task_id,
                    document_id=doc.id,
                    processing_steps=processing_steps.copy(),
                    priority=priority,
                    status=ProcessingStatus.PENDING,
                    created_at=datetime.now()
                )
                tasks.append(task)
            
            # Create batch job
            job = BatchJob(
                job_id=job_id,
                name=name,
                description=f"Batch processing of {len(documents)} documents",
                tasks=tasks,
                status=ProcessingStatus.PENDING,
                priority=priority,
                created_at=datetime.now(),
                total_documents=len(documents),
                processing_options=processing_options or {},
                export_options=export_options or {}
            )
            
            # Estimate completion time
            job.estimated_completion = self._estimate_completion_time(job)
            
            logger.info(f"Created batch job {job_id} with {len(tasks)} tasks")
            return job
            
        except Exception as e:
            logger.error(f"Error creating batch job: {str(e)}")
            raise
    
    async def submit_job(self, job: BatchJob) -> str:
        """Submit a batch job for processing."""
        try:
            # Add to processing queue
            self.processing_queue.append(job)
            
            # Sort queue by priority
            self.processing_queue.sort(key=lambda j: j.priority.value, reverse=True)
            
            logger.info(f"Submitted job {job.job_id} to processing queue")
            
            # Start processing if capacity available
            await self._process_queue()
            
            return job.job_id
            
        except Exception as e:
            logger.error(f"Error submitting job: {str(e)}")
            raise
    
    async def _process_queue(self):
        """Process jobs in the queue."""
        try:
            # Check if we can start new jobs
            if len(self.active_jobs) >= self.max_concurrent_jobs:
                return
            
            # Start jobs from queue
            while self.processing_queue and len(self.active_jobs) < self.max_concurrent_jobs:
                job = self.processing_queue.pop(0)
                await self._start_job_processing(job)
                
        except Exception as e:
            logger.error(f"Error processing queue: {str(e)}")
    
    async def _start_job_processing(self, job: BatchJob):
        """Start processing a batch job."""
        try:
            job.status = ProcessingStatus.RUNNING
            job.started_at = datetime.now()
            self.active_jobs[job.job_id] = job
            
            logger.info(f"Started processing job {job.job_id}")
            
            # Create executor for this job
            executor = ThreadPoolExecutor(max_workers=self.max_workers)
            self.task_executors[job.job_id] = executor
            
            # Process tasks in parallel
            asyncio.create_task(self._process_job_tasks(job))
            
        except Exception as e:
            logger.error(f"Error starting job processing: {str(e)}")
            job.status = ProcessingStatus.FAILED
    
    async def _process_job_tasks(self, job: BatchJob):
        """Process all tasks in a job."""
        try:
            executor = self.task_executors[job.job_id]
            
            # Process tasks in batches
            batch_size = self.max_workers
            task_batches = [job.tasks[i:i + batch_size] 
                           for i in range(0, len(job.tasks), batch_size)]
            
            for batch in task_batches:
                # Process batch in parallel
                futures = []
                for task in batch:
                    future = executor.submit(self._process_single_task, task, job)
                    futures.append(future)
                
                # Wait for batch completion
                for future in futures:
                    result = await asyncio.get_event_loop().run_in_executor(None, future.result)
                    await self._handle_task_result(result, job)
            
            # Complete job
            await self._complete_job(job)
            
        except Exception as e:
            logger.error(f"Error processing job tasks: {str(e)}")
            job.status = ProcessingStatus.FAILED
            await self._complete_job(job)
    
    def _process_single_task(self, task: ProcessingTask, job: BatchJob) -> ProcessingResult:
        """Process a single task."""
        start_time = datetime.now()
        
        try:
            task.status = ProcessingStatus.RUNNING
            task.started_at = start_time
            
            # Load document (mock implementation)
            document = self._load_document(task.document_id)
            if not document:
                raise ValueError(f"Document {task.document_id} not found")
            
            result = ProcessingResult(
                document_id=task.document_id,
                task_id=task.task_id,
                processing_time=0.0,
                success=False
            )
            
            # Execute processing steps
            total_steps = len(task.processing_steps)
            for i, step in enumerate(task.processing_steps):
                try:
                    step_result = self._execute_processing_step(step, document, job.processing_options)
                    self._merge_step_result(result, step, step_result)
                    
                    # Update progress
                    task.progress = (i + 1) / total_steps
                    
                except Exception as e:
                    logger.warning(f"Step {step} failed for task {task.task_id}: {str(e)}")
                    if task.retry_count < task.max_retries:
                        task.retry_count += 1
                        # Could implement step retry logic here
                    
            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds()
            result.processing_time = processing_time
            result.success = True
            
            task.status = ProcessingStatus.COMPLETED
            task.completed_at = datetime.now()
            
            return result
            
        except Exception as e:
            processing_time = (datetime.now() - start_time).total_seconds()
            
            task.status = ProcessingStatus.FAILED
            task.error_message = str(e)
            task.completed_at = datetime.now()
            
            return ProcessingResult(
                document_id=task.document_id,
                task_id=task.task_id,
                processing_time=processing_time,
                success=False,
                error_message=str(e)
            )
    
    def _load_document(self, document_id: str) -> Optional[LegislativeDocument]:
        """Load document by ID (mock implementation)."""
        # In production, this would load from database or file system
        # For now, return a mock document
        return LegislativeDocument(
            id=document_id,
            title=f"Mock Document {document_id}",
            summary="Mock document for batch processing testing",
            data_evento="2024-01-01",
            tipo_documento="Lei",
            fonte="Mock Source"
        )
    
    def _execute_processing_step(self, step: str, document: LegislativeDocument, 
                                options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single processing step."""
        if step not in self.processing_functions:
            raise ValueError(f"Unknown processing step: {step}")
        
        processing_func = self.processing_functions[step]
        return processing_func(document, options)
    
    def _process_entity_extraction(self, document: LegislativeDocument, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process entity extraction step."""
        try:
            entities = self.entity_extractor.extract_entities(document)
            return {
                'entities': [entity.__dict__ for entity in entities],
                'entity_count': len(entities),
                'processing_time': 0.5  # Mock processing time
            }
        except Exception as e:
            logger.error(f"Entity extraction failed: {str(e)}")
            return {'error': str(e)}
    
    def _process_knowledge_graph(self, document: LegislativeDocument, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process knowledge graph building step."""
        try:
            # Mock knowledge graph data
            return {
                'nodes': 10,
                'edges': 15,
                'centrality_scores': {'node1': 0.8, 'node2': 0.6},
                'processing_time': 1.2
            }
        except Exception as e:
            logger.error(f"Knowledge graph building failed: {str(e)}")
            return {'error': str(e)}
    
    def _process_pattern_detection(self, document: LegislativeDocument, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process pattern detection step."""
        try:
            # Mock pattern detection
            return {
                'patterns_found': 3,
                'pattern_types': ['temporal', 'thematic'],
                'confidence_scores': [0.85, 0.72, 0.91],
                'processing_time': 0.8
            }
        except Exception as e:
            logger.error(f"Pattern detection failed: {str(e)}")
            return {'error': str(e)}
    
    def _process_spatial_analysis(self, document: LegislativeDocument, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process spatial analysis step."""
        try:
            # Mock spatial analysis
            return {
                'locations_found': 2,
                'primary_location': 'São Paulo',
                'coverage_area': ['SP', 'RJ'],
                'confidence_score': 0.78,
                'processing_time': 1.0
            }
        except Exception as e:
            logger.error(f"Spatial analysis failed: {str(e)}")
            return {'error': str(e)}
    
    def _process_government_standards(self, document: LegislativeDocument, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process government standards validation step."""
        try:
            # Mock government standards validation
            return {
                'compliance_score': 0.82,
                'digitization_level': 3,
                'quality_issues': 2,
                'recommendations': ['Complete metadata', 'Improve structure'],
                'processing_time': 0.6
            }
        except Exception as e:
            logger.error(f"Government standards validation failed: {str(e)}")
            return {'error': str(e)}
    
    def _process_ai_enhancement(self, document: LegislativeDocument, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process AI enhancement step."""
        try:
            # Mock AI enhancement
            return {
                'enhanced_summary': f"AI-enhanced summary of {document.title}",
                'keywords': ['transporte', 'regulamentação', 'brasil'],
                'sentiment_score': 0.65,
                'relevance_score': 0.88,
                'processing_time': 2.1
            }
        except Exception as e:
            logger.error(f"AI enhancement failed: {str(e)}")
            return {'error': str(e)}
    
    def _process_export_generation(self, document: LegislativeDocument, options: Dict[str, Any]) -> Dict[str, Any]:
        """Process export generation step."""
        try:
            export_formats = options.get('export_formats', ['json'])
            exports = {}
            
            for format_type in export_formats:
                if format_type == 'json':
                    exports['json'] = {'file_path': f'/exports/{document.id}.json', 'size_kb': 15}
                elif format_type == 'pdf':
                    exports['pdf'] = {'file_path': f'/exports/{document.id}.pdf', 'size_kb': 245}
                elif format_type == 'csv':
                    exports['csv'] = {'file_path': f'/exports/{document.id}.csv', 'size_kb': 8}
            
            return {
                'exports': exports,
                'total_size_kb': sum(exp['size_kb'] for exp in exports.values()),
                'processing_time': 0.9
            }
        except Exception as e:
            logger.error(f"Export generation failed: {str(e)}")
            return {'error': str(e)}
    
    def _merge_step_result(self, result: ProcessingResult, step: str, step_result: Dict[str, Any]):
        """Merge step result into overall processing result."""
        if 'error' in step_result:
            return  # Skip failed steps
        
        if step == 'entity_extraction':
            result.extracted_entities = step_result
        elif step == 'knowledge_graph':
            result.knowledge_graph_data = step_result
        elif step == 'pattern_detection':
            result.detected_patterns = step_result
        elif step == 'spatial_analysis':
            result.spatial_analysis = step_result
        elif step == 'government_standards':
            result.government_standards_validation = step_result
        elif step == 'ai_enhancement':
            result.ai_analysis = step_result
        else:
            # Store in metadata
            result.metadata[step] = step_result
    
    async def _handle_task_result(self, result: ProcessingResult, job: BatchJob):
        """Handle the result of a completed task."""
        try:
            if result.success:
                job.processed_documents += 1
                self.processing_stats['success_count'] += 1
            else:
                job.failed_documents += 1
                self.processing_stats['failure_count'] += 1
            
            # Store result
            job.results[result.document_id] = result.__dict__
            
            # Update statistics
            self.processing_stats['total_processed'] += 1
            self.processing_stats['total_time'] += result.processing_time
            
            logger.debug(f"Processed task {result.task_id} for document {result.document_id}")
            
        except Exception as e:
            logger.error(f"Error handling task result: {str(e)}")
    
    async def _complete_job(self, job: BatchJob):
        """Complete a batch job."""
        try:
            job.status = ProcessingStatus.COMPLETED if job.failed_documents == 0 else ProcessingStatus.FAILED
            job.completed_at = datetime.now()
            
            # Clean up executor
            if job.job_id in self.task_executors:
                self.task_executors[job.job_id].shutdown(wait=False)
                del self.task_executors[job.job_id]
            
            # Move from active to history
            if job.job_id in self.active_jobs:
                del self.active_jobs[job.job_id]
            self.job_history.append(job)
            
            # Process next jobs in queue
            await self._process_queue()
            
            logger.info(f"Completed job {job.job_id} - {job.processed_documents} successful, {job.failed_documents} failed")
            
        except Exception as e:
            logger.error(f"Error completing job: {str(e)}")
    
    def _estimate_completion_time(self, job: BatchJob) -> datetime:
        """Estimate completion time for a job."""
        # Base estimate on average processing time per document
        avg_time_per_doc = 3.0  # seconds
        if self.processing_stats['total_processed'] > 0:
            avg_time_per_doc = self.processing_stats['total_time'] / self.processing_stats['total_processed']
        
        # Adjust for number of steps
        time_multiplier = len(job.tasks[0].processing_steps) * 0.3 if job.tasks else 1.0
        
        # Estimate total time
        estimated_seconds = job.total_documents * avg_time_per_doc * time_multiplier
        
        # Add queue wait time
        queue_position = len(self.processing_queue) + len(self.active_jobs)
        queue_wait_time = queue_position * 60  # 1 minute per queued job
        
        return datetime.now() + timedelta(seconds=estimated_seconds + queue_wait_time)
    
    async def get_job_status(self, job_id: str) -> Optional[BatchJob]:
        """Get the status of a batch job."""
        # Check active jobs
        if job_id in self.active_jobs:
            return self.active_jobs[job_id]
        
        # Check job history
        for job in self.job_history:
            if job.job_id == job_id:
                return job
        
        # Check queue
        for job in self.processing_queue:
            if job.job_id == job_id:
                return job
        
        return None
    
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a batch job."""
        try:
            # Check if job is in queue
            for i, job in enumerate(self.processing_queue):
                if job.job_id == job_id:
                    job.status = ProcessingStatus.CANCELLED
                    self.processing_queue.pop(i)
                    self.job_history.append(job)
                    logger.info(f"Cancelled queued job {job_id}")
                    return True
            
            # Check if job is active
            if job_id in self.active_jobs:
                job = self.active_jobs[job_id]
                job.status = ProcessingStatus.CANCELLED
                
                # Shutdown executor
                if job_id in self.task_executors:
                    self.task_executors[job_id].shutdown(wait=False)
                    del self.task_executors[job_id]
                
                # Move to history
                del self.active_jobs[job_id]
                self.job_history.append(job)
                
                logger.info(f"Cancelled active job {job_id}")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error cancelling job: {str(e)}")
            return False
    
    async def pause_job(self, job_id: str) -> bool:
        """Pause a batch job."""
        try:
            if job_id in self.active_jobs:
                job = self.active_jobs[job_id]
                job.status = ProcessingStatus.PAUSED
                logger.info(f"Paused job {job_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error pausing job: {str(e)}")
            return False
    
    async def resume_job(self, job_id: str) -> bool:
        """Resume a paused batch job."""
        try:
            if job_id in self.active_jobs:
                job = self.active_jobs[job_id]
                if job.status == ProcessingStatus.PAUSED:
                    job.status = ProcessingStatus.RUNNING
                    logger.info(f"Resumed job {job_id}")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error resuming job: {str(e)}")
            return False
    
    def get_processing_statistics(self) -> ProcessingStatistics:
        """Get processing statistics."""
        try:
            total_jobs = len(self.active_jobs) + len(self.job_history) + len(self.processing_queue)
            active_jobs = len(self.active_jobs)
            completed_jobs = len([j for j in self.job_history if j.status == ProcessingStatus.COMPLETED])
            failed_jobs = len([j for j in self.job_history if j.status == ProcessingStatus.FAILED])
            
            avg_processing_time = 0.0
            if self.processing_stats['total_processed'] > 0:
                avg_processing_time = self.processing_stats['total_time'] / self.processing_stats['total_processed']
            
            success_rate = 0.0
            total_attempts = self.processing_stats['success_count'] + self.processing_stats['failure_count']
            if total_attempts > 0:
                success_rate = self.processing_stats['success_count'] / total_attempts
            
            # Calculate hourly throughput
            runtime_hours = (datetime.now() - self.processing_stats['start_time']).total_seconds() / 3600
            hourly_throughput = self.processing_stats['total_processed'] / runtime_hours if runtime_hours > 0 else 0
            
            # Estimate queue time
            queue_time = len(self.processing_queue) * avg_processing_time if avg_processing_time > 0 else 0
            
            return ProcessingStatistics(
                total_jobs=total_jobs,
                active_jobs=active_jobs,
                completed_jobs=completed_jobs,
                failed_jobs=failed_jobs,
                total_documents_processed=self.processing_stats['total_processed'],
                average_processing_time=avg_processing_time,
                success_rate=success_rate,
                queue_length=len(self.processing_queue),
                estimated_queue_time=queue_time,
                resource_utilization={
                    'cpu': len(self.active_jobs) / self.max_concurrent_jobs,
                    'memory': 0.6,  # Mock value
                    'workers': sum(1 for executor in self.task_executors.values()) / self.max_workers
                },
                hourly_throughput=hourly_throughput
            )
            
        except Exception as e:
            logger.error(f"Error calculating statistics: {str(e)}")
            raise
    
    async def export_job_results(self, job_id: str, export_format: str = 'json') -> Optional[Dict[str, Any]]:
        """Export job results in specified format."""
        try:
            job = await self.get_job_status(job_id)
            if not job:
                return None
            
            export_data = {
                'job_info': {
                    'job_id': job.job_id,
                    'name': job.name,
                    'description': job.description,
                    'status': job.status.value,
                    'created_at': job.created_at.isoformat(),
                    'completed_at': job.completed_at.isoformat() if job.completed_at else None,
                    'total_documents': job.total_documents,
                    'processed_documents': job.processed_documents,
                    'failed_documents': job.failed_documents
                },
                'results': job.results,
                'statistics': {
                    'success_rate': job.processed_documents / job.total_documents if job.total_documents > 0 else 0,
                    'average_processing_time': sum(
                        result.get('processing_time', 0) for result in job.results.values()
                    ) / len(job.results) if job.results else 0
                }
            }
            
            if export_format == 'json':
                return export_data
            elif export_format == 'csv':
                # Convert to CSV format (simplified)
                return {'csv_data': 'document_id,status,processing_time\\n' + 
                       '\\n'.join(f"{doc_id},{result.get('success', False)},{result.get('processing_time', 0)}"
                                for doc_id, result in job.results.items())}
            else:
                raise ValueError(f"Unsupported export format: {export_format}")
                
        except Exception as e:
            logger.error(f"Error exporting job results: {str(e)}")
            raise
    
    async def cleanup_completed_jobs(self, max_age_days: int = 30):
        """Clean up old completed jobs."""
        try:
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            
            # Remove old jobs from history
            old_jobs = [job for job in self.job_history 
                       if job.completed_at and job.completed_at < cutoff_date]
            
            for job in old_jobs:
                self.job_history.remove(job)
            
            logger.info(f"Cleaned up {len(old_jobs)} old jobs")
            
        except Exception as e:
            logger.error(f"Error cleaning up jobs: {str(e)}")
    
    def shutdown(self):
        """Shutdown the batch processor."""
        try:
            # Cancel all active jobs
            for job_id in list(self.active_jobs.keys()):
                asyncio.create_task(self.cancel_job(job_id))
            
            # Shutdown all executors
            for executor in self.task_executors.values():
                executor.shutdown(wait=True)
            
            logger.info("Batch processor shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {str(e)}")