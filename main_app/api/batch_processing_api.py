"""
Batch Processing API Router
FastAPI endpoints for batch document processing with AI enhancement
"""
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
import logging
from datetime import datetime

from core.processing.batch_processor import (
    BatchDocumentProcessor, 
    ProcessingPriority, 
    ProcessingStatus,
    BatchJob,
    ProcessingTask
)
from core.models.legislative_data import LegislativeDocument

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/batch", tags=["Batch Processing"])

# Global processor instance
batch_processor: Optional[BatchDocumentProcessor] = None

async def get_batch_processor() -> BatchDocumentProcessor:
    """Get or create batch processor instance."""
    global batch_processor
    if batch_processor is None:
        batch_processor = BatchDocumentProcessor(max_workers=4, max_concurrent_jobs=2)
    return batch_processor

# Pydantic models for API
class DocumentInput(BaseModel):
    id: str
    title: str
    summary: str
    data_evento: Optional[str] = None
    tipo_documento: Optional[str] = None
    fonte: Optional[str] = None

class BatchJobRequest(BaseModel):
    name: str
    documents: List[DocumentInput]
    processing_steps: List[str]
    priority: str = "normal"  # low, normal, high, urgent
    processing_options: Optional[Dict[str, Any]] = None
    export_options: Optional[Dict[str, Any]] = None

class BatchJobResponse(BaseModel):
    job_id: str
    name: str
    description: str
    status: str
    priority: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    total_documents: int
    processed_documents: int
    failed_documents: int
    estimated_completion: Optional[str] = None
    progress_percentage: float

class TaskResponse(BaseModel):
    task_id: str
    document_id: str
    processing_steps: List[str]
    status: str
    progress: float
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int

class ProcessingStatisticsResponse(BaseModel):
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

def convert_priority(priority_str: str) -> ProcessingPriority:
    """Convert string priority to enum."""
    priority_map = {
        "low": ProcessingPriority.LOW,
        "normal": ProcessingPriority.NORMAL,
        "high": ProcessingPriority.HIGH,
        "urgent": ProcessingPriority.URGENT
    }
    return priority_map.get(priority_str.lower(), ProcessingPriority.NORMAL)

def convert_job_to_response(job: BatchJob) -> BatchJobResponse:
    """Convert BatchJob to response model."""
    progress = 0.0
    if job.total_documents > 0:
        progress = (job.processed_documents / job.total_documents) * 100
    
    return BatchJobResponse(
        job_id=job.job_id,
        name=job.name,
        description=job.description,
        status=job.status.value,
        priority=job.priority.name.lower(),
        created_at=job.created_at.isoformat(),
        started_at=job.started_at.isoformat() if job.started_at else None,
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        total_documents=job.total_documents,
        processed_documents=job.processed_documents,
        failed_documents=job.failed_documents,
        estimated_completion=job.estimated_completion.isoformat() if job.estimated_completion else None,
        progress_percentage=progress
    )

@router.post("/jobs", response_model=Dict[str, str])
async def create_batch_job(request: BatchJobRequest, background_tasks: BackgroundTasks):
    """Create and submit a new batch processing job."""
    try:
        processor = await get_batch_processor()
        
        # Convert documents to LegislativeDocument objects
        documents = [
            LegislativeDocument(
                id=doc.id,
                title=doc.title,
                summary=doc.summary,
                data_evento=doc.data_evento or "",
                tipo_documento=doc.tipo_documento or "",
                fonte=doc.fonte or ""
            )
            for doc in request.documents
        ]
        
        # Validate processing steps
        valid_steps = [
            'entity_extraction', 'knowledge_graph', 'pattern_detection',
            'spatial_analysis', 'government_standards', 'ai_enhancement',
            'export_generation'
        ]
        
        invalid_steps = [step for step in request.processing_steps if step not in valid_steps]
        if invalid_steps:
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid processing steps: {invalid_steps}. Valid steps: {valid_steps}"
            )
        
        # Convert priority
        priority = convert_priority(request.priority)
        
        # Create batch job
        job = await processor.create_batch_job(
            name=request.name,
            documents=documents,
            processing_steps=request.processing_steps,
            priority=priority,
            processing_options=request.processing_options,
            export_options=request.export_options
        )
        
        # Submit job
        job_id = await processor.submit_job(job)
        
        return {
            "job_id": job_id,
            "status": "submitted",
            "message": f"Batch job created with {len(documents)} documents"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating batch job: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create batch job: {str(e)}")

@router.get("/jobs", response_model=List[BatchJobResponse])
async def list_batch_jobs(
    status: Optional[str] = Query(None, description="Filter by job status"),
    limit: int = Query(50, description="Maximum number of jobs to return")
):
    """List batch jobs with optional status filtering."""
    try:
        processor = await get_batch_processor()
        
        # Get all jobs (active + history + queue)
        all_jobs = []
        all_jobs.extend(processor.active_jobs.values())
        all_jobs.extend(processor.job_history)
        all_jobs.extend(processor.processing_queue)
        
        # Filter by status if provided
        if status:
            all_jobs = [job for job in all_jobs if job.status.value == status]
        
        # Sort by creation date (newest first)
        all_jobs.sort(key=lambda x: x.created_at, reverse=True)
        
        # Limit results
        all_jobs = all_jobs[:limit]
        
        return [convert_job_to_response(job) for job in all_jobs]
        
    except Exception as e:
        logger.error(f"Error listing batch jobs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to list batch jobs: {str(e)}")

@router.get("/jobs/{job_id}", response_model=BatchJobResponse)
async def get_batch_job(job_id: str):
    """Get detailed information about a specific batch job."""
    try:
        processor = await get_batch_processor()
        
        job = await processor.get_job_status(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Batch job not found: {job_id}")
        
        return convert_job_to_response(job)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting batch job: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get batch job: {str(e)}")

@router.get("/jobs/{job_id}/tasks", response_model=List[TaskResponse])
async def get_job_tasks(job_id: str):
    """Get all tasks for a specific batch job."""
    try:
        processor = await get_batch_processor()
        
        job = await processor.get_job_status(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Batch job not found: {job_id}")
        
        task_responses = []
        for task in job.tasks:
            task_responses.append(TaskResponse(
                task_id=task.task_id,
                document_id=task.document_id,
                processing_steps=task.processing_steps,
                status=task.status.value,
                progress=task.progress,
                created_at=task.created_at.isoformat(),
                started_at=task.started_at.isoformat() if task.started_at else None,
                completed_at=task.completed_at.isoformat() if task.completed_at else None,
                error_message=task.error_message,
                retry_count=task.retry_count
            ))
        
        return task_responses
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job tasks: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get job tasks: {str(e)}")

@router.get("/jobs/{job_id}/results")
async def get_job_results(
    job_id: str,
    export_format: str = Query("json", description="Export format: json or csv")
):
    """Get processing results for a batch job."""
    try:
        processor = await get_batch_processor()
        
        job = await processor.get_job_status(job_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Batch job not found: {job_id}")
        
        if job.status not in [ProcessingStatus.COMPLETED, ProcessingStatus.FAILED]:
            raise HTTPException(status_code=400, detail=f"Job not completed yet. Status: {job.status.value}")
        
        # Export results
        export_data = await processor.export_job_results(job_id, export_format)
        
        return export_data
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting job results: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get job results: {str(e)}")

@router.post("/jobs/{job_id}/cancel")
async def cancel_batch_job(job_id: str):
    """Cancel a batch job."""
    try:
        processor = await get_batch_processor()
        
        success = await processor.cancel_job(job_id)
        
        if not success:
            raise HTTPException(status_code=404, detail=f"Batch job not found or cannot be cancelled: {job_id}")
        
        return {
            "job_id": job_id,
            "status": "cancelled",
            "message": "Batch job cancelled successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling batch job: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to cancel batch job: {str(e)}")

@router.post("/jobs/{job_id}/pause")
async def pause_batch_job(job_id: str):
    """Pause a batch job."""
    try:
        processor = await get_batch_processor()
        
        success = await processor.pause_job(job_id)
        
        if not success:
            raise HTTPException(status_code=404, detail=f"Batch job not found or cannot be paused: {job_id}")
        
        return {
            "job_id": job_id,
            "status": "paused",
            "message": "Batch job paused successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error pausing batch job: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to pause batch job: {str(e)}")

@router.post("/jobs/{job_id}/resume")
async def resume_batch_job(job_id: str):
    """Resume a paused batch job."""
    try:
        processor = await get_batch_processor()
        
        success = await processor.resume_job(job_id)
        
        if not success:
            raise HTTPException(status_code=404, detail=f"Batch job not found or cannot be resumed: {job_id}")
        
        return {
            "job_id": job_id,
            "status": "resumed",
            "message": "Batch job resumed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resuming batch job: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to resume batch job: {str(e)}")

@router.get("/statistics", response_model=ProcessingStatisticsResponse)
async def get_processing_statistics():
    """Get batch processing statistics."""
    try:
        processor = await get_batch_processor()
        
        stats = processor.get_processing_statistics()
        
        return ProcessingStatisticsResponse(
            total_jobs=stats.total_jobs,
            active_jobs=stats.active_jobs,
            completed_jobs=stats.completed_jobs,
            failed_jobs=stats.failed_jobs,
            total_documents_processed=stats.total_documents_processed,
            average_processing_time=stats.average_processing_time,
            success_rate=stats.success_rate,
            queue_length=stats.queue_length,
            estimated_queue_time=stats.estimated_queue_time,
            resource_utilization=stats.resource_utilization,
            hourly_throughput=stats.hourly_throughput
        )
        
    except Exception as e:
        logger.error(f"Error getting processing statistics: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get processing statistics: {str(e)}")

@router.delete("/jobs/cleanup")
async def cleanup_old_jobs(max_age_days: int = Query(30, description="Maximum age in days for job retention")):
    """Clean up old completed jobs."""
    try:
        processor = await get_batch_processor()
        
        await processor.cleanup_completed_jobs(max_age_days)
        
        return {
            "status": "success",
            "message": f"Cleaned up jobs older than {max_age_days} days"
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up jobs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to cleanup jobs: {str(e)}")

@router.get("/health")
async def get_batch_service_health():
    """Get batch processing service health status."""
    try:
        processor = await get_batch_processor()
        
        stats = processor.get_processing_statistics()
        
        return {
            "status": "healthy",
            "service": "batch_processing",
            "components": {
                "task_executors": "operational",
                "queue_management": "active",
                "parallel_processing": "enabled",
                "progress_tracking": "real_time"
            },
            "capacity": {
                "max_workers": processor.max_workers,
                "max_concurrent_jobs": processor.max_concurrent_jobs,
                "current_active_jobs": stats.active_jobs,
                "current_queue_length": stats.queue_length
            },
            "performance": {
                "total_processed": stats.total_documents_processed,
                "success_rate": stats.success_rate,
                "average_processing_time": stats.average_processing_time,
                "hourly_throughput": stats.hourly_throughput
            },
            "available_steps": [
                "entity_extraction", "knowledge_graph", "pattern_detection",
                "spatial_analysis", "government_standards", "ai_enhancement",
                "export_generation"
            ]
        }
        
    except Exception as e:
        logger.error(f"Batch service health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "service": "batch_processing",
            "error": str(e)
        }