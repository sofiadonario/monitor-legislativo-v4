import { apiConfig } from '../config/api';

export interface DocumentInput {
  id: string;
  title: string;
  summary: string;
  data_evento?: string;
  tipo_documento?: string;
  fonte?: string;
}

export interface BatchJobRequest {
  name: string;
  documents: DocumentInput[];
  processing_steps: string[];
  priority?: 'low' | 'normal' | 'high' | 'urgent';
  processing_options?: Record<string, any>;
  export_options?: Record<string, any>;
}

export interface BatchJob {
  job_id: string;
  name: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'paused';
  priority: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  total_documents: number;
  processed_documents: number;
  failed_documents: number;
  estimated_completion?: string;
  progress_percentage: number;
}

export interface ProcessingTask {
  task_id: string;
  document_id: string;
  processing_steps: string[];
  status: string;
  progress: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  retry_count: number;
}

export interface ProcessingStatistics {
  total_jobs: number;
  active_jobs: number;
  completed_jobs: number;
  failed_jobs: number;
  total_documents_processed: number;
  average_processing_time: number;
  success_rate: number;
  queue_length: number;
  estimated_queue_time: number;
  resource_utilization: Record<string, number>;
  hourly_throughput: number;
}

class BatchProcessingService {
  private baseUrl: string;

  constructor() {
    this.baseUrl = `${apiConfig.baseURL}/api/v1/batch`;
  }

  async createBatchJob(request: BatchJobRequest): Promise<{
    job_id: string;
    status: string;
    message: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/jobs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error(`Failed to create batch job: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error creating batch job:', error);
      throw error;
    }
  }

  async listBatchJobs(status?: string, limit: number = 50): Promise<BatchJob[]> {
    try {
      const params = new URLSearchParams({
        limit: limit.toString(),
      });

      if (status) {
        params.append('status', status);
      }

      const response = await fetch(`${this.baseUrl}/jobs?${params}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to list batch jobs: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error listing batch jobs:', error);
      throw error;
    }
  }

  async getBatchJob(jobId: string): Promise<BatchJob> {
    try {
      const response = await fetch(`${this.baseUrl}/jobs/${jobId}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get batch job: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting batch job:', error);
      throw error;
    }
  }

  async getJobTasks(jobId: string): Promise<ProcessingTask[]> {
    try {
      const response = await fetch(`${this.baseUrl}/jobs/${jobId}/tasks`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get job tasks: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting job tasks:', error);
      throw error;
    }
  }

  async getJobResults(jobId: string, exportFormat: 'json' | 'csv' = 'json'): Promise<any> {
    try {
      const params = new URLSearchParams({
        export_format: exportFormat,
      });

      const response = await fetch(`${this.baseUrl}/jobs/${jobId}/results?${params}`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get job results: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting job results:', error);
      throw error;
    }
  }

  async cancelBatchJob(jobId: string): Promise<{
    job_id: string;
    status: string;
    message: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/jobs/${jobId}/cancel`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error(`Failed to cancel batch job: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error cancelling batch job:', error);
      throw error;
    }
  }

  async pauseBatchJob(jobId: string): Promise<{
    job_id: string;
    status: string;
    message: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/jobs/${jobId}/pause`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error(`Failed to pause batch job: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error pausing batch job:', error);
      throw error;
    }
  }

  async resumeBatchJob(jobId: string): Promise<{
    job_id: string;
    status: string;
    message: string;
  }> {
    try {
      const response = await fetch(`${this.baseUrl}/jobs/${jobId}/resume`, {
        method: 'POST',
      });

      if (!response.ok) {
        throw new Error(`Failed to resume batch job: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error resuming batch job:', error);
      throw error;
    }
  }

  async getProcessingStatistics(): Promise<ProcessingStatistics> {
    try {
      const response = await fetch(`${this.baseUrl}/statistics`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Failed to get processing statistics: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting processing statistics:', error);
      throw error;
    }
  }

  async cleanupOldJobs(maxAgeDays: number = 30): Promise<{
    status: string;
    message: string;
  }> {
    try {
      const params = new URLSearchParams({
        max_age_days: maxAgeDays.toString(),
      });

      const response = await fetch(`${this.baseUrl}/jobs/cleanup?${params}`, {
        method: 'DELETE',
      });

      if (!response.ok) {
        throw new Error(`Failed to cleanup jobs: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error cleaning up jobs:', error);
      throw error;
    }
  }

  async getServiceHealth(): Promise<any> {
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
      });

      if (!response.ok) {
        throw new Error(`Health check failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting service health:', error);
      throw error;
    }
  }

  // Helper method to get available processing steps
  getAvailableProcessingSteps(): string[] {
    return [
      'entity_extraction',
      'knowledge_graph',
      'pattern_detection',
      'spatial_analysis',
      'government_standards',
      'ai_enhancement',
      'export_generation'
    ];
  }

  // Helper method to format job status for display
  formatJobStatus(status: string): string {
    const statusMap: Record<string, string> = {
      'pending': 'Pendente',
      'running': 'Executando',
      'completed': 'Concluído',
      'failed': 'Falhou',
      'cancelled': 'Cancelado',
      'paused': 'Pausado'
    };
    return statusMap[status] || status;
  }

  // Helper method to format priority for display
  formatPriority(priority: string): string {
    const priorityMap: Record<string, string> = {
      'low': 'Baixa',
      'normal': 'Normal',
      'high': 'Alta',
      'urgent': 'Urgente'
    };
    return priorityMap[priority.toLowerCase()] || priority;
  }

  // Helper method to calculate estimated remaining time
  calculateEstimatedRemainingTime(job: BatchJob): string {
    if (job.estimated_completion) {
      const now = new Date();
      const completion = new Date(job.estimated_completion);
      const remaining = completion.getTime() - now.getTime();
      
      if (remaining <= 0) {
        return 'Concluindo...';
      }
      
      const minutes = Math.floor(remaining / (1000 * 60));
      const hours = Math.floor(minutes / 60);
      
      if (hours > 0) {
        return `${hours}h ${minutes % 60}m`;
      } else {
        return `${minutes}m`;
      }
    }
    
    return 'N/A';
  }
}

export const batchProcessingService = new BatchProcessingService();