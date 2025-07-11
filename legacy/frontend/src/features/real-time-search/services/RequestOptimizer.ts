/**
 * Request Optimizer Service
 * Implements intelligent request batching, deduplication, retry logic, and rate limiting
 */

interface PendingRequest<T> {
  id: string;
  request: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: any) => void;
  timestamp: number;
  retryCount: number;
  priority: 'high' | 'medium' | 'low';
  timeout: number;
}

interface BatchableRequest {
  type: 'search' | 'document' | 'suggestions' | 'health';
  params: Record<string, any>;
  cacheKey?: string;
}

interface RequestMetrics {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  deduplicatedRequests: number;
  batchedRequests: number;
  averageResponseTime: number;
  requestsPerMinute: number;
}

export class RequestOptimizer {
  private pendingRequests = new Map<string, PendingRequest<any>>();
  private requestQueue: PendingRequest<any>[] = [];
  private batchQueue = new Map<string, BatchableRequest[]>();
  private activeRequests = new Set<string>();
  private rateLimitQueue: Array<() => void> = [];
  private metrics: RequestMetrics = {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    deduplicatedRequests: 0,
    batchedRequests: 0,
    averageResponseTime: 0,
    requestsPerMinute: 0
  };

  // Configuration
  private readonly config = {
    maxConcurrentRequests: 5,
    batchDelay: 100, // ms
    maxBatchSize: 10,
    retryAttempts: 3,
    retryDelay: 1000, // ms
    rateLimit: {
      maxRequestsPerMinute: 100,
      windowSize: 60000 // 1 minute
    },
    timeouts: {
      search: 10000,
      document: 15000,
      suggestions: 5000,
      health: 3000
    }
  };

  private requestLog: number[] = [];

  constructor() {
    // Start processing queues
    this.startQueueProcessor();
    this.startBatchProcessor();
    this.startMetricsCollector();
  }

  /**
   * Optimize a request with deduplication, batching, and retry logic
   */
  async optimizeRequest<T>(
    requestId: string,
    request: () => Promise<T>,
    options: {
      priority?: 'high' | 'medium' | 'low';
      timeout?: number;
      retryable?: boolean;
      batchable?: BatchableRequest;
    } = {}
  ): Promise<T> {
    const {
      priority = 'medium',
      timeout = this.config.timeouts.search,
      retryable = true,
      batchable
    } = options;

    // Check for existing identical request (deduplication)
    if (this.pendingRequests.has(requestId)) {
      this.metrics.deduplicatedRequests++;
      return new Promise((resolve, reject) => {
        const existing = this.pendingRequests.get(requestId)!;
        const originalResolve = existing.resolve;
        const originalReject = existing.reject;
        
        existing.resolve = (value) => {
          resolve(value);
          originalResolve(value);
        };
        
        existing.reject = (error) => {
          reject(error);
          originalReject(error);
        };
      });
    }

    // Check rate limit
    if (!this.isWithinRateLimit()) {
      return new Promise((resolve, reject) => {
        this.rateLimitQueue.push(() => {
          this.optimizeRequest(requestId, request, options).then(resolve).catch(reject);
        });
      });
    }

    // Handle batchable requests
    if (batchable) {
      return this.handleBatchableRequest(requestId, batchable, request, { priority, timeout });
    }

    // Create pending request
    return new Promise<T>((resolve, reject) => {
      const pendingRequest: PendingRequest<T> = {
        id: requestId,
        request,
        resolve,
        reject,
        timestamp: Date.now(),
        retryCount: 0,
        priority,
        timeout
      };

      this.pendingRequests.set(requestId, pendingRequest);
      this.requestQueue.push(pendingRequest);
      this.sortRequestQueue();
      
      this.metrics.totalRequests++;
      this.logRequest();
    });
  }

  /**
   * Handle batchable requests with intelligent batching
   */
  private async handleBatchableRequest<T>(
    requestId: string,
    batchable: BatchableRequest,
    request: () => Promise<T>,
    options: { priority: string; timeout: number }
  ): Promise<T> {
    const batchKey = this.generateBatchKey(batchable);
    
    if (!this.batchQueue.has(batchKey)) {
      this.batchQueue.set(batchKey, []);
    }
    
    this.batchQueue.get(batchKey)!.push(batchable);
    
    // If batch is full, process immediately
    if (this.batchQueue.get(batchKey)!.length >= this.config.maxBatchSize) {
      return this.processBatch(batchKey);
    }
    
    // Otherwise, wait for batch delay or queue it normally
    return new Promise<T>((resolve, reject) => {
      setTimeout(() => {
        if (this.batchQueue.has(batchKey)) {
          this.processBatch(batchKey).then(resolve).catch(reject);
        }
      }, this.config.batchDelay);
      
      // Also add to regular queue as fallback
      const pendingRequest: PendingRequest<T> = {
        id: requestId,
        request,
        resolve,
        reject,
        timestamp: Date.now(),
        retryCount: 0,
        priority: options.priority as any,
        timeout: options.timeout
      };
      
      this.pendingRequests.set(requestId, pendingRequest);
    });
  }

  /**
   * Process a batch of similar requests
   */
  private async processBatch<T>(batchKey: string): Promise<T> {
    const batch = this.batchQueue.get(batchKey);
    if (!batch || batch.length === 0) {
      throw new Error('Empty batch');
    }

    this.batchQueue.delete(batchKey);
    this.metrics.batchedRequests += batch.length;

    try {
      // Create a single batched request
      const batchedRequest = this.createBatchedRequest(batch);
      const result = await batchedRequest();
      
      // Distribute results to individual requests
      return this.distributeBatchResults(batch, result);
    } catch (error) {
      // Handle batch failure
      throw error;
    }
  }

  /**
   * Create a batched request from multiple similar requests
   */
  private createBatchedRequest(batch: BatchableRequest[]) {
    const firstRequest = batch[0];
    
    switch (firstRequest.type) {
      case 'search':
        return () => this.batchSearchRequests(batch);
      case 'document':
        return () => this.batchDocumentRequests(batch);
      case 'suggestions':
        return () => this.batchSuggestionsRequests(batch);
      default:
        throw new Error(`Unsupported batch type: ${firstRequest.type}`);
    }
  }

  /**
   * Batch multiple search requests into a single API call
   */
  private async batchSearchRequests(batch: BatchableRequest[]) {
    // Combine CQL queries with OR operator
    const queries = batch.map(req => req.params.query).filter(Boolean);
    const combinedQuery = queries.length > 1 ? `(${queries.join(') OR (')})` : queries[0];
    
    const response = await fetch('/api/lexml/search', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: combinedQuery,
        maxRecords: batch.length * 20 // Adjust based on batch size
      })
    });
    
    return response.json();
  }

  /**
   * Batch multiple document content requests
   */
  private async batchDocumentRequests(batch: BatchableRequest[]) {
    const urns = batch.map(req => req.params.urn);
    
    const response = await fetch('/api/lexml/documents/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urns })
    });
    
    return response.json();
  }

  /**
   * Batch multiple suggestion requests
   */
  private async batchSuggestionsRequests(batch: BatchableRequest[]) {
    const terms = batch.map(req => req.params.term);
    
    const response = await fetch('/api/lexml/suggestions/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ terms })
    });
    
    return response.json();
  }

  /**
   * Distribute batch results to individual requests
   */
  private distributeBatchResults(batch: BatchableRequest[], batchResult: any): any {
    // For now, return the full batch result
    // In a real implementation, you'd parse the result and distribute
    // the relevant parts to each original request
    return batchResult;
  }

  /**
   * Generate a unique key for batching similar requests
   */
  private generateBatchKey(request: BatchableRequest): string {
    const keyParts = [request.type];
    
    // Add relevant parameters for batching
    if (request.type === 'search') {
      keyParts.push(request.params.filters || '');
    } else if (request.type === 'suggestions') {
      keyParts.push(request.params.field || '');
    }
    
    return keyParts.join(':');
  }

  /**
   * Start the request queue processor
   */
  private startQueueProcessor() {
    setInterval(() => {
      this.processRequestQueue();
    }, 50); // Process every 50ms
  }

  /**
   * Process pending requests from the queue
   */
  private async processRequestQueue() {
    if (this.activeRequests.size >= this.config.maxConcurrentRequests) {
      return;
    }

    const nextRequest = this.requestQueue.shift();
    if (!nextRequest) {
      return;
    }

    this.activeRequests.add(nextRequest.id);
    
    try {
      const startTime = Date.now();
      const result = await Promise.race([
        nextRequest.request(),
        this.createTimeoutPromise(nextRequest.timeout)
      ]);
      
      const responseTime = Date.now() - startTime;
      this.updateMetrics(responseTime, true);
      
      nextRequest.resolve(result);
      this.metrics.successfulRequests++;
      
    } catch (error) {
      this.metrics.failedRequests++;
      
      // Retry logic
      if (nextRequest.retryCount < this.config.retryAttempts) {
        nextRequest.retryCount++;
        setTimeout(() => {
          this.requestQueue.unshift(nextRequest);
        }, this.config.retryDelay * Math.pow(2, nextRequest.retryCount)); // Exponential backoff
      } else {
        nextRequest.reject(error);
      }
    } finally {
      this.activeRequests.delete(nextRequest.id);
      this.pendingRequests.delete(nextRequest.id);
    }
  }

  /**
   * Start the batch processor
   */
  private startBatchProcessor() {
    setInterval(() => {
      this.processPendingBatches();
    }, this.config.batchDelay);
  }

  /**
   * Process any pending batches that have reached their delay
   */
  private processPendingBatches() {
    for (const [batchKey, batch] of this.batchQueue.entries()) {
      if (batch.length > 0) {
        this.processBatch(batchKey).catch(console.error);
      }
    }
  }

  /**
   * Sort request queue by priority and age
   */
  private sortRequestQueue() {
    this.requestQueue.sort((a, b) => {
      // Priority order: high > medium > low
      const priorityOrder = { high: 3, medium: 2, low: 1 };
      const priorityDiff = priorityOrder[b.priority] - priorityOrder[a.priority];
      
      if (priorityDiff !== 0) {
        return priorityDiff;
      }
      
      // If same priority, older requests first
      return a.timestamp - b.timestamp;
    });
  }

  /**
   * Check if request is within rate limit
   */
  private isWithinRateLimit(): boolean {
    const now = Date.now();
    const windowStart = now - this.config.rateLimit.windowSize;
    
    // Clean old entries
    this.requestLog = this.requestLog.filter(timestamp => timestamp > windowStart);
    
    return this.requestLog.length < this.config.rateLimit.maxRequestsPerMinute;
  }

  /**
   * Log a request for rate limiting
   */
  private logRequest() {
    this.requestLog.push(Date.now());
    
    // Also log to localStorage for persistence
    const stored = localStorage.getItem('lexml_request_log');
    const log = stored ? JSON.parse(stored) : [];
    log.push(Date.now());
    
    // Keep only last 1000 entries
    if (log.length > 1000) {
      log.splice(0, log.length - 1000);
    }
    
    localStorage.setItem('lexml_request_log', JSON.stringify(log));
  }

  /**
   * Create a timeout promise
   */
  private createTimeoutPromise(timeout: number): Promise<never> {
    return new Promise((_, reject) => {
      setTimeout(() => {
        reject(new Error(`Request timeout after ${timeout}ms`));
      }, timeout);
    });
  }

  /**
   * Update performance metrics
   */
  private updateMetrics(responseTime: number, success: boolean) {
    const oldAvg = this.metrics.averageResponseTime;
    const oldCount = this.metrics.successfulRequests + this.metrics.failedRequests;
    
    this.metrics.averageResponseTime = (oldAvg * oldCount + responseTime) / (oldCount + 1);
  }

  /**
   * Start metrics collection
   */
  private startMetricsCollector() {
    setInterval(() => {
      this.updateRequestsPerMinute();
    }, 10000); // Update every 10 seconds
  }

  /**
   * Update requests per minute metric
   */
  private updateRequestsPerMinute() {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    const recentRequests = this.requestLog.filter(timestamp => timestamp > oneMinuteAgo);
    this.metrics.requestsPerMinute = recentRequests.length;
  }

  /**
   * Process rate limit queue
   */
  private processRateLimitQueue() {
    while (this.rateLimitQueue.length > 0 && this.isWithinRateLimit()) {
      const nextCallback = this.rateLimitQueue.shift();
      if (nextCallback) {
        nextCallback();
      }
    }
  }

  /**
   * Get current metrics
   */
  getMetrics(): RequestMetrics {
    return { ...this.metrics };
  }

  /**
   * Get queue status
   */
  getQueueStatus() {
    return {
      pending: this.requestQueue.length,
      active: this.activeRequests.size,
      rateLimited: this.rateLimitQueue.length,
      batches: Array.from(this.batchQueue.entries()).map(([key, batch]) => ({
        key,
        size: batch.length
      }))
    };
  }

  /**
   * Clear all pending requests
   */
  clearQueue() {
    this.requestQueue.forEach(req => {
      req.reject(new Error('Queue cleared'));
    });
    
    this.requestQueue.length = 0;
    this.pendingRequests.clear();
    this.batchQueue.clear();
    this.rateLimitQueue.length = 0;
  }
}

// Global instance
export const requestOptimizer = new RequestOptimizer();

// Export utility functions
export const optimizeSearchRequest = (query: string, filters: any) => {
  const requestId = `search:${query}:${JSON.stringify(filters)}`;
  return requestOptimizer.optimizeRequest(
    requestId,
    () => fetch(`/api/lexml/search?q=${encodeURIComponent(query)}`).then(r => r.json()),
    {
      priority: 'high',
      batchable: {
        type: 'search',
        params: { query, filters }
      }
    }
  );
};

export const optimizeDocumentRequest = (urn: string) => {
  const requestId = `document:${urn}`;
  return requestOptimizer.optimizeRequest(
    requestId,
    () => fetch(`/api/lexml/document/${encodeURIComponent(urn)}`).then(r => r.json()),
    {
      priority: 'medium',
      timeout: 15000,
      batchable: {
        type: 'document',
        params: { urn }
      }
    }
  );
};

export const optimizeSuggestionsRequest = (term: string, field?: string) => {
  const requestId = `suggestions:${term}:${field || ''}`;
  return requestOptimizer.optimizeRequest(
    requestId,
    () => fetch(`/api/lexml/suggest?term=${encodeURIComponent(term)}`).then(r => r.json()),
    {
      priority: 'low',
      timeout: 5000,
      batchable: {
        type: 'suggestions',
        params: { term, field }
      }
    }
  );
};