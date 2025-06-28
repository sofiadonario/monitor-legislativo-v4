import { LegislativeDocument, SearchFilters } from '../types';
import { rShinyConfig, sanitizeSyncData, isOriginAllowed } from '../config/rshiny';

interface RShinyDataPacket {
  timestamp: number;
  type: 'filters' | 'documents' | 'selection' | 'command';
  data: any;
  sessionId: string;
}

class RShinyDataSyncService {
  private sessionId: string;
  private eventTarget: EventTarget;
  private syncQueue: RShinyDataPacket[] = [];
  private isOnline: boolean = true;
  private retryTimeout: NodeJS.Timeout | null = null;

  constructor() {
    
    this.sessionId = this.generateSessionId();
    this.eventTarget = new EventTarget();
    
    // Initialize connection monitoring
    this.initializeConnectionMonitoring();
  }

  private generateSessionId(): string {
    return `react_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private initializeConnectionMonitoring(): void {
    // Only check R Shiny availability every 2 minutes to reduce load
    setInterval(() => {
      this.checkRShinyHealth();
    }, 120000); // 2 minutes instead of 30 seconds

    // Initial health check with delay
    setTimeout(() => {
      this.checkRShinyHealth();
    }, 5000); // Wait 5 seconds before first check
  }

  private async checkRShinyHealth(): Promise<boolean> {
    try {
      const response = await fetch(`${rShinyConfig.baseUrl}${rShinyConfig.healthEndpoint}`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000)
      });
      
      const isHealthy = response.ok;
      
      if (this.isOnline !== isHealthy) {
        this.isOnline = isHealthy;
        this.eventTarget.dispatchEvent(new CustomEvent('connectionchange', {
          detail: { isOnline: this.isOnline }
        }));
      }
      
      return isHealthy;
    } catch (error) {
      console.warn('R Shiny health check failed:', error);
      
      if (this.isOnline) {
        this.isOnline = false;
        this.eventTarget.dispatchEvent(new CustomEvent('connectionchange', {
          detail: { isOnline: false, error }
        }));
      }
      
      return false;
    }
  }

  /**
   * Sync search filters to R Shiny application
   */
  async syncFilters(filters: SearchFilters): Promise<boolean> {
    const packet: RShinyDataPacket = {
      timestamp: Date.now(),
      type: 'filters',
      data: sanitizeSyncData({
        searchTerm: filters.searchTerm,
        documentTypes: filters.documentTypes,
        states: filters.states,
        municipalities: filters.municipalities,
        dateRange: {
          from: filters.dateFrom,
          to: filters.dateTo
        },
        keywords: filters.keywords
      }),
      sessionId: this.sessionId
    };

    return this.sendDataPacket(packet);
  }

  /**
   * Sync legislative documents to R Shiny application
   */
  async syncDocuments(documents: LegislativeDocument[]): Promise<boolean> {
    // Prepare documents for R Shiny (remove React-specific fields)
    const rShinyDocuments = documents.map(doc => ({
      id: doc.id,
      title: doc.title,
      type: doc.type,
      number: doc.number,
      date: doc.date,
      state: doc.state,
      municipality: doc.municipality,
      author: doc.author,
      summary: doc.summary,
      url: doc.url,
      source: doc.source,
      chamber: doc.chamber
    }));

    const packet: RShinyDataPacket = {
      timestamp: Date.now(),
      type: 'documents',
      data: sanitizeSyncData({
        documents: rShinyDocuments,
        count: rShinyDocuments.length,
        lastUpdated: new Date().toISOString()
      }),
      sessionId: this.sessionId
    };

    return this.sendDataPacket(packet);
  }

  /**
   * Sync selection state (selected state/municipality)
   */
  async syncSelection(selectedState?: string, selectedMunicipality?: string): Promise<boolean> {
    const packet: RShinyDataPacket = {
      timestamp: Date.now(),
      type: 'selection',
      data: sanitizeSyncData({
        selectedState,
        selectedMunicipality,
        selectionTimestamp: Date.now()
      }),
      sessionId: this.sessionId
    };

    return this.sendDataPacket(packet);
  }

  /**
   * Send command to R Shiny application
   */
  async sendCommand(command: string, parameters: any = {}): Promise<any> {
    const packet: RShinyDataPacket = {
      timestamp: Date.now(),
      type: 'command',
      data: sanitizeSyncData({
        command,
        parameters: sanitizeSyncData(parameters),
        responseRequired: true
      }),
      sessionId: this.sessionId
    };

    try {
      const response = await this.sendDataPacketWithResponse(packet);
      return response;
    } catch (error) {
      console.error('Error sending command to R Shiny:', error);
      throw error;
    }
  }

  /**
   * Get current session data from R Shiny
   */
  async getSessionData(): Promise<any> {
    try {
      const response = await fetch(`${rShinyConfig.baseUrl}${rShinyConfig.apiEndpoint}/session/${this.sessionId}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
        signal: AbortSignal.timeout(rShinyConfig.loadTimeout)
      });

      if (!response.ok) {
        throw new Error(`Failed to get session data: ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Error getting session data from R Shiny:', error);
      throw error;
    }
  }

  private async sendDataPacket(packet: RShinyDataPacket): Promise<boolean> {
    if (!this.isOnline) {
      console.warn('R Shiny is offline, queueing data packet');
      this.syncQueue.push(packet);
      return false;
    }

    try {
      // Validate origin if in browser
      if (typeof window !== 'undefined' && !isOriginAllowed(window.location.origin)) {
        throw new Error('Origin not allowed for R Shiny communication');
      }

      const response = await fetch(`${rShinyConfig.baseUrl}${rShinyConfig.apiEndpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(packet),
        signal: AbortSignal.timeout(rShinyConfig.loadTimeout)
      });

      if (!response.ok) {
        throw new Error(`Sync failed: ${response.status} ${response.statusText}`);
      }

      console.log(`Successfully synced ${packet.type} data to R Shiny`);
      return true;
    } catch (error) {
      console.error('Error syncing data to R Shiny:', error);
      this.syncQueue.push(packet);
      this.scheduleRetry();
      return false;
    }
  }

  private async sendDataPacketWithResponse(packet: RShinyDataPacket): Promise<any> {
    const response = await fetch(`${rShinyConfig.baseUrl}${rShinyConfig.apiEndpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(packet),
      signal: AbortSignal.timeout(rShinyConfig.loadTimeout)
    });

    if (!response.ok) {
      throw new Error(`Command failed: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  }

  private scheduleRetry(): void {
    if (this.retryTimeout) {
      clearTimeout(this.retryTimeout);
    }

    this.retryTimeout = setTimeout(() => {
      this.processSyncQueue();
    }, 5000); // Retry after 5 seconds
  }

  private async processSyncQueue(): Promise<void> {
    if (this.syncQueue.length === 0 || !this.isOnline) {
      return;
    }

    console.log(`Processing ${this.syncQueue.length} queued sync packets`);
    
    const queue = [...this.syncQueue];
    this.syncQueue = [];

    for (const packet of queue) {
      const success = await this.sendDataPacket(packet);
      if (!success) {
        // If it fails again, it will be re-queued
        break;
      }
    }
  }

  /**
   * Listen for connection status changes
   */
  onConnectionChange(callback: (isOnline: boolean, error?: any) => void): () => void {
    const handler = (event: Event) => {
      const customEvent = event as CustomEvent;
      callback(customEvent.detail.isOnline, customEvent.detail.error);
    };

    this.eventTarget.addEventListener('connectionchange', handler);
    
    return () => {
      this.eventTarget.removeEventListener('connectionchange', handler);
    };
  }

  /**
   * Get connection status
   */
  isConnected(): boolean {
    return this.isOnline;
  }

  /**
   * Get queue size
   */
  getQueueSize(): number {
    return this.syncQueue.length;
  }

  /**
   * Clear sync queue
   */
  clearQueue(): void {
    this.syncQueue = [];
  }

  /**
   * Get R Shiny application URL
   */
  getRShinyUrl(): string {
    return rShinyConfig.baseUrl;
  }

  /**
   * Get session ID
   */
  getSessionId(): string {
    return this.sessionId;
  }

  /**
   * Cleanup resources
   */
  dispose(): void {
    if (this.retryTimeout) {
      clearTimeout(this.retryTimeout);
    }
    this.clearQueue();
  }
}

// Create singleton instance
export const rShinyDataSync = new RShinyDataSyncService();

export default RShinyDataSyncService;