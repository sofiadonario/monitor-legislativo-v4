/**
 * Real-time Service for Monitor Legislativo
 * Handles real-time updates and notifications
 */

import { apiClient } from './apiClient';

export interface RealtimeEvent {
  type: string;
  data: any;
  timestamp: string;
}

export class RealtimeService {
  private eventListeners: Map<string, Set<(event: RealtimeEvent) => void>> = new Map();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;

  constructor() {
    this.setupHealthCheck();
  }

  private setupHealthCheck() {
    // Periodic health check to ensure service is responsive
    setInterval(async () => {
      try {
        await apiClient.healthCheck();
      } catch (error) {
        console.warn('Health check failed:', error);
      }
    }, 30000); // Every 30 seconds
  }

  addEventListener(eventType: string, callback: (event: RealtimeEvent) => void) {
    if (!this.eventListeners.has(eventType)) {
      this.eventListeners.set(eventType, new Set());
    }
    this.eventListeners.get(eventType)!.add(callback);
  }

  removeEventListener(eventType: string, callback: (event: RealtimeEvent) => void) {
    const listeners = this.eventListeners.get(eventType);
    if (listeners) {
      listeners.delete(callback);
      if (listeners.size === 0) {
        this.eventListeners.delete(eventType);
      }
    }
  }

  private emit(eventType: string, data: any) {
    const event: RealtimeEvent = {
      type: eventType,
      data,
      timestamp: new Date().toISOString()
    };

    const listeners = this.eventListeners.get(eventType);
    if (listeners) {
      listeners.forEach(callback => {
        try {
          callback(event);
        } catch (error) {
          console.error('Event listener error:', error);
        }
      });
    }
  }

  // Simulate real-time events for demo purposes
  simulateSearchUpdate(query: string, results: any[]) {
    this.emit('search_update', { query, results });
  }

  simulateDataUpdate(type: string, data: any) {
    this.emit('data_update', { type, data });
  }

  simulateStatusUpdate(status: string, message: string) {
    this.emit('status_update', { status, message });
  }

  // Polling-based updates for simple real-time functionality
  async startPolling(interval: number = 30000) {
    const poll = async () => {
      try {
        const response = await apiClient.healthCheck();
        if (response.success) {
          this.emit('health_update', response.data);
        }
      } catch (error) {
        console.error('Polling error:', error);
      }
    };

    // Initial poll
    await poll();

    // Set up interval polling
    setInterval(poll, interval);
  }

  destroy() {
    this.eventListeners.clear();
  }
}

// Export singleton instance
export const realtimeService = new RealtimeService();
export default realtimeService;