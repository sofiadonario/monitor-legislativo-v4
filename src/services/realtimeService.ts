// Real-time updates service for new legislation notifications
import { LegislativeDocument } from '../types/types';
import { EventEmitter } from 'events';

export interface RealtimeUpdate {
  type: 'new_document' | 'document_updated' | 'document_deleted' | 'system_message';
  data: any;
  timestamp: Date;
  id: string;
}

export interface RealtimeConfig {
  url?: string;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  enableSSE?: boolean;
  enableWebSocket?: boolean;
}

class RealtimeService extends EventEmitter {
  private config: Required<RealtimeConfig>;
  private eventSource?: EventSource;
  private websocket?: WebSocket;
  private reconnectAttempts: number = 0;
  private reconnectTimer?: NodeJS.Timeout;
  private isConnected: boolean = false;
  private lastEventId?: string;
  private updateQueue: RealtimeUpdate[] = [];

  constructor(config: RealtimeConfig = {}) {
    super();
    this.config = {
      url: config.url || import.meta.env.VITE_REALTIME_URL || 'https://monitor-legislativo-v4-production.up.railway.app',
      reconnectInterval: config.reconnectInterval || 5000,
      maxReconnectAttempts: config.maxReconnectAttempts || 10,
      enableSSE: config.enableSSE !== false,
      enableWebSocket: config.enableWebSocket || false
    };
  }

  // Connect to real-time service
  connect(): void {
    if (this.config.enableWebSocket && 'WebSocket' in window) {
      this.connectWebSocket();
    } else if (this.config.enableSSE && 'EventSource' in window) {
      this.connectSSE();
    } else {
      // Fallback to polling
      this.startPolling();
    }
  }

  // Disconnect from real-time service
  disconnect(): void {
    this.isConnected = false;
    
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = undefined;
    }
    
    if (this.websocket) {
      this.websocket.close();
      this.websocket = undefined;
    }
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = undefined;
    }
    
    this.emit('disconnected');
  }

  // Server-Sent Events connection
  private connectSSE(): void {
    const url = `${this.config.url}/api/v1/realtime/sse`;
    const urlWithLastId = this.lastEventId ? `${url}?lastEventId=${this.lastEventId}` : url;
    
    try {
      this.eventSource = new EventSource(urlWithLastId);
      
      this.eventSource.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.emit('connected', { type: 'sse' });
        console.log('SSE connection established');
      };
      
      this.eventSource.onmessage = (event) => {
        try {
          const update: RealtimeUpdate = JSON.parse(event.data);
          this.handleUpdate(update);
          this.lastEventId = event.lastEventId || update.id;
        } catch (error) {
          console.error('Error parsing SSE message:', error);
        }
      };
      
      // Handle specific event types
      this.eventSource.addEventListener('new_document', (event: any) => {
        try {
          const document: LegislativeDocument = JSON.parse(event.data);
          this.handleNewDocument(document);
        } catch (error) {
          console.error('Error handling new document:', error);
        }
      });
      
      this.eventSource.addEventListener('document_updated', (event: any) => {
        try {
          const document: LegislativeDocument = JSON.parse(event.data);
          this.handleDocumentUpdate(document);
        } catch (error) {
          console.error('Error handling document update:', error);
        }
      });
      
      this.eventSource.onerror = (error) => {
        console.error('SSE error:', error);
        this.handleConnectionError();
      };
    } catch (error) {
      console.error('Failed to create SSE connection:', error);
      this.handleConnectionError();
    }
  }

  // WebSocket connection
  private connectWebSocket(): void {
    const wsUrl = this.config.url.replace(/^https?/, 'ws');
    const url = `${wsUrl}/api/v1/realtime/ws`;
    
    try {
      this.websocket = new WebSocket(url);
      
      this.websocket.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.emit('connected', { type: 'websocket' });
        console.log('WebSocket connection established');
        
        // Send any queued updates
        this.flushUpdateQueue();
        
        // Subscribe to updates
        this.websocket?.send(JSON.stringify({
          type: 'subscribe',
          channels: ['legislation_updates']
        }));
      };
      
      this.websocket.onmessage = (event) => {
        try {
          const update: RealtimeUpdate = JSON.parse(event.data);
          this.handleUpdate(update);
        } catch (error) {
          console.error('Error parsing WebSocket message:', error);
        }
      };
      
      this.websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.handleConnectionError();
      };
      
      this.websocket.onclose = () => {
        this.isConnected = false;
        this.emit('disconnected');
        this.handleConnectionError();
      };
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      this.handleConnectionError();
    }
  }

  // Polling fallback
  private startPolling(): void {
    console.log('Using polling fallback for real-time updates');
    
    const poll = async () => {
      if (!this.isConnected) return;
      
      try {
        const response = await fetch(`${this.config.url}/api/v1/realtime/poll`, {
          headers: {
            'Last-Event-ID': this.lastEventId || ''
          }
        });
        
        if (response.ok) {
          const updates: RealtimeUpdate[] = await response.json();
          updates.forEach(update => this.handleUpdate(update));
          
          if (updates.length > 0) {
            this.lastEventId = updates[updates.length - 1].id;
          }
        }
      } catch (error) {
        console.error('Polling error:', error);
      }
      
      // Schedule next poll
      if (this.isConnected) {
        setTimeout(poll, 30000); // Poll every 30 seconds
      }
    };
    
    this.isConnected = true;
    this.emit('connected', { type: 'polling' });
    poll();
  }

  // Handle connection errors and reconnection
  private handleConnectionError(): void {
    this.isConnected = false;
    
    if (this.reconnectAttempts >= this.config.maxReconnectAttempts) {
      this.emit('error', new Error('Max reconnection attempts reached'));
      return;
    }
    
    this.reconnectAttempts++;
    const delay = Math.min(this.config.reconnectInterval * this.reconnectAttempts, 30000);
    
    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
    
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  // Handle incoming updates
  private handleUpdate(update: RealtimeUpdate): void {
    switch (update.type) {
      case 'new_document':
        this.handleNewDocument(update.data);
        break;
      case 'document_updated':
        this.handleDocumentUpdate(update.data);
        break;
      case 'document_deleted':
        this.handleDocumentDelete(update.data);
        break;
      case 'system_message':
        this.emit('system_message', update.data);
        break;
      default:
        this.emit('update', update);
    }
  }

  // Handle new document
  private handleNewDocument(document: LegislativeDocument): void {
    this.emit('new_document', document);
    
    // Show notification if permitted
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification('New Legislation', {
        body: `${document.type}: ${document.title}`,
        icon: '/favicon.ico',
        tag: `doc-${document.id}`,
        data: { documentId: document.id }
      });
    }
  }

  // Handle document update
  private handleDocumentUpdate(document: LegislativeDocument): void {
    this.emit('document_updated', document);
  }

  // Handle document deletion
  private handleDocumentDelete(documentId: string): void {
    this.emit('document_deleted', documentId);
  }

  // Queue updates when disconnected
  queueUpdate(update: RealtimeUpdate): void {
    if (this.isConnected && this.websocket?.readyState === WebSocket.OPEN) {
      this.websocket.send(JSON.stringify(update));
    } else {
      this.updateQueue.push(update);
    }
  }

  // Flush queued updates
  private flushUpdateQueue(): void {
    if (this.websocket?.readyState === WebSocket.OPEN) {
      this.updateQueue.forEach(update => {
        this.websocket?.send(JSON.stringify(update));
      });
      this.updateQueue = [];
    }
  }

  // Get connection status
  getStatus(): {
    connected: boolean;
    type: 'sse' | 'websocket' | 'polling' | 'disconnected';
    reconnectAttempts: number;
  } {
    let type: 'sse' | 'websocket' | 'polling' | 'disconnected' = 'disconnected';
    
    if (this.isConnected) {
      if (this.websocket) type = 'websocket';
      else if (this.eventSource) type = 'sse';
      else type = 'polling';
    }
    
    return {
      connected: this.isConnected,
      type,
      reconnectAttempts: this.reconnectAttempts
    };
  }

  // Request notification permissions
  static async requestNotificationPermission(): Promise<NotificationPermission> {
    if (!('Notification' in window)) {
      return 'denied';
    }
    
    if (Notification.permission === 'granted') {
      return 'granted';
    }
    
    if (Notification.permission !== 'denied') {
      return await Notification.requestPermission();
    }
    
    return Notification.permission;
  }
}

// Export singleton instance
export const realtimeService = new RealtimeService();
export default realtimeService;