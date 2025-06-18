// Budget-friendly real-time updates using polling and localStorage
// No additional server costs - uses existing API endpoints
import { LegislativeDocument } from '../types/types';
import { legislativeDataService } from './legislativeDataService';
import { EventEmitter } from 'events';

interface StoredUpdate {
  documentId: string;
  timestamp: number;
  type: 'new' | 'updated';
}

class BudgetRealtimeService extends EventEmitter {
  private pollingInterval: number = 60000; // 1 minute - to stay within free tier limits
  private pollingTimer?: NodeJS.Timeout;
  private isPolling: boolean = false;
  private lastCheckTimestamp: number;
  private seenDocumentIds: Set<string>;
  private storageKey = 'monitor_legislativo_seen_docs';
  private updateStorageKey = 'monitor_legislativo_updates';

  constructor() {
    super();
    this.lastCheckTimestamp = this.getLastCheckTimestamp();
    this.seenDocumentIds = this.loadSeenDocuments();
  }

  // Start polling for updates
  start(): void {
    if (this.isPolling) return;
    
    this.isPolling = true;
    this.emit('connected');
    
    // Initial check
    this.checkForUpdates();
    
    // Set up polling interval
    this.pollingTimer = setInterval(() => {
      this.checkForUpdates();
    }, this.pollingInterval);
  }

  // Stop polling
  stop(): void {
    if (!this.isPolling) return;
    
    this.isPolling = false;
    
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = undefined;
    }
    
    this.emit('disconnected');
  }

  // Check for new documents
  private async checkForUpdates(): Promise<void> {
    try {
      // Fetch recent documents (limited to reduce API calls)
      const documents = await legislativeDataService.fetchDocuments({
        searchTerm: '',
        documentTypes: [],
        states: [],
        municipalities: [],
        keywords: [],
        dateFrom: new Date(this.lastCheckTimestamp),
        dateTo: new Date()
      });

      const updates: StoredUpdate[] = [];
      const now = Date.now();

      // Process documents
      documents.forEach(doc => {
        if (!this.seenDocumentIds.has(doc.id)) {
          // New document
          this.seenDocumentIds.add(doc.id);
          this.emit('new_document', doc);
          
          updates.push({
            documentId: doc.id,
            timestamp: now,
            type: 'new'
          });
          
          // Show notification if it's very recent (last 5 minutes)
          const docDate = typeof doc.date === 'string' ? new Date(doc.date) : doc.date;
          if (now - docDate.getTime() < 5 * 60 * 1000) {
            this.showNotification('New Legislation', `${doc.type}: ${doc.title}`);
          }
        }
      });

      // Save updates to localStorage for cross-tab communication
      if (updates.length > 0) {
        this.saveUpdates(updates);
        this.saveSeenDocuments();
      }

      // Update last check timestamp
      this.lastCheckTimestamp = now;
      this.saveLastCheckTimestamp();
      
      // Emit status update
      this.emit('status', {
        lastCheck: new Date(this.lastCheckTimestamp),
        documentsChecked: documents.length,
        newDocuments: updates.length
      });

    } catch (error) {
      console.error('Error checking for updates:', error);
      this.emit('error', error);
    }
  }

  // Show browser notification
  private showNotification(title: string, body: string): void {
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(title, {
        body,
        icon: '/favicon.ico',
        tag: 'legislation-update',
        requireInteraction: false
      });
    }
  }

  // Load seen documents from localStorage
  private loadSeenDocuments(): Set<string> {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const data = JSON.parse(stored);
        // Keep only recent document IDs (last 30 days) to prevent storage bloat
        const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
        const recentIds = Object.entries(data)
          .filter(([_, timestamp]) => (timestamp as number) > thirtyDaysAgo)
          .map(([id]) => id);
        return new Set(recentIds);
      }
    } catch (error) {
      console.error('Error loading seen documents:', error);
    }
    return new Set();
  }

  // Save seen documents to localStorage
  private saveSeenDocuments(): void {
    try {
      const data: Record<string, number> = {};
      const now = Date.now();
      this.seenDocumentIds.forEach(id => {
        data[id] = now;
      });
      localStorage.setItem(this.storageKey, JSON.stringify(data));
    } catch (error) {
      console.error('Error saving seen documents:', error);
    }
  }

  // Get last check timestamp
  private getLastCheckTimestamp(): number {
    try {
      const stored = localStorage.getItem('monitor_legislativo_last_check');
      if (stored) {
        return parseInt(stored, 10);
      }
    } catch (error) {
      console.error('Error loading last check timestamp:', error);
    }
    // Default to 24 hours ago
    return Date.now() - 24 * 60 * 60 * 1000;
  }

  // Save last check timestamp
  private saveLastCheckTimestamp(): void {
    try {
      localStorage.setItem('monitor_legislativo_last_check', this.lastCheckTimestamp.toString());
    } catch (error) {
      console.error('Error saving last check timestamp:', error);
    }
  }

  // Save updates for cross-tab communication
  private saveUpdates(updates: StoredUpdate[]): void {
    try {
      // Get existing updates
      const stored = localStorage.getItem(this.updateStorageKey);
      const existingUpdates = stored ? JSON.parse(stored) : [];
      
      // Add new updates and keep only last 100
      const allUpdates = [...updates, ...existingUpdates].slice(0, 100);
      
      localStorage.setItem(this.updateStorageKey, JSON.stringify(allUpdates));
      
      // Trigger storage event for other tabs
      window.dispatchEvent(new StorageEvent('storage', {
        key: this.updateStorageKey,
        newValue: JSON.stringify(allUpdates),
        url: window.location.href
      }));
    } catch (error) {
      console.error('Error saving updates:', error);
    }
  }

  // Listen for updates from other tabs
  startCrossTabSync(): void {
    window.addEventListener('storage', (e) => {
      if (e.key === this.updateStorageKey && e.newValue) {
        try {
          const updates: StoredUpdate[] = JSON.parse(e.newValue);
          // Emit events for updates from other tabs
          updates.forEach(update => {
            if (!this.seenDocumentIds.has(update.documentId)) {
              this.seenDocumentIds.add(update.documentId);
              // We don't have the full document data, so just emit the ID
              this.emit('cross_tab_update', update);
            }
          });
        } catch (error) {
          console.error('Error processing cross-tab update:', error);
        }
      }
    });
  }

  // Get recent updates
  getRecentUpdates(): StoredUpdate[] {
    try {
      const stored = localStorage.getItem(this.updateStorageKey);
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (error) {
      console.error('Error loading recent updates:', error);
    }
    return [];
  }

  // Clear all stored data
  clearStoredData(): void {
    localStorage.removeItem(this.storageKey);
    localStorage.removeItem(this.updateStorageKey);
    localStorage.removeItem('monitor_legislativo_last_check');
    this.seenDocumentIds.clear();
    this.lastCheckTimestamp = Date.now() - 24 * 60 * 60 * 1000;
  }

  // Get polling status
  getStatus(): {
    isPolling: boolean;
    lastCheck: Date;
    nextCheck: Date;
    seenDocuments: number;
  } {
    const nextCheck = new Date(this.lastCheckTimestamp + this.pollingInterval);
    
    return {
      isPolling: this.isPolling,
      lastCheck: new Date(this.lastCheckTimestamp),
      nextCheck: this.isPolling ? nextCheck : new Date(),
      seenDocuments: this.seenDocumentIds.size
    };
  }

  // Request notification permission
  static async requestNotificationPermission(): Promise<boolean> {
    if (!('Notification' in window)) {
      return false;
    }
    
    if (Notification.permission === 'granted') {
      return true;
    }
    
    if (Notification.permission !== 'denied') {
      const permission = await Notification.requestPermission();
      return permission === 'granted';
    }
    
    return false;
  }
}

// Export singleton instance
export const budgetRealtimeService = new BudgetRealtimeService();
export default budgetRealtimeService;