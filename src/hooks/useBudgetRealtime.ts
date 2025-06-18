import { useEffect, useState, useCallback } from 'react';
import budgetRealtimeService from '../services/budgetRealtimeService';
import { LegislativeDocument } from '../types/types';

interface UseBudgetRealtimeOptions {
  autoStart?: boolean;
  onNewDocument?: (document: LegislativeDocument) => void;
  onCrossTabUpdate?: (update: any) => void;
}

interface UseBudgetRealtimeReturn {
  isPolling: boolean;
  lastCheck: Date;
  nextCheck: Date;
  seenDocuments: number;
  start: () => void;
  stop: () => void;
  requestNotifications: () => Promise<boolean>;
  clearHistory: () => void;
}

export function useBudgetRealtime(options: UseBudgetRealtimeOptions = {}): UseBudgetRealtimeReturn {
  const { 
    autoStart = true,
    onNewDocument,
    onCrossTabUpdate
  } = options;

  const [status, setStatus] = useState(budgetRealtimeService.getStatus());

  // Update status periodically
  useEffect(() => {
    const updateStatus = () => {
      setStatus(budgetRealtimeService.getStatus());
    };

    // Update every 5 seconds when polling
    const interval = setInterval(updateStatus, 5000);
    
    return () => clearInterval(interval);
  }, []);

  // Handle new documents
  const handleNewDocument = useCallback((document: LegislativeDocument) => {
    onNewDocument?.(document);
    // Update status immediately
    setStatus(budgetRealtimeService.getStatus());
  }, [onNewDocument]);

  // Handle cross-tab updates
  const handleCrossTabUpdate = useCallback((update: any) => {
    onCrossTabUpdate?.(update);
  }, [onCrossTabUpdate]);

  // Handle status updates
  const handleStatusUpdate = useCallback(() => {
    setStatus(budgetRealtimeService.getStatus());
  }, []);

  // Control functions
  const start = useCallback(() => {
    budgetRealtimeService.start();
    setStatus(budgetRealtimeService.getStatus());
  }, []);

  const stop = useCallback(() => {
    budgetRealtimeService.stop();
    setStatus(budgetRealtimeService.getStatus());
  }, []);

  const requestNotifications = useCallback(async (): Promise<boolean> => {
    return await budgetRealtimeService.constructor.requestNotificationPermission();
  }, []);

  const clearHistory = useCallback(() => {
    budgetRealtimeService.clearStoredData();
    setStatus(budgetRealtimeService.getStatus());
  }, []);

  // Set up event listeners
  useEffect(() => {
    budgetRealtimeService.on('new_document', handleNewDocument);
    budgetRealtimeService.on('cross_tab_update', handleCrossTabUpdate);
    budgetRealtimeService.on('status', handleStatusUpdate);
    budgetRealtimeService.on('connected', handleStatusUpdate);
    budgetRealtimeService.on('disconnected', handleStatusUpdate);

    // Start cross-tab synchronization
    budgetRealtimeService.startCrossTabSync();

    // Auto-start if enabled
    if (autoStart && !status.isPolling) {
      start();
    }

    // Cleanup
    return () => {
      budgetRealtimeService.off('new_document', handleNewDocument);
      budgetRealtimeService.off('cross_tab_update', handleCrossTabUpdate);
      budgetRealtimeService.off('status', handleStatusUpdate);
      budgetRealtimeService.off('connected', handleStatusUpdate);
      budgetRealtimeService.off('disconnected', handleStatusUpdate);
      
      if (autoStart) {
        stop();
      }
    };
  }, [autoStart, handleNewDocument, handleCrossTabUpdate, handleStatusUpdate, start, stop, status.isPolling]);

  return {
    isPolling: status.isPolling,
    lastCheck: status.lastCheck,
    nextCheck: status.nextCheck,
    seenDocuments: status.seenDocuments,
    start,
    stop,
    requestNotifications,
    clearHistory
  };
}