import { useCallback, useEffect, useState } from 'react';
import { rShinyDataSync } from '../services/rShinyDataSync';
import { LegislativeDocument, SearchFilters } from '../types';

interface RShinyConnectionStatus {
  isConnected: boolean;
  isLoading: boolean;
  error: string | null;
  queueSize: number;
  lastSyncTime: number | null;
}

interface UseRShinySyncOptions {
  autoSync?: boolean;
  syncFiltersDelay?: number;
  syncDocumentsDelay?: number;
}

export const useRShinySync = (options: UseRShinySyncOptions = {}) => {
  const {
    autoSync = true,
    syncFiltersDelay = 1000, // 1 second delay
    syncDocumentsDelay = 2000 // 2 seconds delay
  } = options;

  const [connectionStatus, setConnectionStatus] = useState<RShinyConnectionStatus>({
    isConnected: rShinyDataSync.isConnected(),
    isLoading: false,
    error: null,
    queueSize: rShinyDataSync.getQueueSize(),
    lastSyncTime: null
  });

  const [syncTimeouts, setSyncTimeouts] = useState<{
    filters: NodeJS.Timeout | null;
    documents: NodeJS.Timeout | null;
  }>({
    filters: null,
    documents: null
  });

  // Monitor connection status
  useEffect(() => {
    const unsubscribe = rShinyDataSync.onConnectionChange((isConnected, error) => {
      setConnectionStatus(prev => ({
        ...prev,
        isConnected,
        error: error ? error.message : null,
        queueSize: rShinyDataSync.getQueueSize()
      }));
    });

    return unsubscribe;
  }, []);

  // Cleanup timeouts on unmount
  useEffect(() => {
    return () => {
      if (syncTimeouts.filters) clearTimeout(syncTimeouts.filters);
      if (syncTimeouts.documents) clearTimeout(syncTimeouts.documents);
    };
  }, [syncTimeouts]);

  const updateConnectionStatus = useCallback(() => {
    setConnectionStatus(prev => ({
      ...prev,
      queueSize: rShinyDataSync.getQueueSize()
    }));
  }, []);

  const syncFilters = useCallback(async (filters: SearchFilters, immediate = false) => {
    if (!autoSync && !immediate) return;

    // Clear existing timeout
    if (syncTimeouts.filters) {
      clearTimeout(syncTimeouts.filters);
    }

    const executeSync = async () => {
      setConnectionStatus(prev => ({ ...prev, isLoading: true, error: null }));
      
      try {
        const success = await rShinyDataSync.syncFilters(filters);
        setConnectionStatus(prev => ({
          ...prev,
          isLoading: false,
          lastSyncTime: Date.now(),
          queueSize: rShinyDataSync.getQueueSize()
        }));
        updateConnectionStatus();
        return success;
      } catch (error) {
        setConnectionStatus(prev => ({
          ...prev,
          isLoading: false,
          error: error instanceof Error ? error.message : 'Sync failed',
          queueSize: rShinyDataSync.getQueueSize()
        }));
        return false;
      }
    };

    if (immediate) {
      return await executeSync();
    } else {
      const timeout = setTimeout(executeSync, syncFiltersDelay);
      setSyncTimeouts(prev => ({ ...prev, filters: timeout }));
    }
  }, [autoSync, syncFiltersDelay, syncTimeouts.filters, updateConnectionStatus]);

  const syncDocuments = useCallback(async (documents: LegislativeDocument[], immediate = false) => {
    if (!autoSync && !immediate) return;

    // Clear existing timeout
    if (syncTimeouts.documents) {
      clearTimeout(syncTimeouts.documents);
    }

    const executeSync = async () => {
      setConnectionStatus(prev => ({ ...prev, isLoading: true, error: null }));
      
      try {
        const success = await rShinyDataSync.syncDocuments(documents);
        setConnectionStatus(prev => ({
          ...prev,
          isLoading: false,
          lastSyncTime: Date.now(),
          queueSize: rShinyDataSync.getQueueSize()
        }));
        updateConnectionStatus();
        return success;
      } catch (error) {
        setConnectionStatus(prev => ({
          ...prev,
          isLoading: false,
          error: error instanceof Error ? error.message : 'Sync failed',
          queueSize: rShinyDataSync.getQueueSize()
        }));
        return false;
      }
    };

    if (immediate) {
      return await executeSync();
    } else {
      const timeout = setTimeout(executeSync, syncDocumentsDelay);
      setSyncTimeouts(prev => ({ ...prev, documents: timeout }));
    }
  }, [autoSync, syncDocumentsDelay, syncTimeouts.documents, updateConnectionStatus]);

  const syncSelection = useCallback(async (selectedState?: string, selectedMunicipality?: string) => {
    setConnectionStatus(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      const success = await rShinyDataSync.syncSelection(selectedState, selectedMunicipality);
      setConnectionStatus(prev => ({
        ...prev,
        isLoading: false,
        lastSyncTime: Date.now(),
        queueSize: rShinyDataSync.getQueueSize()
      }));
      updateConnectionStatus();
      return success;
    } catch (error) {
      setConnectionStatus(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Selection sync failed',
        queueSize: rShinyDataSync.getQueueSize()
      }));
      return false;
    }
  }, [updateConnectionStatus]);

  const sendCommand = useCallback(async (command: string, parameters: any = {}) => {
    setConnectionStatus(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      const response = await rShinyDataSync.sendCommand(command, parameters);
      setConnectionStatus(prev => ({
        ...prev,
        isLoading: false,
        lastSyncTime: Date.now()
      }));
      return response;
    } catch (error) {
      setConnectionStatus(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Command failed'
      }));
      throw error;
    }
  }, []);

  const getSessionData = useCallback(async () => {
    setConnectionStatus(prev => ({ ...prev, isLoading: true, error: null }));
    
    try {
      const sessionData = await rShinyDataSync.getSessionData();
      setConnectionStatus(prev => ({
        ...prev,
        isLoading: false
      }));
      return sessionData;
    } catch (error) {
      setConnectionStatus(prev => ({
        ...prev,
        isLoading: false,
        error: error instanceof Error ? error.message : 'Failed to get session data'
      }));
      throw error;
    }
  }, []);

  const clearQueue = useCallback(() => {
    rShinyDataSync.clearQueue();
    updateConnectionStatus();
  }, [updateConnectionStatus]);

  const getRShinyUrl = useCallback(() => {
    return rShinyDataSync.getRShinyUrl();
  }, []);

  const getSessionId = useCallback(() => {
    return rShinyDataSync.getSessionId();
  }, []);

  const forceSync = useCallback(async (
    filters?: SearchFilters, 
    documents?: LegislativeDocument[],
    selectedState?: string,
    selectedMunicipality?: string
  ) => {
    const results = await Promise.allSettled([
      filters ? syncFilters(filters, true) : Promise.resolve(true),
      documents ? syncDocuments(documents, true) : Promise.resolve(true),
      (selectedState !== undefined || selectedMunicipality !== undefined) 
        ? syncSelection(selectedState, selectedMunicipality) 
        : Promise.resolve(true)
    ]);

    const hasFailures = results.some(result => result.status === 'rejected');
    return !hasFailures;
  }, [syncFilters, syncDocuments, syncSelection]);

  return {
    // Connection status
    connectionStatus,
    
    // Sync methods
    syncFilters,
    syncDocuments,
    syncSelection,
    sendCommand,
    getSessionData,
    forceSync,
    
    // Utility methods
    clearQueue,
    getRShinyUrl,
    getSessionId,
    
    // Helper computed values
    isConnected: connectionStatus.isConnected,
    isLoading: connectionStatus.isLoading,
    hasError: !!connectionStatus.error,
    hasPendingSync: connectionStatus.queueSize > 0,
    lastSyncTime: connectionStatus.lastSyncTime
  };
};

export default useRShinySync;