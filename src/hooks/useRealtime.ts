import { useEffect, useState, useCallback, useRef } from 'react';
import realtimeService, { RealtimeUpdate } from '../services/realtimeService';
import { LegislativeDocument } from '../types';

interface UseRealtimeOptions {
  autoConnect?: boolean;
  onNewDocument?: (document: LegislativeDocument) => void;
  onDocumentUpdated?: (document: LegislativeDocument) => void;
  onDocumentDeleted?: (documentId: string) => void;
  onSystemMessage?: (message: any) => void;
}

interface UseRealtimeReturn {
  isConnected: boolean;
  connectionType: 'sse' | 'websocket' | 'polling' | 'disconnected';
  recentUpdates: RealtimeUpdate[];
  connect: () => void;
  disconnect: () => void;
  clearUpdates: () => void;
  requestNotifications: () => Promise<boolean>;
}

export function useRealtime(options: UseRealtimeOptions = {}): UseRealtimeReturn {
  const { 
    autoConnect = true,
    onNewDocument,
    onDocumentUpdated,
    onDocumentDeleted,
    onSystemMessage
  } = options;

  const [isConnected, setIsConnected] = useState(false);
  const [connectionType, setConnectionType] = useState<'sse' | 'websocket' | 'polling' | 'disconnected'>('disconnected');
  const [recentUpdates, setRecentUpdates] = useState<RealtimeUpdate[]>([]);
  const maxUpdates = 50;
  
  // Use ref to store callbacks to avoid re-subscriptions
  const callbacksRef = useRef({
    onNewDocument,
    onDocumentUpdated,
    onDocumentDeleted,
    onSystemMessage
  });

  // Update callbacks ref when they change
  useEffect(() => {
    callbacksRef.current = {
      onNewDocument,
      onDocumentUpdated,
      onDocumentDeleted,
      onSystemMessage
    };
  }, [onNewDocument, onDocumentUpdated, onDocumentDeleted, onSystemMessage]);

  // Connection handlers
  const handleConnected = useCallback((data: { type: 'sse' | 'websocket' | 'polling' }) => {
    setIsConnected(true);
    setConnectionType(data.type);
    console.log(`Real-time connection established: ${data.type}`);
  }, []);

  const handleDisconnected = useCallback(() => {
    setIsConnected(false);
    setConnectionType('disconnected');
    console.log('Real-time connection lost');
  }, []);

  // Update handlers
  const handleNewDocument = useCallback((document: LegislativeDocument) => {
    const update: RealtimeUpdate = {
      type: 'new_document',
      data: document,
      timestamp: new Date(),
      id: `update-${Date.now()}-${document.id}`
    };
    
    setRecentUpdates(prev => [update, ...prev].slice(0, maxUpdates));
    callbacksRef.current.onNewDocument?.(document);
  }, []);

  const handleDocumentUpdated = useCallback((document: LegislativeDocument) => {
    const update: RealtimeUpdate = {
      type: 'document_updated',
      data: document,
      timestamp: new Date(),
      id: `update-${Date.now()}-${document.id}`
    };
    
    setRecentUpdates(prev => [update, ...prev].slice(0, maxUpdates));
    callbacksRef.current.onDocumentUpdated?.(document);
  }, []);

  const handleDocumentDeleted = useCallback((documentId: string) => {
    const update: RealtimeUpdate = {
      type: 'document_deleted',
      data: { id: documentId },
      timestamp: new Date(),
      id: `update-${Date.now()}-${documentId}`
    };
    
    setRecentUpdates(prev => [update, ...prev].slice(0, maxUpdates));
    callbacksRef.current.onDocumentDeleted?.(documentId);
  }, []);

  const handleSystemMessage = useCallback((message: any) => {
    const update: RealtimeUpdate = {
      type: 'system_message',
      data: message,
      timestamp: new Date(),
      id: `update-${Date.now()}-system`
    };
    
    setRecentUpdates(prev => [update, ...prev].slice(0, maxUpdates));
    callbacksRef.current.onSystemMessage?.(message);
  }, []);

  // Connect/disconnect functions
  const connect = useCallback(() => {
    realtimeService.connect();
  }, []);

  const disconnect = useCallback(() => {
    realtimeService.disconnect();
  }, []);

  const clearUpdates = useCallback(() => {
    setRecentUpdates([]);
  }, []);

  const requestNotifications = useCallback(async (): Promise<boolean> => {
    const permission = await realtimeService.constructor.requestNotificationPermission();
    return permission === 'granted';
  }, []);

  // Set up event listeners
  useEffect(() => {
    // Subscribe to events
    realtimeService.on('connected', handleConnected);
    realtimeService.on('disconnected', handleDisconnected);
    realtimeService.on('new_document', handleNewDocument);
    realtimeService.on('document_updated', handleDocumentUpdated);
    realtimeService.on('document_deleted', handleDocumentDeleted);
    realtimeService.on('system_message', handleSystemMessage);

    // Auto-connect if enabled
    if (autoConnect) {
      connect();
    }

    // Update initial status
    const status = realtimeService.getStatus();
    setIsConnected(status.connected);
    setConnectionType(status.type);

    // Cleanup
    return () => {
      realtimeService.off('connected', handleConnected);
      realtimeService.off('disconnected', handleDisconnected);
      realtimeService.off('new_document', handleNewDocument);
      realtimeService.off('document_updated', handleDocumentUpdated);
      realtimeService.off('document_deleted', handleDocumentDeleted);
      realtimeService.off('system_message', handleSystemMessage);
      
      if (autoConnect) {
        disconnect();
      }
    };
  }, [autoConnect, connect, disconnect, handleConnected, handleDisconnected, 
      handleNewDocument, handleDocumentUpdated, handleDocumentDeleted, handleSystemMessage]);

  return {
    isConnected,
    connectionType,
    recentUpdates,
    connect,
    disconnect,
    clearUpdates,
    requestNotifications
  };
}