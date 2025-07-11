/**
 * Alerts Panel Component
 * Displays active performance alerts and allows users to manage them
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  performanceAlertingService, 
  startPerformanceMonitoring, 
  stopPerformanceMonitoring,
  getActiveAlerts,
  acknowledgeAlert 
} from '../services/PerformanceAlertingService';

interface Alert {
  id: string;
  metric: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  value: number;
  threshold: number;
  timestamp: number;
  acknowledged: boolean;
  resolved: boolean;
  resolvedAt?: number;
}

interface AlertsPanelProps {
  className?: string;
  compact?: boolean;
  autoStart?: boolean;
}

export const AlertsPanel: React.FC<AlertsPanelProps> = ({
  className = '',
  compact = false,
  autoStart = true
}) => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [showResolved, setShowResolved] = useState(false);
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [stats, setStats] = useState<any>(null);
  const refreshInterval = useRef<NodeJS.Timeout | null>(null);

  // Initialize monitoring
  useEffect(() => {
    if (autoStart) {
      handleStartMonitoring();
    }

    // Set up refresh interval
    refreshInterval.current = setInterval(refreshAlerts, 10000); // Refresh every 10 seconds

    return () => {
      if (refreshInterval.current) {
        clearInterval(refreshInterval.current);
      }
      stopPerformanceMonitoring();
    };
  }, [autoStart]);

  const refreshAlerts = () => {
    const activeAlerts = getActiveAlerts();
    const allAlerts = performanceAlertingService.getAllAlerts();
    
    setAlerts(showResolved ? allAlerts : activeAlerts);
    setStats(performanceAlertingService.getAlertStats());
  };

  const handleStartMonitoring = () => {
    startPerformanceMonitoring(30000);
    setIsMonitoring(true);
    refreshAlerts();
  };

  const handleStopMonitoring = () => {
    stopPerformanceMonitoring();
    setIsMonitoring(false);
  };

  const handleAcknowledgeAlert = (alertId: string) => {
    if (acknowledgeAlert(alertId)) {
      refreshAlerts();
    }
  };

  const handleAcknowledgeAll = () => {
    alerts.filter(alert => !alert.acknowledged).forEach(alert => {
      acknowledgeAlert(alert.id);
    });
    refreshAlerts();
  };

  const getSeverityColor = (severity: string) => {
    const colors = {
      low: 'bg-yellow-100 text-yellow-800 border-yellow-200',
      medium: 'bg-orange-100 text-orange-800 border-orange-200',
      high: 'bg-red-100 text-red-800 border-red-200',
      critical: 'bg-purple-100 text-purple-800 border-purple-200'
    };
    return colors[severity as keyof typeof colors] || 'bg-gray-100 text-gray-800 border-gray-200';
  };

  const getSeverityIcon = (severity: string) => {
    const icons = {
      low: '🟡',
      medium: '🟠',
      high: '🔴',
      critical: '💥'
    };
    return icons[severity as keyof typeof icons] || '⚠️';
  };

  const formatTimestamp = (timestamp: number) => {
    return new Date(timestamp).toLocaleString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getTimeAgo = (timestamp: number) => {
    const now = Date.now();
    const diff = now - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) return `${hours}h atrás`;
    if (minutes > 0) return `${minutes}m atrás`;
    return 'Agora';
  };

  const filteredAlerts = alerts.filter(alert => {
    if (selectedSeverity !== 'all' && alert.severity !== selectedSeverity) {
      return false;
    }
    return true;
  });

  if (compact) {
    const activeCount = alerts.filter(a => !a.resolved && !a.acknowledged).length;
    const criticalCount = alerts.filter(a => a.severity === 'critical' && !a.resolved).length;
    
    return (
      <div className={`flex items-center gap-2 ${className}`}>
        <div className="flex items-center gap-1">
          {criticalCount > 0 ? (
            <span className="flex items-center gap-1 text-red-600">
              💥 <span className="text-xs font-medium">{criticalCount} crítico{criticalCount !== 1 ? 's' : ''}</span>
            </span>
          ) : activeCount > 0 ? (
            <span className="flex items-center gap-1 text-orange-600">
              ⚠️ <span className="text-xs font-medium">{activeCount} alerta{activeCount !== 1 ? 's' : ''}</span>
            </span>
          ) : (
            <span className="flex items-center gap-1 text-green-600">
              ✅ <span className="text-xs font-medium">Tudo OK</span>
            </span>
          )}
        </div>
        
        <div className={`w-2 h-2 rounded-full ${isMonitoring ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} 
             title={isMonitoring ? 'Monitoramento ativo' : 'Monitoramento parado'} />
      </div>
    );
  }

  return (
    <div className={`bg-white border border-gray-200 rounded-lg ${className}`}>
      {/* Header */}
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h3 className="text-lg font-semibold text-gray-900">Alertas de Performance</h3>
            <div className={`flex items-center gap-1 px-2 py-1 rounded-full text-xs ${
              isMonitoring ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'
            }`}>
              <div className={`w-2 h-2 rounded-full ${isMonitoring ? 'bg-green-500' : 'bg-gray-400'}`} />
              {isMonitoring ? 'Monitorando' : 'Parado'}
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            <button
              onClick={isMonitoring ? handleStopMonitoring : handleStartMonitoring}
              className={`px-3 py-1 text-sm rounded-lg ${
                isMonitoring 
                  ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                  : 'bg-blue-100 text-blue-700 hover:bg-blue-200'
              }`}
            >
              {isMonitoring ? 'Parar' : 'Iniciar'}
            </button>
            
            <button
              onClick={refreshAlerts}
              className="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg"
              title="Atualizar alertas"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                      d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </button>
          </div>
        </div>

        {/* Stats */}
        {stats && (
          <div className="mt-3 grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="text-center">
              <div className="text-lg font-medium text-gray-900">{stats.active}</div>
              <div className="text-xs text-gray-500">Ativos</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-medium text-red-600">{stats.bySeverity.critical}</div>
              <div className="text-xs text-gray-500">Críticos</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-medium text-orange-600">{stats.bySeverity.high}</div>
              <div className="text-xs text-gray-500">Alto</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-medium text-yellow-600">{stats.bySeverity.medium}</div>
              <div className="text-xs text-gray-500">Médio</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-medium text-gray-600">{stats.last24h}</div>
              <div className="text-xs text-gray-500">Últimas 24h</div>
            </div>
          </div>
        )}
      </div>

      {/* Filters */}
      <div className="p-4 border-b border-gray-200 bg-gray-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={showResolved}
                onChange={(e) => setShowResolved(e.target.checked)}
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-sm text-gray-700">Mostrar resolvidos</span>
            </label>
            
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="text-sm border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="all">Todas as severidades</option>
              <option value="critical">Crítico</option>
              <option value="high">Alto</option>
              <option value="medium">Médio</option>
              <option value="low">Baixo</option>
            </select>
          </div>
          
          {alerts.some(a => !a.acknowledged && !a.resolved) && (
            <button
              onClick={handleAcknowledgeAll}
              className="px-3 py-1 text-sm bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200"
            >
              Confirmar Todos
            </button>
          )}
        </div>
      </div>

      {/* Alerts List */}
      <div className="max-h-96 overflow-y-auto">
        {filteredAlerts.length === 0 ? (
          <div className="p-8 text-center">
            <div className="text-gray-400 mb-2">
              <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1}
                      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <h4 className="text-lg font-medium text-gray-900 mb-1">Nenhum alerta</h4>
            <p className="text-gray-600">
              {!isMonitoring ? 'Inicie o monitoramento para ver alertas' : 'Tudo funcionando normalmente'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                className={`p-4 ${
                  alert.acknowledged ? 'bg-gray-50' : 'bg-white'
                } ${alert.resolved ? 'opacity-60' : ''}`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-lg">{getSeverityIcon(alert.severity)}</span>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(alert.severity)}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                      <span className="text-xs text-gray-500">{alert.metric}</span>
                      {alert.resolved && (
                        <span className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded-full">
                          Resolvido
                        </span>
                      )}
                      {alert.acknowledged && !alert.resolved && (
                        <span className="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded-full">
                          Confirmado
                        </span>
                      )}
                    </div>
                    
                    <p className="text-sm text-gray-900 mb-2">{alert.message}</p>
                    
                    <div className="flex items-center gap-4 text-xs text-gray-500">
                      <span>📅 {formatTimestamp(alert.timestamp)}</span>
                      <span>⏰ {getTimeAgo(alert.timestamp)}</span>
                      <span>📊 Valor: {alert.value.toFixed(2)}</span>
                      <span>🎯 Limite: {alert.threshold}</span>
                    </div>
                  </div>
                  
                  <div className="flex items-center gap-2 ml-4">
                    {!alert.acknowledged && !alert.resolved && (
                      <button
                        onClick={() => handleAcknowledgeAlert(alert.id)}
                        className="px-3 py-1 text-xs bg-blue-100 text-blue-700 rounded-lg hover:bg-blue-200"
                      >
                        Confirmar
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AlertsPanel;