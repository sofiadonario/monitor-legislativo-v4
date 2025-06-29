import React, { useState, useEffect } from 'react';
import { rShinyConfig } from '../config/rshiny';
import { Flask, CheckCircle, XCircle, Clock, ArrowSquareOut } from '@phosphor-icons/react';

interface RShinyStatusProps {
  className?: string;
  showDetails?: boolean;
}

interface HealthStatus {
  status: 'healthy' | 'unhealthy' | 'checking' | 'unknown';
  timestamp?: string;
  version?: string;
  error?: string;
}

const RShinyStatus: React.FC<RShinyStatusProps> = ({ className = '', showDetails = false }) => {
  const [healthStatus, setHealthStatus] = useState<HealthStatus>({ status: 'checking' });
  const [isChecking, setIsChecking] = useState(false);

  const checkHealth = async () => {
    setIsChecking(true);
    try {
      const response = await fetch(`${rShinyConfig.baseUrl}/health`, {
        method: 'GET',
        mode: 'cors',
        headers: {
          'Accept': 'application/json',
        },
        signal: AbortSignal.timeout(rShinyConfig.loadTimeout)
      });

      if (response.ok) {
        const data = await response.json();
        setHealthStatus({
          status: 'healthy',
          timestamp: data.timestamp,
          version: data.version
        });
      } else {
        setHealthStatus({
          status: 'unhealthy',
          error: `HTTP ${response.status}: ${response.statusText}`
        });
      }
    } catch (error) {
      setHealthStatus({
        status: 'unhealthy',
        error: error instanceof Error ? error.message : 'Connection failed'
      });
    } finally {
      setIsChecking(false);
    }
  };

  useEffect(() => {
    checkHealth();
    
    // Set up periodic health checks
    const interval = setInterval(checkHealth, rShinyConfig.heartbeatInterval);
    
    return () => clearInterval(interval);
  }, []);

  const getStatusIcon = () => {
    switch (healthStatus.status) {
      case 'healthy':
        return <CheckCircle size={16} weight="fill" className="text-green-500" />;
      case 'unhealthy':
        return <XCircle size={16} weight="fill" className="text-red-500" />;
      case 'checking':
        return <Clock size={16} weight="fill" className="text-yellow-500 animate-spin" />;
      default:
        return <Clock size={16} weight="fill" className="text-gray-500" />;
    }
  };

  const getStatusText = () => {
    switch (healthStatus.status) {
      case 'healthy':
        return 'R Shiny Available';
      case 'unhealthy':
        return 'R Shiny Unavailable';
      case 'checking':
        return 'Checking R Shiny...';
      default:
        return 'R Shiny Status Unknown';
    }
  };

  const getStatusColor = () => {
    switch (healthStatus.status) {
      case 'healthy':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'unhealthy':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'checking':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  return (
    <div className={`${className}`}>
      {/* Compact Status Indicator */}
      <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-lg border text-sm font-medium ${getStatusColor()}`}>
        <Flask size={14} weight="fill" />
        {getStatusIcon()}
        <span>{getStatusText()}</span>
        {healthStatus.status === 'healthy' && (
          <a
            href={rShinyConfig.baseUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="ml-1 hover:opacity-70 transition-opacity"
            title="Open R Shiny App"
          >
            <ArrowSquareOut size={12} weight="bold" />
          </a>
        )}
      </div>

      {/* Detailed Status (if requested) */}
      {showDetails && (
        <div className="mt-3 p-4 bg-white rounded-lg border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-sm font-semibold text-gray-900 flex items-center gap-2">
              <Flask size={16} weight="fill" />
              R Shiny Analytics Status
            </h4>
            <button
              onClick={checkHealth}
              disabled={isChecking}
              className="text-xs text-blue-600 hover:text-blue-800 disabled:opacity-50"
            >
              {isChecking ? 'Checking...' : 'Refresh'}
            </button>
          </div>

          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-gray-600">Status:</span>
              <span className={`font-medium ${
                healthStatus.status === 'healthy' ? 'text-green-600' : 
                healthStatus.status === 'unhealthy' ? 'text-red-600' : 
                'text-yellow-600'
              }`}>
                {healthStatus.status.charAt(0).toUpperCase() + healthStatus.status.slice(1)}
              </span>
            </div>

            <div className="flex justify-between">
              <span className="text-gray-600">URL:</span>
              <span className="font-mono text-xs text-gray-800">{rShinyConfig.baseUrl}</span>
            </div>

            {healthStatus.version && (
              <div className="flex justify-between">
                <span className="text-gray-600">Version:</span>
                <span className="text-gray-800">{healthStatus.version}</span>
              </div>
            )}

            {healthStatus.timestamp && (
              <div className="flex justify-between">
                <span className="text-gray-600">Last Check:</span>
                <span className="text-gray-800">
                  {new Date(healthStatus.timestamp).toLocaleTimeString()}
                </span>
              </div>
            )}

            {healthStatus.error && (
              <div className="mt-3 p-2 bg-red-50 border border-red-200 rounded">
                <span className="text-red-700 text-xs">{healthStatus.error}</span>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="mt-4 pt-3 border-t border-gray-200">
            <div className="flex gap-2">
              {healthStatus.status === 'healthy' ? (
                <a
                  href={rShinyConfig.baseUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs bg-blue-600 text-white px-3 py-1 rounded hover:bg-blue-700 transition-colors"
                >
                  Open R Shiny App
                </a>
              ) : (
                <div className="text-xs text-gray-500">
                  R Shiny server not available. Check deployment status.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default RShinyStatus;