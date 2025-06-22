/**
 * Data Source Indicator Component
 * Shows users whether they're viewing live API data or CSV fallback
 */

import React from 'react';
import { DataSource } from '../types/lexml-api.types';

interface DataSourceIndicatorProps {
  dataSource: DataSource;
  apiStatus: 'connected' | 'fallback' | 'error';
  searchTime?: number;
  resultCount?: number;
  totalAvailable?: number | 'unlimited';
  className?: string;
}

interface SourceConfig {
  icon: string;
  label: string;
  description: string;
  color: string;
  bgColor: string;
  borderColor: string;
}

const sourceConfigs: Record<DataSource, SourceConfig> = {
  'live-api': {
    icon: '🔴',
    label: 'Live API',
    description: 'Real-time data from LexML Brasil',
    color: 'text-green-700',
    bgColor: 'bg-green-50',
    borderColor: 'border-green-200'
  },
  'cached-api': {
    icon: '🟡',
    label: 'Cached',
    description: 'Recent data from cache',
    color: 'text-blue-700',
    bgColor: 'bg-blue-50',
    borderColor: 'border-blue-200'
  },
  'csv-fallback': {
    icon: '⚫',
    label: 'Fallback',
    description: 'Local dataset (890 documents)',
    color: 'text-gray-700',
    bgColor: 'bg-gray-50',
    borderColor: 'border-gray-200'
  }
};

const apiStatusConfigs = {
  connected: {
    icon: '✅',
    text: 'API Connected',
    color: 'text-green-600'
  },
  fallback: {
    icon: '⚠️',
    text: 'Using Fallback',
    color: 'text-yellow-600'
  },
  error: {
    icon: '❌',
    text: 'API Error',
    color: 'text-red-600'
  }
};

export const DataSourceIndicator: React.FC<DataSourceIndicatorProps> = ({
  dataSource,
  apiStatus,
  searchTime,
  resultCount,
  totalAvailable,
  className = ''
}) => {
  const sourceConfig = sourceConfigs[dataSource];
  const statusConfig = apiStatusConfigs[apiStatus];

  const formatSearchTime = (timeMs?: number): string => {
    if (!timeMs) return '';
    if (timeMs < 1000) return `${Math.round(timeMs)}ms`;
    return `${(timeMs / 1000).toFixed(1)}s`;
  };

  const formatResultCount = (): string => {
    if (resultCount === undefined) return '';
    
    if (totalAvailable === 'unlimited') {
      return `${resultCount.toLocaleString()} results (unlimited database)`;
    } else if (totalAvailable && totalAvailable > resultCount) {
      return `${resultCount.toLocaleString()} of ${totalAvailable.toLocaleString()} results`;
    } else {
      return `${resultCount.toLocaleString()} results`;
    }
  };

  return (
    <div className={`flex items-center gap-4 p-3 rounded-lg border ${sourceConfig.bgColor} ${sourceConfig.borderColor} ${className}`}>
      {/* Data Source Status */}
      <div className="flex items-center gap-2">
        <span className="text-lg" title={sourceConfig.description}>
          {sourceConfig.icon}
        </span>
        <div className="flex flex-col">
          <span className={`text-sm font-medium ${sourceConfig.color}`}>
            {sourceConfig.label}
          </span>
          <span className="text-xs text-gray-500">
            {sourceConfig.description}
          </span>
        </div>
      </div>

      {/* API Status */}
      <div className="flex items-center gap-2 px-2 py-1 rounded-md bg-white/50">
        <span className="text-sm">{statusConfig.icon}</span>
        <span className={`text-sm font-medium ${statusConfig.color}`}>
          {statusConfig.text}
        </span>
      </div>

      {/* Search Performance */}
      {searchTime !== undefined && (
        <div className="flex items-center gap-2 px-2 py-1 rounded-md bg-white/50">
          <span className="text-sm">⚡</span>
          <span className="text-sm text-gray-600">
            {formatSearchTime(searchTime)}
          </span>
        </div>
      )}

      {/* Result Count */}
      {resultCount !== undefined && (
        <div className="flex items-center gap-2 px-2 py-1 rounded-md bg-white/50">
          <span className="text-sm">📄</span>
          <span className="text-sm text-gray-600">
            {formatResultCount()}
          </span>
        </div>
      )}

      {/* Fallback Notice */}
      {dataSource === 'csv-fallback' && (
        <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-yellow-100 border border-yellow-300">
          <span className="text-sm">ℹ️</span>
          <span className="text-sm text-yellow-800">
            Limited to transport legislation dataset
          </span>
        </div>
      )}

      {/* Live API Benefits */}
      {dataSource === 'live-api' && (
        <div className="flex items-center gap-2 px-3 py-1 rounded-md bg-green-100 border border-green-300">
          <span className="text-sm">🚀</span>
          <span className="text-sm text-green-800">
            Complete Brazilian legal database
          </span>
        </div>
      )}
    </div>
  );
};

export default DataSourceIndicator;