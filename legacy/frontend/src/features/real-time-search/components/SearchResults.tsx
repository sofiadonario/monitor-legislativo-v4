/**
 * Search Results Component with Data Source Indicators
 * Displays LexML search results with clear source attribution
 */

import React, { useState } from 'react';
import { LexMLDocument, DataSource } from '../types/lexml-api.types';
import DataSourceIndicator from './DataSourceIndicator';
import { SkeletonDocumentList } from '../../../components/common/SkeletonLoader';

interface SearchResultsProps {
  documents: LexMLDocument[];
  dataSource: DataSource;
  apiStatus: 'connected' | 'fallback' | 'error';
  searchTime?: number;
  resultCount?: number;
  totalAvailable?: number | 'unlimited';
  isLoading?: boolean;
  hasNextPage?: boolean;
  onLoadMore?: () => void;
  onDocumentClick?: (document: LexMLDocument) => void;
  className?: string;
}

interface DocumentCardProps {
  document: LexMLDocument;
  onClick?: (document: LexMLDocument) => void;
}

const DocumentCard: React.FC<DocumentCardProps> = ({ document, onClick }) => {
  const formatDate = (dateString: string): string => {
    try {
      const date = new Date(dateString);
      return date.toLocaleDateString('pt-BR', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    } catch {
      return dateString;
    }
  };

  const getDocumentTypeColor = (type: string): string => {
    const colors: Record<string, string> = {
      'Lei': 'bg-blue-100 text-blue-800',
      'Decreto': 'bg-green-100 text-green-800',
      'Portaria': 'bg-yellow-100 text-yellow-800',
      'Resolução': 'bg-purple-100 text-purple-800',
      'Medida Provisória': 'bg-red-100 text-red-800',
      'Instrução Normativa': 'bg-indigo-100 text-indigo-800'
    };
    return colors[type] || 'bg-gray-100 text-gray-800';
  };

  const getAuthorityIcon = (authority: string): string => {
    const icons: Record<string, string> = {
      'federal': '🇧🇷',
      'estadual': '🏛️',
      'municipal': '🏢',
      'distrital': '🏛️'
    };
    return icons[authority] || '📋';
  };

  return (
    <div 
      className="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow duration-200 cursor-pointer"
      onClick={() => onClick?.(document)}
    >
      {/* Document Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <span className={`px-2 py-1 text-xs font-medium rounded-full ${getDocumentTypeColor(document.metadata.tipoDocumento)}`}>
            {document.metadata.tipoDocumento}
          </span>
          <span className="flex items-center gap-1 text-xs text-gray-600">
            {getAuthorityIcon(document.metadata.autoridade)}
            {document.metadata.autoridade}
          </span>
          <span className="text-xs text-gray-500">
            📍 {document.metadata.localidade}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {/* Data Source Badge */}
          <span className={`
            px-2 py-1 text-xs rounded-full
            ${document.data_source === 'live-api' ? 'bg-green-100 text-green-700' : 
              document.data_source === 'cached-api' ? 'bg-blue-100 text-blue-700' : 
              'bg-gray-100 text-gray-700'}
          `}>
            {document.data_source === 'live-api' ? '🔴 Live' : 
             document.data_source === 'cached-api' ? '🟡 Cached' : 
             '⚫ Fallback'}
          </span>
        </div>
      </div>

      {/* Document Title */}
      <h3 className="text-lg font-semibold text-gray-900 mb-2 line-clamp-2">
        {document.metadata.title}
      </h3>

      {/* Document Description */}
      {document.metadata.description && (
        <p className="text-sm text-gray-600 mb-3 line-clamp-2">
          {document.metadata.description}
        </p>
      )}

      {/* Document Metadata */}
      <div className="space-y-2">
        <div className="flex items-center gap-4 text-sm text-gray-500">
          <span className="flex items-center gap-1">
            📅 {formatDate(document.metadata.date)}
          </span>
          <span className="flex items-center gap-1">
            🔗 {document.metadata.urn.split(':').pop() || 'N/A'}
          </span>
        </div>

        {/* Subject Tags */}
        {document.metadata.subject.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {document.metadata.subject.slice(0, 5).map((subject, index) => (
              <span
                key={index}
                className="bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded-full"
              >
                {subject}
              </span>
            ))}
            {document.metadata.subject.length > 5 && (
              <span className="bg-gray-100 text-gray-700 text-xs px-2 py-1 rounded-full">
                +{document.metadata.subject.length - 5} more
              </span>
            )}
          </div>
        )}
      </div>

      {/* Access Links */}
      <div className="mt-3 pt-3 border-t border-gray-100 flex items-center justify-between">
        <button className="text-blue-600 hover:text-blue-800 text-sm font-medium flex items-center gap-1">
          📄 View Full Document
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
          </svg>
        </button>
        
        {document.metadata.identifier && (
          <a
            href={document.metadata.identifier}
            target="_blank"
            rel="noopener noreferrer"
            onClick={(e) => e.stopPropagation()}
            className="text-gray-600 hover:text-gray-800 text-sm flex items-center gap-1"
          >
            🌐 Official Source
          </a>
        )}
      </div>
    </div>
  );
};

export const SearchResults: React.FC<SearchResultsProps> = ({
  documents,
  dataSource,
  apiStatus,
  searchTime,
  resultCount,
  totalAvailable,
  isLoading = false,
  hasNextPage = false,
  onLoadMore,
  onDocumentClick,
  className = ''
}) => {
  const [viewMode, setViewMode] = useState<'card' | 'list'>('card');

  // Empty state
  if (!isLoading && documents.length === 0) {
    return (
      <div className={`bg-white border border-gray-200 rounded-lg p-8 text-center ${className}`}>
        <div className="text-gray-400 mb-4">
          <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </div>
        <h3 className="text-lg font-medium text-gray-900 mb-2">No documents found</h3>
        <p className="text-gray-500 mb-4">
          Try adjusting your search terms or filters to find relevant legislation.
        </p>
        {apiStatus === 'fallback' && (
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 max-w-md mx-auto">
            <p className="text-sm text-yellow-800">
              ⚠️ Currently using fallback dataset. Try searching for transport-related terms 
              or wait for API connectivity to restore for full database access.
            </p>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={className}>
      {/* Data Source Status */}
      <DataSourceIndicator
        dataSource={dataSource}
        apiStatus={apiStatus}
        searchTime={searchTime}
        resultCount={resultCount}
        totalAvailable={totalAvailable}
        className="mb-4"
      />

      {/* Results Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-semibold text-gray-900">Search Results</h2>
          {resultCount !== undefined && (
            <p className="text-sm text-gray-600 mt-1">
              {dataSource === 'csv-fallback' 
                ? `Showing ${documents.length} of ${resultCount} results from transport legislation dataset`
                : totalAvailable === 'unlimited'
                  ? `Showing ${documents.length} results from complete legal database`
                  : `Showing ${documents.length} of ${totalAvailable?.toLocaleString()} results`
              }
            </p>
          )}
        </div>

        {/* View Mode Toggle */}
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-600">View:</span>
          <div className="flex rounded-lg border border-gray-300">
            <button
              onClick={() => setViewMode('card')}
              className={`px-3 py-1 text-sm rounded-l-lg ${
                viewMode === 'card' 
                  ? 'bg-blue-500 text-white' 
                  : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              Cards
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`px-3 py-1 text-sm rounded-r-lg ${
                viewMode === 'list' 
                  ? 'bg-blue-500 text-white' 
                  : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
            >
              List
            </button>
          </div>
        </div>
      </div>

      {/* Loading State */}
      {isLoading && documents.length === 0 && (
        <SkeletonDocumentList count={viewMode === 'card' ? 6 : 5} />
      )}

      {/* Results Grid/List */}
      <div className={
        viewMode === 'card' 
          ? 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4'
          : 'space-y-4'
      }>
        {documents.map((document, index) => (
          <DocumentCard
            key={`${document.metadata.urn}-${index}`}
            document={document}
            onClick={onDocumentClick}
          />
        ))}
      </div>

      {/* Load More Button */}
      {hasNextPage && onLoadMore && (
        <div className="mt-8 text-center">
          <button
            onClick={onLoadMore}
            disabled={isLoading}
            className="
              px-6 py-3 bg-blue-600 text-white rounded-lg
              hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
              disabled:bg-gray-400 disabled:cursor-not-allowed
              flex items-center gap-2 mx-auto
              transition-colors duration-200
            "
          >
            {isLoading ? (
              <>
                <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                Loading more...
              </>
            ) : (
              <>
                📄 Load More Results
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </>
            )}
          </button>
        </div>
      )}

      {/* Fallback Upgrade Notice */}
      {dataSource === 'csv-fallback' && documents.length > 0 && (
        <div className="mt-6 bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-start gap-3">
            <span className="text-blue-500 text-xl">🚀</span>
            <div>
              <h4 className="text-sm font-medium text-blue-900 mb-1">
                Want access to the complete Brazilian legal database?
              </h4>
              <p className="text-sm text-blue-800 mb-3">
                You're currently viewing results from our transport legislation dataset (890 documents). 
                The live API provides access to millions of documents across all legal areas.
              </p>
              <button className="text-sm text-blue-600 hover:text-blue-800 font-medium">
                Check API Status →
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SearchResults;