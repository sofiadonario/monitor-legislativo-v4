/**
 * Mobile-First Search Interface
 * Optimized for touch devices with responsive design and gesture support
 */

import React, { useState, useRef, useEffect } from 'react';
import { LexMLDocument, SearchFilters } from '../types/lexml-api.types';
import { useLexMLSearch } from '../hooks/useLexMLSearch';
import { searchHistoryService } from '../services/SearchHistoryService';
import { accessibilityService, announceToScreenReader, trapFocus } from '../services/AccessibilityService';

interface MobileSearchInterfaceProps {
  onDocumentSelect?: (document: LexMLDocument) => void;
  className?: string;
}

interface TouchGesture {
  startX: number;
  startY: number;
  currentX: number;
  currentY: number;
  deltaX: number;
  deltaY: number;
  isSwipe: boolean;
  direction?: 'left' | 'right' | 'up' | 'down';
}

export const MobileSearchInterface: React.FC<MobileSearchInterfaceProps> = ({
  onDocumentSelect,
  className = ''
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [showFilters, setShowFilters] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [suggestions, setSuggestions] = useState<any[]>([]);
  const [selectedDocumentIndex, setSelectedDocumentIndex] = useState<number | null>(null);
  const [gesture, setGesture] = useState<TouchGesture | null>(null);
  const [isPullToRefresh, setIsPullToRefresh] = useState(false);
  const [pullDistance, setPullDistance] = useState(0);
  const [isHighContrast, setIsHighContrast] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const filtersDrawerRef = useRef<HTMLDivElement>(null);
  const pullToRefreshRef = useRef<HTMLDivElement>(null);
  const liveRegionRef = useRef<HTMLDivElement>(null);
  const focusTrapCleanup = useRef<(() => void) | null>(null);

  const {
    searchState,
    searchDocuments,
    setFilters,
    clearResults
  } = useLexMLSearch({
    debounceMs: 300,
    autoSearch: false,
    minQueryLength: 2
  });

  // Handle search input changes with suggestions
  useEffect(() => {
    if (searchTerm.length >= 2) {
      const searchSuggestions = searchHistoryService.getSearchSuggestions(searchTerm);
      setSuggestions(searchSuggestions);
      setShowSuggestions(true);
      
      // Announce suggestions to screen readers
      if (searchSuggestions.length > 0) {
        announceToScreenReader(`${searchSuggestions.length} sugestões disponíveis`);
      }
    } else {
      setShowSuggestions(false);
      setSuggestions([]);
    }
  }, [searchTerm]);

  // Initialize accessibility features
  useEffect(() => {
    // Check for user preferences
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const prefersHighContrast = window.matchMedia('(prefers-contrast: high)').matches;
    
    setReducedMotion(prefersReducedMotion);
    setIsHighContrast(prefersHighContrast);
    
    // Add skip links
    accessibilityService.addSkipLinks();
    
    // Create live region for announcements
    if (liveRegionRef.current) {
      accessibilityService.createLiveRegion('search-announcements', 'polite');
    }
    
    return () => {
      // Cleanup
      if (focusTrapCleanup.current) {
        focusTrapCleanup.current();
      }
    };
  }, []);

  // Handle focus management for overlays
  useEffect(() => {
    if (showFilters && filtersDrawerRef.current) {
      accessibilityService.storeFocus();
      focusTrapCleanup.current = trapFocus(filtersDrawerRef.current);
      
      // Focus first interactive element
      const firstButton = filtersDrawerRef.current.querySelector('button');
      if (firstButton) {
        (firstButton as HTMLElement).focus();
      }
    } else if (!showFilters) {
      if (focusTrapCleanup.current) {
        focusTrapCleanup.current();
        focusTrapCleanup.current = null;
      }
      accessibilityService.restoreFocus();
    }
  }, [showFilters]);

  // Touch gesture handling
  const handleTouchStart = (e: React.TouchEvent) => {
    const touch = e.touches[0];
    setGesture({
      startX: touch.clientX,
      startY: touch.clientY,
      currentX: touch.clientX,
      currentY: touch.clientY,
      deltaX: 0,
      deltaY: 0,
      isSwipe: false
    });
  };

  const handleTouchMove = (e: React.TouchEvent) => {
    if (!gesture) return;

    const touch = e.touches[0];
    const deltaX = touch.clientX - gesture.startX;
    const deltaY = touch.clientY - gesture.startY;

    // Handle pull-to-refresh for downward swipes at top of page
    if (window.scrollY === 0 && deltaY > 0 && Math.abs(deltaX) < 50) {
      setIsPullToRefresh(true);
      setPullDistance(Math.min(deltaY, 120));
      e.preventDefault();
    }

    setGesture({
      ...gesture,
      currentX: touch.clientX,
      currentY: touch.clientY,
      deltaX,
      deltaY,
      isSwipe: Math.abs(deltaX) > 50 || Math.abs(deltaY) > 50
    });
  };

  const handleTouchEnd = (e: React.TouchEvent) => {
    // Handle pull-to-refresh release
    if (isPullToRefresh) {
      if (pullDistance > 80) {
        handlePullToRefresh();
      }
      setIsPullToRefresh(false);
      setPullDistance(0);
    }

    if (!gesture || !gesture.isSwipe) {
      setGesture(null);
      return;
    }

    const { deltaX, deltaY } = gesture;
    const threshold = 80;

    // Provide haptic feedback simulation
    triggerHapticFeedback();

    // Determine swipe direction
    if (Math.abs(deltaX) > Math.abs(deltaY)) {
      if (deltaX > threshold) {
        handleSwipeRight();
      } else if (deltaX < -threshold) {
        handleSwipeLeft();
      }
    } else {
      if (deltaY > threshold) {
        handleSwipeDown();
      } else if (deltaY < -threshold) {
        handleSwipeUp();
      }
    }

    setGesture(null);
  };

  const handleSwipeRight = () => {
    // Open filters drawer
    setShowFilters(true);
  };

  const handleSwipeLeft = () => {
    // Close filters drawer or navigate back
    if (showFilters) {
      setShowFilters(false);
    } else if (selectedDocumentIndex !== null) {
      setSelectedDocumentIndex(null);
    }
  };

  const handleSwipeUp = () => {
    // Show search history
    setShowHistory(true);
  };

  const handleSwipeDown = () => {
    // Hide overlays
    setShowHistory(false);
    setShowSuggestions(false);
    if (searchInputRef.current) {
      searchInputRef.current.blur();
    }
  };

  const handlePullToRefresh = async () => {
    if (searchTerm.trim()) {
      await searchDocuments(searchTerm, searchState.filters);
    }
  };

  const triggerHapticFeedback = () => {
    // Simulate haptic feedback on supported devices
    if ('vibrate' in navigator) {
      navigator.vibrate(10); // Short vibration
    }
  };

  const handleSearch = async () => {
    if (searchTerm.trim()) {
      setShowSuggestions(false);
      setShowHistory(false);
      
      // Announce search start
      announceToScreenReader('Iniciando busca', 'polite');
      
      await searchDocuments(searchTerm, searchState.filters);
      
      // Announce search results
      const resultCount = searchState.results.length;
      announceToScreenReader(
        `Busca concluída. ${resultCount} documento${resultCount !== 1 ? 's' : ''} encontrado${resultCount !== 1 ? 's' : ''}`, 
        'polite'
      );
      
      // Add to history
      searchHistoryService.addToHistory({
        query: searchTerm,
        filters: searchState.filters,
        resultCount: searchState.results.length,
        searchTime: searchState.searchTime,
        dataSource: searchState.dataSource,
        userInteraction: {
          documentsViewed: 0,
          timeSpent: 0,
          exported: false,
          shared: false
        }
      });
    }
  };

  const handleSuggestionSelect = (suggestion: any) => {
    setSearchTerm(suggestion.text);
    setShowSuggestions(false);
    announceToScreenReader(`Sugestão selecionada: ${suggestion.text}`);
    searchInputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    // Handle keyboard navigation for suggestions
    if (showSuggestions && suggestions.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        // Focus first suggestion
        const firstSuggestion = document.querySelector('[data-suggestion-index="0"]');
        if (firstSuggestion) {
          (firstSuggestion as HTMLElement).focus();
        }
      }
    }
    
    // Handle Escape key
    if (e.key === 'Escape') {
      setShowSuggestions(false);
      setShowHistory(false);
      setShowFilters(false);
    }
  };

  const handleDocumentTap = (document: LexMLDocument, index: number) => {
    setSelectedDocumentIndex(index);
    onDocumentSelect?.(document);
    
    // Track document interaction for analytics
    const history = searchHistoryService.getHistory({ limit: 1 });
    if (history.length > 0) {
      const lastSearch = history[0];
      lastSearch.userInteraction.documentsViewed++;
      searchHistoryService.addToHistory({
        ...lastSearch,
        id: undefined,
        timestamp: undefined
      } as any);
    }
  };

  const handleExport = () => {
    if (searchState.results.length === 0) return;
    
    const exportData = {
      searchQuery: searchTerm,
      filters: searchState.filters,
      totalResults: searchState.resultCount,
      exportedAt: new Date().toISOString(),
      results: searchState.results.map(doc => ({
        title: doc.metadata.title,
        type: doc.metadata.tipoDocumento,
        authority: doc.metadata.autoridade,
        location: doc.metadata.localidade,
        date: doc.metadata.date,
        description: doc.metadata.description,
        urn: doc.metadata.urn,
        source: doc.data_source
      }))
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json'
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `legislacao-${searchTerm.replace(/\s+/g, '-')}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    // Track export action
    const history = searchHistoryService.getHistory({ limit: 1 });
    if (history.length > 0) {
      const lastSearch = history[0];
      lastSearch.userInteraction.exported = true;
      searchHistoryService.addToHistory({
        ...lastSearch,
        id: undefined,
        timestamp: undefined
      } as any);
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
  };

  return (
    <div 
      className={`min-h-screen bg-gray-50 ${className}`}
      onTouchStart={handleTouchStart}
      onTouchMove={handleTouchMove}
      onTouchEnd={handleTouchEnd}
      style={{
        transform: isPullToRefresh ? `translateY(${pullDistance * 0.5}px)` : 'none',
        transition: isPullToRefresh ? 'none' : 'transform 0.3s ease-out'
      }}
    >
      {/* Pull-to-Refresh Indicator */}
      {isPullToRefresh && (
        <div 
          className="fixed top-0 left-0 right-0 z-50 bg-blue-50 border-b border-blue-200 transition-opacity duration-200"
          style={{ 
            opacity: pullDistance / 80,
            height: `${Math.min(pullDistance, 60)}px`
          }}
        >
          <div className="flex items-center justify-center h-full">
            <div className="flex items-center gap-2 text-blue-600">
              {pullDistance > 80 ? (
                <>
                  <svg className="w-5 h-5 animate-spin" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                  </svg>
                  <span className="text-sm font-medium">Solte para atualizar</span>
                </>
              ) : (
                <>
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
                  </svg>
                  <span className="text-sm font-medium">Puxe para atualizar</span>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Mobile Header */}
      <header className="bg-white border-b border-gray-200 sticky top-0 z-40">
        <div className="px-4 py-3">
          <div className="flex items-center gap-3">
            {/* Menu Button */}
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="p-2 text-gray-600 hover:text-gray-900 touch-target"
              aria-label="Open filters"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>

            {/* Search Input */}
            <div className="flex-1 relative">
              <label htmlFor="search-input" className="sr-only">
                Campo de busca para legislação
              </label>
              <input
                id="search-input"
                ref={searchInputRef}
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                onKeyDown={handleKeyDown}
                placeholder="Buscar legislação..."
                className={`w-full px-4 py-2 text-base border border-gray-300 rounded-full bg-gray-50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 touch-target ${
                  isHighContrast ? 'border-2 border-black' : ''
                }`}
                style={{ fontSize: '16px' }} // Prevent zoom on iOS
                aria-describedby={showSuggestions ? 'suggestions-list' : undefined}
                aria-expanded={showSuggestions}
                aria-autocomplete="list"
                role="combobox"
              />
              
              {/* Search Button */}
              <button
                onClick={handleSearch}
                disabled={searchState.isLoading}
                className="absolute right-2 top-1/2 transform -translate-y-1/2 p-2 text-blue-600 hover:text-blue-800 touch-target"
                aria-label="Search"
              >
                {searchState.isLoading ? (
                  <div className="animate-spin h-5 w-5 border-2 border-blue-500 border-t-transparent rounded-full" />
                ) : (
                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                  </svg>
                )}
              </button>
            </div>

            {/* History Button */}
            <button
              onClick={() => setShowHistory(!showHistory)}
              className="p-2 text-gray-600 hover:text-gray-900 touch-target"
              aria-label="Search history"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </button>
          </div>
        </div>
      </header>

      {/* Search Suggestions Overlay */}
      {showSuggestions && suggestions.length > 0 && (
        <div 
          id="suggestions-list"
          className="absolute top-16 left-0 right-0 bg-white border-b border-gray-200 shadow-lg z-30 max-h-64 overflow-y-auto"
          role="listbox"
          aria-label="Sugestões de busca"
        >
          {suggestions.map((suggestion, index) => (
            <button
              key={index}
              data-suggestion-index={index}
              onClick={() => handleSuggestionSelect(suggestion)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowDown' && index < suggestions.length - 1) {
                  e.preventDefault();
                  const nextItem = document.querySelector(`[data-suggestion-index="${index + 1}"]`);
                  if (nextItem) (nextItem as HTMLElement).focus();
                } else if (e.key === 'ArrowUp') {
                  e.preventDefault();
                  if (index > 0) {
                    const prevItem = document.querySelector(`[data-suggestion-index="${index - 1}"]`);
                    if (prevItem) (prevItem as HTMLElement).focus();
                  } else {
                    searchInputRef.current?.focus();
                  }
                }
              }}
              className="w-full px-4 py-3 text-left hover:bg-gray-50 active:bg-gray-100 border-b border-gray-100 last:border-b-0 touch-target focus:bg-blue-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
              role="option"
              aria-selected={false}
            >
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-medium text-gray-900">{suggestion.text}</div>
                  <div className="text-sm text-gray-500 capitalize">{suggestion.type}</div>
                </div>
                {suggestion.frequency && (
                  <div className="text-xs text-gray-400" aria-label={`Usado ${suggestion.frequency} vezes`}>
                    {suggestion.frequency}x
                  </div>
                )}
              </div>
            </button>
          ))}
        </div>
      )}

      {/* History Overlay */}
      {showHistory && (
        <div className="absolute top-16 left-0 right-0 bg-white border-b border-gray-200 shadow-lg z-30 max-h-80 overflow-y-auto">
          <div className="p-4">
            <h3 className="text-lg font-medium text-gray-900 mb-3">Histórico de Busca</h3>
            {searchHistoryService.getHistory({ limit: 10 }).map((entry, index) => (
              <button
                key={index}
                onClick={() => {
                  setSearchTerm(entry.query);
                  setShowHistory(false);
                  searchInputRef.current?.focus();
                }}
                className="w-full p-3 text-left hover:bg-gray-50 active:bg-gray-100 rounded-lg mb-2 touch-target"
              >
                <div className="font-medium text-gray-900">{entry.query}</div>
                <div className="text-sm text-gray-500">
                  {formatDate(new Date(entry.timestamp).toISOString())} • {entry.resultCount} resultados
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Filters Drawer */}
      <div 
        ref={filtersDrawerRef}
        className={`fixed inset-y-0 left-0 w-80 bg-white shadow-xl transform transition-transform z-50 ${
          reducedMotion ? '' : 'duration-300 ease-in-out'
        } ${
          showFilters ? 'translate-x-0' : '-translate-x-full'
        }`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="filters-title"
      >
        <div className="p-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 id="filters-title" className="text-lg font-semibold text-gray-900">Filtros</h2>
            <button
              onClick={() => setShowFilters(false)}
              className="p-2 text-gray-600 hover:text-gray-900 touch-target"
              aria-label="Fechar filtros"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
        
        <div className="p-4 space-y-6 overflow-y-auto">
          {/* Document Type Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Tipo de Documento</label>
            <div className="space-y-2">
              {['Lei', 'Decreto', 'Portaria', 'Resolução'].map((type) => (
                <label key={type} className="flex items-center touch-target">
                  <input
                    type="checkbox"
                    className="h-4 w-4 text-blue-600 rounded border-gray-300 focus:ring-blue-500"
                    onChange={(e) => {
                      const current = searchState.filters.tipoDocumento || [];
                      const updated = e.target.checked 
                        ? [...current, type]
                        : current.filter(t => t !== type);
                      setFilters({ ...searchState.filters, tipoDocumento: updated });
                    }}
                  />
                  <span className="ml-2 text-sm text-gray-700">{type}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Authority Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Autoridade</label>
            <div className="space-y-2">
              {[
                { value: 'federal', label: 'Federal' },
                { value: 'estadual', label: 'Estadual' },
                { value: 'municipal', label: 'Municipal' }
              ].map((authority) => (
                <label key={authority.value} className="flex items-center touch-target">
                  <input
                    type="checkbox"
                    className="h-4 w-4 text-blue-600 rounded border-gray-300 focus:ring-blue-500"
                    onChange={(e) => {
                      const current = searchState.filters.autoridade || [];
                      const updated = e.target.checked 
                        ? [...current, authority.value]
                        : current.filter(a => a !== authority.value);
                      setFilters({ ...searchState.filters, autoridade: updated });
                    }}
                  />
                  <span className="ml-2 text-sm text-gray-700">{authority.label}</span>
                </label>
              ))}
            </div>
          </div>

          {/* Clear Filters */}
          <button
            onClick={() => {
              setFilters({});
              setShowFilters(false);
            }}
            className="w-full py-2 px-4 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 active:bg-gray-300 touch-target"
          >
            Limpar Filtros
          </button>
        </div>
      </div>

      {/* Overlay for drawer */}
      {showFilters && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 z-40"
          onClick={() => setShowFilters(false)}
        />
      )}

      {/* Live Region for Screen Reader Announcements */}
      <div 
        ref={liveRegionRef}
        id="search-announcements" 
        className="sr-only" 
        aria-live="polite" 
        aria-atomic="true"
      ></div>

      {/* Main Content */}
      <main id="main-content" className="pb-20" role="main">
        {/* Quick Stats */}
        {searchState.results.length > 0 && (
          <div className="bg-white border-b border-gray-200 p-4">
            <div className="flex items-center justify-between text-sm text-gray-600">
              <span>{searchState.resultCount} documentos encontrados</span>
              <span>{searchState.searchTime.toFixed(0)}ms</span>
            </div>
          </div>
        )}

        {/* Search Results */}
        <div ref={resultsRef} className="divide-y divide-gray-200">
          {searchState.isLoading ? (
            <div className="p-8 text-center">
              <div className="animate-spin h-8 w-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-4" />
              <p className="text-gray-600">Buscando documentos...</p>
            </div>
          ) : searchState.results.length === 0 ? (
            <div className="p-8 text-center">
              <div className="text-gray-400 mb-4">
                <svg className="w-16 h-16 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                </svg>
              </div>
              <h3 className="text-lg font-medium text-gray-900 mb-2">Nenhum documento encontrado</h3>
              <p className="text-gray-600">Tente ajustar seus termos de busca ou filtros</p>
            </div>
          ) : (
            searchState.results.map((document, index) => (
              <div
                key={document.metadata.urn}
                onClick={() => handleDocumentTap(document, index)}
                className={`p-4 bg-white hover:bg-gray-50 active:bg-gray-100 cursor-pointer touch-target ${
                  selectedDocumentIndex === index ? 'bg-blue-50 border-l-4 border-blue-500' : ''
                }`}
              >
                <div className="space-y-2">
                  {/* Document Type Badge */}
                  <div className="flex items-center gap-2">
                    <span className="inline-block px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                      {document.metadata.tipoDocumento}
                    </span>
                    <span className="text-xs text-gray-500">
                      {document.metadata.autoridade} • {document.metadata.localidade}
                    </span>
                  </div>

                  {/* Title */}
                  <h3 className="font-medium text-gray-900 line-clamp-2 leading-tight">
                    {document.metadata.title}
                  </h3>

                  {/* Description */}
                  {document.metadata.description && (
                    <p className="text-sm text-gray-600 line-clamp-2">
                      {document.metadata.description}
                    </p>
                  )}

                  {/* Date and Source */}
                  <div className="flex items-center justify-between text-xs text-gray-500">
                    <span>{formatDate(document.metadata.date)}</span>
                    <div className="flex items-center gap-1">
                      <span className={document.data_source === 'live-api' ? '🟢' : document.data_source === 'cached-api' ? '🟡' : '⚫'}>
                      </span>
                      <span>
                        {document.data_source === 'live-api' ? 'API' : 
                         document.data_source === 'cached-api' ? 'Cache' : 'Local'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </section>
      </main>

      {/* Bottom Action Bar */}
      <nav className="fixed bottom-0 left-0 right-0 bg-white border-t border-gray-200 p-4 z-30" role="navigation" aria-label="Ações dos resultados">
        <div className="flex items-center justify-between">
          {/* Results Count */}
          <div className="text-sm text-gray-600" role="status" aria-live="polite">
            {searchState.results.length > 0 && (
              <span aria-label={`${searchState.results.length} resultados de ${searchState.totalAvailable} disponíveis`}>
                {searchState.results.length} de {searchState.totalAvailable}
              </span>
            )}
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2" role="group" aria-label="Ações disponíveis">
            {searchState.results.length > 0 && (
              <>
                <button
                  onClick={handleExport}
                  className="px-4 py-2 text-sm bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 active:bg-gray-300 touch-target focus:outline-none focus:ring-2 focus:ring-blue-500"
                  disabled={searchState.results.length === 0}
                  aria-label={`Exportar ${searchState.results.length} resultados`}
                >
                  Exportar
                </button>
                <button
                  onClick={clearResults}
                  className="px-4 py-2 text-sm bg-red-100 text-red-700 rounded-lg hover:bg-red-200 active:bg-red-300 touch-target focus:outline-none focus:ring-2 focus:ring-red-500"
                  aria-label="Limpar todos os resultados da busca"
                >
                  Limpar
                </button>
              </>
            )}
          </div>
        </div>
      </nav>

      {/* Gesture Hints */}
      <div className="fixed bottom-20 left-4 right-4 pointer-events-none">
        {gesture && gesture.isSwipe && (
          <div className="bg-black bg-opacity-75 text-white text-center py-2 px-4 rounded-full text-sm">
            {Math.abs(gesture.deltaX) > Math.abs(gesture.deltaY) ? (
              gesture.deltaX > 0 ? '← Deslize para abrir filtros' : '→ Deslize para voltar'
            ) : (
              gesture.deltaY > 0 ? '↑ Deslize para ver histórico' : '↓ Deslize para fechar'
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default MobileSearchInterface;