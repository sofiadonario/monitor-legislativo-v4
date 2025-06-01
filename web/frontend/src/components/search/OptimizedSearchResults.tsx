/**
 * Optimized Search Results Component
 * Implements virtual scrolling, lazy loading, and performance optimizations
 */

import React, { useRef, useCallback, memo, useMemo } from 'react';
import { FixedSizeList as List } from 'react-window';
import AutoSizer from 'react-virtualized-auto-sizer';
import InfiniteLoader from 'react-window-infinite-loader';
import { useInView } from 'react-intersection-observer';
import { motion, AnimatePresence } from 'framer-motion';

import { SearchResult } from '../../types';
import { PerformanceProfiler } from '../../utils/performance';
import PropositionCard from './PropositionCard';
import SearchResultSkeleton from './SearchResultSkeleton';
import EmptyState from '../common/EmptyState';

interface OptimizedSearchResultsProps {
  results: SearchResult['results'];
  totalCount: number;
  isLoading: boolean;
  hasNextPage?: boolean;
  loadMore?: () => void;
  isLoadingMore?: boolean;
  enableVirtualization?: boolean;
  itemHeight?: number;
  overscan?: number;
}

// Memoized search result item
const SearchResultItem = memo(({ 
  data, 
  index, 
  style 
}: {
  data: SearchResult['results'];
  index: number;
  style: React.CSSProperties;
}) => {
  const item = data[index];
  
  if (!item) {
    return (
      <div style={style}>
        <SearchResultSkeleton />
      </div>
    );
  }

  return (
    <div style={style} className="px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: index * 0.05 }}
      >
        <PropositionCard proposition={item} />
      </motion.div>
    </div>
  );
}, (prevProps, nextProps) => {
  // Custom comparison for better performance
  return (
    prevProps.index === nextProps.index &&
    prevProps.data[prevProps.index]?.id === nextProps.data[nextProps.index]?.id
  );
});

SearchResultItem.displayName = 'SearchResultItem';

// Virtual scrolling implementation
const VirtualizedResults: React.FC<{
  results: SearchResult['results'];
  hasNextPage?: boolean;
  loadMore?: () => void;
  itemHeight: number;
  overscan: number;
}> = ({ results, hasNextPage, loadMore, itemHeight, overscan }) => {
  const itemCount = hasNextPage ? results.length + 1 : results.length;
  
  const isItemLoaded = useCallback(
    (index: number) => !hasNextPage || index < results.length,
    [hasNextPage, results.length]
  );

  const loadMoreItems = useCallback(
    () => {
      if (loadMore && hasNextPage) {
        return loadMore();
      }
      return Promise.resolve();
    },
    [loadMore, hasNextPage]
  );

  return (
    <AutoSizer>
      {({ height, width }) => (
        <InfiniteLoader
          isItemLoaded={isItemLoaded}
          itemCount={itemCount}
          loadMoreItems={loadMoreItems}
          threshold={5}
        >
          {({ onItemsRendered, ref }) => (
            <List
              ref={ref}
              height={height}
              width={width}
              itemCount={itemCount}
              itemSize={itemHeight}
              overscanCount={overscan}
              onItemsRendered={onItemsRendered}
              itemData={results}
            >
              {SearchResultItem}
            </List>
          )}
        </InfiniteLoader>
      )}
    </AutoSizer>
  );
};

// Standard scrolling with intersection observer
const StandardResults: React.FC<{
  results: SearchResult['results'];
  hasNextPage?: boolean;
  loadMore?: () => void;
  isLoadingMore?: boolean;
}> = ({ results, hasNextPage, loadMore, isLoadingMore }) => {
  const { ref: loadMoreRef, inView } = useInView({
    threshold: 0,
    rootMargin: '100px',
  });

  React.useEffect(() => {
    if (inView && hasNextPage && loadMore && !isLoadingMore) {
      loadMore();
    }
  }, [inView, hasNextPage, loadMore, isLoadingMore]);

  return (
    <div className="space-y-4">
      <AnimatePresence>
        {results.map((result, index) => (
          <motion.div
            key={result.id}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3, delay: index * 0.05 }}
          >
            <PropositionCard proposition={result} />
          </motion.div>
        ))}
      </AnimatePresence>
      
      {hasNextPage && (
        <div ref={loadMoreRef} className="py-4">
          {isLoadingMore && <SearchResultSkeleton count={3} />}
        </div>
      )}
    </div>
  );
};

// Main component
const OptimizedSearchResults: React.FC<OptimizedSearchResultsProps> = ({
  results,
  totalCount,
  isLoading,
  hasNextPage,
  loadMore,
  isLoadingMore,
  enableVirtualization = true,
  itemHeight = 150,
  overscan = 5,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);

  // Memoize results info
  const resultsInfo = useMemo(() => {
    if (totalCount === 0) return null;
    
    const showing = results.length;
    return (
      <div className="text-sm text-gray-600 dark:text-gray-400 mb-4">
        Mostrando {showing} de {totalCount} resultados
      </div>
    );
  }, [results.length, totalCount]);

  if (isLoading && results.length === 0) {
    return (
      <div className="space-y-4">
        <SearchResultSkeleton count={5} />
      </div>
    );
  }

  if (!isLoading && results.length === 0) {
    return (
      <EmptyState
        title="Nenhum resultado encontrado"
        description="Tente ajustar os filtros ou termos de busca"
        icon="search"
      />
    );
  }

  return (
    <PerformanceProfiler id="SearchResults">
      <div className="h-full flex flex-col">
        {resultsInfo}
        
        <div ref={containerRef} className="flex-1 min-h-0">
          {enableVirtualization && results.length > 20 ? (
            <VirtualizedResults
              results={results}
              hasNextPage={hasNextPage}
              loadMore={loadMore}
              itemHeight={itemHeight}
              overscan={overscan}
            />
          ) : (
            <StandardResults
              results={results}
              hasNextPage={hasNextPage}
              loadMore={loadMore}
              isLoadingMore={isLoadingMore}
            />
          )}
        </div>
      </div>
    </PerformanceProfiler>
  );
};

export default memo(OptimizedSearchResults);