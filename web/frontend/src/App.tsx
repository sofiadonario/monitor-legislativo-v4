/**
 * Optimized React Application
 * Performance-focused with code splitting, lazy loading, and memoization
 */

import React, { Suspense, lazy, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';
import { ErrorBoundary } from 'react-error-boundary';
import { Provider } from 'react-redux';
import { PersistGate } from 'redux-persist/integration/react';

import { store, persistor } from './store';
import { setupInterceptors } from './services/api';
import { PerformanceMonitor } from './utils/performance';
import { WebSocketProvider } from './contexts/WebSocketContext';
import { ThemeProvider } from './contexts/ThemeContext';

import LoadingSpinner from './components/common/LoadingSpinner';
import ErrorFallback from './components/common/ErrorFallback';
import Layout from './components/layout/Layout';

// Lazy load pages for code splitting
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Search = lazy(() => import('./pages/Search'));
const PropositionDetail = lazy(() => import('./pages/PropositionDetail'));
const Analytics = lazy(() => import('./pages/Analytics'));
const Settings = lazy(() => import('./pages/Settings'));
const NotFound = lazy(() => import('./pages/NotFound'));

// Configure React Query with performance optimizations
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      refetchOnWindowFocus: false,
      refetchOnReconnect: 'always',
      retry: 3,
      retryDelay: attemptIndex => Math.min(1000 * 2 ** attemptIndex, 30000),
    },
  },
});

function App() {
  useEffect(() => {
    // Setup API interceptors
    setupInterceptors();

    // Initialize performance monitoring
    PerformanceMonitor.init();

    // Report Web Vitals
    PerformanceMonitor.reportWebVitals();

    // Cleanup
    return () => {
      PerformanceMonitor.cleanup();
    };
  }, []);

  return (
    <ErrorBoundary FallbackComponent={ErrorFallback} onReset={() => window.location.reload()}>
      <Provider store={store}>
        <PersistGate loading={<LoadingSpinner fullScreen />} persistor={persistor}>
          <QueryClientProvider client={queryClient}>
            <ThemeProvider>
              <WebSocketProvider>
                <Router>
                  <Layout>
                    <Suspense fallback={<LoadingSpinner />}>
                      <Routes>
                        <Route path="/" element={<Dashboard />} />
                        <Route path="/search" element={<Search />} />
                        <Route path="/proposition/:id" element={<PropositionDetail />} />
                        <Route path="/analytics" element={<Analytics />} />
                        <Route path="/settings" element={<Settings />} />
                        <Route path="*" element={<NotFound />} />
                      </Routes>
                    </Suspense>
                  </Layout>
                </Router>
              </WebSocketProvider>
            </ThemeProvider>
            {process.env.NODE_ENV === 'development' && <ReactQueryDevtools />}
          </QueryClientProvider>
        </PersistGate>
      </Provider>
    </ErrorBoundary>
  );
}

export default App;