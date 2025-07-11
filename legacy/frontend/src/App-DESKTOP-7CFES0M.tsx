import React, { Suspense, lazy } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LoadingSpinner } from './components/LoadingSpinner';
import { I18nProvider, useI18n } from './contexts/I18nContext';
import LanguageToggle from './components/LanguageToggle';

// Lazy load components
const Dashboard = lazy(() => import('./components/Dashboard'));
const LexMLSearchPage = lazy(() => import('./pages/LexMLSearchPage'));
const AdvancedSearchPage = lazy(() => import('./pages/AdvancedSearchPage'));
const AnalyticsPage = lazy(() => import('./pages/AnalyticsPage'));
const DocumentViewerPage = lazy(() => import('./pages/DocumentViewerPage').then(module => ({ default: module.DocumentViewerPage })));

const Navigation: React.FC = () => {
  const location = useLocation();
  const { t } = useI18n();
  
  const isActive = (path: string) => {
    if (path === '/' && location.pathname === '/') return true;
    if (path !== '/' && location.pathname.startsWith(path)) return true;
    return false;
  };

  return (
    <nav className="bg-white border-b border-gray-200 px-4 py-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link to="/" className="text-lg font-semibold text-gray-900 hover:text-blue-600">
            {t('dashboard.title')}
          </Link>
          <div className="flex gap-2">
            <Link
              to="/"
              className={`px-3 py-1 text-sm rounded ${
                isActive('/') && location.pathname === '/'
                  ? 'bg-blue-100 text-blue-700' 
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              {t('nav.dashboard')}
            </Link>
            <Link
              to="/search"
              className={`px-3 py-1 text-sm rounded ${
                isActive('/search')
                  ? 'bg-blue-100 text-blue-700' 
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              {t('nav.lexmlSearch')}
            </Link>
            <Link
              to="/advanced-search"
              className={`px-3 py-1 text-sm rounded ${
                isActive('/advanced-search')
                  ? 'bg-blue-100 text-blue-700' 
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              {t('nav.advancedSearch')}
            </Link>
            <Link
              to="/analytics"
              className={`px-3 py-1 text-sm rounded ${
                isActive('/analytics')
                  ? 'bg-blue-100 text-blue-700' 
                  : 'text-gray-600 hover:text-gray-900'
              }`}
            >
              {t('nav.analytics')}
            </Link>
          </div>
        </div>
        <LanguageToggle />
      </div>
    </nav>
  );
};

const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <I18nProvider>
        <Router>
          <div className="App">
            <Navigation />
            
            <Routes>
              <Route 
                path="/" 
                element={
                  <Suspense fallback={<LoadingSpinner message="Loading Dashboard..." />}>
                    <Dashboard />
                  </Suspense>
                } 
              />
              <Route 
                path="/search" 
                element={
                  <Suspense fallback={<LoadingSpinner message="Loading LexML Search..." />}>
                    <LexMLSearchPage />
                  </Suspense>
                } 
              />
              <Route 
                path="/advanced-search" 
                element={
                  <Suspense fallback={<LoadingSpinner message="Loading Advanced Search..." />}>
                    <AdvancedSearchPage />
                  </Suspense>
                } 
              />
              <Route 
                path="/analytics" 
                element={
                  <Suspense fallback={<LoadingSpinner message="Loading Analytics..." />}>
                    <AnalyticsPage />
                  </Suspense>
                } 
              />
              <Route 
                path="/document/:urn" 
                element={
                  <Suspense fallback={<LoadingSpinner message="Loading Document Viewer..." />}>
                    <DocumentViewerPage />
                  </Suspense>
                } 
              />
            </Routes>
          </div>
        </Router>
      </I18nProvider>
    </ErrorBoundary>
  );
};

export default App;