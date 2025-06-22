import React, { Suspense, lazy, useState } from 'react';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LoadingSpinner } from './components/LoadingSpinner';

// Lazy load components
const Dashboard = lazy(() => import('./components/Dashboard'));
const LexMLSearchPage = lazy(() => import('./pages/LexMLSearchPage'));

type AppPage = 'dashboard' | 'search';

const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<AppPage>('dashboard');

  const renderCurrentPage = () => {
    switch (currentPage) {
      case 'search':
        return (
          <Suspense fallback={<LoadingSpinner message="Loading LexML Search..." />}>
            <LexMLSearchPage />
          </Suspense>
        );
      case 'dashboard':
      default:
        return (
          <Suspense fallback={<LoadingSpinner message="Loading Dashboard..." />}>
            <Dashboard />
          </Suspense>
        );
    }
  };

  return (
    <ErrorBoundary>
      <div className="App">
        {/* Simple Navigation */}
        <nav className="bg-white border-b border-gray-200 px-4 py-2">
          <div className="flex items-center gap-4">
            <h1 className="text-lg font-semibold text-gray-900">Monitor Legislativo v4</h1>
            <div className="flex gap-2">
              <button
                onClick={() => setCurrentPage('dashboard')}
                className={`px-3 py-1 text-sm rounded ${
                  currentPage === 'dashboard' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Dashboard
              </button>
              <button
                onClick={() => setCurrentPage('search')}
                className={`px-3 py-1 text-sm rounded ${
                  currentPage === 'search' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                LexML Search
              </button>
            </div>
          </div>
        </nav>
        
        {renderCurrentPage()}
      </div>
    </ErrorBoundary>
  );
};

export default App;