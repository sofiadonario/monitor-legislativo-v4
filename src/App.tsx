import React, { Suspense, lazy, useState } from 'react';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LoadingSpinner } from './components/LoadingSpinner';

// Lazy load components
const Dashboard = lazy(() => import('./components/Dashboard'));
const LexMLSearchPage = lazy(() => import('./pages/LexMLSearchPage'));
const KnowledgeGraphViewer = lazy(() => import('./components/KnowledgeGraphViewer'));
const ResearchWorkflow = lazy(() => import('./components/ResearchWorkflow'));
const VocabularyNavigator = lazy(() => import('./components/VocabularyNavigator'));
const AnalyticsPage = lazy(() => import('./pages/AnalyticsPage'));

type AppPage = 'dashboard' | 'search' | 'knowledge-graph' | 'research' | 'vocabulary' | 'analytics';

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
      case 'knowledge-graph':
        return (
          <Suspense fallback={<LoadingSpinner message="Loading Knowledge Graph..." />}>
            <div className="p-4">
              <KnowledgeGraphViewer />
            </div>
          </Suspense>
        );
      case 'research':
        return (
          <Suspense fallback={<LoadingSpinner message="Loading Research Workflow..." />}>
            <div className="p-4">
              <ResearchWorkflow />
            </div>
          </Suspense>
        );
      case 'vocabulary':
        return (
          <Suspense fallback={<LoadingSpinner message="Loading Vocabulary Navigator..." />}>
            <div className="p-4">
              <VocabularyNavigator />
            </div>
          </Suspense>
        );
      case 'analytics':
        return (
          <Suspense fallback={<LoadingSpinner message="Loading Analytics..." />}>
            <AnalyticsPage />
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
              <button
                onClick={() => setCurrentPage('research')}
                className={`px-3 py-1 text-sm rounded ${
                  currentPage === 'research' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Research Workflow
              </button>
              <button
                onClick={() => setCurrentPage('vocabulary')}
                className={`px-3 py-1 text-sm rounded ${
                  currentPage === 'vocabulary' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Vocabulary
              </button>
              <button
                onClick={() => setCurrentPage('knowledge-graph')}
                className={`px-3 py-1 text-sm rounded ${
                  currentPage === 'knowledge-graph' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Knowledge Graph
              </button>
              <button
                onClick={() => setCurrentPage('analytics')}
                className={`px-3 py-1 text-sm rounded ${
                  currentPage === 'analytics' 
                    ? 'bg-blue-100 text-blue-700' 
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Analytics
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