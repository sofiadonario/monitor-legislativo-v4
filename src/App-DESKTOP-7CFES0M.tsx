import React, { Suspense, lazy } from 'react';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LoadingSpinner } from './components/LoadingSpinner';

// Lazy load Dashboard component
const Dashboard = lazy(() => import('./components/Dashboard'));

const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <div className="App">
        <Suspense fallback={<LoadingSpinner message="Loading Dashboard..." />}>
          <Dashboard />
        </Suspense>
      </div>
    </ErrorBoundary>
  );
};

export default App;