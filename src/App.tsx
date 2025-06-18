import React, { useState } from 'react';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LoadingSpinner } from './components/LoadingSpinner';

const App: React.FC = () => {
  const [showSpinner, setShowSpinner] = useState(false);
  const [apiStatus, setApiStatus] = useState<string>('Not tested');
  const [isTestingApi, setIsTestingApi] = useState(false);

  const testBackendApi = async () => {
    setIsTestingApi(true);
    setApiStatus('Testing...');
    
    try {
      const response = await fetch('https://monitor-legislativo-v4-production.up.railway.app/health');
      const data = await response.json();
      setApiStatus(`✅ API Working! Status: ${data.status}`);
    } catch (error) {
      setApiStatus(`❌ API Error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsTestingApi(false);
    }
  };

  return (
    <ErrorBoundary>
      <div className="App">
        <header style={{
          padding: '2rem',
          textAlign: 'center',
          backgroundColor: '#f0f0f0',
          borderBottom: '1px solid #ddd'
        }}>
          <h1>Monitor Legislativo v4</h1>
          <p>Brazilian Legislative Monitoring System</p>
          <p>✅ Successfully deployed to GitHub Pages!</p>
          <p>🔗 Backend API: <a href="https://monitor-legislativo-v4-production.up.railway.app/health" target="_blank">Railway Health Check</a></p>
        </header>
        <main style={{ padding: '2rem', textAlign: 'center' }}>
          <h2>🎉 Deployment Successful!</h2>
          <p>Your full-stack application is now live:</p>
          <ul style={{ listStyle: 'none', padding: 0 }}>
            <li>✅ Frontend: GitHub Pages</li>
            <li>✅ Backend: Railway</li>
            <li>✅ Database: Supabase</li>
            <li>✅ Cache: Upstash Redis</li>
          </ul>
          <p><strong>Step 1: ErrorBoundary added ✅</strong></p>
          <p><strong>Step 2: LoadingSpinner added ✅</strong></p>
          <p><strong>Step 3: API connectivity test ✅</strong></p>
          
          <div style={{ margin: '2rem 0' }}>
            <button 
              onClick={() => setShowSpinner(!showSpinner)}
              style={{ 
                padding: '0.5rem 1rem', 
                margin: '0.5rem',
                backgroundColor: '#007bff',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              {showSpinner ? 'Hide' : 'Show'} Loading Spinner
            </button>
            
            <button 
              onClick={testBackendApi}
              disabled={isTestingApi}
              style={{ 
                padding: '0.5rem 1rem', 
                margin: '0.5rem',
                backgroundColor: isTestingApi ? '#6c757d' : '#28a745',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: isTestingApi ? 'not-allowed' : 'pointer'
              }}
            >
              {isTestingApi ? 'Testing...' : 'Test Railway API'}
            </button>
          </div>
          
          {showSpinner && <LoadingSpinner message="Testing spinner component..." />}
          
          <div style={{ 
            margin: '1rem 0', 
            padding: '1rem', 
            backgroundColor: '#f8f9fa', 
            borderRadius: '4px',
            border: '1px solid #dee2e6'
          }}>
            <strong>API Status:</strong> {apiStatus}
          </div>
          
          <p>Next: Adding Dashboard component with Suspense...</p>
        </main>
      </div>
    </ErrorBoundary>
  );
};

export default App;