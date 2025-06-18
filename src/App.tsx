import React, { useState, Suspense, lazy } from 'react';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LoadingSpinner } from './components/LoadingSpinner';

// Lazy load SIMPLE Dashboard component (safe version)
const SimpleDashboard = lazy(() => import('./components/SimpleDashboard'));

const App: React.FC = () => {
  const [showSpinner, setShowSpinner] = useState(false);
  const [apiStatus, setApiStatus] = useState<string>('Not tested');
  const [isTestingApi, setIsTestingApi] = useState(false);
  const [showDashboard, setShowDashboard] = useState(false);
  const [showScrollButton, setShowScrollButton] = useState(false);

  // Handle scroll visibility
  React.useEffect(() => {
    const handleScroll = () => {
      setShowScrollButton(window.scrollY > 300);
    };
    
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const scrollToBottom = () => {
    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
  };

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
          <p><strong>Step 4: Suspense + Lazy Loading ✅</strong></p>
          
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

            <button 
              onClick={() => setShowDashboard(!showDashboard)}
              style={{ 
                padding: '0.5rem 1rem', 
                margin: '0.5rem',
                backgroundColor: '#6f42c1',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              {showDashboard ? 'Hide' : 'Show'} Dashboard
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
          
          {showDashboard && (
            <div style={{ 
              margin: '2rem 0', 
              padding: '1rem', 
              border: '2px solid #6f42c1',
              borderRadius: '8px',
              backgroundColor: '#f8f9ff'
            }}>
              <h3>🚀 Step 5: Simple Dashboard with Suspense</h3>
              <Suspense fallback={<LoadingSpinner message="Loading Dashboard component..." />}>
                <SimpleDashboard />
              </Suspense>
            </div>
          )}
          
          <p><strong>✅ REBUILD COMPLETE!</strong> All components working!</p>
          
          {/* Add some content to make scrolling useful */}
          <div style={{ height: '100vh', padding: '2rem', backgroundColor: '#f8f9fa', marginTop: '2rem' }}>
            <h3>📜 Extended Content Area</h3>
            <p>This is additional content to demonstrate the scroll functionality.</p>
            <p>Scroll down to see the floating scroll buttons appear!</p>
            <div style={{ height: '80vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <div style={{ textAlign: 'center', fontSize: '1.2rem', color: '#6c757d' }}>
                <p>🚀 Your app is fully functional!</p>
                <p>Frontend ↔️ Backend communication working</p>
                <p>Scroll buttons will appear when you scroll down</p>
              </div>
            </div>
          </div>
        </main>
      </div>

      {/* Floating Scroll Buttons */}
      {showScrollButton && (
        <div style={{
          position: 'fixed',
          right: '20px',
          bottom: '20px',
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
          zIndex: 1000
        }}>
          <button
            onClick={scrollToTop}
            style={{
              width: '50px',
              height: '50px',
              borderRadius: '50%',
              border: 'none',
              backgroundColor: '#007bff',
              color: 'white',
              fontSize: '20px',
              cursor: 'pointer',
              boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
              transition: 'all 0.3s ease',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.backgroundColor = '#0056b3';
              e.currentTarget.style.transform = 'scale(1.1)';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.backgroundColor = '#007bff';
              e.currentTarget.style.transform = 'scale(1)';
            }}
            title="Scroll to top"
          >
            ⬆️
          </button>
          
          <button
            onClick={scrollToBottom}
            style={{
              width: '50px',
              height: '50px',
              borderRadius: '50%',
              border: 'none',
              backgroundColor: '#28a745',
              color: 'white',
              fontSize: '20px',
              cursor: 'pointer',
              boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
              transition: 'all 0.3s ease',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.backgroundColor = '#1e7e34';
              e.currentTarget.style.transform = 'scale(1.1)';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.backgroundColor = '#28a745';
              e.currentTarget.style.transform = 'scale(1)';
            }}
            title="Scroll to bottom"
          >
            ⬇️
          </button>
        </div>
      )}
    </ErrorBoundary>
  );
};

export default App;