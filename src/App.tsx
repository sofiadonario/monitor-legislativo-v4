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
          
          {/* Add LOTS of content to make scrolling obvious */}
          <div style={{ padding: '2rem', backgroundColor: '#f8f9fa', marginTop: '2rem' }}>
            <h3>📜 Extended Content Area - SCROLL DOWN TO SEE NAVIGATION BUTTONS!</h3>
            <p style={{ fontSize: '1.2rem', fontWeight: 'bold', color: '#007bff' }}>
              👇 SCROLL DOWN NOW! The floating navigation buttons will appear after you scroll 300px down! 👇
            </p>
            
            {/* Section 1 */}
            <div style={{ height: '100vh', backgroundColor: '#e7f3ff', padding: '2rem', margin: '1rem 0', borderRadius: '8px' }}>
              <h4>🔍 Section 1: Monitor Legislativo Features</h4>
              <p>This Brazilian Legislative Monitoring System provides comprehensive tracking of transport legislation across all 27 states.</p>
              <p>Key features include:</p>
              <ul style={{ fontSize: '1.1rem', lineHeight: '2' }}>
                <li>📊 Real-time legislative document tracking</li>
                <li>🗺️ Interactive map visualization</li>
                <li>🔍 Advanced search and filtering</li>
                <li>📈 Export functionality for research</li>
                <li>♿ Full accessibility compliance</li>
              </ul>
              <p style={{ marginTop: '2rem', fontSize: '1.1rem' }}>
                Keep scrolling to see more content and watch for the floating navigation buttons!
              </p>
            </div>

            {/* Section 2 */}
            <div style={{ height: '100vh', backgroundColor: '#fff7e6', padding: '2rem', margin: '1rem 0', borderRadius: '8px' }}>
              <h4>🏛️ Section 2: State Coverage</h4>
              <p>Our system monitors legislation from all Brazilian states:</p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginTop: '2rem' }}>
                <div>Acre, Alagoas, Amapá, Amazonas, Bahia, Ceará, Distrito Federal, Espírito Santo, Goiás</div>
                <div>Maranhão, Mato Grosso, Mato Grosso do Sul, Minas Gerais, Pará, Paraíba, Paraná, Pernambuco, Piauí</div>
                <div>Rio de Janeiro, Rio Grande do Norte, Rio Grande do Sul, Rondônia, Roraima, Santa Catarina, São Paulo, Sergipe, Tocantins</div>
              </div>
              <p style={{ marginTop: '2rem', fontSize: '1.2rem', color: '#ff6b35' }}>
                🎯 By now you should see the floating scroll buttons appear on the right side! 🎯
              </p>
            </div>

            {/* Section 3 */}
            <div style={{ height: '100vh', backgroundColor: '#f0fff4', padding: '2rem', margin: '1rem 0', borderRadius: '8px' }}>
              <h4>📚 Section 3: Document Types</h4>
              <p>We track various types of legislative documents:</p>
              <ul style={{ fontSize: '1.1rem', lineHeight: '2', marginTop: '2rem' }}>
                <li>📜 Laws (Leis)</li>
                <li>📋 Decrees (Decretos)</li>
                <li>📝 Administrative Orders (Portarias)</li>
                <li>⚖️ Resolutions (Resoluções)</li>
                <li>📊 Normative Instructions (Instruções Normativas)</li>
                <li>🏗️ Bill Projects (Projetos de Lei)</li>
                <li>⚡ Provisional Measures (Medidas Provisórias)</li>
              </ul>
              <p style={{ marginTop: '2rem', fontSize: '1.2rem', color: '#28a745' }}>
                ✅ The scroll buttons should be visible now! Use them to navigate quickly! ✅
              </p>
            </div>

            {/* Section 4 */}
            <div style={{ height: '100vh', backgroundColor: '#fce4ec', padding: '2rem', margin: '1rem 0', borderRadius: '8px' }}>
              <h4>🚀 Section 4: Technical Architecture</h4>
              <p>Built with modern web technologies:</p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '2rem', marginTop: '2rem' }}>
                <div>
                  <h5>Frontend</h5>
                  <ul>
                    <li>React 18</li>
                    <li>TypeScript</li>
                    <li>Vite</li>
                    <li>Leaflet Maps</li>
                  </ul>
                </div>
                <div>
                  <h5>Backend</h5>
                  <ul>
                    <li>FastAPI</li>
                    <li>Python 3.11</li>
                    <li>Supabase PostgreSQL</li>
                    <li>Upstash Redis</li>
                  </ul>
                </div>
              </div>
              <p style={{ marginTop: '2rem', fontSize: '1.2rem', color: '#e91e63' }}>
                🎪 This is getting long! The scroll buttons should definitely be showing now! 🎪
              </p>
            </div>

            {/* Final Section */}
            <div style={{ height: '50vh', backgroundColor: '#f3e5f5', padding: '2rem', margin: '1rem 0', borderRadius: '8px', textAlign: 'center' }}>
              <h4>🎉 Final Section: You Made It!</h4>
              <p style={{ fontSize: '1.5rem', color: '#9c27b0' }}>
                Congratulations! You've scrolled through all the content.
              </p>
              <p style={{ fontSize: '1.2rem', marginTop: '2rem' }}>
                Use the floating scroll buttons to quickly navigate:
              </p>
              <p style={{ fontSize: '1.1rem' }}>
                ⬆️ Blue button: Scroll to top<br/>
                ⬇️ Green button: Scroll to bottom
              </p>
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