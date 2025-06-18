import React from 'react';
import { ErrorBoundary } from './components/ErrorBoundary';

const App: React.FC = () => {
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
          <p>Next: Adding components gradually...</p>
        </main>
      </div>
    </ErrorBoundary>
  );
};

export default App;