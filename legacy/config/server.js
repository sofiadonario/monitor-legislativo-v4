const express = require('express');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files from the React build
app.use(express.static(path.join(__dirname, 'dist')));

// Proxy API requests to backend
if (process.env.BACKEND_URL) {
  app.use('/api', createProxyMiddleware({
    target: process.env.BACKEND_URL || 'http://backend-api:8000',
    changeOrigin: true,
    logLevel: 'debug'
  }));
}

// Health check
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

// Handle React routing, return all requests to React app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Frontend server running on port ${PORT}`);
});