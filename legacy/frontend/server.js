const express = require('express');
const path = require('path');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files from the React build
app.use(express.static(path.join(__dirname, 'dist')));

// Proxy API requests to backend
app.use('/api', createProxyMiddleware({
  target: 'https://backend-api-production-2392.up.railway.app',
  changeOrigin: true,
  logLevel: 'debug'
}));

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