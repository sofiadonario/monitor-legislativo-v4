import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/globals.css'

// Cache bust timestamp: Force API integration v2.1
console.log('🚀 Monitor Legislativo v2.1 - API Integration Active', Date.now())

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('Root element not found')
}

const root = ReactDOM.createRoot(rootElement)

root.render(<App />)