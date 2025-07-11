// Service Worker for Monitor Legislativo v4
// Implements offline-first caching strategy

const CACHE_NAME = 'legislativo-v1';
const API_CACHE = 'legislativo-api-v1';
const ASSET_CACHE = 'legislativo-assets-v1';

// Static assets to cache immediately
const STATIC_ASSETS = [
  '/monitor-legislativo-v4/',
  '/monitor-legislativo-v4/index.html',
  '/monitor-legislativo-v4/map-icon.svg'
];

// Cache strategies by route pattern
const CACHE_STRATEGIES = {
  // Network first, falling back to cache
  networkFirst: [
    '/api/v1/search',
    '/api/v1/proposals',
    '/api/v1/sources'
  ],
  // Cache first, falling back to network
  cacheFirst: [
    '/assets/',
    '/static/',
    '.js',
    '.css',
    '.woff2',
    '.png',
    '.jpg',
    '.svg'
  ],
  // Stale while revalidate
  staleWhileRevalidate: [
    '/api/v1/geography',
    '/api/v1/sources',
    '/api/v1/document-types'
  ]
};

// Install event - cache static assets
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames
          .filter(name => name.startsWith('legislativo-') && name !== CACHE_NAME)
          .map(name => caches.delete(name))
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - implement caching strategies
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);
  
  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }
  
  // Determine caching strategy
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(handleAPIRequest(request));
  } else if (isStaticAsset(url.pathname)) {
    event.respondWith(handleStaticAsset(request));
  }
});

// Handle API requests with network-first strategy
async function handleAPIRequest(request) {
  const cache = await caches.open(API_CACHE);
  
  try {
    // Try network first
    const response = await fetch(request, { 
      timeout: 5000,
      headers: {
        'X-Requested-With': 'ServiceWorker'
      }
    });
    
    // Cache successful responses
    if (response.ok) {
      // Clone response before caching
      const responseToCache = response.clone();
      cache.put(request, responseToCache);
      
      // Add cache headers
      const headers = new Headers(response.headers);
      headers.set('X-Cache', 'MISS');
      headers.set('X-Cache-Time', new Date().toISOString());
      
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: headers
      });
    }
    
    return response;
  } catch (error) {
    // Network failed, try cache
    const cachedResponse = await cache.match(request);
    
    if (cachedResponse) {
      // Add cache headers
      const headers = new Headers(cachedResponse.headers);
      headers.set('X-Cache', 'HIT');
      headers.set('X-Cache-Offline', 'true');
      
      return new Response(cachedResponse.body, {
        status: cachedResponse.status,
        statusText: cachedResponse.statusText,
        headers: headers
      });
    }
    
    // Return offline error response
    return new Response(JSON.stringify({
      error: 'Offline',
      message: 'Não foi possível conectar ao servidor',
      cached: false,
      timestamp: new Date().toISOString()
    }), {
      status: 503,
      headers: { 
        'Content-Type': 'application/json',
        'X-Cache': 'MISS',
        'X-Offline': 'true'
      }
    });
  }
}

// Handle static assets with cache-first strategy
async function handleStaticAsset(request) {
  const cache = await caches.open(ASSET_CACHE);
  
  // Try cache first
  const cachedResponse = await cache.match(request);
  
  if (cachedResponse) {
    // Update cache in background
    fetchAndCache(request, cache);
    
    // Return cached version immediately
    const headers = new Headers(cachedResponse.headers);
    headers.set('X-Cache', 'HIT');
    
    return new Response(cachedResponse.body, {
      status: cachedResponse.status,
      statusText: cachedResponse.statusText,
      headers: headers
    });
  }
  
  // Not in cache, fetch from network
  try {
    const response = await fetch(request);
    
    if (response.ok) {
      // Only cache valid URL schemes (skip chrome-extension://)
      if (request.url.startsWith('http://') || request.url.startsWith('https://')) {
        cache.put(request, response.clone());
      }
      
      const headers = new Headers(response.headers);
      headers.set('X-Cache', 'MISS');
      
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: headers
      });
    }
    
    return response;
  } catch (error) {
    // Return offline page for navigation requests
    if (request.mode === 'navigate') {
      const offlineResponse = await cache.match('/offline.html');
      if (offlineResponse) {
        return offlineResponse;
      }
    }
    
    return new Response('Offline', {
      status: 503,
      headers: { 'Content-Type': 'text/plain' }
    });
  }
}

// Helper function to check if URL is a static asset
function isStaticAsset(pathname) {
  const staticExtensions = ['.js', '.css', '.png', '.jpg', '.svg', '.woff2', '.woff', '.ttf'];
  return staticExtensions.some(ext => pathname.endsWith(ext)) ||
         pathname.startsWith('/assets/') ||
         pathname.startsWith('/static/');
}

// Background fetch and cache update
async function fetchAndCache(request, cache) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      cache.put(request, response);
    }
  } catch (error) {
    // Silently fail - we already returned cached version
    console.error('Background fetch failed:', error);
  }
}

// Handle stale-while-revalidate strategy
async function staleWhileRevalidate(request, cache) {
  const cachedResponse = await cache.match(request);
  
  const fetchPromise = fetch(request).then(response => {
    if (response.ok) {
      cache.put(request, response.clone());
    }
    return response;
  });
  
  return cachedResponse || fetchPromise;
}

// Message handling for cache management
self.addEventListener('message', event => {
  const { type, payload } = event.data;
  
  switch (type) {
    case 'SKIP_WAITING':
      self.skipWaiting();
      break;
      
    case 'CLEAR_CACHE':
      event.waitUntil(
        caches.keys().then(names => 
          Promise.all(names.map(name => caches.delete(name)))
        )
      );
      break;
      
    case 'CACHE_URLS':
      event.waitUntil(
        caches.open(API_CACHE).then(cache => 
          cache.addAll(payload.urls)
        )
      );
      break;
  }
});