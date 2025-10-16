# Monitor Legislativo - Modern Frontend Skeleton

Minimal React + TypeScript + Vite frontend for the R Plumber API.

## 🎯 Purpose

This is a **lightweight, modern alternative** to the existing `legacy/frontend`. It's specifically designed to integrate with the new R Plumber API endpoints and demonstrate clean architecture patterns.

## 📁 Structure

```
web/
├── src/
│   ├── api/
│   │   └── client.ts          ✅ API client with error handling
│   ├── types/
│   │   └── api.ts              ✅ TypeScript types for API responses
│   ├── queries/
│   │   ├── useSearch.ts        ✅ React Query hook for search
│   │   ├── useDocument.ts      ✅ React Query hook for documents
│   │   ├── useAggregations.ts  ✅ React Query hook for aggregations
│   │   └── useChoropleth.ts    ✅ React Query hook for maps
│   ├── components/
│   │   └── EmptyState.tsx      ✅ Loading, error, empty states
│   ├── pages/
│   │   ├── Search.tsx          📝 TO CREATE
│   │   └── Document.tsx        📝 TO CREATE
│   ├── App.tsx                 📝 TO CREATE
│   └── main.tsx                📝 TO CREATE
├── package.json                📝 TO CREATE
├── vite.config.ts              📝 TO CREATE
├── tsconfig.json               📝 TO CREATE
└── index.html                  📝 TO CREATE
```

## ✅ What's Already Built

### 1. API Client (`src/api/client.ts`)

```typescript
// Simple, type-safe API calls
const data = await api('/api/v1/search?q=mobilidade');

// With query parameters
const data = await apiWithParams('/api/v1/search', {
  q: 'transporte',
  scope: 'federal',
  page: 1
});
```

**Features:**
- Automatic error handling
- Type-safe responses
- Base URL configuration via `VITE_API_BASE`
- Network error detection

### 2. TypeScript Types (`src/types/api.ts`)

All API response types defined:
- `SearchResponse` & `SearchParams`
- `Document`
- `AggregationResponse` & `Aggregation Params`
- `ChoroplethResponse` & `ChoroplethParams`
- `ApiError`

### 3. React Query Hooks (`src/queries/`)

#### useSearch
```tsx
const { data, isLoading, error } = useSearch({
  q: 'mobilidade urbana',
  scope: 'federal',
  page: 1,
  page_size: 25
});
```

#### useDocument
```tsx
const { data: document, isLoading } = useDocument('doc-123');
```

#### useAggregations
```tsx
const { data } = useAggregations({ group_by: 'year' });
```

#### useChoropleth
```tsx
const { data } = useChoropleth({ metric: 'bills_per_100k', year: 2023 });
```

**Features:**
- Automatic caching (5-30 minutes based on data type)
- Automatic refetching on window focus
- Conditional fetching (enabled/disabled logic)
- TypeScript inference

### 4. Empty State Components (`src/components/EmptyState.tsx`)

```tsx
<LoadingState message="Carregando documentos..." />
<ErrorState error={error} onRetry={refetch} />
<NoResultsState query="mobilidade" />
<EmptyState title="Nenhum dado" description="..." />
```

## 📝 To Complete

### 1. Create `package.json`

```json
{
  "name": "monitor-legislativo-web",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^7.6.3",
    "@tanstack/react-query": "^5.0.0"
  },
  "devDependencies": {
    "@types/react": "^18.3.12",
    "@types/react-dom": "^18.3.1",
    "@vitejs/plugin-react": "^4.3.3",
    "typescript": "^5.7.2",
    "vite": "^6.3.5"
  }
}
```

### 2. Create `vite.config.ts`

```typescript
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'https://monitor-legislativo-unified-production.up.railway.app',
        changeOrigin: true,
      }
    }
  }
});
```

### 3. Create `src/pages/Search.tsx`

```tsx
import { useState } from 'react';
import { useSearch } from '../queries/useSearch';
import { LoadingState, ErrorState, NoResultsState } from '../components/EmptyState';

export function SearchPage() {
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');

  const { data, isLoading, error, refetch } = useSearch({
    q: debouncedQuery,
    page_size: 25
  });

  if (error) return <ErrorState error={error} onRetry={refetch} />;
  if (isLoading) return <LoadingState message="Buscando documentos..." />;
  if (!data || data.items.length === 0) return <NoResultsState query={debouncedQuery} />;

  return (
    <div>
      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Buscar legislação..."
      />

      <div>
        {data.items.map(item => (
          <div key={item.id}>
            <h3>{item.title}</h3>
            <p>{item.snippet}</p>
          </div>
        ))}
      </div>

      <div>
        Página {data.meta.page} de {Math.ceil(data.meta.total / data.meta.page_size)}
      </div>
    </div>
  );
}
```

### 4. Create `src/pages/Document.tsx`

```tsx
import { useParams } from 'react-router-dom';
import { useDocument } from '../queries/useDocument';
import { LoadingState, ErrorState } from '../components/EmptyState';

export function DocumentPage() {
  const { id } = useParams<{ id: string }>();
  const { data: document, isLoading, error, refetch } = useDocument(id);

  if (error) return <ErrorState error={error} onRetry={refetch} />;
  if (isLoading) return <LoadingState />;
  if (!document) return <div>Documento não encontrado</div>;

  return (
    <article>
      <header>
        <h1>{document.title}</h1>
        <div>
          <span>{document.jurisdiction}</span>
          <span>{document.status}</span>
          <span>{document.dates.presented}</span>
        </div>
      </header>

      {document.summary && (
        <section>
          <h2>Resumo</h2>
          <p>{document.summary}</p>
        </section>
      )}

      <section>
        <h2>Texto Completo</h2>
        <div>{document.full_text}</div>
      </section>
    </article>
  );
}
```

### 5. Create `src/App.tsx`

```tsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { SearchPage } from './pages/Search';
import { DocumentPage } from './pages/Document';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<SearchPage />} />
          <Route path="/document/:id" element={<DocumentPage />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
```

### 6. Create `src/main.tsx`

```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { App } from './App';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
```

### 7. Create `index.html`

```html
<!DOCTYPE html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Monitor Legislativo</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

## 🚀 Getting Started

```bash
# Navigate to web directory
cd web

# Install dependencies
npm install

# Set API base URL (optional, defaults to proxy)
echo "VITE_API_BASE=https://monitor-legislativo-unified-production.up.railway.app" > .env

# Start development server
npm run dev

# Build for production
npm run build
```

## 🎨 Styling Options

The skeleton uses inline styles for simplicity. You can add:

1. **Tailwind CSS** - `npm install -D tailwindcss postcss autoprefixer`
2. **CSS Modules** - Already supported by Vite
3. **Styled Components** - `npm install styled-components`
4. **Plain CSS** - Import in components

## 🔗 API Integration

### Environment Variables

Create `.env` in the `web/` directory:

```env
VITE_API_BASE=https://monitor-legislativo-unified-production.up.railway.app
```

### Development Proxy

The Vite config proxies `/api/*` requests to avoid CORS issues during development.

## 📊 Features Demonstrated

✅ **Type-safe API calls** with TypeScript
✅ **React Query** for data fetching & caching
✅ **Error handling** with user-friendly messages
✅ **Loading states** with spinners
✅ **Empty states** for no results
✅ **Pagination** support in search
✅ **Conditional fetching** (only when enabled)
✅ **Automatic refetching** on stale data

## 🎯 Next Steps

1. **Complete the remaining files** (pages, App.tsx, main.tsx)
2. **Add styling** (Tailwind, CSS Modules, or plain CSS)
3. **Add more pages** (Aggregations, Maps, etc.)
4. **Add charts** for visualizations (Recharts, Chart.js)
5. **Add authentication** if needed
6. **Deploy** to Vercel, Netlify, or Railway

## 📚 Comparison with Legacy Frontend

| Feature | Legacy Frontend | Modern Skeleton |
|---------|----------------|-----------------|
| **Size** | ~100+ components | Minimal (4 core files) |
| **Focus** | Full-featured app | API integration demo |
| **Dependencies** | 50+ packages | ~5 core packages |
| **API** | Custom/older patterns | R Plumber API |
| **State Management** | Complex | React Query only |
| **Purpose** | Production app | Clean starting point |

## 🤝 When to Use Each

**Use Legacy Frontend (`legacy/frontend/`):**
- Need full-featured application NOW
- Want advanced visualizations
- Need all existing components

**Use Modern Skeleton (`web/`):**
- Starting fresh project
- Learning the API
- Building custom UI
- Need minimal dependencies
- Want clean architecture

## 📖 Documentation

- **API Documentation**: `../RAILWAY_API_ENDPOINTS.md`
- **API Types**: `src/types/api.ts`
- **React Query**: https://tanstack.com/query
- **Vite**: https://vitejs.dev

## 🐛 Troubleshooting

### CORS Errors
Add proxy in `vite.config.ts` or use `VITE_API_BASE` with full URL.

### TypeScript Errors
Run `npm run type-check` to see all type errors.

### API Errors
Check `RAILWAY_API_ENDPOINTS.md` for correct endpoint format.

---

**Created:** 2025-01-16
**API Version:** R Plumber 1.0.0
**React Version:** 18.3.1
**Vite Version:** 6.3.5
