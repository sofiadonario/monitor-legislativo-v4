# Mackintegridade Integration Architecture
## Monitor Legislativo as Transport Research Vertical

**Project:** Mackintegridade - Energy - Transport  
**URL:** https://www.mackenzie.br/mackintegridade/energia/transporte  
**Parent Platform:** Mackintegridade Research Ecosystem  

---

## Integration Overview

### Hierarchical Structure
```
www.mackenzie.br
└── mackintegridade (Integrity Research Platform)
    ├── About Mackintegridade
    ├── Research Areas
    │   ├── energia (Energy Research)
    │   │   ├── Overview
    │   │   ├── transporte (Transport Legislation Monitor) ← Our Project
    │   │   ├── renovaveis (Renewable Energy)
    │   │   └── eficiencia (Energy Efficiency)
    │   ├── governanca (Governance)
    │   ├── transparencia (Transparency)
    │   └── sustentabilidade (Sustainability)
    └── Resources & Publications
```

### Technical Integration Points

#### 1. URL Routing Strategy
```nginx
# Nginx configuration for Mackintegridade
location /mackintegridade/energia/transporte {
    # Proxy to CloudFront distribution
    proxy_pass https://d123456789.cloudfront.net;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Original-URI $request_uri;
    
    # Preserve Mackintegridade context
    proxy_set_header X-Mackintegridade-Area "energia";
    proxy_set_header X-Mackintegridade-Project "transporte";
}
```

#### 2. Frontend Base Path Configuration
```typescript
// src/config/mackintegridade.ts
export const MACKINTEGRIDADE_CONFIG = {
  basePath: '/mackintegridade/energia/transporte',
  apiBasePath: '/mackintegridade/energia/transporte/api',
  parentPortal: 'https://www.mackenzie.br/mackintegridade',
  researchArea: 'energia',
  projectName: 'Monitor Legislativo de Transporte',
  
  // Navigation breadcrumbs
  breadcrumbs: [
    { label: 'Mackintegridade', href: '/mackintegridade' },
    { label: 'Energia', href: '/mackintegridade/energia' },
    { label: 'Transporte', href: '/mackintegridade/energia/transporte' }
  ],
  
  // Shared resources
  sharedAuth: '/mackintegridade/auth',
  sharedAnalytics: '/mackintegridade/analytics',
  dataRepository: '/mackintegridade/data'
};
```

#### 3. React Router Configuration
```typescript
// src/App.tsx
import { BrowserRouter } from 'react-router-dom';
import { MACKINTEGRIDADE_CONFIG } from './config/mackintegridade';

function App() {
  return (
    <BrowserRouter basename={MACKINTEGRIDADE_CONFIG.basePath}>
      <MackintegradeLayout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/search" element={<Search />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/export" element={<Export />} />
        </Routes>
      </MackintegradeLayout>
    </BrowserRouter>
  );
}
```

### Mackintegridade Shared Components

#### 1. Unified Header
```typescript
// components/MackintegrideHeader.tsx
export function MackintegrideHeader() {
  return (
    <header className="mackintegridade-header">
      <div className="mackintegridade-logo">
        <img src="/mackintegridade/assets/logo.svg" alt="Mackintegridade" />
      </div>
      <nav className="mackintegridade-nav">
        <a href="/mackintegridade">Home</a>
        <a href="/mackintegridade/energia" className="active">Energia</a>
        <a href="/mackintegridade/governanca">Governança</a>
        <a href="/mackintegridade/transparencia">Transparência</a>
      </nav>
      <div className="project-identifier">
        <span className="research-area">Energia</span>
        <span className="separator">›</span>
        <span className="project-name">Monitor de Transporte</span>
      </div>
    </header>
  );
}
```

#### 2. Cross-Project Data Sharing
```typescript
// services/mackintegrideDataService.ts
export class MackintegrideDataService {
  // Share transport data with other Mackintegridade projects
  async shareWithMackintegridade(data: TransportData) {
    return await fetch('/mackintegridade/api/data/share', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Project': 'energia/transporte',
        'X-Data-Type': 'legislative-transport'
      },
      body: JSON.stringify({
        source: 'monitor-legislativo',
        category: 'transport-legislation',
        data: data,
        metadata: {
          researchArea: 'energia',
          subProject: 'transporte',
          timestamp: new Date().toISOString()
        }
      })
    });
  }
  
  // Access data from other Mackintegridade projects
  async getMackintegradeData(filters: DataFilters) {
    return await fetch('/mackintegridade/api/data/query', {
      method: 'POST',
      body: JSON.stringify({
        projects: ['energia/*', 'governanca/compliance'],
        filters: filters,
        requester: 'energia/transporte'
      })
    });
  }
}
```

### Authentication Integration

#### SSO with Mackintegridade Portal
```typescript
// auth/mackintegradeAuth.ts
export class MackintegradeAuth {
  private static AUTH_ENDPOINT = '/mackintegridade/auth';
  
  async login() {
    // Redirect to Mackintegridade SSO
    window.location.href = `${this.AUTH_ENDPOINT}/login?redirect=${encodeURIComponent(window.location.pathname)}`;
  }
  
  async checkSession() {
    const response = await fetch(`${this.AUTH_ENDPOINT}/session`, {
      credentials: 'include'
    });
    
    if (response.ok) {
      const session = await response.json();
      return {
        isAuthenticated: true,
        user: session.user,
        permissions: session.permissions,
        researchAreas: session.researchAreas
      };
    }
    
    return { isAuthenticated: false };
  }
  
  async hasAccessToTransportData(): Promise<boolean> {
    const session = await this.checkSession();
    return session.isAuthenticated && 
           session.researchAreas?.includes('energia');
  }
}
```

### Visual Identity & Branding

#### Mackintegridade Design System
```scss
// styles/mackintegridade-theme.scss

// Mackintegridade Color Palette
$mackintegridade-primary: #003366;      // Deep Blue
$mackintegridade-secondary: #0066CC;    // Bright Blue
$energia-accent: #FF6B35;               // Energy Orange
$transporte-accent: #4ECDC4;            // Transport Teal

// Typography
$font-family-mackintegridade: 'Roboto', 'Arial', sans-serif;
$font-family-headings: 'Montserrat', sans-serif;

// Component Styling
.mackintegridade-container {
  font-family: $font-family-mackintegridade;
  
  // Energy research area styling
  &.energia {
    .section-header {
      border-left: 4px solid $energia-accent;
    }
    
    // Transport sub-project styling
    &.transporte {
      .accent-elements {
        color: $transporte-accent;
      }
      
      .data-visualization {
        .chart-primary-color {
          fill: $transporte-accent;
        }
      }
    }
  }
}

// Responsive breadcrumb for mobile
.mackintegridade-breadcrumb {
  @media (max-width: 768px) {
    .breadcrumb-item:not(:last-child) {
      display: none;
    }
    
    .breadcrumb-item:last-child::before {
      content: "← ";
    }
  }
}
```

### Analytics Integration

#### Unified Mackintegridade Analytics
```typescript
// analytics/mackintegradeAnalytics.ts
export class MackintegradeAnalytics {
  private static ANALYTICS_ENDPOINT = '/mackintegridade/analytics';
  
  // Track user interactions with transport monitor
  trackEvent(event: AnalyticsEvent) {
    return fetch(`${this.ANALYTICS_ENDPOINT}/events`, {
      method: 'POST',
      body: JSON.stringify({
        project: 'energia/transporte',
        event: event,
        context: {
          url: window.location.pathname,
          referrer: document.referrer,
          researchArea: 'energia',
          subProject: 'transporte'
        }
      })
    });
  }
  
  // Contribute to Mackintegridade research metrics
  async reportResearchMetrics(metrics: ResearchMetrics) {
    return fetch(`${this.ANALYTICS_ENDPOINT}/research-metrics`, {
      method: 'POST',
      body: JSON.stringify({
        project: 'energia/transporte',
        metrics: {
          documentsAnalyzed: metrics.documentsAnalyzed,
          searchQueries: metrics.searchQueries,
          exportCount: metrics.exportCount,
          userEngagement: metrics.userEngagement
        },
        period: metrics.period
      })
    });
  }
}
```

### Data Export & Repository Integration

#### Mackintegridade Research Repository
```typescript
// export/mackintegradeExport.ts
export class MackintegradeExport {
  // Export data to Mackintegridade research repository
  async exportToRepository(data: ExportData) {
    const exportPackage = {
      metadata: {
        project: 'Mackintegridade - Energia - Transporte',
        description: 'Legislative transport data from Monitor Legislativo',
        authors: data.authors,
        date: new Date().toISOString(),
        license: 'CC BY-SA 4.0',
        doi: null // Will be assigned by repository
      },
      data: {
        format: data.format,
        content: data.content,
        query: data.query,
        filters: data.filters
      },
      citations: {
        software: 'Monitor Legislativo v4. Mackintegridade - Energia - Transporte. Available at: https://www.mackenzie.br/mackintegridade/energia/transporte',
        data: `Legislative Transport Data. Retrieved from Monitor Legislativo via Mackintegridade. ${new Date().toLocaleDateString()}`
      }
    };
    
    return await fetch('/mackintegridade/repository/deposit', {
      method: 'POST',
      body: JSON.stringify(exportPackage)
    });
  }
}
```

### Deployment Configuration

#### CloudFront Path Pattern Rules
```yaml
# CloudFront Behaviors for Mackintegridade paths
Behaviors:
  - PathPattern: "/mackintegridade/energia/transporte/*"
    TargetOriginId: S3-TransportMonitor
    ViewerProtocolPolicy: redirect-to-https
    AllowedMethods: [GET, HEAD, OPTIONS]
    CachedMethods: [GET, HEAD]
    Compress: true
    
  - PathPattern: "/mackintegridade/energia/transporte/api/*"
    TargetOriginId: ALB-TransportAPI
    ViewerProtocolPolicy: redirect-to-https
    AllowedMethods: [GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE]
    CachePolicyId: 4135ea2d-6df8-44a3-9df3-4b5a84be39ad # Managed-CachingDisabled
    OriginRequestPolicyId: 88a5eaf4-2fd4-4709-b370-b4c650ea3fcf # Managed-CORS-S3Origin
```

#### S3 Static Website Configuration
```bash
# S3 bucket structure for Mackintegridade integration
s3://mackintegridade-platform/
├── energia/
│   └── transporte/
│       ├── index.html
│       ├── static/
│       │   ├── css/
│       │   ├── js/
│       │   └── media/
│       └── assets/
│           ├── icons/
│           └── images/
```

### API Gateway Integration

#### Path-Based Routing
```yaml
# API Gateway Routes for Mackintegridade
/mackintegridade/energia/transporte/api:
  /search:
    GET: 
      integration: 
        uri: http://alb.internal/api/v1/search
        requestParameters:
          integration.request.header.X-Project: "'energia/transporte'"
  
  /export:
    POST:
      integration:
        uri: http://alb.internal/api/v1/export
        requestParameters:
          integration.request.header.X-Mackintegridade-Context: method.request.header.X-Mackintegridade-Context
  
  /analytics:
    POST:
      integration:
        uri: http://mackintegridade-analytics.internal/collect
        requestParameters:
          integration.request.body.project: "'energia/transporte'"
```

### Benefits of Mackintegridade Integration

1. **Research Synergy**: Transport data enriches energy research ecosystem
2. **Unified Access**: Single sign-on across all Mackintegridade projects
3. **Data Interoperability**: Share insights with governance and transparency verticals
4. **Institutional Weight**: Part of major university integrity initiative
5. **Resource Sharing**: Leverage Mackintegridade infrastructure and tools
6. **Cross-Disciplinary Impact**: Enable multi-vertical research collaborations
7. **Standardized Metrics**: Contribute to unified research impact measurements

### Migration Checklist

- [ ] Configure base paths in React application
- [ ] Update API endpoints for /mackintegridade/energia/transporte prefix
- [ ] Integrate Mackintegridade header and navigation
- [ ] Implement SSO authentication flow
- [ ] Apply Mackintegridade design system
- [ ] Set up cross-project data sharing APIs
- [ ] Configure CloudFront path patterns
- [ ] Update S3 bucket structure
- [ ] Test full integration with parent portal
- [ ] Validate analytics data flow