# Monitor Legislativo v4 - API Documentation

## Overview

Monitor Legislativo integrates with 14 different Brazilian government data sources to track legislative proposals and regulatory consultations. This document provides detailed information on how each API works.

## API Categories

### 1. **Legislative APIs** (Direct REST APIs)
- Câmara dos Deputados
- Senado Federal  
- Planalto (Presidency)

### 2. **Regulatory Agencies** (Web Scraping)
- ANEEL, ANATEL, ANVISA, ANS, ANA, ANCINE, ANTT, ANTAQ, ANAC, ANP, ANM

---

## Legislative APIs

### 📌 **Câmara dos Deputados API**

**Type**: REST API  
**Base URL**: `https://dadosabertos.camara.leg.br/api/v2`  
**Authentication**: None required  
**Rate Limit**: Not officially documented, but implements retry logic

**How it works**:
1. **Search Endpoint**: `/proposicoes`
2. **Parameters**:
   - `dataInicio` / `dataFim`: Date range (YYYY-MM-DD)
   - `siglaTipo`: Proposition types (PL, PEC, PDC, etc.)
   - `ordenarPor`: Sort field (default: "id")
   - `ordem`: Sort order (ASC/DESC)
   - `itens`: Items per page (max 200)
   - `pagina`: Page number

3. **Search Process**:
   - Fetches propositions within date range
   - Applies local keyword filtering (API doesn't support text search)
   - Enriches each proposition with author details via `/proposicoes/{id}/autores`
   - Returns standardized Proposition objects

4. **Special Features**:
   - Automatic pagination (up to 10 pages)
   - Author enrichment for each proposition
   - Circuit breaker protection

**Example Response**:
```json
{
  "dados": [
    {
      "id": 2348123,
      "siglaTipo": "PL",
      "numero": 1234,
      "ano": 2024,
      "ementa": "Dispõe sobre...",
      "dataApresentacao": "2024-03-15T10:00:00"
    }
  ],
  "links": [...]
}
```

---

### 📌 **Senado Federal API**

**Type**: REST API  
**Base URL**: `https://legis.senado.leg.br/dadosabertos`  
**Authentication**: None required  
**Format**: XML (converted to JSON internally)

**How it works**:
1. **Search Endpoint**: `/materia/pesquisa/lista`
2. **Parameters**:
   - `palavraChave`: Keyword search
   - `dataInicio` / `dataFim`: Date range
   - `tipoMateria`: Matter types
   - `situacao`: Status filter
   - `nomeAutor`: Author name

3. **Search Process**:
   - Searches using keyword parameter
   - Parses XML response
   - Extracts matter details from nested XML structure
   - Converts to standardized format

4. **XML Structure**:
```xml
<PesquisaBasicaMateria>
  <Materias>
    <Materia>
      <CodigoMateria>123456</CodigoMateria>
      <SiglaTipo>PLS</SiglaTipo>
      <NumeroMateria>100</NumeroMateria>
      <AnoMateria>2024</AnoMateria>
      <Ementa>Texto da ementa...</Ementa>
    </Materia>
  </Materias>
</PesquisaBasicaMateria>
```

---

### 📌 **Planalto API**

**Type**: Web Scraping (JavaScript-rendered)  
**Base URL**: `http://www4.planalto.gov.br/legislacao`  
**Technology**: Playwright for browser automation

**How it works**:
1. **Search Process**:
   - Launches headless browser
   - Navigates to search page
   - Fills search form with query
   - Waits for JavaScript to render results
   - Extracts data from DOM

2. **Challenges**:
   - Requires full browser rendering
   - Slow response times (30+ seconds)
   - Complex DOM structure
   - Session-based navigation

3. **Fallback Strategy**:
   - Primary: Playwright automation
   - Secondary: Direct HTTP with BeautifulSoup
   - Circuit breaker after 3 failures

---

## Regulatory Agency APIs

All regulatory agencies use web scraping as they don't provide REST APIs. They share common patterns:

### 🏛️ **Common Architecture**

1. **Base Class**: `RegulatoryAgencyService`
   - Provides common scraping functionality
   - Document type detection
   - Proposition creation from HTML
   - Circuit breaker integration

2. **Search Strategy**:
   - Primary URL (usually gov.br portal)
   - Fallback URLs (agency's own domain)
   - Generic HTML parsing with configurable selectors
   - Adaptive parsing for different page structures

3. **Configuration** (in `api_endpoints.py`):
```python
REGULATORY_SCRAPERS = {
    "ANEEL": ScraperConfig(
        search_url="https://www.gov.br/aneel/pt-br/assuntos/consultas-publicas",
        selectors={
            "results_container": "#content-core",
            "result_item": ".tileItem",
            "title": "h2.tileHeadline",
            "link": "h2.tileHeadline a",
            "date": ".documentByLine",
            "summary": ".tileDescription"
        }
    )
}
```

---

### 📊 **Individual Agency Details**

#### ANEEL (Agência Nacional de Energia Elétrica)
- **URLs Tried**: 3 different endpoints
- **Selectors**: .tileItem, article, .consulta-item
- **Circuit Breaker**: 3 failures, 5-minute recovery

#### ANATEL (Agência Nacional de Telecomunicações)
- **Special Feature**: Table-based layout parsing
- **Fallback**: Generic div/article parsing
- **Challenge**: Multiple domain changes

#### ANVISA (Agência Nacional de Vigilância Sanitária)
- **Technology**: Requires Playwright (JavaScript-heavy)
- **Wait Strategy**: Explicit waits for dynamic content
- **Timeout**: 10 seconds for initial load

#### Other Agencies (ANS, ANA, ANCINE, ANTT, ANTAQ, ANAC, ANP, ANM)
- All use the generic `_generic_gov_br_search` method
- Fallback parsing strategies
- Circuit breaker protection
- 404 error handling with URL alternatives

---

## Error Handling & Resilience

### 1. **Circuit Breakers**
- Each service has independent circuit breaker
- States: CLOSED (normal) → OPEN (failing) → HALF_OPEN (testing)
- Configurable thresholds and recovery times

### 2. **Retry Logic**
- Exponential backoff (0.5, 1, 2, 4... seconds)
- Max 3 retries by default
- Different strategies for timeout vs. error responses

### 3. **Session Management**
- Centralized SessionFactory
- Connection pooling
- Automatic session recovery
- User-Agent rotation

### 4. **Caching**
- Smart cache with adaptive TTL
- Per-source cache statistics
- Automatic eviction policies
- Disk persistence for durability

---

## Performance Optimizations

1. **Parallel Execution**: Search all sources concurrently
2. **Connection Pooling**: Reuse HTTP connections
3. **Smart Caching**: Adaptive TTL based on access patterns
4. **Pagination Limits**: Max 10 pages to avoid overload
5. **Timeout Management**: 30-second default, 60-second for Playwright

---

## Common Issues & Solutions

### "Session is closed" Error
**Cause**: Services creating individual sessions instead of using SessionFactory  
**Solution**: All services now use `SessionFactory.get_session()`

### 404 Errors on Regulatory Sites
**Cause**: Government sites frequently change URLs  
**Solution**: Multiple fallback URLs with circuit breakers

### Slow Planalto Searches
**Cause**: JavaScript-heavy site requires full browser rendering  
**Solution**: Playwright with aggressive timeouts and circuit breakers

### SSL Certificate Warnings
**Cause**: Government sites often have certificate issues  
**Solution**: SSL verification disabled (security trade-off acknowledged)

---

## Usage Example

```python
from core.api.api_service import APIService

# Initialize service
api_service = APIService()

# Search all sources
results = await api_service.search_all(
    query="energia renovável",
    filters={"start_date": "2024-01-01", "end_date": "2024-12-31"},
    sources=["camara", "senado", "aneel"]
)

# Process results
for result in results:
    print(f"{result.source}: {result.total_count} propositions found")
    for prop in result.propositions:
        print(f"  - {prop.type} {prop.number}/{prop.year}: {prop.title}")
```

---

## Monitoring & Health Checks

Each API service provides health check capabilities:

```python
# Check individual service health
health = await service.check_health()

# Get API status with metrics
status = await api_service.get_api_status()
for api_status in status:
    print(f"{api_status.name}: {api_status.status} ({api_status.response_time}ms)")
```

---

This documentation reflects the actual implementation after cleanup and fixes. All services are designed to be resilient, with multiple fallback strategies and comprehensive error handling.