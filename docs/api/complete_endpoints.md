# Complete API Endpoints Documentation

## Overview
This document provides comprehensive documentation for all API endpoints in the Legislative Monitoring System.

## Base URL
- **Development**: `http://localhost:5000`
- **Production**: `https://api.legislativo.gov.br`

## Authentication
Most endpoints require JWT authentication. Include the token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

---

## System Endpoints

### Health Check
- **Endpoint**: `GET /api/health`
- **Authentication**: None required
- **Description**: Returns system health status and service availability
- **Response Example**:
```json
{
  "status": "healthy",
  "version": "4.0.0",
  "timestamp": "2025-01-30T15:30:00Z",
  "services": {
    "database": "connected",
    "redis": "connected",
    "camara_api": "available",
    "senado_api": "available",
    "planalto_api": "available"
  }
}
```

### System Metrics
- **Endpoint**: `GET /api/metrics`
- **Authentication**: Required (Admin only)
- **Description**: Returns system performance metrics
- **Response Example**:
```json
{
  "requests": {
    "total": 15420,
    "success_rate": 0.998,
    "average_response_time": 145.6
  },
  "cache": {
    "hit_rate": 0.856,
    "memory_usage": 2048576
  },
  "external_apis": {
    "camara": {"status": "healthy", "response_time": 234.5},
    "senado": {"status": "healthy", "response_time": 189.2}
  }
}
```

---

## Authentication Endpoints

### Login
- **Endpoint**: `POST /api/auth/login`
- **Authentication**: None required
- **Request Body**:
```json
{
  "username": "user@example.com",
  "password": "secure_password"
}
```
- **Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Refresh Token
- **Endpoint**: `POST /api/auth/refresh`
- **Authentication**: Refresh token required
- **Response**:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "expires_in": 3600
}
```

### Logout
- **Endpoint**: `POST /api/auth/logout`
- **Authentication**: Required
- **Response**: `204 No Content`

---

## Camara API Endpoints

### List Proposals
- **Endpoint**: `GET /api/camara/proposicoes`
- **Authentication**: None required (rate limited)
- **Parameters**:
  - `ano` (integer): Year (1988-2030)
  - `tipo` (string): Proposal type (PL, PEC, PDC, PLP, PLV)
  - `numero` (integer): Proposal number
  - `autor` (string): Author name (partial match)
  - `tema` (string): Theme/subject
  - `limit` (integer): Max results (1-100, default: 10)
  - `offset` (integer): Results offset (default: 0)
- **Response Example**:
```json
{
  "data": [
    {
      "id": 2390524,
      "siglaTipo": "PL",
      "numero": 1234,
      "ano": 2025,
      "ementa": "Estabelece diretrizes para a educação digital",
      "dataApresentacao": "2025-01-30T10:00:00Z",
      "statusProposicao": {
        "descricaoSituacao": "Aguardando Parecer",
        "descricaoTramitacao": "CEDU"
      },
      "autor": "Deputado Silva",
      "urlInteiroTeor": "https://www.camara.leg.br/..."
    }
  ],
  "pagination": {
    "total": 1523,
    "limit": 10,
    "offset": 0,
    "has_next": true,
    "has_prev": false
  }
}
```

### Get Proposal Details
- **Endpoint**: `GET /api/camara/proposicoes/{id}`
- **Authentication**: None required
- **Parameters**:
  - `id` (path, integer): Proposal ID
- **Response**: Detailed proposal information

### Get Proposal Authors
- **Endpoint**: `GET /api/camara/proposicoes/{id}/autores`
- **Authentication**: None required
- **Response**: List of proposal authors

### Get Proposal Tramitacao
- **Endpoint**: `GET /api/camara/proposicoes/{id}/tramitacoes`
- **Authentication**: None required
- **Response**: Proposal processing history

---

## Senado API Endpoints

### List Matters
- **Endpoint**: `GET /api/senado/materias`
- **Authentication**: None required (rate limited)
- **Parameters**:
  - `ano` (integer): Year
  - `tipo` (string): Matter type (PLS, PEC, PDC, PLP)
  - `numero` (integer): Matter number
  - `autor` (string): Author name
  - `limit` (integer): Max results (1-100, default: 10)
- **Response Example**:
```json
{
  "data": [
    {
      "codigo": 54321,
      "siglaSubtipo": "PLS",
      "numero": 4321,
      "ano": 2025,
      "descricaoObjetivo": "Dispõe sobre proteção de dados",
      "dataApresentacao": "30/01/2025",
      "situacaoAtual": {
        "descricaoSituacao": "Em tramitação na CCJ"
      },
      "autorPrincipal": {
        "nomeAutor": "Senador Santos"
      }
    }
  ],
  "pagination": {
    "total": 892,
    "limit": 10,
    "offset": 0,
    "has_next": true,
    "has_prev": false
  }
}
```

### Get Matter Details
- **Endpoint**: `GET /api/senado/materias/{codigo}`
- **Authentication**: None required
- **Response**: Detailed matter information

---

## Planalto API Endpoints

### List Norms
- **Endpoint**: `GET /api/planalto/normas`
- **Authentication**: None required (rate limited)
- **Parameters**:
  - `ano` (integer): Year
  - `tipo` (string): Norm type (LEI, DECRETO, PORTARIA)
  - `numero` (string): Norm number
  - `palavras_chave` (string): Keywords
  - `limit` (integer): Max results
- **Response Example**:
```json
{
  "data": [
    {
      "id": "lei-14567-2025",
      "tipo": "LEI",
      "numero": "14.567",
      "ano": 2025,
      "data": "2025-01-30",
      "ementa": "Marco legal da inteligência artificial",
      "situacao": "PUBLICADA",
      "url_texto": "https://www.planalto.gov.br/..."
    }
  ],
  "pagination": {
    "total": 245,
    "limit": 10,
    "offset": 0,
    "has_next": true,
    "has_prev": false
  }
}
```

---

## Regulatory Agencies Endpoints

### ANATEL Consultations
- **Endpoint**: `GET /api/anatel/consultas`
- **Authentication**: None required
- **Parameters**:
  - `status` (string): ABERTA, ENCERRADA, SUSPENSA
  - `area` (string): TELECOMUNICACOES, RADIODIFUSAO
  - `ano` (integer): Year
- **Response Example**:
```json
{
  "data": [
    {
      "id": "12345",
      "numero": "05/2025",
      "titulo": "Consulta sobre 5G em áreas rurais",
      "data_inicio": "2025-01-30",
      "data_fim": "2025-03-30",
      "status": "ABERTA",
      "area": "TELECOMUNICACOES"
    }
  ]
}
```

### ANEEL Consultations
- **Endpoint**: `GET /api/aneel/consultas`
- **Authentication**: None required
- **Response**: Similar structure to ANATEL

### ANVISA Consultations
- **Endpoint**: `GET /api/anvisa/consultas`
- **Authentication**: None required
- **Response**: Similar structure to other agencies

---

## Search Endpoints

### Unified Search
- **Endpoint**: `POST /api/search`
- **Authentication**: Required
- **Request Body**:
```json
{
  "keywords": "educação digital",
  "sources": ["camara", "senado", "planalto"],
  "types": ["PL", "PLS", "LEI"],
  "start_date": "2025-01-01",
  "end_date": "2025-12-31",
  "limit": 20,
  "offset": 0
}
```
- **Response Example**:
```json
{
  "results": [
    {
      "id": "camara_2390524",
      "source": "camara",
      "type": "PL",
      "title": "PL 1234/2025 - Educação Digital",
      "description": "Estabelece diretrizes para educação digital",
      "date": "2025-01-30T10:00:00Z",
      "url": "https://www.camara.leg.br/...",
      "score": 0.95
    }
  ],
  "pagination": {
    "total": 156,
    "limit": 20,
    "offset": 0,
    "has_next": true,
    "has_prev": false
  },
  "facets": {
    "sources": {"camara": 89, "senado": 45, "planalto": 22},
    "types": {"PL": 78, "PLS": 34, "LEI": 44},
    "years": {"2025": 156}
  }
}
```

### Search Suggestions
- **Endpoint**: `GET /api/search/suggestions`
- **Authentication**: Required
- **Parameters**:
  - `q` (string): Partial query
- **Response**:
```json
{
  "suggestions": [
    "educação digital",
    "educação básica",
    "educação infantil"
  ]
}
```

---

## Export Endpoints

### Create Export
- **Endpoint**: `POST /api/export`
- **Authentication**: Required
- **Request Body**:
```json
{
  "format": "csv",
  "data_source": "search_results",
  "filters": {
    "sources": ["camara", "senado"],
    "date_range": "2025-01-01,2025-12-31"
  }
}
```
- **Response**:
```json
{
  "job_id": "export_123456",
  "status": "queued",
  "estimated_completion": "2025-01-30T15:35:00Z"
}
```

### Get Export Status
- **Endpoint**: `GET /api/export/{job_id}`
- **Authentication**: Required
- **Response**:
```json
{
  "job_id": "export_123456",
  "status": "completed",
  "download_url": "https://api.legislativo.gov.br/downloads/export_123456.csv",
  "file_size": 2048576,
  "created_at": "2025-01-30T15:30:00Z",
  "completed_at": "2025-01-30T15:34:23Z"
}
```

### Download Export
- **Endpoint**: `GET /api/export/{job_id}/download`
- **Authentication**: Required
- **Response**: File download

---

## User Management Endpoints

### Get User Profile
- **Endpoint**: `GET /api/users/profile`
- **Authentication**: Required
- **Response**:
```json
{
  "id": 12345,
  "username": "user@example.com",
  "name": "João Silva",
  "role": "analyst",
  "created_at": "2024-12-01T10:00:00Z",
  "last_login": "2025-01-30T09:15:00Z",
  "preferences": {
    "default_sources": ["camara", "senado"],
    "notifications": true
  }
}
```

### Update User Profile
- **Endpoint**: `PUT /api/users/profile`
- **Authentication**: Required
- **Request Body**:
```json
{
  "name": "João Silva Santos",
  "preferences": {
    "default_sources": ["camara", "senado", "planalto"],
    "notifications": false
  }
}
```

### Get User Activity
- **Endpoint**: `GET /api/users/activity`
- **Authentication**: Required
- **Parameters**:
  - `limit` (integer): Max results
  - `days` (integer): Days back to look
- **Response**: List of user activities

---

## Admin Endpoints

### List Users (Admin only)
- **Endpoint**: `GET /api/admin/users`
- **Authentication**: Required (Admin role)
- **Response**: List of all users

### System Statistics
- **Endpoint**: `GET /api/admin/stats`
- **Authentication**: Required (Admin role)
- **Response**:
```json
{
  "users": {
    "total": 1245,
    "active_today": 89,
    "new_this_month": 34
  },
  "api_usage": {
    "requests_today": 15420,
    "most_used_endpoint": "/api/search",
    "error_rate": 0.002
  },
  "data": {
    "total_documents": 89654,
    "last_update": "2025-01-30T14:30:00Z"
  }
}
```

### Clear Cache
- **Endpoint**: `DELETE /api/admin/cache`
- **Authentication**: Required (Admin role)
- **Parameters**:
  - `pattern` (string, optional): Cache key pattern to clear
- **Response**: `204 No Content`

---

## Error Responses

All endpoints may return these error responses:

### 400 Bad Request
```json
{
  "error": "bad_request",
  "message": "Invalid parameter 'ano': must be between 1988 and 2030",
  "details": {
    "field": "ano",
    "value": "2050",
    "constraint": "range"
  },
  "timestamp": "2025-01-30T15:30:00Z"
}
```

### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "message": "Invalid or missing authentication token",
  "timestamp": "2025-01-30T15:30:00Z"
}
```

### 403 Forbidden
```json
{
  "error": "forbidden",
  "message": "Insufficient permissions for this resource",
  "timestamp": "2025-01-30T15:30:00Z"
}
```

### 404 Not Found
```json
{
  "error": "not_found",
  "message": "Resource not found",
  "timestamp": "2025-01-30T15:30:00Z"
}
```

### 429 Too Many Requests
```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded. Try again in 60 seconds",
  "retry_after": 60,
  "timestamp": "2025-01-30T15:30:00Z"
}
```

### 500 Internal Server Error
```json
{
  "error": "internal_server_error",
  "message": "An unexpected error occurred",
  "request_id": "req_123456789",
  "timestamp": "2025-01-30T15:30:00Z"
}
```

### 503 Service Unavailable
```json
{
  "error": "service_unavailable",
  "message": "External service temporarily unavailable",
  "service": "camara_api",
  "timestamp": "2025-01-30T15:30:00Z"
}
```

---

## Rate Limiting

### Limits by User Type
- **Unauthenticated**: 100 requests/hour, 10 requests/minute
- **Authenticated**: 1000 requests/hour, 100 requests/minute
- **API Key**: 5000 requests/hour, 500 requests/minute
- **Admin**: 10000 requests/hour, 1000 requests/minute

### Rate Limit Headers
All responses include rate limiting headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1643723400
```

---

## Pagination

All list endpoints support pagination:

### Query Parameters
- `limit`: Number of results per page (max 100)
- `offset`: Number of results to skip

### Response Format
```json
{
  "data": [...],
  "pagination": {
    "total": 1523,
    "limit": 10,
    "offset": 0,
    "has_next": true,
    "has_prev": false,
    "next_url": "?limit=10&offset=10",
    "prev_url": null
  }
}
```

---

## WebSocket Endpoints

### Real-time Updates
- **Endpoint**: `WS /api/ws/updates`
- **Authentication**: Required
- **Description**: Real-time notifications for new legislative data

### Example WebSocket Message
```json
{
  "type": "new_proposal",
  "data": {
    "source": "camara",
    "id": 2390525,
    "title": "PL 1235/2025",
    "summary": "Nova proposta sobre telemedicina"
  },
  "timestamp": "2025-01-30T15:30:00Z"
}
```