# GraphQL API Examples - Monitor Legislativo v4

**Developed by:** Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães  
**Organization:** MackIntegridade  
**Financing:** MackPesquisa

## Overview

The GraphQL API provides flexible querying capabilities for legislative data. Access the GraphQL playground at: `http://localhost:8000/api/v1/graphql`

## Query Examples

### 1. Search Propositions

```graphql
query SearchPropositions {
  searchPropositions(
    query: "saúde"
    sources: [CAMARA, SENADO]
    limit: 10
  ) {
    propositions {
      id
      source
      type
      number
      year
      title
      summary
      status
      author {
        name
        party
        state
      }
      createdAt
      keywords
    }
    stats {
      totalResults
      sourcesQueried
      queryTimeMs
      cacheHit
    }
  }
}
```

### 2. Get Specific Proposition

```graphql
query GetProposition {
  getProposition(id: "PL-1234-2025", source: CAMARA) {
    id
    title
    summary
    status
    author {
      name
      party
    }
    createdAt
    updatedAt
    url
  }
}
```

### 3. Get Analytics

```graphql
query GetAnalytics {
  getAnalytics {
    totalPropositions
    bySource
    byStatus
    trends {
      keyword
      count
      growthRate
      sources
    }
    lastUpdated
  }
}
```

### 4. Search with Filters

```graphql
query AdvancedSearch {
  searchPropositions(
    query: "educação"
    sources: [CAMARA]
    status: ACTIVE
    startDate: "2025-01-01T00:00:00Z"
    limit: 20
    offset: 0
  ) {
    propositions {
      id
      title
      status
      createdAt
    }
    stats {
      totalResults
    }
  }
}
```

### 5. Search Authors

```graphql
query SearchAuthors {
  searchAuthors(name: "Silva", limit: 10) {
    id
    name
    party
    state
  }
}
```

## Mutation Examples

### 1. Track Proposition

```graphql
mutation TrackProposition {
  trackProposition(
    propositionId: "PL-5678-2025"
    source: SENADO
  )
}
```

### 2. Export Search Results

```graphql
mutation ExportResults {
  exportSearchResults(
    query: "meio ambiente"
    format: "xlsx"
    email: "user@example.com"
  )
}
```

## Using Variables

```graphql
query SearchWithVariables($searchTerm: String!, $sources: [DataSourceType!]) {
  searchPropositions(query: $searchTerm, sources: $sources) {
    propositions {
      id
      title
      source
    }
    stats {
      totalResults
    }
  }
}
```

Variables:
```json
{
  "searchTerm": "reforma tributária",
  "sources": ["CAMARA", "SENADO"]
}
```

## Pagination

```graphql
query PaginatedSearch($offset: Int!, $limit: Int!) {
  searchPropositions(
    query: "economia"
    offset: $offset
    limit: $limit
  ) {
    propositions {
      id
      title
    }
    stats {
      totalResults
    }
  }
}
```

Variables:
```json
{
  "offset": 20,
  "limit": 10
}
```

## Error Handling

The GraphQL API returns structured errors:

```json
{
  "errors": [
    {
      "message": "Invalid source type",
      "extensions": {
        "code": "INVALID_ARGUMENT",
        "argument": "source"
      }
    }
  ]
}
```

## Rate Limiting

- Anonymous: 100 requests per hour
- Authenticated: 1000 requests per hour

## Authentication

Include JWT token in Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## Best Practices

1. **Request only needed fields** - GraphQL allows field selection
2. **Use fragments** for repeated field sets
3. **Implement pagination** for large result sets
4. **Cache queries** on the client side
5. **Use variables** instead of string interpolation

## Fragment Example

```graphql
fragment PropositionBasic on Proposition {
  id
  title
  source
  status
  createdAt
}

query SearchWithFragment {
  searchPropositions(query: "saúde") {
    propositions {
      ...PropositionBasic
      author {
        name
      }
    }
  }
}
```