"""
Elasticsearch Integration Service
Advanced search capabilities with full-text search, faceting, and analytics
"""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import hashlib
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import NotFoundError, ElasticsearchException
import time

logger = logging.getLogger(__name__)

@dataclass
class SearchRequest:
    """Search request parameters"""
    query: str
    filters: Dict[str, Any] = None
    facets: List[str] = None
    sort_by: str = "_score"
    sort_order: str = "desc"
    page: int = 1
    page_size: int = 25
    highlight: bool = True
    fuzzy: bool = True
    
@dataclass
class SearchResponse:
    """Search response with results and metadata"""
    results: List[Dict[str, Any]]
    total_count: int
    page: int
    page_size: int
    facets: Dict[str, List[Dict[str, Any]]]
    took_ms: int
    query: str
    
class ElasticsearchService:
    """Main Elasticsearch service for advanced search"""
    
    def __init__(self, hosts: List[str] = None, index_name: str = "propositions"):
        self.hosts = hosts or ["http://localhost:9200"]
        self.index_name = index_name
        self.client = None
        self._connect()
        
    def _connect(self):
        """Connect to Elasticsearch cluster"""
        try:
            self.client = Elasticsearch(
                self.hosts,
                verify_certs=True,
                request_timeout=30,
                retry_on_timeout=True,
                max_retries=3
            )
            
            # Test connection
            if not self.client.ping():
                raise ConnectionError("Failed to connect to Elasticsearch")
                
            logger.info(f"Connected to Elasticsearch cluster: {self.client.info()['cluster_name']}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            self.client = None
    
    def create_index(self):
        """Create optimized index with Brazilian Portuguese analyzer"""
        
        if not self.client:
            logger.error("Elasticsearch client not connected")
            return False
            
        # Index settings with Brazilian Portuguese support
        settings = {
            "settings": {
                "number_of_shards": 2,
                "number_of_replicas": 1,
                "index": {
                    "max_result_window": 50000,
                    "analysis": {
                        "filter": {
                            "brazilian_stop": {
                                "type": "stop",
                                "stopwords": "_brazilian_"
                            },
                            "brazilian_stemmer": {
                                "type": "stemmer",
                                "language": "brazilian"
                            },
                            "brazilian_synonym": {
                                "type": "synonym",
                                "synonyms": [
                                    "pl,projeto lei,projeto de lei",
                                    "mp,medida provisoria,medida provisória",
                                    "pec,emenda constitucional,proposta emenda constituição",
                                    "deputado,parlamentar",
                                    "senador,parlamentar",
                                    "camara,câmara,camara dos deputados",
                                    "senado,senado federal"
                                ]
                            }
                        },
                        "analyzer": {
                            "brazilian_analyzer": {
                                "tokenizer": "standard",
                                "filter": [
                                    "lowercase",
                                    "brazilian_stop",
                                    "brazilian_synonym",
                                    "brazilian_stemmer"
                                ]
                            },
                            "edge_ngram_analyzer": {
                                "tokenizer": "edge_ngram_tokenizer",
                                "filter": ["lowercase"]
                            },
                            "keyword_lowercase": {
                                "tokenizer": "keyword",
                                "filter": ["lowercase"]
                            }
                        },
                        "tokenizer": {
                            "edge_ngram_tokenizer": {
                                "type": "edge_ngram",
                                "min_gram": 2,
                                "max_gram": 15,
                                "token_chars": ["letter", "digit"]
                            }
                        }
                    }
                }
            },
            "mappings": {
                "properties": {
                    # Core fields
                    "id": {"type": "keyword"},
                    "type": {
                        "type": "keyword",
                        "fields": {
                            "text": {"type": "text", "analyzer": "brazilian_analyzer"}
                        }
                    },
                    "number": {"type": "keyword"},
                    "year": {"type": "integer"},
                    "title": {
                        "type": "text",
                        "analyzer": "brazilian_analyzer",
                        "fields": {
                            "keyword": {"type": "keyword"},
                            "suggest": {"type": "text", "analyzer": "edge_ngram_analyzer"}
                        }
                    },
                    "summary": {
                        "type": "text",
                        "analyzer": "brazilian_analyzer"
                    },
                    "full_text": {
                        "type": "text",
                        "analyzer": "brazilian_analyzer",
                        "term_vector": "with_positions_offsets"
                    },
                    
                    # Status and metadata
                    "status": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "url": {"type": "keyword"},
                    "full_text_url": {"type": "keyword"},
                    
                    # Dates
                    "publication_date": {"type": "date"},
                    "last_update": {"type": "date"},
                    "indexed_at": {"type": "date"},
                    
                    # Authors (nested for complex queries)
                    "authors": {
                        "type": "nested",
                        "properties": {
                            "name": {
                                "type": "text",
                                "analyzer": "brazilian_analyzer",
                                "fields": {
                                    "keyword": {"type": "keyword"},
                                    "suggest": {"type": "text", "analyzer": "edge_ngram_analyzer"}
                                }
                            },
                            "type": {"type": "keyword"},
                            "party": {"type": "keyword"},
                            "state": {"type": "keyword"}
                        }
                    },
                    
                    # Keywords and topics
                    "keywords": {
                        "type": "keyword",
                        "fields": {
                            "text": {"type": "text", "analyzer": "brazilian_analyzer"}
                        }
                    },
                    "topics": {"type": "keyword"},
                    
                    # Scoring and analytics
                    "popularity_score": {"type": "integer"},
                    "relevance_score": {"type": "float"},
                    "view_count": {"type": "long"},
                    "click_count": {"type": "long"},
                    
                    # Additional data
                    "attachments": {"type": "object", "enabled": False},
                    "extra_data": {"type": "object", "enabled": False},
                    
                    # Search optimization
                    "search_vector": {
                        "type": "text",
                        "analyzer": "brazilian_analyzer"
                    },
                    "suggest": {
                        "type": "completion",
                        "analyzer": "keyword_lowercase",
                        "search_analyzer": "keyword_lowercase"
                    }
                }
            }
        }
        
        try:
            # Delete existing index if needed
            if self.client.indices.exists(index=self.index_name):
                self.client.indices.delete(index=self.index_name)
                
            # Create new index
            self.client.indices.create(index=self.index_name, body=settings)
            logger.info(f"Created Elasticsearch index: {self.index_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create index: {e}")
            return False
    
    def index_proposition(self, proposition: Dict[str, Any]) -> bool:
        """Index a single proposition"""
        
        if not self.client:
            return False
            
        try:
            # Prepare document for indexing
            doc = self._prepare_document(proposition)
            
            # Index document
            response = self.client.index(
                index=self.index_name,
                id=proposition['id'],
                body=doc,
                refresh='wait_for'
            )
            
            return response['result'] in ['created', 'updated']
            
        except Exception as e:
            logger.error(f"Failed to index proposition {proposition.get('id')}: {e}")
            return False
    
    def bulk_index_propositions(self, propositions: List[Dict[str, Any]], 
                              batch_size: int = 500) -> Tuple[int, int]:
        """Bulk index multiple propositions"""
        
        if not self.client:
            return 0, len(propositions)
            
        success_count = 0
        failed_count = 0
        
        # Process in batches
        for i in range(0, len(propositions), batch_size):
            batch = propositions[i:i + batch_size]
            
            # Prepare bulk actions
            actions = []
            for prop in batch:
                doc = self._prepare_document(prop)
                actions.append({
                    "_index": self.index_name,
                    "_id": prop['id'],
                    "_source": doc
                })
            
            try:
                # Bulk index
                success, errors = helpers.bulk(
                    self.client,
                    actions,
                    raise_on_error=False,
                    raise_on_exception=False
                )
                
                success_count += success
                failed_count += len(errors) if isinstance(errors, list) else 0
                
                logger.info(f"Indexed batch {i//batch_size + 1}: "
                          f"{success} successful, {len(errors) if isinstance(errors, list) else 0} failed")
                
            except Exception as e:
                logger.error(f"Bulk indexing failed for batch {i//batch_size + 1}: {e}")
                failed_count += len(batch)
        
        return success_count, failed_count
    
    def search(self, request: SearchRequest) -> SearchResponse:
        """Perform advanced search with faceting and highlighting"""
        
        if not self.client:
            return SearchResponse(
                results=[],
                total_count=0,
                page=request.page,
                page_size=request.page_size,
                facets={},
                took_ms=0,
                query=request.query
            )
        
        start_time = time.time()
        
        # Build Elasticsearch query
        es_query = self._build_query(request)
        
        # Calculate pagination
        from_index = (request.page - 1) * request.page_size
        
        # Execute search
        try:
            response = self.client.search(
                index=self.index_name,
                body=es_query,
                from_=from_index,
                size=request.page_size
            )
            
            # Process results
            results = self._process_search_results(response, request)
            
            # Extract facets
            facets = self._process_facets(response.get('aggregations', {}))
            
            took_ms = int((time.time() - start_time) * 1000)
            
            return SearchResponse(
                results=results,
                total_count=response['hits']['total']['value'],
                page=request.page,
                page_size=request.page_size,
                facets=facets,
                took_ms=took_ms,
                query=request.query
            )
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return SearchResponse(
                results=[],
                total_count=0,
                page=request.page,
                page_size=request.page_size,
                facets={},
                took_ms=int((time.time() - start_time) * 1000),
                query=request.query
            )
    
    def _prepare_document(self, proposition: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare proposition document for indexing"""
        
        # Create search vector combining multiple fields
        search_parts = [
            proposition.get('title', ''),
            proposition.get('summary', ''),
            proposition.get('type', ''),
            ' '.join(proposition.get('keywords', []))
        ]
        
        # Add author names to search vector
        if proposition.get('authors'):
            for author in proposition['authors']:
                search_parts.append(author.get('name', ''))
        
        search_vector = ' '.join(filter(None, search_parts))
        
        # Prepare suggest field for autocomplete
        suggest_inputs = [proposition.get('title', '')]
        if proposition.get('number'):
            suggest_inputs.append(f"{proposition.get('type', '')} {proposition['number']}/{proposition.get('year', '')}")
        
        doc = {
            'id': proposition['id'],
            'type': proposition.get('type'),
            'number': proposition.get('number'),
            'year': proposition.get('year'),
            'title': proposition.get('title'),
            'summary': proposition.get('summary'),
            'full_text': proposition.get('full_text'),
            'status': proposition.get('status'),
            'source': proposition.get('source'),
            'url': proposition.get('url'),
            'full_text_url': proposition.get('full_text_url'),
            'publication_date': proposition.get('publication_date'),
            'last_update': proposition.get('last_update'),
            'indexed_at': datetime.utcnow().isoformat(),
            'authors': proposition.get('authors', []),
            'keywords': proposition.get('keywords', []),
            'topics': proposition.get('topics', []),
            'popularity_score': proposition.get('popularity_score', 0),
            'relevance_score': proposition.get('relevance_score', 1.0),
            'view_count': proposition.get('view_count', 0),
            'click_count': proposition.get('click_count', 0),
            'attachments': proposition.get('attachments'),
            'extra_data': proposition.get('extra_data'),
            'search_vector': search_vector,
            'suggest': {
                'input': suggest_inputs,
                'weight': proposition.get('popularity_score', 1)
            }
        }
        
        return doc
    
    def _build_query(self, request: SearchRequest) -> Dict[str, Any]:
        """Build Elasticsearch query from search request"""
        
        # Base query structure
        query = {
            "query": {
                "bool": {
                    "must": [],
                    "filter": [],
                    "should": []
                }
            },
            "aggs": {},
            "highlight": {},
            "sort": []
        }
        
        # Main search query
        if request.query:
            if request.fuzzy:
                # Multi-match with fuzzy matching
                query["query"]["bool"]["must"].append({
                    "multi_match": {
                        "query": request.query,
                        "fields": [
                            "title^3",
                            "title.suggest^2",
                            "summary^2",
                            "full_text",
                            "search_vector",
                            "authors.name^2",
                            "keywords.text"
                        ],
                        "type": "best_fields",
                        "fuzziness": "AUTO",
                        "prefix_length": 2,
                        "max_expansions": 50
                    }
                })
            else:
                # Exact phrase matching
                query["query"]["bool"]["must"].append({
                    "multi_match": {
                        "query": request.query,
                        "fields": ["title^3", "summary^2", "full_text"],
                        "type": "phrase"
                    }
                })
        
        # Apply filters
        if request.filters:
            for field, value in request.filters.items():
                if value is not None:
                    if field == 'date_range':
                        # Date range filter
                        date_filter = {"range": {"publication_date": {}}}
                        if value.get('from'):
                            date_filter["range"]["publication_date"]["gte"] = value['from']
                        if value.get('to'):
                            date_filter["range"]["publication_date"]["lte"] = value['to']
                        query["query"]["bool"]["filter"].append(date_filter)
                    
                    elif field == 'authors':
                        # Nested author query
                        query["query"]["bool"]["filter"].append({
                            "nested": {
                                "path": "authors",
                                "query": {
                                    "bool": {
                                        "must": [
                                            {"match": {"authors.name": value}}
                                        ]
                                    }
                                }
                            }
                        })
                    
                    elif isinstance(value, list):
                        # Multi-value filter
                        query["query"]["bool"]["filter"].append({
                            "terms": {field: value}
                        })
                    else:
                        # Single value filter
                        query["query"]["bool"]["filter"].append({
                            "term": {field: value}
                        })
        
        # Add facets/aggregations
        if request.facets:
            for facet in request.facets:
                if facet == 'type':
                    query["aggs"]["type_facet"] = {
                        "terms": {
                            "field": "type",
                            "size": 20
                        }
                    }
                elif facet == 'status':
                    query["aggs"]["status_facet"] = {
                        "terms": {
                            "field": "status",
                            "size": 10
                        }
                    }
                elif facet == 'year':
                    query["aggs"]["year_facet"] = {
                        "terms": {
                            "field": "year",
                            "size": 30,
                            "order": {"_key": "desc"}
                        }
                    }
                elif facet == 'source':
                    query["aggs"]["source_facet"] = {
                        "terms": {
                            "field": "source",
                            "size": 20
                        }
                    }
                elif facet == 'authors':
                    query["aggs"]["authors_facet"] = {
                        "nested": {
                            "path": "authors"
                        },
                        "aggs": {
                            "top_authors": {
                                "terms": {
                                    "field": "authors.name.keyword",
                                    "size": 50
                                }
                            }
                        }
                    }
                elif facet == 'keywords':
                    query["aggs"]["keywords_facet"] = {
                        "terms": {
                            "field": "keywords",
                            "size": 50
                        }
                    }
                elif facet == 'date_histogram':
                    query["aggs"]["date_histogram"] = {
                        "date_histogram": {
                            "field": "publication_date",
                            "calendar_interval": "month",
                            "min_doc_count": 1
                        }
                    }
        
        # Add highlighting
        if request.highlight:
            query["highlight"] = {
                "fields": {
                    "title": {
                        "fragment_size": 200,
                        "number_of_fragments": 1
                    },
                    "summary": {
                        "fragment_size": 300,
                        "number_of_fragments": 2
                    },
                    "full_text": {
                        "fragment_size": 150,
                        "number_of_fragments": 3
                    }
                },
                "pre_tags": ["<mark>"],
                "post_tags": ["</mark>"]
            }
        
        # Add sorting
        if request.sort_by == "_score":
            # Default relevance sorting
            query["sort"] = ["_score", {"publication_date": "desc"}]
        elif request.sort_by == "date":
            query["sort"] = [
                {"publication_date": {"order": request.sort_order}},
                "_score"
            ]
        elif request.sort_by == "popularity":
            query["sort"] = [
                {"popularity_score": {"order": request.sort_order}},
                "_score"
            ]
        else:
            query["sort"] = [{request.sort_by: {"order": request.sort_order}}]
        
        return query
    
    def _process_search_results(self, response: Dict[str, Any], 
                               request: SearchRequest) -> List[Dict[str, Any]]:
        """Process Elasticsearch response into results"""
        
        results = []
        
        for hit in response['hits']['hits']:
            result = hit['_source'].copy()
            result['_score'] = hit['_score']
            
            # Add highlights if available
            if request.highlight and 'highlight' in hit:
                result['highlights'] = hit['highlight']
            
            results.append(result)
        
        return results
    
    def _process_facets(self, aggregations: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """Process aggregations into facets"""
        
        facets = {}
        
        for agg_name, agg_data in aggregations.items():
            if 'buckets' in agg_data:
                facet_name = agg_name.replace('_facet', '')
                facets[facet_name] = [
                    {
                        'value': bucket['key'],
                        'count': bucket['doc_count']
                    }
                    for bucket in agg_data['buckets']
                ]
            elif 'top_authors' in agg_data:
                # Nested aggregation
                facets['authors'] = [
                    {
                        'value': bucket['key'],
                        'count': bucket['doc_count']
                    }
                    for bucket in agg_data['top_authors']['buckets']
                ]
        
        return facets
    
    def suggest(self, prefix: str, size: int = 10) -> List[str]:
        """Get autocomplete suggestions"""
        
        if not self.client:
            return []
            
        try:
            response = self.client.search(
                index=self.index_name,
                body={
                    "suggest": {
                        "proposition_suggest": {
                            "prefix": prefix,
                            "completion": {
                                "field": "suggest",
                                "size": size,
                                "skip_duplicates": True
                            }
                        }
                    }
                }
            )
            
            suggestions = []
            for option in response['suggest']['proposition_suggest'][0]['options']:
                suggestions.append(option['text'])
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Suggest failed: {e}")
            return []
    
    def more_like_this(self, proposition_id: str, size: int = 10) -> List[Dict[str, Any]]:
        """Find similar propositions"""
        
        if not self.client:
            return []
            
        try:
            response = self.client.search(
                index=self.index_name,
                body={
                    "query": {
                        "more_like_this": {
                            "fields": ["title", "summary", "keywords.text"],
                            "like": [
                                {
                                    "_index": self.index_name,
                                    "_id": proposition_id
                                }
                            ],
                            "min_term_freq": 2,
                            "max_query_terms": 25
                        }
                    },
                    "size": size
                }
            )
            
            return self._process_search_results(response, SearchRequest(query=""))
            
        except Exception as e:
            logger.error(f"More like this failed: {e}")
            return []
    
    def get_analytics(self) -> Dict[str, Any]:
        """Get search analytics from Elasticsearch"""
        
        if not self.client:
            return {}
            
        try:
            # Get index stats
            stats = self.client.indices.stats(index=self.index_name)
            
            # Get document count by type
            type_counts = self.client.search(
                index=self.index_name,
                body={
                    "size": 0,
                    "aggs": {
                        "types": {
                            "terms": {
                                "field": "type",
                                "size": 50
                            }
                        }
                    }
                }
            )
            
            # Get date range
            date_range = self.client.search(
                index=self.index_name,
                body={
                    "size": 0,
                    "aggs": {
                        "date_range": {
                            "stats": {
                                "field": "publication_date"
                            }
                        }
                    }
                }
            )
            
            return {
                'total_documents': stats['indices'][self.index_name]['primaries']['docs']['count'],
                'index_size_mb': stats['indices'][self.index_name]['primaries']['store']['size_in_bytes'] / 1024 / 1024,
                'types': [
                    {'type': bucket['key'], 'count': bucket['doc_count']}
                    for bucket in type_counts['aggregations']['types']['buckets']
                ],
                'date_range': {
                    'min': date_range['aggregations']['date_range']['min_as_string'],
                    'max': date_range['aggregations']['date_range']['max_as_string']
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get analytics: {e}")
            return {}
    
    def health_check(self) -> Dict[str, Any]:
        """Check Elasticsearch cluster health"""
        
        if not self.client:
            return {
                'status': 'disconnected',
                'available': False
            }
            
        try:
            # Get cluster health
            health = self.client.cluster.health()
            
            # Get index health
            index_health = self.client.cat.indices(index=self.index_name, format='json')
            
            return {
                'status': health['status'],
                'available': True,
                'cluster_name': health['cluster_name'],
                'number_of_nodes': health['number_of_nodes'],
                'active_shards': health['active_shards'],
                'index_health': index_health[0] if index_health else None
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'status': 'error',
                'available': False,
                'error': str(e)
            }
    
    def optimize_index(self):
        """Optimize index for better performance"""
        
        if not self.client:
            return
            
        try:
            # Force merge to optimize index
            self.client.indices.forcemerge(
                index=self.index_name,
                max_num_segments=1
            )
            
            # Clear cache
            self.client.indices.clear_cache(index=self.index_name)
            
            # Refresh index
            self.client.indices.refresh(index=self.index_name)
            
            logger.info(f"Optimized index: {self.index_name}")
            
        except Exception as e:
            logger.error(f"Index optimization failed: {e}")

# Global Elasticsearch service instance
_es_service: Optional[ElasticsearchService] = None

def get_elasticsearch_service() -> ElasticsearchService:
    """Get global Elasticsearch service instance"""
    global _es_service
    if _es_service is None:
        _es_service = ElasticsearchService()
    return _es_service

def init_elasticsearch_service(hosts: List[str] = None, 
                             index_name: str = "propositions") -> ElasticsearchService:
    """Initialize global Elasticsearch service"""
    global _es_service
    _es_service = ElasticsearchService(hosts, index_name)
    return _es_service