"""Advanced search functionality with filters, facets, and intelligent ranking."""

import re
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, date, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import logging

from core.utils.input_validator import InputValidator
from core.models.models import Document, DocumentType
from core.utils.cache_manager import CacheManager, CacheKey


@dataclass
class SearchFilter:
    """Search filter configuration."""
    field: str
    operator: str  # 'eq', 'in', 'range', 'contains', 'starts_with'
    value: Any
    exclude: bool = False


@dataclass
class SearchFacet:
    """Search facet for aggregations."""
    field: str
    name: str
    values: List[Dict[str, Any]]  # [{'value': 'LEI', 'count': 15}]


@dataclass
class SearchResult:
    """Enhanced search result with scoring and metadata."""
    document: Dict[str, Any]
    score: float
    highlights: List[str]
    matched_fields: List[str]
    relevance_factors: Dict[str, float]


@dataclass
class SearchResponse:
    """Complete search response with results and metadata."""
    results: List[SearchResult]
    total_count: int
    page: int
    per_page: int
    query_time_ms: float
    facets: List[SearchFacet]
    suggestions: List[str]
    filters_applied: List[SearchFilter]


class AdvancedSearchEngine:
    """Advanced search engine with filtering, faceting, and intelligent ranking."""
    
    def __init__(self):
        self.validator = InputValidator()
        self.cache_manager = CacheManager()
        self.logger = logging.getLogger(__name__)
        
        # Search configuration
        self.min_score_threshold = 0.1
        self.max_results_per_page = 100
        self.default_per_page = 20
        
        # Field weights for scoring
        self.field_weights = {
            'title': 3.0,
            'content': 1.0,
            'keywords': 2.0,
            'summary': 1.5,
            'metadata.description': 1.2
        }
        
        # Boost factors
        self.recency_boost_days = 365  # Boost documents from last year
        self.importance_boost = {
            'alta': 1.5,
            'media': 1.2,
            'baixa': 1.0
        }
    
    def search(self, 
               query: str,
               filters: Optional[List[SearchFilter]] = None,
               facets: Optional[List[str]] = None,
               page: int = 1,
               per_page: int = 20,
               sort_by: str = 'relevance',
               sort_order: str = 'desc') -> SearchResponse:
        """
        Execute advanced search with filters and facets.
        
        Args:
            query: Search query string
            filters: List of search filters to apply
            facets: List of fields to generate facets for
            page: Page number (1-based)
            per_page: Results per page
            sort_by: Sort field ('relevance', 'date', 'title')
            sort_order: Sort order ('asc', 'desc')
        
        Returns:
            SearchResponse with results and metadata
        """
        start_time = datetime.now()
        
        # Validate inputs
        query = self._validate_and_clean_query(query)
        filters = filters or []
        facets = facets or ['source', 'document_type', 'published_year']
        per_page = min(per_page, self.max_results_per_page)
        
        # Check cache
        cache_key = self._generate_cache_key(query, filters, facets, page, per_page, sort_by, sort_order)
        cached_result = self.cache_manager.get(cache_key)
        if cached_result:
            return SearchResponse(**cached_result)
        
        # Execute search
        try:
            # Get base results
            candidate_documents = self._get_candidate_documents(query, filters)
            
            # Score and rank results
            scored_results = self._score_and_rank_results(query, candidate_documents, sort_by, sort_order)
            
            # Apply pagination
            total_count = len(scored_results)
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            page_results = scored_results[start_idx:end_idx]
            
            # Generate facets
            facet_results = self._generate_facets(candidate_documents, facets)
            
            # Generate suggestions
            suggestions = self._generate_suggestions(query, total_count)
            
            # Calculate query time
            query_time_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            # Create response
            response = SearchResponse(
                results=page_results,
                total_count=total_count,
                page=page,
                per_page=per_page,
                query_time_ms=query_time_ms,
                facets=facet_results,
                suggestions=suggestions,
                filters_applied=filters
            )
            
            # Cache result
            self.cache_manager.set(cache_key, asdict(response), ttl=300)  # 5 minutes
            
            return response
            
        except Exception as e:
            self.logger.error(f"Search error: {e}")
            return SearchResponse(
                results=[],
                total_count=0,
                page=page,
                per_page=per_page,
                query_time_ms=(datetime.now() - start_time).total_seconds() * 1000,
                facets=[],
                suggestions=[],
                filters_applied=filters
            )
    
    def _validate_and_clean_query(self, query: str) -> str:
        """Validate and clean search query."""
        if not query or not query.strip():
            raise ValueError("Search query cannot be empty")
        
        # Sanitize query
        query = self.validator.sanitize_search_query(query)
        
        # Limit query length
        if len(query) > 500:
            query = query[:500]
        
        return query.strip()
    
    def _generate_cache_key(self, query: str, filters: List[SearchFilter], 
                           facets: List[str], page: int, per_page: int,
                           sort_by: str, sort_order: str) -> CacheKey:
        """Generate cache key for search request."""
        filter_str = str(sorted([(f.field, f.operator, str(f.value), f.exclude) for f in filters]))
        facet_str = str(sorted(facets))
        
        params = {
            'query': query,
            'filters': filter_str,
            'facets': facet_str,
            'page': page,
            'per_page': per_page,
            'sort_by': sort_by,
            'sort_order': sort_order
        }
        
        return CacheKey('search', 'advanced', params)
    
    def _get_candidate_documents(self, query: str, filters: List[SearchFilter]) -> List[Dict[str, Any]]:
        """Get candidate documents based on query and filters."""
        # This would typically query a database or search index
        # For now, we'll simulate with mock data
        
        # Mock document data - in reality this would come from database/index
        mock_documents = [
            {
                'id': 1,
                'title': 'Lei Geral de Proteção de Dados Pessoais',
                'content': 'Esta lei dispõe sobre o tratamento de dados pessoais...',
                'source': 'Planalto',
                'document_type': 'LEI',
                'published_date': '2018-08-14',
                'keywords': ['dados', 'privacidade', 'proteção'],
                'metadata': {'importance': 'alta', 'status': 'ativo'},
                'url': 'http://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm'
            },
            {
                'id': 2,
                'title': 'Decreto sobre Governo Digital',
                'content': 'Decreto que institui a Estratégia de Governo Digital...',
                'source': 'Planalto',
                'document_type': 'DECRETO',
                'published_date': '2020-03-15',
                'keywords': ['digital', 'governo', 'tecnologia'],
                'metadata': {'importance': 'media', 'status': 'ativo'},
                'url': 'http://www.planalto.gov.br/ccivil_03/_ato2019-2022/2020/decreto/d10332.htm'
            }
        ]
        
        # Apply text matching
        query_terms = query.lower().split()
        candidates = []
        
        for doc in mock_documents:
            # Check if document matches query
            if self._document_matches_query(doc, query_terms):
                # Apply filters
                if self._document_matches_filters(doc, filters):
                    candidates.append(doc)
        
        return candidates
    
    def _document_matches_query(self, document: Dict[str, Any], query_terms: List[str]) -> bool:
        """Check if document matches search query."""
        # Combine searchable text
        searchable_text = ' '.join([
            document.get('title', ''),
            document.get('content', ''),
            ' '.join(document.get('keywords', [])),
            document.get('metadata', {}).get('description', '')
        ]).lower()
        
        # Check if any query term matches
        for term in query_terms:
            if term in searchable_text:
                return True
        
        return False
    
    def _document_matches_filters(self, document: Dict[str, Any], filters: List[SearchFilter]) -> bool:
        """Check if document matches all filters."""
        for filter_obj in filters:
            if not self._apply_filter(document, filter_obj):
                return False
        return True
    
    def _apply_filter(self, document: Dict[str, Any], filter_obj: SearchFilter) -> bool:
        """Apply a single filter to document."""
        field_value = self._get_field_value(document, filter_obj.field)
        
        if field_value is None:
            return filter_obj.exclude  # Exclude if field doesn't exist
        
        match = False
        
        if filter_obj.operator == 'eq':
            match = field_value == filter_obj.value
        elif filter_obj.operator == 'in':
            match = field_value in filter_obj.value
        elif filter_obj.operator == 'contains':
            match = str(filter_obj.value).lower() in str(field_value).lower()
        elif filter_obj.operator == 'starts_with':
            match = str(field_value).lower().startswith(str(filter_obj.value).lower())
        elif filter_obj.operator == 'range':
            if len(filter_obj.value) == 2:
                min_val, max_val = filter_obj.value
                match = min_val <= field_value <= max_val
        
        return not match if filter_obj.exclude else match
    
    def _get_field_value(self, document: Dict[str, Any], field: str) -> Any:
        """Get field value from document, supporting nested fields."""
        if '.' in field:
            # Handle nested fields like 'metadata.importance'
            parts = field.split('.')
            value = document
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return None
            return value
        else:
            return document.get(field)
    
    def _score_and_rank_results(self, query: str, documents: List[Dict[str, Any]],
                               sort_by: str, sort_order: str) -> List[SearchResult]:
        """Score and rank search results."""
        query_terms = query.lower().split()
        scored_results = []
        
        for doc in documents:
            if sort_by == 'relevance':
                score = self._calculate_relevance_score(doc, query_terms)
            else:
                score = 1.0  # Default score for non-relevance sorting
            
            # Generate highlights
            highlights = self._generate_highlights(doc, query_terms)
            
            # Find matched fields
            matched_fields = self._find_matched_fields(doc, query_terms)
            
            # Calculate relevance factors
            relevance_factors = self._calculate_relevance_factors(doc, query_terms)
            
            result = SearchResult(
                document=doc,
                score=score,
                highlights=highlights,
                matched_fields=matched_fields,
                relevance_factors=relevance_factors
            )
            
            if score >= self.min_score_threshold:
                scored_results.append(result)
        
        # Sort results
        if sort_by == 'relevance':
            scored_results.sort(key=lambda x: x.score, reverse=(sort_order == 'desc'))
        elif sort_by == 'date':
            scored_results.sort(
                key=lambda x: x.document.get('published_date', ''),
                reverse=(sort_order == 'desc')
            )
        elif sort_by == 'title':
            scored_results.sort(
                key=lambda x: x.document.get('title', ''),
                reverse=(sort_order == 'desc')
            )
        
        return scored_results
    
    def _calculate_relevance_score(self, document: Dict[str, Any], query_terms: List[str]) -> float:
        """Calculate relevance score for document."""
        total_score = 0.0
        
        # Text matching scores
        for field, weight in self.field_weights.items():
            field_value = str(self._get_field_value(document, field) or '').lower()
            field_score = self._calculate_text_score(field_value, query_terms)
            total_score += field_score * weight
        
        # Recency boost
        recency_boost = self._calculate_recency_boost(document)
        total_score *= recency_boost
        
        # Importance boost
        importance = document.get('metadata', {}).get('importance', 'baixa')
        importance_boost = self.importance_boost.get(importance, 1.0)
        total_score *= importance_boost
        
        # Document type boost
        doc_type = document.get('document_type', '')
        type_boost = self._get_document_type_boost(doc_type)
        total_score *= type_boost
        
        return min(total_score, 10.0)  # Cap at 10.0
    
    def _calculate_text_score(self, text: str, query_terms: List[str]) -> float:
        """Calculate text matching score."""
        if not text or not query_terms:
            return 0.0
        
        score = 0.0
        text_words = text.split()
        
        for term in query_terms:
            # Exact matches
            exact_matches = text.count(term)
            score += exact_matches * 2.0
            
            # Partial matches
            partial_matches = sum(1 for word in text_words if term in word)
            score += partial_matches * 0.5
        
        # Length normalization
        text_length = len(text_words)
        if text_length > 0:
            score = score / (text_length ** 0.5)
        
        return score
    
    def _calculate_recency_boost(self, document: Dict[str, Any]) -> float:
        """Calculate recency boost factor."""
        pub_date_str = document.get('published_date')
        if not pub_date_str:
            return 1.0
        
        try:
            pub_date = datetime.strptime(pub_date_str, '%Y-%m-%d').date()
            days_old = (date.today() - pub_date).days
            
            if days_old <= self.recency_boost_days:
                # Linear decay over boost period
                boost = 1.0 + (0.5 * (self.recency_boost_days - days_old) / self.recency_boost_days)
                return boost
        except ValueError:
            pass
        
        return 1.0
    
    def _get_document_type_boost(self, doc_type: str) -> float:
        """Get boost factor based on document type."""
        boost_map = {
            'LEI': 1.5,
            'DECRETO': 1.3,
            'PORTARIA': 1.1,
            'RESOLUCAO': 1.0,
            'INSTRUCAO_NORMATIVA': 1.0
        }
        return boost_map.get(doc_type, 1.0)
    
    def _generate_highlights(self, document: Dict[str, Any], query_terms: List[str]) -> List[str]:
        """Generate highlighted text snippets."""
        highlights = []
        
        # Highlight in title
        title = document.get('title', '')
        title_highlight = self._highlight_text(title, query_terms)
        if title_highlight != title:
            highlights.append(title_highlight)
        
        # Highlight in content
        content = document.get('content', '')
        content_highlights = self._extract_highlighted_snippets(content, query_terms)
        highlights.extend(content_highlights)
        
        return highlights[:3]  # Limit to 3 highlights
    
    def _highlight_text(self, text: str, query_terms: List[str]) -> str:
        """Add highlighting markup to text."""
        highlighted = text
        for term in query_terms:
            pattern = re.compile(re.escape(term), re.IGNORECASE)
            highlighted = pattern.sub(f'<mark>{term}</mark>', highlighted)
        return highlighted
    
    def _extract_highlighted_snippets(self, text: str, query_terms: List[str], 
                                     snippet_length: int = 150) -> List[str]:
        """Extract highlighted snippets from text."""
        snippets = []
        text_lower = text.lower()
        
        for term in query_terms:
            start_pos = text_lower.find(term.lower())
            if start_pos != -1:
                # Extract snippet around the term
                snippet_start = max(0, start_pos - snippet_length // 2)
                snippet_end = min(len(text), start_pos + len(term) + snippet_length // 2)
                
                snippet = text[snippet_start:snippet_end]
                if snippet_start > 0:
                    snippet = '...' + snippet
                if snippet_end < len(text):
                    snippet = snippet + '...'
                
                # Highlight the snippet
                highlighted_snippet = self._highlight_text(snippet, [term])
                snippets.append(highlighted_snippet)
        
        return snippets[:2]  # Limit to 2 snippets
    
    def _find_matched_fields(self, document: Dict[str, Any], query_terms: List[str]) -> List[str]:
        """Find which fields matched the query."""
        matched_fields = []
        
        for field in ['title', 'content', 'keywords']:
            field_value = str(self._get_field_value(document, field) or '').lower()
            for term in query_terms:
                if term in field_value:
                    matched_fields.append(field)
                    break
        
        return matched_fields
    
    def _calculate_relevance_factors(self, document: Dict[str, Any], 
                                   query_terms: List[str]) -> Dict[str, float]:
        """Calculate individual relevance factors."""
        factors = {}
        
        # Text match strength
        factors['text_match'] = self._calculate_text_score(
            document.get('content', ''), query_terms
        )
        
        # Title match
        factors['title_match'] = self._calculate_text_score(
            document.get('title', ''), query_terms
        )
        
        # Recency factor
        factors['recency'] = self._calculate_recency_boost(document) - 1.0
        
        # Importance factor
        importance = document.get('metadata', {}).get('importance', 'baixa')
        factors['importance'] = self.importance_boost.get(importance, 1.0) - 1.0
        
        return factors
    
    def _generate_facets(self, documents: List[Dict[str, Any]], 
                        facet_fields: List[str]) -> List[SearchFacet]:
        """Generate facets for search results."""
        facets = []
        
        for field in facet_fields:
            facet_values = defaultdict(int)
            
            for doc in documents:
                if field == 'published_year':
                    # Special handling for year extraction
                    pub_date = doc.get('published_date', '')
                    if pub_date:
                        year = pub_date.split('-')[0]
                        facet_values[year] += 1
                else:
                    value = self._get_field_value(doc, field)
                    if value:
                        facet_values[str(value)] += 1
            
            # Convert to facet format
            facet_list = [
                {'value': value, 'count': count}
                for value, count in sorted(facet_values.items(), key=lambda x: x[1], reverse=True)
            ]
            
            if facet_list:
                facet = SearchFacet(
                    field=field,
                    name=self._get_facet_display_name(field),
                    values=facet_list[:10]  # Limit to top 10
                )
                facets.append(facet)
        
        return facets
    
    def _get_facet_display_name(self, field: str) -> str:
        """Get display name for facet field."""
        display_names = {
            'source': 'Fonte',
            'document_type': 'Tipo de Documento',
            'published_year': 'Ano de Publicação'
        }
        return display_names.get(field, field.replace('_', ' ').title())
    
    def _generate_suggestions(self, query: str, result_count: int) -> List[str]:
        """Generate search suggestions."""
        suggestions = []
        
        if result_count == 0:
            # Suggest related terms if no results
            suggestions = self._get_related_terms(query)
        elif result_count < 5:
            # Suggest broader terms if few results
            suggestions = self._get_broader_terms(query)
        
        return suggestions[:5]  # Limit to 5 suggestions
    
    def _get_related_terms(self, query: str) -> List[str]:
        """Get related search terms."""
        # This would typically use a thesaurus or ML model
        # For now, return some common related terms
        related_terms_map = {
            'dados': ['privacidade', 'proteção', 'LGPD', 'informações'],
            'educação': ['ensino', 'escola', 'estudante', 'professor'],
            'saúde': ['medicina', 'hospital', 'paciente', 'tratamento'],
            'tecnologia': ['digital', 'inovação', 'internet', 'software']
        }
        
        suggestions = []
        query_lower = query.lower()
        
        for term, related in related_terms_map.items():
            if term in query_lower:
                suggestions.extend(related)
        
        return suggestions[:5]
    
    def _get_broader_terms(self, query: str) -> List[str]:
        """Get broader search terms."""
        # Simple implementation - remove adjectives and specific terms
        words = query.split()
        if len(words) > 1:
            # Suggest removing last word
            broader_query = ' '.join(words[:-1])
            return [broader_query]
        
        return []