"""
CQL Query Builder for LexML Brasil API
Builds Contextual Query Language queries for academic legal research
"""

import re
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum

from ..models.lexml_models import (
    CQLQuery, SearchFilters, DocumentType, Autoridade
)


class CQLFieldType(str, Enum):
    """LexML supported CQL fields"""
    TITLE = "title"
    DESCRIPTION = "description" 
    URN = "urn"
    TIPO_DOCUMENTO = "tipoDocumento"
    AUTORIDADE = "autoridade"
    LOCALIDADE = "localidade"
    DATE = "date"
    SUBJECT = "subject"
    IDENTIFIER = "identifier"


class CQLRelation(str, Enum):
    """CQL relation operators"""
    EXACT = "exact"
    ANY = "any"
    ALL = "all"
    WITHIN = "within"
    GREATER_THAN = ">"
    LESS_THAN = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="


class CQLBooleanOperator(str, Enum):
    """CQL boolean operators"""
    AND = "AND"
    OR = "OR"
    NOT = "NOT"


class CQLQueryBuilder:
    """
    Advanced CQL query builder for LexML Brasil API
    Supports academic research patterns and legal document discovery
    """
    
    def __init__(self):
        self.transport_terms = [
            "transporte", "transportes", "rodoviário", "rodovia", "estrada",
            "carga", "logística", "frete", "fretamento", "caminhão", "veículo",
            "tráfego", "mobilidade", "infraestrutura", "pedágio", "combustível"
        ]
        
        self.legal_stopwords = [
            "de", "da", "do", "das", "dos", "e", "o", "a", "os", "as",
            "em", "no", "na", "nos", "nas", "por", "para", "com", "sem"
        ]
    
    def build_simple_query(self, search_term: str) -> str:
        """Build simple CQL query for basic text search"""
        if not search_term.strip():
            return "*"
        
        # Escape quotes and special characters
        escaped_term = self._escape_cql_term(search_term)
        
        # Search in title and description
        return f'title any "{escaped_term}" OR description any "{escaped_term}"'
    
    def build_field_query(
        self, 
        field: CQLFieldType, 
        value: str, 
        relation: CQLRelation = CQLRelation.ANY
    ) -> str:
        """Build CQL query for specific field"""
        escaped_value = self._escape_cql_term(value)
        return f'{field.value} {relation.value} "{escaped_value}"'
    
    def build_document_type_query(self, document_types: List[DocumentType]) -> str:
        """Build CQL query for document types"""
        if not document_types:
            return ""
        
        type_queries = [
            f'tipoDocumento exact "{doc_type.value}"' 
            for doc_type in document_types
        ]
        return f"({' OR '.join(type_queries)})"
    
    def build_authority_query(self, authorities: List[Autoridade]) -> str:
        """Build CQL query for authorities"""
        if not authorities:
            return ""
        
        auth_queries = [
            f'autoridade exact "{auth.value}"' 
            for auth in authorities
        ]
        return f"({' OR '.join(auth_queries)})"
    
    def build_locality_query(self, localities: List[str]) -> str:
        """Build CQL query for geographic localities"""
        if not localities:
            return ""
        
        # Handle both exact codes and partial matches
        loc_queries = []
        for locality in localities:
            if "." in locality:  # State.municipality format
                loc_queries.append(f'localidade exact "{locality}"')
            else:  # State or general locality
                loc_queries.append(f'localidade any "{locality}"')
        
        return f"({' OR '.join(loc_queries)})"
    
    def build_date_range_query(
        self, 
        start_year: Optional[int] = None, 
        end_year: Optional[int] = None
    ) -> str:
        """Build CQL query for date ranges"""
        if not start_year and not end_year:
            return ""
        
        if start_year and end_year:
            return f'date within "{start_year} {end_year}"'
        elif start_year:
            return f'date >= "{start_year}"'
        else:
            return f'date <= "{end_year}"'
    
    def build_subject_query(self, subjects: List[str]) -> str:
        """Build CQL query for subject classifications"""
        if not subjects:
            return ""
        
        subj_queries = [
            f'subject any "{self._escape_cql_term(subj)}"' 
            for subj in subjects
        ]
        return f"({' OR '.join(subj_queries)})"
    
    def build_transport_legislation_query(
        self, 
        search_term: Optional[str] = None,
        include_related_terms: bool = True
    ) -> str:
        """Build specialized query for transport legislation research"""
        queries = []
        
        # Main search term
        if search_term:
            queries.append(self.build_simple_query(search_term))
        
        # Transport-related terms
        if include_related_terms:
            transport_query = " OR ".join([
                f'title any "{term}" OR description any "{term}"'
                for term in self.transport_terms
            ])
            queries.append(f"({transport_query})")
        
        # Combine with OR for broader search
        return f"({' OR '.join(queries)})" if queries else "*"
    
    def build_boolean_query(
        self, 
        queries: List[str], 
        operator: CQLBooleanOperator = CQLBooleanOperator.AND
    ) -> str:
        """Combine multiple CQL queries with boolean operators"""
        if not queries:
            return "*"
        
        # Filter out empty queries
        valid_queries = [q.strip() for q in queries if q.strip()]
        
        if not valid_queries:
            return "*"
        
        if len(valid_queries) == 1:
            return valid_queries[0]
        
        return f" {operator.value} ".join(f"({q})" for q in valid_queries)
    
    def build_advanced_query(
        self,
        search_term: Optional[str] = None,
        filters: Optional[SearchFilters] = None,
        boolean_operator: CQLBooleanOperator = CQLBooleanOperator.AND
    ) -> str:
        """Build advanced CQL query from search term and filters"""
        query_parts = []
        
        # Main search term
        if search_term and search_term.strip():
            query_parts.append(self.build_simple_query(search_term))
        
        if filters:
            # Document type filter
            if filters.tipoDocumento:
                query_parts.append(self.build_document_type_query(filters.tipoDocumento))
            
            # Authority filter
            if filters.autoridade:
                query_parts.append(self.build_authority_query(filters.autoridade))
            
            # Locality filter
            if filters.localidade:
                query_parts.append(self.build_locality_query(filters.localidade))
            
            # Date range filter
            start_year = filters.date_from.year if filters.date_from else None
            end_year = filters.date_to.year if filters.date_to else None
            date_query = self.build_date_range_query(start_year, end_year)
            if date_query:
                query_parts.append(date_query)
            
            # Subject filter
            if filters.subject:
                query_parts.append(self.build_subject_query(filters.subject))
        
        # Combine all parts
        return self.build_boolean_query(query_parts, boolean_operator)
    
    def parse_user_query(self, user_input: str) -> CQLQuery:
        """Parse user input into structured CQL query"""
        try:
            # Check if already valid CQL
            if self._is_valid_cql(user_input):
                return CQLQuery(
                    raw_query=user_input,
                    parsed_terms=self._extract_cql_terms(user_input),
                    is_valid=True
                )
            
            # Parse as natural language and convert to CQL
            cql_query = self._convert_natural_to_cql(user_input)
            
            return CQLQuery(
                raw_query=user_input,
                parsed_terms=self._extract_cql_terms(cql_query),
                is_valid=True
            )
            
        except Exception as e:
            return CQLQuery(
                raw_query=user_input,
                is_valid=False,
                error_message=f"Query parsing error: {str(e)}"
            )
    
    def build_suggestion_queries(self, partial_term: str) -> List[str]:
        """Build CQL queries for auto-suggestions"""
        suggestions = []
        
        if len(partial_term) < 2:
            return suggestions
        
        # Field-specific suggestions
        for field in CQLFieldType:
            if field.value.startswith(partial_term.lower()):
                suggestions.append(f'{field.value} any "termo"')
        
        # Document type suggestions
        for doc_type in DocumentType:
            if doc_type.value.lower().startswith(partial_term.lower()):
                suggestions.append(f'tipoDocumento exact "{doc_type.value}"')
        
        # Authority suggestions
        for auth in Autoridade:
            if auth.value.startswith(partial_term.lower()):
                suggestions.append(f'autoridade exact "{auth.value}"')
        
        # Transport term suggestions
        for term in self.transport_terms:
            if term.startswith(partial_term.lower()):
                suggestions.append(f'title any "{term}" OR description any "{term}"')
        
        return suggestions[:10]  # Limit suggestions
    
    def _escape_cql_term(self, term: str) -> str:
        """Escape special characters in CQL terms"""
        # Escape quotes and backslashes
        escaped = term.replace('\\', '\\\\').replace('"', '\\"')
        return escaped.strip()
    
    def _is_valid_cql(self, query: str) -> bool:
        """Check if query is already valid CQL"""
        cql_keywords = ['exact', 'any', 'all', 'within', 'AND', 'OR', 'NOT']
        cql_fields = [field.value for field in CQLFieldType]
        
        # Simple heuristic: contains CQL keywords and field names
        query_upper = query.upper()
        has_cql_keyword = any(keyword in query_upper for keyword in cql_keywords)
        has_field = any(field in query.lower() for field in cql_fields)
        
        return has_cql_keyword and has_field
    
    def _extract_cql_terms(self, cql_query: str) -> List[Dict[str, Any]]:
        """Extract terms and operators from CQL query"""
        terms = []
        
        # Simple regex-based extraction (can be enhanced)
        pattern = r'(\w+)\s+(exact|any|all|within)\s+"([^"]+)"'
        matches = re.findall(pattern, cql_query, re.IGNORECASE)
        
        for field, relation, value in matches:
            terms.append({
                "field": field,
                "relation": relation,
                "value": value
            })
        
        return terms
    
    def _convert_natural_to_cql(self, natural_query: str) -> str:
        """Convert natural language query to CQL (basic implementation)"""
        # Remove stop words
        words = [
            word for word in natural_query.lower().split()
            if word not in self.legal_stopwords
        ]
        
        # Build simple text search
        if len(words) == 1:
            return f'title any "{words[0]}" OR description any "{words[0]}"'
        else:
            # Multi-word search
            full_phrase = " ".join(words)
            return f'title any "{full_phrase}" OR description any "{full_phrase}"'
    
    def get_common_patterns(self) -> Dict[str, str]:
        """Get common CQL query patterns for legal research"""
        return {
            "transport_laws": 'tipoDocumento exact "Lei" AND (title any "transporte" OR description any "transporte")',
            "federal_decrees": 'tipoDocumento exact "Decreto" AND autoridade exact "federal"',
            "sao_paulo_legislation": 'localidade any "sao.paulo"',
            "recent_laws": 'tipoDocumento exact "Lei" AND date >= "2020"',
            "transport_regulations": '(title any "transporte" OR description any "transporte") AND (tipoDocumento exact "Portaria" OR tipoDocumento exact "Resolução")',
            "municipal_transport": 'autoridade exact "municipal" AND (title any "transporte" OR description any "transporte")',
            "cargo_legislation": 'title any "carga" OR description any "carga" OR subject any "carga"',
            "road_infrastructure": 'title any "rodovia" OR description any "infraestrutura" OR subject any "infraestrutura"'
        }


# Utility functions for CQL building
def escape_cql_string(s: str) -> str:
    """Utility function to escape CQL strings"""
    return CQLQueryBuilder()._escape_cql_term(s)


def build_quick_search(term: str) -> str:
    """Quick utility for building simple search queries"""
    builder = CQLQueryBuilder()
    return builder.build_simple_query(term)


def build_transport_search(term: str = "") -> str:
    """Quick utility for transport legislation searches"""
    builder = CQLQueryBuilder()
    return builder.build_transport_legislation_query(term)