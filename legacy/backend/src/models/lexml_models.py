"""
LexML Brasil API data models and types
"""

from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, HttpUrl
from datetime import datetime
from enum import Enum


class DocumentType(str, Enum):
    """Brazilian legal document types from LexML taxonomy"""
    LEI = "Lei"
    DECRETO = "Decreto"
    DECRETO_LEI = "Decreto-Lei"
    MEDIDA_PROVISORIA = "Medida Provisória"
    PORTARIA = "Portaria"
    RESOLUCAO = "Resolução"
    INSTRUCAO_NORMATIVA = "Instrução Normativa"
    EMENDA_CONSTITUCIONAL = "Emenda Constitucional"
    ACORDAO = "Acórdão"
    PARECER = "Parecer"


class Autoridade(str, Enum):
    """Authority levels in Brazilian legal system"""
    FEDERAL = "federal"
    ESTADUAL = "estadual"
    MUNICIPAL = "municipal"
    DISTRITAL = "distrital"


class CQLOperator(str, Enum):
    """CQL search operators supported by LexML"""
    EXACT = "exact"
    ANY = "any"
    ALL = "all"
    WITHIN = "within"


class DataSource(str, Enum):
    """Data source indicators for hybrid architecture"""
    LIVE_API = "live-api"
    CACHED_API = "cached-api"
    CSV_FALLBACK = "csv-fallback"


class LexMLMetadata(BaseModel):
    """Core LexML document metadata"""
    urn: str = Field(..., description="Legal document URN identifier")
    title: str = Field(..., description="Document title")
    description: Optional[str] = Field(None, description="Document description/summary")
    date: datetime = Field(..., description="Document publication date")
    tipoDocumento: DocumentType = Field(..., description="Document type")
    autoridade: Autoridade = Field(..., description="Issuing authority level")
    localidade: str = Field(..., description="Geographic jurisdiction code")
    subject: List[str] = Field(default_factory=list, description="Subject classifications")
    identifier: HttpUrl = Field(..., description="Official document URL")
    source_url: Optional[HttpUrl] = Field(None, description="LexML record URL")


class LexMLDocument(BaseModel):
    """Complete LexML document with content and metadata"""
    metadata: LexMLMetadata
    full_text: Optional[str] = Field(None, description="Complete document text")
    structure: Optional[Dict[str, Any]] = Field(None, description="Document structure (articles, sections)")
    last_modified: datetime = Field(default_factory=datetime.now)
    data_source: DataSource = Field(DataSource.LIVE_API, description="Source of this document")
    cache_key: Optional[str] = Field(None, description="Cache key for this document")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class CQLQuery(BaseModel):
    """CQL query structure for LexML searches"""
    raw_query: str = Field(..., description="Raw CQL query string")
    parsed_terms: List[Dict[str, Any]] = Field(default_factory=list, description="Parsed query components")
    field_queries: Dict[str, str] = Field(default_factory=dict, description="Field-specific queries")
    boolean_operators: List[str] = Field(default_factory=list, description="Boolean operators used")
    date_range: Optional[Dict[str, int]] = Field(None, description="Date range filter")
    is_valid: bool = Field(True, description="Query validation status")
    error_message: Optional[str] = Field(None, description="Validation error if any")


class SearchFilters(BaseModel):
    """Search filters for LexML API queries"""
    tipoDocumento: List[DocumentType] = Field(default_factory=list)
    autoridade: List[Autoridade] = Field(default_factory=list)
    localidade: List[str] = Field(default_factory=list)
    date_from: Optional[datetime] = Field(None)
    date_to: Optional[datetime] = Field(None)
    subject: List[str] = Field(default_factory=list)
    search_term: Optional[str] = Field(None)


class LexMLSearchRequest(BaseModel):
    """LexML API search request"""
    query: Optional[str] = Field(None, description="Free text search query")
    cql_query: Optional[str] = Field(None, description="Direct CQL query")
    filters: SearchFilters = Field(default_factory=SearchFilters)
    start_record: int = Field(1, ge=1, description="Pagination start record")
    max_records: int = Field(50, ge=1, le=100, description="Maximum records per page")
    include_content: bool = Field(False, description="Include full document content")


class LexMLSearchResponse(BaseModel):
    """LexML API search response"""
    documents: List[LexMLDocument]
    total_found: Optional[int] = Field(None, description="Total documents found")
    start_record: int = Field(1, description="Starting record number")
    records_returned: int = Field(0, description="Number of records in this response")
    next_start_record: Optional[int] = Field(None, description="Next page start record")
    search_time_ms: float = Field(0.0, description="Search execution time in milliseconds")
    data_source: DataSource = Field(DataSource.LIVE_API, description="Source of this response")
    cache_hit: bool = Field(False, description="Whether this was served from cache")
    api_status: str = Field("healthy", description="API health status")


class CircuitBreakerState(BaseModel):
    """Circuit breaker state for API reliability"""
    status: str = Field("CLOSED", description="Circuit breaker status")
    failure_count: int = Field(0, description="Consecutive failure count")
    last_failure_time: Optional[datetime] = Field(None)
    next_attempt_time: Optional[datetime] = Field(None)
    total_requests: int = Field(0, description="Total requests processed")
    successful_requests: int = Field(0, description="Successful requests")
    failed_requests: int = Field(0, description="Failed requests")


class APIHealthStatus(BaseModel):
    """API health monitoring data"""
    is_healthy: bool = Field(True, description="Overall API health")
    response_time_ms: float = Field(0.0, description="Average response time")
    success_rate: float = Field(100.0, description="Success rate percentage")
    last_checked: datetime = Field(default_factory=datetime.now)
    circuit_breaker: CircuitBreakerState = Field(default_factory=CircuitBreakerState)
    error_message: Optional[str] = Field(None, description="Latest error message")