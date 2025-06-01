"""
Standardized API base classes and patterns for Monitor Legislativo v4.
Provides consistent interfaces, error handling, and response formats.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union, Type
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import logging
import asyncio
from pydantic import BaseModel, Field, validator
from flask import jsonify, request
from functools import wraps

from core.utils.input_validator import InputValidator
from core.monitoring.observability import observability
from core.auth.decorators import require_auth


class APIVersion(Enum):
    """API version enumeration."""
    V1 = "v1"
    V2 = "v2"


class HTTPMethod(Enum):
    """HTTP method enumeration."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class ResponseStatus(Enum):
    """Standard response status codes."""
    SUCCESS = "success"
    ERROR = "error"
    WARNING = "warning"
    PARTIAL = "partial"


@dataclass
class APIMetadata:
    """API response metadata."""
    timestamp: str
    version: str
    request_id: str
    execution_time_ms: float
    total_count: Optional[int] = None
    page: Optional[int] = None
    per_page: Optional[int] = None
    has_more: Optional[bool] = None


@dataclass
class StandardAPIResponse:
    """Standard API response format."""
    status: ResponseStatus
    data: Any
    metadata: APIMetadata
    errors: List[Dict[str, Any]] = None
    warnings: List[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        response = {
            'status': self.status.value,
            'data': self.data,
            'metadata': asdict(self.metadata)
        }
        
        if self.errors:
            response['errors'] = self.errors
        
        if self.warnings:
            response['warnings'] = self.warnings
        
        return response


class APIError(Exception):
    """Standard API error with structured information."""
    
    def __init__(self, 
                 message: str,
                 code: str = "GENERIC_ERROR",
                 status_code: int = 400,
                 details: Dict[str, Any] = None):
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API response."""
        return {
            'code': self.code,
            'message': self.message,
            'details': self.details
        }


class ValidationError(APIError):
    """Input validation error."""
    
    def __init__(self, message: str, field: str = None, value: Any = None):
        details = {}
        if field:
            details['field'] = field
        if value is not None:
            details['value'] = str(value)
        
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            status_code=400,
            details=details
        )


class AuthenticationError(APIError):
    """Authentication error."""
    
    def __init__(self, message: str = "Authentication required"):
        super().__init__(
            message=message,
            code="AUTHENTICATION_ERROR",
            status_code=401
        )


class AuthorizationError(APIError):
    """Authorization error."""
    
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message=message,
            code="AUTHORIZATION_ERROR",
            status_code=403
        )


class NotFoundError(APIError):
    """Resource not found error."""
    
    def __init__(self, resource: str, identifier: str = None):
        message = f"{resource} not found"
        if identifier:
            message += f": {identifier}"
        
        super().__init__(
            message=message,
            code="NOT_FOUND",
            status_code=404,
            details={'resource': resource, 'identifier': identifier}
        )


class RateLimitError(APIError):
    """Rate limit exceeded error."""
    
    def __init__(self, limit: int, window: str):
        super().__init__(
            message=f"Rate limit exceeded: {limit} requests per {window}",
            code="RATE_LIMIT_EXCEEDED",
            status_code=429,
            details={'limit': limit, 'window': window}
        )


# Pydantic models for request/response validation
class BaseRequest(BaseModel):
    """Base request model."""
    
    class Config:
        extra = "forbid"  # Reject unknown fields
        validate_assignment = True


class BaseResponse(BaseModel):
    """Base response model."""
    
    class Config:
        extra = "allow"
        validate_assignment = True


class PaginationRequest(BaseRequest):
    """Pagination parameters."""
    page: int = Field(default=1, ge=1, le=1000)
    per_page: int = Field(default=20, ge=1, le=100)
    
    @validator('page')
    def validate_page(cls, v):
        if v < 1:
            raise ValueError('Page must be >= 1')
        return v
    
    @validator('per_page')
    def validate_per_page(cls, v):
        if v < 1 or v > 100:
            raise ValueError('Per page must be between 1 and 100')
        return v


class SearchRequest(PaginationRequest):
    """Standard search request."""
    query: str = Field(..., min_length=1, max_length=500)
    filters: Dict[str, Any] = Field(default_factory=dict)
    sort_by: str = Field(default="relevance")
    sort_order: str = Field(default="desc", regex="^(asc|desc)$")
    
    @validator('query')
    def validate_query(cls, v):
        if not v or not v.strip():
            raise ValueError('Query cannot be empty')
        return v.strip()


class DocumentResponse(BaseResponse):
    """Document response model."""
    id: int
    title: str
    content: Optional[str]
    source: str
    document_type: str
    published_date: str
    url: Optional[str]
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SearchResponse(BaseResponse):
    """Search response model."""
    results: List[DocumentResponse]
    total_count: int
    page: int
    per_page: int
    facets: List[Dict[str, Any]] = Field(default_factory=list)
    suggestions: List[str] = Field(default_factory=list)


class StandardizedAPIBase(ABC):
    """Base class for standardized API services."""
    
    def __init__(self, version: APIVersion = APIVersion.V1):
        self.version = version
        self.validator = InputValidator()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def get_service_name(self) -> str:
        """Return the service name for monitoring."""
        pass
    
    def validate_request(self, data: Dict[str, Any], model_class: Type[BaseRequest]) -> BaseRequest:
        """Validate request data against Pydantic model."""
        try:
            return model_class(**data)
        except Exception as e:
            raise ValidationError(f"Invalid request data: {str(e)}")
    
    def create_response(self, 
                       data: Any,
                       status: ResponseStatus = ResponseStatus.SUCCESS,
                       request_id: str = None,
                       execution_time_ms: float = None,
                       total_count: int = None,
                       page: int = None,
                       per_page: int = None,
                       errors: List[Dict[str, Any]] = None,
                       warnings: List[str] = None) -> StandardAPIResponse:
        """Create standardized API response."""
        
        metadata = APIMetadata(
            timestamp=datetime.now().isoformat(),
            version=self.version.value,
            request_id=request_id or self._generate_request_id(),
            execution_time_ms=execution_time_ms or 0.0,
            total_count=total_count,
            page=page,
            per_page=per_page,
            has_more=self._calculate_has_more(total_count, page, per_page)
        )
        
        return StandardAPIResponse(
            status=status,
            data=data,
            metadata=metadata,
            errors=errors,
            warnings=warnings
        )
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _calculate_has_more(self, total_count: int, page: int, per_page: int) -> bool:
        """Calculate if there are more pages."""
        if total_count is None or page is None or per_page is None:
            return None
        return (page * per_page) < total_count
    
    async def handle_request(self, handler_func: callable, *args, **kwargs) -> StandardAPIResponse:
        """Handle API request with standard error handling and monitoring."""
        request_id = self._generate_request_id()
        start_time = datetime.now()
        
        try:
            # Record request metrics
            observability.record_metric(
                f"api_request_{self.get_service_name()}", 1,
                labels={'method': request.method, 'version': self.version.value}
            )
            
            # Execute handler
            result = await handler_func(*args, **kwargs)
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Create success response
            if isinstance(result, StandardAPIResponse):
                result.metadata.request_id = request_id
                result.metadata.execution_time_ms = execution_time
                return result
            else:
                return self.create_response(
                    data=result,
                    request_id=request_id,
                    execution_time_ms=execution_time
                )
        
        except APIError as e:
            # Handle known API errors
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            observability.record_error(
                'api_error', self.get_service_name(), str(e)
            )
            
            return self.create_response(
                data=None,
                status=ResponseStatus.ERROR,
                request_id=request_id,
                execution_time_ms=execution_time,
                errors=[e.to_dict()]
            )
        
        except Exception as e:
            # Handle unexpected errors
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            self.logger.error(f"Unexpected error in {self.get_service_name()}: {e}")
            observability.record_error(
                'unexpected_error', self.get_service_name(), str(e)
            )
            
            return self.create_response(
                data=None,
                status=ResponseStatus.ERROR,
                request_id=request_id,
                execution_time_ms=execution_time,
                errors=[{
                    'code': 'INTERNAL_ERROR',
                    'message': 'An unexpected error occurred',
                    'details': {}
                }]
            )


def api_endpoint(methods: List[HTTPMethod] = None,
                auth_required: bool = True,
                rate_limit: int = None,
                version: APIVersion = APIVersion.V1):
    """Decorator for standardized API endpoints."""
    
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Apply authentication if required
            if auth_required:
                # This would integrate with the auth system
                pass
            
            # Apply rate limiting if specified
            if rate_limit:
                # This would integrate with rate limiting
                pass
            
            # Execute the function
            result = await func(*args, **kwargs)
            
            # Ensure result is a StandardAPIResponse
            if not isinstance(result, StandardAPIResponse):
                # Convert to standard response
                service_name = getattr(func, '__self__', {}).get_service_name() or 'unknown'
                base_service = StandardizedAPIBase(version)
                base_service.get_service_name = lambda: service_name
                result = base_service.create_response(result)
            
            return jsonify(result.to_dict()), 200
        
        return wrapper
    return decorator


class DocumentAPIService(StandardizedAPIBase):
    """Standardized document API service."""
    
    def get_service_name(self) -> str:
        return "documents"
    
    async def search_documents(self, request_data: Dict[str, Any]) -> StandardAPIResponse:
        """Search documents with standardized interface."""
        # Validate request
        search_req = self.validate_request(request_data, SearchRequest)
        
        # Sanitize input
        query = self.validator.sanitize_search_query(search_req.query)
        
        # Mock search implementation (replace with actual search)
        mock_results = [
            DocumentResponse(
                id=1,
                title="Lei Geral de Proteção de Dados",
                content="Esta lei dispõe sobre...",
                source="Planalto",
                document_type="LEI",
                published_date="2018-08-14",
                url="http://www.planalto.gov.br/...",
                metadata={"importance": "alta"}
            )
        ]
        
        search_response = SearchResponse(
            results=mock_results,
            total_count=1,
            page=search_req.page,
            per_page=search_req.per_page,
            facets=[
                {"field": "source", "values": [{"value": "Planalto", "count": 1}]}
            ],
            suggestions=[]
        )
        
        return self.create_response(
            data=search_response.dict(),
            total_count=1,
            page=search_req.page,
            per_page=search_req.per_page
        )
    
    async def get_document(self, document_id: int) -> StandardAPIResponse:
        """Get document by ID."""
        if document_id <= 0:
            raise ValidationError("Invalid document ID", "document_id", document_id)
        
        # Mock document retrieval
        if document_id == 999:
            raise NotFoundError("Document", str(document_id))
        
        document = DocumentResponse(
            id=document_id,
            title="Sample Document",
            content="Sample content...",
            source="Planalto",
            document_type="LEI",
            published_date="2024-01-01",
            url="http://example.com",
            metadata={}
        )
        
        return self.create_response(data=document.dict())


class AlertAPIService(StandardizedAPIBase):
    """Standardized alert API service."""
    
    def get_service_name(self) -> str:
        return "alerts"
    
    async def create_alert(self, request_data: Dict[str, Any]) -> StandardAPIResponse:
        """Create monitoring alert."""
        # Implementation here
        pass
    
    async def get_user_alerts(self, user_id: int, pagination: PaginationRequest) -> StandardAPIResponse:
        """Get alerts for user."""
        # Implementation here
        pass


# Export utilities for easy import
__all__ = [
    'APIVersion',
    'HTTPMethod', 
    'ResponseStatus',
    'StandardAPIResponse',
    'APIError',
    'ValidationError',
    'AuthenticationError',
    'AuthorizationError',
    'NotFoundError',
    'RateLimitError',
    'BaseRequest',
    'BaseResponse',
    'PaginationRequest',
    'SearchRequest',
    'DocumentResponse',
    'SearchResponse',
    'StandardizedAPIBase',
    'api_endpoint',
    'DocumentAPIService',
    'AlertAPIService'
]