"""
Standardized Error Handling for APIs
Prevents information leakage and ensures consistent responses
"""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any
import logging
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

class APIError(Exception):
    """Custom API error with structured response"""
    
    def __init__(self, status_code: int, error_code: str, message: str, details: Dict[str, Any] = None):
        self.status_code = status_code
        self.error_code = error_code
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

async def api_error_handler(request: Request, exc: APIError):
    """Handle custom API errors with structured response"""
    error_id = str(uuid.uuid4())
    
    # Log error with correlation ID
    logger.error(f"API Error [{error_id}]: {exc.error_code} - {exc.message}", extra={
        'error_id': error_id,
        'status_code': exc.status_code,
        'path': request.url.path,
        'method': request.method,
        'client_ip': request.client.host
    })
    
    response_data = {
        'error': {
            'code': exc.error_code,
            'message': exc.message,
            'timestamp': datetime.utcnow().isoformat(),
            'error_id': error_id
        }
    }
    
    # Only include details in development
    if exc.details and os.getenv('ENV') != 'production':
        response_data['error']['details'] = exc.details
    
    return JSONResponse(
        status_code=exc.status_code,
        content=response_data
    )

# Standard error codes
class ErrorCodes:
    INVALID_INPUT = "INVALID_INPUT"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    SQL_INJECTION_ATTEMPT = "SQL_INJECTION_ATTEMPT"
