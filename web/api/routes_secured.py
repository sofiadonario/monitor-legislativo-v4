"""
Secured API routes for Monitor Legislativo Web
"""

import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from flask import Blueprint, request, jsonify, g
from pydantic import BaseModel, validator

from core.api.api_service import APIService
from core.models.models import SearchResult, APIStatus
from core.utils.export_service import ExportService
from core.auth.decorators import require_auth, require_permission, optional_auth, rate_limit
from core.utils.input_validator import sanitize_input, validate_date_format

logger = logging.getLogger(__name__)

# Create blueprint
api_router = Blueprint('api', __name__, url_prefix='/api/v1')

# Initialize services
api_service = APIService()
export_service = ExportService()

# Pydantic models for request validation
class SearchRequest(BaseModel):
    """Search request model with validation"""
    query: str
    sources: Optional[List[str]] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    page: int = 1
    page_size: int = 25
    
    @validator('query')
    def validate_query(cls, v):
        if not v or not v.strip():
            raise ValueError('Query cannot be empty')
        if len(v) < 3:
            raise ValueError('Query must be at least 3 characters')
        if len(v) > 500:
            raise ValueError('Query too long')
        return sanitize_input(v)
    
    @validator('page')
    def validate_page(cls, v):
        if v < 1:
            raise ValueError('Page must be >= 1')
        if v > 1000:
            raise ValueError('Page number too high')
        return v
    
    @validator('page_size')
    def validate_page_size(cls, v):
        if v < 1 or v > 100:
            raise ValueError('Page size must be between 1 and 100')
        return v
    
    @validator('start_date', 'end_date')
    def validate_dates(cls, v):
        if v and not validate_date_format(v):
            raise ValueError('Date must be in YYYY-MM-DD format')
        return v

class ExportRequest(BaseModel):
    """Export request model with validation"""
    query: str
    format: str = "csv"
    filters: Optional[Dict[str, Any]] = {}
    
    @validator('format')
    def validate_format(cls, v):
        allowed_formats = ['csv', 'json', 'excel', 'pdf']
        if v.lower() not in allowed_formats:
            raise ValueError(f'Format must be one of: {", ".join(allowed_formats)}')
        return v.lower()
    
    @validator('query')
    def validate_query(cls, v):
        if not v or not v.strip():
            raise ValueError('Query cannot be empty')
        return sanitize_input(v)

# Routes
@api_router.route('/documents', methods=['GET'])
@optional_auth  # Works with or without authentication
@rate_limit(max_requests=100, window=60)
def search_documents():
    """Search for legislative documents"""
    try:
        # Parse and validate request parameters
        search_data = SearchRequest(
            query=request.args.get('q', ''),
            sources=request.args.getlist('sources'),
            start_date=request.args.get('start_date'),
            end_date=request.args.get('end_date'),
            page=int(request.args.get('page', 1)),
            page_size=int(request.args.get('page_size', 25))
        )
        
        # Check if user has premium features
        is_authenticated = hasattr(g, 'current_user') and g.current_user
        
        # Apply restrictions for unauthenticated users
        if not is_authenticated:
            search_data.page_size = min(search_data.page_size, 10)  # Limit results
            if search_data.page > 10:
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'Please login to access more results'
                }), 401
        
        # Build filters
        filters = {}
        if search_data.start_date:
            filters['start_date'] = search_data.start_date
        if search_data.end_date:
            filters['end_date'] = search_data.end_date
        
        # Log search query
        user_id = g.current_user.id if is_authenticated else 'anonymous'
        logger.info(f"Search query by user {user_id}: {search_data.query}")
        
        # Perform search
        results = api_service.search_all_sync(
            search_data.query, 
            filters, 
            search_data.sources
        )
        
        # Aggregate results
        all_documents = []
        total_count = 0
        
        for result in results:
            for prop in result.propositions:
                prop_dict = prop.to_dict()
                prop_dict['_source'] = result.source.value if result.source else 'Unknown'
                all_documents.append(prop_dict)
            total_count += result.total_count
        
        # Apply pagination
        start_idx = (search_data.page - 1) * search_data.page_size
        end_idx = start_idx + search_data.page_size
        paginated_docs = all_documents[start_idx:end_idx]
        
        return jsonify({
            'query': search_data.query,
            'filters': filters,
            'sources': search_data.sources or list(api_service.get_available_sources().keys()),
            'total_count': total_count,
            'page': search_data.page,
            'page_size': search_data.page_size,
            'total_pages': (total_count + search_data.page_size - 1) // search_data.page_size,
            'results': paginated_docs,
            'authenticated': is_authenticated
        }), 200
        
    except ValueError as e:
        return jsonify({
            'error': 'Validation error',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Search error: {str(e)}")
        return jsonify({
            'error': 'Search failed',
            'message': 'An error occurred during search'
        }), 500

@api_router.route('/documents/<string:source>/<string:doc_id>', methods=['GET'])
@optional_auth
def get_document_details(source: str, doc_id: str):
    """Get detailed information about a specific document"""
    try:
        # Validate source
        if source not in api_service.get_available_sources():
            return jsonify({
                'error': 'Invalid source',
                'message': f'Source {source} is not available'
            }), 404
        
        # Sanitize document ID
        doc_id = sanitize_input(doc_id)
        
        # TODO: Implement document details retrieval
        # For now, return mock data
        return jsonify({
            'id': doc_id,
            'source': source,
            'title': f'Document {doc_id} from {source}',
            'content': 'Document content would be here',
            'metadata': {
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get document error: {str(e)}")
        return jsonify({
            'error': 'Failed to retrieve document',
            'message': str(e)
        }), 500

@api_router.route('/export', methods=['POST'])
@require_auth
@require_permission('document:export')
@rate_limit(max_requests=10, window=3600)  # 10 exports per hour
def export_documents():
    """Export search results to specified format"""
    try:
        # Validate request
        export_data = ExportRequest(**request.get_json())
        
        # Log export request
        logger.info(f"Export request by user {g.current_user.id}: {export_data.format}")
        
        # Perform search first
        results = api_service.search_all_sync(
            export_data.query,
            export_data.filters
        )
        
        # Aggregate results
        all_documents = []
        for result in results:
            for prop in result.propositions:
                prop_dict = prop.to_dict()
                prop_dict['_source'] = result.source.value if result.source else 'Unknown'
                all_documents.append(prop_dict)
        
        # Limit export size
        max_export_size = 10000
        if len(all_documents) > max_export_size:
            return jsonify({
                'error': 'Export too large',
                'message': f'Export limited to {max_export_size} documents. Please refine your search.'
            }), 400
        
        # Create export job
        export_id = export_service.create_export_job(
            user_id=g.current_user.id,
            query=export_data.query,
            format=export_data.format,
            documents=all_documents
        )
        
        return jsonify({
            'export_id': export_id,
            'status': 'processing',
            'message': 'Export job created. You will be notified when complete.',
            'document_count': len(all_documents)
        }), 202
        
    except ValueError as e:
        return jsonify({
            'error': 'Validation error',
            'message': str(e)
        }), 400
    except Exception as e:
        logger.error(f"Export error: {str(e)}")
        return jsonify({
            'error': 'Export failed',
            'message': 'An error occurred during export'
        }), 500

@api_router.route('/sources', methods=['GET'])
def get_sources():
    """Get available data sources"""
    sources = api_service.get_available_sources()
    return jsonify({
        'sources': [
            {
                'key': key,
                'name': name,
                'enabled': True,
                'description': f'Legislative data from {name}'
            }
            for key, name in sources.items()
        ]
    }), 200

@api_router.route('/status', methods=['GET'])
def get_api_status():
    """Get current status of all APIs"""
    try:
        statuses = api_service.get_api_status_sync()
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'services': [
                {
                    'name': status.name,
                    'source': status.source.value,
                    'is_healthy': status.is_healthy,
                    'last_check': status.last_check.isoformat() if status.last_check else None,
                    'response_time': status.response_time,
                    'error_message': status.error_message
                }
                for status in statuses
            ]
        }), 200
        
    except Exception as e:
        logger.error(f"Status check error: {str(e)}")
        return jsonify({
            'error': 'Status check failed',
            'message': str(e)
        }), 500

@api_router.route('/cache', methods=['DELETE'])
@require_auth
@require_permission('admin:config')
def clear_cache():
    """Clear cache for specific source or all sources"""
    try:
        source = request.args.get('source')
        
        if source and source not in api_service.get_available_sources():
            return jsonify({
                'error': 'Invalid source',
                'message': f'Source {source} is not available'
            }), 400
        
        api_service.clear_cache(source)
        
        logger.info(f"Cache cleared by user {g.current_user.id} for source: {source or 'all'}")
        
        return jsonify({
            'message': f"Cache cleared for {'source: ' + source if source else 'all sources'}",
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Clear cache error: {str(e)}")
        return jsonify({
            'error': 'Failed to clear cache',
            'message': str(e)
        }), 500

# Error handlers
@api_router.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Not found',
        'message': 'The requested resource was not found'
    }), 404

@api_router.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred'
    }), 500