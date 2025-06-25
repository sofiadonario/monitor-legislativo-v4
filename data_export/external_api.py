# External Data Access API for Monitor Legislativo v4
# Phase 5 Week 18: RESTful API endpoints for external system integration
# Provides secure access to legislative data for researchers and institutions

import asyncio
import asyncpg
from fastapi import FastAPI, HTTPException, Depends, Query, Path, Body
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
import uvicorn
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, date, timedelta
from enum import Enum
import pandas as pd
import jwt
from passlib.context import CryptContext
import secrets
import hashlib
import time
import uuid
from pathlib import Path
import aiofiles
import zipfile
import tempfile
import io

logger = logging.getLogger(__name__)

# Import our export modules
from .comprehensive_exporter import ComprehensiveDataExporter, ExportConfiguration, ExportFilter, ExportFormat, DataSource, CompressionType
from .report_generator import CustomReportGenerator, ReportRequest, ReportFormat, ReportType
from .visualization_engine import AdvancedVisualizationEngine, VisualizationConfig, DashboardConfig, VisualizationType, DashboardLayout

class APIKeyType(Enum):
    """Types of API keys with different access levels"""
    READ_ONLY = "read_only"
    FULL_ACCESS = "full_access"
    ACADEMIC = "academic"
    INSTITUTIONAL = "institutional"
    DEVELOPER = "developer"

class DataFormat(Enum):
    """Data response formats"""
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    EXCEL = "excel"
    PARQUET = "parquet"

@dataclass
class APIKey:
    """API key configuration"""
    key_id: str
    key_hash: str
    key_type: APIKeyType
    user_id: str
    organization: str
    description: str
    rate_limit: int = 1000  # requests per hour
    quota_limit: int = 10000  # total requests per month
    allowed_endpoints: List[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime = None
    is_active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['key_type'] = self.key_type.value
        if self.created_at:
            result['created_at'] = self.created_at.isoformat()
        if self.expires_at:
            result['expires_at'] = self.expires_at.isoformat()
        return result

@dataclass
class APIUsage:
    """API usage tracking"""
    usage_id: str
    key_id: str
    endpoint: str
    method: str
    status_code: int
    response_size: int = 0
    processing_time: float = 0.0
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        if self.timestamp:
            result['timestamp'] = self.timestamp.isoformat()
        return result

class ExternalDataAPI:
    """
    RESTful API for external access to Monitor Legislativo v4 data
    
    Features:
    - Secure API key authentication
    - Rate limiting and quota management
    - Multiple data formats (JSON, CSV, XML, Excel)
    - Real-time and bulk data access
    - Export job management
    - Comprehensive documentation
    - Usage analytics and monitoring
    - Academic research support
    """
    
    def __init__(self, db_config: Dict[str, str], 
                 secret_key: str = None,
                 rate_limit_storage: str = "memory"):
        self.db_config = db_config
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.rate_limit_storage = rate_limit_storage
        
        # Initialize FastAPI app
        self.app = FastAPI(
            title="Monitor Legislativo v4 External API",
            description="RESTful API for accessing Brazilian legislative data",
            version="4.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        # Security
        self.security = HTTPBearer()
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # Rate limiting storage
        self.rate_limit_cache: Dict[str, Dict] = {}
        
        # Components
        self.data_exporter: Optional[ComprehensiveDataExporter] = None
        self.report_generator: Optional[CustomReportGenerator] = None
        self.viz_engine: Optional[AdvancedVisualizationEngine] = None
        
        # Setup middleware and routes
        self._setup_middleware()
        self._setup_routes()
    
    async def initialize(self):
        """Initialize API components"""
        await self._create_api_tables()
        
        # Initialize export components
        self.data_exporter = ComprehensiveDataExporter(self.db_config)
        await self.data_exporter.initialize()
        
        self.report_generator = CustomReportGenerator(self.db_config)
        await self.report_generator.initialize()
        
        self.viz_engine = AdvancedVisualizationEngine(self.db_config)
        await self.viz_engine.initialize()
        
        logger.info("External Data API initialized")
    
    def _setup_middleware(self):
        """Setup middleware for CORS, rate limiting, etc."""
        
        # CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE"],
            allow_headers=["*"],
        )
        
        # Request logging middleware
        @self.app.middleware("http")
        async def log_requests(request, call_next):
            start_time = time.time()
            response = await call_next(request)
            process_time = time.time() - start_time
            
            # Log API usage
            if hasattr(request.state, 'api_key'):
                await self._log_api_usage(
                    key_id=request.state.api_key['key_id'],
                    endpoint=str(request.url),
                    method=request.method,
                    status_code=response.status_code,
                    processing_time=process_time,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get('user-agent')
                )
            
            return response
    
    def _setup_routes(self):
        """Setup API routes"""
        
        # Authentication endpoints
        @self.app.post("/auth/create-key", tags=["Authentication"])
        async def create_api_key(
            user_id: str = Body(...),
            organization: str = Body(...),
            description: str = Body(...),
            key_type: APIKeyType = Body(APIKeyType.READ_ONLY),
            admin_key: HTTPAuthorizationCredentials = Depends(self.security)
        ):
            """Create new API key (admin only)"""
            if not await self._verify_admin_key(admin_key.credentials):
                raise HTTPException(status_code=401, detail="Invalid admin key")
            
            return await self._create_api_key(user_id, organization, description, key_type)
        
        @self.app.get("/auth/verify", tags=["Authentication"])
        async def verify_api_key(api_key: APIKey = Depends(self._get_api_key)):
            """Verify API key validity"""
            return {
                "valid": True,
                "key_type": api_key.key_type.value,
                "organization": api_key.organization,
                "rate_limit": api_key.rate_limit,
                "quota_limit": api_key.quota_limit
            }
        
        # Document endpoints
        @self.app.get("/documents", tags=["Documents"])
        async def get_documents(
            limit: int = Query(100, le=1000),
            offset: int = Query(0, ge=0),
            document_type: Optional[str] = Query(None),
            institution: Optional[str] = Query(None),
            date_from: Optional[date] = Query(None),
            date_to: Optional[date] = Query(None),
            keywords: Optional[str] = Query(None),
            format: DataFormat = Query(DataFormat.JSON),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get legislative documents with filtering"""
            
            # Check rate limit
            await self._check_rate_limit(api_key.key_id)
            
            # Build filters
            filters = ExportFilter(
                date_from=date_from,
                date_to=date_to,
                document_types=[document_type] if document_type else [],
                institutions=[institution] if institution else [],
                keywords=keywords.split(',') if keywords else [],
                max_records=limit
            )
            
            # Get data
            data = await self._get_filtered_documents(filters, offset)
            
            # Format response
            if format == DataFormat.JSON:
                return {"documents": data, "total": len(data), "offset": offset}
            elif format == DataFormat.CSV:
                return await self._format_as_csv(data)
            elif format == DataFormat.XML:
                return await self._format_as_xml(data)
            else:
                return {"documents": data, "total": len(data), "offset": offset}
        
        @self.app.get("/documents/{document_id}", tags=["Documents"])
        async def get_document(
            document_id: str = Path(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get specific document by ID"""
            
            await self._check_rate_limit(api_key.key_id)
            
            document = await self._get_document_by_id(document_id)
            if not document:
                raise HTTPException(status_code=404, detail="Document not found")
            
            return document
        
        # Search endpoints
        @self.app.get("/search", tags=["Search"])
        async def search_documents(
            query: str = Query(..., min_length=1),
            limit: int = Query(100, le=1000),
            offset: int = Query(0, ge=0),
            search_fields: Optional[str] = Query("title,content"),
            format: DataFormat = Query(DataFormat.JSON),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Full-text search across documents"""
            
            await self._check_rate_limit(api_key.key_id)
            
            results = await self._search_documents(query, search_fields.split(','), limit, offset)
            
            if format == DataFormat.JSON:
                return {"results": results, "query": query, "total": len(results)}
            elif format == DataFormat.CSV:
                return await self._format_as_csv(results)
            else:
                return {"results": results, "query": query, "total": len(results)}
        
        # Export endpoints
        @self.app.post("/export/create", tags=["Export"])
        async def create_export_job(
            export_config: dict = Body(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Create data export job"""
            
            await self._check_rate_limit(api_key.key_id)
            
            if api_key.key_type == APIKeyType.READ_ONLY:
                raise HTTPException(status_code=403, detail="Export requires full access")
            
            # Parse export configuration
            try:
                filters = ExportFilter(**export_config.get('filters', {}))
                config = ExportConfiguration(
                    format_type=ExportFormat(export_config['format']),
                    data_source=DataSource(export_config['data_source']),
                    filters=filters,
                    **{k: v for k, v in export_config.items() 
                       if k not in ['format', 'data_source', 'filters']}
                )
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid configuration: {str(e)}")
            
            # Create export job
            job_id = await self.data_exporter.create_export_job(api_key.user_id, config)
            
            # Start processing asynchronously
            asyncio.create_task(self.data_exporter.process_export_job(job_id))
            
            return {"job_id": job_id, "status": "pending"}
        
        @self.app.get("/export/status/{job_id}", tags=["Export"])
        async def get_export_status(
            job_id: str = Path(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get export job status"""
            
            await self._check_rate_limit(api_key.key_id)
            
            status = await self.data_exporter.get_job_status(job_id)
            if not status:
                raise HTTPException(status_code=404, detail="Export job not found")
            
            # Verify user has access to this job
            if status['user_id'] != api_key.user_id:
                raise HTTPException(status_code=403, detail="Access denied")
            
            return status
        
        @self.app.get("/export/download/{job_id}", tags=["Export"])
        async def download_export(
            job_id: str = Path(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Download completed export"""
            
            await self._check_rate_limit(api_key.key_id)
            
            file_path = await self.data_exporter.download_export_file(job_id, api_key.user_id)
            if not file_path:
                raise HTTPException(status_code=404, detail="Export file not found or not ready")
            
            return FileResponse(
                path=file_path,
                filename=f"export_{job_id}.{Path(file_path).suffix[1:]}",
                media_type='application/octet-stream'
            )
        
        # Report endpoints
        @self.app.post("/reports/generate", tags=["Reports"])
        async def generate_report(
            report_request: dict = Body(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Generate custom report"""
            
            await self._check_rate_limit(api_key.key_id)
            
            if api_key.key_type == APIKeyType.READ_ONLY:
                raise HTTPException(status_code=403, detail="Report generation requires full access")
            
            try:
                request = ReportRequest(
                    request_id=str(uuid.uuid4()),
                    user_id=api_key.user_id,
                    template_id=report_request['template_id'],
                    parameters=report_request['parameters'],
                    output_format=ReportFormat(report_request['output_format']),
                    title=report_request.get('title'),
                    description=report_request.get('description')
                )
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")
            
            # Generate report asynchronously
            report_id = await self.report_generator.generate_report(request)
            
            return {"report_id": report_id, "status": "generating"}
        
        @self.app.get("/reports/status/{report_id}", tags=["Reports"])
        async def get_report_status(
            report_id: str = Path(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get report generation status"""
            
            await self._check_rate_limit(api_key.key_id)
            
            status = await self.report_generator.get_report_status(report_id)
            if not status:
                raise HTTPException(status_code=404, detail="Report not found")
            
            # Verify user has access
            if status['user_id'] != api_key.user_id:
                raise HTTPException(status_code=403, detail="Access denied")
            
            return status
        
        @self.app.get("/reports/download/{report_id}", tags=["Reports"])
        async def download_report(
            report_id: str = Path(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Download generated report"""
            
            await self._check_rate_limit(api_key.key_id)
            
            file_path = await self.report_generator.download_report(report_id, api_key.user_id)
            if not file_path:
                raise HTTPException(status_code=404, detail="Report not found or not ready")
            
            return FileResponse(
                path=file_path,
                filename=f"report_{report_id}.{Path(file_path).suffix[1:]}",
                media_type='application/octet-stream'
            )
        
        @self.app.get("/reports/templates", tags=["Reports"])
        async def get_report_templates(
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get available report templates"""
            
            await self._check_rate_limit(api_key.key_id)
            
            templates = await self.report_generator.get_available_templates(api_key.user_id)
            return {"templates": templates}
        
        # Visualization endpoints
        @self.app.post("/visualizations/create", tags=["Visualizations"])
        async def create_visualization(
            viz_config: dict = Body(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Create data visualization"""
            
            await self._check_rate_limit(api_key.key_id)
            
            if api_key.key_type == APIKeyType.READ_ONLY:
                raise HTTPException(status_code=403, detail="Visualization creation requires full access")
            
            try:
                config = VisualizationConfig(
                    viz_id=str(uuid.uuid4()),
                    title=viz_config['title'],
                    type=VisualizationType(viz_config['type']),
                    data_source=viz_config['data_source'],
                    query=viz_config['query'],
                    **{k: v for k, v in viz_config.items() 
                       if k not in ['title', 'type', 'data_source', 'query']}
                )
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid configuration: {str(e)}")
            
            # Create visualization
            chart_html = await self.viz_engine.create_visualization(config)
            
            return {
                "viz_id": config.viz_id,
                "html": chart_html,
                "config": config.to_dict()
            }
        
        @self.app.get("/visualizations/dashboard/{dashboard_id}", tags=["Visualizations"])
        async def get_dashboard(
            dashboard_id: str = Path(...),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get dashboard HTML"""
            
            await self._check_rate_limit(api_key.key_id)
            
            dashboard_html = await self.viz_engine.get_dashboard(dashboard_id)
            if not dashboard_html:
                raise HTTPException(status_code=404, detail="Dashboard not found")
            
            return {"dashboard_id": dashboard_id, "html": dashboard_html}
        
        # Statistics endpoints
        @self.app.get("/stats/summary", tags=["Statistics"])
        async def get_summary_stats(
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get summary statistics"""
            
            await self._check_rate_limit(api_key.key_id)
            
            stats = await self._get_summary_statistics()
            return stats
        
        @self.app.get("/stats/trends", tags=["Statistics"])
        async def get_trend_stats(
            period: str = Query("30d", regex="^(7d|30d|90d|1y)$"),
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get trend statistics"""
            
            await self._check_rate_limit(api_key.key_id)
            
            trends = await self._get_trend_statistics(period)
            return trends
        
        # API usage endpoints
        @self.app.get("/usage/current", tags=["Usage"])
        async def get_current_usage(
            api_key: APIKey = Depends(self._get_api_key)
        ):
            """Get current API usage for the key"""
            
            usage = await self._get_api_key_usage(api_key.key_id)
            return usage
        
        # Health check
        @self.app.get("/health", tags=["Health"])
        async def health_check():
            """API health check"""
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "version": "4.0.0"
            }
    
    async def _create_api_tables(self):
        """Create API-related database tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # API keys table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id VARCHAR(36) PRIMARY KEY,
                    key_hash VARCHAR(255) NOT NULL,
                    key_type VARCHAR(20) NOT NULL,
                    user_id VARCHAR(100) NOT NULL,
                    organization VARCHAR(200) NOT NULL,
                    description TEXT NULL,
                    rate_limit INTEGER DEFAULT 1000,
                    quota_limit INTEGER DEFAULT 10000,
                    allowed_endpoints JSONB NULL,
                    expires_at TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    is_active BOOLEAN DEFAULT TRUE
                );
            """)
            
            # API usage table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS api_usage (
                    usage_id VARCHAR(36) PRIMARY KEY,
                    key_id VARCHAR(36) NOT NULL,
                    endpoint VARCHAR(500) NOT NULL,
                    method VARCHAR(10) NOT NULL,
                    status_code INTEGER NOT NULL,
                    response_size INTEGER DEFAULT 0,
                    processing_time FLOAT DEFAULT 0.0,
                    ip_address INET NULL,
                    user_agent TEXT NULL,
                    timestamp TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # API quotas table (for tracking monthly limits)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS api_quotas (
                    quota_id VARCHAR(36) PRIMARY KEY,
                    key_id VARCHAR(36) NOT NULL,
                    month_period DATE NOT NULL,
                    requests_count INTEGER DEFAULT 0,
                    data_transferred BIGINT DEFAULT 0,
                    last_reset TIMESTAMP DEFAULT NOW(),
                    UNIQUE(key_id, month_period)
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_usage_key ON api_usage(key_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_usage_timestamp ON api_usage(timestamp);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_quotas_key_month ON api_quotas(key_id, month_period);")
            
            logger.info("API tables created successfully")
        
        finally:
            await conn.close()
    
    async def _get_api_key(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> APIKey:
        """Validate and get API key"""
        
        key_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            row = await conn.fetchrow("""
                SELECT * FROM api_keys 
                WHERE key_hash = $1 AND is_active = TRUE
                AND (expires_at IS NULL OR expires_at > NOW())
            """, key_hash)
            
            if not row:
                raise HTTPException(status_code=401, detail="Invalid API key")
            
            api_key = APIKey(
                key_id=row['key_id'],
                key_hash=row['key_hash'],
                key_type=APIKeyType(row['key_type']),
                user_id=row['user_id'],
                organization=row['organization'],
                description=row['description'],
                rate_limit=row['rate_limit'],
                quota_limit=row['quota_limit'],
                allowed_endpoints=json.loads(row['allowed_endpoints']) if row['allowed_endpoints'] else None,
                expires_at=row['expires_at'],
                created_at=row['created_at'],
                is_active=row['is_active']
            )
            
            return api_key
        
        finally:
            await conn.close()
    
    async def _check_rate_limit(self, key_id: str):
        """Check and enforce rate limiting"""
        
        current_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
        
        # Get current usage
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Count requests in current hour
            usage_count = await conn.fetchval("""
                SELECT COUNT(*) FROM api_usage 
                WHERE key_id = $1 AND timestamp >= $2
            """, key_id, current_hour)
            
            # Get rate limit for key
            rate_limit = await conn.fetchval("""
                SELECT rate_limit FROM api_keys WHERE key_id = $1
            """, key_id)
            
            if usage_count >= rate_limit:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. Limit: {rate_limit} requests per hour"
                )
        
        finally:
            await conn.close()
    
    async def _create_api_key(self, user_id: str, organization: str, description: str, key_type: APIKeyType) -> dict:
        """Create new API key"""
        
        # Generate API key
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        key_id = str(uuid.uuid4())
        
        # Set rate limits based on key type
        rate_limits = {
            APIKeyType.READ_ONLY: 500,
            APIKeyType.FULL_ACCESS: 2000,
            APIKeyType.ACADEMIC: 1000,
            APIKeyType.INSTITUTIONAL: 5000,
            APIKeyType.DEVELOPER: 10000
        }
        
        quota_limits = {
            APIKeyType.READ_ONLY: 5000,
            APIKeyType.FULL_ACCESS: 50000,
            APIKeyType.ACADEMIC: 20000,
            APIKeyType.INSTITUTIONAL: 100000,
            APIKeyType.DEVELOPER: 500000
        }
        
        rate_limit = rate_limits.get(key_type, 1000)
        quota_limit = quota_limits.get(key_type, 10000)
        
        # Save to database
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO api_keys 
                (key_id, key_hash, key_type, user_id, organization, description, 
                 rate_limit, quota_limit, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """, key_id, key_hash, key_type.value, user_id, organization, 
                description, rate_limit, quota_limit, datetime.now())
        
        finally:
            await conn.close()
        
        return {
            "key_id": key_id,
            "api_key": api_key,  # Only shown once
            "key_type": key_type.value,
            "rate_limit": rate_limit,
            "quota_limit": quota_limit,
            "organization": organization
        }
    
    async def _verify_admin_key(self, key: str) -> bool:
        """Verify admin API key"""
        # In production, implement proper admin key verification
        return key == "admin_secret_key_change_in_production"
    
    async def _log_api_usage(self, key_id: str, endpoint: str, method: str, 
                           status_code: int, processing_time: float = 0.0,
                           response_size: int = 0, ip_address: str = None,
                           user_agent: str = None):
        """Log API usage"""
        
        usage_id = str(uuid.uuid4())
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO api_usage 
                (usage_id, key_id, endpoint, method, status_code, 
                 response_size, processing_time, ip_address, user_agent, timestamp)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            """, usage_id, key_id, endpoint, method, status_code,
                response_size, processing_time, ip_address, user_agent, datetime.now())
        
        except Exception as e:
            logger.error(f"Failed to log API usage: {e}")
        
        finally:
            await conn.close()
    
    async def _get_filtered_documents(self, filters: ExportFilter, offset: int = 0) -> List[Dict[str, Any]]:
        """Get documents with filters applied"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Build query dynamically
            conditions = []
            params = []
            param_count = 0
            
            if filters.date_from:
                param_count += 1
                conditions.append(f"published_date >= ${param_count}")
                params.append(filters.date_from)
            
            if filters.date_to:
                param_count += 1
                conditions.append(f"published_date <= ${param_count}")
                params.append(filters.date_to)
            
            if filters.document_types:
                param_count += 1
                conditions.append(f"document_type = ANY(${param_count})")
                params.append(filters.document_types)
            
            if filters.institutions:
                param_count += 1
                conditions.append(f"institution = ANY(${param_count})")
                params.append(filters.institutions)
            
            if filters.text_contains:
                param_count += 1
                conditions.append(f"(title ILIKE ${param_count} OR content ILIKE ${param_count})")
                params.append(f"%{filters.text_contains}%")
            
            where_clause = " AND ".join(conditions) if conditions else "TRUE"
            
            # Add limit and offset
            param_count += 1
            limit_clause = f"LIMIT ${param_count}"
            params.append(filters.max_records or 100)
            
            param_count += 1
            offset_clause = f"OFFSET ${param_count}"
            params.append(offset)
            
            query = f"""
                SELECT document_id, title, content, document_type, institution,
                       published_date, url, keywords, metadata
                FROM legislative_documents 
                WHERE {where_clause}
                ORDER BY published_date DESC
                {limit_clause} {offset_clause}
            """
            
            rows = await conn.fetch(query, *params)
            
            documents = []
            for row in rows:
                doc = dict(row)
                # Convert datetime to ISO string
                if doc['published_date']:
                    doc['published_date'] = doc['published_date'].isoformat()
                
                # Parse JSON fields
                if doc['keywords']:
                    doc['keywords'] = json.loads(doc['keywords']) if isinstance(doc['keywords'], str) else doc['keywords']
                if doc['metadata']:
                    doc['metadata'] = json.loads(doc['metadata']) if isinstance(doc['metadata'], str) else doc['metadata']
                
                documents.append(doc)
            
            return documents
        
        finally:
            await conn.close()
    
    async def _get_document_by_id(self, document_id: str) -> Optional[Dict[str, Any]]:
        """Get specific document by ID"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            row = await conn.fetchrow("""
                SELECT * FROM legislative_documents WHERE document_id = $1
            """, document_id)
            
            if not row:
                return None
            
            doc = dict(row)
            
            # Convert datetime fields
            for field in ['published_date', 'created_at', 'updated_at']:
                if doc.get(field):
                    doc[field] = doc[field].isoformat()
            
            # Parse JSON fields
            for field in ['keywords', 'metadata']:
                if doc.get(field) and isinstance(doc[field], str):
                    doc[field] = json.loads(doc[field])
            
            return doc
        
        finally:
            await conn.close()
    
    async def _search_documents(self, query: str, search_fields: List[str], 
                              limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Full-text search documents"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Build search query
            search_conditions = []
            for field in search_fields:
                if field in ['title', 'content', 'keywords']:
                    search_conditions.append(f"{field} ILIKE $1")
            
            if not search_conditions:
                search_conditions = ["title ILIKE $1 OR content ILIKE $1"]
            
            search_clause = " OR ".join(search_conditions)
            
            sql_query = f"""
                SELECT document_id, title, content, document_type, institution,
                       published_date, url, keywords
                FROM legislative_documents 
                WHERE {search_clause}
                ORDER BY published_date DESC
                LIMIT $2 OFFSET $3
            """
            
            rows = await conn.fetch(sql_query, f"%{query}%", limit, offset)
            
            results = []
            for row in rows:
                doc = dict(row)
                if doc['published_date']:
                    doc['published_date'] = doc['published_date'].isoformat()
                
                # Parse keywords
                if doc['keywords'] and isinstance(doc['keywords'], str):
                    doc['keywords'] = json.loads(doc['keywords'])
                
                results.append(doc)
            
            return results
        
        finally:
            await conn.close()
    
    async def _format_as_csv(self, data: List[Dict]) -> StreamingResponse:
        """Format data as CSV response"""
        
        if not data:
            csv_content = "No data available\n"
        else:
            df = pd.DataFrame(data)
            csv_content = df.to_csv(index=False)
        
        return StreamingResponse(
            io.StringIO(csv_content),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=data.csv"}
        )
    
    async def _format_as_xml(self, data: List[Dict]) -> StreamingResponse:
        """Format data as XML response"""
        
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n<documents>\n'
        
        for item in data:
            xml_content += '  <document>\n'
            for key, value in item.items():
                safe_key = key.replace(' ', '_').replace('-', '_')
                xml_content += f'    <{safe_key}>{str(value) if value is not None else ""}</{safe_key}>\n'
            xml_content += '  </document>\n'
        
        xml_content += '</documents>'
        
        return StreamingResponse(
            io.StringIO(xml_content),
            media_type="application/xml",
            headers={"Content-Disposition": "attachment; filename=data.xml"}
        )
    
    async def _get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Total documents
            total_docs = await conn.fetchval("SELECT COUNT(*) FROM legislative_documents")
            
            # Documents by type
            doc_types = await conn.fetch("""
                SELECT document_type, COUNT(*) as count
                FROM legislative_documents 
                GROUP BY document_type
                ORDER BY count DESC
                LIMIT 10
            """)
            
            # Documents by institution
            institutions = await conn.fetch("""
                SELECT institution, COUNT(*) as count
                FROM legislative_documents 
                GROUP BY institution
                ORDER BY count DESC
                LIMIT 10
            """)
            
            # Recent activity (last 30 days)
            recent_count = await conn.fetchval("""
                SELECT COUNT(*) FROM legislative_documents 
                WHERE published_date >= NOW() - INTERVAL '30 days'
            """)
            
            return {
                "total_documents": total_docs,
                "recent_documents": recent_count,
                "document_types": [dict(row) for row in doc_types],
                "institutions": [dict(row) for row in institutions],
                "last_updated": datetime.now().isoformat()
            }
        
        finally:
            await conn.close()
    
    async def _get_trend_statistics(self, period: str) -> Dict[str, Any]:
        """Get trend statistics for specified period"""
        
        # Convert period to days
        days = {"7d": 7, "30d": 30, "90d": 90, "1y": 365}.get(period, 30)
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Daily document counts
            daily_trends = await conn.fetch("""
                SELECT DATE(published_date) as date, COUNT(*) as count
                FROM legislative_documents 
                WHERE published_date >= NOW() - INTERVAL '%s days'
                GROUP BY DATE(published_date)
                ORDER BY date
            """, days)
            
            # Document type trends
            type_trends = await conn.fetch("""
                SELECT document_type, DATE(published_date) as date, COUNT(*) as count
                FROM legislative_documents 
                WHERE published_date >= NOW() - INTERVAL '%s days'
                GROUP BY document_type, DATE(published_date)
                ORDER BY date, document_type
            """, days)
            
            return {
                "period": period,
                "daily_trends": [
                    {"date": row['date'].isoformat(), "count": row['count']}
                    for row in daily_trends
                ],
                "type_trends": [
                    {
                        "document_type": row['document_type'],
                        "date": row['date'].isoformat(),
                        "count": row['count']
                    }
                    for row in type_trends
                ]
            }
        
        finally:
            await conn.close()
    
    async def _get_api_key_usage(self, key_id: str) -> Dict[str, Any]:
        """Get API usage statistics for a key"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Current hour usage
            current_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
            hourly_usage = await conn.fetchval("""
                SELECT COUNT(*) FROM api_usage 
                WHERE key_id = $1 AND timestamp >= $2
            """, key_id, current_hour)
            
            # Current month usage
            current_month = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            monthly_usage = await conn.fetchval("""
                SELECT COUNT(*) FROM api_usage 
                WHERE key_id = $1 AND timestamp >= $2
            """, key_id, current_month)
            
            # Get rate and quota limits
            limits = await conn.fetchrow("""
                SELECT rate_limit, quota_limit FROM api_keys WHERE key_id = $1
            """, key_id)
            
            return {
                "key_id": key_id,
                "current_hour_usage": hourly_usage,
                "hourly_limit": limits['rate_limit'],
                "current_month_usage": monthly_usage,
                "monthly_limit": limits['quota_limit'],
                "hour_remaining": max(0, limits['rate_limit'] - hourly_usage),
                "month_remaining": max(0, limits['quota_limit'] - monthly_usage)
            }
        
        finally:
            await conn.close()
    
    def run(self, host: str = "0.0.0.0", port: int = 8000, **kwargs):
        """Run the API server"""
        uvicorn.run(self.app, host=host, port=port, **kwargs)

# Factory function for easy creation
async def create_external_api(db_config: Dict[str, str], secret_key: str = None) -> ExternalDataAPI:
    """Create and initialize external data API"""
    api = ExternalDataAPI(db_config, secret_key)
    await api.initialize()
    return api

# Export main classes
__all__ = [
    'ExternalDataAPI',
    'APIKey',
    'APIUsage',
    'APIKeyType',
    'DataFormat',
    'create_external_api'
]