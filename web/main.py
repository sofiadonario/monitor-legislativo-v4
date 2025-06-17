"""
Monitor Legislativo Web Application
FastAPI-based web service
"""

import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import uvicorn

import sys
from pathlib import Path

# Add project root to path if not already there
project_root = Path(__file__).parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from web.api.routes import router as api_router
from web.api.monitoring_routes import router as monitoring_router
from core.config.config import Config
from core.api.cache_interceptor import CacheInterceptor

# Configure centralized logging
from core.config.logging_config import setup_logging, get_logger
setup_logging()
logger = get_logger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Monitor de Políticas Públicas API",
    description="API para monitoramento legislativo brasileiro",
    version="4.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configure CORS with secure settings
config = Config()
allowed_origins = config.get("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # Specific origins only
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
    expose_headers=["Content-Disposition", "X-Cache", "X-Cache-Time"],
    max_age=3600
)

# Add cache interceptor middleware
app.add_middleware(
    CacheInterceptor,
    exclude_paths=["/api/health", "/api/docs", "/api/redoc", "/api/v1/monitoring"]
)

# Include API routes
app.include_router(api_router, prefix="/api/v1")
app.include_router(monitoring_router, prefix="/api/v1/monitoring", tags=["monitoring"])

# Serve static files
# app.mount("/static", StaticFiles(directory="web/frontend/static"), name="static")

@app.get("/", response_class=HTMLResponse)
async def root():
    """Root endpoint - returns basic HTML"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Monitor de Políticas Públicas</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
            }
            h1 { color: #003366; }
            .info { 
                background-color: #f0f0f0; 
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
            }
            a { color: #0066CC; }
        </style>
    </head>
    <body>
        <h1>Monitor de Políticas Públicas MackIntegridade</h1>
        <div class="info">
            <h2>API v4.0.0</h2>
            <p>Sistema integrado de monitoramento legislativo brasileiro.</p>
            <p>
                <strong>Documentação:</strong><br>
                <a href="/api/docs">Swagger UI</a> | 
                <a href="/api/redoc">ReDoc</a>
            </p>
        </div>
        <div class="info">
            <h3>Endpoints Principais:</h3>
            <ul>
                <li><code>GET /api/v1/search</code> - Buscar proposições</li>
                <li><code>GET /api/v1/sources</code> - Listar fontes disponíveis</li>
                <li><code>GET /api/v1/status</code> - Status das APIs</li>
                <li><code>POST /api/v1/export</code> - Exportar resultados</li>
            </ul>
        </div>
        <p>© 2025 MackIntegridade</p>
    </body>
    </html>
    """

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "4.0.0"}

def main():
    """Main entry point for web application"""
    config = Config()
    
    uvicorn.run(
        "web.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

if __name__ == "__main__":
    main()