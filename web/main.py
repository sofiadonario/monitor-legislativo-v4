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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create FastAPI app
app = FastAPI(
    title="Monitor de Políticas Públicas API",
    description="API para monitoramento legislativo brasileiro",
    version="4.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(api_router, prefix="/api/v1")
app.include_router(monitoring_router, prefix="/api/v1/monitoring", tags=["monitoring"])

# Include GraphQL routes
try:
    from web.api.graphql_routes import router as graphql_router
    app.include_router(graphql_router, prefix="/api/v1")
    logging.info("GraphQL endpoint enabled at /api/v1/graphql")
except ImportError as e:
    logging.warning(f"GraphQL not available: {e}")

# Include WebSocket routes
try:
    from web.api.websocket_routes import router as websocket_router
    app.include_router(websocket_router, prefix="/api/v1")
    logging.info("WebSocket endpoint enabled at /api/v1/ws")
except ImportError as e:
    logging.warning(f"WebSocket not available: {e}")

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
            h1 { color: #e1001e; }
            .info { 
                background-color: #f0f0f0; 
                padding: 20px;
                border-radius: 8px;
                margin: 20px 0;
            }
            .attribution {
                background-color: #fff;
                border-left: 4px solid #e1001e;
                padding: 15px;
                margin: 15px 0;
                border-radius: 4px;
            }
            .attribution p {
                margin: 5px 0;
                color: #333;
            }
            a { color: #e1001e; }
        </style>
    </head>
    <body>
        <h1>Monitor Legislativo - MackIntegridade</h1>
        <div class="info">
            <h2>API v4.0.0</h2>
            <p>Sistema integrado de monitoramento legislativo brasileiro.</p>
            <div class="attribution">
                <p><strong>Desenvolvido por:</strong> Sofia Pereira Medeiros Donario &amp; Lucas Ramos Guimarães</p>
                <p><strong>Organização:</strong> MackIntegridade - Integridade e Monitoramento de Políticas Públicas</p>
                <p><strong>Financiamento:</strong> MackPesquisa - Instituto de Pesquisa Mackenzie</p>
            </div>
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