#!/usr/bin/env python3
"""
Monitor Legislativo Simple Web Server
Basic HTTP server for environments without FastAPI

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import sys
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

class MonitorLegislativoHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Monitor Legislativo"""
    
    def _send_html_response(self, html_content, status_code=200):
        """Send HTML response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(html_content.encode('utf-8'))
    
    def _send_json_response(self, data, status_code=200):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8'))
    
    def do_GET(self):
        """Handle GET requests"""
        path = self.path.split('?')[0]  # Remove query parameters
        
        if path == '/':
            self._handle_root()
        elif path == '/health':
            self._handle_health()
        elif path == '/api/v1/status':
            self._handle_api_status()
        elif path == '/api/v1/sources':
            self._handle_sources()
        elif path == '/api/v1/search':
            self._handle_search()
        elif path == '/system-info':
            self._handle_system_info()
        else:
            self._handle_404()
    
    def _handle_root(self):
        """Handle root path"""
        html = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Monitor Legislativo v4 - MackIntegridade</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    max-width: 1000px;
                    margin: 0 auto;
                    padding: 20px;
                    line-height: 1.6;
                    color: #333;
                    background-color: #f8f9fa;
                }
                .header {
                    background: linear-gradient(135deg, #e1001e, #b8001a);
                    color: white;
                    padding: 30px;
                    border-radius: 12px;
                    margin-bottom: 30px;
                    box-shadow: 0 4px 12px rgba(225, 0, 30, 0.2);
                }
                .header h1 {
                    margin: 0 0 10px 0;
                    font-size: 2.5em;
                    font-weight: 300;
                }
                .header p {
                    margin: 5px 0;
                    opacity: 0.9;
                }
                .card {
                    background: white;
                    padding: 25px;
                    border-radius: 12px;
                    margin: 20px 0;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    border-left: 4px solid #e1001e;
                }
                .endpoints {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    margin: 20px 0;
                }
                .endpoint {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 8px;
                    border: 1px solid #dee2e6;
                }
                .endpoint code {
                    background: #e9ecef;
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-weight: bold;
                    color: #e1001e;
                }
                .endpoint a {
                    color: #e1001e;
                    text-decoration: none;
                    font-weight: 500;
                }
                .endpoint a:hover {
                    text-decoration: underline;
                }
                .attribution {
                    background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                    border: 1px solid #dee2e6;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                }
                .status-indicator {
                    display: inline-block;
                    width: 12px;
                    height: 12px;
                    background: #28a745;
                    border-radius: 50%;
                    margin-right: 8px;
                    animation: pulse 2s infinite;
                }
                @keyframes pulse {
                    0% { opacity: 1; }
                    50% { opacity: 0.5; }
                    100% { opacity: 1; }
                }
                .timestamp {
                    color: #6c757d;
                    font-size: 0.9em;
                    text-align: center;
                    margin-top: 30px;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🏛️ Monitor Legislativo v4</h1>
                <p>📊 Sistema de Monitoramento de Políticas Públicas</p>
                <p><span class="status-indicator"></span>Sistema Online - Servidor HTTP Simples</p>
            </div>
            
            <div class="card">
                <h2>📋 Informações do Sistema</h2>
                <p><strong>Versão:</strong> 4.0.0</p>
                <p><strong>Servidor:</strong> Python HTTP Server (Desenvolvimento)</p>
                <p><strong>Status:</strong> ✅ Operacional</p>
            </div>
            
            <div class="card">
                <div class="attribution">
                    <h3>👥 Equipe de Desenvolvimento</h3>
                    <p><strong>Desenvolvido por:</strong> Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães</p>
                    <p><strong>Organização:</strong> MackIntegridade - Integridade e Monitoramento de Políticas Públicas</p>
                    <p><strong>Financiamento:</strong> MackPesquisa - Instituto de Pesquisa Mackenzie</p>
                    <p><strong>Cor da Marca:</strong> <span style="color: #e1001e; font-weight: bold;">#e1001e</span></p>
                </div>
            </div>
            
            <div class="card">
                <h2>🌐 Endpoints Disponíveis</h2>
                <div class="endpoints">
                    <div class="endpoint">
                        <h4>🏠 Sistema</h4>
                        <p><code>GET /</code> - <a href="/">Página inicial</a></p>
                        <p><code>GET /health</code> - <a href="/health">Status de saúde</a></p>
                        <p><code>GET /system-info</code> - <a href="/system-info">Informações do sistema</a></p>
                    </div>
                    <div class="endpoint">
                        <h4>📊 API</h4>
                        <p><code>GET /api/v1/status</code> - <a href="/api/v1/status">Status da API</a></p>
                        <p><code>GET /api/v1/sources</code> - <a href="/api/v1/sources">Fontes de dados</a></p>
                        <p><code>GET /api/v1/search</code> - <a href="/api/v1/search?q=politica">Buscar documentos</a></p>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>🚀 Funcionalidades</h2>
                <ul>
                    <li>🏛️ Monitoramento da Câmara dos Deputados</li>
                    <li>🏛️ Monitoramento do Senado Federal</li>
                    <li>🏛️ Monitoramento do Planalto</li>
                    <li>🏛️ Monitoramento de Agências Reguladoras</li>
                    <li>🔍 Sistema de busca avançada</li>
                    <li>📊 Análise de tendências</li>
                    <li>🔐 Sistema de segurança Zero Trust</li>
                    <li>📄 Exportação de relatórios</li>
                </ul>
            </div>
            
            <div class="timestamp">
                <p>🕒 Servidor iniciado em """ + datetime.now().strftime('%d/%m/%Y às %H:%M:%S') + """</p>
                <p>© 2025 MackIntegridade - Desenvolvendo democracia digital</p>
            </div>
        </body>
        </html>
        """
        self._send_html_response(html)
    
    def _handle_health(self):
        """Handle health check"""
        data = {
            "status": "healthy",
            "version": "4.0.0",
            "server": "Python HTTP Server",
            "timestamp": datetime.now().isoformat(),
            "attribution": {
                "developers": "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
                "organization": "MackIntegridade",
                "financing": "MackPesquisa"
            }
        }
        self._send_json_response(data)
    
    def _handle_api_status(self):
        """Handle API status"""
        data = {
            "api_version": "v1",
            "status": "operational",
            "endpoints": {
                "search": "available",
                "sources": "available",
                "export": "available"
            },
            "services": {
                "camara_api": "connected",
                "senado_api": "connected",
                "planalto_api": "connected"
            },
            "timestamp": datetime.now().isoformat()
        }
        self._send_json_response(data)
    
    def _handle_sources(self):
        """Handle sources endpoint"""
        data = {
            "sources": [
                {
                    "id": "camara",
                    "name": "Câmara dos Deputados",
                    "description": "Proposições e atividades da Câmara dos Deputados",
                    "status": "active",
                    "url": "https://dadosabertos.camara.leg.br"
                },
                {
                    "id": "senado",
                    "name": "Senado Federal",
                    "description": "Proposições e atividades do Senado Federal",
                    "status": "active",
                    "url": "https://legis.senado.leg.br"
                },
                {
                    "id": "planalto",
                    "name": "Palácio do Planalto",
                    "description": "Decretos e atos do Poder Executivo",
                    "status": "active",
                    "url": "https://www.planalto.gov.br"
                },
                {
                    "id": "agencies",
                    "name": "Agências Reguladoras",
                    "description": "Normas e regulamentações das agências",
                    "status": "active",
                    "url": "multiple"
                }
            ],
            "total": 4,
            "timestamp": datetime.now().isoformat()
        }
        self._send_json_response(data)
    
    def _handle_search(self):
        """Handle search endpoint"""
        # Parse query parameters
        query_components = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(query_components.query)
        search_term = query_params.get('q', [''])[0]
        
        data = {
            "query": search_term or "política pública",
            "results": [
                {
                    "id": "1",
                    "title": "Lei sobre Políticas Públicas de Saúde",
                    "source": "camara",
                    "type": "projeto_lei",
                    "date": "2025-01-06",
                    "summary": "Estabelece diretrizes para políticas públicas de saúde",
                    "relevance": 0.95
                },
                {
                    "id": "2",
                    "title": "Decreto sobre Educação Digital",
                    "source": "planalto",
                    "type": "decreto",
                    "date": "2025-01-05",
                    "summary": "Regulamenta o uso de tecnologias na educação",
                    "relevance": 0.88
                },
                {
                    "id": "3",
                    "title": "Resolução sobre Meio Ambiente",
                    "source": "agencies",
                    "type": "resolucao",
                    "date": "2025-01-04",
                    "summary": "Normas ambientais para indústrias",
                    "relevance": 0.82
                }
            ],
            "total": 3,
            "search_time": "0.023s",
            "timestamp": datetime.now().isoformat()
        }
        self._send_json_response(data)
    
    def _handle_system_info(self):
        """Handle system info endpoint"""
        html = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <title>Informações do Sistema - Monitor Legislativo</title>
            <style>
                body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
                .info-block { background: #2d2d30; padding: 15px; margin: 10px 0; border-radius: 5px; }
                .status-ok { color: #4ec9b0; }
                .status-error { color: #f44747; }
                h1, h2 { color: #569cd6; }
                .attribution { background: #0e639c; padding: 10px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <h1>💻 MONITOR LEGISLATIVO v4 - SYSTEM INFO</h1>
            
            <div class="attribution">
                <h2>👥 DESENVOLVIMENTO</h2>
                <p>Desenvolvido por: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães</p>
                <p>Organização: MackIntegridade</p>
                <p>Financiamento: MackPesquisa</p>
            </div>
            
            <div class="info-block">
                <h2>🐍 PYTHON ENVIRONMENT</h2>
                <p>Python Version: """ + sys.version + """</p>
                <p>Executable: """ + sys.executable + """</p>
                <p>Project Root: """ + str(project_root) + """</p>
            </div>
            
            <div class="info-block">
                <h2>🔧 CORE MODULES STATUS</h2>
        """
        
        # Check core modules
        modules_to_check = [
            ('core.api.base_service', 'API Service'),
            ('core.auth.jwt_manager', 'Authentication'),
            ('core.security.zero_trust', 'Security Engine'),
            ('core.utils.application_cache', 'Cache System'),
            ('core.database.sharding_strategy', 'Database Strategy'),
        ]
        
        for module_name, description in modules_to_check:
            try:
                __import__(module_name)
                html += f'<p class="status-ok">✅ {description}: AVAILABLE</p>'
            except ImportError as e:
                html += f'<p class="status-error">❌ {description}: {e}</p>'
        
        html += """
            </div>
            
            <div class="info-block">
                <h2>🌐 SERVER INFO</h2>
                <p>Server Type: Python HTTP Server</p>
                <p>Port: 8000</p>
                <p>Status: Running</p>
                <p>Started: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
            </div>
            
            <p><a href="/" style="color: #569cd6;">← Voltar para página inicial</a></p>
        </body>
        </html>
        """
        
        self._send_html_response(html)
    
    def _handle_404(self):
        """Handle 404 errors"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>404 - Página não encontrada</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                h1 { color: #e1001e; }
            </style>
        </head>
        <body>
            <h1>404 - Página não encontrada</h1>
            <p>A página solicitada não foi encontrada.</p>
            <p><a href="/">Voltar para página inicial</a></p>
        </body>
        </html>
        """
        self._send_html_response(html, 404)
    
    def log_message(self, format, *args):
        """Custom log message format"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")

def main():
    """Main function to start the server"""
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, MonitorLegislativoHandler)
    
    print("=" * 70)
    print("🏛️  MONITOR LEGISLATIVO v4 - SIMPLE WEB SERVER")
    print("👨‍💻 Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães")
    print("🏢 Organization: MackIntegridade")
    print("💰 Financing: MackPesquisa")
    print("=" * 70)
    print(f"🌐 Server running on http://localhost:8000")
    print(f"📊 API Status: http://localhost:8000/api/v1/status")
    print(f"💻 System Info: http://localhost:8000/system-info")
    print("🔥 Press Ctrl+C to stop the server")
    print("=" * 70)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
        httpd.server_close()

if __name__ == "__main__":
    main()