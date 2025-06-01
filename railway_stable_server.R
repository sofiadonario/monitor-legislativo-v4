#!/usr/bin/env Rscript
# Railway Stable Server - Simple and Reliable
# ============================================

cat("=== Railway Stable Server Starting ===\n")

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Port: %d, Host: %s\n", port, host))

# Load httpuv for basic server
library(httpuv)

# Function to get system status
get_system_status <- function() {
  list(
    time = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"),
    port = port,
    host = host,
    r_version = R.version.string,
    working_dir = getwd(),
    railway_env = Sys.getenv("RAILWAY_ENVIRONMENT", "Not set"),
    database_url = if(nchar(Sys.getenv("DATABASE_URL")) > 0) "Configured" else "Not configured",
    memory_limit = Sys.getenv("R_MAX_VSIZE", "Not set")
  )
}

# Create HTTP server
cat("Creating stable HTTP server...\n")

s <- startServer(
  host = host,
  port = port,
  app = list(
    call = function(req) {
      path <- req$PATH_INFO
      
      # Health check endpoint
      if (!is.null(path) && grepl("^/health", path)) {
        status <- get_system_status()
        
        response_json <- paste0(
          '{',
          '"status":"healthy",',
          '"timestamp":"', status$time, '",',
          '"service":"monitor-legislativo-v4",',
          '"port":', status$port, ',',
          '"database":"', status$database_url, '",',
          '"environment":"', status$railway_env, '"',
          '}'
        )
        
        return(list(
          status = 200L,
          headers = list(
            "Content-Type" = "application/json",
            "Cache-Control" = "no-cache"
          ),
          body = response_json
        ))
      }
      
      # Main page - show status dashboard
      status <- get_system_status()
      
      html_content <- paste0(
        '<!DOCTYPE html>',
        '<html lang="pt-BR">',
        '<head>',
        '<meta charset="UTF-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
        '<title>Monitor Legislativo v4 - Status</title>',
        '<style>',
        '* { margin: 0; padding: 0; box-sizing: border-box; }',
        'body {',
        '  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;',
        '  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);',
        '  min-height: 100vh;',
        '  display: flex;',
        '  align-items: center;',
        '  justify-content: center;',
        '  padding: 20px;',
        '}',
        '.container {',
        '  background: white;',
        '  border-radius: 20px;',
        '  box-shadow: 0 20px 60px rgba(0,0,0,0.3);',
        '  max-width: 800px;',
        '  width: 100%;',
        '  overflow: hidden;',
        '}',
        '.header {',
        '  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);',
        '  color: white;',
        '  padding: 30px;',
        '  text-align: center;',
        '}',
        '.header h1 {',
        '  font-size: 2em;',
        '  margin-bottom: 10px;',
        '}',
        '.status-badge {',
        '  display: inline-block;',
        '  background: rgba(255,255,255,0.2);',
        '  padding: 8px 20px;',
        '  border-radius: 20px;',
        '  font-weight: 600;',
        '}',
        '.content {',
        '  padding: 40px;',
        '}',
        '.info-grid {',
        '  display: grid;',
        '  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));',
        '  gap: 20px;',
        '  margin-bottom: 30px;',
        '}',
        '.info-card {',
        '  background: #f8f9fa;',
        '  padding: 20px;',
        '  border-radius: 10px;',
        '  border-left: 4px solid #667eea;',
        '}',
        '.info-card h3 {',
        '  color: #495057;',
        '  font-size: 0.9em;',
        '  text-transform: uppercase;',
        '  margin-bottom: 8px;',
        '  opacity: 0.7;',
        '}',
        '.info-card p {',
        '  color: #212529;',
        '  font-size: 1.1em;',
        '  font-weight: 600;',
        '}',
        '.status-good { color: #10b981; }',
        '.status-warn { color: #f59e0b; }',
        '.actions {',
        '  display: flex;',
        '  gap: 15px;',
        '  flex-wrap: wrap;',
        '}',
        '.btn {',
        '  display: inline-block;',
        '  padding: 12px 24px;',
        '  background: #667eea;',
        '  color: white;',
        '  text-decoration: none;',
        '  border-radius: 8px;',
        '  font-weight: 600;',
        '  transition: transform 0.2s, box-shadow 0.2s;',
        '}',
        '.btn:hover {',
        '  transform: translateY(-2px);',
        '  box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);',
        '}',
        '.btn-secondary {',
        '  background: #6c757d;',
        '}',
        '.message {',
        '  background: #e3f2fd;',
        '  border: 1px solid #90caf9;',
        '  padding: 15px;',
        '  border-radius: 8px;',
        '  margin-top: 20px;',
        '}',
        '.message p {',
        '  color: #1565c0;',
        '  line-height: 1.6;',
        '}',
        '</style>',
        '</head>',
        '<body>',
        '<div class="container">',
        '<div class="header">',
        '<h1>Monitor Legislativo v4</h1>',
        '<div class="status-badge">✓ Servidor Ativo</div>',
        '</div>',
        '<div class="content">',
        '<div class="info-grid">',
        '<div class="info-card">',
        '<h3>Status</h3>',
        '<p class="status-good">Online</p>',
        '</div>',
        '<div class="info-card">',
        '<h3>Porta</h3>',
        '<p>', status$port, '</p>',
        '</div>',
        '<div class="info-card">',
        '<h3>Ambiente</h3>',
        '<p>', status$railway_env, '</p>',
        '</div>',
        '<div class="info-card">',
        '<h3>Banco de Dados</h3>',
        '<p class="', ifelse(status$database_url == "Configured", "status-good", "status-warn"), '">',
        status$database_url, '</p>',
        '</div>',
        '<div class="info-card">',
        '<h3>Hora do Servidor</h3>',
        '<p>', status$time, '</p>',
        '</div>',
        '<div class="info-card">',
        '<h3>Versão R</h3>',
        '<p>', gsub("R version ", "", status$r_version), '</p>',
        '</div>',
        '</div>',
        '<div class="actions">',
        '<a href="/health" class="btn">Health Check API</a>',
        '<a href="https://railway.app" target="_blank" class="btn btn-secondary">Railway Dashboard</a>',
        '</div>',
        '<div class="message">',
        '<p><strong>ℹ️ Informação:</strong> Este é o servidor de status do Monitor Legislativo. ',
        'A aplicação principal Shiny está sendo carregada. Se você está vendo esta página, ',
        'significa que o servidor está funcionando corretamente e pronto para servir a aplicação.</p>',
        '</div>',
        '</div>',
        '</div>',
        '</body>',
        '</html>'
      )
      
      list(
        status = 200L,
        headers = list(
          "Content-Type" = "text/html; charset=utf-8",
          "Cache-Control" = "no-cache"
        ),
        body = html_content
      )
    }
  )
)

cat("========================================\n")
cat(sprintf("✓ Server started successfully on %s:%d\n", host, port))
cat("✓ Health check available at: /health\n")
cat("✓ Status dashboard available at: /\n")
cat("========================================\n")

# Keep server running
while(TRUE) {
  Sys.sleep(0.1)
  service()
}