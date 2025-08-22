#!/usr/bin/env Rscript
# Railway Diagnostic - Debug App Loading Issues
# =============================================

cat("=== Railway Diagnostic Starting ===\n")

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Port: %d, Host: %s\n", port, host))

# Load httpuv for server
library(httpuv)

# Diagnostic information
diagnostic_info <- list()

# Check file system
cat("=== File System Check ===\n")
diagnostic_info$files <- list(
  app_exists = file.exists("app.R"),
  working_directory = getwd(),
  files_in_dir = list.files(".", pattern = "*.R")[1:10] # First 10 R files
)

cat("App.R exists:", diagnostic_info$files$app_exists, "\n")
cat("Working directory:", diagnostic_info$files$working_directory, "\n")

# Try to load app.R with detailed error reporting
cat("=== App Loading Test ===\n")
app_load_result <- list(
  loaded = FALSE,
  error = NULL,
  warnings = NULL,
  objects_found = NULL
)

tryCatch({
  # Capture warnings
  withCallingHandlers({
    # Create test environment
    test_env <- new.env()
    
    # Source the app
    source("app.R", local = test_env)
    
    # Check what objects were created
    app_load_result$objects_found = ls(test_env)
    
    # Check if ui and server exist
    has_ui <- exists("ui", envir = test_env)
    has_server <- exists("server", envir = test_env)
    
    app_load_result$has_ui = has_ui
    app_load_result$has_server = has_server
    
    if (has_ui && has_server) {
      app_load_result$loaded = TRUE
      cat("✓ App loaded successfully in test environment\n")
    } else {
      app_load_result$error = paste("Missing objects - UI:", has_ui, "Server:", has_server)
    }
    
  }, warning = function(w) {
    app_load_result$warnings <<- c(app_load_result$warnings, w$message)
  })
  
}, error = function(e) {
  app_load_result$error = e$message
  cat("✗ App loading failed:", e$message, "\n")
})

# Check package availability
cat("=== Package Check ===\n")
required_packages <- c("shiny", "shinydashboard", "DT", "plotly", "dplyr", 
                      "RPostgres", "DBI", "pool", "jsonlite", "sf", "leaflet")

package_status <- sapply(required_packages, function(pkg) {
  tryCatch({
    library(pkg, character.only = TRUE, quietly = TRUE, warn.conflicts = FALSE)
    return("OK")
  }, error = function(e) {
    return(paste("ERROR:", e$message))
  })
})

diagnostic_info$packages <- package_status

# Database connection test
cat("=== Database Check ===\n")
db_status <- list(
  url_exists = nchar(Sys.getenv("DATABASE_URL")) > 0,
  url_format = "Unknown"
)

if (db_status$url_exists) {
  db_url <- Sys.getenv("DATABASE_URL")
  if (grepl("postgresql://", db_url)) {
    db_status$url_format = "PostgreSQL"
    # Try to connect
    tryCatch({
      library(DBI)
      library(RPostgres)
      con <- dbConnect(RPostgres::Postgres(), db_url)
      db_status$connection_test = "SUCCESS"
      dbDisconnect(con)
    }, error = function(e) {
      db_status$connection_test = paste("ERROR:", e$message)
    })
  }
}

diagnostic_info$database <- db_status

# Create diagnostic server
cat("=== Starting Diagnostic Server ===\n")

s <- startServer(
  host = host,
  port = port,
  app = list(
    call = function(req) {
      path <- req$PATH_INFO
      
      # Health check
      if (!is.null(path) && grepl("^/health", path)) {
        return(list(
          status = 200L,
          headers = list("Content-Type" = "application/json"),
          body = '{"status":"healthy","mode":"diagnostic"}'
        ))
      }
      
      # Diagnostic page
      html_content <- paste0(
        '<!DOCTYPE html>',
        '<html lang="pt-BR">',
        '<head>',
        '<meta charset="UTF-8">',
        '<title>Monitor Legislativo v4 - Diagnóstico</title>',
        '<style>',
        'body { font-family: monospace; background: #1a1a1a; color: #00ff00; padding: 20px; }',
        '.container { max-width: 1200px; margin: 0 auto; }',
        'h1 { color: #00ffff; }',
        'h2 { color: #ffff00; margin-top: 30px; }',
        '.status-ok { color: #00ff00; }',
        '.status-error { color: #ff4444; }',
        '.status-warning { color: #ffaa00; }',
        '.code-block { background: #333; padding: 15px; margin: 10px 0; border-radius: 5px; overflow-x: auto; }',
        'pre { margin: 0; white-space: pre-wrap; }',
        '</style>',
        '</head>',
        '<body>',
        '<div class="container">',
        '<h1>🔍 Monitor Legislativo v4 - Diagnóstico</h1>',
        
        '<h2>📁 Sistema de Arquivos</h2>',
        '<div class="code-block">',
        '<pre>',
        'app.R existe: ', ifelse(diagnostic_info$files$app_exists, 
                                '<span class="status-ok">✓ SIM</span>', 
                                '<span class="status-error">✗ NÃO</span>'), '\n',
        'Diretório de trabalho: ', diagnostic_info$files$working_directory, '\n',
        'Arquivos R encontrados: ', paste(diagnostic_info$files$files_in_dir, collapse = ', '),
        '</pre>',
        '</div>',
        
        '<h2>📦 Carregamento da Aplicação</h2>',
        '<div class="code-block">',
        '<pre>',
        'Status: ', ifelse(app_load_result$loaded, 
                          '<span class="status-ok">✓ SUCESSO</span>', 
                          '<span class="status-error">✗ FALHOU</span>'), '\n',
        ifelse(!is.null(app_load_result$error), 
               paste('Erro:', app_load_result$error, '\n'), ''),
        ifelse(!is.null(app_load_result$objects_found),
               paste('Objetos encontrados:', paste(app_load_result$objects_found, collapse = ', '), '\n'), ''),
        ifelse(!is.null(app_load_result$warnings) && length(app_load_result$warnings) > 0,
               paste('Avisos:', paste(app_load_result$warnings, collapse = '\n'), '\n'), ''),
        '</pre>',
        '</div>',
        
        '<h2>📚 Pacotes</h2>',
        '<div class="code-block">',
        '<pre>',
        paste(sapply(names(package_status), function(pkg) {
          status <- package_status[[pkg]]
          color_class <- ifelse(status == "OK", "status-ok", "status-error")
          paste0(sprintf("%-15s", pkg), ': <span class="', color_class, '">', status, '</span>')
        }), collapse = '\n'),
        '</pre>',
        '</div>',
        
        '<h2>🗄️ Banco de Dados</h2>',
        '<div class="code-block">',
        '<pre>',
        'DATABASE_URL: ', ifelse(diagnostic_info$database$url_exists, 
                               '<span class="status-ok">✓ CONFIGURADA</span>', 
                               '<span class="status-warning">⚠ NÃO CONFIGURADA</span>'), '\n',
        'Formato: ', diagnostic_info$database$url_format, '\n',
        ifelse(!is.null(diagnostic_info$database$connection_test),
               paste('Teste de Conexão:', 
                     ifelse(diagnostic_info$database$connection_test == "SUCCESS",
                           '<span class="status-ok">✓ SUCESSO</span>',
                           paste('<span class="status-error">✗', diagnostic_info$database$connection_test, '</span>')), '\n'),
               ''),
        '</pre>',
        '</div>',
        
        '<h2>🔧 Informações do Sistema</h2>',
        '<div class="code-block">',
        '<pre>',
        'R Version: ', R.version.string, '\n',
        'Platform: ', R.version$platform, '\n',
        'Port: ', port, '\n',
        'Host: ', host, '\n',
        'Environment: ', Sys.getenv("RAILWAY_ENVIRONMENT", "not set"), '\n',
        'Time: ', format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), '\n',
        '</pre>',
        '</div>',
        
        '<h2>🔗 Links</h2>',
        '<div class="code-block">',
        '<a href="/health" style="color: #00ffff;">Health Check</a> | ',
        '<a href="https://railway.app" target="_blank" style="color: #00ffff;">Railway Dashboard</a>',
        '</div>',
        
        '</div>',
        '</body>',
        '</html>'
      )
      
      list(
        status = 200L,
        headers = list("Content-Type" = "text/html; charset=utf-8"),
        body = html_content
      )
    }
  )
)

cat("========================================\n")
cat("✓ Diagnostic server started\n")
cat("✓ Health check: /health\n")
cat("✓ Diagnostic info: /\n")
cat("========================================\n")

# Keep server running
while(TRUE) {
  Sys.sleep(0.1)
  service()
}