# ============================================================================
# DOCUMENTATION INTEGRATION - SPRINT 7A (API-006)
# ============================================================================
# 
# Integration of comprehensive API documentation with main Plumber API
# Serves enhanced Swagger UI and all documentation resources at /docs
# 
# Features:
# - Complete OpenAPI 3.0 specification serving
# - Enhanced Swagger UI with Brazilian government styling
# - Academic research workflow documentation
# - Authentication and rate limiting guides
# - Interactive examples and tutorials
# - Multi-language support (Portuguese/English)
# - LGPD compliance documentation
# ============================================================================

cat("📚 Loading Documentation Integration for Monitor Legislativo API\n")

# Load documentation components
if (file.exists("api/documentation/swagger_ui_enhanced.R")) {
  source("api/documentation/swagger_ui_enhanced.R")
  cat("✅ Enhanced Swagger UI loaded\n")
} else {
  cat("⚠️ Enhanced Swagger UI not found\n")
}

if (file.exists("api/documentation/api_examples.R")) {
  source("api/documentation/api_examples.R")
  cat("✅ Interactive examples loaded\n")
} else {
  cat("⚠️ Interactive examples not found\n")
}

# Documentation configuration
DOCS_CONFIG <- list(
  version = "1.0.0",
  last_updated = "2024-01-15",
  languages = c("pt", "en"),
  default_language = "pt",
  base_path = "/docs",
  assets_path = "/docs/assets",
  openapi_spec_path = "api/documentation/openapi_complete.yaml",
  academic_guide_path = "api/documentation/academic_research_guide.md",
  auth_guide_path = "api/documentation/authentication_guide.md"
)

# Documentation endpoints
cat("📡 Setting up documentation endpoints...\n")

#' Serve Main Documentation Page (Enhanced Swagger UI)
#' @get /docs
#' @serializer html
docs_main <- function() {
  
  tryCatch({
    # Generate enhanced Swagger UI HTML
    if (exists("generate_enhanced_swagger_html")) {
      openapi_spec_path <- DOCS_CONFIG$openapi_spec_path
      
      # Check if OpenAPI spec exists
      if (file.exists(openapi_spec_path)) {
        html_content <- generate_enhanced_swagger_html(
          openapi_spec_path = openapi_spec_path,
          title = "Monitor Legislativo API - Documentação Interativa"
        )
        return(html_content)
      } else {
        cat("⚠️ OpenAPI spec not found at:", openapi_spec_path, "\n")
      }
    }
    
    # Fallback HTML if enhanced UI not available
    fallback_html <- paste0('
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Monitor Legislativo API - Documentação</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; }
        .header { text-align: center; color: #1E4D8B; margin-bottom: 2rem; }
        .nav-links { display: flex; gap: 1rem; margin: 2rem 0; }
        .nav-link { padding: 0.75rem 1.5rem; background: #1E4D8B; color: white; text-decoration: none; border-radius: 5px; }
        .nav-link:hover { background: #2E7F32; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏛️ Monitor Legislativo API</h1>
            <p>Sistema de Monitoramento da Legislação Brasileira</p>
            <p><strong>Versão:</strong> ', DOCS_CONFIG$version, ' | <strong>Atualizado:</strong> ', DOCS_CONFIG$last_updated, '</p>
        </div>
        
        <div class="nav-links">
            <a href="/docs/openapi" class="nav-link">📋 Especificação OpenAPI</a>
            <a href="/docs/academic-guide" class="nav-link">🎓 Guia Acadêmico</a>
            <a href="/docs/auth-guide" class="nav-link">🔐 Autenticação</a>
            <a href="/docs/examples" class="nav-link">💻 Exemplos</a>
        </div>
        
        <h2>🚀 Recursos Principais</h2>
        <ul>
            <li><strong>134.000+ Documentos Legislativos</strong> - Dataset completo da legislação brasileira</li>
            <li><strong>Busca Avançada</strong> - Algoritmos especializados em terminologia jurídica</li>
            <li><strong>Análise Geográfica</strong> - Integração com dados IBGE</li>
            <li><strong>Citações Acadêmicas</strong> - Geração automática em padrões ABNT, APA, Chicago</li>
            <li><strong>Performance Otimizada</strong> - PostgreSQL + Redis para respostas sub-segundo</li>
            <li><strong>Conformidade LGPD</strong> - Proteção e privacidade de dados</li>
        </ul>
        
        <h2>🎯 Para Pesquisadores Acadêmicos</h2>
        <p>A API foi projetada especificamente para apoiar pesquisa acadêmica de qualidade. Oferece:</p>
        <ul>
            <li>Acesso gratuito para pesquisadores verificados</li>
            <li>Documentação detalhada de metodologias</li>
            <li>Suporte técnico especializado</li>
            <li>Conformidade com padrões éticos de pesquisa</li>
        </ul>
        
        <h2>📞 Suporte</h2>
        <p><strong>Email:</strong> api@monitorlegislativo.gov.br</p>
        <p><strong>Pesquisa Acadêmica:</strong> pesquisa@monitorlegislativo.gov.br</p>
        <p><strong>GitHub:</strong> <a href="https://github.com/monitorlegislativo/api">github.com/monitorlegislativo/api</a></p>
    </div>
</body>
</html>
    ')
    
    return(fallback_html)
    
  }, error = function(e) {
    cat("❌ Error serving documentation:", e$message, "\n")
    return(paste("<h1>Error loading documentation:</h1><p>", e$message, "</p>"))
  })
}

#' Serve OpenAPI Specification
#' @get /docs/openapi
#' @serializer json
docs_openapi <- function() {
  
  tryCatch({
    openapi_spec_path <- DOCS_CONFIG$openapi_spec_path
    
    if (file.exists(openapi_spec_path)) {
      # Read and parse YAML
      openapi_content <- readLines(openapi_spec_path)
      
      # Try to parse as YAML and convert to JSON
      if (requireNamespace("yaml", quietly = TRUE)) {
        spec_data <- yaml::read_yaml(openapi_spec_path)
        return(spec_data)
      } else {
        # Return raw content if yaml package not available
        return(list(
          error = FALSE,
          message = "OpenAPI specification (raw format)",
          data = paste(openapi_content, collapse = "\n"),
          format = "yaml"
        ))
      }
    } else {
      return(list(
        error = TRUE,
        message = "OpenAPI specification not found",
        code = 404
      ))
    }
    
  }, error = function(e) {
    return(list(
      error = TRUE,
      message = paste("Error reading OpenAPI spec:", e$message),
      code = 500
    ))
  })
}

#' Serve Academic Research Guide
#' @get /docs/academic-guide
#' @serializer html
docs_academic_guide <- function() {
  
  tryCatch({
    guide_path <- DOCS_CONFIG$academic_guide_path
    
    if (file.exists(guide_path)) {
      # Read markdown content
      md_content <- readLines(guide_path, warn = FALSE)
      md_text <- paste(md_content, collapse = "\n")
      
      # Convert to HTML (basic conversion)
      html_content <- paste0('
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guia de Pesquisa Acadêmica - Monitor Legislativo API</title>
    <style>
        body { font-family: Georgia, serif; line-height: 1.6; margin: 0; padding: 2rem; background: #f9f9f9; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 3rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #1E4D8B; border-bottom: 2px solid #e0e0e0; padding-bottom: 0.5rem; }
        h1 { text-align: center; font-size: 2.5rem; }
        h2 { font-size: 1.8rem; margin-top: 2rem; }
        h3 { font-size: 1.4rem; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
        pre { background: #f4f4f4; padding: 1rem; border-radius: 5px; overflow-x: auto; border-left: 4px solid #1E4D8B; }
        .back-link { text-align: center; margin-bottom: 2rem; }
        .back-link a { color: #1E4D8B; text-decoration: none; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { border: 1px solid #ddd; padding: 0.75rem; text-align: left; }
        th { background: #f8f9fa; font-weight: bold; }
        ul, ol { margin: 1rem 0; padding-left: 2rem; }
        li { margin: 0.5rem 0; }
        blockquote { border-left: 4px solid #2E7F32; padding-left: 1rem; margin: 1rem 0; font-style: italic; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="/docs">← Voltar à Documentação Principal</a>
        </div>
        <div id="content">
            <pre>', htmlEscape(md_text), '</pre>
        </div>
        <div class="back-link">
            <a href="/docs">← Voltar à Documentação Principal</a>
        </div>
    </div>
</body>
</html>
      ')
      
      return(html_content)
      
    } else {
      return(paste0('
        <h1>Guia Acadêmico Não Encontrado</h1>
        <p>O guia de pesquisa acadêmica não foi encontrado no caminho: ', guide_path, '</p>
        <p><a href="/docs">← Voltar à Documentação</a></p>
      '))
    }
    
  }, error = function(e) {
    return(paste0('<h1>Erro ao Carregar Guia Acadêmico</h1><p>', e$message, '</p>'))
  })
}

#' Serve Authentication Guide
#' @get /docs/auth-guide
#' @serializer html
docs_auth_guide <- function() {
  
  tryCatch({
    guide_path <- DOCS_CONFIG$auth_guide_path
    
    if (file.exists(guide_path)) {
      # Read markdown content
      md_content <- readLines(guide_path, warn = FALSE)
      md_text <- paste(md_content, collapse = "\n")
      
      # Convert to HTML (basic conversion)
      html_content <- paste0('
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guia de Autenticação - Monitor Legislativo API</title>
    <style>
        body { font-family: Georgia, serif; line-height: 1.6; margin: 0; padding: 2rem; background: #f9f9f9; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 3rem; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #1E4D8B; border-bottom: 2px solid #e0e0e0; padding-bottom: 0.5rem; }
        h1 { text-align: center; font-size: 2.5rem; }
        h2 { font-size: 1.8rem; margin-top: 2rem; }
        h3 { font-size: 1.4rem; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
        pre { background: #f4f4f4; padding: 1rem; border-radius: 5px; overflow-x: auto; border-left: 4px solid #1E4D8B; }
        .back-link { text-align: center; margin-bottom: 2rem; }
        .back-link a { color: #1E4D8B; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="/docs">← Voltar à Documentação Principal</a>
        </div>
        <div id="content">
            <pre>', htmlEscape(md_text), '</pre>
        </div>
        <div class="back-link">
            <a href="/docs">← Voltar à Documentação Principal</a>
        </div>
    </div>
</body>
</html>
      ')
      
      return(html_content)
      
    } else {
      return(paste0('
        <h1>Guia de Autenticação Não Encontrado</h1>
        <p>O guia de autenticação não foi encontrado no caminho: ', guide_path, '</p>
        <p><a href="/docs">← Voltar à Documentação</a></p>
      '))
    }
    
  }, error = function(e) {
    return(paste0('<h1>Erro ao Carregar Guia de Autenticação</h1><p>', e$message, '</p>'))
  })
}

#' Serve Interactive Examples
#' @get /docs/examples
#' @serializer html
docs_examples <- function() {
  
  tryCatch({
    # Generate interactive examples
    if (exists("create_realistic_examples_database")) {
      examples_db <- create_realistic_examples_database()
      
      # Convert examples to HTML
      html_content <- paste0('
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Exemplos Interativos - Monitor Legislativo API</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 2rem; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; color: #1E4D8B; margin-bottom: 2rem; }
        .example-section { background: white; margin: 2rem 0; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .example-title { color: #1E4D8B; border-bottom: 2px solid #e0e0e0; padding-bottom: 0.5rem; }
        .code-block { background: #f8f9fa; padding: 1rem; border-radius: 5px; border-left: 4px solid #1E4D8B; margin: 1rem 0; }
        .back-link { text-align: center; margin-bottom: 2rem; }
        .back-link a { color: #1E4D8B; text-decoration: none; font-weight: bold; }
        .nav-tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
        .nav-tab { padding: 0.5rem 1rem; background: #e9ecef; border: none; cursor: pointer; border-radius: 4px 4px 0 0; }
        .nav-tab.active { background: #1E4D8B; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
    <script>
        function showTab(tabName, element) {
            // Hide all tab contents
            var contents = document.querySelectorAll(".tab-content");
            contents.forEach(function(content) { content.classList.remove("active"); });
            
            // Remove active class from all tabs
            var tabs = document.querySelectorAll(".nav-tab");
            tabs.forEach(function(tab) { tab.classList.remove("active"); });
            
            // Show selected tab content
            document.getElementById(tabName).classList.add("active");
            element.classList.add("active");
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="back-link">
            <a href="/docs">← Voltar à Documentação Principal</a>
        </div>
        
        <div class="header">
            <h1>💻 Exemplos Interativos</h1>
            <p>Exemplos práticos para uso da API Monitor Legislativo</p>
        </div>
        
        <div class="example-section">
            <h2 class="example-title">📋 Descoberta de Documentos</h2>
            <p>Exemplos de como descobrir e filtrar documentos legislativos</p>
            
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab(\'r-discovery\', this)">R</button>
                <button class="nav-tab" onclick="showTab(\'python-discovery\', this)">Python</button>
                <button class="nav-tab" onclick="showTab(\'curl-discovery\', this)">cURL</button>
            </div>
            
            <div id="r-discovery" class="tab-content active">
                <div class="code-block">
<pre>
# Buscar leis de educação em São Paulo (2020-2023)
library(httr)
library(jsonlite)

api_key <- "sua_chave_api"
headers <- add_headers(`X-API-Key` = api_key)

response <- GET(
  "https://monitorlegislativo.up.railway.app/api/v1/documents",
  query = list(
    estado = "SP",
    species = "Lei",
    ano_inicio = 2020,
    ano_fim = 2023,
    limit = 100
  ),
  headers
)

docs <- fromJSON(content(response, "text"))
print(paste("Encontrados:", length(docs$data), "documentos"))
</pre>
                </div>
            </div>
            
            <div id="python-discovery" class="tab-content">
                <div class="code-block">
<pre>
# Buscar leis de educação em São Paulo (2020-2023)
import requests

api_key = "sua_chave_api"
headers = {"X-API-Key": api_key}

response = requests.get(
    "https://monitorlegislativo.up.railway.app/api/v1/documents",
    params={
        "estado": "SP",
        "species": "Lei",
        "ano_inicio": 2020,
        "ano_fim": 2023,
        "limit": 100
    },
    headers=headers
)

if response.status_code == 200:
    docs = response.json()
    print(f"Encontrados: {len(docs[\'data\'])} documentos")
</pre>
                </div>
            </div>
            
            <div id="curl-discovery" class="tab-content">
                <div class="code-block">
<pre>
# Buscar leis de educação em São Paulo (2020-2023)
curl -X GET "https://monitorlegislativo.up.railway.app/api/v1/documents?estado=SP&species=Lei&ano_inicio=2020&ano_fim=2023&limit=100" \\
  -H "X-API-Key: sua_chave_api"
</pre>
                </div>
            </div>
        </div>
        
        <div class="example-section">
            <h2 class="example-title">🔍 Busca Avançada</h2>
            <p>Exemplos de busca textual com filtros avançados</p>
            
            <div class="code-block">
<pre>
# Buscar documentos sobre "educação" com filtros
POST /api/v1/search

{
  "query": "educação AND ensino",
  "filters": {
    "estado": "SP",
    "ano_inicio": 2020,
    "species": "Lei"
  },
  "sort": "relevance",
  "limit": 50
}
</pre>
            </div>
        </div>
        
        <div class="example-section">
            <h2 class="example-title">🗺️ Análise Geográfica</h2>
            <p>Exemplos de análise espacial da legislação</p>
            
            <div class="code-block">
<pre>
# Análise por estado
GET /api/v1/geographic/analysis?level=state&metric=count&year=2023

# Dados para mapa coroplético
GET /api/v1/geographic/choropleth?level=state&metric=density
</pre>
            </div>
        </div>
        
        <div class="example-section">
            <h2 class="example-title">📚 Citações Acadêmicas</h2>
            <p>Exemplos de geração de citações padronizadas</p>
            
            <div class="code-block">
<pre>
# Gerar citação ABNT
POST /api/v1/citations/generate

{
  "document_id": "doc_sp_001",
  "style": "abnt",
  "format": "text"
}

# Resposta esperada:
{
  "error": false,
  "data": {
    "citation": "SÃO PAULO (Estado). Lei nº 17.293, de 15 de outubro de 2020..."
  }
}
</pre>
            </div>
        </div>
        
        <div class="back-link">
            <a href="/docs">← Voltar à Documentação Principal</a>
        </div>
    </div>
</body>
</html>
      ')
      
      return(html_content)
      
    } else {
      return('
        <h1>Exemplos Não Disponíveis</h1>
        <p>Os exemplos interativos não estão disponíveis no momento.</p>
        <p><a href="/docs">← Voltar à Documentação</a></p>
      ')
    }
    
  }, error = function(e) {
    return(paste0('<h1>Erro ao Carregar Exemplos</h1><p>', e$message, '</p>'))
  })
}

#' Serve Documentation Assets (CSS, JS, Images)
#' @get /docs/assets/<file>
#' @param file:str Asset filename
#' @serializer content_type
docs_assets <- function(file) {
  
  # Security: Prevent path traversal
  if (grepl("\\.\\.", file) || grepl("/", file)) {
    return(list(
      error = TRUE,
      message = "Invalid file path",
      code = 400
    ))
  }
  
  # Define asset directory
  assets_dir <- "api/documentation/assets"
  file_path <- file.path(assets_dir, file)
  
  if (file.exists(file_path)) {
    # Determine content type
    file_ext <- tools::file_ext(file)
    content_type <- switch(file_ext,
      "css" = "text/css",
      "js" = "application/javascript",
      "png" = "image/png",
      "jpg" = "image/jpeg",
      "jpeg" = "image/jpeg",
      "gif" = "image/gif",
      "svg" = "image/svg+xml",
      "application/octet-stream"
    )
    
    # Read file content
    file_content <- readBin(file_path, "raw", file.info(file_path)$size)
    
    return(list(
      content = file_content,
      content_type = content_type
    ))
  } else {
    return(list(
      error = TRUE,
      message = "Asset not found",
      code = 404
    ))
  }
}

#' Documentation Status and Health Check
#' @get /docs/status
#' @serializer json
docs_status <- function() {
  
  status_info <- list(
    docs_version = DOCS_CONFIG$version,
    last_updated = DOCS_CONFIG$last_updated,
    languages = DOCS_CONFIG$languages,
    available_guides = list(),
    openapi_spec = list(
      available = file.exists(DOCS_CONFIG$openapi_spec_path),
      path = DOCS_CONFIG$openapi_spec_path
    ),
    components_loaded = list(
      swagger_ui = exists("generate_enhanced_swagger_html"),
      examples = exists("create_realistic_examples_database"),
      academic_guide = file.exists(DOCS_CONFIG$academic_guide_path),
      auth_guide = file.exists(DOCS_CONFIG$auth_guide_path)
    ),
    endpoints = list(
      main = "/docs",
      openapi = "/docs/openapi", 
      academic_guide = "/docs/academic-guide",
      auth_guide = "/docs/auth-guide",
      examples = "/docs/examples",
      status = "/docs/status"
    )
  )
  
  # Check available guides
  if (file.exists(DOCS_CONFIG$academic_guide_path)) {
    status_info$available_guides$academic <- "/docs/academic-guide"
  }
  
  if (file.exists(DOCS_CONFIG$auth_guide_path)) {
    status_info$available_guides$authentication <- "/docs/auth-guide"
  }
  
  return(list(
    error = FALSE,
    message = "Documentation system operational",
    data = status_info,
    timestamp = Sys.time()
  ))
}

# Helper function for HTML escaping
htmlEscape <- function(text) {
  text <- gsub("&", "&amp;", text)
  text <- gsub("<", "&lt;", text)
  text <- gsub(">", "&gt;", text)
  text <- gsub("\"", "&quot;", text)
  text <- gsub("'", "&#39;", text)
  return(text)
}

cat("✅ Documentation Integration loaded\n")
cat("📚 Available endpoints:\n")
cat("  - GET  /docs (Main documentation page with enhanced Swagger UI)\n")
cat("  - GET  /docs/openapi (OpenAPI 3.0 specification)\n")
cat("  - GET  /docs/academic-guide (Academic research workflow guide)\n")
cat("  - GET  /docs/auth-guide (Authentication and rate limiting guide)\n")
cat("  - GET  /docs/examples (Interactive examples and tutorials)\n")
cat("  - GET  /docs/status (Documentation system status)\n")
cat("  - GET  /docs/assets/<file> (Documentation assets)\n")

# Integration status
integration_status <- list(
  components_available = list(
    openapi_spec = file.exists(DOCS_CONFIG$openapi_spec_path),
    academic_guide = file.exists(DOCS_CONFIG$academic_guide_path),
    auth_guide = file.exists(DOCS_CONFIG$auth_guide_path),
    swagger_ui = exists("generate_enhanced_swagger_html"),
    examples = exists("create_realistic_examples_database")
  ),
  version = DOCS_CONFIG$version,
  ready = TRUE
)

cat("📊 Integration Status:\n")
for (component in names(integration_status$components_available)) {
  status <- if (integration_status$components_available[[component]]) "✅" else "❌"
  cat("  ", status, component, "\n")
}