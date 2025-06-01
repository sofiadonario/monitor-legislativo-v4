# ============================================================================
# INTERACTIVE API DOCUMENTATION - WEEK 6 REST API IMPLEMENTATION
# ============================================================================
# 
# Swagger UI integration for comprehensive API documentation
# Provides interactive documentation with Brazilian examples and tutorials
# Includes academic research guides and authentication workflows
# 
# Features:
# - Interactive Swagger UI with Brazilian Portuguese interface
# - Live API testing with authentication
# - Academic research workflow examples
# - Multi-language code examples (R, Python, curl)
# - Citation format previews
# - Export format demonstrations
# ============================================================================

cat("📚 Loading Interactive API Documentation - Week 6\n")

# Documentation configuration
DOCS_CONFIG <- list(
  title = "Monitor Legislativo v4 API - Documentação Interativa",
  description = "Documentação completa da API brasileira para pesquisa legislativa",
  version = "4.0.0-week6",
  base_url = "/api/v1",
  
  # Swagger UI configuration
  swagger_ui = list(
    theme = "light",
    language = "pt-BR",
    default_model_expand_depth = 2,
    default_models_expand_depth = 1,
    display_request_duration = TRUE,
    try_it_out_enabled = TRUE,
    filter = TRUE,
    show_extensions = TRUE,
    show_common_extensions = TRUE
  ),
  
  # Brazilian academic context
  academic_context = list(
    supported_institutions = c("USP", "UNICAMP", "UFRJ", "UFMG", "UnB", "UFRGS", "UFPR", "UFSC"),
    citation_standards = c("ABNT NBR 6023", "APA 7ª Edição", "Chicago", "Vancouver"),
    research_areas = c("Transporte Público", "Mobilidade Urbana", "Política Pública", "Direito Administrativo")
  ),
  
  # Code examples
  code_examples = list(
    r = list(
      search_basic = '
library(httr)
library(jsonlite)

# Configurar autenticação
api_key <- "sua_api_key_aqui"
base_url <- "https://monitor-legislativo-unified-production.up.railway.app/api/v1"

# Buscar documentos sobre transporte público em São Paulo
response <- GET(
  paste0(base_url, "/legislation/search"),
  add_headers("X-API-Key" = api_key),
  query = list(
    q = "transporte público",
    estado = "SP",
    limit = 10
  )
)

# Processar resposta
data <- fromJSON(content(response, "text"))
print(paste("Encontrados", length(data$data), "documentos"))
',
      citation_generation = '
# Gerar citação ABNT para documento específico
citation_response <- GET(
  paste0(base_url, "/citations/generate"),
  add_headers("X-API-Key" = api_key),
  query = list(
    document_id = "LEI_SP_2023_001",
    format = "abnt"
  )
)

citation_data <- fromJSON(content(citation_response, "text"))
cat("Citação ABNT:\\n", citation_data$data$citacao)
'
    ),
    
    python = list(
      search_basic = '
import requests
import json

# Configurar autenticação
api_key = "sua_api_key_aqui"
base_url = "https://monitor-legislativo-unified-production.up.railway.app/api/v1"

# Headers para autenticação
headers = {
    "X-API-Key": api_key,
    "Accept": "application/json"
}

# Buscar documentos sobre transporte público em São Paulo
params = {
    "q": "transporte público",
    "estado": "SP", 
    "limit": 10
}

response = requests.get(f"{base_url}/legislation/search", 
                       headers=headers, 
                       params=params)

if response.status_code == 200:
    data = response.json()
    print(f"Encontrados {len(data[\'data\'])} documentos")
    
    # Exibir títulos dos documentos
    for doc in data["data"]:
        print(f"- {doc[\'titulo\']}")
else:
    print(f"Erro: {response.status_code} - {response.text}")
'
    ),
    
    curl = list(
      search_basic = '
# Buscar documentos sobre transporte público em São Paulo
curl -X GET "https://monitor-legislativo-unified-production.up.railway.app/api/v1/legislation/search?q=transporte%20público&estado=SP&limit=10" \\
  -H "X-API-Key: sua_api_key_aqui" \\
  -H "Accept: application/json"
',
      export_data = '
# Exportar dados em formato CSV
curl -X GET "https://monitor-legislativo-unified-production.up.railway.app/api/v1/export/data?format=csv&estado=SP&ano=2023&limit=100" \\
  -H "X-API-Key: sua_api_key_aqui" \\
  -H "Accept: text/csv" \\
  -o "legislacao_sp_2023.csv"
'
    )
  )
)

# Generate Swagger UI HTML
generate_swagger_ui_html <- function() {
  swagger_html <- paste0('
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>Monitor Legislativo v4 API - Documentação</title>
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
  <link rel="icon" type="image/png" href="https://monitor-legislativo.br/favicon-32x32.png" sizes="32x32" />
  <link rel="icon" type="image/png" href="https://monitor-legislativo.br/favicon-16x16.png" sizes="16x16" />
  <style>
    html {
      box-sizing: border-box;
      overflow: -moz-scrollbars-vertical;
      overflow-y: scroll;
    }
    *, *:before, *:after {
      box-sizing: inherit;
    }
    body {
      margin: 0;
      background: #fafafa;
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Brazilian theme customizations */
    .topbar {
      background-color: #009739 !important; /* Brazilian green */
    }
    
    .swagger-ui .topbar .download-url-button {
      background-color: #FFD700 !important; /* Brazilian yellow */
      color: #000 !important;
    }
    
    .swagger-ui .topbar .link {
      color: #FFD700 !important;
    }
    
    .swagger-ui .scheme-container {
      background: #e8f5e8;
      border: 1px solid #009739;
      border-radius: 4px;
      padding: 10px;
      margin: 20px 0;
    }
    
    /* Custom header styling */
    .api-header {
      background: linear-gradient(135deg, #009739, #00b04f);
      color: white;
      padding: 20px;
      margin-bottom: 20px;
      border-radius: 8px;
    }
    
    .api-header h1 {
      margin: 0;
      font-size: 2.2em;
      font-weight: 300;
    }
    
    .api-header .subtitle {
      margin: 10px 0 0 0;
      font-size: 1.1em;
      opacity: 0.9;
    }
    
    .api-stats {
      display: flex;
      gap: 30px;
      margin-top: 15px;
      flex-wrap: wrap;
    }
    
    .stat-item {
      background: rgba(255,255,255,0.1);
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 0.9em;
    }
    
    .quick-start {
      background: #f8f9fa;
      border: 1px solid #dee2e6;
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
    }
    
    .quick-start h3 {
      color: #009739;
      margin-top: 0;
    }
    
    .code-example {
      background: #f1f3f4;
      border: 1px solid #dadce0;
      border-radius: 4px;
      padding: 12px;
      font-family: "Consolas", "Monaco", monospace;
      font-size: 0.9em;
      overflow-x: auto;
    }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  
  <!-- Custom header -->
  <script>
    // Add custom header after Swagger UI loads
    setTimeout(function() {
      const swaggerContainer = document.getElementById("swagger-ui");
      if (swaggerContainer) {
        const headerHTML = `
          <div class="api-header">
            <h1>🏛️ Monitor Legislativo v4 API</h1>
            <p class="subtitle">Sistema Brasileiro de Monitoramento Legislativo - API REST Acadêmica</p>
            <div class="api-stats">
              <div class="stat-item">📊 134.000+ Documentos</div>
              <div class="stat-item">🗺️ 27 Estados + DF</div>
              <div class="stat-item">📚 Citações ABNT</div>
              <div class="stat-item">🔍 Busca Avançada</div>
              <div class="stat-item">📈 Análise Geográfica</div>
            </div>
          </div>
          
          <div class="quick-start">
            <h3>🚀 Início Rápido</h3>
            <p><strong>1. Obtenha sua API Key:</strong> Registre-se no portal acadêmico</p>
            <p><strong>2. Teste uma busca:</strong></p>
            <div class="code-example">curl -H "X-API-Key: sua_chave" "', DOCS_CONFIG$base_url, '/legislation/search?q=transporte&estado=SP"</div>
            <p><strong>3. Explore os endpoints abaixo</strong> usando a interface interativa</p>
          </div>
        `;
        
        swaggerContainer.innerHTML = headerHTML + swaggerContainer.innerHTML;
      }
    }, 1000);
  </script>

  <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
  <script>
    window.onload = function() {
      const ui = SwaggerUIBundle({
        url: "', DOCS_CONFIG$base_url, '/docs/openapi.yaml",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        
        // Brazilian Portuguese customization
        defaultModelsExpandDepth: ', DOCS_CONFIG$swagger_ui$default_models_expand_depth, ',
        defaultModelExpandDepth: ', DOCS_CONFIG$swagger_ui$default_model_expand_depth, ',
        displayRequestDuration: ', tolower(DOCS_CONFIG$swagger_ui$display_request_duration), ',
        tryItOutEnabled: ', tolower(DOCS_CONFIG$swagger_ui$try_it_out_enabled), ',
        filter: ', tolower(DOCS_CONFIG$swagger_ui$filter), ',
        showExtensions: ', tolower(DOCS_CONFIG$swagger_ui$show_extensions), ',
        showCommonExtensions: ', tolower(DOCS_CONFIG$swagger_ui$show_common_extensions), ',
        
        // Custom request interceptor for Brazilian context
        requestInterceptor: function(req) {
          // Add custom headers
          req.headers["Accept-Language"] = "pt-BR,pt;q=0.9,en;q=0.8";
          req.headers["X-Client"] = "SwaggerUI-MonitorLegislativo";
          return req;
        },
        
        // Custom response interceptor
        responseInterceptor: function(res) {
          // Log API usage for documentation
          console.log("API Response:", res.status, res.url);
          return res;
        },
        
        // Custom validation
        onComplete: function() {
          console.log("Monitor Legislativo API Documentation loaded successfully");
          
          // Add Brazilian academic context tooltips
          setTimeout(function() {
            addBrazilianTooltips();
          }, 2000);
        }
      });
      
      window.ui = ui;
    }
    
    // Add Brazilian academic context tooltips
    function addBrazilianTooltips() {
      const endpoints = document.querySelectorAll(".opblock-summary");
      endpoints.forEach(function(endpoint) {
        const pathElement = endpoint.querySelector(".opblock-summary-path");
        if (pathElement) {
          const path = pathElement.textContent;
          
          // Add contextual help for Brazilian researchers
          if (path.includes("legislation")) {
            endpoint.setAttribute("title", "Busca em 134k+ documentos legislativos brasileiros");
          } else if (path.includes("geographic")) {
            endpoint.setAttribute("title", "Análise geográfica com dados IBGE integrados");
          } else if (path.includes("citations")) {
            endpoint.setAttribute("title", "Citações acadêmicas conforme ABNT NBR 6023");
          } else if (path.includes("export")) {
            endpoint.setAttribute("title", "Exportação para Excel, R, Python e LaTeX");
          }
        }
      });
    }
  </script>
</body>
</html>
  ')
  
  return(swagger_html)
}

# Academic guide content
generate_academic_guide <- function() {
  guide_content <- list(
    title = "Guia Acadêmico - Monitor Legislativo API",
    sections = list(
      introducao = list(
        title = "Introdução para Pesquisadores",
        content = "A API do Monitor Legislativo v4 foi desenvolvida especificamente para pesquisadores acadêmicos brasileiros que estudam políticas públicas de transporte e mobilidade urbana. Com acesso a mais de 134.000 documentos legislativos autênticos, a API oferece ferramentas sofisticadas para análise quantitativa e qualitativa.",
        highlights = c(
          "Dados verificados e validados academicamente",
          "Cobertura nacional completa (27 estados + DF)",
          "Período histórico desde a Constituição de 1988",
          "Integração com padrões brasileiros (ABNT, IBGE)"
        )
      ),
      
      fluxo_pesquisa = list(
        title = "Fluxo de Pesquisa Recomendado",
        steps = list(
          list(
            step = 1,
            title = "Definição do Escopo",
            description = "Defina os parâmetros da pesquisa: período, região, tipo de documento",
            api_endpoints = c("/legislation/types", "/legislation/states"),
            example = 'GET /legislation/states  # Ver estados disponíveis'
          ),
          list(
            step = 2,
            title = "Busca Exploratória", 
            description = "Realize buscas iniciais para entender o volume e qualidade dos dados",
            api_endpoints = c("/legislation/search"),
            example = 'GET /legislation/search?q=transporte&estado=SP&limit=10'
          ),
          list(
            step = 3,
            title = "Análise Quantitativa",
            description = "Use endpoints de análise geográfica e temporal para identificar padrões",
            api_endpoints = c("/geographic/analysis"),
            example = 'GET /geographic/analysis?level=state&metric=density'
          ),
          list(
            step = 4,
            title = "Coleta de Dados",
            description = "Exporte os dados relevantes nos formatos adequados para análise",
            api_endpoints = c("/export/data"),
            example = 'GET /export/data?format=csv&estado=SP&year_start=2018'
          ),
          list(
            step = 5,
            title = "Citação Acadêmica",
            description = "Gere citações conforme padrões acadêmicos brasileiros",
            api_endpoints = c("/citations/generate"),
            example = 'GET /citations/generate?document_id=LEI_SP_2023_001&format=abnt'
          )
        )
      ),
      
      metodologia = list(
        title = "Metodologia de Pesquisa com a API",
        content = "Esta seção apresenta metodologias comprovadas para pesquisa acadêmica usando a API do Monitor Legislativo.",
        approaches = list(
          quantitativa = list(
            title = "Abordagem Quantitativa",
            description = "Análise estatística de grandes volumes de dados legislativos",
            tools = c("R", "Python", "SPSS", "Stata"),
            techniques = c(
              "Análise de séries temporais da produção legislativa",
              "Análise de clusters geográficos",
              "Regressões múltiplas com variáveis institucionais",
              "Network analysis de citações entre documentos"
            )
          ),
          qualitativa = list(
            title = "Abordagem Qualitativa",
            description = "Análise de conteúdo e discourse analysis",
            tools = c("NVivo", "Atlas.ti", "R (tm package)"),
            techniques = c(
              "Análise de conteúdo categorial",
              "Análise do discurso político",
              "Topic modeling com LDA",
              "Análise de redes semânticas"
            )
          )
        )
      ),
      
      exemplos_pesquisa = list(
        title = "Exemplos de Pesquisa Acadêmica",
        cases = list(
          dissertacao_mestrado = list(
            title = "Dissertação: Evolução das Políticas de Transporte Público",
            objective = "Analisar a evolução das políticas municipais de transporte público no estado de São Paulo entre 2010-2020",
            methodology = list(
              "1. Coleta de dados: Leis e decretos municipais sobre transporte",
              "2. Análise temporal: Identificação de tendências por período",
              "3. Análise geográfica: Comparação entre municípios",
              "4. Análise de conteúdo: Categorização temática das políticas"
            ),
            api_usage = list(
              search = 'GET /legislation/search?tipo=lei&estado=SP&year_start=2010&year_end=2020&q=transporte público',
              geographic = 'GET /geographic/analysis?level=municipality&estado=SP',
              export = 'GET /export/data?format=excel&estado=SP&tipo=lei&year_start=2010&year_end=2020',
              citations = 'GET /citations/batch (para bibliografia)'
            )
          ),
          
          tese_doutorado = list(
            title = "Tese: Federalismo e Políticas de Mobilidade Urbana",
            objective = "Comparar as abordagens regionais para mobilidade urbana sustentável no Brasil",
            methodology = list(
              "1. Análise comparativa inter-regional",
              "2. Identificação de inovações políticas",
              "3. Mapeamento de difusão de políticas",
              "4. Análise de network governance"
            ),
            api_usage = list(
              regional = 'GET /geographic/analysis?level=region&metric=distribution',
              temporal = 'GET /geographic/temporal?period=yearly&year_start=2015',
              innovation_tracking = 'GET /legislation/search?q=inovação OR sustentabilidade&limit=1000'
            )
          )
        )
      ),
      
      boas_praticas = list(
        title = "Boas Práticas Acadêmicas",
        guidelines = list(
          reproducibility = list(
            title = "Reprodutibilidade",
            practices = c(
              "Documente todas as queries da API usadas",
              "Registre as datas de coleta dos dados",
              "Use controle de versão para scripts de análise",
              "Mantenha logs de todas as requisições à API"
            )
          ),
          ethics = list(
            title = "Ética em Pesquisa",
            practices = c(
              "Respeite os limites de taxa da API",
              "Cite adequadamente a fonte dos dados",
              "Siga as diretrizes LGPD para proteção de dados",
              "Obtenha aprovação do comitê de ética quando necessário"
            )
          ),
          quality = list(
            title = "Qualidade dos Dados",
            practices = c(
              "Valide a completude dos dados coletados",
              "Verifique a consistência temporal",
              "Documente limitações e vieses conhecidos",
              "Use triangulação com outras fontes quando possível"
            )
          )
        )
      ),
      
      recursos_adicionais = list(
        title = "Recursos Adicionais",
        links = list(
          "Documentação ABNT NBR 6023" = "https://www.abnt.org.br/normalizacao/abnt-nbr/nbr-6023",
          "Portal IBGE Cidades" = "https://cidades.ibge.gov.br",
          "Lei de Acesso à Informação" = "http://www.acessoainformacao.gov.br",
          "LGPD - Lei Geral de Proteção de Dados" = "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm"
        ),
        academic_support = list(
          email = "suporte-academico@monitor-legislativo.br",
          office_hours = "Segundas e quartas, 14h-17h (horário de Brasília)",
          webinars = "Mensais, sempre na primeira quinta-feira do mês",
          slack = "monitor-legislativo-research.slack.com"
        )
      )
    )
  )
  
  return(guide_content)
}

# Endpoints for documentation

#' @get /api/v1/docs
#' @tag system
#' @serializer html
function(req, res) {
  res$setHeader("Content-Type", "text/html; charset=utf-8")
  return(generate_swagger_ui_html())
}

#' @get /api/v1/docs/openapi
#' @tag system
#' @serializer yaml
function(req, res) {
  # Return the OpenAPI specification
  if (file.exists("api/openapi-enhanced-week6.yaml")) {
    spec_content <- readLines("api/openapi-enhanced-week6.yaml")
    res$setHeader("Content-Type", "application/x-yaml")
    return(paste(spec_content, collapse = "\n"))
  } else {
    res$status <- 404
    return(list(error = TRUE, message = "OpenAPI specification not found"))
  }
}

#' @get /api/v1/docs/academic-guide
#' @tag system
#' @serializer unboxedJSON
function(req, res) {
  guide <- generate_academic_guide()
  
  return(list(
    error = FALSE,
    message = "Guia acadêmico para pesquisadores",
    data = guide,
    timestamp = Sys.time()
  ))
}

#' @get /api/v1/docs/examples
#' @tag system
#' @serializer unboxedJSON
function(req, res) {
  
  # Get language parameter
  language <- req$args$language %||% "all"
  
  examples <- if (language == "all") {
    DOCS_CONFIG$code_examples
  } else if (language %in% names(DOCS_CONFIG$code_examples)) {
    list(DOCS_CONFIG$code_examples[[language]])
    names(list(DOCS_CONFIG$code_examples[[language]])) <- language
    list(DOCS_CONFIG$code_examples[[language]])
  } else {
    list()
  }
  
  return(list(
    error = FALSE,
    message = "Exemplos de código para integração com a API",
    data = list(
      available_languages = names(DOCS_CONFIG$code_examples),
      examples = examples,
      academic_context = DOCS_CONFIG$academic_context
    ),
    meta = list(
      language_filter = language,
      total_examples = length(unlist(examples, recursive = FALSE))
    ),
    timestamp = Sys.time()
  ))
}

#' @get /api/v1/docs/status
#' @tag system
#' @serializer unboxedJSON
function(req, res) {
  
  # Documentation system status
  docs_status <- list(
    status = "operational",
    components = list(
      swagger_ui = list(
        status = "available",
        version = "4.15.5",
        url = "/api/v1/docs"
      ),
      openapi_spec = list(
        status = if (file.exists("api/openapi-enhanced-week6.yaml")) "available" else "missing",
        version = "3.0.3",
        url = "/api/v1/docs/openapi"
      ),
      academic_guide = list(
        status = "available",
        sections = length(generate_academic_guide()$sections),
        url = "/api/v1/docs/academic-guide"
      ),
      code_examples = list(
        status = "available",
        languages = length(DOCS_CONFIG$code_examples),
        url = "/api/v1/docs/examples"
      )
    ),
    
    statistics = list(
      total_endpoints_documented = length(c("health", "status", "legislation/search", "geographic/analysis", "citations/generate", "export/data")),
      code_examples_count = length(unlist(DOCS_CONFIG$code_examples, recursive = FALSE)),
      supported_languages = names(DOCS_CONFIG$code_examples),
      academic_institutions = length(DOCS_CONFIG$academic_context$supported_institutions)
    ),
    
    last_updated = Sys.time(),
    version = DOCS_CONFIG$version
  )
  
  return(list(
    error = FALSE,
    message = "Status do sistema de documentação",
    data = docs_status,
    timestamp = Sys.time()
  ))
}

cat("✅ Interactive API Documentation loaded successfully\n")
cat("📚 Features: Swagger UI • Academic guides • Code examples • Brazilian context\n")
cat("🔗 Endpoints: /docs • /docs/openapi • /docs/academic-guide • /docs/examples\n")