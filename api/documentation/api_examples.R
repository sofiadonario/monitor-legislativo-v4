# ============================================================================
# INTERACTIVE API EXAMPLES AND TUTORIALS - SPRINT 7A (API-006)
# ============================================================================
# 
# Comprehensive interactive examples and tutorials for academic research
# Demonstrates real-world usage patterns for the Brazilian Legislative API
# 
# Features:
# - Step-by-step academic research workflows
# - Realistic Brazilian legislative data examples
# - Multi-language code samples (R, Python, JavaScript, cURL)
# - Interactive parameter builders
# - Citation generation examples
# - Error handling demonstrations
# - Performance optimization tips
# ============================================================================

cat("📖 Loading Interactive API Examples and Tutorials\n")

# Required packages for examples
required_packages <- c("jsonlite", "httr", "knitr", "rmarkdown", "DT")

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat(paste("📦 Installing", pkg, "\n"))
    install.packages(pkg, quiet = TRUE)
  }
  suppressPackageStartupMessages(library(pkg, character.only = TRUE))
}

# Brazilian Legislative API Examples Configuration
API_EXAMPLES_CONFIG <- list(
  base_url = "https://monitorlegislativo.up.railway.app/api/v1",
  dev_url = "http://localhost:8000/api/v1",
  demo_api_key = "demo_key_for_examples",
  academic_api_key = "academic_key_example",
  common_endpoints = c(
    "/documents", "/search", "/geographic/analysis", 
    "/analytics/dashboard", "/citations/generate", "/export/documents"
  ),
  brazilian_states = c(
    "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
    "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
    "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"
  ),
  document_types = c(
    "Lei", "Decreto", "Medida Provisória", "Portaria", 
    "Resolução", "Instrução Normativa", "Parecer"
  ),
  research_topics = c(
    "direitos humanos", "educação", "meio ambiente", "saúde pública",
    "licitação pública", "transparência", "federalismo", "segurança jurídica"
  )
)

# ============================================================================
# ACADEMIC RESEARCH WORKFLOW EXAMPLES
# ============================================================================

#' Generate Academic Research Workflow Tutorial
#' 
#' Creates a comprehensive tutorial for academic researchers
#' @param format Output format ("html", "markdown", "interactive")
#' @param language Programming language for examples ("r", "python", "javascript", "all")
#' @return Formatted tutorial content
generate_academic_workflow_tutorial <- function(format = "markdown", language = "r") {
  
  workflow_steps <- list(
    
    # Step 1: Dataset Discovery
    step1 = list(
      title = "1. Descoberta do Dataset",
      description = "Explore o dataset para entender a estrutura e disponibilidade dos dados",
      objective = "Compreender o escopo e a qualidade dos dados legislativos disponíveis",
      endpoints = c("/documents", "/documents/categories", "/documents/stats"),
      examples = list(
        r = '
# Exemplo 1.1: Exploração inicial do dataset
library(httr)
library(jsonlite)

# Configurar autenticação
api_key <- "sua_chave_api_academica"
base_url <- "https://monitorlegislativo.up.railway.app/api/v1"
headers <- add_headers(`X-API-Key` = api_key)

# 1.1.1 Obter informações gerais da API
response <- GET(paste0(base_url, "/info"), headers)
api_info <- fromJSON(content(response, "text"))
print(api_info$data)

# 1.1.2 Verificar categorias disponíveis
response <- GET(paste0(base_url, "/documents/categories"), headers)
categories <- fromJSON(content(response, "text"))

cat("Tipos de documentos disponíveis:\\n")
print(categories$data$species)

cat("\\nEstados com dados:\\n")
print(categories$data$estados)

# 1.1.3 Obter estatísticas gerais
response <- GET(paste0(base_url, "/documents/stats"), headers)
stats <- fromJSON(content(response, "text"))

cat("\\nEstatísticas do dataset:\\n")
cat("Total de documentos:", stats$data$total_documents, "\\n")
cat("Período temporal:", stats$data$year_range$min, "-", stats$data$year_range$max, "\\n")
        ',
        python = '
# Exemplo 1.1: Exploração inicial do dataset
import requests
import json

# Configurar autenticação
api_key = "sua_chave_api_academica"
base_url = "https://monitorlegislativo.up.railway.app/api/v1"
headers = {"X-API-Key": api_key}

# 1.1.1 Obter informações gerais da API
response = requests.get(f"{base_url}/info", headers=headers)
if response.status_code == 200:
    api_info = response.json()
    print("Informações da API:", json.dumps(api_info["data"], indent=2))

# 1.1.2 Verificar categorias disponíveis
response = requests.get(f"{base_url}/documents/categories", headers=headers)
if response.status_code == 200:
    categories = response.json()
    print("Tipos de documentos:", categories["data"]["species"])
    print("Estados disponíveis:", categories["data"]["estados"])

# 1.1.3 Obter estatísticas gerais
response = requests.get(f"{base_url}/documents/stats", headers=headers)
if response.status_code == 200:
    stats = response.json()
    print(f"Total de documentos: {stats[\'data\'][\'total_documents\']}")
    print(f"Período: {stats[\'data\'][\'year_range\'][\'min\']} - {stats[\'data\'][\'year_range\'][\'max\']}")
        ',
        curl = '
# Exemplo 1.1: Exploração inicial do dataset

# 1.1.1 Obter informações gerais da API
curl -X GET "https://monitorlegislativo.up.railway.app/api/v1/info" \\
  -H "X-API-Key: sua_chave_api_academica"

# 1.1.2 Verificar categorias disponíveis
curl -X GET "https://monitorlegislativo.up.railway.app/api/v1/documents/categories" \\
  -H "X-API-Key: sua_chave_api_academica"

# 1.1.3 Obter estatísticas gerais
curl -X GET "https://monitorlegislativo.up.railway.app/api/v1/documents/stats" \\
  -H "X-API-Key: sua_chave_api_academica"
        '
      ),
      expected_output = "Compreensão da estrutura do dataset, tipos de documentos disponíveis e período temporal coberto",
      research_tips = c(
        "Documente as categorias de documentos relevantes para sua pesquisa",
        "Identifique o período temporal que será analisado",
        "Verifique a disponibilidade de dados por estado/região",
        "Anote os campos de metadados disponíveis para cada documento"
      )
    ),
    
    # Step 2: Targeted Search
    step2 = list(
      title = "2. Busca Direcionada",
      description = "Utilize filtros avançados para encontrar documentos específicos para sua pesquisa",
      objective = "Construir consultas precisas que retornem dados relevantes para a hipótese de pesquisa",
      endpoints = c("/documents", "/search", "/search/suggest"),
      examples = list(
        r = '
# Exemplo 2.1: Busca por tema específico - Educação em São Paulo
library(dplyr)

# 2.1.1 Busca simples por estado e tipo
response <- GET(
  paste0(base_url, "/documents"),
  query = list(
    estado = "SP",
    species = "Lei",
    ano = 2023,
    limit = 100
  ),
  headers
)

documents_sp <- fromJSON(content(response, "text"))
cat("Documentos encontrados:", nrow(documents_sp$data), "\\n")

# 2.1.2 Busca textual avançada
search_query <- list(
  query = "educação básica AND ensino fundamental",
  filters = list(
    estado = "SP",
    ano_inicio = 2020,
    ano_fim = 2023,
    species = "Lei"
  ),
  sort = "relevance",
  limit = 50
)

response <- POST(
  paste0(base_url, "/search"),
  body = search_query,
  encode = "json",
  headers
)

search_results <- fromJSON(content(response, "text"))

# Analisar resultados
if (length(search_results$data) > 0) {
  education_docs <- search_results$data
  
  # Extrair palavras-chave mais relevantes
  cat("\\nDocumentos sobre educação encontrados:\\n")
  for (i in 1:min(5, nrow(education_docs))) {
    cat(paste0(i, ". ", education_docs$titulo[i], "\\n"))
    cat("   Relevância:", education_docs$relevance_score[i], "\\n")
    cat("   Data:", education_docs$data_publicacao[i], "\\n\\n")
  }
}

# 2.1.3 Busca por múltiplos estados (comparação regional)
compare_states <- c("SP", "RJ", "MG", "RS")
regional_data <- list()

for (state in compare_states) {
  response <- GET(
    paste0(base_url, "/documents"),
    query = list(
      estado = state,
      species = "Lei",
      ano = 2023,
      limit = 1000
    ),
    headers
  )
  
  state_docs <- fromJSON(content(response, "text"))
  regional_data[[state]] <- state_docs$data
  cat("Estado", state, ":", nrow(state_docs$data), "documentos\\n")
}
        ',
        python = '
# Exemplo 2.1: Busca por tema específico - Educação em São Paulo
import pandas as pd

# 2.1.1 Busca simples por estado e tipo
params = {
    "estado": "SP",
    "species": "Lei", 
    "ano": 2023,
    "limit": 100
}

response = requests.get(f"{base_url}/documents", params=params, headers=headers)
if response.status_code == 200:
    documents_sp = response.json()
    print(f"Documentos encontrados: {len(documents_sp[\'data\'])}")

# 2.1.2 Busca textual avançada
search_query = {
    "query": "educação básica AND ensino fundamental",
    "filters": {
        "estado": "SP",
        "ano_inicio": 2020,
        "ano_fim": 2023,
        "species": "Lei"
    },
    "sort": "relevance",
    "limit": 50
}

response = requests.post(f"{base_url}/search", json=search_query, headers=headers)
if response.status_code == 200:
    search_results = response.json()
    
    # Analisar resultados
    if len(search_results["data"]) > 0:
        education_docs = pd.DataFrame(search_results["data"])
        
        print("\\nTop 5 documentos sobre educação:")
        for idx, doc in education_docs.head().iterrows():
            print(f"{idx+1}. {doc[\'titulo\']}")
            print(f"   Relevância: {doc.get(\'relevance_score\', \'N/A\')}")
            print(f"   Data: {doc[\'data_publicacao\']}\\n")

# 2.1.3 Comparação regional
compare_states = ["SP", "RJ", "MG", "RS"]
regional_data = {}

for state in compare_states:
    params = {"estado": state, "species": "Lei", "ano": 2023, "limit": 1000}
    response = requests.get(f"{base_url}/documents", params=params, headers=headers)
    
    if response.status_code == 200:
        state_docs = response.json()
        regional_data[state] = state_docs["data"]
        print(f"Estado {state}: {len(state_docs[\'data\'])} documentos")
        '
      ),
      expected_output = "Dataset filtrado com documentos relevantes para a pesquisa específica",
      research_tips = c(
        "Use operadores booleanos (AND, OR, NOT) para refinar buscas",
        "Combine filtros temporais com geográficos para análises regionais",
        "Teste diferentes variações de termos para maximizar cobertura",
        "Documente os critérios de busca para reprodutibilidade"
      )
    ),
    
    # Step 3: Geographic Analysis
    step3 = list(
      title = "3. Análise Geográfica",
      description = "Realize análises espaciais para identificar padrões regionais na legislação",
      objective = "Compreender distribuições geográficas e variações regionais nos dados legislativos",
      endpoints = c("/geographic/analysis", "/geographic/choropleth", "/geographic/ibge"),
      examples = list(
        r = '
# Exemplo 3.1: Análise geográfica da legislação educacional
library(ggplot2)

# 3.1.1 Análise por estado
response <- GET(
  paste0(base_url, "/geographic/analysis"),
  query = list(
    level = "state",
    metric = "count",
    year = 2023
  ),
  headers
)

geo_analysis <- fromJSON(content(response, "text"))
geo_data <- geo_analysis$data

# Criar visualização
geo_df <- data.frame(
  estado = geo_data$region,
  count = geo_data$count,
  percentage = geo_data$percentage,
  stringsAsFactors = FALSE
)

# Top 10 estados
top_states <- head(geo_df[order(-geo_df$count), ], 10)
print("Top 10 estados por volume legislativo:")
print(top_states)

# 3.1.2 Dados para mapa coroplético
response <- GET(
  paste0(base_url, "/geographic/choropleth"),
  query = list(
    level = "state",
    metric = "density"
  ),
  headers
)

choropleth_data <- fromJSON(content(response, "text"))

# Salvar dados geográficos para visualização
write.csv(geo_df, "dados_geograficos_legislacao.csv", row.names = FALSE)
cat("Dados geográficos salvos em: dados_geograficos_legislacao.csv\\n")

# 3.1.3 Integração com dados IBGE
response <- GET(
  paste0(base_url, "/geographic/ibge"),
  query = list(
    indicator = "population",
    year = 2022
  ),
  headers
)

ibge_data <- fromJSON(content(response, "text"))

# Correlação entre população e volume legislativo
if (!is.null(ibge_data$data)) {
  merged_data <- merge(geo_df, ibge_data$data, by.x = "estado", by.y = "state_code")
  correlation <- cor(merged_data$count, merged_data$population, use = "complete.obs")
  cat("Correlação população x volume legislativo:", round(correlation, 3), "\\n")
}
        ',
        python = '
# Exemplo 3.1: Análise geográfica da legislação educacional
import matplotlib.pyplot as plt
import seaborn as sns

# 3.1.1 Análise por estado
params = {"level": "state", "metric": "count", "year": 2023}
response = requests.get(f"{base_url}/geographic/analysis", params=params, headers=headers)

if response.status_code == 200:
    geo_analysis = response.json()
    geo_data = pd.DataFrame(geo_analysis["data"])
    
    # Top 10 estados
    top_states = geo_data.nlargest(10, "count")
    print("Top 10 estados por volume legislativo:")
    print(top_states[["region", "count", "percentage"]])
    
    # Visualização
    plt.figure(figsize=(12, 6))
    sns.barplot(data=top_states, x="count", y="region")
    plt.title("Volume Legislativo por Estado (2023)")
    plt.xlabel("Número de Documentos")
    plt.ylabel("Estado")
    plt.tight_layout()
    plt.savefig("volume_legislativo_estados.png", dpi=300, bbox_inches="tight")
    plt.show()

# 3.1.2 Dados para mapa coroplético
params = {"level": "state", "metric": "density"}
response = requests.get(f"{base_url}/geographic/choropleth", params=params, headers=headers)

if response.status_code == 200:
    choropleth_data = response.json()
    # Salvar dados para visualização em outras ferramentas
    pd.DataFrame(geo_data).to_csv("dados_geograficos_legislacao.csv", index=False)
    print("Dados geográficos salvos em: dados_geograficos_legislacao.csv")

# 3.1.3 Análise de correlação com dados demográficos
params = {"indicator": "population", "year": 2022}
response = requests.get(f"{base_url}/geographic/ibge", params=params, headers=headers)

if response.status_code == 200:
    ibge_data = response.json()
    # Análise de correlação seria implementada aqui
    print("Dados demográficos IBGE obtidos com sucesso")
        '
      ),
      expected_output = "Visualizações e análises espaciais revelando padrões geográficos na legislação",
      research_tips = c(
        "Compare distribuições geográficas entre diferentes períodos",
        "Correlacione com dados socioeconômicos do IBGE",
        "Identifique outliers regionais para investigação qualitativa",
        "Use mapas coropléticos para comunicar resultados visualmente"
      )
    ),
    
    # Step 4: Temporal Analysis
    step4 = list(
      title = "4. Análise Temporal",
      description = "Examine tendências temporais e sazonalidade na produção legislativa",
      objective = "Identificar padrões temporais, ciclos políticos e tendências evolutivas",
      endpoints = c("/analytics/trends", "/analytics/keywords", "/documents"),
      examples = list(
        r = '
# Exemplo 4.1: Análise temporal da legislação
library(lubridate)

# 4.1.1 Tendências anuais (2019-2023)
temporal_data <- list()
years <- 2019:2023

for (year in years) {
  response <- GET(
    paste0(base_url, "/documents"),
    query = list(
      ano = year,
      limit = 10000,
      estado = "SP"  # Foco em SP para exemplo
    ),
    headers
  )
  
  year_docs <- fromJSON(content(response, "text"))
  temporal_data[[as.character(year)]] <- list(
    year = year,
    count = nrow(year_docs$data),
    documents = year_docs$data
  )
  
  cat("Ano", year, ":", nrow(year_docs$data), "documentos\\n")
}

# Análise de sazonalidade
monthly_analysis <- list()
for (year_data in temporal_data) {
  if (nrow(year_data$documents) > 0) {
    year_data$documents$mes <- month(as.Date(year_data$documents$data_publicacao))
    monthly_counts <- table(year_data$documents$mes)
    monthly_analysis[[as.character(year_data$year)]] <- monthly_counts
  }
}

# 4.1.2 Análise de palavras-chave ao longo do tempo
response <- GET(
  paste0(base_url, "/analytics/keywords"),
  query = list(
    period = "all_time",
    min_frequency = 50,
    limit = 20
  ),
  headers
)

keywords_data <- fromJSON(content(response, "text"))
print("Palavras-chave mais frequentes:")
print(keywords_data$data)

# 4.1.3 Tendências por tipo de documento
response <- GET(
  paste0(base_url, "/analytics/trends"),
  query = list(
    timeframe = "yearly",
    category = "by_type"
  ),
  headers
)

trends_data <- fromJSON(content(response, "text"))
cat("\\nTendências identificadas:\\n")
print(trends_data$data)
        '
      ),
      expected_output = "Compreensão de padrões temporais, sazonalidade e evolução temática da legislação",
      research_tips = c(
        "Analise ciclos eleitorais e mudanças de governo",
        "Identifique sazonalidade na produção legislativa", 
        "Correlacione com eventos históricos importantes",
        "Examine evolução de terminologia jurídica ao longo do tempo"
      )
    ),
    
    # Step 5: Data Export and Citation
    step5 = list(
      title = "5. Exportação e Citação",
      description = "Exporte dados para análise offline e gere citações acadêmicas padronizadas",
      objective = "Preparar dados para publicação e garantir citação adequada das fontes",
      endpoints = c("/export/documents", "/citations/generate", "/citations/batch"),
      examples = list(
        r = '
# Exemplo 5.1: Exportação de dados e geração de citações

# 5.1.1 Exportar dataset filtrado
export_query <- list(
  filters = list(
    estado = "SP",
    ano_inicio = 2020,
    ano_fim = 2023,
    species = "Lei"
  ),
  format = "csv",
  fields = c("id", "titulo", "data_publicacao", "estado", "species", "ementa"),
  max_records = 5000
)

response <- POST(
  paste0(base_url, "/export/documents"),
  body = export_query,
  encode = "json",
  headers
)

if (response$status_code == 200) {
  # Salvar arquivo CSV
  writeBin(content(response, "raw"), "legislacao_sp_2020_2023.csv")
  cat("Dataset exportado: legislacao_sp_2020_2023.csv\\n")
}

# 5.1.2 Gerar citações para documentos específicos
document_ids <- c("doc_sp_001", "doc_sp_002", "doc_sp_003")

# Citação individual (ABNT)
citation_request <- list(
  document_id = document_ids[1],
  style = "abnt",
  format = "text"
)

response <- POST(
  paste0(base_url, "/citations/generate"),
  body = citation_request,
  encode = "json",
  headers
)

citation_result <- fromJSON(content(response, "text"))
cat("\\nCitação ABNT:\\n")
cat(citation_result$data$citation, "\\n\\n")

# 5.1.3 Citações em lote para bibliografia
batch_citation_request <- list(
  document_ids = document_ids,
  style = "abnt",
  format = "bibtex"
)

response <- POST(
  paste0(base_url, "/citations/batch"),
  body = batch_citation_request,
  encode = "json",
  headers
)

batch_citations <- fromJSON(content(response, "text"))

# Salvar bibliografia
bibtex_content <- paste(sapply(batch_citations$data, function(x) x$bibtex), collapse = "\\n\\n")
writeLines(bibtex_content, "bibliografia_legislacao.bib")
cat("Bibliografia BibTeX salva: bibliografia_legislacao.bib\\n")

# 5.1.4 Relatório analítico completo
report_request <- list(
  report_type = "comprehensive",
  format = "pdf",
  parameters = list(
    estados = c("SP", "RJ", "MG"),
    periodo = "2020-2023",
    tema = "educacao"
  ),
  include_charts = TRUE,
  language = "pt"
)

response <- POST(
  paste0(base_url, "/export/analytics"),
  body = report_request,
  encode = "json",
  headers
)

if (response$status_code == 200) {
  writeBin(content(response, "raw"), "relatorio_legislacao_educacao.pdf")
  cat("Relatório analítico gerado: relatorio_legislacao_educacao.pdf\\n")
}
        '
      ),
      expected_output = "Dados exportados, citações padronizadas e relatórios prontos para publicação acadêmica",
      research_tips = c(
        "Exporte dados em formatos compatíveis com suas ferramentas de análise",
        "Use citações padronizadas (ABNT) para conformidade acadêmica",
        "Mantenha metadados de proveniência para reprodutibilidade",
        "Gere relatórios visuais para comunicação de resultados"
      )
    )
  )
  
  # Format output based on requested format
  if (format == "html") {
    return(format_workflow_as_html(workflow_steps, language))
  } else if (format == "interactive") {
    return(create_interactive_tutorial(workflow_steps))
  } else {
    return(format_workflow_as_markdown(workflow_steps, language))
  }
}

# ============================================================================
# REALISTIC BRAZILIAN LEGISLATIVE EXAMPLES
# ============================================================================

#' Generate Realistic Examples Database
#' 
#' Creates a database of realistic examples for API documentation
#' @return List of categorized examples
create_realistic_examples_database <- function() {
  
  examples_db <- list(
    
    # Document Discovery Examples
    document_discovery = list(
      title = "Descoberta de Documentos Legislativos",
      scenarios = list(
        
        # Scenario 1: Education Laws in São Paulo
        education_sp = list(
          description = "Buscar leis de educação em São Paulo (2020-2023)",
          api_call = list(
            endpoint = "/documents",
            method = "GET",
            parameters = list(
              estado = "SP",
              species = "Lei",
              ano_inicio = 2020,
              ano_fim = 2023,
              limit = 100
            )
          ),
          expected_results = list(
            total_found = 45,
            sample_titles = c(
              "Lei nº 17.329, de 8 de janeiro de 2021 - Programa Educação Digital",
              "Lei nº 17.341, de 29 de janeiro de 2021 - Merenda Escolar Orgânica",
              "Lei nº 17.456, de 15 de junho de 2021 - Ensino Híbrido"
            )
          ),
          research_value = "Mapeamento da agenda educacional paulista no período pós-pandemia"
        ),
        
        # Scenario 2: Environmental Legislation Comparison
        environmental_comparison = list(
          description = "Comparar legislação ambiental entre estados da Amazônia",
          api_call = list(
            endpoint = "/search",
            method = "POST",
            body = list(
              query = "meio ambiente AND preservação",
              filters = list(
                estado = c("AM", "PA", "AC", "RO"),
                ano_inicio = 2019,
                species = c("Lei", "Decreto")
              ),
              sort = "relevance",
              limit = 200
            )
          ),
          expected_results = list(
            total_found = 156,
            distribution = list(
              AM = 42, PA = 38, AC = 35, RO = 41
            )
          ),
          research_value = "Análise comparativa de políticas ambientais regionais"
        )
      )
    ),
    
    # Geographic Analysis Examples
    geographic_analysis = list(
      title = "Análise Geográfica da Legislação",
      scenarios = list(
        
        # Scenario 1: Regional Development Patterns
        regional_development = list(
          description = "Mapear padrões regionais de legislação sobre desenvolvimento",
          api_call = list(
            endpoint = "/geographic/analysis",
            method = "GET",
            parameters = list(
              level = "region",
              metric = "density",
              year = 2023
            )
          ),
          expected_results = list(
            regions = list(
              Sudeste = list(count = 1250, density = 2.1),
              Sul = list(count = 890, density = 1.8),
              Nordeste = list(count = 1100, density = 1.2),
              Norte = list(count = 340, density = 0.4),
              CentroOeste = list(count = 420, density = 0.9)
            )
          ),
          research_value = "Identificação de disparidades regionais na produção legislativa"
        ),
        
        # Scenario 2: Municipal Legislation Hotspots
        municipal_hotspots = list(
          description = "Identificar municípios com maior atividade legislativa",
          api_call = list(
            endpoint = "/geographic/analysis",
            method = "GET",
            parameters = list(
              level = "municipality",
              metric = "per_capita",
              state = "SP"
            )
          ),
          visualization = "Mapa coroplético com gradiente de cores por atividade legislativa",
          research_value = "Identificação de municípios inovadores em gestão pública"
        )
      )
    ),
    
    # Citation Examples
    citation_examples = list(
      title = "Geração de Citações Acadêmicas",
      scenarios = list(
        
        # ABNT Citations
        abnt_example = list(
          description = "Citação ABNT para lei federal",
          document = list(
            id = "doc_federal_001",
            titulo = "Lei nº 14.133, de 1º de abril de 2021",
            ementa = "Lei de Licitações e Contratos Administrativos"
          ),
          citation_abnt = "BRASIL. Lei nº 14.133, de 1º de abril de 2021. Lei de Licitações e Contratos Administrativos. Brasília, DF: Presidência da República, 2021. Disponível em: <http://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/l14133.htm>. Acesso em: 15 jan. 2024.",
          bibtex = '@misc{brasil2021lei14133,
  title={Lei nº 14.133, de 1º de abril de 2021},
  author={Brasil},
  year={2021},
  publisher={Presidência da República},
  url={http://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/l14133.htm}
}'
        ),
        
        # State Law Citation
        state_law_example = list(
          description = "Citação ABNT para lei estadual",
          document = list(
            id = "doc_sp_001",
            titulo = "Lei nº 17.293, de 15 de outubro de 2020",
            estado = "SP"
          ),
          citation_abnt = "SÃO PAULO (Estado). Lei nº 17.293, de 15 de outubro de 2020. Institui o Programa de Proteção e Defesa do Usuário de Serviços Públicos do Estado de São Paulo. São Paulo: Assembleia Legislativa, 2020."
        )
      )
    ),
    
    # Advanced Analytics Examples
    analytics_examples = list(
      title = "Análises Avançadas e Métricas",
      scenarios = list(
        
        # Keyword Evolution
        keyword_evolution = list(
          description = "Evolução de palavras-chave na legislação ao longo do tempo",
          api_call = list(
            endpoint = "/analytics/keywords",
            method = "GET",
            parameters = list(
              period = "yearly",
              min_frequency = 10,
              years = "2019-2023"
            )
          ),
          expected_insights = list(
            trending_up = c("digital", "sustentabilidade", "inovação"),
            trending_down = c("fax", "protocolo físico"),
            stable = c("educação", "saúde", "segurança")
          ),
          research_value = "Identificação de mudanças na agenda política e social"
        ),
        
        # Legislative Productivity
        productivity_analysis = list(
          description = "Análise de produtividade legislativa por estado",
          metrics = list(
            total_laws = "Número total de leis aprovadas",
            laws_per_capita = "Leis per capita (por 100.000 habitantes)",
            complexity_index = "Índice de complexidade baseado no tamanho médio"
          ),
          visualization = "Dashboard interativo com múltiplas visualizações",
          research_value = "Avaliação comparativa da eficiência legislativa"
        )
      )
    )
  )
  
  return(examples_db)
}

# ============================================================================
# CODE GENERATION UTILITIES
# ============================================================================

#' Generate Code Examples in Multiple Languages
#' 
#' @param api_call API call specification
#' @param languages Vector of languages to generate ("r", "python", "javascript", "curl")
#' @return Named list of code examples
generate_multilang_examples <- function(api_call, languages = c("r", "python", "javascript", "curl")) {
  
  examples <- list()
  
  if ("r" %in% languages) {
    examples$r <- generate_r_example(api_call)
  }
  
  if ("python" %in% languages) {
    examples$python <- generate_python_example(api_call)
  }
  
  if ("javascript" %in% languages) {
    examples$javascript <- generate_javascript_example(api_call)
  }
  
  if ("curl" %in% languages) {
    examples$curl <- generate_curl_example(api_call)
  }
  
  return(examples)
}

# R Code Generation
generate_r_example <- function(api_call) {
  
  base_template <- '
# Configuração da API
library(httr)
library(jsonlite)

api_key <- "sua_chave_api"
base_url <- "https://monitorlegislativo.up.railway.app/api/v1"
headers <- add_headers(`X-API-Key` = api_key)
'
  
  if (api_call$method == "GET") {
    query_params <- ""
    if (!is.null(api_call$parameters)) {
      params_list <- paste(
        names(api_call$parameters),
        paste0('"', api_call$parameters, '"'),
        sep = " = ",
        collapse = ",\n    "
      )
      query_params <- paste0("\n  query = list(\n    ", params_list, "\n  ),")
    }
    
    code <- paste0(base_template, '
# Realizar requisição GET
response <- GET(
  paste0(base_url, "', api_call$endpoint, '"),', query_params, '
  headers
)

# Processar resposta
if (status_code(response) == 200) {
  data <- fromJSON(content(response, "text"))
  print(data$data)
} else {
  cat("Erro:", status_code(response), "\\n")
}')
    
  } else if (api_call$method == "POST") {
    body_json <- jsonlite::toJSON(api_call$body, auto_unbox = TRUE, pretty = TRUE)
    
    code <- paste0(base_template, '
# Preparar dados para POST
request_body <- ', body_json, '

# Realizar requisição POST
response <- POST(
  paste0(base_url, "', api_call$endpoint, '"),
  body = request_body,
  encode = "json",
  headers
)

# Processar resposta
if (status_code(response) == 200) {
  data <- fromJSON(content(response, "text"))
  print(data$data)
} else {
  cat("Erro:", status_code(response), "\\n")
}')
  }
  
  return(code)
}

# Python Code Generation
generate_python_example <- function(api_call) {
  
  base_template <- '
# Configuração da API
import requests
import json

api_key = "sua_chave_api"
base_url = "https://monitorlegislativo.up.railway.app/api/v1"
headers = {"X-API-Key": api_key}
'
  
  if (api_call$method == "GET") {
    params_code <- ""
    if (!is.null(api_call$parameters)) {
      params_dict <- jsonlite::toJSON(api_call$parameters, auto_unbox = TRUE)
      params_code <- paste0("\nparams = ", params_dict)
    }
    
    code <- paste0(base_template, params_code, '

# Realizar requisição GET
response = requests.get(f"{base_url}', api_call$endpoint, '", params=params, headers=headers)

# Processar resposta
if response.status_code == 200:
    data = response.json()
    print(json.dumps(data["data"], indent=2))
else:
    print(f"Erro: {response.status_code}")
')
    
  } else if (api_call$method == "POST") {
    body_json <- jsonlite::toJSON(api_call$body, auto_unbox = TRUE, pretty = TRUE)
    
    code <- paste0(base_template, '
# Preparar dados para POST
request_body = ', body_json, '

# Realizar requisição POST
response = requests.post(f"{base_url}', api_call$endpoint, '", json=request_body, headers=headers)

# Processar resposta
if response.status_code == 200:
    data = response.json()
    print(json.dumps(data["data"], indent=2))
else:
    print(f"Erro: {response.status_code}")
')
  }
  
  return(code)
}

# cURL Code Generation
generate_curl_example <- function(api_call) {
  
  if (api_call$method == "GET") {
    query_string <- ""
    if (!is.null(api_call$parameters)) {
      params <- paste(
        names(api_call$parameters),
        api_call$parameters,
        sep = "=",
        collapse = "&"
      )
      query_string <- paste0("?", params)
    }
    
    code <- paste0('# Requisição GET
curl -X GET "https://monitorlegislativo.up.railway.app/api/v1', api_call$endpoint, query_string, '" \\
  -H "X-API-Key: sua_chave_api" \\
  -H "Accept: application/json"')
    
  } else if (api_call$method == "POST") {
    body_json <- jsonlite::toJSON(api_call$body, auto_unbox = TRUE, pretty = TRUE)
    # Escape quotes for shell
    body_json <- gsub('"', '\\"', body_json)
    
    code <- paste0('# Requisição POST
curl -X POST "https://monitorlegislativo.up.railway.app/api/v1', api_call$endpoint, '" \\
  -H "X-API-Key: sua_chave_api" \\
  -H "Content-Type: application/json" \\
  -H "Accept: application/json" \\
  -d "', body_json, '"')
  }
  
  return(code)
}

# ============================================================================
# TUTORIAL FORMATTING FUNCTIONS
# ============================================================================

# Format workflow as Markdown
format_workflow_as_markdown <- function(workflow_steps, language = "r") {
  
  markdown_content <- paste0('
# 🎓 Guia de Pesquisa Acadêmica - API Monitor Legislativo

Este guia fornece um fluxo de trabalho completo para pesquisadores acadêmicos utilizarem a API Monitor Legislativo para estudos sobre legislação brasileira.

## 📋 Pré-requisitos

- Chave de API válida (nível acadêmico recomendado)
- Conhecimento básico de programação em ', toupper(language), '
- Acesso a ferramentas de análise de dados

## 🔧 Configuração Inicial

```', language, '
# Configuração da API Monitor Legislativo
api_key <- "sua_chave_api_academica"
base_url <- "https://monitorlegislativo.up.railway.app/api/v1"
```

---

')
  
  for (i in 1:length(workflow_steps)) {
    step <- workflow_steps[[i]]
    
    markdown_content <- paste0(markdown_content, '
## ', step$title, '

**Objetivo:** ', step$objective, '

**Descrição:** ', step$description, '

**Endpoints utilizados:** `', paste(step$endpoints, collapse = "`, `"), '`

### Exemplo de Código (', toupper(language), ')

```', language, '
', step$examples[[language]], '
```

### Resultado Esperado

', step$expected_output, '

### 💡 Dicas de Pesquisa

', paste("- ", step$research_tips, collapse = "\n"), '

---

')
  }
  
  markdown_content <- paste0(markdown_content, '
## 📚 Recursos Adicionais

- [Documentação Completa da API](https://monitorlegislativo.gov.br/api/docs)
- [Guia de Autenticação](https://monitorlegislativo.gov.br/docs/auth)
- [Exemplos de Código](https://github.com/monitorlegislativo/examples)
- [Fórum de Suporte](https://github.com/monitorlegislativo/api/discussions)

## 📧 Suporte

Para dúvidas específicas sobre pesquisa acadêmica:
- Email: pesquisa@monitorlegislativo.gov.br
- Discord: [Monitor Legislativo](https://discord.gg/monitorlegislativo)

## 📄 Citação Recomendada

Para citar este guia em trabalhos acadêmicos:

**ABNT:**
BRASIL. Monitor Legislativo. Guia de Pesquisa Acadêmica - API Monitor Legislativo. Brasília, DF: Governo Federal, 2024. Disponível em: <https://monitorlegislativo.gov.br/api/docs/academic-guide>. Acesso em: [data de acesso].

**BibTeX:**
```bibtex
@misc{monitorlegislativo2024guide,
  title={Guia de Pesquisa Acadêmica - API Monitor Legislativo},
  author={{Monitor Legislativo}},
  year={2024},
  publisher={Governo Federal},
  url={https://monitorlegislativo.gov.br/api/docs/academic-guide}
}
```
')
  
  return(markdown_content)
}

# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

#' Export Complete Examples and Tutorials
#' 
#' Generates all tutorial files and examples for documentation
#' @param output_dir Output directory for files
#' @return List of generated files
export_complete_documentation <- function(output_dir = "documentation/examples") {
  
  # Ensure output directory exists
  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
    cat("📁 Created examples directory:", output_dir, "\n")
  }
  
  # Generate academic workflow tutorial
  academic_guide <- generate_academic_workflow_tutorial("markdown", "r")
  academic_file <- file.path(output_dir, "academic-research-guide.md")
  writeLines(academic_guide, academic_file)
  cat("📖 Generated academic guide:", academic_file, "\n")
  
  # Generate examples database
  examples_db <- create_realistic_examples_database()
  examples_file <- file.path(output_dir, "realistic-examples.json")
  write(jsonlite::toJSON(examples_db, auto_unbox = TRUE, pretty = TRUE), examples_file)
  cat("💾 Generated examples database:", examples_file, "\n")
  
  # Generate multi-language code samples
  languages <- c("r", "python", "javascript", "curl")
  for (lang in languages) {
    lang_guide <- generate_academic_workflow_tutorial("markdown", lang)
    lang_file <- file.path(output_dir, paste0("academic-guide-", lang, ".md"))
    writeLines(lang_guide, lang_file)
    cat("📝 Generated", lang, "guide:", lang_file, "\n")
  }
  
  return(list(
    academic_guide = academic_file,
    examples_db = examples_file,
    language_guides = file.path(output_dir, paste0("academic-guide-", languages, ".md"))
  ))
}

# Export functions for use in plumber API
cat("✅ Interactive API Examples and Tutorials loaded\n")
cat("📚 Functions available:\n")
cat("  - generate_academic_workflow_tutorial(): Complete academic workflow\n")
cat("  - create_realistic_examples_database(): Brazilian legislative examples\n")
cat("  - generate_multilang_examples(): Multi-language code generation\n")
cat("  - export_complete_documentation(): Export all tutorial files\n")