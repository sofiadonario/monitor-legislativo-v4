# UI Components Module
# Monitor Legislativo v4 - Reusable UI Components
# ===============================================

#' Create Executive Summary Tab
#' 
#' Creates the executive summary tab with key metrics and insights
#' 
#' @return Tab item for executive summary
#' @export
create_executive_tab <- function() {
  
  shinydashboard::tabItem(
    tabName = "executive",
    
    # Strategic Insights Panel - Top Priority Information
    fluidRow(
      box(
        title = "📊 Legislative Landscape Overview", 
        status = "primary", 
        solidHeader = TRUE, 
        width = 12,
        background = "light-blue",
        
        fluidRow(
          column(4,
            div(class = "insight-card",
              h4("Current Focus Areas", style = "color: #2c3e50; margin-top: 0;"),
              uiOutput("exec_focus_areas"),
              style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;"
            )
          ),
          column(4,
            div(class = "insight-card",
              h4("Legislative Activity", style = "color: #2c3e50; margin-top: 0;"),
              uiOutput("exec_activity_summary"),
              style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;"
            )
          ),
          column(4,
            div(class = "insight-card",
              h4("Coverage Quality", style = "color: #2c3e50; margin-top: 0;"),
              uiOutput("exec_coverage_quality"),
              style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;"
            )
          )
        )
      )
    ),
    
    # Critical Metrics Dashboard - Enhanced Value Boxes
    fluidRow(
      column(3, valueBoxOutput("exec_total_docs")),
      column(3, valueBoxOutput("exec_states_coverage")),
      column(3, valueBoxOutput("exec_recent_additions")),
      column(3, valueBoxOutput("exec_data_freshness"))
    ),

    # Key Performance Indicators
    fluidRow(
      column(2, valueBoxOutput("exec_federal_docs")),
      column(2, valueBoxOutput("exec_state_docs")),
      column(2, valueBoxOutput("exec_municipal_docs")),
      column(2, valueBoxOutput("exec_jurisprudence_docs")),
      column(2, valueBoxOutput("exec_doctrine_docs")),
      column(2, valueBoxOutput("exec_active_themes"))
    ),
    
    # Trend Visualizations Row
    fluidRow(
      # Document Publication Trends
      box(
        title = "📈 Document Publication Trends", 
        status = "info", 
        solidHeader = TRUE, 
        width = 8,
        plotlyOutput("exec_publication_trends", height = "300px")
      ),
      
      # Geographic Distribution
      box(
        title = "🗺️ Geographic Distribution", 
        status = "success", 
        solidHeader = TRUE, 
        width = 4,
        plotlyOutput("exec_geographic_overview", height = "300px")
      )
    ),
    
    # Recent Activity and Quality Metrics
    fluidRow(
      box(
        title = "⏱️ Recent Legislative Activity", 
        status = "warning", 
        solidHeader = TRUE, 
        width = 6,
        DT::DTOutput("exec_recent_documents")
      ),
      
      box(
        title = "📊 Data Quality Metrics", 
        status = "info", 
        solidHeader = TRUE, 
        width = 6,
        uiOutput("exec_quality_metrics")
      )
    )
  )
}

#' Create Library Tab
#' 
#' Creates the main library search and browse interface
#' 
#' @return Tab item for library
#' @export
create_library_tab <- function() {
  
  shinydashboard::tabItem(
    tabName = "library",
    
    # Research Workflow Header
    fluidRow(
      tags$section(
        class = "research-workflow-header",
        role = "banner",
        `aria-labelledby` = "library-title",
        
        box(
          id = "search-interface",
          title = tags$h2(
            id = "library-title",
            class = "box-title",
            tags$i(class = "fas fa-search", `aria-hidden` = "true"),
            "Busca Avançada de Documentos Legislativos"
          ),
          status = "primary",
          solidHeader = TRUE,
          width = 12,
          
          # Search Interface with Accessibility
          tags$form(
            role = "search",
            `aria-label` = "Formulário de busca de documentos legislativos",
            onsubmit = "return false;",
            
            fluidRow(
              column(9,
                div(
                  class = "form-group",
                  tags$label(
                    `for` = "search_query",
                    class = "form-label sr-only",
                    "Termos de busca"
                  ),
                  textInput(
                    "search_query",
                    label = NULL,
                    placeholder = "Digite termos de busca (ex: 'transporte público', 'meio ambiente', 'educação')",
                    width = "100%"
                  ) %>% 
                    tagAppendAttributes(
                      `aria-label` = "Campo de busca principal",
                      `aria-describedby` = "search-help",
                      autocomplete = "off",
                      spellcheck = "true"
                    ),
                  
                  tags$div(
                    id = "search-help",
                    class = "form-text",
                    tags$small(
                      class = "text-muted",
                      "Use aspas para busca exata, + para termos obrigatórios, - para excluir termos"
                    )
                  )
                )
              ),
              column(3,
                div(
                  class = "form-group",
                  tags$label(class = "sr-only", `for` = "search_button", "Executar busca"),
                  actionButton(
                    "search_button",
                    "Pesquisar",
                    icon = icon("search"),
                    class = "btn-primary btn-block btn-lg",
                    `data-loading-text` = "Buscando...",
                    `aria-describedby` = "search-button-help"
                  ),
                  
                  tags$div(
                    id = "search-button-help",
                    class = "sr-only",
                    "Pressione Enter ou clique para executar a busca"
                  )
                )
              )
            )
          ),
          
          # Advanced Search Filters
          tags$details(
            class = "advanced-filters-container mt-4",
            `aria-expanded` = "false",
            
            tags$summary(
              class = "btn btn-outline-secondary",
              role = "button",
              `aria-controls` = "advanced-filters-content",
              tags$i(class = "fas fa-filter me-2"),
              "Filtros Avançados",
              tags$i(class = "fas fa-chevron-down ms-2")
            ),
            
            tags$div(
              id = "advanced-filters-content",
              class = "advanced-filters-content mt-3 p-4 bg-light rounded",
              role = "region",
              `aria-label` = "Opções de filtros avançados",
              
              fluidRow(
                column(3,
                  div(
                    class = "form-group",
                    tags$label(
                      `for` = "filter_estado",
                      class = "form-label",
                      "Estado/Jurisdição"
                    ),
                    selectInput(
                      "filter_estado",
                      label = NULL,
                      choices = list(
                        "Todos os Estados" = "",
                        "Federal" = "BR",
                        "Acre" = "AC",
                        "Alagoas" = "AL", 
                        "Amapá" = "AP",
                        "Amazonas" = "AM",
                        "Bahia" = "BA",
                        "Ceará" = "CE",
                        "Distrito Federal" = "DF",
                        "Espírito Santo" = "ES",
                        "Goiás" = "GO",
                        "Maranhão" = "MA",
                        "Mato Grosso" = "MT",
                        "Mato Grosso do Sul" = "MS",
                        "Minas Gerais" = "MG",
                        "Pará" = "PA",
                        "Paraíba" = "PB",
                        "Paraná" = "PR",
                        "Pernambuco" = "PE",
                        "Piauí" = "PI",
                        "Rio de Janeiro" = "RJ",
                        "Rio Grande do Norte" = "RN",
                        "Rio Grande do Sul" = "RS",
                        "Rondônia" = "RO",
                        "Roraima" = "RR",
                        "Santa Catarina" = "SC",
                        "São Paulo" = "SP",
                        "Sergipe" = "SE",
                        "Tocantins" = "TO"
                      ),
                      width = "100%"
                    ) %>%
                      tagAppendAttributes(
                        `aria-describedby` = "estado-help"
                      ),
                    
                    tags$div(
                      id = "estado-help",
                      class = "form-text",
                      "Filtre por jurisdição específica"
                    )
                  )
                ),
                column(3,
                  div(
                    class = "form-group",
                    tags$label(
                      `for` = "filter_tipo",
                      class = "form-label",
                      "Tipo de Documento"
                    ),
                    selectInput(
                      "filter_tipo",
                      label = NULL,
                      choices = list(
                        "Todos os Tipos" = "",
                        "Lei" = "lei",
                        "Decreto" = "decreto",
                        "Portaria" = "portaria",
                        "Resolução" = "resolucao",
                        "Instrução Normativa" = "instrucao_normativa",
                        "Medida Provisória" = "medida_provisoria",
                        "Emenda Constitucional" = "emenda_constitucional",
                        "Jurisprudência" = "jurisprudencia",
                        "Doutrina" = "doutrina"
                      ),
                      width = "100%"
                    ) %>%
                      tagAppendAttributes(
                        `aria-describedby` = "tipo-help"
                      ),
                    
                    tags$div(
                      id = "tipo-help",
                      class = "form-text",
                      "Filtre por categoria de norma"
                    )
                  )
                ),
                column(3,
                  div(
                    class = "form-group",
                    tags$label(
                      `for` = "filter_ano_min",
                      class = "form-label",
                      "Ano Inicial"
                    ),
                    numericInput(
                      "filter_ano_min",
                      label = NULL,
                      value = 2000,
                      min = 1824,
                      max = 2025,
                      step = 1,
                      width = "100%"
                    ) %>%
                      tagAppendAttributes(
                        `aria-describedby` = "ano-min-help"
                      ),
                    
                    tags$div(
                      id = "ano-min-help",
                      class = "form-text",
                      "A partir de que ano"
                    )
                  )
                ),
                column(3,
                  div(
                    class = "form-group",
                    tags$label(
                      `for` = "filter_ano_max",
                      class = "form-label",
                      "Ano Final"
                    ),
                    numericInput(
                      "filter_ano_max",
                      label = NULL,
                      value = 2025,
                      min = 1824,
                      max = 2025,
                      step = 1,
                      width = "100%"
                    ) %>%
                      tagAppendAttributes(
                        `aria-describedby` = "ano-max-help"
                      ),
                    
                    tags$div(
                      id = "ano-max-help",
                      class = "form-text",
                      "Até que ano"
                    )
                  )
                )
              ),
              
              # Additional Filter Options
              fluidRow(
                column(4,
                  div(
                    class = "form-group",
                    tags$label(
                      `for` = "filter_tema",
                      class = "form-label",
                      "Tema Principal"
                    ),
                    selectInput(
                      "filter_tema",
                      label = NULL,
                      choices = list(
                        "Todos os Temas" = "",
                        "Meio Ambiente" = "meio_ambiente",
                        "Saúde" = "saude",
                        "Educação" = "educacao",
                        "Transporte" = "transporte",
                        "Segurança Pública" = "seguranca",
                        "Economia" = "economia",
                        "Trabalho" = "trabalho",
                        "Previdência" = "previdencia",
                        "Tributário" = "tributario",
                        "Civil" = "civil",
                        "Penal" = "penal",
                        "Administrativo" = "administrativo"
                      ),
                      width = "100%"
                    )
                  )
                ),
                column(4,
                  div(
                    class = "form-group",
                    checkboxInput(
                      "filter_recent_only",
                      "Apenas documentos recentes (últimos 2 anos)",
                      value = FALSE
                    )
                  )
                ),
                column(4,
                  div(
                    class = "form-group d-flex align-items-end",
                    actionButton(
                      "clear_filters",
                      "Limpar Filtros",
                      icon = icon("times"),
                      class = "btn-outline-secondary"
                    )
                  )
                )
              )
            )
          )
        )
      )
    ),
    
    # Search Results Section
    fluidRow(
      tags$section(
        role = "main",
        `aria-labelledby` = "results-title",
        
        box(
          id = "search-results",
          title = tags$h2(
            id = "results-title",
            class = "box-title",
            tags$i(class = "fas fa-list-ul", `aria-hidden` = "true"),
            "Resultados da Pesquisa"
          ),
          status = "success",
          solidHeader = TRUE,
          width = 12,
          
          # Search Statistics and Controls
          div(
            class = "search-controls-bar d-flex justify-content-between align-items-center mb-3",
            role = "toolbar",
            `aria-label` = "Controles de busca e estatísticas",
            
            div(
              class = "search-stats",
              `aria-live` = "polite",
              `aria-atomic` = "true",
              uiOutput("search_stats")
            ),
            
            div(
              class = "view-controls d-flex gap-2",
              
              # Sort Options
              selectInput(
                "sort_results",
                label = NULL,
                choices = list(
                  "Mais Relevantes" = "relevance",
                  "Mais Recentes" = "date_desc",
                  "Mais Antigas" = "date_asc",
                  "Alfabética A-Z" = "title_asc",
                  "Alfabética Z-A" = "title_desc"
                ),
                selected = "relevance",
                width = "150px"
              ) %>%
                tagAppendAttributes(
                  `aria-label` = "Ordenar resultados por",
                  title = "Ordenar resultados"
                ),
              
              # Results per page
              selectInput(
                "results_per_page",
                label = NULL,
                choices = list(
                  "10 por página" = 10,
                  "25 por página" = 25,
                  "50 por página" = 50,
                  "100 por página" = 100
                ),
                selected = 25,
                width = "120px"
              ) %>%
                tagAppendAttributes(
                  `aria-label` = "Resultados por página",
                  title = "Quantidade de resultados por página"
                )
            )
          ),
          
          # Results Table
          div(
            class = "results-container",
            role = "region",
            `aria-label` = "Tabela de resultados da busca",
            `aria-describedby` = "table-description",
            
            tags$div(
              id = "table-description",
              class = "sr-only",
              "Tabela com os documentos encontrados. Use as setas do teclado para navegar e Enter para selecionar."
            ),
            
            DT::DTOutput(
              "search_results_table",
              width = "100%",
              height = "auto"
            ) %>%
              tagAppendAttributes(
                role = "table",
                `aria-label` = "Resultados da busca de documentos legislativos"
              )
          ),
          
          # Action Bar
          div(
            class = "action-bar mt-4 p-3 bg-light rounded",
            role = "toolbar",
            `aria-label` = "Ações para os resultados da busca",
            
            fluidRow(
              column(8,
                div(
                  class = "export-options d-flex gap-2",
                  
                  downloadButton(
                    "export_csv",
                    "Exportar CSV",
                    class = "btn-secondary export-button",
                    icon = icon("file-csv"),
                    `data-format` = "CSV",
                    `aria-describedby` = "csv-help"
                  ),
                  
                  tags$div(
                    id = "csv-help",
                    class = "sr-only",
                    "Exportar resultados em formato CSV para análise em planilhas"
                  ),
                  
                  downloadButton(
                    "export_bibtex",
                    "Exportar Citações",
                    class = "btn-secondary export-button",
                    icon = icon("quote-right"),
                    `data-format` = "BibTeX",
                    `aria-describedby` = "bibtex-help"
                  ),
                  
                  tags$div(
                    id = "bibtex-help",
                    class = "sr-only",
                    "Exportar citações em formato BibTeX para gerenciadores de referência"
                  ),
                  
                  actionButton(
                    "create_collection",
                    "Criar Coleção",
                    class = "btn-info",
                    icon = icon("folder-plus"),
                    `aria-describedby` = "collection-help"
                  ),
                  
                  tags$div(
                    id = "collection-help",
                    class = "sr-only",
                    "Criar uma coleção personalizada com os documentos selecionados"
                  )
                )
              ),
              column(4,
                div(
                  class = "pagination-wrapper d-flex justify-content-end",
                  `aria-label` = "Navegação de páginas",
                  uiOutput("pagination_controls")
                )
              )
            )
          )
        )
      )
    ),
    
    # Quick Help Panel
    fluidRow(
      tags$aside(
        role = "complementary",
        `aria-labelledby` = "help-title",
        
        box(
          title = tags$h3(
            id = "help-title",
            class = "box-title h5",
            tags$i(class = "fas fa-question-circle", `aria-hidden` = "true"),
            "Dicas de Pesquisa"
          ),
          status = "info",
          solidHeader = TRUE,
          width = 12,
          collapsible = TRUE,
          collapsed = TRUE,
          
          div(
            class = "help-content",
            
            tags$dl(
              class = "row",
              
              tags$dt(class = "col-3", "Busca Exata:"),
              tags$dd(class = "col-9", 'Use aspas: "meio ambiente"'),
              
              tags$dt(class = "col-3", "Termo Obrigatório:"),
              tags$dd(class = "col-9", "Use +: +lei +ambiental"),
              
              tags$dt(class = "col-3", "Excluir Termo:"),
              tags$dd(class = "col-9", "Use -: transporte -rodoviário"),
              
              tags$dt(class = "col-3", "Busca por Número:"),
              tags$dd(class = "col-9", "Digite: Lei 12345 ou 12345/2020"),
              
              tags$dt(class = "col-3", "Coringas:"),
              tags$dd(class = "col-9", "Use *: ambient* (ambiental, ambiente)")
            ),
            
            tags$p(
              class = "mt-3 text-muted",
              tags$strong("Atalhos de Teclado:"),
              " Ctrl+K para busca rápida | F6 para navegar entre seções | Esc para limpar"
            )
          )
        )
      )
    )
  )
}

#' Create Analytics Tab
#' 
#' Creates the advanced analytics interface
#' 
#' @return Tab item for analytics
#' @export
create_analytics_tab <- function() {
  
  shinydashboard::tabItem(
    tabName = "analytics",
    
    fluidRow(
      box(
        title = "📈 Advanced Analytics Dashboard",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        p("Advanced analytics and visualizations for legislative data research.")
      )
    ),
    
    # Topic Modeling Section
    fluidRow(
      box(
        title = "🏷️ Topic Modeling",
        status = "info",
        solidHeader = TRUE,
        width = 6,
        
        numericInput("topic_k", "Number of Topics", value = 10, min = 3, max = 20),
        actionButton("run_topic_analysis", "Run Analysis", class = "btn-primary"),
        br(), br(),
        plotOutput("topic_plot")
      ),
      
      box(
        title = "📊 Temporal Trends",
        status = "warning",
        solidHeader = TRUE,
        width = 6,
        
        selectInput("trend_metric", "Metric", 
                   choices = c("Document Count" = "count", "Activity Score" = "activity")),
        plotlyOutput("temporal_trends_plot")
      )
    )
  )
}

#' Create Geographic Analysis Tab
#' 
#' Creates the geographic analysis interface with interactive maps
#' 
#' @return Tab item for geographic analysis
#' @export
create_geographic_tab <- function() {
  
  shinydashboard::tabItem(
    tabName = "geographic",
    
    fluidRow(
      box(
        title = "🗺️ Geographic Analysis",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        p("Interactive geographic analysis of Brazilian legislative activity.")
      )
    ),
    
    # Map and Controls
    fluidRow(
      box(
        title = "Interactive Map",
        status = "success",
        solidHeader = TRUE,
        width = 8,
        
        leaflet::leafletOutput("main_map", height = "500px")
      ),
      
      box(
        title = "Map Controls",
        status = "info",
        solidHeader = TRUE,
        width = 4,
        
        selectInput("map_metric", "Map Metric",
                   choices = c("Document Count" = "count", 
                             "Per Capita" = "per_capita",
                             "Activity Score" = "activity")),
        
        selectInput("map_year", "Year",
                   choices = NULL),
        
        checkboxInput("show_capitals", "Show State Capitals", value = TRUE),
        
        hr(),
        
        h5("Map Statistics"),
        uiOutput("map_stats")
      )
    )
  )
}

#' Create São Paulo Analysis Tab
#' 
#' Creates the specialized São Paulo analysis interface
#' 
#' @return Tab item for São Paulo analysis
#' @export
create_saopaulo_tab <- function() {
  
  shinydashboard::tabItem(
    tabName = "saopaulo",
    
    fluidRow(
      box(
        title = "🏙️ São Paulo Legislative Analysis",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        p("Specialized analysis for São Paulo state and municipality legislative documents.")
      )
    )
  )
}

#' Create Text Analytics Tab
#' 
#' Creates the NLP and text analytics interface
#' 
#' @return Tab item for text analytics
#' @export
create_nlp_tab <- function() {
  
  shinydashboard::tabItem(
    tabName = "nlp",
    
    fluidRow(
      box(
        title = "🧠 Text Analytics",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        p("Natural Language Processing and text analytics for Portuguese legal documents.")
      )
    )
  )
}

#' Create System Monitoring Tab
#' 
#' Creates the system monitoring interface
#' 
#' @return Tab item for monitoring
#' @export
create_monitoring_tab <- function() {
  
  shinydashboard::tabItem(
    tabName = "monitoring",
    
    fluidRow(
      box(
        title = "⚙️ System Monitoring",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        
        p("Real-time system monitoring and performance metrics.")
      )
    )
  )
}

#' Create Research Tools Tabs
#' 
#' Creates the research tools tabs (citations, export, API docs)
#' 
#' @return List of tab items for research tools
#' @export
create_research_tools_tabs <- function() {
  
  list(
    shinydashboard::tabItem(
      tabName = "citations",
      
      fluidRow(
        box(
          title = "📝 Citation Generator",
          status = "primary",
          solidHeader = TRUE,
          width = 12,
          
          p("Generate ABNT-compliant citations for legislative documents.")
        )
      )
    ),
    
    shinydashboard::tabItem(
      tabName = "export",
      
      fluidRow(
        box(
          title = "📊 Data Export",
          status = "primary",
          solidHeader = TRUE,
          width = 12,
          
          p("Export research data in various academic formats.")
        )
      )
    ),
    
    shinydashboard::tabItem(
      tabName = "api_docs",
      
      fluidRow(
        box(
          title = "📚 API Documentation",
          status = "primary",
          solidHeader = TRUE,
          width = 12,
          
          p("Documentation for the Monitor Legislativo API.")
        )
      )
    )
  )
}

#' Create Value Box with Enhanced Styling
#' 
#' Creates a value box with improved academic styling
#' 
#' @param value Numeric or character value to display
#' @param subtitle Subtitle text
#' @param icon Icon to display
#' @param color Color scheme
#' @param width Box width (1-12)
#' @return Value box output
#' @export
create_enhanced_value_box <- function(value, subtitle, icon, color = "blue", width = 3) {
  
  safe_valueBox(
    value = value,
    subtitle = subtitle,
    icon = icon,
    color = color,
    width = width
  )
}

#' Create Info Box with Academic Styling
#' 
#' Creates an info box optimized for academic presentation
#' 
#' @param title Box title
#' @param value Main value
#' @param subtitle Additional information
#' @param icon Icon to display
#' @param color Color scheme
#' @param width Box width
#' @return Info box HTML
#' @export
create_academic_info_box <- function(title, value, subtitle = "", icon, color = "blue", width = 4) {
  
  column(
    width = width,
    div(
      class = paste("small-box bg", color, sep = "-"),
      div(
        class = "inner",
        h3(value),
        h4(title),
        if (subtitle != "") p(subtitle)
      ),
      div(
        class = "icon",
        icon(icon)
      )
    )
  )
}

cat("✅ UI components module loaded\n")