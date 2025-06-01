# UI Components for Monitor Legislativo v4
# Advanced bslib components and custom UI elements

library(bslib)
library(shiny)
library(htmltools)
library(shinyWidgets)

#' Create modern search interface with vocabulary suggestions
#' @param id Module ID
#' @return UI elements for search interface
search_interface_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "search-interface",
    
    # Main search input with autocomplete
    div(
      class = "search-input-container mb-3",
      div(
        class = "input-group input-group-lg",
        span(
          class = "input-group-text bg-primary text-white",
          icon("search")
        ),
        textInput(
          ns("search_query"),
          label = NULL,
          placeholder = "Buscar legislação (ex: transporte público, mobilidade urbana...)",
          width = "100%"
        ),
        span(
          class = "input-group-text",
          actionButton(
            ns("btn_search"),
            "Buscar",
            class = "btn btn-primary border-0"
          )
        )
      )
    ),
    
    # Vocabulary suggestions
    conditionalPanel(
      condition = paste0("output['", ns("show_suggestions"), "']"),
      div(
        class = "vocabulary-suggestions mb-3",
        h6("💡 Sugestões de vocabulário:", class = "text-muted mb-2"),
        uiOutput(ns("vocabulary_chips"))
      )
    ),
    
    # Advanced filters (collapsible)
    accordion(
      accordion_panel(
        "🔧 Filtros Avançados",
        icon = icon("filter"),
        
        layout_columns(
          col_widths = c(6, 6),
          
          # Date filters
          div(
            h6("📅 Período"),
            dateRangeInput(
              ns("date_range"),
              label = NULL,
              start = Sys.Date() - 365,
              end = Sys.Date(),
              format = "dd/mm/yyyy",
              language = "pt-BR",
              separator = " até "
            )
          ),
          
          # Document type filter
          div(
            h6("📄 Tipos de Documento"),
            checkboxGroupInput(
              ns("document_types"),
              label = NULL,
              choices = list(
                "Leis" = "lei",
                "Decretos" = "decreto",
                "Portarias" = "portaria",
                "Resoluções" = "resolucao",
                "Medidas Provisórias" = "medida_provisoria"
              ),
              selected = c("lei", "decreto"),
              inline = TRUE
            )
          )
        ),
        
        layout_columns(
          col_widths = c(6, 6),
          
          # Geographic filters
          div(
            h6("🗺️ Localização"),
            selectizeInput(
              ns("states_filter"),
              "Estados:",
              choices = NULL,
              multiple = TRUE,
              options = list(
                placeholder = "Selecione estados...",
                plugins = list("remove_button")
              )
            ),
            conditionalPanel(
              condition = paste0("input['", ns("states_filter"), "'] != null"),
              selectizeInput(
                ns("municipalities_filter"),
                "Municípios:",
                choices = NULL,
                multiple = TRUE,
                options = list(
                  placeholder = "Selecione municípios...",
                  plugins = list("remove_button")
                )
              )
            )
          ),
          
          # Source filters
          div(
            h6("🏛️ Fontes"),
            checkboxGroupInput(
              ns("sources_filter"),
              label = NULL,
              choices = list(
                "LexML Brasil" = "lexml",
                "Câmara dos Deputados" = "camara",
                "Senado Federal" = "senado",
                "Assembleias Estaduais" = "estados",
                "Câmaras Municipais" = "municipios"
              ),
              selected = c("lexml", "camara", "senado"),
              inline = TRUE
            )
          )
        ),
        
        # Action buttons
        div(
          class = "mt-3 d-flex gap-2",
          actionButton(
            ns("btn_apply_filters"),
            "Aplicar Filtros",
            class = "btn-success",
            icon = icon("check")
          ),
          actionButton(
            ns("btn_clear_filters"),
            "Limpar Filtros",
            class = "btn-outline-secondary",
            icon = icon("eraser")
          ),
          actionButton(
            ns("btn_save_search"),
            "Salvar Busca",
            class = "btn-outline-primary",
            icon = icon("bookmark")
          )
        )
      )
    ),
    
    # Search statistics
    div(
      class = "search-stats mt-3",
      uiOutput(ns("search_summary"))
    )
  )
}

#' Create enhanced value box with animations
#' @param title Box title
#' @param value Box value
#' @param icon Box icon
#' @param color Box color theme
#' @param subtitle Optional subtitle
#' @return Enhanced value box
enhanced_value_box <- function(title, value, icon = NULL, color = "primary", subtitle = NULL) {
  
  color_classes <- list(
    "primary" = "border-primary text-primary",
    "success" = "border-success text-success", 
    "info" = "border-info text-info",
    "warning" = "border-warning text-warning",
    "danger" = "border-danger text-danger"
  )
  
  color_class <- color_classes[[color]] %||% color_classes[["primary"]]
  
  div(
    class = paste("enhanced-value-box card border-2", color_class),
    style = "transition: all 0.3s ease; cursor: pointer;",
    onmouseover = "this.style.transform = 'translateY(-2px)'; this.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';",
    onmouseout = "this.style.transform = 'translateY(0)'; this.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';",
    
    div(
      class = "card-body text-center p-3",
      
      if (!is.null(icon)) {
        div(
          class = "mb-2",
          icon(icon, class = "fa-2x")
        )
      },
      
      h3(
        class = "mb-1 fw-bold",
        style = "font-size: 1.8rem;",
        value
      ),
      
      p(
        class = "mb-0 fw-medium",
        style = "font-size: 0.9rem;",
        title
      ),
      
      if (!is.null(subtitle)) {
        p(
          class = "text-muted mb-0",
          style = "font-size: 0.8rem;",
          subtitle
        )
      }
    )
  )
}

#' Create modern data table with export options
#' @param id Module ID
#' @param data Data to display
#' @param options DT options
#' @return Enhanced DT table
enhanced_data_table <- function(id, data = NULL, options = list()) {
  ns <- NS(id)
  
  default_options <- list(
    pageLength = 25,
    scrollX = TRUE,
    scrollY = "400px",
    dom = 'Bfrtip',
    buttons = list(
      list(extend = 'copy', text = 'Copiar'),
      list(extend = 'csv', text = 'CSV'),
      list(extend = 'excel', text = 'Excel'),
      list(extend = 'pdf', text = 'PDF'),
      list(extend = 'print', text = 'Imprimir')
    ),
    language = list(
      url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
    ),
    columnDefs = list(
      list(
        targets = "_all",
        render = htmlwidgets::JS("
          function(data, type, row) {
            if (type === 'display' && data && data.length > 50) {
              return '<span title=\"' + data + '\">' + data.substr(0, 50) + '...</span>';
            }
            return data;
          }
        ")
      )
    ),
    initComplete = htmlwidgets::JS("
      function(settings, json) {
        $(this.api().table().header()).css({
          'background-color': '#0d6efd',
          'color': 'white'
        });
      }
    ")
  )
  
  # Merge with custom options
  final_options <- modifyList(default_options, options)
  
  div(
    class = "enhanced-data-table",
    
    # Table controls
    div(
      class = "table-controls mb-3 d-flex justify-content-between align-items-center",
      
      div(
        class = "table-info",
        span(
          class = "badge bg-secondary",
          textOutput(ns("row_count"), inline = TRUE)
        )
      ),
      
      div(
        class = "table-actions",
        actionButton(
          ns("btn_refresh"),
          "Atualizar",
          class = "btn btn-outline-primary btn-sm",
          icon = icon("refresh")
        )
      )
    ),
    
    # Data table
    DT::dataTableOutput(ns("table")),
    
    # Table footer with pagination info
    div(
      class = "table-footer mt-2 text-muted",
      textOutput(ns("pagination_info"))
    )
  )
}

#' Create interactive map with custom controls
#' @param id Module ID
#' @param height Map height
#' @return Enhanced leaflet map
enhanced_map_ui <- function(id, height = "500px") {
  ns <- NS(id)
  
  div(
    class = "enhanced-map-container",
    
    # Map controls
    div(
      class = "map-controls mb-3",
      layout_columns(
        col_widths = c(3, 3, 3, 3),
        
        selectInput(
          ns("map_style"),
          "Estilo do Mapa:",
          choices = list(
            "Claro" = "CartoDB.Positron",
            "Escuro" = "CartoDB.DarkMatter",
            "Satélite" = "Esri.WorldImagery",
            "Terreno" = "OpenTopoMap"
          ),
          selected = "CartoDB.Positron"
        ),
        
        selectInput(
          ns("color_variable"),
          "Colorir por:",
          choices = list(
            "Número de documentos" = "count",
            "Densidade (docs/km²)" = "density",
            "Data mais recente" = "latest",
            "Tipos de documento" = "types"
          ),
          selected = "count"
        ),
        
        div(
          style = "padding-top: 1.5rem;",
          checkboxInput(
            ns("show_clusters"),
            "Agrupar marcadores",
            value = TRUE
          )
        ),
        
        div(
          style = "padding-top: 1.2rem;",
          actionButton(
            ns("btn_reset_view"),
            "Resetar Vista",
            class = "btn btn-outline-secondary btn-sm",
            icon = icon("home")
          )
        )
      )
    ),
    
    # Map container
    div(
      class = "map-wrapper position-relative",
      style = paste0("height: ", height, ";"),
      
      leafletOutput(ns("map"), height = "100%"),
      
      # Map overlay with loading indicator
      conditionalPanel(
        condition = paste0("output['", ns("map_loading"), "']"),
        div(
          class = "map-loading-overlay position-absolute top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center",
          style = "background: rgba(255,255,255,0.8); z-index: 1000;",
          div(
            class = "text-center",
            div(class = "spinner-border text-primary", role = "status"),
            p("Carregando dados geográficos...", class = "mt-2 text-muted")
          )
        )
      )
    ),
    
    # Map info panel
    div(
      class = "map-info mt-3",
      conditionalPanel(
        condition = paste0("output['", ns("has_selection"), "']"),
        card(
          class = "border-primary",
          card_header(
            class = "bg-primary text-white",
            "📍 Informações da Seleção"
          ),
          card_body(
            uiOutput(ns("selection_info"))
          )
        )
      )
    )
  )
}

#' Create modern chart container with controls
#' @param id Module ID
#' @param title Chart title
#' @param height Chart height
#' @return Chart container with controls
enhanced_chart_ui <- function(id, title = "Gráfico", height = "400px") {
  ns <- NS(id)
  
  card(
    class = "enhanced-chart-card",
    
    card_header(
      class = "d-flex justify-content-between align-items-center",
      
      h5(title, class = "mb-0"),
      
      div(
        class = "chart-controls",
        dropdown(
          icon = icon("cog"),
          status = "primary",
          size = "sm",
          
          h6("Configurações do Gráfico"),
          
          selectInput(
            ns("chart_type"),
            "Tipo:",
            choices = list(
              "Barra" = "bar",
              "Linha" = "line", 
              "Pizza" = "pie",
              "Área" = "area"
            )
          ),
          
          selectInput(
            ns("chart_theme"),
            "Tema:",
            choices = list(
              "Padrão" = "default",
              "Escuro" = "dark",
              "Vintage" = "vintage",
              "Macarons" = "macarons"
            )
          ),
          
          checkboxInput(
            ns("show_legend"),
            "Mostrar legenda",
            value = TRUE
          ),
          
          actionButton(
            ns("btn_download_chart"),
            "Baixar Gráfico",
            class = "btn btn-sm btn-outline-primary w-100",
            icon = icon("download")
          )
        )
      )
    ),
    
    card_body(
      padding = 0,
      div(
        style = paste0("height: ", height, ";"),
        echarts4rOutput(ns("chart"), height = "100%")
      )
    )
  )
}

#' Create status indicator component
#' @param status Status value ("online", "offline", "loading", "error")
#' @param label Status label
#' @param details Additional details
#' @return Status indicator UI
status_indicator <- function(status = "unknown", label = "Status", details = NULL) {
  
  status_config <- list(
    "online" = list(color = "success", icon = "check-circle", text = "Online"),
    "offline" = list(color = "danger", icon = "times-circle", text = "Offline"),
    "loading" = list(color = "warning", icon = "sync fa-spin", text = "Carregando"),
    "error" = list(color = "danger", icon = "exclamation-triangle", text = "Erro"),
    "unknown" = list(color = "secondary", icon = "question-circle", text = "Desconhecido")
  )
  
  config <- status_config[[status]] %||% status_config[["unknown"]]
  
  div(
    class = paste("status-indicator d-flex align-items-center text-", config$color),
    
    icon(config$icon, class = "me-2"),
    
    div(
      strong(label, ": "),
      span(config$text),
      if (!is.null(details)) {
        small(
          class = "text-muted ms-2",
          paste0("(", details, ")")
        )
      }
    )
  )
}

#' Create notification toast
#' @param message Toast message
#' @param type Toast type ("success", "error", "warning", "info")
#' @param duration Duration in milliseconds
#' @return Toast notification
create_toast <- function(message, type = "info", duration = 5000) {
  
  type_config <- list(
    "success" = list(class = "bg-success", icon = "check-circle"),
    "error" = list(class = "bg-danger", icon = "times-circle"),
    "warning" = list(class = "bg-warning", icon = "exclamation-triangle"),
    "info" = list(class = "bg-info", icon = "info-circle")
  )
  
  config <- type_config[[type]] %||% type_config[["info"]]
  
  showNotification(
    ui = div(
      class = "d-flex align-items-center",
      icon(config$icon, class = "me-2"),
      message
    ),
    type = type,
    duration = duration / 1000
  )
}

#' Create loading overlay
#' @param show Whether to show overlay
#' @param message Loading message
#' @return Loading overlay UI
loading_overlay <- function(show = FALSE, message = "Carregando...") {
  if (!show) return(NULL)
  
  div(
    class = "loading-overlay position-fixed top-0 start-0 w-100 h-100 d-flex align-items-center justify-content-center",
    style = "background: rgba(255,255,255,0.9); z-index: 9999;",
    
    div(
      class = "text-center",
      div(
        class = "spinner-border text-primary mb-3",
        style = "width: 3rem; height: 3rem;",
        role = "status"
      ),
      h5(message, class = "text-primary")
    )
  )
}