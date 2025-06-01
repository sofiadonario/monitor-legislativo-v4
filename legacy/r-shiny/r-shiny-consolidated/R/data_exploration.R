# Interactive Data Exploration Tools for Monitor Legislativo v4
# Advanced data discovery, filtering, and interactive analysis capabilities

library(shiny)
library(htmltools)
library(echarts4r)
library(plotly)
library(dplyr)
library(DT)
library(shinycssloaders)
library(crosstalk)
library(leaflet)
library(stringr)
library(lubridate)
library(corrplot)
library(heatmaply)

# Data exploration configuration
EXPLORATION_CONFIG <- list(
  visualization_types = list(
    "scatter" = "Gráfico de Dispersão",
    "histogram" = "Histograma",
    "boxplot" = "Box Plot",
    "violin" = "Violin Plot",
    "heatmap" = "Mapa de Calor",
    "correlation" = "Matriz de Correlação",
    "parallel" = "Coordenadas Paralelas",
    "treemap" = "Treemap",
    "sunburst" = "Sunburst",
    "sankey" = "Diagrama Sankey"
  ),
  
  aggregation_functions = list(
    "count" = "Contagem",
    "sum" = "Soma",
    "mean" = "Média",
    "median" = "Mediana",
    "max" = "Máximo",
    "min" = "Mínimo",
    "sd" = "Desvio Padrão",
    "var" = "Variância"
  ),
  
  grouping_variables = list(
    "estado" = "Estado",
    "regiao" = "Região",
    "tipo" = "Tipo de Documento",
    "categoria" = "Categoria",
    "ano" = "Ano",
    "mes" = "Mês",
    "trimestre" = "Trimestre",
    "fonte" = "Fonte"
  ),
  
  numeric_variables = list(
    "validation_score" = "Score de Qualidade",
    "document_count" = "Contagem de Documentos",
    "type_diversity" = "Diversidade de Tipos",
    "geographic_coverage" = "Cobertura Geográfica"
  ),
  
  filter_operators = list(
    "eq" = "Igual a",
    "ne" = "Diferente de",
    "gt" = "Maior que",
    "gte" = "Maior ou igual a",
    "lt" = "Menor que",
    "lte" = "Menor ou igual a",
    "in" = "Contém",
    "not_in" = "Não contém",
    "starts_with" = "Inicia com",
    "ends_with" = "Termina com",
    "contains" = "Contém texto"
  ),
  
  color_palettes = list(
    "viridis" = "Viridis",
    "plasma" = "Plasma",
    "blues" = "Azuis",
    "reds" = "Vermelhos",
    "greens" = "Verdes",
    "oranges" = "Laranjas",
    "categorical" = "Categórica",
    "diverging" = "Divergente"
  ),
  
  export_formats = list(
    "png" = "PNG (Imagem)",
    "html" = "HTML (Interativo)",
    "csv" = "CSV (Dados)",
    "json" = "JSON (Dados)"
  )
)

#' Create interactive data exploration interface
#' @param id Module ID
#' @return Data exploration UI
data_exploration_ui <- function(id) {
  ns <- NS(id)
  
  div(
    class = "data-exploration-container",
    
    # Header with gradient background
    div(
      class = "exploration-header",
      style = "background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 12px 12px 0 0; color: white;",
      
      fluidRow(
        column(8,
          h3("🔍 Exploração Interativa de Dados", style = "margin: 0; text-shadow: 0 1px 2px rgba(0,0,0,0.3);"),
          p("Ferramentas avançadas para descoberta e análise exploratória de dados", 
            style = "margin: 5px 0 0 0; opacity: 0.9; font-size: 0.95em;")
        ),
        
        column(4,
          div(
            class = "exploration-controls text-end",
            
            # Quick actions
            actionButton(
              ns("reset_exploration"),
              "🔄 Resetar",
              class = "btn btn-outline-light btn-sm me-2"
            ),
            
            actionButton(
              ns("save_exploration"),
              "💾 Salvar",
              class = "btn btn-outline-light btn-sm"
            )
          )
        )
      )
    ),
    
    # Control panels
    div(
      class = "control-panels",
      style = "background: white; border-bottom: 1px solid #dee2e6;",
      
      # Data filtering panel
      div(
        class = "filtering-panel",
        style = "padding: 15px; border-bottom: 1px solid #f0f0f0;",
        
        fluidRow(
          column(12,
            h6("🎯 Filtros de Dados", class = "mb-3"),
            
            # Dynamic filter controls
            div(
              id = ns("filter_controls"),
              class = "filter-controls-container",
              
              # Add filter button
              actionButton(
                ns("add_filter"),
                "➕ Adicionar Filtro",
                class = "btn btn-outline-primary btn-sm mb-3"
              ),
              
              # Filter summary
              div(
                id = ns("filter_summary"),
                class = "filter-summary mt-2"
              )
            )
          )
        )
      ),
      
      # Visualization configuration panel
      div(
        class = "visualization-panel",
        style = "padding: 15px;",
        
        fluidRow(
          column(3,
            h6("📊 Configuração da Visualização"),
            
            # Chart type
            selectInput(
              ns("chart_type"),
              "Tipo de Gráfico:",
              choices = EXPLORATION_CONFIG$visualization_types,
              selected = "scatter"
            ),
            
            # X axis variable
            selectInput(
              ns("x_variable"),
              "Variável X:",
              choices = NULL
            ),
            
            # Y axis variable
            conditionalPanel(
              condition = paste0("input['", ns("chart_type"), "'] != 'histogram'"),
              selectInput(
                ns("y_variable"),
                "Variável Y:",
                choices = NULL
              )
            )
          ),
          
          column(3,
            h6("🎨 Estilização"),
            
            # Color variable
            selectInput(
              ns("color_variable"),
              "Colorir por:",
              choices = c("Nenhum" = "none")
            ),
            
            # Size variable (for scatter plots)
            conditionalPanel(
              condition = paste0("input['", ns("chart_type"), "'] == 'scatter'"),
              selectInput(
                ns("size_variable"),
                "Tamanho por:",
                choices = c("Nenhum" = "none")
              )
            ),
            
            # Color palette
            selectInput(
              ns("color_palette"),
              "Paleta de Cores:",
              choices = EXPLORATION_CONFIG$color_palettes,
              selected = "viridis"
            )
          ),
          
          column(3,
            h6("📈 Agregação"),
            
            # Grouping variable
            selectInput(
              ns("group_by"),
              "Agrupar por:",
              choices = c("Nenhum" = "none")
            ),
            
            # Aggregation function
            conditionalPanel(
              condition = paste0("input['", ns("group_by"), "'] != 'none'"),
              selectInput(
                ns("agg_function"),
                "Função de Agregação:",
                choices = EXPLORATION_CONFIG$aggregation_functions,
                selected = "count"
              )
            ),
            
            # Sample size
            numericInput(
              ns("sample_size"),
              "Amostra (máx):",
              value = 1000,
              min = 100,
              max = 10000,
              step = 100
            )
          ),
          
          column(3,
            h6("🎯 Ações"),
            
            br(),
            
            actionButton(
              ns("update_visualization"),
              "📊 Atualizar Gráfico",
              class = "btn btn-primary w-100 mb-2"
            ),
            
            actionButton(
              ns("export_visualization"),
              "📤 Exportar",
              class = "btn btn-outline-success w-100 mb-2"
            ),
            
            actionButton(
              ns("fullscreen_viz"),
              "⛶ Tela Cheia",
              class = "btn btn-outline-secondary w-100"
            )
          )
        )
      )
    ),
    
    # Main content area
    div(
      class = "exploration-content",
      style = "background: white;",
      
      # Tabs for different views
      navset_card_tab(
        id = ns("exploration_tabs"),
        
        # Interactive visualization tab
        nav_panel(
          "📊 Visualização Interativa",
          
          fluidRow(
            column(12,
              card(
                card_header(
                  div(
                    class = "d-flex justify-content-between align-items-center",
                    span(textOutput(ns("chart_title"), inline = TRUE)),
                    div(
                      # Chart controls
                      checkboxInput(
                        ns("show_legend"),
                        "Legenda",
                        value = TRUE,
                        inline = TRUE
                      ),
                      checkboxInput(
                        ns("enable_zoom"),
                        "Zoom",
                        value = TRUE,
                        inline = TRUE
                      )
                    )
                  )
                ),
                card_body(
                  # Loading indicator
                  conditionalPanel(
                    condition = paste0("!output['", ns("viz_ready"), "']"),
                    div(
                      class = "text-center py-5",
                      withSpinner(
                        div(
                          icon("chart-bar", class = "fa-3x text-muted mb-3"),
                          h4("Exploração de Dados", class = "text-muted"),
                          p("Configure os parâmetros e clique em 'Atualizar Gráfico'", class = "text-muted")
                        ),
                        type = 6,
                        color = "#0d6efd"
                      )
                    )
                  ),
                  
                  # Visualization output
                  conditionalPanel(
                    condition = paste0("output['", ns("viz_ready"), "']"),
                    withSpinner(
                      uiOutput(ns("dynamic_visualization")),
                      type = 4
                    )
                  )
                )
              )
            )
          )
        ),
        
        # Data table tab
        nav_panel(
          "📋 Dados Filtrados",
          
          fluidRow(
            column(12,
              card(
                card_header(
                  div(
                    class = "d-flex justify-content-between align-items-center",
                    span("Dados Filtrados"),
                    div(
                      span(textOutput(ns("filtered_count"), inline = TRUE), class = "badge bg-primary me-2"),
                      downloadButton(
                        ns("download_filtered_data"),
                        "📥 Baixar CSV",
                        class = "btn btn-outline-primary btn-sm"
                      )
                    )
                  )
                ),
                card_body(
                  withSpinner(
                    DT::dataTableOutput(ns("filtered_data_table")),
                    type = 4
                  )
                )
              )
            )
          )
        ),
        
        # Statistical summary tab
        nav_panel(
          "📊 Resumo Estatístico",
          
          fluidRow(
            column(6,
              card(
                card_header("📈 Estatísticas Descritivas"),
                card_body(
                  withSpinner(
                    htmlOutput(ns("descriptive_statistics")),
                    type = 4
                  )
                )
              )
            ),
            
            column(6,
              card(
                card_header("🔗 Matriz de Correlação"),
                card_body(
                  withSpinner(
                    plotlyOutput(ns("correlation_matrix"), height = "400px"),
                    type = 4
                  )
                )
              )
            )
          ),
          
          br(),
          
          fluidRow(
            column(12,
              card(
                card_header("📊 Distribuições das Variáveis"),
                card_body(
                  withSpinner(
                    plotlyOutput(ns("distribution_plots"), height = "500px"),
                    type = 4
                  )
                )
              )
            )
          )
        ),
        
        # Advanced insights tab
        nav_panel(
          "🧠 Insights Automáticos",
          
          fluidRow(
            column(6,
              card(
                card_header("🔍 Padrões Detectados"),
                card_body(
                  htmlOutput(ns("detected_patterns"))
                )
              )
            ),
            
            column(6,
              card(
                card_header("💡 Recomendações de Análise"),
                card_body(
                  htmlOutput(ns("analysis_suggestions"))
                )
              )
            )
          ),
          
          br(),
          
          fluidRow(
            column(12,
              card(
                card_header("📊 Outliers e Anomalias"),
                card_body(
                  withSpinner(
                    DT::dataTableOutput(ns("outliers_table")),
                    type = 4
                  )
                )
              )
            )
          )
        )
      )
    ),
    
    # Footer with exploration metadata
    div(
      class = "exploration-footer",
      style = "background: #f8f9fa; padding: 15px; border-top: 1px solid #dee2e6; border-radius: 0 0 12px 12px;",
      
      fluidRow(
        column(8,
          div(
            class = "d-flex align-items-center",
            span("🔍 Última atualização: ", class = "text-muted me-2"),
            strong(textOutput(ns("last_update_time"), inline = TRUE), class = "text-primary"),
            span(" | ", class = "text-muted mx-2"),
            span("📊 Registros exibidos: ", class = "text-muted me-2"),
            strong(textOutput(ns("displayed_records"), inline = TRUE), class = "text-success")
          )
        ),
        
        column(4,
          div(
            class = "text-end",
            span("🎯 Filtros ativos: ", class = "text-muted"),
            strong(textOutput(ns("active_filters_count"), inline = TRUE), class = "text-info"),
            span(" | ", class = "text-muted mx-2"),
            span("📈 Visualização: ", class = "text-muted"),
            strong(textOutput(ns("current_chart_type"), inline = TRUE), class = "text-warning")
          )
        )
      )
    )
  )
}

#' Interactive data exploration server function
#' @param id Module ID
#' @param legislative_data Reactive containing legislative data
data_exploration_server <- function(id, legislative_data) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive values for exploration state
    values <- reactiveValues(
      filtered_data = NULL,
      active_filters = list(),
      current_visualization = NULL,
      last_update = NULL,
      available_variables = NULL
    )
    
    # ========================================================================
    # INITIALIZE AVAILABLE VARIABLES
    # ========================================================================
    
    observe({
      if (!is.null(legislative_data()) && nrow(legislative_data()) > 0) {
        data <- legislative_data()
        
        # Identify variable types
        numeric_vars <- names(data)[sapply(data, is.numeric)]
        character_vars <- names(data)[sapply(data, function(x) is.character(x) || is.factor(x))]
        date_vars <- names(data)[sapply(data, function(x) inherits(x, "Date") || grepl("data|date", names(data), ignore.case = TRUE))]
        
        # Update variable choices
        all_vars <- c(
          setNames(numeric_vars, paste(numeric_vars, "(numérico)")),
          setNames(character_vars, paste(character_vars, "(categórico)")),
          setNames(date_vars, paste(date_vars, "(data)"))
        )
        
        updateSelectInput(session, "x_variable", choices = all_vars)
        updateSelectInput(session, "y_variable", choices = all_vars)
        updateSelectInput(session, "color_variable", choices = c("Nenhum" = "none", all_vars))
        updateSelectInput(session, "size_variable", choices = c("Nenhum" = "none", numeric_vars))
        updateSelectInput(session, "group_by", choices = c("Nenhum" = "none", character_vars))
        
        values$available_variables <- list(
          numeric = numeric_vars,
          character = character_vars,
          date = date_vars,
          all = all_vars
        )
        
        # Initialize with all data
        values$filtered_data <- data
        values$last_update <- Sys.time()
      }
    })
    
    # ========================================================================
    # FILTER MANAGEMENT
    # ========================================================================
    
    # Add new filter
    observeEvent(input$add_filter, {
      if (is.null(values$available_variables)) return()
      
      # Generate unique filter ID
      filter_id <- paste0("filter_", length(values$active_filters) + 1)
      
      # Create filter UI
      filter_ui <- div(
        id = ns(paste0(filter_id, "_container")),
        class = "filter-row mb-2 p-2 border rounded",
        
        fluidRow(
          column(3,
            selectInput(
              ns(paste0(filter_id, "_variable")),
              "Variável:",
              choices = values$available_variables$all,
              width = "100%"
            )
          ),
          
          column(2,
            selectInput(
              ns(paste0(filter_id, "_operator")),
              "Operador:",
              choices = EXPLORATION_CONFIG$filter_operators,
              selected = "eq",
              width = "100%"
            )
          ),
          
          column(5,
            textInput(
              ns(paste0(filter_id, "_value")),
              "Valor:",
              width = "100%"
            )
          ),
          
          column(2,
            br(),
            actionButton(
              ns(paste0(filter_id, "_remove")),
              "🗑️",
              class = "btn btn-outline-danger btn-sm w-100",
              title = "Remover filtro"
            )
          )
        )
      )
      
      # Insert filter UI
      insertUI(
        selector = paste0("#", ns("filter_controls")),
        where = "beforeEnd",
        ui = filter_ui
      )
      
      # Add to active filters
      values$active_filters[[filter_id]] <- list(
        variable = NULL,
        operator = "eq",
        value = NULL
      )
      
      # Observe remove button
      observeEvent(input[[paste0(filter_id, "_remove")]], {
        removeUI(selector = paste0("#", ns(paste0(filter_id, "_container"))))
        values$active_filters[[filter_id]] <- NULL
        apply_filters()
      })
      
      # Observe filter changes
      observe({
        req(input[[paste0(filter_id, "_variable")]])
        req(input[[paste0(filter_id, "_operator")]])
        req(input[[paste0(filter_id, "_value")]])
        
        values$active_filters[[filter_id]] <- list(
          variable = input[[paste0(filter_id, "_variable")]],
          operator = input[[paste0(filter_id, "_operator")]],
          value = input[[paste0(filter_id, "_value")]]
        )
        
        apply_filters()
      })
    })
    
    # Apply filters to data
    apply_filters <- function() {
      if (is.null(legislative_data())) return()
      
      filtered <- legislative_data()
      
      for (filter_config in values$active_filters) {
        if (!is.null(filter_config$variable) && !is.null(filter_config$value) && filter_config$value != "") {
          filtered <- apply_single_filter(filtered, filter_config)
        }
      }
      
      values$filtered_data <- filtered
      values$last_update <- Sys.time()
    }
    
    # Apply single filter
    apply_single_filter <- function(data, filter_config) {
      var_name <- filter_config$variable
      operator <- filter_config$operator
      value <- filter_config$value
      
      if (!var_name %in% names(data)) return(data)
      
      tryCatch({
        switch(operator,
          "eq" = data[data[[var_name]] == value, ],
          "ne" = data[data[[var_name]] != value, ],
          "gt" = data[data[[var_name]] > as.numeric(value), ],
          "gte" = data[data[[var_name]] >= as.numeric(value), ],
          "lt" = data[data[[var_name]] < as.numeric(value), ],
          "lte" = data[data[[var_name]] <= as.numeric(value), ],
          "contains" = data[grepl(value, data[[var_name]], ignore.case = TRUE), ],
          "starts_with" = data[grepl(paste0("^", value), data[[var_name]], ignore.case = TRUE), ],
          "ends_with" = data[grepl(paste0(value, "$"), data[[var_name]], ignore.case = TRUE), ],
          data
        )
      }, error = function(e) {
        log_event(paste("Error applying filter:", e$message), "ERROR")
        data
      })
    }
    
    # ========================================================================
    # VISUALIZATION GENERATION
    # ========================================================================
    
    observeEvent(input$update_visualization, {
      if (is.null(values$filtered_data) || nrow(values$filtered_data) == 0) {
        showNotification("Nenhum dado disponível para visualização", type = "warning")
        return()
      }
      
      if (is.null(input$x_variable) || input$x_variable == "") {
        showNotification("Selecione uma variável para o eixo X", type = "warning")
        return()
      }
      
      showNotification("Gerando visualização...", type = "message")
      
      # Generate visualization
      viz_result <- create_exploration_visualization(
        data = values$filtered_data,
        chart_type = input$chart_type,
        x_var = input$x_variable,
        y_var = input$y_variable,
        color_var = input$color_variable,
        size_var = input$size_variable,
        group_by = input$group_by,
        agg_function = input$agg_function,
        sample_size = input$sample_size,
        color_palette = input$color_palette
      )
      
      if (!is.null(viz_result)) {
        values$current_visualization <- viz_result
        showNotification("Visualização atualizada!", type = "success")
      } else {
        showNotification("Erro ao gerar visualização", type = "error")
      }
    })
    
    # ========================================================================
    # OUTPUTS
    # ========================================================================
    
    output$viz_ready <- reactive({
      !is.null(values$current_visualization)
    })
    outputOptions(output, "viz_ready", suspendWhenHidden = FALSE)
    
    output$chart_title <- renderText({
      if (is.null(input$chart_type) || is.null(input$x_variable)) return("")
      
      chart_name <- EXPLORATION_CONFIG$visualization_types[[input$chart_type]]
      paste(chart_name, "-", input$x_variable)
    })
    
    output$dynamic_visualization <- renderUI({
      if (is.null(values$current_visualization)) return(NULL)
      
      # Return appropriate output based on chart type
      switch(input$chart_type,
        "scatter" = echarts4rOutput(ns("scatter_plot"), height = "500px"),
        "histogram" = echarts4rOutput(ns("histogram_plot"), height = "500px"),
        "boxplot" = echarts4rOutput(ns("boxplot_plot"), height = "500px"),
        "heatmap" = echarts4rOutput(ns("heatmap_plot"), height = "500px"),
        echarts4rOutput(ns("default_plot"), height = "500px")
      )
    })
    
    # Render specific chart types
    output$scatter_plot <- renderEcharts4r({
      if (is.null(values$current_visualization)) return(NULL)
      values$current_visualization
    })
    
    output$histogram_plot <- renderEcharts4r({
      if (is.null(values$current_visualization)) return(NULL)
      values$current_visualization
    })
    
    output$boxplot_plot <- renderEcharts4r({
      if (is.null(values$current_visualization)) return(NULL)
      values$current_visualization
    })
    
    output$heatmap_plot <- renderEcharts4r({
      if (is.null(values$current_visualization)) return(NULL)
      values$current_visualization
    })
    
    output$default_plot <- renderEcharts4r({
      if (is.null(values$current_visualization)) return(NULL)
      values$current_visualization
    })
    
    # Filtered data table
    output$filtered_data_table <- DT::renderDataTable({
      if (is.null(values$filtered_data)) return(NULL)
      
      values$filtered_data %>%
        select_if(function(x) !all(is.na(x))) %>%
        head(input$sample_size %||% 1000)
        
    }, options = list(
      pageLength = 25,
      scrollX = TRUE,
      scrollY = "400px",
      language = list(
        url = '//cdn.datatables.net/plug-ins/1.10.11/i18n/Portuguese-Brasil.json'
      )
    ))
    
    # Footer outputs
    output$last_update_time <- renderText({
      if (is.null(values$last_update)) "Nunca"
      else format(values$last_update, "%d/%m/%Y %H:%M:%S")
    })
    
    output$displayed_records <- renderText({
      if (is.null(values$filtered_data)) "0"
      else format(nrow(values$filtered_data), big.mark = ".")
    })
    
    output$filtered_count <- renderText({
      if (is.null(values$filtered_data)) "0 registros"
      else paste(format(nrow(values$filtered_data), big.mark = "."), "registros")
    })
    
    output$active_filters_count <- renderText({
      length(values$active_filters)
    })
    
    output$current_chart_type <- renderText({
      if (is.null(input$chart_type)) "Nenhuma"
      else EXPLORATION_CONFIG$visualization_types[[input$chart_type]]
    })
    
    # Statistical outputs
    output$descriptive_statistics <- renderUI({
      if (is.null(values$filtered_data)) return(NULL)
      create_descriptive_stats_ui(values$filtered_data)
    })
    
    output$correlation_matrix <- renderPlotly({
      if (is.null(values$filtered_data)) return(NULL)
      create_correlation_matrix_plot(values$filtered_data)
    })
    
    output$distribution_plots <- renderPlotly({
      if (is.null(values$filtered_data)) return(NULL)
      create_distribution_plots(values$filtered_data)
    })
    
    # ========================================================================
    # EXPORT AND DOWNLOAD
    # ========================================================================
    
    output$download_filtered_data <- downloadHandler(
      filename = function() {
        paste0("filtered_data_", Sys.Date(), ".csv")
      },
      content = function(file) {
        if (!is.null(values$filtered_data)) {
          write.csv(values$filtered_data, file, row.names = FALSE)
        }
      }
    )
    
    # Reset exploration
    observeEvent(input$reset_exploration, {
      values$filtered_data <- legislative_data()
      values$active_filters <- list()
      values$current_visualization <- NULL
      values$last_update <- Sys.time()
      
      # Remove all filter UIs
      removeUI(selector = paste0("#", ns("filter_controls"), " .filter-row"))
      
      showNotification("Exploração resetada", type = "info")
    })
  })
}

# ============================================================================
# HELPER FUNCTIONS FOR DATA EXPLORATION
# ============================================================================

#' Create exploration visualization based on parameters
#' @param data Data to visualize
#' @param chart_type Type of chart
#' @param x_var X variable
#' @param y_var Y variable (optional)
#' @param color_var Color variable (optional)
#' @param size_var Size variable (optional)
#' @param group_by Grouping variable (optional)
#' @param agg_function Aggregation function
#' @param sample_size Sample size
#' @param color_palette Color palette
#' @return echarts4r visualization
create_exploration_visualization <- function(data, chart_type, x_var, y_var = NULL, 
                                           color_var = "none", size_var = "none",
                                           group_by = "none", agg_function = "count",
                                           sample_size = 1000, color_palette = "viridis") {
  if (is.null(data) || nrow(data) == 0) return(NULL)
  
  tryCatch({
    # Sample data if needed
    if (nrow(data) > sample_size) {
      data <- data %>% sample_n(sample_size)
    }
    
    # Apply grouping if specified
    if (group_by != "none" && group_by %in% names(data)) {
      data <- apply_grouping(data, group_by, x_var, y_var, agg_function)
    }
    
    # Generate visualization based on chart type
    switch(chart_type,
      "scatter" = create_scatter_plot(data, x_var, y_var, color_var, size_var, color_palette),
      "histogram" = create_histogram_plot(data, x_var, color_var, color_palette),
      "boxplot" = create_boxplot(data, x_var, y_var, color_var, color_palette),
      "heatmap" = create_heatmap_plot(data, x_var, y_var, color_palette),
      "treemap" = create_treemap_plot(data, x_var, y_var, color_palette),
      create_scatter_plot(data, x_var, y_var, color_var, size_var, color_palette)
    )
    
  }, error = function(e) {
    log_event(paste("Error creating exploration visualization:", e$message), "ERROR")
    return(NULL)
  })
}

#' Apply grouping and aggregation to data
#' @param data Input data
#' @param group_var Grouping variable
#' @param x_var X variable
#' @param y_var Y variable
#' @param agg_function Aggregation function
#' @return Grouped and aggregated data
apply_grouping <- function(data, group_var, x_var, y_var, agg_function) {
  if (is.null(data) || !group_var %in% names(data)) return(data)
  
  tryCatch({
    if (agg_function == "count") {
      # Simple count aggregation
      data %>%
        group_by(!!sym(group_var)) %>%
        summarise(
          count = n(),
          .groups = "drop"
        ) %>%
        rename(!!x_var := !!sym(group_var), !!paste0(y_var, "_agg") := count)
    } else {
      # Numeric aggregation
      if (!is.null(y_var) && y_var %in% names(data) && is.numeric(data[[y_var]])) {
        data %>%
          group_by(!!sym(group_var)) %>%
          summarise(
            agg_value = switch(agg_function,
              "mean" = mean(!!sym(y_var), na.rm = TRUE),
              "median" = median(!!sym(y_var), na.rm = TRUE),
              "sum" = sum(!!sym(y_var), na.rm = TRUE),
              "max" = max(!!sym(y_var), na.rm = TRUE),
              "min" = min(!!sym(y_var), na.rm = TRUE),
              "sd" = sd(!!sym(y_var), na.rm = TRUE),
              "var" = var(!!sym(y_var), na.rm = TRUE),
              mean(!!sym(y_var), na.rm = TRUE)
            ),
            .groups = "drop"
          ) %>%
          rename(!!x_var := !!sym(group_var), !!paste0(y_var, "_agg") := agg_value)
      } else {
        data
      }
    }
  }, error = function(e) {
    log_event(paste("Error applying grouping:", e$message), "ERROR")
    data
  })
}

#' Create scatter plot
#' @param data Plot data
#' @param x_var X variable
#' @param y_var Y variable
#' @param color_var Color variable
#' @param size_var Size variable
#' @param color_palette Color palette
#' @return echarts4r scatter plot
create_scatter_plot <- function(data, x_var, y_var, color_var, size_var, color_palette) {
  if (is.null(data) || !x_var %in% names(data)) return(NULL)
  
  # Use y_var if available, otherwise use a default
  if (is.null(y_var) || !y_var %in% names(data)) {
    y_var <- names(data)[sapply(data, is.numeric)][1]
  }
  
  if (is.null(y_var)) return(NULL)
  
  chart <- data %>%
    e_charts_(x_var) %>%
    e_scatter_(y_var, name = "Dados") %>%
    e_tooltip(trigger = "item") %>%
    e_animation(duration = 1000)
  
  # Add color if specified
  if (color_var != "none" && color_var %in% names(data)) {
    chart <- chart %>% e_add_nested("itemStyle", color_var)
  }
  
  return(chart)
}

#' Create histogram plot
#' @param data Plot data
#' @param x_var X variable
#' @param color_var Color variable
#' @param color_palette Color palette
#' @return echarts4r histogram
create_histogram_plot <- function(data, x_var, color_var, color_palette) {
  if (is.null(data) || !x_var %in% names(data)) return(NULL)
  
  # Create histogram data
  if (is.numeric(data[[x_var]])) {
    hist_data <- hist(data[[x_var]], plot = FALSE)
    chart_data <- data.frame(
      breaks = head(hist_data$breaks, -1),
      counts = hist_data$counts
    )
    
    chart_data %>%
      e_charts(breaks) %>%
      e_bar(counts, name = "Frequência") %>%
      e_tooltip(trigger = "axis") %>%
      e_animation(duration = 800)
  } else {
    # For categorical data, create bar chart
    data %>%
      count(!!sym(x_var)) %>%
      e_charts_(x_var) %>%
      e_bar(n, name = "Contagem") %>%
      e_tooltip(trigger = "axis") %>%
      e_animation(duration = 800)
  }
}

#' Create box plot
#' @param data Plot data
#' @param x_var X variable (categorical)
#' @param y_var Y variable (numeric)
#' @param color_var Color variable
#' @param color_palette Color palette
#' @return echarts4r box plot
create_boxplot <- function(data, x_var, y_var, color_var, color_palette) {
  if (is.null(data) || !x_var %in% names(data) || !y_var %in% names(data)) return(NULL)
  
  # Create box plot data
  box_data <- data %>%
    group_by(!!sym(x_var)) %>%
    summarise(
      min = min(!!sym(y_var), na.rm = TRUE),
      q1 = quantile(!!sym(y_var), 0.25, na.rm = TRUE),
      median = median(!!sym(y_var), na.rm = TRUE),
      q3 = quantile(!!sym(y_var), 0.75, na.rm = TRUE),
      max = max(!!sym(y_var), na.rm = TRUE),
      .groups = "drop"
    )
  
  box_data %>%
    e_charts_(x_var) %>%
    e_boxplot(min, q1, median, q3, max, name = "Distribuição") %>%
    e_tooltip(trigger = "item") %>%
    e_animation(duration = 1000)
}

#' Create heatmap plot
#' @param data Plot data
#' @param x_var X variable
#' @param y_var Y variable
#' @param color_palette Color palette
#' @return echarts4r heatmap
create_heatmap_plot <- function(data, x_var, y_var, color_palette) {
  if (is.null(data) || !x_var %in% names(data) || !y_var %in% names(data)) return(NULL)
  
  # Create heatmap data
  heatmap_data <- data %>%
    group_by(!!sym(x_var), !!sym(y_var)) %>%
    summarise(count = n(), .groups = "drop")
  
  heatmap_data %>%
    e_charts_(x_var) %>%
    e_heatmap_(y_var, count) %>%
    e_visual_map(count, show = TRUE) %>%
    e_tooltip(trigger = "item") %>%
    e_animation(duration = 1200)
}

#' Create treemap plot
#' @param data Plot data
#' @param x_var X variable (categories)
#' @param y_var Y variable (values)
#' @param color_palette Color palette
#' @return echarts4r treemap
create_treemap_plot <- function(data, x_var, y_var, color_palette) {
  if (is.null(data) || !x_var %in% names(data)) return(NULL)
  
  # Aggregate data for treemap
  if (!is.null(y_var) && y_var %in% names(data) && is.numeric(data[[y_var]])) {
    treemap_data <- data %>%
      group_by(!!sym(x_var)) %>%
      summarise(value = sum(!!sym(y_var), na.rm = TRUE), .groups = "drop")
  } else {
    treemap_data <- data %>%
      count(!!sym(x_var)) %>%
      rename(value = n)
  }
  
  treemap_data %>%
    e_charts() %>%
    e_treemap_(x_var, value) %>%
    e_tooltip(trigger = "item") %>%
    e_animation(duration = 1000)
}

#' Create descriptive statistics UI
#' @param data Input data
#' @return HTML UI with statistics
create_descriptive_stats_ui <- function(data) {
  if (is.null(data)) return(NULL)
  
  numeric_vars <- select_if(data, is.numeric)
  
  if (ncol(numeric_vars) == 0) {
    return(p("Nenhuma variável numérica disponível", class = "text-muted"))
  }
  
  stats_list <- lapply(names(numeric_vars), function(var) {
    values <- numeric_vars[[var]]
    values <- values[!is.na(values)]
    
    if (length(values) == 0) return(NULL)
    
    div(
      class = "mb-3",
      h6(var, class = "text-primary"),
      tags$ul(
        tags$li(paste("Média:", round(mean(values), 2))),
        tags$li(paste("Mediana:", round(median(values), 2))),
        tags$li(paste("Desvio Padrão:", round(sd(values), 2))),
        tags$li(paste("Mínimo:", round(min(values), 2))),
        tags$li(paste("Máximo:", round(max(values), 2)))
      )
    )
  })
  
  do.call(tagList, stats_list)
}

#' Create correlation matrix plot
#' @param data Input data
#' @return plotly correlation matrix
create_correlation_matrix_plot <- function(data) {
  if (is.null(data)) return(NULL)
  
  numeric_data <- select_if(data, is.numeric)
  
  if (ncol(numeric_data) < 2) {
    return(plotly_empty() %>% 
           layout(title = "Insuficientes variáveis numéricas para correlação"))
  }
  
  # Calculate correlation matrix
  cor_matrix <- cor(numeric_data, use = "complete.obs")
  
  # Create heatmap
  plot_ly(
    z = ~cor_matrix,
    type = "heatmap",
    colorscale = "RdBu",
    zmid = 0,
    hovertemplate = "Correlação: %{z:.2f}<extra></extra>"
  ) %>%
    layout(
      title = "Matriz de Correlação",
      xaxis = list(title = ""),
      yaxis = list(title = "")
    )
}

#' Create distribution plots
#' @param data Input data
#' @return plotly distribution plots
create_distribution_plots <- function(data) {
  if (is.null(data)) return(NULL)
  
  numeric_vars <- select_if(data, is.numeric)
  
  if (ncol(numeric_vars) == 0) {
    return(plotly_empty() %>% 
           layout(title = "Nenhuma variável numérica disponível"))
  }
  
  # Create histogram for first numeric variable
  var_name <- names(numeric_vars)[1]
  values <- numeric_vars[[var_name]]
  values <- values[!is.na(values)]
  
  plot_ly(
    x = ~values,
    type = "histogram",
    name = var_name
  ) %>%
    layout(
      title = paste("Distribuição de", var_name),
      xaxis = list(title = var_name),
      yaxis = list(title = "Frequência")
    )
}