# Performance Monitoring Module
# Monitor Legislativo v4 - Database Performance Monitoring & System Health
# ==============================================================================

#' Performance Monitoring Module for Monitor Legislativo v4
#'
#' Comprehensive Shiny module for real-time database performance monitoring,
#' query optimization tracking, and system health assessment.
#'
#' Features:
#' - Real-time performance dashboard with KPI cards
#' - Index status monitoring with usage statistics
#' - Query performance benchmarking
#' - Table health and vacuum status
#' - Auto-refresh with manual override
#' - CSV export functionality

library(shiny)
library(DT)
library(plotly)
library(DBI)

# ==============================================================================
# PERFORMANCE MONITORING HELPER FUNCTIONS
# ==============================================================================
# Inline versions of functions from db/performance_monitor.R

check_indexes <- function(conn) {
  query <- "
    SELECT
      indexname,
      pg_size_pretty(pg_relation_size(schemaname||'.'||indexname::regclass)) as size,
      idx_scan as scans,
      idx_tup_read as tuples_read,
      idx_tup_fetch as tuples_fetched
    FROM pg_indexes
    JOIN pg_stat_user_indexes USING (schemaname, tablename, indexname)
    WHERE tablename = 'documents'
    ORDER BY indexname;
  "

  result <- dbGetQuery(conn, query)
  return(result)
}

check_query_performance <- function(conn) {
  # Test typical Library tab query
  start <- Sys.time()
  result1 <- dbGetQuery(conn, "
    SELECT id, titulo, tipo, data
    FROM documents
    WHERE tipo = 'Lei'
    ORDER BY data DESC
    LIMIT 100;
  ")
  time1 <- as.numeric(difftime(Sys.time(), start, units = "secs"))

  # Test text search query
  start <- Sys.time()
  result2 <- dbGetQuery(conn, "
    SELECT id, titulo, tipo, data
    FROM documents
    WHERE titulo ILIKE '%transporte%'
    ORDER BY data DESC
    LIMIT 100;
  ")
  time2 <- as.numeric(difftime(Sys.time(), start, units = "secs"))

  # Test count query
  start <- Sys.time()
  result3 <- dbGetQuery(conn, "
    SELECT tipo, COUNT(*) as count
    FROM documents
    GROUP BY tipo
    ORDER BY count DESC;
  ")
  time3 <- as.numeric(difftime(Sys.time(), start, units = "secs"))

  return(list(filter_time = time1, search_time = time2, count_time = time3))
}

check_table_statistics <- function(conn) {
  query <- "
    SELECT
      pg_size_pretty(pg_total_relation_size('documents')) as total_size,
      pg_size_pretty(pg_relation_size('documents')) as table_size,
      pg_size_pretty(pg_indexes_size('documents')) as indexes_size,
      (SELECT COUNT(*) FROM documents) as row_count,
      (SELECT COUNT(DISTINCT tipo) FROM documents) as unique_tipos;
  "

  result <- dbGetQuery(conn, query)
  return(result)
}

check_database_health <- function(conn) {
  query <- "
    SELECT
      schemaname,
      relname as table_name,
      n_live_tup as live_tuples,
      n_dead_tup as dead_tuples,
      ROUND(100.0 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0), 2) as dead_tuple_pct,
      last_vacuum,
      last_autovacuum,
      last_analyze,
      last_autoanalyze
    FROM pg_stat_user_tables
    WHERE relname = 'documents';
  "

  result <- dbGetQuery(conn, query)
  return(result)
}

#' Performance Monitoring UI
#'
#' Creates the performance monitoring interface with 5 navigation tabs:
#' - Dashboard: KPI cards with health metrics
#' - Index Status: All database indexes with usage stats
#' - Query Performance: Live timing for typical queries
#' - Table Health: Database size, dead tuples, vacuum status
#' - Monitoring: Real-time refresh controls
#'
#' @param id Character string for module namespace ID
#' @return Shiny UI tagList containing performance monitoring interface
#' @export
performanceMonitoringUI <- function(id) {
  ns <- NS(id)

  tagList(
    fluidRow(
      column(12,
        h3("📊 Database Performance Monitoring",
           style = "color: #2c3e50; margin-bottom: 20px;"),
        div(
          class = "alert alert-info",
          icon("info-circle"),
          strong(" Sistema de Monitoramento: "),
          "Monitore o desempenho do banco de dados em tempo real. ",
          "Atualização automática a cada 30 segundos. ",
          "Última atualização: ",
          textOutput(ns("last_update"), inline = TRUE)
        )
      )
    ),

    # Refresh controls
    fluidRow(
      column(12,
        actionButton(
          ns("refresh_now"),
          "🔄 Atualizar Agora",
          class = "btn-primary",
          style = "margin-bottom: 15px;"
        ),
        checkboxInput(
          ns("auto_refresh"),
          "Atualização automática (30s)",
          value = TRUE
        )
      )
    ),

    # Main navigation tabs
    fluidRow(
      column(12,
        tabsetPanel(
          type = "tabs",
          id = ns("main_tabs"),

          # ===================================================================
          # DASHBOARD TAB - KPI Overview
          # ===================================================================
          tabPanel(
            title = "Dashboard",
            icon = icon("tachometer-alt"),
            br(),

            # KPI Cards Row
            fluidRow(
              # Database Connection Status
              column(3,
                div(
                  class = "info-box",
                  style = uiOutput(ns("kpi_db_style"), inline = TRUE),
                  span(class = "info-box-icon", icon("database")),
                  div(class = "info-box-content",
                    span(class = "info-box-text", "Conexão DB"),
                    span(class = "info-box-number", textOutput(ns("kpi_db_status"), inline = TRUE))
                  )
                )
              ),

              # Index Health Status
              column(3,
                div(
                  class = "info-box",
                  style = uiOutput(ns("kpi_index_style"), inline = TRUE),
                  span(class = "info-box-icon", icon("list-ol")),
                  div(class = "info-box-content",
                    span(class = "info-box-text", "Índices"),
                    span(class = "info-box-number", textOutput(ns("kpi_index_count"), inline = TRUE))
                  )
                )
              ),

              # Query Performance Status
              column(3,
                div(
                  class = "info-box",
                  style = uiOutput(ns("kpi_query_style"), inline = TRUE),
                  span(class = "info-box-icon", icon("bolt")),
                  div(class = "info-box-content",
                    span(class = "info-box-text", "Performance"),
                    span(class = "info-box-number", textOutput(ns("kpi_query_speed"), inline = TRUE))
                  )
                )
              ),

              # Table Health Status
              column(3,
                div(
                  class = "info-box",
                  style = uiOutput(ns("kpi_health_style"), inline = TRUE),
                  span(class = "info-box-icon", icon("heartbeat")),
                  div(class = "info-box-content",
                    span(class = "info-box-text", "Saúde da Tabela"),
                    span(class = "info-box-number", textOutput(ns("kpi_health_status"), inline = TRUE))
                  )
                )
              )
            ),

            br(),

            # Quick Stats Summary
            fluidRow(
              column(12,
                h4("Resumo Rápido"),
                wellPanel(
                  fluidRow(
                    column(4,
                      h5("📦 Tamanho da Base"),
                      textOutput(ns("summary_total_size"))
                    ),
                    column(4,
                      h5("📄 Total de Documentos"),
                      textOutput(ns("summary_row_count"))
                    ),
                    column(4,
                      h5("🔍 Índices Ativos"),
                      textOutput(ns("summary_index_size"))
                    )
                  )
                )
              )
            ),

            # Performance Timeline (placeholder for future)
            fluidRow(
              column(12,
                h4("Histórico de Performance (próxima versão)"),
                p("Gráficos de tendência de performance ao longo do tempo serão adicionados em versões futuras.")
              )
            )
          ),

          # ===================================================================
          # INDEX STATUS TAB
          # ===================================================================
          tabPanel(
            title = "Status dos Índices",
            icon = icon("list"),
            br(),

            fluidRow(
              column(12,
                h4("Índices do Banco de Dados"),
                p("Todos os índices na tabela 'documents' com estatísticas de uso."),

                # Index recommendations
                uiOutput(ns("index_recommendations")),

                # Index table
                DT::dataTableOutput(ns("index_table")),

                br(),
                downloadButton(ns("download_indexes"), "⬇️ Exportar CSV")
              )
            ),

            br(),

            fluidRow(
              column(12,
                h4("Sobre os Índices"),
                wellPanel(
                  tags$ul(
                    tags$li(strong("idx_documents_tipo:"), " Índice para filtragem rápida por tipo de documento"),
                    tags$li(strong("idx_documents_data_desc:"), " Índice para ordenação por data (mais recentes primeiro)"),
                    tags$li(strong("idx_documents_tipo_data:"), " Índice composto para consultas tipo+data (otimizado)"),
                    tags$li(strong("idx_documents_titulo_gin:"), " Índice de texto completo em português para busca"),
                    tags$li(strong("Scans:"), " Número de vezes que o índice foi usado"),
                    tags$li(strong("Tuples Read/Fetched:"), " Número de registros lidos/retornados via índice")
                  )
                )
              )
            )
          ),

          # ===================================================================
          # QUERY PERFORMANCE TAB
          # ===================================================================
          tabPanel(
            title = "Performance de Consultas",
            icon = icon("stopwatch"),
            br(),

            fluidRow(
              column(12,
                h4("Benchmarks de Consultas Típicas"),
                p("Tempo de execução para consultas comuns da aplicação."),

                # Performance assessment
                uiOutput(ns("performance_assessment")),

                br(),

                # Query timing results
                wellPanel(
                  h5("⚡ Consulta 1: Filtrar por Tipo + Ordenar por Data"),
                  p(strong("Query:"), code("SELECT * FROM documents WHERE tipo = 'Lei' ORDER BY data DESC LIMIT 100")),
                  p(strong("Tempo:"), textOutput(ns("query1_time"), inline = TRUE), " segundos"),
                  p(strong("Resultados:"), textOutput(ns("query1_rows"), inline = TRUE), " linhas"),
                  hr(),

                  h5("🔍 Consulta 2: Busca de Texto no Título"),
                  p(strong("Query:"), code("SELECT * FROM documents WHERE titulo ILIKE '%transporte%' ORDER BY data DESC LIMIT 100")),
                  p(strong("Tempo:"), textOutput(ns("query2_time"), inline = TRUE), " segundos"),
                  p(strong("Resultados:"), textOutput(ns("query2_rows"), inline = TRUE), " linhas"),
                  hr(),

                  h5("📊 Consulta 3: Contagem por Tipo"),
                  p(strong("Query:"), code("SELECT tipo, COUNT(*) FROM documents GROUP BY tipo ORDER BY count DESC")),
                  p(strong("Tempo:"), textOutput(ns("query3_time"), inline = TRUE), " segundos"),
                  p(strong("Resultados:"), textOutput(ns("query3_rows"), inline = TRUE), " tipos diferentes")
                )
              )
            ),

            br(),

            fluidRow(
              column(12,
                h4("Benchmarks de Referência"),
                wellPanel(
                  tags$ul(
                    tags$li(strong("EXCELENTE:"), " < 50ms para filtros, < 100ms para busca de texto"),
                    tags$li(strong("BOM:"), " 50-200ms para filtros, 100-500ms para busca de texto"),
                    tags$li(strong("LENTO:"), " > 200ms para filtros, > 500ms para busca (requer otimização)")
                  )
                )
              )
            )
          ),

          # ===================================================================
          # TABLE HEALTH TAB
          # ===================================================================
          tabPanel(
            title = "Saúde da Tabela",
            icon = icon("medkit"),
            br(),

            fluidRow(
              column(12,
                h4("Estatísticas da Tabela 'documents'"),

                # Table size info
                wellPanel(
                  fluidRow(
                    column(4,
                      h5("💾 Tamanho Total"),
                      h3(textOutput(ns("table_total_size"), inline = TRUE)),
                      p("Tabela + Índices")
                    ),
                    column(4,
                      h5("📋 Tamanho da Tabela"),
                      h3(textOutput(ns("table_data_size"), inline = TRUE)),
                      p("Apenas dados")
                    ),
                    column(4,
                      h5("🔖 Tamanho dos Índices"),
                      h3(textOutput(ns("table_index_size"), inline = TRUE)),
                      p("Todos os índices")
                    )
                  )
                ),

                br(),

                # Row counts
                wellPanel(
                  fluidRow(
                    column(6,
                      h5("📄 Total de Linhas"),
                      h3(textOutput(ns("table_row_count"), inline = TRUE)),
                      p("Documentos no banco")
                    ),
                    column(6,
                      h5("📑 Tipos Únicos"),
                      h3(textOutput(ns("table_unique_tipos"), inline = TRUE)),
                      p("Tipos diferentes de documentos")
                    )
                  )
                )
              )
            ),

            br(),

            fluidRow(
              column(12,
                h4("Saúde e Manutenção"),

                # Health metrics
                wellPanel(
                  h5("🧹 Status de Tuplas"),
                  fluidRow(
                    column(4,
                      p(strong("Tuplas Vivas:")),
                      p(textOutput(ns("health_live_tuples"), inline = TRUE))
                    ),
                    column(4,
                      p(strong("Tuplas Mortas:")),
                      p(textOutput(ns("health_dead_tuples"), inline = TRUE))
                    ),
                    column(4,
                      p(strong("% Tuplas Mortas:")),
                      p(textOutput(ns("health_dead_pct"), inline = TRUE))
                    )
                  ),

                  hr(),

                  h5("⏰ Última Manutenção"),
                  fluidRow(
                    column(6,
                      p(strong("VACUUM:")),
                      p(textOutput(ns("health_last_vacuum"), inline = TRUE))
                    ),
                    column(6,
                      p(strong("ANALYZE:")),
                      p(textOutput(ns("health_last_analyze"), inline = TRUE))
                    )
                  )
                ),

                # Health assessment
                uiOutput(ns("health_recommendations"))
              )
            )
          ),

          # ===================================================================
          # REAL-TIME MONITORING TAB
          # ===================================================================
          tabPanel(
            title = "Monitoramento",
            icon = icon("chart-line"),
            br(),

            fluidRow(
              column(12,
                h4("Monitoramento em Tempo Real"),
                p("Visualização consolidada de todas as métricas de performance."),

                wellPanel(
                  h5("⚙️ Configurações"),
                  checkboxInput(
                    ns("auto_refresh_detail"),
                    "Atualização automática (30 segundos)",
                    value = TRUE
                  ),
                  actionButton(
                    ns("refresh_detail"),
                    "🔄 Atualizar Agora",
                    class = "btn-success"
                  ),
                  hr(),
                  p(strong("Status do Monitoramento:")),
                  textOutput(ns("monitoring_status"))
                )
              )
            ),

            br(),

            fluidRow(
              column(12,
                h4("Log de Monitoramento"),
                verbatimTextOutput(ns("monitoring_log"))
              )
            )
          )
        )
      )
    )
  )
}

#' Performance Monitoring Server
#'
#' Server logic for the performance monitoring module.
#' Handles data refresh, metric calculations, and reactive outputs.
#'
#' @param id Character string for module namespace ID
#' @param db_connection Reactive expression returning database connection
#' @export
performanceMonitoringServer <- function(id, db_connection) {
  moduleServer(id, function(input, output, session) {

    # =========================================================================
    # REACTIVE VALUES & DATA STORAGE
    # =========================================================================

    rv <- reactiveValues(
      last_update = Sys.time(),
      index_data = NULL,
      performance_data = NULL,
      stats_data = NULL,
      health_data = NULL,
      monitoring_log = "Sistema iniciado...\n"
    )

    # =========================================================================
    # DATA REFRESH FUNCTION
    # =========================================================================

    refresh_data <- function() {
      conn <- db_connection()

      if (is.null(conn)) {
        rv$monitoring_log <- paste0(
          rv$monitoring_log,
          format(Sys.time(), "%H:%M:%S"), " - ❌ Falha na conexão com banco de dados\n"
        )
        return(NULL)
      }

      tryCatch({
        # Get all monitoring data
        rv$index_data <- check_indexes(conn)
        rv$performance_data <- check_query_performance(conn)
        rv$stats_data <- check_table_statistics(conn)
        rv$health_data <- check_database_health(conn)
        rv$last_update <- Sys.time()

        rv$monitoring_log <- paste0(
          rv$monitoring_log,
          format(Sys.time(), "%H:%M:%S"), " - ✓ Dados atualizados com sucesso\n"
        )
      }, error = function(e) {
        rv$monitoring_log <- paste0(
          rv$monitoring_log,
          format(Sys.time(), "%H:%M:%S"), " - ❌ Erro: ", conditionMessage(e), "\n"
        )
      })
    }

    # Initial data load
    observe({
      refresh_data()
    })

    # Manual refresh button
    observeEvent(input$refresh_now, {
      refresh_data()
    })

    observeEvent(input$refresh_detail, {
      refresh_data()
    })

    # Auto-refresh timer (30 seconds)
    observe({
      if (isTRUE(input$auto_refresh) || isTRUE(input$auto_refresh_detail)) {
        invalidateLater(30000)  # 30 seconds
        isolate(refresh_data())
      }
    })

    # =========================================================================
    # LAST UPDATE DISPLAY
    # =========================================================================

    output$last_update <- renderText({
      format(rv$last_update, "%H:%M:%S")
    })

    # =========================================================================
    # DASHBOARD TAB - KPI OUTPUTS
    # =========================================================================

    # Database connection status
    output$kpi_db_status <- renderText({
      if (is.null(db_connection())) "OFFLINE" else "ONLINE"
    })

    output$kpi_db_style <- renderUI({
      if (is.null(db_connection())) {
        "background-color: #dc3545;"  # Red
      } else {
        "background-color: #28a745;"  # Green
      }
    })

    # Index count and status
    output$kpi_index_count <- renderText({
      if (is.null(rv$index_data)) return("--")
      paste0(nrow(rv$index_data), "/10")
    })

    output$kpi_index_style <- renderUI({
      if (is.null(rv$index_data)) return("background-color: #6c757d;")

      required_indexes <- c(
        "idx_documents_tipo",
        "idx_documents_data_desc",
        "idx_documents_tipo_data",
        "idx_documents_titulo_gin"
      )

      existing <- rv$index_data$indexname
      missing <- setdiff(required_indexes, existing)

      if (length(missing) == 0) {
        "background-color: #28a745;"  # Green
      } else if (length(missing) <= 2) {
        "background-color: #ffc107;"  # Yellow
      } else {
        "background-color: #dc3545;"  # Red
      }
    })

    # Query performance status
    output$kpi_query_speed <- renderText({
      if (is.null(rv$performance_data)) return("--")

      filter_time <- rv$performance_data$filter_time

      if (filter_time < 0.05) {
        "EXCELENTE"
      } else if (filter_time < 0.2) {
        "BOM"
      } else {
        "LENTO"
      }
    })

    output$kpi_query_style <- renderUI({
      if (is.null(rv$performance_data)) return("background-color: #6c757d;")

      filter_time <- rv$performance_data$filter_time

      if (filter_time < 0.05) {
        "background-color: #28a745;"  # Green
      } else if (filter_time < 0.2) {
        "background-color: #ffc107;"  # Yellow
      } else {
        "background-color: #dc3545;"  # Red
      }
    })

    # Table health status
    output$kpi_health_status <- renderText({
      if (is.null(rv$health_data)) return("--")

      dead_pct <- rv$health_data$dead_tuple_pct

      if (is.na(dead_pct)) {
        "OK"
      } else if (dead_pct < 5) {
        "EXCELENTE"
      } else if (dead_pct < 10) {
        "BOM"
      } else {
        "ATENÇÃO"
      }
    })

    output$kpi_health_style <- renderUI({
      if (is.null(rv$health_data)) return("background-color: #6c757d;")

      dead_pct <- rv$health_data$dead_tuple_pct

      if (is.na(dead_pct) || dead_pct < 5) {
        "background-color: #28a745;"  # Green
      } else if (dead_pct < 10) {
        "background-color: #ffc107;"  # Yellow
      } else {
        "background-color: #dc3545;"  # Red
      }
    })

    # Summary stats
    output$summary_total_size <- renderText({
      if (is.null(rv$stats_data)) return("--")
      rv$stats_data$total_size
    })

    output$summary_row_count <- renderText({
      if (is.null(rv$stats_data)) return("--")
      format(rv$stats_data$row_count, big.mark = ",")
    })

    output$summary_index_size <- renderText({
      if (is.null(rv$stats_data)) return("--")
      rv$stats_data$indexes_size
    })

    # =========================================================================
    # INDEX STATUS TAB
    # =========================================================================

    output$index_table <- DT::renderDataTable({
      req(rv$index_data)

      DT::datatable(
        rv$index_data,
        options = list(
          pageLength = 15,
          order = list(list(2, 'desc'))  # Sort by scans
        ),
        rownames = FALSE
      )
    })

    output$index_recommendations <- renderUI({
      req(rv$index_data)

      required_indexes <- c(
        "idx_documents_tipo",
        "idx_documents_data_desc",
        "idx_documents_tipo_data",
        "idx_documents_titulo_gin"
      )

      existing <- rv$index_data$indexname
      missing <- setdiff(required_indexes, existing)

      if (length(missing) > 0) {
        div(
          class = "alert alert-warning",
          icon("exclamation-triangle"),
          strong(" Índices Recomendados Ausentes:"),
          tags$ul(
            lapply(missing, function(idx) tags$li(code(idx)))
          ),
          p("Execute ", code("db/apply_optimizations.sql"), " para criar os índices recomendados.")
        )
      } else {
        div(
          class = "alert alert-success",
          icon("check-circle"),
          strong(" Todos os índices recomendados estão presentes!")
        )
      }
    })

    output$download_indexes <- downloadHandler(
      filename = function() {
        paste0("index_status_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".csv")
      },
      content = function(file) {
        write.csv(rv$index_data, file, row.names = FALSE)
      }
    )

    # =========================================================================
    # QUERY PERFORMANCE TAB
    # =========================================================================

    output$query1_time <- renderText({
      if (is.null(rv$performance_data)) return("--")
      sprintf("%.3f", rv$performance_data$filter_time)
    })

    output$query1_rows <- renderText({
      "100"  # Fixed LIMIT in query
    })

    output$query2_time <- renderText({
      if (is.null(rv$performance_data)) return("--")
      sprintf("%.3f", rv$performance_data$search_time)
    })

    output$query2_rows <- renderText({
      "≤100"  # Up to LIMIT
    })

    output$query3_time <- renderText({
      if (is.null(rv$performance_data)) return("--")
      sprintf("%.3f", rv$performance_data$count_time)
    })

    output$query3_rows <- renderText({
      if (is.null(rv$stats_data)) return("--")
      rv$stats_data$unique_tipos
    })

    output$performance_assessment <- renderUI({
      req(rv$performance_data)

      filter_time <- rv$performance_data$filter_time
      search_time <- rv$performance_data$search_time

      filter_status <- if (filter_time < 0.05) {
        list(class = "alert-success", icon = "check-circle", text = "EXCELENTE")
      } else if (filter_time < 0.2) {
        list(class = "alert-warning", icon = "exclamation-triangle", text = "BOM")
      } else {
        list(class = "alert-danger", icon = "times-circle", text = "LENTO")
      }

      search_status <- if (search_time < 0.1) {
        list(class = "alert-success", icon = "check-circle", text = "EXCELENTE")
      } else if (search_time < 0.5) {
        list(class = "alert-warning", icon = "exclamation-triangle", text = "MODERADO")
      } else {
        list(class = "alert-danger", icon = "times-circle", text = "LENTO")
      }

      div(
        div(
          class = paste("alert", filter_status$class),
          icon(filter_status$icon),
          strong(" Consultas de Filtro: "), filter_status$text,
          sprintf(" (%.0fms)", filter_time * 1000)
        ),
        div(
          class = paste("alert", search_status$class),
          icon(search_status$icon),
          strong(" Busca de Texto: "), search_status$text,
          sprintf(" (%.0fms)", search_time * 1000)
        )
      )
    })

    # =========================================================================
    # TABLE HEALTH TAB
    # =========================================================================

    output$table_total_size <- renderText({
      if (is.null(rv$stats_data)) return("--")
      rv$stats_data$total_size
    })

    output$table_data_size <- renderText({
      if (is.null(rv$stats_data)) return("--")
      rv$stats_data$table_size
    })

    output$table_index_size <- renderText({
      if (is.null(rv$stats_data)) return("--")
      rv$stats_data$indexes_size
    })

    output$table_row_count <- renderText({
      if (is.null(rv$stats_data)) return("--")
      format(rv$stats_data$row_count, big.mark = ",")
    })

    output$table_unique_tipos <- renderText({
      if (is.null(rv$stats_data)) return("--")
      rv$stats_data$unique_tipos
    })

    output$health_live_tuples <- renderText({
      if (is.null(rv$health_data)) return("--")
      format(rv$health_data$live_tuples, big.mark = ",")
    })

    output$health_dead_tuples <- renderText({
      if (is.null(rv$health_data)) return("--")
      format(rv$health_data$dead_tuples, big.mark = ",")
    })

    output$health_dead_pct <- renderText({
      if (is.null(rv$health_data)) return("--")
      if (is.na(rv$health_data$dead_tuple_pct)) return("0%")
      sprintf("%.2f%%", rv$health_data$dead_tuple_pct)
    })

    output$health_last_vacuum <- renderText({
      if (is.null(rv$health_data)) return("--")
      if (is.na(rv$health_data$last_autovacuum)) return("Nunca")
      format(rv$health_data$last_autovacuum, "%Y-%m-%d %H:%M")
    })

    output$health_last_analyze <- renderText({
      if (is.null(rv$health_data)) return("--")
      if (is.na(rv$health_data$last_autoanalyze)) return("Nunca")
      format(rv$health_data$last_autoanalyze, "%Y-%m-%d %H:%M")
    })

    output$health_recommendations <- renderUI({
      req(rv$health_data)

      dead_pct <- rv$health_data$dead_tuple_pct

      if (is.na(dead_pct) || dead_pct < 5) {
        div(
          class = "alert alert-success",
          icon("check-circle"),
          strong(" Saúde da tabela: EXCELENTE"),
          p("A tabela está em boas condições. Nenhuma manutenção necessária.")
        )
      } else if (dead_pct < 10) {
        div(
          class = "alert alert-warning",
          icon("exclamation-triangle"),
          strong(" Saúde da tabela: BOA"),
          p(sprintf("%.1f%% de tuplas mortas. Considere executar VACUUM em breve.", dead_pct))
        )
      } else {
        div(
          class = "alert alert-danger",
          icon("times-circle"),
          strong(" Saúde da tabela: ATENÇÃO"),
          p(sprintf("%.1f%% de tuplas mortas. Execute VACUUM imediatamente!", dead_pct)),
          p(code("VACUUM ANALYZE documents;"))
        )
      }
    })

    # =========================================================================
    # MONITORING TAB
    # =========================================================================

    output$monitoring_status <- renderText({
      if (isTRUE(input$auto_refresh_detail)) {
        "🟢 Monitoramento ativo (atualização a cada 30 segundos)"
      } else {
        "🟡 Monitoramento pausado (clique em 'Atualizar Agora' para atualizar)"
      }
    })

    output$monitoring_log <- renderText({
      rv$monitoring_log
    })

  })
}
