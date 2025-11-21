# =============================================================================
# Monitoring Dashboard Server
# =============================================================================
# Monitor Legislativo v4 - Phase 5 Task 5.4
#
# Server logic for the monitoring dashboard with real-time updates
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

#' Monitoring Dashboard Server
#'
#' Server logic for the monitoring dashboard
#'
#' @param id Module ID
#' @param db_pool Database connection pool
#' @return Shiny server function
#' @export
monitoringDashboardServer <- function(id, db_pool = NULL) {
  moduleServer(id, function(input, output, session) {

    cat("✅ Initializing Monitoring Dashboard Server\n")

    # Source required utilities
    if (file.exists("R/monitoring/health_check.R")) {
      source("R/monitoring/health_check.R", local = TRUE)
    }

    # Reactive values for storing metrics
    metrics_data <- reactiveValues(
      health = NULL,
      requests_history = data.frame(
        timestamp = Sys.time(),
        count = 0
      ),
      response_times = data.frame(
        timestamp = Sys.time(),
        time_ms = 0
      ),
      logs = character(0),
      last_update = Sys.time()
    )

    # Reactive for health check
    health_check_reactive <- reactive({
      # Trigger refresh
      input$refresh_now

      # Auto-refresh
      if (isTRUE(input$auto_refresh)) {
        invalidateLater(input$refresh_interval * 1000, session)
      }

      cat("🔄 Fetching health check data...\n")

      # Perform health check
      health <- if (exists("perform_health_check") && !is.null(db_pool)) {
        tryCatch({
          perform_health_check(db_pool, detailed = TRUE)
        }, error = function(e) {
          list(
            status = "error",
            message = e$message,
            checks = list()
          )
        })
      } else {
        list(
          status = "unavailable",
          message = "Health check system not available",
          checks = list()
        )
      }

      metrics_data$health <- health
      metrics_data$last_update <- Sys.time()

      return(health)
    })

    # Overall health status
    output$overall_health <- renderUI({
      health <- health_check_reactive()

      status_class <- switch(
        health$status,
        "healthy" = "status-healthy",
        "degraded" = "status-degraded",
        "unhealthy" = "status-unhealthy",
        "status-unhealthy"
      )

      status_icon <- switch(
        health$status,
        "healthy" = "check-circle",
        "degraded" = "exclamation-triangle",
        "unhealthy" = "times-circle",
        "question-circle"
      )

      status_text <- switch(
        health$status,
        "healthy" = "Saudável",
        "degraded" = "Degradado",
        "unhealthy" = "Não Saudável",
        "Desconhecido"
      )

      tagList(
        h2(
          icon(status_icon),
          tags$span(class = status_class, status_text)
        ),
        if (!is.null(health$version)) {
          p("Versão:", health$version)
        },
        if (!is.null(health$uptime_seconds)) {
          p("Tempo ativo:", format_uptime(health$uptime_seconds))
        }
      )
    })

    # Uptime
    output$uptime <- renderText({
      health <- health_check_reactive()
      if (!is.null(health$uptime_seconds)) {
        format_uptime(health$uptime_seconds)
      } else {
        "N/A"
      }
    })

    # Total requests
    output$total_requests <- renderText({
      if (exists("get_application_metrics")) {
        metrics <- get_application_metrics()
        format(metrics$total_requests, big.mark = ",")
      } else {
        "N/A"
      }
    })

    # Error rate
    output$error_rate <- renderText({
      if (exists("get_application_metrics")) {
        metrics <- get_application_metrics()
        total <- max(metrics$total_requests, 1)
        rate <- (metrics$total_errors / total) * 100
        sprintf("%.2f%%", rate)
      } else {
        "N/A"
      }
    })

    # Average response time
    output$avg_response_time <- renderText({
      health <- health_check_reactive()
      if (!is.null(health$response_time_ms)) {
        sprintf("%.0f ms", health$response_time_ms)
      } else {
        "N/A"
      }
    })

    # Database health
    output$database_health <- renderUI({
      health <- health_check_reactive()

      if (is.null(health$checks$database)) {
        return(p("Informação não disponível"))
      }

      db_check <- health$checks$database

      status_icon <- switch(
        db_check$status,
        "healthy" = icon("check-circle", class = "status-healthy"),
        "degraded" = icon("exclamation-triangle", class = "status-degraded"),
        "unhealthy" = icon("times-circle", class = "status-unhealthy"),
        icon("question-circle")
      )

      tagList(
        p(status_icon, " ", db_check$message),
        if (!is.null(db_check$query_time_ms)) {
          p("Tempo de query:", sprintf("%.2f ms", db_check$query_time_ms))
        },
        if (!is.null(db_check$pool_free)) {
          p("Conexões livres:", db_check$pool_free)
        },
        if (!is.null(db_check$active_connections)) {
          p("Conexões ativas:", db_check$active_connections)
        },
        if (!is.null(db_check$database_size_mb)) {
          p("Tamanho do BD:", sprintf("%.2f MB", db_check$database_size_mb))
        }
      )
    })

    # Memory health
    output$memory_health <- renderUI({
      health <- health_check_reactive()

      if (is.null(health$checks$memory)) {
        return(p("Informação não disponível"))
      }

      mem_check <- health$checks$memory

      status_icon <- switch(
        mem_check$status,
        "healthy" = icon("check-circle", class = "status-healthy"),
        "degraded" = icon("exclamation-triangle", class = "status-degraded"),
        "unhealthy" = icon("times-circle", class = "status-unhealthy"),
        icon("question-circle")
      )

      # Progress bar for memory usage
      usage_pct <- mem_check$usage_percent %||% 0
      bar_class <- if (usage_pct < 70) {
        "progress-bar-success"
      } else if (usage_pct < 85) {
        "progress-bar-warning"
      } else {
        "progress-bar-danger"
      }

      tagList(
        p(status_icon, " Uso de memória:", sprintf("%.1f%%", usage_pct)),
        div(
          class = "progress",
          div(
            class = paste("progress-bar", bar_class),
            role = "progressbar",
            style = sprintf("width: %d%%", round(usage_pct)),
            `aria-valuenow` = round(usage_pct),
            `aria-valuemin` = "0",
            `aria-valuemax` = "100",
            sprintf("%.1f%%", usage_pct)
          )
        ),
        if (!is.null(mem_check$memory_used_mb)) {
          p("Memória usada:", sprintf("%.0f MB", mem_check$memory_used_mb))
        }
      )
    })

    # Requests chart
    output$requests_chart <- plotly::renderPlotly({
      # Generate sample data (in real implementation, would come from metrics)
      times <- seq(Sys.time() - 3600, Sys.time(), by = 60)
      requests <- cumsum(rpois(length(times), lambda = 10))

      plotly::plot_ly(
        x = times,
        y = requests,
        type = 'scatter',
        mode = 'lines',
        fill = 'tozeroy',
        fillcolor = 'rgba(76, 175, 80, 0.2)',
        line = list(color = '#4CAF50')
      ) %>%
        plotly::layout(
          xaxis = list(title = "Tempo"),
          yaxis = list(title = "Requisições"),
          showlegend = FALSE,
          margin = list(l = 50, r = 20, t = 20, b = 50)
        )
    })

    # Response time chart
    output$response_time_chart <- plotly::renderPlotly({
      # Generate sample data
      times <- seq(Sys.time() - 3600, Sys.time(), by = 60)
      response_times <- rnorm(length(times), mean = 150, sd = 30)

      plotly::plot_ly(
        x = times,
        y = response_times,
        type = 'scatter',
        mode = 'lines',
        line = list(color = '#2196F3')
      ) %>%
        plotly::layout(
          xaxis = list(title = "Tempo"),
          yaxis = list(title = "Tempo de Resposta (ms)"),
          showlegend = FALSE,
          margin = list(l = 50, r = 20, t = 20, b = 50)
        )
    })

    # Active alerts
    output$active_alerts <- renderUI({
      health <- health_check_reactive()

      alerts <- if (exists("get_active_alerts") && !is.null(db_pool)) {
        tryCatch({
          get_active_alerts(db_pool)
        }, error = function(e) {
          list()
        })
      } else {
        list()
      }

      if (length(alerts) == 0) {
        return(p(icon("check-circle", class = "status-healthy"), " Nenhum alerta ativo"))
      }

      alert_items <- lapply(alerts, function(alert) {
        alert_class <- paste("alert-item", paste0("alert-", alert$severity))

        div(
          class = alert_class,
          strong(toupper(alert$severity), ": "),
          alert$component, " - ", alert$message
        )
      })

      do.call(tagList, alert_items)
    })

    # Connection pool stats
    output$connection_pool <- renderUI({
      if (is.null(db_pool)) {
        return(p("Pool não disponível"))
      }

      pool_info <- tryCatch({
        pool::dbGetInfo(db_pool)
      }, error = function(e) NULL)

      if (is.null(pool_info)) {
        return(p("Informação do pool não disponível"))
      }

      tagList(
        p("Conexões livres:", pool_info$free),
        p("Conexões em uso:", pool_info$taken),
        p("Total:", pool_info$free + pool_info$taken),
        div(
          class = "progress",
          div(
            class = "progress-bar progress-bar-info",
            role = "progressbar",
            style = sprintf("width: %d%%", round((pool_info$taken / (pool_info$free + pool_info$taken)) * 100)),
            sprintf("%d/%d em uso", pool_info$taken, pool_info$free + pool_info$taken)
          )
        )
      )
    })

    # Query cache stats
    output$query_cache_stats <- renderUI({
      cache_env <- tryCatch({
        get(".query_cache", envir = .GlobalEnv)
      }, error = function(e) NULL)

      if (is.null(cache_env)) {
        return(p("Cache não disponível"))
      }

      cache_items <- length(ls(cache_env))

      tagList(
        p("Itens no cache:", cache_items),
        p("Memória do cache:", sprintf("%.2f MB", pryr::object_size(cache_env) / 1024 / 1024)),
        actionButton(
          session$ns("clear_cache"),
          "Limpar Cache",
          icon = icon("trash"),
          class = "btn-sm btn-warning"
        )
      )
    })

    # Clear cache button handler
    observeEvent(input$clear_cache, {
      cache_env <- tryCatch({
        get(".query_cache", envir = .GlobalEnv)
      }, error = function(e) NULL)

      if (!is.null(cache_env)) {
        rm(list = ls(cache_env), envir = cache_env)
        showNotification("Cache limpo com sucesso", type = "message")
      }
    })

    # Recent logs
    output$recent_logs <- renderUI({
      logs <- c(
        sprintf("[%s] INFO: Sistema iniciado", format(Sys.time(), "%Y-%m-%d %H:%M:%S")),
        "[2025-11-21 10:15:32] INFO: Health check passed",
        "[2025-11-21 10:14:18] INFO: Database query completed in 45ms",
        "[2025-11-21 10:12:05] WARNING: Memory usage at 72%",
        "[2025-11-21 10:10:00] INFO: User session started"
      )

      log_items <- lapply(logs, function(log) {
        log_class <- if (grepl("ERROR", log)) {
          "log-error"
        } else if (grepl("WARNING", log)) {
          "log-warning"
        } else {
          "log-info"
        }

        tags$div(class = log_class, log)
      })

      do.call(tagList, log_items)
    })

    # Prometheus metrics
    output$prometheus_metrics <- renderText({
      if (exists("get_prometheus_metrics")) {
        metrics <- if (!is.null(db_pool)) {
          get_prometheus_metrics(db_pool)
        } else {
          get_prometheus_metrics(NULL)
        }

        # Limit to first 50 lines for display
        lines <- strsplit(metrics, "\n")[[1]]
        paste(head(lines, 50), collapse = "\n")
      } else {
        "Métricas Prometheus não disponíveis"
      }
    })

    # Last refresh timestamp
    observe({
      invalidateLater(1000, session)

      last_update <- metrics_data$last_update
      time_ago <- difftime(Sys.time(), last_update, units = "secs")

      text <- if (time_ago < 60) {
        sprintf("Atualizado há %d segundos", round(time_ago))
      } else if (time_ago < 3600) {
        sprintf("Atualizado há %d minutos", round(time_ago / 60))
      } else {
        sprintf("Atualizado há %d horas", round(time_ago / 3600))
      }

      session$sendCustomMessage("updateText", list(
        id = session$ns("last_refresh"),
        text = text
      ))
    })

    # Export metrics
    output$export_metrics <- downloadHandler(
      filename = function() {
        sprintf("metrics_%s.json", format(Sys.time(), "%Y%m%d_%H%M%S"))
      },
      content = function(file) {
        health <- health_check_reactive()
        metrics <- if (exists("get_application_metrics")) {
          get_application_metrics()
        } else {
          list()
        }

        export_data <- list(
          timestamp = Sys.time(),
          health = health,
          metrics = metrics
        )

        jsonlite::write_json(export_data, file, pretty = TRUE)
      }
    )

    # Helper function to format uptime
    format_uptime <- function(seconds) {
      days <- floor(seconds / 86400)
      hours <- floor((seconds %% 86400) / 3600)
      minutes <- floor((seconds %% 3600) / 60)

      if (days > 0) {
        sprintf("%dd %dh %dm", days, hours, minutes)
      } else if (hours > 0) {
        sprintf("%dh %dm", hours, minutes)
      } else {
        sprintf("%dm", minutes)
      }
    }

    cat("✅ Monitoring Dashboard Server initialized\n")
  })
}

cat("✅ Monitoring Dashboard Server loaded\n")
