# ==============================================================================
# EXECUTIVE EXPORT MODULE
# ==============================================================================
# Shiny module for PDF/HTML export with Cloud Storage integration
# Integrates all Week 2 export functionality
#
# Author: Monitor Legislativo Team
# Date: 2025-11-26
# Version: 1.0
# ==============================================================================

# Source required utilities
if (file.exists("R/utils/kpi_calculations.R")) {
  source("R/utils/kpi_calculations.R")
}
if (file.exists("R/utils/pdf_generator.R")) {
  source("R/utils/pdf_generator.R")
}
if (file.exists("R/utils/html_report_generator.R")) {
  source("R/utils/html_report_generator.R")
}
if (file.exists("R/utils/cloud_storage.R")) {
  source("R/utils/cloud_storage.R")
}

#' Executive Export UI Module
#'
#' @param id Module namespace ID
#' @return Shiny UI elements
#' @export
executive_export_ui <- function(id) {
  ns <- NS(id)

  tagList(
    # Export buttons panel
    div(
      style = "margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #007bff;",

      h4(
        HTML("<i class='fa fa-download'></i> Exportar Relatório"),
        style = "margin-top: 0; margin-bottom: 15px;"
      ),

      p(
        "Gere relatórios executivos em PDF ou HTML para compartilhar com stakeholders.",
        style = "color: #6c757d; margin-bottom: 20px;"
      ),

      fluidRow(
        column(4,
          actionButton(
            ns("export_pdf"),
            HTML("<i class='fa fa-file-pdf'></i> Exportar PDF"),
            class = "btn-primary btn-block",
            style = "margin-bottom: 10px;"
          )
        ),
        column(4,
          actionButton(
            ns("export_html"),
            HTML("<i class='fa fa-file-code'></i> Exportar HTML"),
            class = "btn-success btn-block",
            style = "margin-bottom: 10px;"
          )
        ),
        column(4,
          actionButton(
            ns("refresh_data"),
            HTML("<i class='fa fa-sync-alt'></i> Atualizar Dados"),
            class = "btn-info btn-block",
            style = "margin-bottom: 10px;"
          )
        )
      ),

      # Export status and download link
      uiOutput(ns("export_status")),
      uiOutput(ns("download_link"))
    )
  )
}

#' Executive Export Server Module
#'
#' @param id Module namespace ID
#' @param db_pool Database connection pool
#' @return Server logic
#' @export
executive_export_server <- function(id, db_pool) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Reactive values for export state
    export_state <- reactiveValues(
      status = NULL,
      message = NULL,
      download_url = NULL,
      object_name = NULL
    )

    # Export PDF handler
    observeEvent(input$export_pdf, {
      cat("📄 PDF export requested\n")

      # Clear previous state
      export_state$status <- "processing"
      export_state$message <- "Gerando relatório PDF..."
      export_state$download_url <- NULL

      tryCatch({
        # Fetch data from materialized views
        kpis <- get_executive_kpis(db_pool)
        state_summary <- get_state_summary(db_pool, top_n = 10)
        monthly_trends <- get_monthly_trends(db_pool, months = 12)

        # Check for errors
        if (!is.null(kpis$error)) {
          stop(sprintf("Error fetching KPIs: %s", kpis$error))
        }

        # Generate PDF
        pdf_path <- generate_executive_pdf(kpis, state_summary, monthly_trends)

        if (is.null(pdf_path)) {
          stop("PDF generation failed")
        }

        # Upload to Cloud Storage and get signed URL
        result <- upload_report_and_share(pdf_path, expires_in_hours = 72)

        if (is.null(result)) {
          stop("Failed to upload to Cloud Storage")
        }

        # Update state
        export_state$status <- "success"
        export_state$message <- "Relatório PDF gerado com sucesso!"
        export_state$download_url <- result$signed_url
        export_state$object_name <- result$object_name

        # Clean up local file
        if (file.exists(pdf_path)) {
          file.remove(pdf_path)
        }

        cat("✅ PDF export completed successfully\n")

      }, error = function(e) {
        cat("❌ PDF export error:", e$message, "\n")
        export_state$status <- "error"
        export_state$message <- sprintf("Erro ao gerar PDF: %s", e$message)
        export_state$download_url <- NULL
      })
    })

    # Export HTML handler
    observeEvent(input$export_html, {
      cat("📄 HTML export requested\n")

      # Clear previous state
      export_state$status <- "processing"
      export_state$message <- "Gerando relatório HTML..."
      export_state$download_url <- NULL

      tryCatch({
        # Fetch data from materialized views
        kpis <- get_executive_kpis(db_pool)
        state_summary <- get_state_summary(db_pool, top_n = 10)
        monthly_trends <- get_monthly_trends(db_pool, months = 12)

        # Check for errors
        if (!is.null(kpis$error)) {
          stop(sprintf("Error fetching KPIs: %s", kpis$error))
        }

        # Generate HTML
        html_path <- generate_executive_html(kpis, state_summary, monthly_trends)

        if (is.null(html_path)) {
          stop("HTML generation failed")
        }

        # Upload to Cloud Storage and get signed URL
        result <- upload_report_and_share(html_path, expires_in_hours = 72)

        if (is.null(result)) {
          stop("Failed to upload to Cloud Storage")
        }

        # Update state
        export_state$status <- "success"
        export_state$message <- "Relatório HTML gerado com sucesso!"
        export_state$download_url <- result$signed_url
        export_state$object_name <- result$object_name

        # Clean up local file
        if (file.exists(html_path)) {
          file.remove(html_path)
        }

        cat("✅ HTML export completed successfully\n")

      }, error = function(e) {
        cat("❌ HTML export error:", e$message, "\n")
        export_state$status <- "error"
        export_state$message <- sprintf("Erro ao gerar HTML: %s", e$message)
        export_state$download_url <- NULL
      })
    })

    # Refresh data handler (refresh materialized views)
    observeEvent(input$refresh_data, {
      cat("🔄 Data refresh requested\n")

      export_state$status <- "processing"
      export_state$message <- "Atualizando visões materializadas..."
      export_state$download_url <- NULL

      tryCatch({
        success <- refresh_materialized_views(db_pool)

        if (success) {
          export_state$status <- "success"
          export_state$message <- "Dados atualizados com sucesso!"
          cat("✅ Data refresh completed\n")
        } else {
          stop("Refresh failed")
        }

      }, error = function(e) {
        cat("❌ Data refresh error:", e$message, "\n")
        export_state$status <- "error"
        export_state$message <- sprintf("Erro ao atualizar dados: %s", e$message)
      })
    })

    # Export status output
    output$export_status <- renderUI({
      if (is.null(export_state$status)) {
        return(NULL)
      }

      style_class <- switch(export_state$status,
        "processing" = "alert alert-info",
        "success" = "alert alert-success",
        "error" = "alert alert-danger",
        "alert alert-secondary"
      )

      icon_class <- switch(export_state$status,
        "processing" = "fa-spinner fa-spin",
        "success" = "fa-check-circle",
        "error" = "fa-exclamation-triangle",
        "fa-info-circle"
      )

      div(
        class = style_class,
        style = "margin-top: 20px;",
        HTML(sprintf("<i class='fa %s'></i> %s", icon_class, export_state$message))
      )
    })

    # Download link output
    output$download_link <- renderUI({
      if (is.null(export_state$download_url) || export_state$status != "success") {
        return(NULL)
      }

      div(
        style = "margin-top: 15px; padding: 15px; background: white; border-radius: 4px; border: 1px solid #dee2e6;",

        h5(
          HTML("<i class='fa fa-link'></i> Link para Download"),
          style = "margin-top: 0;"
        ),

        p(
          "O relatório está disponível para download através do link abaixo. ",
          "O link expira em 72 horas.",
          style = "font-size: 14px; color: #6c757d; margin-bottom: 15px;"
        ),

        div(
          style = "display: flex; gap: 10px;",

          tags$a(
            href = export_state$download_url,
            target = "_blank",
            class = "btn btn-primary",
            HTML("<i class='fa fa-download'></i> Baixar Relatório")
          ),

          actionButton(
            ns("copy_link"),
            HTML("<i class='fa fa-copy'></i> Copiar Link"),
            class = "btn btn-outline-secondary",
            onclick = sprintf("navigator.clipboard.writeText('%s'); alert('Link copiado para a área de transferência!');", export_state$download_url)
          )
        ),

        p(
          sprintf("Nome do arquivo: %s", export_state$object_name),
          style = "font-size: 12px; color: #6c757d; margin-top: 15px; margin-bottom: 0;"
        )
      )
    })
  })
}

cat("✅ Executive Export Module loaded\n")
