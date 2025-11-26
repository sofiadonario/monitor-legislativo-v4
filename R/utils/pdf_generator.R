# ==============================================================================
# PDF EXPORT GENERATOR
# ==============================================================================
# Professional PDF report generation using pagedown
# Integrates with Cloud Storage for distribution
#
# Author: Monitor Legislativo Team
# Date: 2025-11-26
# Version: 1.0
# ==============================================================================

library(rmarkdown)
library(pagedown)

#' Generate executive summary PDF report
#'
#' @param kpis List of KPI metrics from get_executive_kpis()
#' @param state_summary Data frame from get_state_summary()
#' @param monthly_trends Data frame from get_monthly_trends()
#' @param output_dir Directory to save PDF (default: /tmp)
#' @return Path to generated PDF file
#' @export
generate_executive_pdf <- function(kpis, state_summary, monthly_trends, output_dir = "/tmp") {
  tryCatch({
    cat("📄 Generating executive PDF report...\n")

    # Create unique filename with timestamp
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- sprintf("executive-report-%s.pdf", timestamp)
    pdf_path <- file.path(output_dir, filename)

    # Create temporary RMarkdown file
    rmd_path <- file.path(output_dir, sprintf("temp-report-%s.Rmd", timestamp))

    # Generate RMarkdown content
    rmd_content <- generate_rmarkdown_content(kpis, state_summary, monthly_trends)

    # Write RMarkdown file
    writeLines(rmd_content, rmd_path)

    # Convert to PDF using pagedown
    pagedown::chrome_print(
      input = rmd_path,
      output = pdf_path,
      timeout = 30,
      verbose = 1
    )

    # Clean up temporary RMarkdown file
    if (file.exists(rmd_path)) {
      file.remove(rmd_path)
    }

    cat("✅ PDF generated successfully:", pdf_path, "\n")
    pdf_path

  }, error = function(e) {
    cat("❌ Error generating PDF:", e$message, "\n")
    NULL
  })
}

#' Generate RMarkdown content for executive report
#'
#' @param kpis KPI metrics
#' @param state_summary State summary data
#' @param monthly_trends Monthly trend data
#' @return Character vector with RMarkdown content
generate_rmarkdown_content <- function(kpis, state_summary, monthly_trends) {
  # Format numbers
  total_docs <- format(kpis$total_documents, big.mark = ",")
  states <- kpis$states_covered
  monthly_avg <- format(round(kpis$monthly_avg), big.mark = ",")
  growth_rate <- sprintf("%.1f%%", kpis$growth_rate)

  # Format dates
  report_date <- format(Sys.time(), "%d de %B de %Y")
  latest_doc_date <- if (!is.na(kpis$latest_document_date)) {
    format(as.Date(kpis$latest_document_date), "%d/%m/%Y")
  } else {
    "N/A"
  }

  # Build top states list
  top_states_html <- if (nrow(state_summary) > 0) {
    paste(
      sapply(1:min(5, nrow(state_summary)), function(i) {
        sprintf(
          "- **%s**: %s documentos (%s recentes)",
          state_summary$state[i],
          format(state_summary$document_count[i], big.mark = ","),
          format(state_summary$recent_count[i], big.mark = ",")
        )
      }),
      collapse = "\n"
    )
  } else {
    "Nenhum dado disponível"
  }

  # RMarkdown template
  c(
    "---",
    "title: \"Monitor Legislativo - Relatório Executivo\"",
    "subtitle: \"Análise de Legislação de Transporte Brasileiro\"",
    sprintf("date: \"%s\"", report_date),
    "output:",
    "  pagedown::html_paged:",
    "    toc: false",
    "    number_sections: false",
    "    css: [\"default\", \"default-fonts\"]",
    "---",
    "",
    "```{css, echo=FALSE}",
    ".header-logo {",
    "  text-align: center;",
    "  margin-bottom: 30px;",
    "  padding: 20px;",
    "  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);",
    "  color: white;",
    "  border-radius: 8px;",
    "}",
    "",
    ".kpi-card {",
    "  border-left: 4px solid #007bff;",
    "  padding: 15px;",
    "  margin: 10px 0;",
    "  background: #f8f9fa;",
    "  border-radius: 4px;",
    "}",
    "",
    ".kpi-value {",
    "  font-size: 32px;",
    "  font-weight: bold;",
    "  color: #2c3e50;",
    "}",
    "",
    ".kpi-label {",
    "  font-size: 14px;",
    "  color: #6c757d;",
    "}",
    "",
    ".footer-note {",
    "  text-align: center;",
    "  font-size: 10px;",
    "  color: #6c757d;",
    "  margin-top: 40px;",
    "  padding-top: 20px;",
    "  border-top: 1px solid #dee2e6;",
    "}",
    "```",
    "",
    "<div class='header-logo'>",
    "  <h1 style='margin: 0;'>📊 Monitor Legislativo</h1>",
    "  <p style='margin: 10px 0 0 0; font-size: 18px;'>Relatório Executivo - Legislação de Transporte</p>",
    "</div>",
    "",
    "## Indicadores-Chave de Desempenho",
    "",
    "<div style='display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0;'>",
    "",
    sprintf("  <div class='kpi-card'>"),
    sprintf("    <div class='kpi-value'>%s</div>", total_docs),
    sprintf("    <div class='kpi-label'>Documentos Totais</div>"),
    sprintf("  </div>"),
    "",
    sprintf("  <div class='kpi-card'>"),
    sprintf("    <div class='kpi-value'>%d</div>", states),
    sprintf("    <div class='kpi-label'>Estados Cobertos</div>"),
    sprintf("  </div>"),
    "",
    sprintf("  <div class='kpi-card'>"),
    sprintf("    <div class='kpi-value'>%s</div>", monthly_avg),
    sprintf("    <div class='kpi-label'>Média Mensal (30 dias)</div>"),
    sprintf("  </div>"),
    "",
    sprintf("  <div class='kpi-card'>"),
    sprintf("    <div class='kpi-value'>%s</div>", growth_rate),
    sprintf("    <div class='kpi-label'>Taxa de Crescimento</div>"),
    sprintf("  </div>"),
    "",
    "</div>",
    "",
    "## Estados Mais Ativos",
    "",
    top_states_html,
    "",
    "## Informações do Relatório",
    "",
    sprintf("- **Data do Relatório**: %s", report_date),
    sprintf("- **Documento Mais Recente**: %s", latest_doc_date),
    sprintf("- **Período de Análise**: Últimos 12 meses"),
    sprintf("- **Fonte de Dados**: Monitor Legislativo - Banco de Dados PostgreSQL"),
    "",
    "<div class='footer-note'>",
    "  <p>Este relatório foi gerado automaticamente pelo Monitor Legislativo v4.</p>",
    "  <p>Monitor Legislativo - Sistema de Monitoramento de Legislação de Transporte Brasileiro</p>",
    "  <p>© 2025 - Todos os direitos reservados</p>",
    "</div>"
  )
}

cat("✅ PDF Generator module loaded\n")
