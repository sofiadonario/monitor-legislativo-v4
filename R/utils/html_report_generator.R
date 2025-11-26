# ==============================================================================
# HTML STATIC REPORT GENERATOR
# ==============================================================================
# Self-contained HTML reports for sharing
# No external dependencies - all CSS inline
#
# Author: Monitor Legislativo Team
# Date: 2025-11-26
# Version: 1.0
# ==============================================================================

#' Generate self-contained HTML report
#'
#' @param kpis List of KPI metrics from get_executive_kpis()
#' @param state_summary Data frame from get_state_summary()
#' @param monthly_trends Data frame from get_monthly_trends()
#' @param output_dir Directory to save HTML (default: /tmp)
#' @return Path to generated HTML file
#' @export
generate_executive_html <- function(kpis, state_summary, monthly_trends, output_dir = "/tmp") {
  tryCatch({
    cat("📄 Generating HTML report...\n")

    # Create unique filename with timestamp
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- sprintf("executive-report-%s.html", timestamp)
    html_path <- file.path(output_dir, filename)

    # Generate HTML content
    html_content <- generate_html_content(kpis, state_summary, monthly_trends)

    # Write HTML file
    writeLines(html_content, html_path)

    cat("✅ HTML generated successfully:", html_path, "\n")
    html_path

  }, error = function(e) {
    cat("❌ Error generating HTML:", e$message, "\n")
    NULL
  })
}

#' Generate complete HTML content
#'
#' @param kpis KPI metrics
#' @param state_summary State summary data
#' @param monthly_trends Monthly trend data
#' @return Character vector with HTML content
generate_html_content <- function(kpis, state_summary, monthly_trends) {
  # Format data
  total_docs <- format(kpis$total_documents, big.mark = ",")
  states <- kpis$states_covered
  monthly_avg <- format(round(kpis$monthly_avg), big.mark = ",")
  growth_rate <- sprintf("%.1f%%", kpis$growth_rate)

  report_date <- format(Sys.time(), "%d de %B de %Y às %H:%M")
  latest_doc_date <- if (!is.na(kpis$latest_document_date)) {
    format(as.Date(kpis$latest_document_date), "%d/%m/%Y")
  } else {
    "N/A"
  }

  # Build states table HTML
  states_table_html <- if (nrow(state_summary) > 0) {
    rows <- sapply(1:nrow(state_summary), function(i) {
      sprintf(
        "<tr>
          <td>%s</td>
          <td style='text-align: right;'>%s</td>
          <td style='text-align: right;'>%s</td>
          <td style='text-align: right;'>%.1f%%</td>
        </tr>",
        state_summary$state[i],
        format(state_summary$document_count[i], big.mark = ","),
        format(state_summary$recent_count[i], big.mark = ","),
        state_summary$recent_pct[i]
      )
    })
    paste(rows, collapse = "\n")
  } else {
    "<tr><td colspan='4' style='text-align: center;'>Nenhum dado disponível</td></tr>"
  }

  # Growth indicator
  growth_color <- if (kpis$growth_rate > 0) "#28a745" else if (kpis$growth_rate < 0) "#dc3545" else "#6c757d"
  growth_icon <- if (kpis$growth_rate > 0) "↑" else if (kpis$growth_rate < 0) "↓" else "→"

  # Complete HTML document
  c(
    "<!DOCTYPE html>",
    "<html lang='pt-BR'>",
    "<head>",
    "  <meta charset='UTF-8'>",
    "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
    "  <title>Monitor Legislativo - Relatório Executivo</title>",
    "  <style>",
    "    * {",
    "      margin: 0;",
    "      padding: 0;",
    "      box-sizing: border-box;",
    "    }",
    "",
    "    body {",
    "      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;",
    "      line-height: 1.6;",
    "      color: #333;",
    "      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);",
    "      padding: 20px;",
    "      min-height: 100vh;",
    "    }",
    "",
    "    .container {",
    "      max-width: 1200px;",
    "      margin: 0 auto;",
    "      background: white;",
    "      border-radius: 12px;",
    "      box-shadow: 0 10px 40px rgba(0,0,0,0.2);",
    "      overflow: hidden;",
    "    }",
    "",
    "    .header {",
    "      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);",
    "      color: white;",
    "      padding: 40px;",
    "      text-align: center;",
    "    }",
    "",
    "    .header h1 {",
    "      font-size: 36px;",
    "      margin-bottom: 10px;",
    "    }",
    "",
    "    .header p {",
    "      font-size: 18px;",
    "      opacity: 0.9;",
    "    }",
    "",
    "    .content {",
    "      padding: 40px;",
    "    }",
    "",
    "    .kpis {",
    "      display: grid;",
    "      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));",
    "      gap: 20px;",
    "      margin-bottom: 40px;",
    "    }",
    "",
    "    .kpi-card {",
    "      background: #f8f9fa;",
    "      border-left: 4px solid #007bff;",
    "      border-radius: 8px;",
    "      padding: 20px;",
    "      transition: all 0.3s ease;",
    "    }",
    "",
    "    .kpi-card:hover {",
    "      transform: translateY(-5px);",
    "      box-shadow: 0 5px 20px rgba(0,0,0,0.1);",
    "    }",
    "",
    "    .kpi-card.success { border-left-color: #28a745; }",
    "    .kpi-card.warning { border-left-color: #ffc107; }",
    "    .kpi-card.info { border-left-color: #17a2b8; }",
    "",
    "    .kpi-value {",
    "      font-size: 32px;",
    "      font-weight: bold;",
    "      color: #2c3e50;",
    "      margin-bottom: 5px;",
    "    }",
    "",
    "    .kpi-label {",
    "      font-size: 14px;",
    "      color: #6c757d;",
    "      text-transform: uppercase;",
    "      letter-spacing: 0.5px;",
    "    }",
    "",
    "    .kpi-trend {",
    "      font-size: 14px;",
    "      margin-top: 8px;",
    "      font-weight: 600;",
    "    }",
    "",
    "    .section {",
    "      margin-bottom: 40px;",
    "    }",
    "",
    "    .section h2 {",
    "      font-size: 24px;",
    "      color: #2c3e50;",
    "      margin-bottom: 20px;",
    "      padding-bottom: 10px;",
    "      border-bottom: 2px solid #007bff;",
    "    }",
    "",
    "    table {",
    "      width: 100%;",
    "      border-collapse: collapse;",
    "      margin-top: 20px;",
    "    }",
    "",
    "    th, td {",
    "      padding: 12px;",
    "      text-align: left;",
    "      border-bottom: 1px solid #dee2e6;",
    "    }",
    "",
    "    th {",
    "      background: #f8f9fa;",
    "      font-weight: 600;",
    "      color: #495057;",
    "      text-transform: uppercase;",
    "      font-size: 12px;",
    "      letter-spacing: 0.5px;",
    "    }",
    "",
    "    tr:hover {",
    "      background: #f8f9fa;",
    "    }",
    "",
    "    .footer {",
    "      background: #f8f9fa;",
    "      padding: 30px 40px;",
    "      text-align: center;",
    "      font-size: 12px;",
    "      color: #6c757d;",
    "      border-top: 1px solid #dee2e6;",
    "    }",
    "",
    "    .footer p {",
    "      margin: 5px 0;",
    "    }",
    "",
    "    .info-box {",
    "      background: #e7f3ff;",
    "      border-left: 4px solid #007bff;",
    "      padding: 15px;",
    "      border-radius: 4px;",
    "      margin-top: 20px;",
    "    }",
    "",
    "    .info-box ul {",
    "      list-style: none;",
    "      padding-left: 0;",
    "    }",
    "",
    "    .info-box li {",
    "      padding: 5px 0;",
    "    }",
    "",
    "    .info-box li:before {",
    "      content: '•';",
    "      color: #007bff;",
    "      font-weight: bold;",
    "      display: inline-block;",
    "      width: 1em;",
    "      margin-left: -1em;",
    "    }",
    "",
    "    @media print {",
    "      body {",
    "        background: white;",
    "        padding: 0;",
    "      }",
    "      .container {",
    "        box-shadow: none;",
    "      }",
    "    }",
    "  </style>",
    "</head>",
    "<body>",
    "  <div class='container'>",
    "    <div class='header'>",
    "      <h1>📊 Monitor Legislativo</h1>",
    "      <p>Relatório Executivo - Legislação de Transporte Brasileiro</p>",
    "    </div>",
    "",
    "    <div class='content'>",
    "      <div class='kpis'>",
    sprintf("        <div class='kpi-card'>"),
    sprintf("          <div class='kpi-value'>%s</div>", total_docs),
    sprintf("          <div class='kpi-label'>Documentos Totais</div>"),
    sprintf("        </div>"),
    "",
    sprintf("        <div class='kpi-card success'>"),
    sprintf("          <div class='kpi-value'>%d</div>", states),
    sprintf("          <div class='kpi-label'>Estados Cobertos</div>"),
    sprintf("          <div class='kpi-label' style='margin-top: 5px;'>%.1f%% de cobertura</div>", (states/27)*100),
    sprintf("        </div>"),
    "",
    sprintf("        <div class='kpi-card info'>"),
    sprintf("          <div class='kpi-value'>%s</div>", monthly_avg),
    sprintf("          <div class='kpi-label'>Média Mensal (30 dias)</div>"),
    sprintf("        </div>"),
    "",
    sprintf("        <div class='kpi-card warning'>"),
    sprintf("          <div class='kpi-value'>%s</div>", growth_rate),
    sprintf("          <div class='kpi-label'>Taxa de Crescimento</div>"),
    sprintf("          <div class='kpi-trend' style='color: %s;'>%s Tendência</div>", growth_color, growth_icon),
    sprintf("        </div>"),
    "      </div>",
    "",
    "      <div class='section'>",
    "        <h2>Estados Mais Ativos</h2>",
    "        <table>",
    "          <thead>",
    "            <tr>",
    "              <th>Estado</th>",
    "              <th style='text-align: right;'>Total de Documentos</th>",
    "              <th style='text-align: right;'>Documentos Recentes</th>",
    "              <th style='text-align: right;'>% Recentes</th>",
    "            </tr>",
    "          </thead>",
    "          <tbody>",
    states_table_html,
    "          </tbody>",
    "        </table>",
    "      </div>",
    "",
    "      <div class='section'>",
    "        <h2>Informações do Relatório</h2>",
    "        <div class='info-box'>",
    "          <ul>",
    sprintf("            <li><strong>Data do Relatório:</strong> %s</li>", report_date),
    sprintf("            <li><strong>Documento Mais Recente:</strong> %s</li>", latest_doc_date),
    sprintf("            <li><strong>Período de Análise:</strong> Últimos 12 meses</li>"),
    sprintf("            <li><strong>Fonte de Dados:</strong> Monitor Legislativo - Banco de Dados PostgreSQL</li>"),
    "          </ul>",
    "        </div>",
    "      </div>",
    "    </div>",
    "",
    "    <div class='footer'>",
    "      <p><strong>Este relatório foi gerado automaticamente pelo Monitor Legislativo v4</strong></p>",
    "      <p>Monitor Legislativo - Sistema de Monitoramento de Legislação de Transporte Brasileiro</p>",
    "      <p>© 2025 - Todos os direitos reservados</p>",
    "    </div>",
    "  </div>",
    "</body>",
    "</html>"
  )
}

cat("✅ HTML Report Generator module loaded\n")
