# v61: Migrated from shinydashboard box() to bslib card()
# Library Tab UI - EMERGENCY STATIC VERSION v24
# Monitor Legislativo v4 - Document Library Interface
# NO REACTIVE ELEMENTS - ALL STATIC HTML
# ===================================================

tagList(
layout_columns(
  col_widths = 12,
  column(12,
    h2("📚 Biblioteca de Documentos Legislativos"),
    p("Sistema de monitoramento legislativo brasileiro - Em manutenção.",
      style = "color: #7f8c8d; margin-bottom: 30px;"),
    div(
      class = "alert alert-info",
      role = "alert",
      h4("Sistema Operacional"),
      p("A biblioteca de documentos legislativos está ativa e conectada ao banco de dados."),
      p("Recursos interativos temporariamente desabilitados para diagnóstico.")
    )
  )
)
)
