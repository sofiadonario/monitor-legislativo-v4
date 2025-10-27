# v61: Migrated from shinydashboard box() to bslib card()
# São Paulo Analysis Tab UI
# Monitor Legislativo v4 - São Paulo Specific Analysis
# ====================================================

tagList(
layout_columns(
  col_widths = 12,
  column(12,
    h2("🏙️ Análise Específica de São Paulo"),
    p("Análise detalhada da legislação paulista com foco em políticas de transporte e desenvolvimento urbano.",
      style = "color: #7f8c8d; margin-bottom: 30px;")
  )
),

# São Paulo specific interface will be loaded from existing module
if(exists("sp_system_loaded") && sp_system_loaded) {
  uiOutput("saopaulo_content")
} else {
  layout_columns(
    col_widths = 12,
    column(12,
      div(
        class = "alert alert-info",
        h4("Sistema São Paulo"),
        p("O módulo de análise específica de São Paulo está sendo carregado..."),
        p("Esta seção fornecerá análises detalhadas da legislação paulista.")
      )
    )
  )
}
)
