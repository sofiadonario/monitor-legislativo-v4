# v78: FIX for extent=0 error by removing shiny::column from bslib::layout_columns
# São Paulo Tab UI
# Monitor Legislativo v4 - São Paulo Legislative Interface
# ==========================================================

div(
  layout_columns(
    col_widths = 12,
    h2("🏙️ Análise Específica de São Paulo"),
    p("Análise detalhada da legislação paulista com foco em políticas de transporte e desenvolvimento urbano.",
      style = "color: #7f8c8d; margin-bottom: 30px;")
  ),

  layout_columns(
    col_widths = 12,
    if(exists("sp_system_loaded") && sp_system_loaded) {
      uiOutput("saopaulo_content")
    } else {
      div(
        class = "alert alert-info",
        h4("Sistema São Paulo"),
        p("O módulo de análise específica de São Paulo está sendo carregado..."),
        p("Esta seção fornecerá análises detalhadas da legislação paulista.")
      )
    }
  )
)