# v78: FIX for extent=0 error by removing shiny::column from bslib::layout_columns
# Library Tab UI
# Monitor Legislativo v4 - Document Library Interface
# ======================================================

div(
  layout_columns(
    col_widths = 12,
    h2("📚 Biblioteca de Documentos Legislativos"),
    p("Pesquise, filtre e explore a coleção completa de documentos legislativos brasileiros.",
      style = "color: #7f8c8d; margin-bottom: 30px;")
  ),

  # Search and Filter Panel
  layout_columns(
    col_widths = 12,
    card(
      card_header("Filtros de Pesquisa"),
      layout_columns(
        col_widths = c(6, 3, 3),
        textInput("library_search", "Termo de Pesquisa:", placeholder = "Ex: 'tributário' ou 'lei 14.133'"),
        selectInput("library_state", "Filtrar por Estado:", choices = c("Todos" = "all", "SP", "RJ", "MG")), # Example states
        dateRangeInput("library_date", "Filtrar por Data:", format = "dd/mm/yyyy", language = "pt-BR")
      )
    )
  ),

  # Results Display Panel
  layout_columns(
    col_widths = 12,
    card(
      card_header("Resultados da Pesquisa"),
      DT::dataTableOutput("library_table")
    )
  )
)