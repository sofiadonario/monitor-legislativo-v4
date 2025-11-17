# Módulo de Metodologia (Portuguese Only)
# Exibe metodologia de pesquisa e métodos analíticos

# Load Portuguese content functions
source("R/modules/methodology_module_pt.R", local = TRUE)

methodology_ui <- function(id) {
  ns <- NS(id)

  tagList(
    fluidRow(
      column(12,
        h3(icon("book-open"), " Metodologia de Pesquisa"),
        p(class = "lead", "Guia completo de métodos analíticos, algoritmos e diretrizes de interpretação utilizados nesta plataforma."),
        hr(),

        # Navigation buttons (Portuguese only)
        div(class = "btn-group", role = "group",
          actionButton(ns("show_overview"), "Visão Geral", class = "btn btn-primary btn-sm"),
          actionButton(ns("show_data"), "Coleta de Dados", class = "btn btn-outline-primary btn-sm"),
          actionButton(ns("show_voting"), "Análise de Votação", class = "btn btn-outline-primary btn-sm"),
          actionButton(ns("show_limitations"), "Limitações", class = "btn btn-outline-primary btn-sm")
        ),

        hr(),

        # Content panel
        uiOutput(ns("content_panel"))
      )
    )
  )
}

methodology_server <- function(id) {
  moduleServer(id, function(input, output, session) {

    # Current section
    current_section <- reactiveVal("overview")

    # Section navigation
    observeEvent(input$show_overview, { current_section("overview") })
    observeEvent(input$show_data, { current_section("data") })
    observeEvent(input$show_voting, { current_section("voting") })
    observeEvent(input$show_limitations, { current_section("limitations") })

    # Content panel - all Portuguese
    output$content_panel <- renderUI({
      section <- current_section()

      switch(section,
        "overview" = overview_content_pt(),
        "data" = data_content_pt(),
        "voting" = voting_content_pt(),
        "limitations" = limitations_content_pt(),
        overview_content_pt()  # Default
      )
    })
  })
}
