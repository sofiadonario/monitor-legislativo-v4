# Library Tab UI
# Monitor Legislativo v4 - Document Library Interface
# ===================================================

tagList(
fluidRow(
  column(12,
    h2("📚 Biblioteca de Documentos Legislativos"),
    p("Acesse e explore a coleção completa de documentos legislativos brasileiros com ferramentas avançadas de busca e análise.", 
      style = "color: #7f8c8d; margin-bottom: 30px;")
  )
),

# Search and Filter Controls
fluidRow(
  column(12,
    wellPanel(
      fluidRow(
        column(6,
          textInput(
            inputId = "library_search_term",
            label = "Buscar Documentos:",
            placeholder = "Digite termos para busca...",
            value = ""
          )
        ),
        column(3,
          selectInput(
            inputId = "library_category",
            label = "Categoria:",
            choices = list(
              "Todas as Categorias" = "all",
              "Legislação" = "legislation",
              "Jurisprudência" = "jurisprudence",
              "Doutrina" = "doctrine"
            ),
            selected = "all"
          )
        ),
        column(3,
          selectInput(
            inputId = "library_state",
            label = "Estado:",
            choices = list(
              "Todos os Estados" = "all",
              "São Paulo" = "SP",
              "Rio de Janeiro" = "RJ",
              "Minas Gerais" = "MG",
              "Bahia" = "BA",
              "Paraná" = "PR",
              "Rio Grande do Sul" = "RS"
            ),
            selected = "all"
          )
        )
      ),
      fluidRow(
        column(6,
          dateRangeInput(
            inputId = "library_date_range",
            label = "Período:",
            start = Sys.Date() - 365,
            end = Sys.Date(),
            format = "dd/mm/yyyy",
            language = "pt-BR"
          )
        ),
        column(3,
          selectInput(
            inputId = "library_sort",
            label = "Ordenar por:",
            choices = list(
              "Data (mais recente)" = "date_desc",
              "Data (mais antigo)" = "date_asc",
              "Relevância" = "relevance",
              "Título (A-Z)" = "title_asc"
            ),
            selected = "date_desc"
          )
        ),
        column(3,
          br(),
          actionButton(
            inputId = "library_search_button",
            label = "Buscar",
            icon = icon("search"),
            class = "btn-primary btn-block",
            style = "margin-top: 5px;"
          )
        )
      )
    )
  )
),

# Results Summary
fluidRow(
  column(12,
    uiOutput("library_results_summary")
  )
),

# Main Results Display
fluidRow(
  column(12,
    box(
      title = "Resultados da Busca", 
      status = "primary", 
      solidHeader = TRUE, 
      width = 12,
      DT::dataTableOutput("library_results_table"),
      footer = div(
        style = "margin-top: 10px;",
        fluidRow(
          column(4,
            downloadButton(
              outputId = "library_download_csv",
              label = "Baixar CSV",
              icon = icon("download"),
              class = "btn-info"
            )
          ),
          column(4,
            downloadButton(
              outputId = "library_download_bibtex",
              label = "Baixar BibTeX",
              icon = icon("quote-right"),
              class = "btn-warning"
            )
          ),
          column(4,
            actionButton(
              inputId = "library_advanced_export",
              label = "Exportação Avançada",
              icon = icon("cog"),
              class = "btn-secondary"
            )
          )
        )
      )
    )
  )
),

# Quick Statistics
fluidRow(
  column(3,
    valueBoxOutput("library_total_results")
  ),
  column(3,
    valueBoxOutput("library_states_covered")
  ),
  column(3,
    valueBoxOutput("library_categories_found")
  ),
  column(3,
    valueBoxOutput("library_date_span")
  )
)
)
