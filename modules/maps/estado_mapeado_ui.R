# ==============================================================================
# GEOGRAPHIC MAP VISUALIZATION - UI MODULE
# ==============================================================================
# Interactive choropleth map showing Brazilian legislative document distribution
# by state using the estado_mapeado field created in migration 008b
#
# FEATURES:
# - Interactive Brazilian state choropleth map
# - Comprehensive filters: temporal (ano/mes), hierarchical (nivel/poder/corte), document type
# - Real-time statistics and document counts
# - Color-coded visualization by document density
# - Responsive design for all screen sizes
# ==============================================================================

library(shiny)
library(leaflet)
library(DT)

#' Geographic Map Visualization UI
#'
#' Creates the complete UI for the Geographic Map tab with interactive filters
#' and statistics panels
#'
#' @param id Module namespace ID
#' @return Shiny UI elements
estadoMapeadoUI <- function(id) {
  ns <- NS(id)

  tagList(
    # Custom CSS for styling
    tags$head(
      tags$style(HTML("
        .geo-map-container {
          height: 700px;
          border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.1);
          overflow: hidden;
        }

        .geo-filter-panel {
          background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
          border-radius: 8px;
          padding: 20px;
          margin-bottom: 20px;
          box-shadow: 0 2px 6px rgba(0,0,0,0.08);
        }

        .geo-stat-card {
          background: white;
          border-radius: 6px;
          padding: 15px;
          margin-bottom: 15px;
          border-left: 4px solid #007bff;
          box-shadow: 0 2px 4px rgba(0,0,0,0.05);
          transition: all 0.3s ease;
        }

        .geo-stat-card:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }

        .geo-stat-value {
          font-size: 28px;
          font-weight: bold;
          color: #007bff;
          margin-bottom: 5px;
        }

        .geo-stat-label {
          font-size: 12px;
          color: #6c757d;
          text-transform: uppercase;
          font-weight: 600;
        }

        .geo-section-header {
          color: #495057;
          font-weight: 600;
          font-size: 16px;
          margin-bottom: 15px;
          padding-bottom: 8px;
          border-bottom: 2px solid #007bff;
        }

        .filter-reset-btn {
          margin-top: 15px;
          width: 100%;
        }

        .leaflet-container {
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
      "))
    ),

    fluidPage(
      h2(icon("map-marked-alt"), " Visualização Geográfica de Documentos Legislativos"),
      p("Explore a distribuição de documentos legislativos brasileiros por estado usando filtros interativos."),
      hr(),

      fluidRow(
        # LEFT PANEL: Filters
        column(4,
          div(class = "geo-filter-panel",
            h4(class = "geo-section-header", icon("filter"), " Filtros de Dados"),

            # Temporal Filters
            h5(icon("calendar"), " Temporal"),
            selectInput(
              ns("filter_ano"),
              "Ano:",
              choices = NULL,  # Will be populated from server
              selected = NULL,
              multiple = TRUE
            ),
            selectInput(
              ns("filter_mes"),
              "Mês:",
              choices = c(
                "Todos" = "",
                "Janeiro" = "01", "Fevereiro" = "02", "Março" = "03",
                "Abril" = "04", "Maio" = "05", "Junho" = "06",
                "Julho" = "07", "Agosto" = "08", "Setembro" = "09",
                "Outubro" = "10", "Novembro" = "11", "Dezembro" = "12"
              ),
              selected = "",
              multiple = TRUE
            ),

            hr(),

            # Hierarchical Filters
            h5(icon("sitemap"), " Hierarquia"),
            selectInput(
              ns("filter_nivel"),
              "Nível:",
              choices = NULL,  # Will be populated from server
              selected = NULL,
              multiple = TRUE
            ),
            selectInput(
              ns("filter_poder"),
              "Poder:",
              choices = NULL,  # Will be populated from server
              selected = NULL,
              multiple = TRUE
            ),
            selectInput(
              ns("filter_corte"),
              "Corte/Tribunal:",
              choices = NULL,  # Will be populated from server
              selected = NULL,
              multiple = TRUE
            ),

            hr(),

            # Document Type Filter
            h5(icon("file-alt"), " Tipo de Documento"),
            selectInput(
              ns("filter_tipo_documento"),
              "Tipo:",
              choices = NULL,  # Will be populated from server
              selected = NULL,
              multiple = TRUE
            ),

            # Reset Button
            actionButton(
              ns("reset_filters"),
              "Limpar Filtros",
              icon = icon("redo"),
              class = "btn-warning filter-reset-btn"
            )
          ),

          # Statistics Panel
          div(class = "geo-filter-panel",
            h4(class = "geo-section-header", icon("chart-bar"), " Estatísticas"),

            div(class = "geo-stat-card",
              div(class = "geo-stat-value", textOutput(ns("stat_total_docs"))),
              div(class = "geo-stat-label", "Total de Documentos")
            ),

            div(class = "geo-stat-card",
              div(class = "geo-stat-value", textOutput(ns("stat_mapped_docs"))),
              div(class = "geo-stat-label", "Documentos Mapeados")
            ),

            div(class = "geo-stat-card",
              div(class = "geo-stat-value", textOutput(ns("stat_coverage_pct"))),
              div(class = "geo-stat-label", "Cobertura Geográfica")
            ),

            div(class = "geo-stat-card",
              div(class = "geo-stat-value", textOutput(ns("stat_states_count"))),
              div(class = "geo-stat-label", "Estados com Documentos")
            )
          )
        ),

        # RIGHT PANEL: Map and Data Table
        column(8,
          # Map - use explicit pixel height to avoid rendering issues on lazy-loaded tabs
          div(class = "geo-map-container",
            leafletOutput(ns("main_map"), height = "600px") %>%
              shinycssloaders::withSpinner(type = 6, color = "#007bff")
          ),

          # Data Table
          br(),
          div(class = "geo-filter-panel",
            h4(class = "geo-section-header", icon("table"), " Distribuição por Estado"),
            DT::dataTableOutput(ns("state_distribution_table"))
          )
        )
      )
    )
  )
}
