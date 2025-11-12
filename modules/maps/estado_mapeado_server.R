# ==============================================================================
# GEOGRAPHIC MAP VISUALIZATION - SERVER MODULE
# ==============================================================================
# Server logic for interactive choropleth map using estado_mapeado field
#
# FEATURES:
# - Reactive data querying with comprehensive filters
# - Brazilian state polygons using geobr package
# - Color-coded choropleth visualization
# - Real-time statistics computation
# - Performance-optimized for 119K+ documents
# ==============================================================================

library(shiny)
library(leaflet)
library(sf)
library(DBI)
library(dplyr)
library(DT)

#' Geographic Map Visualization Server
#'
#' @param id Module namespace ID
#' @param db_connection Database connection object
#' @param table_name Name of the documents table
#' @return NULL
estadoMapeadoServer <- function(id, db_connection, table_name = "documents") {
  moduleServer(id, function(input, output, session) {

    # ============================================================================
    # BRAZILIAN STATE GEOMETRIES
    # ============================================================================

    # Load Brazilian state boundaries
    brazil_states <- reactive({
      tryCatch({
        # Load from local GeoJSON file (fast, no internet required)
        geojson_path <- "data/brazil_states.geojson"

        if (file.exists(geojson_path)) {
          cat("Loading Brazilian states from local GeoJSON:", geojson_path, "\n")
          states_sf <- sf::st_read(geojson_path, quiet = TRUE)
          cat("✅ Loaded", nrow(states_sf), "state polygons from GeoJSON\n")
          return(states_sf)
        } else {
          cat("⚠️ Local GeoJSON not found, trying geobr...\n")

          # Fallback: Try geobr (slow, requires internet)
          if (requireNamespace("geobr", quietly = TRUE)) {
            states_sf <- geobr::read_state(year = 2020, showProgress = FALSE)
            return(states_sf)
          } else {
            # Last resort: Create simplified state boundaries with centroids
            cat("⚠️ Creating simplified state boundaries (no polygons)\n")
            states_data <- data.frame(
              abbrev_state = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO",
                              "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI",
                              "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
              name_state = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará",
                            "Distrito Federal", "Espírito Santo", "Goiás", "Maranhão",
                            "Mato Grosso", "Mato Grosso do Sul", "Minas Gerais", "Pará",
                            "Paraíba", "Paraná", "Pernambuco", "Piauí", "Rio de Janeiro",
                            "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia",
                            "Roraima", "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
              lon = c(-70.55, -36.66, -51.07, -63.07, -41.70, -39.52, -47.93, -40.31,
                     -49.25, -44.30, -55.67, -54.62, -44.55, -52.00, -36.78, -51.21,
                     -37.97, -42.80, -43.21, -36.52, -53.02, -63.58, -60.67, -50.30,
                     -48.64, -37.43, -48.29),
              lat = c(-9.02, -9.66, 1.41, -4.16, -12.58, -5.49, -15.83, -19.18,
                     -15.94, -4.96, -12.64, -20.44, -18.51, -3.80, -7.23, -24.95,
                     -8.31, -7.61, -22.91, -5.81, -30.04, -10.93, 1.82, -27.25,
                     -22.22, -10.57, -10.17),
              stringsAsFactors = FALSE
            )

            # Convert to sf object with points
            states_sf <- sf::st_as_sf(
              states_data,
              coords = c("lon", "lat"),
              crs = 4326
            )

            return(states_sf)
          }
        }
      }, error = function(e) {
        cat("❌ Error loading state geometries:", e$message, "\n")
        return(NULL)
      })
    })

    # ============================================================================
    # POPULATE FILTER CHOICES
    # ============================================================================

    observe({
      req(db_connection)

      tryCatch({
        # Get unique years (excluding NULL and 0)
        anos <- dbGetQuery(db_connection,
          sprintf("SELECT DISTINCT ano FROM %s WHERE ano IS NOT NULL AND ano > 0 ORDER BY ano DESC", table_name)
        )$ano

        updateSelectInput(session, "filter_ano",
          choices = c("Todos" = "", sort(anos, decreasing = TRUE)),
          selected = ""
        )

        # Get unique níveis
        niveis <- dbGetQuery(db_connection,
          sprintf("SELECT DISTINCT nivel FROM %s WHERE nivel IS NOT NULL ORDER BY nivel", table_name)
        )$nivel

        updateSelectInput(session, "filter_nivel",
          choices = c("Todos" = "", niveis),
          selected = ""
        )

        # Get unique poderes
        poderes <- dbGetQuery(db_connection,
          sprintf("SELECT DISTINCT poder FROM %s WHERE poder IS NOT NULL ORDER BY poder", table_name)
        )$poder

        updateSelectInput(session, "filter_poder",
          choices = c("Todos" = "", poderes),
          selected = ""
        )

        # Get unique cortes
        cortes <- dbGetQuery(db_connection,
          sprintf("SELECT DISTINCT corte FROM %s WHERE corte IS NOT NULL ORDER BY corte", table_name)
        )$corte

        updateSelectInput(session, "filter_corte",
          choices = c("Todos" = "", cortes),
          selected = ""
        )

        # Get unique document types
        tipos <- dbGetQuery(db_connection,
          sprintf("SELECT DISTINCT tipo_documento FROM %s WHERE tipo_documento IS NOT NULL ORDER BY tipo_documento", table_name)
        )$tipo_documento

        updateSelectInput(session, "filter_tipo_documento",
          choices = c("Todos" = "", tipos),
          selected = ""
        )

      }, error = function(e) {
        cat("Error populating filters:", e$message, "\n")
      })
    })

    # ============================================================================
    # REACTIVE DATA QUERIES
    # ============================================================================

    # Build WHERE clause based on filters
    filter_where_clause <- reactive({
      conditions <- c()

      # Year filter
      if (!is.null(input$filter_ano) && length(input$filter_ano) > 0 && input$filter_ano[1] != "") {
        anos_str <- paste0("'", input$filter_ano, "'", collapse = ", ")
        conditions <- c(conditions, sprintf("CAST(ano AS TEXT) IN (%s)", anos_str))
      }

      # Month filter
      if (!is.null(input$filter_mes) && length(input$filter_mes) > 0 && input$filter_mes[1] != "") {
        meses_str <- paste0("'", input$filter_mes, "'", collapse = ", ")
        conditions <- c(conditions, sprintf("mes IN (%s)", meses_str))
      }

      # Nivel filter
      if (!is.null(input$filter_nivel) && length(input$filter_nivel) > 0 && input$filter_nivel[1] != "") {
        niveis_str <- paste0("'", gsub("'", "''", input$filter_nivel), "'", collapse = ", ")
        conditions <- c(conditions, sprintf("nivel IN (%s)", niveis_str))
      }

      # Poder filter
      if (!is.null(input$filter_poder) && length(input$filter_poder) > 0 && input$filter_poder[1] != "") {
        poderes_str <- paste0("'", gsub("'", "''", input$filter_poder), "'", collapse = ", ")
        conditions <- c(conditions, sprintf("poder IN (%s)", poderes_str))
      }

      # Corte filter
      if (!is.null(input$filter_corte) && length(input$filter_corte) > 0 && input$filter_corte[1] != "") {
        cortes_str <- paste0("'", gsub("'", "''", input$filter_corte), "'", collapse = ", ")
        conditions <- c(conditions, sprintf("corte IN (%s)", cortes_str))
      }

      # Document type filter
      if (!is.null(input$filter_tipo_documento) && length(input$filter_tipo_documento) > 0 && input$filter_tipo_documento[1] != "") {
        tipos_str <- paste0("'", gsub("'", "''", input$filter_tipo_documento), "'", collapse = ", ")
        conditions <- c(conditions, sprintf("tipo_documento IN (%s)", tipos_str))
      }

      if (length(conditions) > 0) {
        return(paste0(" AND ", paste(conditions, collapse = " AND ")))
      } else {
        return("")
      }
    })

    # Query geographic distribution
    geo_data <- reactive({
      req(db_connection)

      where_clause <- filter_where_clause()

      query <- sprintf("
        SELECT
          COALESCE(estado_mapeado, 'Não Identificado') as estado,
          COUNT(*) as count
        FROM %s
        WHERE 1=1 %s
        GROUP BY estado_mapeado
        ORDER BY count DESC
      ", table_name, where_clause)

      tryCatch({
        result <- dbGetQuery(db_connection, query)
        return(result)
      }, error = function(e) {
        cat("Error querying geo data:", e$message, "\n")
        return(data.frame(estado = character(), count = integer()))
      })
    })

    # ============================================================================
    # STATISTICS OUTPUTS
    # ============================================================================

    output$stat_total_docs <- renderText({
      data <- geo_data()
      format(sum(data$count), big.mark = ".", decimal.mark = ",")
    })

    output$stat_mapped_docs <- renderText({
      data <- geo_data()
      mapped <- data %>% filter(estado != "Não Identificado") %>% pull(count) %>% sum()
      format(mapped, big.mark = ".", decimal.mark = ",")
    })

    output$stat_coverage_pct <- renderText({
      data <- geo_data()
      total <- sum(data$count)
      mapped <- data %>% filter(estado != "Não Identificado") %>% pull(count) %>% sum()
      if (total > 0) {
        pct <- round(100 * mapped / total, 2)
        paste0(format(pct, decimal.mark = ","), "%")
      } else {
        "0%"
      }
    })

    output$stat_states_count <- renderText({
      data <- geo_data()
      state_count <- data %>% filter(estado != "Não Identificado" & estado != "Nacional") %>% nrow()
      as.character(state_count)
    })

    # ============================================================================
    # MAP RENDERING
    # ============================================================================

    output$main_map <- renderLeaflet({
      states_sf <- brazil_states()
      geo_counts <- geo_data()

      # Create base map
      map <- leaflet() %>%
        addProviderTiles(providers$CartoDB.Positron) %>%
        setView(lng = -54, lat = -14, zoom = 4)

      # If we have state geometries, create choropleth
      if (!is.null(states_sf) && nrow(geo_counts) > 0) {

        # Filter out Nacional and Não Identificado for state mapping
        state_counts <- geo_counts %>%
          filter(!estado %in% c("Nacional", "Não Identificado", "Estadual", "DF"))

        # Join with state geometries
        # Check which column name is used for state abbreviation
        state_col <- if ("sigla" %in% names(states_sf)) {
          "sigla"  # Local GeoJSON uses 'sigla'
        } else if ("abbrev_state" %in% names(states_sf)) {
          "abbrev_state"  # geobr uses 'abbrev_state'
        } else {
          "abbrev_state"  # Fallback
        }

        states_with_data <- states_sf %>%
          left_join(state_counts, by = setNames("estado", state_col))

        # Replace NA counts with 0
        states_with_data$count[is.na(states_with_data$count)] <- 0

        # Create color palette
        if (max(states_with_data$count, na.rm = TRUE) > 0) {
          pal <- colorNumeric(
            palette = "YlOrRd",
            domain = c(0, max(states_with_data$count, na.rm = TRUE)),
            na.color = "#eeeeee"
          )

          # Add polygons or markers depending on geometry type
          if ("MULTIPOLYGON" %in% st_geometry_type(states_with_data) ||
              "POLYGON" %in% st_geometry_type(states_with_data)) {
            # We have proper polygons
            map <- map %>%
              addPolygons(
                data = states_with_data,
                fillColor = ~pal(count),
                fillOpacity = 0.7,
                color = "#444444",
                weight = 1,
                opacity = 0.8,
                highlight = highlightOptions(
                  weight = 3,
                  color = "#666",
                  fillOpacity = 0.9,
                  bringToFront = TRUE
                ),
                label = ~paste0(
                  name_state, ": ",
                  format(count, big.mark = ".")
                ),
                labelOptions = labelOptions(
                  style = list("font-weight" = "normal", padding = "3px 8px"),
                  textsize = "12px",
                  direction = "auto"
                )
              ) %>%
              addLegend(
                position = "bottomright",
                pal = pal,
                values = states_with_data$count,
                title = "Documentos<br>por Estado",
                opacity = 0.7
              )
          } else {
            # Fallback: use circle markers for point geometries
            states_with_data <- states_with_data %>%
              filter(count > 0)

            map <- map %>%
              addCircleMarkers(
                data = states_with_data,
                radius = ~sqrt(count) / 10,
                fillColor = ~pal(count),
                fillOpacity = 0.7,
                color = "#444444",
                weight = 1,
                label = ~paste0(
                  name_state, ": ",
                  format(count, big.mark = ".")
                )
              ) %>%
              addLegend(
                position = "bottomright",
                pal = pal,
                values = states_with_data$count,
                title = "Documentos<br>por Estado",
                opacity = 0.7
              )
          }
        }
      }

      return(map)
    })

    # ============================================================================
    # DATA TABLE
    # ============================================================================

    output$state_distribution_table <- DT::renderDataTable({
      data <- geo_data() %>%
        mutate(
          percentual = round(100 * count / sum(count), 2)
        ) %>%
        arrange(desc(count))

      datatable(
        data,
        colnames = c("Estado/Região", "Documentos", "Percentual (%)"),
        options = list(
          pageLength = 10,
          dom = 'frtip',
          language = list(
            search = "Buscar:",
            lengthMenu = "Mostrar _MENU_ registros por página",
            info = "Mostrando _START_ a _END_ de _TOTAL_ registros",
            infoEmpty = "Nenhum registro disponível",
            infoFiltered = "(filtrado de _MAX_ registros totais)",
            paginate = list(
              first = "Primeiro",
              last = "Último",
              `next` = "Próximo",
              previous = "Anterior"
            )
          )
        ),
        rownames = FALSE
      ) %>%
        formatCurrency("count", currency = "", interval = 3, mark = ".", digits = 0) %>%
        formatRound("percentual", digits = 2, mark = ".", dec.mark = ",")
    })

    # ============================================================================
    # RESET FILTERS
    # ============================================================================

    observeEvent(input$reset_filters, {
      updateSelectInput(session, "filter_ano", selected = "")
      updateSelectInput(session, "filter_mes", selected = "")
      updateSelectInput(session, "filter_nivel", selected = "")
      updateSelectInput(session, "filter_poder", selected = "")
      updateSelectInput(session, "filter_corte", selected = "")
      updateSelectInput(session, "filter_tipo_documento", selected = "")
    })

  })
}
