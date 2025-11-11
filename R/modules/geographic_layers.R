# Geographic Layers Module
# Monitor Legislativo v4 - Toggleable Map Layer System
# ========================================================

library(dplyr)
library(leaflet)
library(RColorBrewer)

#' Calculate Population Density Layer Data
#'
#' @param db_connection Database connection
#' @return Data frame with state, population, and bills per 100k
#' @export
calculate_population_density_layer <- function(db_connection = NULL) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      SELECT
        state,
        year,
        population,
        bills_per_100k
      FROM mv_docs_state_density
      WHERE year = (SELECT MAX(year) FROM mv_docs_state_density)
      ORDER BY bills_per_100k DESC
    "

    result <- DBI::dbGetQuery(db_connection, query)
    return(result)

  }, error = function(e) {
    message("Error calculating population density: ", e$message)
    return(NULL)
  })
}


#' Calculate Document Type Distribution by State
#'
#' @param db_connection Database connection
#' @param filtered_states Optional vector of state codes to filter
#' @return Data frame with state and document type counts
#' @export
calculate_document_type_layer <- function(db_connection = NULL, filtered_states = NULL) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      SELECT
        estado AS state,
        tipo AS doc_type,
        COUNT(*) AS count
      FROM documents
      WHERE estado IS NOT NULL AND estado != ''
        AND tipo IS NOT NULL AND tipo != ''
    "

    if (!is.null(filtered_states) && length(filtered_states) > 0) {
      state_list <- paste0("'", paste(filtered_states, collapse = "','"), "'")
      query <- paste0(query, " AND estado IN (", state_list, ")")
    }

    query <- paste0(query, "
      GROUP BY estado, tipo
      ORDER BY estado, count DESC
    ")

    result <- DBI::dbGetQuery(db_connection, query)
    return(result)

  }, error = function(e) {
    message("Error calculating document types: ", e$message)
    return(NULL)
  })
}


#' Calculate Authority Level Distribution by State
#'
#' @param data Data frame with documents (must have 'estado' column)
#' @return Data frame with federal/state/municipal counts
#' @export
calculate_authority_level_layer <- function(data) {

  if (is.null(data) || nrow(data) == 0) {
    return(NULL)
  }

  tryCatch({
    # Determine authority level from estado column
    # Federal = "Federal" or empty, State = 2-letter code, Municipal = has municipio
    result <- data %>%
      mutate(
        authority_level = case_when(
          is.na(estado) | estado == "" | estado == "Federal" ~ "Federal",
          !is.na(municipio) & municipio != "" ~ "Municipal",
          TRUE ~ "State"
        )
      ) %>%
      group_by(estado, authority_level) %>%
      summarise(count = n(), .groups = "drop") %>%
      filter(!is.na(estado) & estado != "")

    return(as.data.frame(result))

  }, error = function(e) {
    message("Error calculating authority levels: ", e$message)
    return(NULL)
  })
}


#' Calculate Transport Legislation Density
#'
#' @param db_connection Database connection
#' @return Data frame with transport-related document counts by state
#' @export
calculate_transport_layer <- function(db_connection = NULL) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    # Search for transport-related keywords in titles and content
    query <- "
      SELECT
        estado AS state,
        COUNT(*) AS transport_docs
      FROM documents
      WHERE estado IS NOT NULL AND estado != ''
        AND (
          LOWER(titulo) LIKE '%transport%'
          OR LOWER(titulo) LIKE '%trânsit%'
          OR LOWER(titulo) LIKE '%mobilidade%'
          OR LOWER(titulo) LIKE '%viação%'
          OR LOWER(titulo) LIKE '%rodov%'
          OR LOWER(titulo) LIKE '%ferrov%'
          OR LOWER(titulo) LIKE '%ônibus%'
          OR LOWER(content) LIKE '%transport%'
          OR LOWER(content) LIKE '%trânsit%'
        )
      GROUP BY estado
      ORDER BY transport_docs DESC
    "

    result <- DBI::dbGetQuery(db_connection, query)
    return(result)

  }, error = function(e) {
    message("Error calculating transport layer: ", e$message)
    return(NULL)
  })
}


#' Calculate Legislative Productivity (Documents per Year)
#'
#' @param db_connection Database connection
#' @param years_back Number of years to look back (default 5)
#' @return Data frame with average documents per year by state
#' @export
calculate_productivity_layer <- function(db_connection = NULL, years_back = 5) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    current_year <- as.integer(format(Sys.Date(), "%Y"))
    start_year <- current_year - years_back

    query <- sprintf("
      SELECT
        estado AS state,
        COUNT(*) AS total_docs,
        COUNT(DISTINCT ano) AS years_covered,
        ROUND(COUNT(*)::numeric / COUNT(DISTINCT ano), 2) AS docs_per_year
      FROM documents
      WHERE estado IS NOT NULL AND estado != ''
        AND ano >= %d AND ano <= %d
      GROUP BY estado
      HAVING COUNT(DISTINCT ano) > 0
      ORDER BY docs_per_year DESC
    ", start_year, current_year)

    result <- DBI::dbGetQuery(db_connection, query)
    return(result)

  }, error = function(e) {
    message("Error calculating productivity: ", e$message)
    return(NULL)
  })
}


#' Calculate Document Quality Index by State
#'
#' @param data Data frame with quality metrics (text_quality, completeness_score)
#' @return Data frame with average quality scores by state
#' @export
calculate_quality_layer <- function(data) {

  if (is.null(data) || nrow(data) == 0) {
    return(NULL)
  }

  # Check if quality columns exist
  has_quality <- all(c("text_quality", "completeness_score") %in% names(data))

  if (!has_quality) {
    message("Quality metrics not available in data")
    return(NULL)
  }

  tryCatch({
    result <- data %>%
      filter(!is.na(estado) & estado != "") %>%
      group_by(estado) %>%
      summarise(
        avg_text_quality = mean(text_quality, na.rm = TRUE),
        avg_completeness = mean(completeness_score, na.rm = TRUE),
        quality_index = (avg_text_quality + avg_completeness) / 2,
        doc_count = n(),
        .groups = "drop"
      ) %>%
      filter(!is.na(quality_index))

    return(as.data.frame(result))

  }, error = function(e) {
    message("Error calculating quality index: ", e$message)
    return(NULL)
  })
}


#' Calculate Recent Activity (Last 5 Years)
#'
#' @param db_connection Database connection
#' @return Data frame with recent document counts by state
#' @export
calculate_recent_activity_layer <- function(db_connection = NULL) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    current_year <- as.integer(format(Sys.Date(), "%Y"))
    five_years_ago <- current_year - 5

    query <- sprintf("
      SELECT
        estado AS state,
        COUNT(*) AS recent_docs,
        MAX(ano) AS latest_year,
        MIN(ano) AS earliest_year
      FROM documents
      WHERE estado IS NOT NULL AND estado != ''
        AND ano >= %d
      GROUP BY estado
      ORDER BY recent_docs DESC
    ", five_years_ago)

    result <- DBI::dbGetQuery(db_connection, query)
    return(result)

  }, error = function(e) {
    message("Error calculating recent activity: ", e$message)
    return(NULL)
  })
}


#' Calculate Municipal Coverage by State
#'
#' @param db_connection Database connection
#' @return Data frame with unique municipality counts by state
#' @export
calculate_municipal_coverage_layer <- function(db_connection = NULL) {

  if (is.null(db_connection)) {
    return(NULL)
  }

  tryCatch({
    query <- "
      SELECT
        estado AS state,
        COUNT(DISTINCT municipio) AS municipalities_count,
        COUNT(*) AS municipal_docs
      FROM documents
      WHERE estado IS NOT NULL AND estado != ''
        AND municipio IS NOT NULL AND municipio != ''
      GROUP BY estado
      ORDER BY municipalities_count DESC
    "

    result <- DBI::dbGetQuery(db_connection, query)
    return(result)

  }, error = function(e) {
    message("Error calculating municipal coverage: ", e$message)
    return(NULL)
  })
}


#' Create Leaflet Choropleth Layer
#'
#' Helper function to create a choropleth layer for Leaflet
#'
#' @param map Leaflet map object
#' @param spatial_data Spatial data frame (sf object with state geometries)
#' @param metric_data Data frame with state and metric values
#' @param metric_column Name of the metric column
#' @param layer_id Unique layer ID for layer control
#' @param layer_name Display name for layer
#' @param color_palette RColorBrewer palette name (default "YlOrRd")
#' @param legend_title Title for the legend
#' @return Leaflet map with added layer
#' @export
add_choropleth_layer <- function(map, spatial_data, metric_data, metric_column,
                                 layer_id, layer_name, color_palette = "YlOrRd",
                                 legend_title = NULL) {

  if (is.null(spatial_data) || is.null(metric_data)) {
    return(map)
  }

  tryCatch({
    # Join metric data with spatial data
    # Assume spatial_data has 'sigla' or 'state' column
    state_col <- if ("sigla" %in% names(spatial_data)) "sigla" else "state"
    metric_state_col <- if ("state" %in% names(metric_data)) "state" else "estado"

    # Merge data
    joined_data <- merge(spatial_data, metric_data,
                        by.x = state_col, by.y = metric_state_col,
                        all.x = TRUE)

    # Create color palette
    metric_values <- joined_data[[metric_column]]
    metric_values <- metric_values[!is.na(metric_values)]

    if (length(metric_values) == 0) {
      return(map)
    }

    pal <- colorNumeric(
      palette = color_palette,
      domain = metric_values,
      na.color = "#E0E0E0"
    )

    # Add polygon layer with group for layer control
    map <- map %>%
      addPolygons(
        data = joined_data,
        fillColor = ~pal(joined_data[[metric_column]]),
        fillOpacity = 0.7,
        color = "#FFFFFF",
        weight = 2,
        opacity = 0.8,
        group = layer_name,  # Important for layer control
        highlightOptions = highlightOptions(
          weight = 3,
          color = "#666666",
          fillOpacity = 0.9,
          bringToFront = TRUE
        ),
        label = ~sprintf(
          "%s: %s",
          get(state_col),
          format(round(get(metric_column), 2), big.mark = ",")
        ),
        labelOptions = labelOptions(
          style = list("font-weight" = "normal", padding = "3px 8px"),
          textsize = "15px",
          direction = "auto"
        )
      )

    # Add legend if title provided
    if (!is.null(legend_title)) {
      map <- map %>%
        addLegend(
          pal = pal,
          values = metric_values,
          title = legend_title,
          position = "topright",
          group = layer_name
        )
    }

    return(map)

  }, error = function(e) {
    message("Error adding choropleth layer: ", e$message)
    return(map)
  })
}


# Export all functions
.export_geographic_layers <- function() {
  list(
    calculate_population_density_layer = calculate_population_density_layer,
    calculate_document_type_layer = calculate_document_type_layer,
    calculate_authority_level_layer = calculate_authority_level_layer,
    calculate_transport_layer = calculate_transport_layer,
    calculate_productivity_layer = calculate_productivity_layer,
    calculate_quality_layer = calculate_quality_layer,
    calculate_recent_activity_layer = calculate_recent_activity_layer,
    calculate_municipal_coverage_layer = calculate_municipal_coverage_layer,
    add_choropleth_layer = add_choropleth_layer
  )
}
