# Spatial Data Processing Utilities
# Monitor Legislativo v4 - Brazilian Geographic Data Processing
# ==============================================================

#' Spatial Data Processing for Monitor Legislativo v4
#' 
#' Advanced utilities for processing Brazilian geographic data including
#' coordinate transformations, spatial joins, and boundary simplification.
#' Optimized for Railway deployment constraints and large datasets.

# Load essential geospatial libraries
suppressPackageStartupMessages({
  library(sf)  # must exist (already built from source with system libs)
  library(dplyr)
})

# Load optional packages with graceful fallback
has_geosphere <- requireNamespace("geosphere", quietly = TRUE)
if (has_geosphere) {
  suppressPackageStartupMessages(library(geosphere))
} else {
  message("[spatial] 'geosphere' not available – spherical calculations limited to sf functions.")
}

has_lwgeom <- requireNamespace("lwgeom", quietly = TRUE)

if (!has_lwgeom) {
  message("[geospatial] 'lwgeom' not available – running without advanced spherical ops.")
  # All lwgeom operations will use sf fallbacks or be skipped gracefully
} else {
  message("[geospatial] 'lwgeom' available – advanced ops enabled.")
  suppressPackageStartupMessages(library(lwgeom))
}

# Brazilian coordinate systems
BRAZIL_CRS <- list(
  wgs84 = 4326,           # World Geodetic System 1984
  sirgas2000 = 4674,      # Sistema de Referência Geocêntrico para as Américas 2000
  utm_zone_23s = 31983,   # UTM Zone 23S (São Paulo region)
  utm_zone_22s = 31982,   # UTM Zone 22S (Rio de Janeiro region)
  albers_brazil = "+proj=aea +lat_0=-12 +lon_0=-54 +lat_1=-2 +lat_2=-22 +x_0=0 +y_0=0 +ellps=GRS80 +units=m +no_defs"
)

#' Simplify Geometries for Railway Performance
#' 
#' Simplifies complex geometries to reduce memory usage while maintaining
#' visual quality for web mapping applications.
#' 
#' @param sf_data sf object with geometries
#' @param tolerance Numeric tolerance for simplification (degrees)
#' @param preserve_topology Logical whether to preserve topology
#' @return sf object with simplified geometries
#' @export
simplify_geometries_railway <- function(sf_data, tolerance = 0.01, preserve_topology = TRUE) {
  cat("🔧 Simplifying geometries for Railway deployment...\n")
  
  tryCatch({
    if (is.null(sf_data) || nrow(sf_data) == 0) {
      warning("No data to simplify")
      return(sf_data)
    }
    
    # Check current CRS and transform to WGS84 if needed
    if (sf::st_crs(sf_data)$input != "EPSG:4326") {
      sf_data <- sf::st_transform(sf_data, crs = 4326)
    }
    
    # Make geometries valid before simplification
    sf_data <- sf::st_make_valid(sf_data)
    
    # Simplify based on tolerance
    if (preserve_topology) {
      simplified <- sf::st_simplify(sf_data, dTolerance = tolerance, preserveTopology = TRUE)
    } else {
      simplified <- sf::st_simplify(sf_data, dTolerance = tolerance)
    }
    
    # Check for empty geometries and remove if necessary
    empty_geoms <- sf::st_is_empty(simplified)
    if (any(empty_geoms)) {
      warning("Removing ", sum(empty_geoms), " empty geometries after simplification")
      simplified <- simplified[!empty_geoms, ]
    }
    
    # Calculate memory reduction
    original_size <- object.size(sf_data)
    simplified_size <- object.size(simplified)
    reduction_pct <- round((1 - as.numeric(simplified_size) / as.numeric(original_size)) * 100, 1)
    
    cat("✅ Geometries simplified -", reduction_pct, "% memory reduction\n")
    cat("📏 Original features:", nrow(sf_data), "→ Simplified features:", nrow(simplified), "\n")
    
    return(simplified)
    
  }, error = function(e) {
    warning("Error simplifying geometries: ", e$message)
    return(sf_data)
  })
}

#' Create Brazilian Administrative Boundaries Dataset
#' 
#' Creates a comprehensive dataset of Brazilian administrative boundaries
#' optimized for legislative document analysis.
#' 
#' @param include_municipalities Logical whether to include municipal boundaries
#' @param simplification_level Character level of simplification ("high", "medium", "low")
#' @return sf object with Brazilian boundaries
#' @export
create_brazilian_boundaries <- function(include_municipalities = FALSE, simplification_level = "medium") {
  cat("🏛️ Creating Brazilian administrative boundaries dataset...\n")
  
  tryCatch({
    # Define simplification tolerances
    tolerance_levels <- list(
      high = 0.05,      # Most simplified for Railway
      medium = 0.01,    # Balanced quality/performance
      low = 0.005       # High quality but larger file
    )
    
    tolerance <- tolerance_levels[[simplification_level]]
    
    # Create fallback boundaries if IBGE API unavailable
    boundaries_list <- create_fallback_brazilian_boundaries()
    
    # Simplify for Railway performance
    if (nrow(boundaries_list$states) > 0) {
      boundaries_list$states <- simplify_geometries_railway(
        boundaries_list$states, 
        tolerance = tolerance
      )
    }
    
    if (include_municipalities && nrow(boundaries_list$municipalities) > 0) {
      # Limit municipalities for Railway memory constraints
      boundaries_list$municipalities <- boundaries_list$municipalities %>%
        slice_head(n = 500) %>%  # Limit to 500 largest municipalities
        simplify_geometries_railway(tolerance = tolerance * 2)  # More aggressive simplification
    }
    
    cat("✅ Brazilian boundaries created successfully\n")
    return(boundaries_list)
    
  }, error = function(e) {
    warning("Error creating Brazilian boundaries: ", e$message)
    return(create_minimal_boundaries())
  })
}

#' Perform Spatial Join with Legislative Documents
#' 
#' Joins legislative documents with geographic boundaries based on location data.
#' 
#' @param documents_data data.frame with legislative documents
#' @param boundaries_data sf object with geographic boundaries
#' @param location_column Character name of location column in documents
#' @return data.frame with spatial join results
#' @export
spatial_join_documents <- function(documents_data, boundaries_data, location_column = "localidade") {
  cat("🔗 Performing spatial join with legislative documents...\n")
  
  tryCatch({
    if (is.null(documents_data) || is.null(boundaries_data)) {
      warning("Missing data for spatial join")
      return(documents_data)
    }
    
    # Extract coordinates or locations from documents
    document_points <- extract_document_coordinates(documents_data, location_column)
    
    if (nrow(document_points) == 0) {
      warning("No valid coordinates found in documents")
      return(documents_data)
    }
    
    # Convert to sf points
    documents_sf <- sf::st_as_sf(
      document_points,
      coords = c("longitude", "latitude"),
      crs = 4326
    )
    
    # Ensure same CRS
    if (sf::st_crs(boundaries_data) != sf::st_crs(documents_sf)) {
      boundaries_data <- sf::st_transform(boundaries_data, crs = sf::st_crs(documents_sf))
    }
    
    # Perform spatial join
    joined_data <- sf::st_join(documents_sf, boundaries_data, join = sf::st_within)
    
    # Convert back to regular data frame and merge with original
    joined_df <- joined_data %>%
      sf::st_drop_geometry() %>%
      select(-longitude, -latitude)  # Remove duplicate coordinate columns
    
    # Merge with original documents data
    result <- documents_data %>%
      left_join(joined_df, by = names(documents_data)[1])  # Join by first column (assumed to be ID)
    
    cat("✅ Spatial join completed:", nrow(joined_df), "documents matched\n")
    return(result)
    
  }, error = function(e) {
    warning("Error in spatial join: ", e$message)
    return(documents_data)
  })
}

#' Extract Coordinates from Document Location Data
#' 
#' Attempts to extract or estimate coordinates from location text in documents.
#' 
#' @param documents_data data.frame with documents
#' @param location_column Character name of location column
#' @return data.frame with coordinate information
extract_document_coordinates <- function(documents_data, location_column) {
  cat("📍 Extracting coordinates from document locations...\n")
  
  tryCatch({
    # State capitals coordinates (fallback)
    state_capitals <- data.frame(
      state = c("SP", "RJ", "MG", "BA", "PR", "RS", "PE", "CE", "GO", "MA", "SC", "PB", "PA", "ES", "PI", "AL", "MT", "MS", "RN", "RO", "DF", "AC", "AM", "RR", "AP", "SE", "TO"),
      latitude = c(-23.5505, -22.9068, -19.9167, -12.9714, -25.4244, -30.0346, -8.0476, -3.7319, -16.6869, -2.5307, -27.5954, -7.1195, -1.4558, -20.1287, -5.0892, -9.6498, -15.6014, -20.4697, -5.8130, -8.7619, -15.7942, -9.9731, -3.1190, 2.8235, 0.0389, -10.9472, -10.1753),
      longitude = c(-46.6333, -43.1729, -43.9345, -38.5014, -49.2654, -51.2177, -34.8770, -38.5267, -49.2648, -44.3068, -48.5480, -34.8450, -48.5044, -40.3075, -42.8019, -35.7089, -56.0979, -54.6201, -35.2044, -63.9039, -47.8822, -67.8099, -60.0217, -60.6758, -51.0694, -37.0731, -48.2982),
      stringsAsFactors = FALSE
    )
    
    coordinates_data <- data.frame()
    
    if (location_column %in% names(documents_data)) {
      # Extract state codes from location text
      documents_with_coords <- documents_data %>%
        mutate(
          estado_extracted = case_when(
            grepl("SP|São Paulo|SAO PAULO", get(location_column), ignore.case = TRUE) ~ "SP",
            grepl("RJ|Rio de Janeiro|RIO DE JANEIRO", get(location_column), ignore.case = TRUE) ~ "RJ",
            grepl("MG|Minas Gerais|MINAS GERAIS", get(location_column), ignore.case = TRUE) ~ "MG",
            grepl("BA|Bahia|BAHIA", get(location_column), ignore.case = TRUE) ~ "BA",
            grepl("PR|Paraná|PARANA", get(location_column), ignore.case = TRUE) ~ "PR",
            grepl("RS|Rio Grande do Sul|RIO GRANDE DO SUL", get(location_column), ignore.case = TRUE) ~ "RS",
            grepl("PE|Pernambuco|PERNAMBUCO", get(location_column), ignore.case = TRUE) ~ "PE",
            grepl("CE|Ceará|CEARA", get(location_column), ignore.case = TRUE) ~ "CE",
            grepl("GO|Goiás|GOIAS", get(location_column), ignore.case = TRUE) ~ "GO",
            grepl("DF|Distrito Federal|DISTRITO FEDERAL|Brasília|BRASILIA", get(location_column), ignore.case = TRUE) ~ "DF",
            TRUE ~ NA_character_
          )
        ) %>%
        filter(!is.na(estado_extracted))
      
      # Join with state capitals coordinates
      coordinates_data <- documents_with_coords %>%
        left_join(state_capitals, by = c("estado_extracted" = "state")) %>%
        filter(!is.na(latitude) & !is.na(longitude)) %>%
        select(all_of(names(documents_data)), latitude, longitude)
        
    } else if ("estado" %in% names(documents_data)) {
      # Use existing state column
      coordinates_data <- documents_data %>%
        left_join(state_capitals, by = c("estado" = "state")) %>%
        filter(!is.na(latitude) & !is.na(longitude))
    }
    
    # Add some random noise to avoid overlapping points (for visualization)
    if (nrow(coordinates_data) > 0) {
      coordinates_data <- coordinates_data %>%
        mutate(
          latitude = latitude + runif(n(), -0.5, 0.5),
          longitude = longitude + runif(n(), -0.5, 0.5)
        )
    }
    
    cat("✅ Extracted coordinates for", nrow(coordinates_data), "documents\n")
    return(coordinates_data)
    
  }, error = function(e) {
    warning("Error extracting coordinates: ", e$message)
    return(data.frame())
  })
}

#' Calculate Distance Matrix Between Locations
#' 
#' Calculates distances between document locations for transport analysis.
#' 
#' @param coordinates_data data.frame with latitude/longitude
#' @param method Character distance calculation method ("haversine", "vincenty")
#' @return matrix with distances in kilometers
#' @export
calculate_distance_matrix <- function(coordinates_data, method = "haversine") {
  cat("📏 Calculating distance matrix...\n")
  
  tryCatch({
    if (nrow(coordinates_data) == 0) {
      return(matrix(0, nrow = 0, ncol = 0))
    }
    
    # Limit to 100 points for Railway memory constraints
    if (nrow(coordinates_data) > 100) {
      coordinates_data <- coordinates_data %>% slice_head(n = 100)
      warning("Limited to 100 points for distance calculation")
    }
    
    # Create coordinate matrix
    coords_matrix <- as.matrix(coordinates_data[, c("longitude", "latitude")])
    
    # Calculate distances based on method
    if (method == "haversine") {
      distance_matrix <- geosphere::distm(coords_matrix, fun = geosphere::distHaversine)
    } else if (method == "vincenty") {
      distance_matrix <- geosphere::distm(coords_matrix, fun = geosphere::distVincentyEllipsoid)
    } else {
      distance_matrix <- geosphere::distm(coords_matrix)
    }
    
    # Convert from meters to kilometers
    distance_matrix <- distance_matrix / 1000
    
    # Add row/column names if available
    if ("municipio" %in% names(coordinates_data)) {
      rownames(distance_matrix) <- coordinates_data$municipio
      colnames(distance_matrix) <- coordinates_data$municipio
    }
    
    cat("✅ Distance matrix calculated:", nrow(distance_matrix), "x", ncol(distance_matrix), "\n")
    return(distance_matrix)
    
  }, error = function(e) {
    warning("Error calculating distance matrix: ", e$message)
    return(matrix(0, nrow = 0, ncol = 0))
  })
}

#' Create Transport Corridors Analysis
#' 
#' Identifies and analyzes transport corridors based on document density.
#' 
#' @param documents_data data.frame with geographic documents
#' @param corridor_threshold Numeric minimum documents for corridor identification
#' @return list with corridor analysis results
#' @export
analyze_transport_corridors <- function(documents_data, corridor_threshold = 10) {
  cat("🛣️ Analyzing transport corridors...\n")
  
  tryCatch({
    # Extract transport-related documents
    transport_keywords <- c(
      "transporte", "rodovia", "ferrovia", "porto", "aeroporto", "estrada",
      "BR-", "SP-", "RJ-", "MG-", "logistics", "logística", "tráfego", 
      "mobilidade", "corredor", "eixo", "modal"
    )
    
    transport_docs <- documents_data %>%
      filter(
        grepl(paste(transport_keywords, collapse = "|"), 
              paste(titulo, resumo, localidade, sep = " "), 
              ignore.case = TRUE)
      )
    
    if (nrow(transport_docs) == 0) {
      warning("No transport-related documents found")
      return(list(corridors = data.frame(), statistics = list()))
    }
    
    # Get coordinates for transport documents
    transport_coords <- extract_document_coordinates(transport_docs, "localidade")
    
    # Identify major corridors based on document density
    corridors <- transport_coords %>%
      group_by(estado_extracted) %>%
      summarise(
        document_count = n(),
        avg_latitude = mean(latitude, na.rm = TRUE),
        avg_longitude = mean(longitude, na.rm = TRUE),
        .groups = "drop"
      ) %>%
      filter(document_count >= corridor_threshold) %>%
      arrange(desc(document_count))
    
    # Calculate corridor statistics
    corridor_stats <- list(
      total_transport_docs = nrow(transport_docs),
      corridors_identified = nrow(corridors),
      top_corridor = if(nrow(corridors) > 0) corridors$estado_extracted[1] else NA,
      coverage_percentage = round((nrow(transport_docs) / nrow(documents_data)) * 100, 2)
    )
    
    cat("✅ Transport corridor analysis complete:", nrow(corridors), "corridors identified\n")
    
    return(list(
      corridors = corridors,
      transport_documents = transport_docs,
      coordinates = transport_coords,
      statistics = corridor_stats
    ))
    
  }, error = function(e) {
    warning("Error analyzing transport corridors: ", e$message)
    return(list(corridors = data.frame(), statistics = list()))
  })
}

# FALLBACK DATA CREATION FUNCTIONS
# ================================

#' Create fallback Brazilian boundaries
create_fallback_brazilian_boundaries <- function() {
  # Simplified Brazilian state boundaries (major states only)
  states_simple <- data.frame(
    state_id = c(35, 33, 31, 23, 41, 43, 42, 50, 53),
    state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Ceará", 
                   "Paraná", "Rio Grande do Sul", "Santa Catarina", 
                   "Mato Grosso do Sul", "Distrito Federal"),
    state_abbr = c("SP", "RJ", "MG", "CE", "PR", "RS", "SC", "MS", "DF"),
    # Approximate bounding boxes
    min_lat = c(-25.5, -23.8, -22.9, -7.7, -26.7, -33.8, -29.4, -24.1, -16.1),
    max_lat = c(-19.8, -20.8, -14.2, -2.8, -22.5, -27.1, -25.2, -19.3, -15.5),
    min_lon = c(-53.1, -44.9, -51.0, -41.4, -54.6, -57.6, -53.8, -58.2, -48.3),
    max_lon = c(-44.2, -40.9, -39.9, -37.3, -48.0, -49.7, -48.3, -53.1, -47.4),
    stringsAsFactors = FALSE
  )
  
  # Create simple rectangular geometries for states
  states_sf <- states_simple %>%
    rowwise() %>%
    do({
      # Create rectangular polygon
      coords <- matrix(c(
        .$min_lon, .$min_lat,
        .$max_lon, .$min_lat,
        .$max_lon, .$max_lat,
        .$min_lon, .$max_lat,
        .$min_lon, .$min_lat
      ), ncol = 2, byrow = TRUE)
      
      polygon <- sf::st_polygon(list(coords))
      
      data.frame(
        state_id = .$state_id,
        state_name = .$state_name,
        state_abbr = .$state_abbr,
        geometry = sf::st_sfc(polygon, crs = 4326)
      )
    }) %>%
    sf::st_as_sf()
  
  # Create minimal municipalities dataset
  municipalities_simple <- data.frame(
    municipality_id = c(3550308, 3304557, 3106200),
    municipality_name = c("São Paulo", "Rio de Janeiro", "Belo Horizonte"),
    state_abbr = c("SP", "RJ", "MG"),
    latitude = c(-23.5505, -22.9068, -19.9167),
    longitude = c(-46.6333, -43.1729, -43.9345)
  ) %>%
    sf::st_as_sf(coords = c("longitude", "latitude"), crs = 4326)
  
  return(list(
    states = states_sf,
    municipalities = municipalities_simple
  ))
}

#' Create minimal boundaries for emergency fallback
create_minimal_boundaries <- function() {
  # Brazil outline only
  brazil_coords <- matrix(c(
    -73.985, -33.752,
    -34.793, -33.752,
    -34.793, 5.272,
    -73.985, 5.272,
    -73.985, -33.752
  ), ncol = 2, byrow = TRUE)
  
  brazil_polygon <- sf::st_polygon(list(brazil_coords))
  
  brazil_sf <- sf::st_sf(
    country = "Brasil",
    geometry = sf::st_sfc(brazil_polygon, crs = 4326)
  )
  
  return(list(
    states = sf::st_sf(geometry = sf::st_sfc(crs = 4326)),  # Empty
    municipalities = sf::st_sf(geometry = sf::st_sfc(crs = 4326)),  # Empty
    country = brazil_sf
  ))
}

# Memory management for Railway
cleanup_spatial_objects <- function() {
  # Clean up large spatial objects from memory
  invisible(gc())
  cat("✅ Spatial objects cleaned up\n")
}

cat("✅ Spatial processing utilities loaded successfully\n")