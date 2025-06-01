# GeoJSON Handler Module
# Fixes GeoJSON closure error and provides Brazilian state boundaries

library(jsonlite)
library(sf)

# Load Brazil GeoJSON with proper error handling
load_brazil_geojson <- function() {
  tryCatch({
    # Try to load from external file first
    geojson_paths <- c(
      "data/brazil_states.geojson",
      "inst/extdata/brazil_states.geojson",
      system.file("extdata", "brazil_states.geojson", package = "monitor_legislativo")
    )
    
    for (path in geojson_paths) {
      if (file.exists(path)) {
        cat("Loading GeoJSON from:", path, "\n")
        geojson_data <- fromJSON(path, simplifyVector = FALSE)
        
        # Validate that it's proper GeoJSON
        if (!is.null(geojson_data$type) && geojson_data$type == "FeatureCollection") {
          return(geojson_data)
        }
      }
    }
    
    # If no file found, use inline boundaries
    cat("Using inline Brazil boundaries\n")
    return(get_inline_brazil_boundaries())
    
  }, error = function(e) {
    cat("Error loading GeoJSON:", e$message, "\n")
    cat("Falling back to inline boundaries\n")
    return(get_inline_brazil_boundaries())
  })
}

# Inline Brazil state boundaries (simplified)
get_inline_brazil_boundaries <- function() {
  # Simplified boundaries for Brazilian states
  # This is a fallback when GeoJSON files are not available
  
  boundaries <- list(
    type = "FeatureCollection",
    features = list(
      # São Paulo
      list(
        type = "Feature",
        properties = list(
          state_code = "SP",
          state_name = "São Paulo",
          region = "Southeast"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-53.11, -25.31), c(-53.11, -19.78), c(-44.16, -19.78),
            c(-44.16, -25.31), c(-53.11, -25.31)
          ))
        )
      ),
      
      # Rio de Janeiro
      list(
        type = "Feature",
        properties = list(
          state_code = "RJ",
          state_name = "Rio de Janeiro",
          region = "Southeast"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-44.89, -23.37), c(-44.89, -20.76), c(-40.96, -20.76),
            c(-40.96, -23.37), c(-44.89, -23.37)
          ))
        )
      ),
      
      # Minas Gerais
      list(
        type = "Feature",
        properties = list(
          state_code = "MG",
          state_name = "Minas Gerais",
          region = "Southeast"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-51.04, -22.92), c(-51.04, -14.23), c(-39.86, -14.23),
            c(-39.86, -22.92), c(-51.04, -22.92)
          ))
        )
      ),
      
      # Bahia
      list(
        type = "Feature",
        properties = list(
          state_code = "BA",
          state_name = "Bahia",
          region = "Northeast"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-46.62, -18.35), c(-46.62, -8.53), c(-37.34, -8.53),
            c(-37.34, -18.35), c(-46.62, -18.35)
          ))
        )
      ),
      
      # Distrito Federal
      list(
        type = "Feature",
        properties = list(
          state_code = "DF",
          state_name = "Distrito Federal",
          region = "Central-West"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-48.28, -16.05), c(-48.28, -15.50), c(-47.31, -15.50),
            c(-47.31, -16.05), c(-48.28, -16.05)
          ))
        )
      ),
      
      # Paraná
      list(
        type = "Feature",
        properties = list(
          state_code = "PR",
          state_name = "Paraná",
          region = "South"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-54.62, -26.52), c(-54.62, -22.52), c(-48.02, -22.52),
            c(-48.02, -26.52), c(-54.62, -26.52)
          ))
        )
      ),
      
      # Santa Catarina
      list(
        type = "Feature",
        properties = list(
          state_code = "SC",
          state_name = "Santa Catarina",
          region = "South"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-53.84, -29.35), c(-53.84, -25.95), c(-48.55, -25.95),
            c(-48.55, -29.35), c(-53.84, -29.35)
          ))
        )
      ),
      
      # Rio Grande do Sul
      list(
        type = "Feature",
        properties = list(
          state_code = "RS",
          state_name = "Rio Grande do Sul",
          region = "South"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-57.64, -33.75), c(-57.64, -27.08), c(-49.69, -27.08),
            c(-49.69, -33.75), c(-57.64, -33.75)
          ))
        )
      ),
      
      # Amazonas
      list(
        type = "Feature",
        properties = list(
          state_code = "AM",
          state_name = "Amazonas",
          region = "North"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-73.98, -9.82), c(-73.98, 2.25), c(-56.10, 2.25),
            c(-56.10, -9.82), c(-73.98, -9.82)
          ))
        )
      ),
      
      # Pará
      list(
        type = "Feature",
        properties = list(
          state_code = "PA",
          state_name = "Pará",
          region = "North"
        ),
        geometry = list(
          type = "Polygon",
          coordinates = list(list(
            c(-58.89, -9.83), c(-58.89, 2.59), c(-46.06, 2.59),
            c(-46.06, -9.83), c(-58.89, -9.83)
          ))
        )
      )
      
      # Add more states as needed...
    )
  )
  
  return(boundaries)
}

# Convert GeoJSON to sf object for spatial operations
geojson_to_sf <- function(geojson_data) {
  tryCatch({
    # Convert GeoJSON to sf object
    sf_obj <- st_read(
      toJSON(geojson_data, auto_unbox = TRUE),
      quiet = TRUE
    )
    
    # Set CRS to SIRGAS 2000 (Brazilian standard)
    st_crs(sf_obj) <- "EPSG:4674"
    
    return(sf_obj)
    
  }, error = function(e) {
    cat("Error converting GeoJSON to sf:", e$message, "\n")
    return(NULL)
  })
}

# Create choropleth data from state statistics
prepare_choropleth_data <- function(state_stats, geojson_boundaries = NULL) {
  if (is.null(geojson_boundaries)) {
    geojson_boundaries <- load_brazil_geojson()
  }
  
  # Ensure state_stats has required columns
  required_cols <- c("estado", "doc_count")
  if (!all(required_cols %in% names(state_stats))) {
    stop("state_stats must have 'estado' and 'doc_count' columns")
  }
  
  # Create mapping between state codes and values
  choropleth_data <- list(
    geojson = geojson_boundaries,
    values = state_stats %>%
      select(estado, value = doc_count) %>%
      deframe(),  # Convert to named vector
    metadata = list(
      min_value = min(state_stats$doc_count, na.rm = TRUE),
      max_value = max(state_stats$doc_count, na.rm = TRUE),
      total_states = nrow(state_stats),
      timestamp = Sys.time()
    )
  )
  
  return(choropleth_data)
}

# Validate GeoJSON structure
validate_geojson <- function(geojson_data) {
  required_fields <- c("type", "features")
  
  # Check if it's a list/object
  if (!is.list(geojson_data)) {
    return(list(valid = FALSE, error = "GeoJSON must be a list/object"))
  }
  
  # Check required fields
  if (!all(required_fields %in% names(geojson_data))) {
    return(list(valid = FALSE, error = "Missing required fields: type or features"))
  }
  
  # Check type
  if (geojson_data$type != "FeatureCollection") {
    return(list(valid = FALSE, error = "GeoJSON type must be FeatureCollection"))
  }
  
  # Check features
  if (!is.list(geojson_data$features) || length(geojson_data$features) == 0) {
    return(list(valid = FALSE, error = "Features must be a non-empty list"))
  }
  
  # Validate each feature
  for (i in seq_along(geojson_data$features)) {
    feature <- geojson_data$features[[i]]
    
    if (!is.list(feature) || 
        !all(c("type", "properties", "geometry") %in% names(feature))) {
      return(list(
        valid = FALSE, 
        error = sprintf("Invalid feature at index %d", i)
      ))
    }
    
    if (feature$type != "Feature") {
      return(list(
        valid = FALSE,
        error = sprintf("Feature %d has invalid type", i)
      ))
    }
  }
  
  return(list(valid = TRUE, error = NULL))
}

# Create or update GeoJSON file with Brazilian states
create_brazil_geojson_file <- function(output_path = "data/brazil_states.geojson") {
  # Ensure directory exists
  dir.create(dirname(output_path), showWarnings = FALSE, recursive = TRUE)
  
  # Get inline boundaries
  geojson_data <- get_inline_brazil_boundaries()
  
  # Validate before saving
  validation <- validate_geojson(geojson_data)
  if (!validation$valid) {
    stop("Invalid GeoJSON: ", validation$error)
  }
  
  # Write to file
  write_json(
    geojson_data,
    output_path,
    auto_unbox = TRUE,
    pretty = TRUE
  )
  
  cat("GeoJSON file created at:", output_path, "\n")
  return(output_path)
}

# Export functions
geojson_handler_exports <- list(
  load_brazil_geojson = load_brazil_geojson,
  get_inline_brazil_boundaries = get_inline_brazil_boundaries,
  geojson_to_sf = geojson_to_sf,
  prepare_choropleth_data = prepare_choropleth_data,
  validate_geojson = validate_geojson,
  create_brazil_geojson_file = create_brazil_geojson_file
)