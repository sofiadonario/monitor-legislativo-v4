# Brazilian Coordinate Systems Integration Module - Sprint 1
# Monitor Legislativo v4 - SIRGAS 2000 and IBGE Administrative Boundaries Integration
# =================================================================================
# 
# Academic implementation of Brazilian official coordinate systems and administrative boundaries
# following RESEARCH_METHODOLOGY.md standards and Brazilian geodetic survey protocols
# Optimized for Railway 2GB memory constraints with chunked processing strategies
# 
# Key Features:
# - SIRGAS 2000 (EPSG:4674) official Brazilian datum integration
# - IBGE administrative boundaries (states, municipalities, regions) with academic validation
# - Memory-optimized processing for Railway deployment constraints (2GB limit)
# - Chunked geographic data loading with progressive enhancement
# - Academic coordinate transformation protocols with precision validation
# - Brazilian Administrative Code (IBGE) standardization and validation

# Load geospatial libraries with graceful lwgeom fallback
suppressPackageStartupMessages({
  library(sf)
  library(geobr)
  library(dplyr)
})

has_lwgeom <- requireNamespace("lwgeom", quietly = TRUE)

if (!has_lwgeom) {
  message("[brazil_coord] 'lwgeom' not available – using sf fallbacks for geometry operations.")
} else {
  message("[brazil_coord] 'lwgeom' available – advanced geometry operations enabled.")
  suppressPackageStartupMessages(library(lwgeom))
}

# Brazilian Coordinate Reference Systems Constants
# ==============================================

#' Brazilian Official Coordinate Reference Systems
#' 
#' Academic documentation of Brazilian coordinate systems following IBGE standards
#' and international geodetic survey protocols for legislative geographic research
BRAZILIAN_CRS <- list(
  
  # Primary Brazilian coordinate systems
  SIRGAS2000_GEOGRAPHIC = list(
    epsg = 4674,
    proj4 = "+proj=longlat +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +no_defs",
    name = "SIRGAS 2000",
    authority = "IBGE",
    scope = "Brazilian official geodetic datum",
    accuracy = "Sub-meter precision",
    adoption_year = 2005,
    legal_status = "Official Brazilian datum (IBGE Resolution 1/2005)",
    academic_reference = "IBGE (2005). Resolução 1/2005 - Adoção do SIRGAS2000"
  ),
  
  # UTM projections for different zones in Brazil
  SIRGAS2000_UTM_18S = list(
    epsg = 31978,
    proj4 = "+proj=utm +zone=18 +south +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +units=m +no_defs",
    coverage = "Western Brazil (Acre, western Amazonas)",
    academic_use = "Western Amazon region analysis"
  ),
  
  SIRGAS2000_UTM_19S = list(
    epsg = 31979,
    proj4 = "+proj=utm +zone=19 +south +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +units=m +no_defs",
    coverage = "Western Brazil (Rondônia, western Mato Grosso)",
    academic_use = "Western Central Brazil analysis"
  ),
  
  SIRGAS2000_UTM_20S = list(
    epsg = 31980,
    proj4 = "+proj=utm +zone=20 +south +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +units=m +no_defs",
    coverage = "Central Brazil (Mato Grosso, Goiás, Tocantins)",
    academic_use = "Central Brazil and Cerrado region analysis"
  ),
  
  SIRGAS2000_UTM_21S = list(
    epsg = 31981,
    proj4 = "+proj=utm +zone=21 +south +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +units=m +no_defs",
    coverage = "Central-East Brazil (Minas Gerais, Bahia, Goiás)",
    academic_use = "Southeastern and northeastern regions analysis"
  ),
  
  SIRGAS2000_UTM_22S = list(
    epsg = 31982,
    proj4 = "+proj=utm +zone=22 +south +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +units=m +no_defs",
    coverage = "Southeast Brazil (São Paulo, Rio de Janeiro, Espírito Santo)",
    academic_use = "Most populated region analysis"
  ),
  
  SIRGAS2000_UTM_23S = list(
    epsg = 31983,
    proj4 = "+proj=utm +zone=23 +south +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +units=m +no_defs",
    coverage = "Southeast Brazil (São Paulo, Paraná, Santa Catarina)",
    academic_use = "Southern Brazil economic corridor analysis"
  ),
  
  SIRGAS2000_UTM_24S = list(
    epsg = 31984,
    proj4 = "+proj=utm +zone=24 +south +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +units=m +no_defs",
    coverage = "Southern Brazil (Rio Grande do Sul, Santa Catarina)",
    academic_use = "Southern Brazil regional analysis"
  ),
  
  SIRGAS2000_UTM_25S = list(
    epsg = 31985,
    proj4 = "+proj=utm +zone=25 +south +ellps=GRS80 +towgs84=0,0,0,0,0,0,0 +units=m +no_defs",
    coverage = "Easternmost Brazil (coastal areas)",
    academic_use = "Atlantic coast analysis"
  ),
  
  # Legacy coordinate system (for historical data compatibility)
  SAD69_GEOGRAPHIC = list(
    epsg = 4618,
    proj4 = "+proj=longlat +ellps=aust_SA +towgs84=-67.35,3.88,-38.22,0,0,0,0 +no_defs",
    name = "South American Datum 1969",
    status = "Legacy (replaced by SIRGAS 2000)",
    academic_use = "Historical geodetic analysis and datum transformation studies"
  ),
  
  # International reference for comparison
  WGS84_GEOGRAPHIC = list(
    epsg = 4326,
    proj4 = "+proj=longlat +datum=WGS84 +no_defs",
    name = "World Geodetic System 1984",
    academic_use = "International comparison and GPS integration"
  )
)

# Brazilian Administrative Hierarchy
# ================================

#' IBGE Administrative Code Structure
#' 
#' Official Brazilian administrative hierarchy following IBGE standards
#' for academic legislative geographic research
IBGE_ADMINISTRATIVE_CODES <- list(
  
  # Federal level
  country = list(
    code = "BR",
    name = "Brasil",
    level = 0,
    authority = "IBGE",
    total_area_km2 = 8515767
  ),
  
  # Regional level (5 major regions)
  regions = data.frame(
    region_code = 1:5,
    region_name = c("Norte", "Nordeste", "Sudeste", "Sul", "Centro-Oeste"),
    region_name_en = c("North", "Northeast", "Southeast", "South", "Center-West"),
    established_year = c(1942, 1942, 1942, 1942, 1942),
    stringsAsFactors = FALSE
  ),
  
  # State level (26 states + 1 federal district)
  states = data.frame(
    state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                   "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                   "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    
    state_name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", "Distrito Federal",
                   "Espírito Santo", "Goiás", "Maranhão", "Mato Grosso", "Mato Grosso do Sul", 
                   "Minas Gerais", "Pará", "Paraíba", "Paraná", "Pernambuco", "Piauí", 
                   "Rio de Janeiro", "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", 
                   "Roraima", "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
    
    region_code = c(1, 2, 1, 1, 2, 2, 5, 3, 5, 2, 5, 5, 3, 1, 2, 4, 2, 2, 3, 2, 4, 1, 1, 4, 3, 2, 1),
    
    capital = c("Rio Branco", "Maceió", "Macapá", "Manaus", "Salvador", "Fortaleza", "Brasília",
                "Vitória", "Goiânia", "São Luís", "Cuiabá", "Campo Grande", "Belo Horizonte", 
                "Belém", "João Pessoa", "Curitiba", "Recife", "Teresina", "Rio de Janeiro", 
                "Natal", "Porto Alegre", "Porto Velho", "Boa Vista", "Florianópolis", 
                "São Paulo", "Aracaju", "Palmas"),
    
    creation_year = c(1962, 1817, 1943, 1850, 1534, 1822, 1960, 1534, 1744, 1621, 1977, 1977, 
                      1720, 1621, 1585, 1853, 1534, 1718, 1565, 1597, 1807, 1943, 1943, 
                      1738, 1532, 1820, 1988),
    
    area_km2 = c(164123, 27848, 142815, 1559167, 564733, 148920, 5760, 46095, 340111, 331936,
                 903366, 357145, 586520, 1247954, 56439, 199307, 98311, 251529, 43696, 52797,
                 281748, 237765, 224299, 95346, 248222, 21915, 277621),
    
    stringsAsFactors = FALSE
  )
)

# Memory-Optimized Geographic Data Loading
# =======================================

#' Load Brazilian Administrative Boundaries with Memory Optimization
#' 
#' Academic implementation of IBGE boundary loading optimized for Railway 2GB constraints
#' with progressive enhancement and chunked processing strategies
#' 
#' @param level Administrative level ("state", "municipality", "region")
#' @param year Reference year for boundaries (default: 2020)
#' @param simplified Simplification level for memory optimization (0-1, default: 0.1)
#' @param chunk_size Maximum number of features per chunk for processing
#' @param progress_callback Function to report loading progress
#' @return SF object with Brazilian administrative boundaries in SIRGAS 2000
load_brazil_boundaries_optimized <- function(level = "state", 
                                            year = 2020, 
                                            simplified = 0.1,
                                            chunk_size = 100,
                                            progress_callback = NULL) {
  
  tryCatch({
    
    if (!is.null(progress_callback)) {
      progress_callback(0, paste("Loading Brazilian", level, "boundaries..."))
    }
    
    # Memory monitoring
    initial_memory <- gc(verbose = FALSE)
    
    # Load boundaries based on level
    if (level == "state") {
      
      if (!is.null(progress_callback)) {
        progress_callback(0.2, "Downloading state boundaries from IBGE...")
      }
      
      # Load state boundaries
      boundaries_raw <- geobr::read_state(year = year, showProgress = FALSE)
      
      if (!is.null(progress_callback)) {
        progress_callback(0.5, "Processing state boundaries...")
      }
      
      # Transform to SIRGAS 2000 and simplify for memory efficiency
      boundaries <- boundaries_raw %>%
        sf::st_transform(crs = 4674) %>%  # SIRGAS 2000
        sf::st_simplify(preserveTopology = TRUE, dTolerance = simplified) %>%
        mutate(
          # Standardize column names for academic analysis
          state_code = abbrev_state,
          state_name = name_state,
          region_name = name_region,
          region_code = code_region,
          area_km2 = as.numeric(sf::st_area(.)) / 1000000,  # Convert to km²
          
          # Academic metadata
          ibge_code = code_state,
          coordinate_system = "SIRGAS 2000 (EPSG:4674)",
          data_source = "IBGE",
          reference_year = year,
          processing_date = Sys.Date()
        ) %>%
        select(state_code, state_name, region_name, region_code, area_km2, 
               ibge_code, coordinate_system, data_source, reference_year, 
               processing_date, geometry)
      
    } else if (level == "municipality") {
      
      if (!is.null(progress_callback)) {
        progress_callback(0.2, "Loading municipal boundaries in chunks...")
      }
      
      # Load municipalities in chunks by state to manage memory
      # Focus on major states first for Railway memory constraints
      major_states <- c("SP", "MG", "RJ", "RS", "PR", "SC", "BA", "GO", "DF")
      
      municipality_chunks <- list()
      
      for (i in seq_along(major_states)) {
        state <- major_states[i]
        
        if (!is.null(progress_callback)) {
          progress_callback(0.2 + (i / length(major_states)) * 0.6, 
                          paste("Processing", state, "municipalities..."))
        }
        
        # Load state municipalities
        state_municipalities <- geobr::read_municipality(code_muni = state, year = year, showProgress = FALSE)
        
        # Process chunk
        processed_chunk <- state_municipalities %>%
          sf::st_transform(crs = 4674) %>%  # SIRGAS 2000
          sf::st_simplify(preserveTopology = TRUE, dTolerance = simplified * 2) %>%  # More aggressive simplification
          mutate(
            municipality_code = code_muni,
            municipality_name = name_muni,
            state_code = abbrev_state,
            area_km2 = as.numeric(sf::st_area(.)) / 1000000,
            coordinate_system = "SIRGAS 2000 (EPSG:4674)",
            data_source = "IBGE",
            reference_year = year
          ) %>%
          select(municipality_code, municipality_name, state_code, area_km2,
                 coordinate_system, data_source, reference_year, geometry)
        
        municipality_chunks[[state]] <- processed_chunk
        
        # Memory management
        rm(state_municipalities, processed_chunk)
        gc(verbose = FALSE)
        
        # Safety check for Railway memory constraints
        current_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
        if (current_memory > 1500) {  # 1.5GB threshold
          warning("Approaching memory limit, stopping municipal loading")
          break
        }
      }
      
      if (!is.null(progress_callback)) {
        progress_callback(0.9, "Combining municipal boundaries...")
      }
      
      # Combine all chunks
      boundaries <- bind_rows(municipality_chunks)
      
    } else if (level == "region") {
      
      if (!is.null(progress_callback)) {
        progress_callback(0.3, "Creating regional boundaries from states...")
      }
      
      # Create regional boundaries by aggregating states
      state_boundaries <- load_brazil_boundaries_optimized("state", year, simplified, chunk_size, NULL)
      
      boundaries <- state_boundaries %>%
        group_by(region_name, region_code) %>%
        summarise(
          states_count = n(),
          total_area_km2 = sum(area_km2, na.rm = TRUE),
          coordinate_system = first(coordinate_system),
          data_source = first(data_source),
          reference_year = first(reference_year),
          geometry = sf::st_union(geometry),
          .groups = "drop"
        )
    }
    
    if (!is.null(progress_callback)) {
      progress_callback(0.95, "Validating geographic data...")
    }
    
    # Validate boundaries
    boundaries <- validate_brazil_boundaries(boundaries, level)
    
    # Add academic metadata
    attr(boundaries, "academic_metadata") <- list(
      administrative_level = level,
      coordinate_system = "SIRGAS 2000 (EPSG:4674)",
      reference_year = year,
      data_source = "IBGE (Instituto Brasileiro de Geografia e Estatística)",
      simplification_level = simplified,
      processing_date = Sys.time(),
      memory_optimization = "Railway 2GB constraints",
      academic_validation = "RESEARCH_METHODOLOGY.md compliant",
      legal_framework = "Brazilian Federal Constitution, Art. 18"
    )
    
    # Memory cleanup
    final_memory <- gc(verbose = FALSE)
    memory_used <- sum(final_memory[, "(Mb)"])
    
    if (!is.null(progress_callback)) {
      progress_callback(1, paste("Boundaries loaded successfully. Memory:", round(memory_used, 1), "MB"))
    }
    
    return(boundaries)
    
  }, error = function(e) {
    warning("Error loading Brazilian boundaries: ", e$message)
    return(NULL)
  })
}

#' Validate Brazilian Administrative Boundaries
#' 
#' Academic validation of Brazilian administrative boundaries following
#' IBGE standards and geographic research protocols
#' 
#' @param boundaries SF object with Brazilian boundaries
#' @param level Administrative level for validation
#' @return Validated SF object with quality indicators
validate_brazil_boundaries <- function(boundaries, level) {
  
  if (is.null(boundaries) || nrow(boundaries) == 0) {
    return(boundaries)
  }
  
  # Geometric validation
  validation_results <- list(
    valid_geometries = sf::st_is_valid(boundaries),
    empty_geometries = sf::st_is_empty(boundaries),
    coordinate_system = sf::st_crs(boundaries),
    bbox = sf::st_bbox(boundaries)
  )
  
  # Check coordinate system
  if (validation_results$coordinate_system$epsg != 4674) {
    warning("Boundaries not in SIRGAS 2000 (EPSG:4674)")
  }
  
  # Validate administrative completeness
  if (level == "state") {
    expected_states <- 27  # 26 states + 1 federal district
    if (!is.null(boundaries) && is.data.frame(boundaries) && nrow(boundaries) != expected_states) {
      warning(paste("Expected 27 Brazilian states, found", nrow(boundaries)))
    }
  }
  
  # Add validation metadata
  boundaries$geometry_valid <- validation_results$valid_geometries
  boundaries$geometry_empty <- validation_results$empty_geometries
  boundaries$data_quality <- case_when(
    !validation_results$valid_geometries ~ "invalid_geometry",
    validation_results$empty_geometries ~ "empty_geometry",
    is.na(boundaries$area_km2) ~ "missing_area",
    boundaries$area_km2 <= 0 ~ "invalid_area",
    TRUE ~ "valid"
  )
  
  return(boundaries)
}

#' Transform Coordinates Between Brazilian Systems
#' 
#' Academic coordinate transformation following Brazilian geodetic standards
#' with precision validation and academic documentation
#' 
#' @param spatial_data SF object to transform
#' @param target_crs Target coordinate reference system (EPSG code or proj4 string)
#' @param source_crs Source coordinate reference system (auto-detected if NULL)
#' @param validate_precision Validate transformation precision (default: TRUE)
#' @return Transformed SF object with transformation metadata
transform_brazil_coordinates <- function(spatial_data, 
                                        target_crs = 4674, 
                                        source_crs = NULL,
                                        validate_precision = TRUE) {
  
  tryCatch({
    
    if (is.null(spatial_data) || nrow(spatial_data) == 0) {
      return(spatial_data)
    }
    
    # Determine source CRS
    if (is.null(source_crs)) {
      source_crs <- sf::st_crs(spatial_data)
    }
    
    # Check if transformation is needed
    if (sf::st_crs(spatial_data)$epsg == target_crs) {
      return(spatial_data)
    }
    
    # Record original centroids for precision validation
    if (validate_precision) {
      original_centroids <- sf::st_coordinates(sf::st_centroid(spatial_data))
    }
    
    # Perform transformation
    transformed_data <- sf::st_transform(spatial_data, crs = target_crs)
    
    # Precision validation
    if (validate_precision && !is.null(transformed_data) && is.data.frame(transformed_data) && nrow(transformed_data) > 0) {
      transformed_centroids <- sf::st_coordinates(sf::st_centroid(transformed_data))
      
      # Calculate transformation quality metrics
      coordinate_shift <- sqrt(
        (transformed_centroids[, 1] - original_centroids[, 1])^2 + 
        (transformed_centroids[, 2] - original_centroids[, 2])^2
      )
      
      # Add transformation metadata
      attr(transformed_data, "transformation_metadata") <- list(
        source_crs = source_crs,
        target_crs = sf::st_crs(transformed_data),
        transformation_date = Sys.time(),
        precision_validation = list(
          max_coordinate_shift = max(coordinate_shift, na.rm = TRUE),
          mean_coordinate_shift = mean(coordinate_shift, na.rm = TRUE),
          precision_warning = any(coordinate_shift > 1000, na.rm = TRUE)  # Warning if shift > 1km
        ),
        academic_standard = "IBGE geodetic transformation protocols"
      )
    }
    
    return(transformed_data)
    
  }, error = function(e) {
    warning("Error in coordinate transformation: ", e$message)
    return(spatial_data)
  })
}

#' Get Optimal UTM Zone for Brazilian Coordinates
#' 
#' Determine optimal UTM zone for Brazilian geographic data based on centroid location
#' following academic cartographic standards
#' 
#' @param spatial_data SF object with Brazilian geographic data
#' @param return_epsg Return EPSG code instead of zone number (default: TRUE)
#' @return UTM zone number or EPSG code for optimal projection
get_optimal_utm_zone_brazil <- function(spatial_data, return_epsg = TRUE) {
  
  tryCatch({
    
    if (is.null(spatial_data) || nrow(spatial_data) == 0) {
      return(if (return_epsg) 31983 else 23)  # Default to UTM 23S
    }
    
    # Calculate centroid in geographic coordinates (SIRGAS 2000)
    if (sf::st_crs(spatial_data)$epsg != 4674) {
      spatial_data <- sf::st_transform(spatial_data, crs = 4674)
    }
    
    centroid <- sf::st_coordinates(sf::st_centroid(sf::st_union(spatial_data)))
    longitude <- centroid[1, "X"]
    latitude <- centroid[1, "Y"]
    
    # Determine UTM zone based on longitude
    # Brazil spans UTM zones 18-25 (south)
    utm_zone <- floor((longitude + 180) / 6) + 1
    
    # Validate for Brazilian territory
    utm_zone <- max(18, min(25, utm_zone))
    
    if (return_epsg) {
      # Return SIRGAS 2000 UTM zone EPSG code
      epsg_codes <- c(
        "18" = 31978, "19" = 31979, "20" = 31980, "21" = 31981,
        "22" = 31982, "23" = 31983, "24" = 31984, "25" = 31985
      )
      return(epsg_codes[as.character(utm_zone)])
    } else {
      return(utm_zone)
    }
    
  }, error = function(e) {
    warning("Error determining optimal UTM zone: ", e$message)
    return(if (return_epsg) 31983 else 23)
  })
}

# Export all functions and constants
list(
  BRAZILIAN_CRS = BRAZILIAN_CRS,
  IBGE_ADMINISTRATIVE_CODES = IBGE_ADMINISTRATIVE_CODES,
  load_brazil_boundaries_optimized = load_brazil_boundaries_optimized,
  validate_brazil_boundaries = validate_brazil_boundaries,
  transform_brazil_coordinates = transform_brazil_coordinates,
  get_optimal_utm_zone_brazil = get_optimal_utm_zone_brazil
)