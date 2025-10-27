# IBGE Geographic Data Integration Module - Sprint 5B
# Brazilian Legislative Monitoring System - GEO-001 Implementation
# ================================================================================
# 
# Core IBGE integration system providing robust administrative boundary data
# for the Brazilian Legislative Dashboard with 134k+ documents
# 
# FEATURES:
# - Official IBGE administrative boundaries (estados and municípios)
# - Memory-optimized loading for Railway 2GB constraints
# - Progressive spatial data caching system
# - Geographic reference linking to legislative documents
# - State and municipality-level analysis capabilities
# - SIRGAS 2000 coordinate system standardization
# 
# TECHNICAL ARCHITECTURE:
# - Modular design following existing app patterns
# - PostgreSQL spatial extensions integration
# - Efficient spatial indexing and caching
# - Robust error handling and fallback mechanisms
# - Academic-grade data validation and quality controls
# 
# RAILWAY OPTIMIZATIONS:
# - Chunked data loading to prevent memory exhaustion
# - Smart caching to minimize API calls
# - Compressed spatial data storage
# - Progressive enhancement for user experience
# ================================================================================

library(sf)
library(dplyr)
library(DBI)
library(pool)
library(jsonlite)

# Load core geographic coordinate systems
if (file.exists("modules/geographic/brazil_coordinate_systems.R")) {
  source("modules/geographic/brazil_coordinate_systems.R")
}

# IBGE Data Sources and Configuration
# ==================================

#' IBGE Administrative Boundary Configuration
#' Official Brazilian administrative boundaries with academic validation
IBGE_CONFIG <- list(
  # Data sources
  data_sources = list(
    states = "https://servicodados.ibge.gov.br/api/v3/malhas/paises/BR?resolucao=5&formato=application/vnd.geo+json",
    municipalities = "https://servicodados.ibge.gov.br/api/v3/malhas/estados/{UF}?resolucao=5&formato=application/vnd.geo+json",
    regions = "https://servicodados.ibge.gov.br/api/v3/malhas/paises/BR?resolucao=5&formato=application/vnd.geo+json&intrarregiao=regiao"
  ),
  
  # Memory optimization settings for Railway
  memory_limits = list(
    max_features_per_chunk = 100,
    simplification_tolerance = 0.01,  # 1% simplification for web display
    cache_expiry_hours = 24,
    max_memory_usage_mb = 1500  # Stay under 1.5GB
  ),
  
  # Quality control parameters
  validation = list(
    min_area_km2 = 0.1,  # Minimum valid area
    max_area_km2 = 2000000,  # Maximum valid area (larger than any Brazilian state)
    required_columns = c("code", "name", "geometry"),
    coordinate_systems = c(4674, 4326)  # SIRGAS 2000 and WGS84
  ),
  
  # Academic metadata
  metadata = list(
    data_source = "IBGE - Instituto Brasileiro de Geografia e Estatística",
    coordinate_system = "SIRGAS 2000 (EPSG:4674)",
    legal_framework = "Brazilian Federal Constitution, Article 18",
    academic_standard = "RESEARCH_METHODOLOGY.md compliant",
    update_frequency = "Annual with IBGE territorial updates",
    quality_assurance = "Academic validation protocols"
  )
)

# Core IBGE Integration Functions
# ==============================

#' Initialize IBGE Geographic System
#' 
#' Sets up the IBGE integration system with database connections,
#' cache management, and spatial data validation
#' 
#' @param db_pool Database connection pool
#' @param force_refresh Force refresh of cached data (default: FALSE)
#' @return List with system status and initialization results
initialize_ibge_system <- function(db_pool = NULL, force_refresh = FALSE) {
  
  cat("🌐 Initializing IBGE Geographic Integration System...\n")
  
  tryCatch({
    
    # Initialize results structure
    init_results <- list(
      status = "initializing",
      timestamp = Sys.time(),
      components = list(),
      errors = c(),
      warnings = c()
    )
    
    # 1. Database Connection Validation
    cat("📊 Validating database connection...\n")
    if (!is.null(db_pool)) {
      db_status <- validate_spatial_database(db_pool)
      init_results$components$database <- db_status
      
      if (!db_status$valid) {
        init_results$warnings <- c(init_results$warnings, "Database spatial extensions not available")
      }
    } else {
      init_results$warnings <- c(init_results$warnings, "No database pool provided")
    }
    
    # 2. Cache System Setup
    cat("💾 Setting up spatial data cache...\n")
    cache_status <- setup_spatial_cache()
    init_results$components$cache <- cache_status
    
    # 3. Memory Management Setup
    cat("🧠 Configuring memory management...\n")
    memory_config <- setup_memory_management()
    init_results$components$memory <- memory_config
    
    # 4. Load Core Administrative Data
    cat("🗺️ Loading core administrative boundaries...\n")
    
    # Load states first (smaller dataset)
    states_data <- load_ibge_states(force_refresh = force_refresh)
    init_results$components$states <- list(
      loaded = !is.null(states_data),
      count = ifelse(!is.null(states_data), nrow(states_data), 0),
      memory_mb = round(object.size(states_data) / 1024^2, 2)
    )
    
    # Test municipality loading with a small state
    test_municipalities <- load_ibge_municipalities(
      state_code = "DF",  # Federal District - smallest administrative unit
      force_refresh = force_refresh
    )
    init_results$components$municipalities_test <- list(
      loaded = !is.null(test_municipalities),
      count = ifelse(!is.null(test_municipalities), nrow(test_municipalities), 0),
      memory_mb = round(object.size(test_municipalities) / 1024^2, 2)
    )
    
    # 5. System Status Assessment
    successful_components <- sum(sapply(init_results$components, function(x) {
      if (is.list(x) && "loaded" %in% names(x)) return(x$loaded)
      if (is.list(x) && "valid" %in% names(x)) return(x$valid)
      return(TRUE)
    }))
    
    total_components <- length(init_results$components)
    
    if (successful_components >= total_components * 0.7) {
      init_results$status <- "operational"
      cat("✅ IBGE System initialized successfully\n")
    } else {
      init_results$status <- "partial"
      cat("⚠️ IBGE System partially initialized\n")
    }
    
    # Add academic metadata
    init_results$metadata <- IBGE_CONFIG$metadata
    init_results$metadata$initialization_date <- Sys.time()
    
    return(init_results)
    
  }, error = function(e) {
    cat("❌ IBGE System initialization failed:", e$message, "\n")
    return(list(
      status = "failed",
      error = e$message,
      timestamp = Sys.time()
    ))
  })
}

#' Load IBGE State Boundaries
#' 
#' Loads and processes Brazilian state administrative boundaries
#' with memory optimization and academic validation
#' 
#' @param force_refresh Force refresh from IBGE API (default: FALSE)
#' @param simplify_geometry Apply geometry simplification (default: TRUE)
#' @return SF object with Brazilian state boundaries
load_ibge_states <- function(force_refresh = FALSE, simplify_geometry = TRUE) {
  
  cat("📍 Loading Brazilian state boundaries...\n")
  
  tryCatch({
    
    # Check cache first
    cache_key <- "ibge_states"
    if (!force_refresh) {
      cached_states <- get_spatial_cache(cache_key)
      if (!is.null(cached_states)) {
        cat("💾 Using cached state boundaries\n")
        return(cached_states)
      }
    }
    
    # Use geobr package as primary source (more reliable than direct API)
    if (require(geobr, quietly = TRUE)) {
      
      cat("🔄 Downloading state boundaries from geobr...\n")
      
      # Load with progress monitoring
      states_raw <- geobr::read_state(year = 2020, showProgress = FALSE)
      
      if (isTRUE(is.null(states_raw)) || nrow(states_raw) == 0) {
        stop("Failed to load state boundaries from geobr")
      }
      
      cat("✅ Downloaded", nrow(states_raw), "state boundaries\n")
      
      # Process and standardize
      states_processed <- states_raw %>%
        # Transform to SIRGAS 2000
        sf::st_transform(crs = 4674) %>%
        # Apply simplification for web performance if requested
        {if(simplify_geometry) sf::st_simplify(., preserveTopology = TRUE, dTolerance = 0.01) else .} %>%
        # Standardize column names
        mutate(
          state_code = abbrev_state,
          state_name = name_state,
          state_name_clean = toupper(trimws(name_state)),
          region_code = code_region,
          region_name = name_region,
          ibge_code = code_state,
          area_km2 = as.numeric(sf::st_area(geometry)) / 1000000,
          
          # Academic metadata
          data_source = "IBGE via geobr",
          coordinate_system = "SIRGAS 2000 (EPSG:4674)",
          reference_year = 2020,
          processing_date = Sys.Date(),
          simplification_applied = simplify_geometry
        ) %>%
        # Select standardized columns
        select(
          state_code, state_name, state_name_clean, region_code, region_name,
          ibge_code, area_km2, data_source, coordinate_system, reference_year,
          processing_date, simplification_applied, geometry
        )
      
      # Quality validation
      states_validated <- validate_spatial_data(
        states_processed, 
        level = "state",
        expected_count = 27  # 26 states + 1 federal district
      )
      
      if (!is.null(states_validated)) {
        # Cache the processed data
        set_spatial_cache(cache_key, states_validated, expiry_hours = 24)
        
        cat("✅ Processed", nrow(states_validated), "state boundaries\n")
        return(states_validated)
      }
    }
    
    # Fallback to manual boundary creation if geobr fails
    cat("⚠️ geobr unavailable, creating fallback state boundaries...\n")
    fallback_states <- create_fallback_states()
    
    if (!is.null(fallback_states)) {
      set_spatial_cache(cache_key, fallback_states, expiry_hours = 6)  # Shorter cache for fallback
    }
    
    return(fallback_states)
    
  }, error = function(e) {
    cat("❌ Error loading state boundaries:", e$message, "\n")
    
    # Try to return cached data even if expired
    cached_fallback <- get_spatial_cache("ibge_states", ignore_expiry = TRUE)
    if (!is.null(cached_fallback)) {
      cat("💾 Using expired cache as fallback\n")
      return(cached_fallback)
    }
    
    return(NULL)
  })
}

#' Load IBGE Municipality Boundaries
#' 
#' Loads municipal boundaries for specified states with memory optimization
#' 
#' @param state_code State code(s) to load municipalities for (default: all major states)
#' @param force_refresh Force refresh from IBGE API (default: FALSE)
#' @param chunk_size Maximum municipalities per processing chunk
#' @return SF object with municipality boundaries
load_ibge_municipalities <- function(state_code = c("SP", "MG", "RJ", "RS", "PR", "SC", "DF"), 
                                    force_refresh = FALSE, 
                                    chunk_size = 50) {
  
  cat("🏘️ Loading municipality boundaries for:", paste(state_code, collapse = ", "), "\n")
  
  tryCatch({
    
    # Process states in chunks to manage memory
    all_municipalities <- list()
    
    for (state in state_code) {
      
      cat("📍 Processing municipalities for state:", state, "\n")
      
      # Check cache for this state
      cache_key <- paste0("ibge_municipalities_", state)
      if (!force_refresh) {
        cached_munic <- get_spatial_cache(cache_key)
        if (!is.null(cached_munic)) {
          cat("💾 Using cached municipalities for", state, "\n")
          all_municipalities[[state]] <- cached_munic
          next
        }
      }
      
      # Load municipalities for this state
      if (require(geobr, quietly = TRUE)) {
        
        # Memory check before loading
        current_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
        if (current_memory > IBGE_CONFIG$memory_limits$max_memory_usage_mb) {
          cat("⚠️ Memory limit approached, stopping municipality loading\n")
          break
        }
        
        state_municipalities <- geobr::read_municipality(
          code_muni = state, 
          year = 2020, 
          showProgress = FALSE
        )
        
        if (!isTRUE(is.null(state_municipalities)) && nrow(state_municipalities) > 0) {
          
          # Process municipalities
          processed_munic <- state_municipalities %>%
            sf::st_transform(crs = 4674) %>%
            sf::st_simplify(preserveTopology = TRUE, dTolerance = 0.02) %>%  # More aggressive simplification
            mutate(
              municipality_code = code_muni,
              municipality_name = name_muni,
              municipality_name_clean = toupper(trimws(name_muni)),
              state_code = abbrev_state,
              state_name = name_state,
              area_km2 = as.numeric(sf::st_area(geometry)) / 1000000,
              
              # Processing metadata
              data_source = "IBGE via geobr",
              coordinate_system = "SIRGAS 2000 (EPSG:4674)",
              processing_date = Sys.Date()
            ) %>%
            select(
              municipality_code, municipality_name, municipality_name_clean,
              state_code, state_name, area_km2, data_source, 
              coordinate_system, processing_date, geometry
            )
          
          # Quality validation
          validated_munic <- validate_spatial_data(processed_munic, level = "municipality")
          
          if (!is.null(validated_munic)) {
            all_municipalities[[state]] <- validated_munic
            
            # Cache individual state municipalities
            set_spatial_cache(cache_key, validated_munic, expiry_hours = 24)
            
            cat("✅ Processed", nrow(validated_munic), "municipalities for", state, "\n")
          }
          
          # Memory cleanup
          rm(state_municipalities, processed_munic)
          gc(verbose = FALSE)
        }
      }
    }
    
    # Combine all municipalities if any were loaded
    if (length(all_municipalities) > 0) {
      combined_municipalities <- bind_rows(all_municipalities)
      
      cat("✅ Combined", nrow(combined_municipalities), "municipalities from", length(all_municipalities), "states\n")
      return(combined_municipalities)
    }
    
    return(NULL)
    
  }, error = function(e) {
    cat("❌ Error loading municipalities:", e$message, "\n")
    return(NULL)
  })
}

# Geographic Reference System Functions
# ====================================

#' Link Legislative Documents to Geographic Entities
#' 
#' Creates geographic references between legislative documents and administrative boundaries
#' 
#' @param db_pool Database connection pool
#' @param states_data SF object with state boundaries
#' @param municipalities_data SF object with municipality boundaries (optional)
#' @return Summary of geographic linking results
link_documents_to_geography <- function(db_pool, states_data = NULL, municipalities_data = NULL) {
  
  cat("🔗 Linking documents to geographic entities...\n")
  
  tryCatch({
    
    if (is.null(db_pool)) {
      stop("Database connection required for document linking")
    }
    
    linking_results <- list(
      states_linked = 0,
      municipalities_linked = 0,
      documents_processed = 0,
      errors = c(),
      timestamp = Sys.time()
    )
    
    # Get sample of documents with geographic information
    documents_sample <- pool::poolWithTransaction(db_pool, function(conn) {
      
      query <- "
        SELECT id, titulo, estado, municipio, data_documento
        FROM documents 
        WHERE (estado IS NOT NULL AND estado != '') 
           OR (municipio IS NOT NULL AND municipio != '')
        ORDER BY data_documento DESC
        LIMIT 1000;  -- Sample for testing
      "
      
      DBI::dbGetQuery(conn, query)
    })

    if (isTRUE(is.null(documents_sample)) || !is.data.frame(documents_sample) || nrow(documents_sample) == 0) {
      cat("⚠️ No documents with geographic information found\n")
      return(linking_results)
    }
    
    cat("📊 Processing", nrow(documents_sample), "documents with geographic data\n")
    linking_results$documents_processed <- nrow(documents_sample)
    
    # State-level linking
    if (!is.null(states_data)) {
      
      cat("🏛️ Linking documents to states...\n")
      
      # Create state lookup
      state_lookup <- states_data %>%
        sf::st_drop_geometry() %>%
        select(state_code, state_name, state_name_clean, ibge_code) %>%
        distinct()
      
      # Match documents to states
      state_matches <- documents_sample %>%
        filter(!is.na(estado) & estado != "") %>%
        mutate(estado_clean = toupper(trimws(estado))) %>%
        left_join(
          state_lookup, 
          by = c("estado_clean" = "state_name_clean")
        ) %>%
        filter(!is.na(state_code))
      
      linking_results$states_linked <- nrow(state_matches)
      cat("✅ Linked", linking_results$states_linked, "documents to states\n")
    }
    
    # Municipality-level linking (if available)
    if (!is.null(municipalities_data)) {
      
      cat("🏙️ Linking documents to municipalities...\n")
      
      # Create municipality lookup
      municipality_lookup <- municipalities_data %>%
        sf::st_drop_geometry() %>%
        select(municipality_code, municipality_name, municipality_name_clean, state_code) %>%
        distinct()
      
      # Match documents to municipalities
      municipality_matches <- documents_sample %>%
        filter(!is.na(municipio) & municipio != "") %>%
        mutate(
          municipio_clean = toupper(trimws(municipio)),
          estado_clean = toupper(trimws(estado))
        ) %>%
        left_join(
          municipality_lookup, 
          by = c("municipio_clean" = "municipality_name_clean")
        ) %>%
        filter(!is.na(municipality_code))
      
      linking_results$municipalities_linked <- nrow(municipality_matches)
      cat("✅ Linked", linking_results$municipalities_linked, "documents to municipalities\n")
    }
    
    return(linking_results)
    
  }, error = function(e) {
    cat("❌ Error linking documents to geography:", e$message, "\n")
    linking_results$errors <- c(linking_results$errors, e$message)
    return(linking_results)
  })
}

# Supporting Functions
# ===================

#' Validate Spatial Database Capabilities
#' 
#' Checks if the database has required spatial extensions
#' 
#' @param db_pool Database connection pool
#' @return List with validation results
validate_spatial_database <- function(db_pool) {
  
  tryCatch({
    
    spatial_status <- pool::poolWithTransaction(db_pool, function(conn) {
      
      # Check for PostGIS extension
      postgis_check <- DBI::dbGetQuery(conn, 
        "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'postgis') as has_postgis;"
      )
      
      # Check for spatial tables
      spatial_tables <- DBI::dbGetQuery(conn, 
        "SELECT table_name FROM information_schema.tables 
         WHERE table_name IN ('spatial_ref_sys', 'geography_columns', 'geometry_columns');"
      )
      
      list(
        has_postgis = postgis_check$has_postgis[1],
        spatial_tables = nrow(spatial_tables),
        capabilities = c("basic_spatial", "geometry_processing")
      )
    })
    
    return(list(
      valid = spatial_status$has_postgis && spatial_status$spatial_tables >= 1,
      details = spatial_status,
      timestamp = Sys.time()
    ))
    
  }, error = function(e) {
    return(list(
      valid = FALSE,
      error = e$message,
      timestamp = Sys.time()
    ))
  })
}

#' Setup Spatial Data Cache
#' 
#' Initializes caching system for spatial data
#' 
#' @return Cache configuration status
setup_spatial_cache <- function() {
  
  cache_dir <- "cache/spatial"
  
  if (!dir.exists(cache_dir)) {
    dir.create(cache_dir, recursive = TRUE, showWarnings = FALSE)
  }
  
  return(list(
    enabled = dir.exists(cache_dir),
    path = cache_dir,
    timestamp = Sys.time()
  ))
}

#' Memory Management Setup
#' 
#' Configures memory management for Railway constraints
#' 
#' @return Memory management configuration
setup_memory_management <- function() {
  
  # Get current memory usage
  current_memory <- sum(gc(verbose = FALSE)[, "(Mb)"])
  
  return(list(
    current_usage_mb = round(current_memory, 2),
    limit_mb = IBGE_CONFIG$memory_limits$max_memory_usage_mb,
    chunk_size = IBGE_CONFIG$memory_limits$max_features_per_chunk,
    gc_enabled = TRUE,
    timestamp = Sys.time()
  ))
}

#' Get Spatial Cache
#' 
#' Retrieves cached spatial data if available
#' 
#' @param cache_key Unique identifier for cached data
#' @param ignore_expiry Ignore cache expiry (default: FALSE)
#' @return Cached spatial data or NULL
get_spatial_cache <- function(cache_key, ignore_expiry = FALSE) {
  
  tryCatch({
    
    cache_file <- file.path("cache/spatial", paste0(cache_key, ".rds"))
    
    if (!file.exists(cache_file)) {
      return(NULL)
    }
    
    # Check file age
    file_age_hours <- as.numeric(difftime(Sys.time(), file.info(cache_file)$mtime, units = "hours"))
    
    if (!ignore_expiry && file_age_hours > IBGE_CONFIG$memory_limits$cache_expiry_hours) {
      return(NULL)
    }
    
    readRDS(cache_file)
    
  }, error = function(e) {
    return(NULL)
  })
}

#' Set Spatial Cache
#' 
#' Stores spatial data in cache
#' 
#' @param cache_key Unique identifier for cached data
#' @param data Spatial data to cache
#' @param expiry_hours Cache expiry in hours
#' @return Cache operation success status
set_spatial_cache <- function(cache_key, data, expiry_hours = 24) {
  
  tryCatch({
    
    cache_dir <- "cache/spatial"
    if (!dir.exists(cache_dir)) {
      dir.create(cache_dir, recursive = TRUE, showWarnings = FALSE)
    }
    
    cache_file <- file.path(cache_dir, paste0(cache_key, ".rds"))
    saveRDS(data, cache_file)
    
    return(TRUE)
    
  }, error = function(e) {
    return(FALSE)
  })
}

#' Validate Spatial Data
#' 
#' Performs quality checks on spatial data
#' 
#' @param spatial_data SF object to validate
#' @param level Administrative level for validation
#' @param expected_count Expected number of features (optional)
#' @return Validated spatial data or NULL if invalid
validate_spatial_data <- function(spatial_data, level = "unknown", expected_count = NULL) {
  
  tryCatch({
    
    if (isTRUE(is.null(spatial_data)) || nrow(spatial_data) == 0) {
      return(NULL)
    }
    
    # Basic geometric validation
    valid_geometries <- sf::st_is_valid(spatial_data)
    empty_geometries <- sf::st_is_empty(spatial_data)
    
    # Filter out invalid geometries
    clean_data <- spatial_data[valid_geometries & !empty_geometries, ]

    if (isTRUE(is.null(clean_data)) || !is.data.frame(clean_data) || nrow(clean_data) == 0) {
      return(NULL)
    }

    # Check expected count
    if (!is.null(expected_count)) {
      if (!isTRUE(is.null(clean_data)) && is.data.frame(clean_data) && nrow(clean_data) < expected_count * 0.8) {  # Allow 20% tolerance
        warning(paste("Expected", expected_count, "features, found", nrow(clean_data)))
      }
    }
    
    # Add validation metadata
    clean_data$geometry_valid <- TRUE
    clean_data$validation_date <- Sys.Date()
    clean_data$validation_level <- level
    
    return(clean_data)
    
  }, error = function(e) {
    warning("Spatial data validation failed: ", e$message)
    return(spatial_data)  # Return original data if validation fails
  })
}

#' Create Fallback State Boundaries
#' 
#' Creates simplified state boundaries when IBGE data is unavailable
#' 
#' @return Basic state boundary data
create_fallback_states <- function() {
  
  tryCatch({
    
    # Create basic state information without geometry (for emergency fallback)
    fallback_states <- data.frame(
      state_code = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                     "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                     "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
      
      state_name = c("Acre", "Alagoas", "Amapá", "Amazonas", "Bahia", "Ceará", "Distrito Federal",
                     "Espírito Santo", "Goiás", "Maranhão", "Mato Grosso", "Mato Grosso do Sul", 
                     "Minas Gerais", "Pará", "Paraíba", "Paraná", "Pernambuco", "Piauí", 
                     "Rio de Janeiro", "Rio Grande do Norte", "Rio Grande do Sul", "Rondônia", 
                     "Roraima", "Santa Catarina", "São Paulo", "Sergipe", "Tocantins"),
      
      region_name = c("Norte", "Nordeste", "Norte", "Norte", "Nordeste", "Nordeste", "Centro-Oeste",
                      "Sudeste", "Centro-Oeste", "Nordeste", "Centro-Oeste", "Centro-Oeste", 
                      "Sudeste", "Norte", "Nordeste", "Sul", "Nordeste", "Nordeste", 
                      "Sudeste", "Nordeste", "Sul", "Norte", "Norte", "Sul", "Sudeste", "Nordeste", "Norte"),
      
      data_source = "Fallback data",
      coordinate_system = "SIRGAS 2000 (EPSG:4674)",
      reference_year = 2020,
      
      stringsAsFactors = FALSE
    )
    
    # Add state name clean for matching
    fallback_states$state_name_clean <- toupper(trimws(fallback_states$state_name))
    
    return(fallback_states)
    
  }, error = function(e) {
    return(NULL)
  })
}

# Export main functions
list(
  initialize_ibge_system = initialize_ibge_system,
  load_ibge_states = load_ibge_states,
  load_ibge_municipalities = load_ibge_municipalities,
  link_documents_to_geography = link_documents_to_geography,
  IBGE_CONFIG = IBGE_CONFIG
)