# IBGE Data Integration Pipeline
# Monitor Legislativo v4 - Brazilian Geographic Data Integration
# ================================================================

#' IBGE Data Integration for Monitor Legislativo v4
#' 
#' Comprehensive integration with IBGE APIs for Brazilian geographic data including
#' municipal boundaries, demographic data, and administrative divisions.
#' Optimized for Railway deployment with 2GB memory constraints.

library(httr)
library(jsonlite)
library(sf)
library(dplyr)
library(memoise)
library(cachem)

# Configuration
IBGE_BASE_URL <- "https://servicodados.ibge.gov.br/api/v1"
CACHE_DURATION <- 24 * 60 * 60  # 24 hours in seconds
MAX_RETRIES <- 3
RETRY_DELAY <- 2  # seconds

# Initialize cache with memory limit for Railway
cache <- cachem::cache_mem(max_size = 100 * 1024 * 1024)  # 100MB cache

#' Fetch Brazilian States Data from IBGE API
#' 
#' Retrieves complete list of Brazilian states with codes and regions
#' 
#' @return data.frame with state information
#' @export
fetch_ibge_states <- memoise(function() {
  cat("🌐 Fetching Brazilian states from IBGE API...\n")
  
  tryCatch({
    url <- paste0(IBGE_BASE_URL, "/localidades/estados")
    
    response <- httr::GET(
      url,
      httr::timeout(30),
      httr::user_agent("Monitor Legislativo v4 - Academic Research")
    )
    
    if (httr::status_code(response) != 200) {
      warning("IBGE API request failed with status: ", httr::status_code(response))
      return(get_fallback_states())
    }
    
    content <- httr::content(response, as = "text", encoding = "UTF-8")
    states_data <- jsonlite::fromJSON(content, flatten = TRUE)
    
    # Process and standardize state data
    states_clean <- states_data %>%
      select(
        state_id = id,
        state_name = nome,
        state_abbr = sigla,
        region_id = regiao.id,
        region_name = regiao.nome,
        region_abbr = regiao.sigla
      ) %>%
      mutate(
        state_abbr = toupper(state_abbr),
        region_name = case_when(
          region_abbr == "N" ~ "Norte",
          region_abbr == "NE" ~ "Nordeste",
          region_abbr == "CO" ~ "Centro-Oeste",
          region_abbr == "SE" ~ "Sudeste",
          region_abbr == "S" ~ "Sul",
          TRUE ~ region_name
        )
      ) %>%
      arrange(state_name)
    
    cat("✅ Successfully fetched", nrow(states_clean), "Brazilian states\n")
    return(states_clean)
    
  }, error = function(e) {
    warning("Error fetching IBGE states data: ", e$message)
    return(get_fallback_states())
  })
}, cache = cache)

#' Fetch Brazilian Municipalities Data from IBGE API
#' 
#' Retrieves municipalities for specified states with geographic coordinates
#' 
#' @param state_codes Character vector of state codes (UF)
#' @param limit Integer maximum number of municipalities to fetch (Railway memory limit)
#' @return data.frame with municipality information
#' @export
fetch_ibge_municipalities <- function(state_codes = NULL, limit = 1000) {
  cat("🏛️ Fetching Brazilian municipalities from IBGE API...\n")
  
  tryCatch({
    # Use all states if none specified
    if (is.null(state_codes)) {
      states_data <- fetch_ibge_states()
      state_codes <- states_data$state_id
    }
    
    municipalities <- data.frame()
    
    for (state_id in state_codes) {
      if (nrow(municipalities) >= limit) {
        cat("⚠️ Reached municipality limit of", limit, "for Railway constraints\n")
        break
      }
      
      cat("📍 Fetching municipalities for state ID:", state_id, "\n")
      
      url <- paste0(IBGE_BASE_URL, "/localidades/estados/", state_id, "/municipios")
      
      response <- httr::GET(
        url,
        httr::timeout(30),
        httr::user_agent("Monitor Legislativo v4 - Academic Research")
      )
      
      if (httr::status_code(response) == 200) {
        content <- httr::content(response, as = "text", encoding = "UTF-8")
        muni_data <- jsonlite::fromJSON(content, flatten = TRUE)
        
        if (nrow(muni_data) > 0) {
          muni_processed <- muni_data %>%
            select(
              municipality_id = id,
              municipality_name = nome,
              state_id = microrregiao.mesorregiao.UF.id,
              state_abbr = microrregiao.mesorregiao.UF.sigla,
              state_name = microrregiao.mesorregiao.UF.nome,
              microregion_id = microrregiao.id,
              microregion_name = microrregiao.nome,
              mesoregion_id = microrregiao.mesorregiao.id,
              mesoregion_name = microrregiao.mesorregiao.nome
            ) %>%
            mutate(
              state_abbr = toupper(state_abbr)
            )
          
          municipalities <- bind_rows(municipalities, muni_processed)
        }
      }
      
      # Rate limiting to respect IBGE API
      Sys.sleep(0.5)
    }
    
    cat("✅ Successfully fetched", nrow(municipalities), "Brazilian municipalities\n")
    return(municipalities)
    
  }, error = function(e) {
    warning("Error fetching IBGE municipalities data: ", e$message)
    return(get_fallback_municipalities())
  })
}

#' Fetch Municipal Boundaries from IBGE
#' 
#' Retrieves simplified geometries for Brazilian municipalities
#' 
#' @param municipality_ids Character vector of municipality IBGE codes
#' @param simplify Logical whether to simplify geometries for performance
#' @return sf object with municipal boundaries
#' @export
fetch_municipal_boundaries <- memoise(function(municipality_ids = NULL, simplify = TRUE) {
  cat("🗺️ Fetching municipal boundaries from IBGE...\n")
  
  tryCatch({
    # For Railway constraints, use simplified national boundaries
    url <- paste0(IBGE_BASE_URL, "/localidades/estados/geojson")
    
    response <- httr::GET(
      url,
      httr::timeout(60),
      httr::user_agent("Monitor Legislativo v4 - Academic Research")
    )
    
    if (httr::status_code(response) != 200) {
      warning("IBGE boundaries request failed with status: ", httr::status_code(response))
      return(get_fallback_boundaries())
    }
    
    content <- httr::content(response, as = "text", encoding = "UTF-8")
    boundaries_sf <- sf::st_read(content, quiet = TRUE)
    
    if (simplify && nrow(boundaries_sf) > 0) {
      # Simplify geometries for Railway performance
      boundaries_sf <- sf::st_simplify(boundaries_sf, dTolerance = 0.01)
    }
    
    # Transform to WGS84 for web mapping
    if (sf::st_crs(boundaries_sf)$input != "EPSG:4326") {
      boundaries_sf <- sf::st_transform(boundaries_sf, 4326)
    }
    
    cat("✅ Successfully loaded", nrow(boundaries_sf), "boundary geometries\n")
    return(boundaries_sf)
    
  }, error = function(e) {
    warning("Error fetching IBGE boundaries: ", e$message)
    return(get_fallback_boundaries())
  })
}, cache = cache)

#' Fetch State Boundaries GeoJSON
#' 
#' Retrieves state-level boundaries for choropleth mapping
#' 
#' @return sf object with state boundaries
#' @export
fetch_state_boundaries <- memoise(function() {
  cat("🏛️ Fetching Brazilian state boundaries...\n")
  
  tryCatch({
    # Try IBGE API first
    url <- "https://servicodados.ibge.gov.br/api/v3/malhas/paises/BR?formato=application/vnd.geo+json&qualidade=minima&intrarregiao=uf"
    
    response <- httr::GET(
      url,
      httr::timeout(60),
      httr::user_agent("Monitor Legislativo v4 - Academic Research")
    )
    
    if (httr::status_code(response) == 200) {
      content <- httr::content(response, as = "text", encoding = "UTF-8")
      state_boundaries <- sf::st_read(content, quiet = TRUE)
      
      # Simplify for Railway performance
      state_boundaries <- sf::st_simplify(state_boundaries, dTolerance = 0.01)
      
      # Transform to WGS84
      if (!sf::st_is_longlat(state_boundaries)) {
        state_boundaries <- sf::st_transform(state_boundaries, 4326)
      }
      
      cat("✅ Successfully loaded", nrow(state_boundaries), "state boundaries\n")
      return(state_boundaries)
    }
    
    # Fallback to alternative source
    return(get_fallback_state_boundaries())
    
  }, error = function(e) {
    warning("Error fetching state boundaries: ", e$message)
    return(get_fallback_state_boundaries())
  })
}, cache = cache)

#' Map Legislation Documents to Geographic Data
#' 
#' Links legislative documents to IBGE geographic entities
#' 
#' @param documents_data data.frame with legislative documents
#' @param states_data data.frame with IBGE states data
#' @param municipalities_data data.frame with IBGE municipalities data
#' @return data.frame with enhanced geographic information
#' @export
map_legislation_geography <- function(documents_data, states_data = NULL, municipalities_data = NULL) {
  cat("🔗 Mapping legislation to IBGE geographic data...\n")
  
  tryCatch({
    if (isTRUE(is.null(documents_data)) || nrow(documents_data) == 0) {
      warning("No documents data provided")
      return(data.frame())
    }
    
    # Fetch IBGE data if not provided
    if (is.null(states_data)) {
      states_data <- fetch_ibge_states()
    }
    
    # Clean and standardize state codes in documents
    if ("estado" %in% names(documents_data)) {
      documents_enhanced <- documents_data %>%
        mutate(
          estado_clean = toupper(trimws(estado)),
          # Handle common variations
          estado_clean = case_when(
            estado_clean %in% c("SAO PAULO", "SÃO PAULO") ~ "SP",
            estado_clean %in% c("RIO DE JANEIRO") ~ "RJ",
            estado_clean %in% c("MINAS GERAIS") ~ "MG",
            nchar(estado_clean) == 2 ~ estado_clean,
            TRUE ~ estado_clean
          )
        )
    } else {
      # Try to extract state from other fields
      documents_enhanced <- documents_data %>%
        mutate(
          estado_clean = case_when(
            grepl("SP|São Paulo|SAO PAULO", localidade, ignore.case = TRUE) ~ "SP",
            grepl("RJ|Rio de Janeiro|RIO DE JANEIRO", localidade, ignore.case = TRUE) ~ "RJ",
            grepl("MG|Minas Gerais|MINAS GERAIS", localidade, ignore.case = TRUE) ~ "MG",
            TRUE ~ "BR"  # Default to federal level
          )
        )
    }
    
    # Join with IBGE states data
    enhanced_docs <- documents_enhanced %>%
      left_join(
        states_data,
        by = c("estado_clean" = "state_abbr")
      ) %>%
      mutate(
        # Add geographic analysis fields
        geographic_level = case_when(
          !is.na(state_id) ~ "state",
          grepl("federal|brasil|união", tolower(localidade)) ~ "federal",
          TRUE ~ "unknown"
        ),
        region_analysis = coalesce(region_name, "Federal/Nacional")
      )
    
    cat("✅ Successfully mapped", nrow(enhanced_docs), "documents to geographic data\n")
    return(enhanced_docs)
    
  }, error = function(e) {
    warning("Error mapping legislation geography: ", e$message)
    return(documents_data)
  })
}

#' Calculate Geographic Statistics
#' 
#' Computes statistical summaries for geographic analysis
#' 
#' @param documents_data data.frame with geographic-enhanced documents
#' @param analysis_type Character analysis type (density, distribution, temporal)
#' @return list with geographic statistics
#' @export
calculate_geographic_statistics <- function(documents_data, analysis_type = "density") {
  cat("📊 Calculating geographic statistics...\n")
  
  tryCatch({
    if (isTRUE(is.null(documents_data)) || nrow(documents_data) == 0) {
      return(list(error = "No data available"))
    }
    
    stats <- switch(analysis_type,
      "density" = {
        # Document density by state/region
        documents_data %>%
          filter(!is.na(state_abbr)) %>%
          group_by(state_abbr, state_name, region_name) %>%
          summarise(
            document_count = n(),
            unique_categories = n_distinct(categoria, na.rm = TRUE),
            date_range_start = min(data, na.rm = TRUE),
            date_range_end = max(data, na.rm = TRUE),
            .groups = "drop"
          ) %>%
          arrange(desc(document_count))
      },
      "distribution" = {
        # Document distribution analysis
        regional_stats <- documents_data %>%
          filter(!is.na(region_name)) %>%
          group_by(region_name) %>%
          summarise(
            total_documents = n(),
            states_count = n_distinct(state_abbr, na.rm = TRUE),
            categories_count = n_distinct(categoria, na.rm = TRUE),
            avg_docs_per_state = round(n() / n_distinct(state_abbr, na.rm = TRUE), 1),
            .groups = "drop"
          ) %>%
          arrange(desc(total_documents))
        
        list(
          regional = regional_stats,
          national_total = nrow(documents_data),
          coverage_stats = calculate_coverage_statistics(documents_data)
        )
      },
      "temporal" = {
        # Temporal geographic analysis
        documents_data %>%
          filter(!is.na(data) & !is.na(state_abbr)) %>%
          mutate(
            year = as.numeric(format(as.Date(data), "%Y")),
            month = as.numeric(format(as.Date(data), "%m"))
          ) %>%
          group_by(year, region_name, state_abbr) %>%
          summarise(
            document_count = n(),
            .groups = "drop"
          ) %>%
          filter(year >= 2000 & year <= 2025) %>%
          arrange(year, region_name, state_abbr)
      },
      # Default to density
      documents_data %>%
        filter(!is.na(state_abbr)) %>%
        group_by(state_abbr) %>%
        summarise(document_count = n(), .groups = "drop") %>%
        arrange(desc(document_count))
    )
    
    cat("✅ Geographic statistics calculated for", 
        ifelse(is.data.frame(stats), nrow(stats), "multiple"), "entities\n")
    
    return(stats)
    
  }, error = function(e) {
    warning("Error calculating geographic statistics: ", e$message)
    return(list(error = e$message))
  })
}

#' Calculate Coverage Statistics
#' 
#' Analyzes geographic coverage of legislative documents
#' 
#' @param documents_data data.frame with geographic data
#' @return list with coverage metrics
calculate_coverage_statistics <- function(documents_data) {
  tryCatch({
    total_states <- 27  # Including DF
    total_regions <- 5
    
    covered_states <- documents_data %>%
      filter(!is.na(state_abbr)) %>%
      distinct(state_abbr) %>%
      nrow()
    
    covered_regions <- documents_data %>%
      filter(!is.na(region_name)) %>%
      distinct(region_name) %>%
      nrow()
    
    list(
      states_covered = covered_states,
      states_total = total_states,
      states_percentage = round((covered_states / total_states) * 100, 1),
      regions_covered = covered_regions,
      regions_total = total_regions,
      regions_percentage = round((covered_regions / total_regions) * 100, 1),
      documents_with_location = sum(!is.na(documents_data$state_abbr)),
      documents_total = nrow(documents_data),
      location_coverage_pct = round(
        (sum(!is.na(documents_data$state_abbr)) / nrow(documents_data)) * 100, 1
      )
    )
  }, error = function(e) {
    list(error = e$message)
  })
}

# FALLBACK DATA FUNCTIONS
# ======================

#' Get fallback states data when IBGE API is unavailable
get_fallback_states <- function() {
  data.frame(
    state_id = c(11, 12, 13, 14, 15, 16, 17, 21, 22, 23, 24, 25, 26, 27, 28, 29, 31, 32, 33, 35, 41, 42, 43, 50, 51, 52, 53),
    state_name = c("Rondônia", "Acre", "Amazonas", "Roraima", "Pará", "Amapá", "Tocantins",
                   "Maranhão", "Piauí", "Ceará", "Rio Grande do Norte", "Paraíba", "Pernambuco", "Alagoas", "Sergipe", "Bahia",
                   "Minas Gerais", "Espírito Santo", "Rio de Janeiro", "São Paulo",
                   "Paraná", "Santa Catarina", "Rio Grande do Sul",
                   "Mato Grosso do Sul", "Mato Grosso", "Goiás", "Distrito Federal"),
    state_abbr = c("RO", "AC", "AM", "RR", "PA", "AP", "TO", "MA", "PI", "CE", "RN", "PB", "PE", "AL", "SE", "BA", "MG", "ES", "RJ", "SP", "PR", "SC", "RS", "MS", "MT", "GO", "DF"),
    region_id = c(1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 5, 5, 5, 5),
    region_name = c(rep("Norte", 7), rep("Nordeste", 9), rep("Sudeste", 4), rep("Sul", 3), rep("Centro-Oeste", 4)),
    region_abbr = c(rep("N", 7), rep("NE", 9), rep("SE", 4), rep("S", 3), rep("CO", 4)),
    stringsAsFactors = FALSE
  )
}

#' Get fallback municipalities data
get_fallback_municipalities <- function() {
  # Use existing sample data if available
  tryCatch({
    if (file.exists("legacy/data/geographic/sample_municipalities.csv")) {
      read.csv("legacy/data/geographic/sample_municipalities.csv", stringsAsFactors = FALSE)
    } else {
      data.frame(
        municipality_id = c(3550308, 3304557, 3106200),
        municipality_name = c("São Paulo", "Rio de Janeiro", "Belo Horizonte"),
        state_abbr = c("SP", "RJ", "MG"),
        state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais")
      )
    }
  }, error = function(e) {
    data.frame(
      municipality_id = c(3550308, 3304557, 3106200),
      municipality_name = c("São Paulo", "Rio de Janeiro", "Belo Horizonte"),
      state_abbr = c("SP", "RJ", "MG"),
      state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais")
    )
  })
}

#' Get fallback boundaries data
get_fallback_boundaries <- function() {
  warning("Using minimal fallback boundaries - full geographic functionality limited")
  # Return empty sf object with correct structure
  sf::st_sf(
    state_abbr = character(0),
    state_name = character(0),
    geometry = sf::st_sfc(crs = 4326)
  )
}

#' Get fallback state boundaries
get_fallback_state_boundaries <- function() {
  warning("Using minimal fallback state boundaries")
  # Create simplified Brazil outline
  brazil_outline <- matrix(c(
    -73.985, -33.752,
    -34.793, -33.752,
    -34.793, 5.272,
    -73.985, 5.272,
    -73.985, -33.752
  ), ncol = 2, byrow = TRUE)
  
  brazil_polygon <- sf::st_polygon(list(brazil_outline))
  
  sf::st_sf(
    state_abbr = "BR",
    state_name = "Brasil",
    geometry = sf::st_sfc(brazil_polygon, crs = 4326)
  )
}

# Clear cache periodically to manage memory
clear_ibge_cache <- function() {
  cache$reset()
  gc()  # Garbage collection for Railway memory management
  cat("✅ IBGE cache cleared\n")
}

# Auto-cleanup for Railway deployment
reg.finalizer(globalenv(), function(e) {
  tryCatch(clear_ibge_cache(), error = function(err) {})
}, onexit = TRUE)

cat("✅ IBGE integration pipeline loaded successfully\n")