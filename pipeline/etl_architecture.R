# ============================================================================
# BRAZILIAN LEGISLATIVE DATA ETL PIPELINE ARCHITECTURE - SPRINT 4B
# ============================================================================
#
# Comprehensive ETL system for Brazilian legislative monitoring
# Integrates LexML, IBGE, and other government data sources
# Optimized for Railway deployment with 2GB memory constraints
#
# Features:
# - LexML (Brazilian Legislative XML) integration
# - IBGE geographic and demographic data
# - Incremental data loading and synchronization
# - Memory-efficient processing for Railway constraints
# - Robust error handling and recovery
# - Data validation and quality assurance
# - Automated scheduling and monitoring
# 
# Author: Legislative Data Science Team
# Version: 4B.1.0 (Sprint 4B)
# Updated: 2025-01-20
# ============================================================================

# Load required packages with graceful error handling
required_packages <- c(
  "DBI", "RPostgres", "pool",           # Database
  "httr", "jsonlite", "xml2",           # API and data parsing
  "dplyr", "data.table", "lubridate",   # Data manipulation
  "stringr", "stringi",                 # Text processing
  "digest", "logger",                   # Utilities and logging
  "memuse", "pryr"                      # Memory monitoring
)

missing_packages <- c()
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ WARNING: Missing ETL packages:", paste(missing_packages, collapse = ", "), "\n")
  cat("🔧 Install with: install.packages(c(", paste0("'", missing_packages, "'", collapse = ", "), "))\n")
}

# Load available packages
suppressPackageStartupMessages({
  if (requireNamespace("dplyr", quietly = TRUE)) library(dplyr)
  if (requireNamespace("data.table", quietly = TRUE)) library(data.table)
  if (requireNamespace("httr", quietly = TRUE)) library(httr)
  if (requireNamespace("jsonlite", quietly = TRUE)) library(jsonlite)
  if (requireNamespace("xml2", quietly = TRUE)) library(xml2)
  if (requireNamespace("stringr", quietly = TRUE)) library(stringr)
  if (requireNamespace("lubridate", quietly = TRUE)) library(lubridate)
  if (requireNamespace("digest", quietly = TRUE)) library(digest)
  if (requireNamespace("memuse", quietly = TRUE)) library(memuse)
})

# ============================================================================
# ETL PIPELINE CONFIGURATION
# ============================================================================

ETL_CONFIG <- list(
  # Data Sources Configuration
  sources = list(
    lexml = list(
      base_url = "https://www.lexml.gov.br/busca",
      api_endpoint = "/api/v2/consulta",
      rate_limit = 60,  # requests per minute
      timeout = 30,     # seconds
      formats = c("xml", "json"),
      standards = "LexML-br"
    ),
    
    ibge = list(
      base_url = "https://servicodados.ibge.gov.br",
      api_municipalities = "/api/v1/localidades/municipios",
      api_states = "/api/v1/localidades/estados",
      api_regions = "/api/v1/localidades/regioes",
      rate_limit = 120, # requests per minute
      timeout = 20      # seconds
    ),
    
    transparency_portal = list(
      base_url = "https://portaldatransparencia.gov.br/api-de-dados",
      rate_limit = 30,
      timeout = 45
    )
  ),
  
  # Processing Configuration
  processing = list(
    batch_size = 1000,        # Records per batch (Railway memory optimization)
    max_memory_usage = 1.5,   # GB memory limit
    chunk_size = 500,         # XML/JSON parsing chunk size
    parallel_workers = 2,     # Number of parallel processes
    temp_dir = "pipeline/temp",
    cache_dir = "pipeline/cache",
    log_dir = "pipeline/logs"
  ),
  
  # Quality Assurance
  quality = list(
    min_title_length = 10,
    max_title_length = 500,
    required_fields = c("titulo", "tipo", "data", "autoridade"),
    duplicate_threshold = 0.95,  # Similarity threshold
    data_freshness_days = 30
  ),
  
  # Error Handling
  error_handling = list(
    max_retries = 3,
    backoff_factor = 2,       # Exponential backoff
    circuit_breaker_threshold = 5,
    recovery_timeout = 300,   # 5 minutes
    alert_threshold = 10      # Failed operations before alert
  )
)

# ============================================================================
# ETL PIPELINE LOGGING SYSTEM
# ============================================================================

setup_etl_logging <- function() {
  # Create log directories
  dirs <- c(ETL_CONFIG$processing$log_dir, 
            ETL_CONFIG$processing$temp_dir,
            ETL_CONFIG$processing$cache_dir)
  
  for (dir in dirs) {
    if (!dir.exists(dir)) {
      dir.create(dir, recursive = TRUE, showWarnings = FALSE)
    }
  }
  
  # Initialize logging system
  if (requireNamespace("logger", quietly = TRUE)) {
    logger::log_appender(logger::appender_file(
      file.path(ETL_CONFIG$processing$log_dir, "etl_pipeline.log"),
      max_lines = 10000,
      max_files = 5
    ))
    logger::log_threshold(logger::DEBUG)
  }
  
  cat("📋 ETL logging system initialized\n")
}

# Custom logging function
log_etl <- function(level, message, component = "ETL", details = NULL) {
  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  log_entry <- sprintf("[%s] [%s] %s: %s", timestamp, level, component, message)
  
  if (!is.null(details)) {
    log_entry <- paste0(log_entry, " | Details: ", jsonlite::toJSON(details, auto_unbox = TRUE))
  }
  
  cat(log_entry, "\n")
  
  # Write to file if logger is available
  if (requireNamespace("logger", quietly = TRUE)) {
    switch(level,
      "ERROR" = logger::log_error(log_entry),
      "WARN" = logger::log_warn(log_entry),
      "INFO" = logger::log_info(log_entry),
      "DEBUG" = logger::log_debug(log_entry),
      logger::log_info(log_entry)
    )
  }
}

# ============================================================================
# MEMORY MANAGEMENT FOR RAILWAY CONSTRAINTS
# ============================================================================

# Memory monitoring class
MemoryMonitor <- R6::R6Class("MemoryMonitor",
  public = list(
    max_memory_gb = NULL,
    current_usage = NULL,
    alerts_sent = 0,
    
    initialize = function(max_memory_gb = 1.5) {
      self$max_memory_gb <- max_memory_gb
      log_etl("INFO", sprintf("Memory monitor initialized with %s GB limit", max_memory_gb), "MEMORY")
    },
    
    check_memory = function() {
      if (requireNamespace("memuse", quietly = TRUE)) {
        current_mb <- as.numeric(memuse::Sys.meminfo()$totalram) / (1024^2)
        self$current_usage <- current_mb / 1024  # Convert to GB
      } else {
        # Fallback using gc()
        mem_info <- gc()
        self$current_usage <- sum(mem_info[, "used"]) * 8 / (1024^3)  # Estimate in GB
      }
      
      if (self$current_usage > self$max_memory_gb * 0.8) {  # 80% threshold
        self$handle_high_memory()
      }
      
      return(self$current_usage)
    },
    
    handle_high_memory = function() {
      log_etl("WARN", sprintf("High memory usage detected: %.2f GB / %.2f GB", 
                             self$current_usage, self$max_memory_gb), "MEMORY")
      
      # Trigger garbage collection
      gc(verbose = FALSE)
      
      # Clear temporary objects
      self$clear_temp_objects()
      
      self$alerts_sent <- self$alerts_sent + 1
      
      if (self$alerts_sent > 5) {
        log_etl("ERROR", "Critical memory usage - ETL pipeline may need restart", "MEMORY")
      }
    },
    
    clear_temp_objects = function() {
      # Remove large temporary objects from global environment
      temp_objects <- ls(envir = .GlobalEnv)
      for (obj_name in temp_objects) {
        if (grepl("^temp_|^tmp_|^cache_", obj_name)) {
          rm(list = obj_name, envir = .GlobalEnv)
        }
      }
    }
  )
)

# Global memory monitor instance
memory_monitor <- MemoryMonitor$new(ETL_CONFIG$processing$max_memory_usage)

# ============================================================================
# API RATE LIMITING AND ERROR HANDLING
# ============================================================================

# Rate limiter class
RateLimiter <- R6::R6Class("RateLimiter",
  public = list(
    requests_per_minute = NULL,
    request_times = NULL,
    
    initialize = function(requests_per_minute = 60) {
      self$requests_per_minute <- requests_per_minute
      self$request_times <- c()
    },
    
    can_make_request = function() {
      current_time <- Sys.time()
      
      # Remove requests older than 1 minute
      self$request_times <- self$request_times[self$request_times > (current_time - 60)]
      
      return(length(self$request_times) < self$requests_per_minute)
    },
    
    record_request = function() {
      self$request_times <- c(self$request_times, Sys.time())
    },
    
    wait_if_needed = function() {
      while (!self$can_make_request()) {
        sleep_time <- 60 / self$requests_per_minute
        log_etl("DEBUG", sprintf("Rate limit hit, waiting %.1f seconds", sleep_time), "RATE_LIMITER")
        Sys.sleep(sleep_time)
      }
    }
  )
)

# Circuit breaker for API failures
CircuitBreaker <- R6::R6Class("CircuitBreaker",
  public = list(
    failure_threshold = NULL,
    recovery_timeout = NULL,
    failure_count = 0,
    last_failure_time = NULL,
    state = "CLOSED",  # CLOSED, OPEN, HALF_OPEN
    
    initialize = function(failure_threshold = 5, recovery_timeout = 300) {
      self$failure_threshold <- failure_threshold
      self$recovery_timeout <- recovery_timeout
    },
    
    can_execute = function() {
      if (self$state == "CLOSED") {
        return(TRUE)
      }
      
      if (self$state == "OPEN") {
        if (Sys.time() - self$last_failure_time > self$recovery_timeout) {
          self$state <- "HALF_OPEN"
          log_etl("INFO", "Circuit breaker moving to HALF_OPEN state", "CIRCUIT_BREAKER")
          return(TRUE)
        }
        return(FALSE)
      }
      
      if (self$state == "HALF_OPEN") {
        return(TRUE)
      }
      
      return(FALSE)
    },
    
    record_success = function() {
      if (self$state == "HALF_OPEN") {
        self$state <- "CLOSED"
        self$failure_count <- 0
        log_etl("INFO", "Circuit breaker reset to CLOSED state", "CIRCUIT_BREAKER")
      }
    },
    
    record_failure = function() {
      self$failure_count <- self$failure_count + 1
      self$last_failure_time <- Sys.time()
      
      if (self$failure_count >= self$failure_threshold) {
        self$state <- "OPEN"
        log_etl("ERROR", sprintf("Circuit breaker OPEN after %d failures", self$failure_count), "CIRCUIT_BREAKER")
      }
    }
  )
)

# ============================================================================
# LEXML DATA SOURCE INTEGRATION
# ============================================================================

LexMLExtractor <- R6::R6Class("LexMLExtractor",
  public = list(
    rate_limiter = NULL,
    circuit_breaker = NULL,
    cache = list(),
    
    initialize = function() {
      self$rate_limiter <- RateLimiter$new(ETL_CONFIG$sources$lexml$rate_limit)
      self$circuit_breaker <- CircuitBreaker$new()
      log_etl("INFO", "LexML extractor initialized", "LEXML")
    },
    
    extract_documents = function(query_params = list(), limit = 1000) {
      if (!self$circuit_breaker$can_execute()) {
        log_etl("ERROR", "LexML circuit breaker is OPEN", "LEXML")
        return(NULL)
      }
      
      tryCatch({
        results <- list()
        offset <- 0
        batch_size <- min(ETL_CONFIG$processing$batch_size, limit)
        
        while (length(results) < limit && offset < 10000) {  # Safety limit
          # Check memory before processing
          memory_monitor$check_memory()
          
          # Rate limiting
          self$rate_limiter$wait_if_needed()
          self$rate_limiter$record_request()
          
          # Build API request
          url <- paste0(ETL_CONFIG$sources$lexml$base_url, 
                       ETL_CONFIG$sources$lexml$api_endpoint)
          
          params <- modifyList(list(
            formato = "json",
            limite = batch_size,
            inicio = offset
          ), query_params)
          
          log_etl("DEBUG", sprintf("LexML API request: offset=%d, limit=%d", offset, batch_size), "LEXML")
          
          # Make API request
          response <- httr::GET(
            url = url,
            query = params,
            httr::timeout(ETL_CONFIG$sources$lexml$timeout),
            httr::add_headers(
              "User-Agent" = "Brazilian-Legislative-Monitor/4.0",
              "Accept" = "application/json"
            )
          )
          
          if (httr::status_code(response) == 200) {
            batch_data <- self$parse_lexml_response(response)
            if (!is.null(batch_data) && nrow(batch_data) > 0) {
              results <- append(results, list(batch_data))
              offset <- offset + batch_size
              self$circuit_breaker$record_success()
            } else {
              break  # No more data
            }
          } else {
            log_etl("ERROR", sprintf("LexML API error: %d", httr::status_code(response)), "LEXML")
            self$circuit_breaker$record_failure()
            break
          }
          
          # Prevent overwhelming the API
          Sys.sleep(1)
        }
        
        # Combine all batches
        if (length(results) > 0) {
          combined_results <- do.call(rbind, results)
          log_etl("INFO", sprintf("LexML extraction complete: %d documents", nrow(combined_results)), "LEXML")
          return(combined_results)
        }
        
        return(NULL)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("LexML extraction failed: %s", e$message), "LEXML")
        self$circuit_breaker$record_failure()
        return(NULL)
      })
    },
    
    parse_lexml_response = function(response) {
      tryCatch({
        content <- httr::content(response, "text", encoding = "UTF-8")
        json_data <- jsonlite::fromJSON(content, flatten = TRUE)
        
        # Extract document metadata from LexML format
        if ("documentos" %in% names(json_data)) {
          docs <- json_data$documentos
          
          # Standardize column names for Brazilian legislative data
          standardized <- data.frame(
            titulo = self$clean_text(docs$titulo %||% ""),
            tipo = self$clean_text(docs$tipo %||% ""),
            data = self$parse_date(docs$data %||% docs$dataPublicacao),
            autoridade = self$clean_text(docs$autoridade %||% docs$orgao),
            estado = self$extract_state(docs$localidade %||% ""),
            municipio = self$extract_municipality(docs$localidade %||% ""),
            ementa = self$clean_text(docs$ementa %||% ""),
            url = docs$url %||% "",
            urn = docs$urn %||% "",
            assuntos = paste(docs$assuntos, collapse = "; "),
            categoria = self$categorize_document(docs$tipo),
            fonte = "LexML",
            data_extracao = Sys.time(),
            stringsAsFactors = FALSE
          )
          
          return(standardized)
        }
        
        return(NULL)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("LexML response parsing failed: %s", e$message), "LEXML")
        return(NULL)
      })
    },
    
    clean_text = function(text) {
      if (is.null(text) || is.na(text) || text == "") return("")
      
      # Remove extra whitespace and normalize encoding
      text <- stringr::str_trim(stringr::str_squish(as.character(text)))
      
      # Handle Brazilian Portuguese characters
      if (requireNamespace("stringi", quietly = TRUE)) {
        text <- stringi::stri_trans_general(text, "Latin-ASCII//IGNORE")
      }
      
      return(text)
    },
    
    parse_date = function(date_string) {
      if (is.null(date_string) || is.na(date_string) || date_string == "") {
        return(NA)
      }
      
      # Try multiple Brazilian date formats
      date_formats <- c(
        "%d/%m/%Y",     # 31/12/2023
        "%Y-%m-%d",     # 2023-12-31
        "%d-%m-%Y",     # 31-12-2023
        "%d.%m.%Y"      # 31.12.2023
      )
      
      for (fmt in date_formats) {
        result <- tryCatch({
          as.Date(date_string, format = fmt)
        }, error = function(e) NA)
        
        if (!is.na(result)) return(result)
      }
      
      return(NA)
    },
    
    extract_state = function(localidade) {
      if (is.null(localidade) || is.na(localidade)) return("")
      
      # Brazilian state patterns
      state_patterns <- c(
        "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas",
        "BA" = "Bahia", "CE" = "Ceará", "DF" = "Distrito Federal", "ES" = "Espírito Santo",
        "GO" = "Goiás", "MA" = "Maranhão", "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul",
        "MG" = "Minas Gerais", "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná",
        "PE" = "Pernambuco", "PI" = "Piauí", "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte",
        "RS" = "Rio Grande do Sul", "RO" = "Rondônia", "RR" = "Roraima", "SC" = "Santa Catarina",
        "SP" = "São Paulo", "SE" = "Sergipe", "TO" = "Tocantins"
      )
      
      localidade_upper <- toupper(localidade)
      
      # Check for state abbreviations
      for (abbr in names(state_patterns)) {
        if (grepl(abbr, localidade_upper)) return(abbr)
      }
      
      # Check for full state names
      for (abbr in names(state_patterns)) {
        if (grepl(toupper(state_patterns[[abbr]]), localidade_upper)) return(abbr)
      }
      
      return("")
    },
    
    extract_municipality = function(localidade) {
      if (is.null(localidade) || is.na(localidade)) return("")
      
      # Extract municipality name (usually comes before state)
      parts <- strsplit(localidade, "[,-/]")[[1]]
      if (length(parts) > 1) {
        return(stringr::str_trim(parts[1]))
      }
      
      return("")
    },
    
    categorize_document = function(tipo) {
      if (is.null(tipo) || is.na(tipo)) return("Outros")
      
      tipo_lower <- tolower(tipo)
      
      if (grepl("lei|decreto|portaria|resolução|instrução", tipo_lower)) {
        return("Legislação")
      } else if (grepl("acórdão|decisão|sentença", tipo_lower)) {
        return("Jurisprudência")
      } else if (grepl("parecer|estudo|relatório", tipo_lower)) {
        return("Doutrina")
      } else {
        return("Outros")
      }
    }
  )
)

# ============================================================================
# IBGE DATA SOURCE INTEGRATION
# ============================================================================

IBGEExtractor <- R6::R6Class("IBGEExtractor",
  public = list(
    rate_limiter = NULL,
    circuit_breaker = NULL,
    municipality_cache = NULL,
    state_cache = NULL,
    
    initialize = function() {
      self$rate_limiter <- RateLimiter$new(ETL_CONFIG$sources$ibge$rate_limit)
      self$circuit_breaker <- CircuitBreaker$new()
      log_etl("INFO", "IBGE extractor initialized", "IBGE")
    },
    
    get_municipalities = function(state_id = NULL, force_refresh = FALSE) {
      cache_key <- paste0("municipalities_", state_id %||% "all")
      
      if (!force_refresh && !is.null(self$municipality_cache[[cache_key]])) {
        log_etl("DEBUG", "Using cached municipality data", "IBGE")
        return(self$municipality_cache[[cache_key]])
      }
      
      if (!self$circuit_breaker$can_execute()) {
        log_etl("ERROR", "IBGE circuit breaker is OPEN", "IBGE")
        return(NULL)
      }
      
      tryCatch({
        self$rate_limiter$wait_if_needed()
        self$rate_limiter$record_request()
        
        url <- paste0(ETL_CONFIG$sources$ibge$base_url, 
                     ETL_CONFIG$sources$ibge$api_municipalities)
        
        if (!is.null(state_id)) {
          url <- paste0(url, "?UF=", state_id)
        }
        
        response <- httr::GET(
          url = url,
          httr::timeout(ETL_CONFIG$sources$ibge$timeout),
          httr::add_headers(
            "User-Agent" = "Brazilian-Legislative-Monitor/4.0",
            "Accept" = "application/json"
          )
        )
        
        if (httr::status_code(response) == 200) {
          content <- httr::content(response, "text", encoding = "UTF-8")
          municipalities <- jsonlite::fromJSON(content, flatten = TRUE)
          
          # Standardize municipality data
          standardized <- data.frame(
            codigo_ibge = municipalities$id,
            nome = municipalities$nome,
            estado_codigo = sapply(municipalities$microrregiao.mesorregiao.UF.id, function(x) x),
            estado_nome = sapply(municipalities$microrregiao.mesorregiao.UF.nome, function(x) x),
            estado_sigla = sapply(municipalities$microrregiao.mesorregiao.UF.sigla, function(x) x),
            microrregiao = sapply(municipalities$microrregiao.nome, function(x) x),
            mesorregiao = sapply(municipalities$microrregiao.mesorregiao.nome, function(x) x),
            data_atualizacao = Sys.time(),
            stringsAsFactors = FALSE
          )
          
          # Cache the results
          self$municipality_cache[[cache_key]] <- standardized
          self$circuit_breaker$record_success()
          
          log_etl("INFO", sprintf("IBGE municipalities extracted: %d records", nrow(standardized)), "IBGE")
          return(standardized)
        } else {
          log_etl("ERROR", sprintf("IBGE API error: %d", httr::status_code(response)), "IBGE")
          self$circuit_breaker$record_failure()
          return(NULL)
        }
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("IBGE municipality extraction failed: %s", e$message), "IBGE")
        self$circuit_breaker$record_failure()
        return(NULL)
      })
    },
    
    get_states = function(force_refresh = FALSE) {
      if (!force_refresh && !is.null(self$state_cache)) {
        log_etl("DEBUG", "Using cached state data", "IBGE")
        return(self$state_cache)
      }
      
      if (!self$circuit_breaker$can_execute()) {
        log_etl("ERROR", "IBGE circuit breaker is OPEN", "IBGE")
        return(NULL)
      }
      
      tryCatch({
        self$rate_limiter$wait_if_needed()
        self$rate_limiter$record_request()
        
        url <- paste0(ETL_CONFIG$sources$ibge$base_url, 
                     ETL_CONFIG$sources$ibge$api_states)
        
        response <- httr::GET(
          url = url,
          httr::timeout(ETL_CONFIG$sources$ibge$timeout),
          httr::add_headers(
            "User-Agent" = "Brazilian-Legislative-Monitor/4.0",
            "Accept" = "application/json"
          )
        )
        
        if (httr::status_code(response) == 200) {
          content <- httr::content(response, "text", encoding = "UTF-8")
          states <- jsonlite::fromJSON(content, flatten = TRUE)
          
          # Standardize state data
          standardized <- data.frame(
            codigo_ibge = states$id,
            nome = states$nome,
            sigla = states$sigla,
            regiao_codigo = states$regiao.id,
            regiao_nome = states$regiao.nome,
            regiao_sigla = states$regiao.sigla,
            data_atualizacao = Sys.time(),
            stringsAsFactors = FALSE
          )
          
          # Cache the results
          self$state_cache <- standardized
          self$circuit_breaker$record_success()
          
          log_etl("INFO", sprintf("IBGE states extracted: %d records", nrow(standardized)), "IBGE")
          return(standardized)
        } else {
          log_etl("ERROR", sprintf("IBGE API error: %d", httr::status_code(response)), "IBGE")
          self$circuit_breaker$record_failure()
          return(NULL)
        }
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("IBGE state extraction failed: %s", e$message), "IBGE")
        self$circuit_breaker$record_failure()
        return(NULL)
      })
    },
    
    enrich_with_geographic_data = function(documents) {
      if (is.null(documents) || nrow(documents) == 0) return(documents)
      
      log_etl("INFO", "Enriching documents with IBGE geographic data", "IBGE")
      
      # Get reference data
      states <- self$get_states()
      
      if (!is.null(states)) {
        # Enrich state information
        documents <- merge(documents, states, 
                          by.x = "estado", by.y = "sigla", 
                          all.x = TRUE, suffixes = c("", "_ibge"))
      }
      
      # Enrich municipality information where available
      if ("municipio" %in% names(documents) && sum(documents$municipio != "") > 0) {
        unique_states <- unique(documents$estado[documents$estado != ""])
        
        for (state in unique_states) {
          municipalities <- self$get_municipalities(state)
          if (!is.null(municipalities)) {
            state_docs <- documents[documents$estado == state, ]
            
            # Fuzzy match municipality names
            enriched <- self$fuzzy_match_municipalities(state_docs, municipalities)
            documents[documents$estado == state, ] <- enriched
          }
        }
      }
      
      log_etl("INFO", sprintf("Geographic enrichment complete for %d documents", nrow(documents)), "IBGE")
      return(documents)
    },
    
    fuzzy_match_municipalities = function(documents, municipalities) {
      # Simple fuzzy matching for municipality names
      for (i in 1:nrow(documents)) {
        if (documents$municipio[i] != "") {
          # Find best match using string distance
          distances <- stringdist::stringdist(
            tolower(documents$municipio[i]), 
            tolower(municipalities$nome),
            method = "jw"  # Jaro-Winkler
          )
          
          best_match_idx <- which.min(distances)
          if (distances[best_match_idx] < 0.3) {  # Similarity threshold
            documents$municipio_ibge_codigo[i] <- municipalities$codigo_ibge[best_match_idx]
            documents$municipio_ibge_nome[i] <- municipalities$nome[best_match_idx]
          }
        }
      }
      
      return(documents)
    }
  )
)

# ============================================================================
# MAIN ETL ORCHESTRATOR
# ============================================================================

ETLOrchestrator <- R6::R6Class("ETLOrchestrator",
  public = list(
    lexml_extractor = NULL,
    ibge_extractor = NULL,
    db_pool = NULL,
    
    initialize = function() {
      setup_etl_logging()
      
      self$lexml_extractor <- LexMLExtractor$new()
      self$ibge_extractor <- IBGEExtractor$new()
      
      # Initialize database connection (reuse existing secure connection)
      if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
        self$db_pool <- secure_db_pool
      }
      
      log_etl("INFO", "ETL Orchestrator initialized", "ORCHESTRATOR")
    },
    
    run_full_pipeline = function(limit = 10000) {
      log_etl("INFO", "Starting full ETL pipeline execution", "ORCHESTRATOR")
      start_time <- Sys.time()
      
      tryCatch({
        # Step 1: Extract from LexML
        log_etl("INFO", "Step 1: Extracting documents from LexML", "ORCHESTRATOR")
        raw_documents <- self$lexml_extractor$extract_documents(limit = limit)
        
        if (is.null(raw_documents) || nrow(raw_documents) == 0) {
          log_etl("ERROR", "No documents extracted from LexML", "ORCHESTRATOR")
          return(FALSE)
        }
        
        log_etl("INFO", sprintf("LexML extraction complete: %d documents", nrow(raw_documents)), "ORCHESTRATOR")
        
        # Step 2: Enrich with IBGE data
        log_etl("INFO", "Step 2: Enriching with IBGE geographic data", "ORCHESTRATOR")
        enriched_documents <- self$ibge_extractor$enrich_with_geographic_data(raw_documents)
        
        # Step 3: Data validation and quality checks
        log_etl("INFO", "Step 3: Running data validation and quality checks", "ORCHESTRATOR")
        validated_documents <- self$validate_and_clean_data(enriched_documents)
        
        if (is.null(validated_documents) || nrow(validated_documents) == 0) {
          log_etl("ERROR", "No valid documents after quality checks", "ORCHESTRATOR")
          return(FALSE)
        }
        
        log_etl("INFO", sprintf("Data validation complete: %d valid documents", nrow(validated_documents)), "ORCHESTRATOR")
        
        # Step 4: Load into database
        log_etl("INFO", "Step 4: Loading data into database", "ORCHESTRATOR")
        load_success <- self$load_to_database(validated_documents)
        
        if (!load_success) {
          log_etl("ERROR", "Database loading failed", "ORCHESTRATOR")
          return(FALSE)
        }
        
        # Step 5: Update metadata and statistics
        log_etl("INFO", "Step 5: Updating metadata and statistics", "ORCHESTRATOR")
        self$update_pipeline_metadata(nrow(validated_documents))
        
        end_time <- Sys.time()
        duration <- as.numeric(end_time - start_time, units = "mins")
        
        log_etl("INFO", sprintf("ETL pipeline completed successfully in %.2f minutes", duration), "ORCHESTRATOR")
        return(TRUE)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("ETL pipeline failed: %s", e$message), "ORCHESTRATOR")
        return(FALSE)
      })
    },
    
    validate_and_clean_data = function(documents) {
      if (is.null(documents) || nrow(documents) == 0) return(NULL)
      
      log_etl("INFO", sprintf("Starting data validation for %d documents", nrow(documents)), "VALIDATOR")
      
      # Required field validation
      required_fields <- ETL_CONFIG$quality$required_fields
      for (field in required_fields) {
        if (!field %in% names(documents)) {
          log_etl("WARN", sprintf("Required field '%s' missing, adding empty column", field), "VALIDATOR")
          documents[[field]] <- ""
        }
      }
      
      # Title validation
      valid_title <- !is.na(documents$titulo) & 
                    nchar(documents$titulo) >= ETL_CONFIG$quality$min_title_length &
                    nchar(documents$titulo) <= ETL_CONFIG$quality$max_title_length
      
      documents <- documents[valid_title, ]
      log_etl("INFO", sprintf("Title validation: %d documents retained", nrow(documents)), "VALIDATOR")
      
      # Date validation
      valid_dates <- !is.na(documents$data) & 
                    documents$data >= as.Date("1988-10-05") &  # Brazilian Constitution date
                    documents$data <= Sys.Date()
      
      documents <- documents[valid_dates, ]
      log_etl("INFO", sprintf("Date validation: %d documents retained", nrow(documents)), "VALIDATOR")
      
      # Remove duplicates
      documents <- self$remove_duplicates(documents)
      
      # Data quality scoring
      documents$quality_score <- self$calculate_quality_score(documents)
      
      log_etl("INFO", sprintf("Data validation complete: %d valid documents", nrow(documents)), "VALIDATOR")
      return(documents)
    },
    
    remove_duplicates = function(documents) {
      if (nrow(documents) == 0) return(documents)
      
      # Create document fingerprint
      documents$fingerprint <- apply(documents[, c("titulo", "data", "autoridade")], 1, function(row) {
        digest::digest(paste(row, collapse = "|"), algo = "md5")
      })
      
      # Remove exact duplicates
      documents_unique <- documents[!duplicated(documents$fingerprint), ]
      
      duplicates_removed <- nrow(documents) - nrow(documents_unique)
      if (duplicates_removed > 0) {
        log_etl("INFO", sprintf("Removed %d duplicate documents", duplicates_removed), "VALIDATOR")
      }
      
      # Remove fingerprint column
      documents_unique$fingerprint <- NULL
      
      return(documents_unique)
    },
    
    calculate_quality_score = function(documents) {
      scores <- rep(0, nrow(documents))
      
      # Title quality (0-30 points)
      scores <- scores + pmin(nchar(documents$titulo) / 10, 30)
      
      # Has summary (20 points)
      scores <- scores + ifelse(!is.na(documents$ementa) & documents$ementa != "", 20, 0)
      
      # Has URL (10 points)
      scores <- scores + ifelse(!is.na(documents$url) & documents$url != "", 10, 0)
      
      # Has state information (15 points)
      scores <- scores + ifelse(!is.na(documents$estado) & documents$estado != "", 15, 0)
      
      # Has municipality information (10 points)
      scores <- scores + ifelse(!is.na(documents$municipio) & documents$municipio != "", 10, 0)
      
      # Recent document (15 points for last 2 years)
      recent_threshold <- Sys.Date() - 730  # 2 years
      scores <- scores + ifelse(documents$data >= recent_threshold, 15, 0)
      
      return(pmin(scores, 100))  # Cap at 100
    },
    
    load_to_database = function(documents) {
      if (is.null(self$db_pool) || is.null(documents) || nrow(documents) == 0) {
        log_etl("ERROR", "Database connection or data not available", "DATABASE_LOADER")
        return(FALSE)
      }
      
      tryCatch({
        # Process in batches to manage memory
        batch_size <- ETL_CONFIG$processing$batch_size
        total_rows <- nrow(documents)
        batches <- ceiling(total_rows / batch_size)
        
        log_etl("INFO", sprintf("Loading %d documents in %d batches", total_rows, batches), "DATABASE_LOADER")
        
        # Create or update table
        table_name <- "brazilian_legislative_complete"
        self$ensure_table_exists(table_name)
        
        success_count <- 0
        
        for (i in 1:batches) {
          start_idx <- (i - 1) * batch_size + 1
          end_idx <- min(i * batch_size, total_rows)
          
          batch <- documents[start_idx:end_idx, ]
          
          # Insert batch
          result <- dbWriteTable(
            self$db_pool, 
            table_name, 
            batch, 
            append = TRUE, 
            row.names = FALSE
          )
          
          if (result) {
            success_count <- success_count + nrow(batch)
            log_etl("DEBUG", sprintf("Batch %d/%d loaded: %d rows", i, batches, nrow(batch)), "DATABASE_LOADER")
          } else {
            log_etl("ERROR", sprintf("Batch %d/%d failed to load", i, batches), "DATABASE_LOADER")
          }
          
          # Memory management
          memory_monitor$check_memory()
        }
        
        log_etl("INFO", sprintf("Database loading complete: %d/%d documents loaded", success_count, total_rows), "DATABASE_LOADER")
        return(success_count == total_rows)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Database loading failed: %s", e$message), "DATABASE_LOADER")
        return(FALSE)
      })
    },
    
    ensure_table_exists = function(table_name) {
      # Create table if it doesn't exist
      create_sql <- sprintf("
        CREATE TABLE IF NOT EXISTS %s (
          id SERIAL PRIMARY KEY,
          titulo TEXT NOT NULL,
          tipo VARCHAR(100),
          data DATE,
          autoridade TEXT,
          estado VARCHAR(2),
          municipio VARCHAR(255),
          ementa TEXT,
          url TEXT,
          urn TEXT,
          assuntos TEXT,
          categoria VARCHAR(100),
          fonte VARCHAR(50),
          data_extracao TIMESTAMP,
          codigo_ibge INTEGER,
          municipio_ibge_nome VARCHAR(255),
          quality_score INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_%s_data ON %s(data);
        CREATE INDEX IF NOT EXISTS idx_%s_estado ON %s(estado);
        CREATE INDEX IF NOT EXISTS idx_%s_categoria ON %s(categoria);
        CREATE INDEX IF NOT EXISTS idx_%s_titulo ON %s USING gin(to_tsvector('portuguese', titulo));
      ", table_name, table_name, table_name, table_name, table_name, table_name, table_name, table_name, table_name)
      
      dbExecute(self$db_pool, create_sql)
    },
    
    update_pipeline_metadata = function(documents_processed) {
      metadata <- list(
        last_run = Sys.time(),
        documents_processed = documents_processed,
        pipeline_version = "4B.1.0",
        memory_peak_gb = memory_monitor$current_usage
      )
      
      # Save metadata to file and database
      saveRDS(metadata, file.path(ETL_CONFIG$processing$cache_dir, "pipeline_metadata.rds"))
      
      log_etl("INFO", sprintf("Pipeline metadata updated: %d documents processed", documents_processed), "ORCHESTRATOR")
    }
  )
)

# ============================================================================
# PIPELINE INITIALIZATION AND EXPORTS
# ============================================================================

# Initialize global ETL orchestrator
etl_orchestrator <- NULL

initialize_etl_pipeline <- function() {
  cat("🚀 Initializing ETL Pipeline for Sprint 4B...\n")
  
  tryCatch({
    etl_orchestrator <<- ETLOrchestrator$new()
    
    cat("✅ ETL Pipeline initialized successfully\n")
    cat("🔧 Components loaded:\n")
    cat("   - LexML Extractor (Brazilian Legislative XML)\n")
    cat("   - IBGE Extractor (Geographic Data)\n")
    cat("   - Memory Monitor (Railway optimization)\n")
    cat("   - Rate Limiters and Circuit Breakers\n")
    cat("   - Data Validation and Quality Framework\n")
    cat("📊 Ready for data pipeline execution\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ ETL Pipeline initialization failed:", e$message, "\n")
    return(FALSE)
  })
}

# Export main functions
run_etl_pipeline <- function(limit = 10000) {
  if (is.null(etl_orchestrator)) {
    if (!initialize_etl_pipeline()) {
      return(FALSE)
    }
  }
  
  return(etl_orchestrator$run_full_pipeline(limit))
}

get_pipeline_status <- function() {
  if (is.null(etl_orchestrator)) {
    return(list(status = "not_initialized"))
  }
  
  metadata_file <- file.path(ETL_CONFIG$processing$cache_dir, "pipeline_metadata.rds")
  
  if (file.exists(metadata_file)) {
    metadata <- readRDS(metadata_file)
    return(list(
      status = "ready",
      last_run = metadata$last_run,
      documents_processed = metadata$documents_processed,
      memory_usage_gb = memory_monitor$current_usage
    ))
  }
  
  return(list(status = "ready", last_run = NULL))
}

cat("🏗️ ETL Pipeline Architecture loaded for Sprint 4B\n")
cat("📋 Brazilian Legislative Data Integration Ready\n")
cat("🔧 Use initialize_etl_pipeline() to start\n")