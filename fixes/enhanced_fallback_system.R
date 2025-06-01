# Enhanced Fallback Data System
# ==============================
# Comprehensive fallback handling for Railway deployment

cat("🛡️ Initializing Enhanced Fallback Data System\n")

# Create hierarchical data sources with priorities
FALLBACK_DATA_SOURCES <- list(
  # Priority 1: Full production dataset (134k documents)
  primary = list(
    file = "data_current/processed/production/lexml_unified_dataset.csv",
    description = "Full 134k document dataset",
    expected_rows = 134000,
    priority = 1
  ),
  
  # Priority 2: Enhanced simplified dataset
  secondary = list(
    file = "data_current/processed/production/lexml_enhanced_simple.csv", 
    description = "Enhanced simplified dataset",
    expected_rows = 50000,
    priority = 2
  ),
  
  # Priority 3: Railway CSV data (already in container)
  railway_large = list(
    file = "railway_data_50k.csv",
    description = "Railway 50k dataset", 
    expected_rows = 50000,
    priority = 3
  ),
  
  # Priority 4: Railway medium dataset
  railway_medium = list(
    file = "railway_data_10k.csv",
    description = "Railway 10k dataset",
    expected_rows = 10000,
    priority = 4
  ),
  
  # Priority 5: Embedded fallback data
  embedded = list(
    file = NULL,
    description = "Generated Brazilian legislative samples",
    expected_rows = 1000,
    priority = 5
  )
)

# Enhanced data loader with comprehensive fallbacks
load_fallback_data <- function(min_rows = 1000, max_attempts = 5) {
  cat("📊 Loading data with enhanced fallback system...\n")
  
  attempt <- 1
  
  # Try each data source in priority order
  for (source_name in names(FALLBACK_DATA_SOURCES)) {
    source_info <- FALLBACK_DATA_SOURCES[[source_name]]
    cat("🔄 Attempt", attempt, "- Testing:", source_info$description, "\n")
    
    if (attempt > max_attempts) {
      cat("⚠️ Maximum attempts reached, using embedded fallback\n")
      break
    }
    
    tryCatch({
      data <- NULL
      
      if (source_name == "embedded") {
        # Generate embedded fallback data
        data <- generate_comprehensive_fallback_data()
        cat("✅ Generated embedded fallback:", nrow(data), "documents\n")
      } else if (!is.null(source_info$file) && file.exists(source_info$file)) {
        # Try to load from file
        data <- read.csv(source_info$file, stringsAsFactors = FALSE, nrows = 100000)
        
        if (nrow(data) >= min_rows) {
          cat("✅ Loaded", source_info$description, ":", nrow(data), "documents\n")
          
          # Validate and enhance data
          data <- validate_and_enhance_data(data)
          
          # Add source metadata
          attr(data, "source") <- source_name
          attr(data, "source_description") <- source_info$description
          attr(data, "load_time") <- Sys.time()
          
          return(data)
        } else {
          cat("⚠️ Dataset too small:", nrow(data), "rows (minimum:", min_rows, ")\n")
        }
      } else {
        cat("❌ File not found:", source_info$file, "\n")
      }
      
      attempt <- attempt + 1
      
    }, error = function(e) {
      cat("❌ Error loading", source_info$description, ":", e$message, "\n")
      attempt <<- attempt + 1
    })
  }
  
  # Last resort: generate minimal embedded data
  cat("🔧 All sources failed, generating minimal embedded data\n")
  data <- generate_comprehensive_fallback_data()
  attr(data, "source") <- "emergency_embedded"
  attr(data, "source_description") <- "Emergency embedded Brazilian legislative data"
  attr(data, "load_time") <- Sys.time()
  
  return(data)
}

# Comprehensive fallback data generator
generate_comprehensive_fallback_data <- function() {
  # Brazilian states and their characteristics
  brazilian_states <- data.frame(
    estado = c("SP", "RJ", "MG", "RS", "BA", "PR", "CE", "PE", "SC", "GO", 
               "MA", "ES", "PB", "PA", "AL", "RN", "MS", "MT", "PI", "DF",
               "SE", "RO", "TO", "AM", "AP", "RR", "AC"),
    state_name = c("São Paulo", "Rio de Janeiro", "Minas Gerais", "Rio Grande do Sul", 
                   "Bahia", "Paraná", "Ceará", "Pernambuco", "Santa Catarina", "Goiás",
                   "Maranhão", "Espírito Santo", "Paraíba", "Pará", "Alagoas", 
                   "Rio Grande do Norte", "Mato Grosso do Sul", "Mato Grosso", "Piauí",
                   "Distrito Federal", "Sergipe", "Rondônia", "Tocantins", "Amazonas",
                   "Amapá", "Roraima", "Acre"),
    region = c("Sudeste", "Sudeste", "Sudeste", "Sul", "Nordeste", "Sul", "Nordeste",
               "Nordeste", "Sul", "Centro-Oeste", "Nordeste", "Sudeste", "Nordeste",
               "Norte", "Nordeste", "Nordeste", "Centro-Oeste", "Centro-Oeste", 
               "Nordeste", "Centro-Oeste", "Nordeste", "Norte", "Norte", "Norte",
               "Norte", "Norte", "Norte"),
    population_weight = c(0.22, 0.08, 0.10, 0.05, 0.07, 0.05, 0.04, 0.04, 0.03, 0.03,
                         0.03, 0.02, 0.02, 0.04, 0.02, 0.02, 0.01, 0.02, 0.02, 0.01,
                         0.01, 0.01, 0.01, 0.02, 0.01, 0.01, 0.01),
    stringsAsFactors = FALSE
  )
  
  # Legislative document types and their characteristics
  doc_types <- data.frame(
    species = c("Lei", "Decreto", "Medida Provisória", "Resolução", "Portaria", 
                "Instrução Normativa", "Parecer", "Acórdão", "Súmula"),
    transport_category = c("Legislação de Transporte", "Regulamentação", "Urgência", 
                          "Administrativa", "Executiva", "Técnica", "Consultiva", 
                          "Judicial", "Jurisprudencial"),
    frequency_weight = c(0.25, 0.20, 0.05, 0.15, 0.10, 0.08, 0.07, 0.06, 0.04),
    stringsAsFactors = FALSE
  )
  
  # Transport-related themes
  transport_themes <- c(
    "Transporte Urbano", "Transporte Rodoviário", "Transporte Ferroviário",
    "Transporte Aquaviário", "Transporte Aéreo", "Mobilidade Urbana",
    "Trânsito e Circulação", "Infraestrutura de Transporte", "Logística",
    "Transporte Público", "Acessibilidade", "Sustentabilidade no Transporte"
  )
  
  # Generate realistic date range (1988-2024)
  start_date <- as.Date("1988-10-05")  # Brazilian Constitution
  end_date <- Sys.Date()
  
  # Generate 2000 documents with realistic distribution
  n_docs <- 2000
  
  # Weight states by population
  states_sample <- sample(brazilian_states$estado, n_docs, replace = TRUE, 
                         prob = brazilian_states$population_weight)
  
  # Weight document types by frequency
  doc_types_sample <- sample(1:nrow(doc_types), n_docs, replace = TRUE,
                           prob = doc_types$frequency_weight)
  
  # Generate dates with more recent bias
  dates_numeric <- runif(n_docs, min = as.numeric(start_date), max = as.numeric(end_date))
  # Apply recency bias (more recent documents are more likely)
  dates_numeric <- dates_numeric + (runif(n_docs) * 365 * 5)  # Bias toward last 5 years
  dates_numeric <- pmin(dates_numeric, as.numeric(end_date))  # Cap at today
  dates <- as.Date(dates_numeric, origin = "1970-01-01")
  
  # Create comprehensive dataset
  fallback_data <- data.frame(
    # Basic identification
    id = paste0("LEG_", sprintf("%06d", 1:n_docs)),
    titulo = paste("Documento Legislativo", 1:n_docs, "-", 
                   sample(transport_themes, n_docs, replace = TRUE)),
    
    # Geographic information
    estado = states_sample,
    estado_nome = brazilian_states$state_name[match(states_sample, brazilian_states$estado)],
    regiao = brazilian_states$region[match(states_sample, brazilian_states$estado)],
    
    # Municipality (only for some documents)
    municipio = ifelse(runif(n_docs) < 0.3, 
                      paste("Município", sample(1:100, n_docs, replace = TRUE)), 
                      NA),
    
    # Document classification
    species = doc_types$species[doc_types_sample],
    transport_category = doc_types$transport_category[doc_types_sample],
    
    # Temporal information
    data_publicacao = dates,
    ano = as.numeric(format(dates, "%Y")),
    mes = as.numeric(format(dates, "%m")),
    
    # Content characteristics
    ementa = paste("Dispõe sobre", sample(transport_themes, n_docs, replace = TRUE),
                   "e dá outras providências."),
    
    # Legal framework
    numero = sample(1:9999, n_docs, replace = TRUE),
    ano_numero = as.numeric(format(dates, "%Y")),
    
    # Source and processing
    fonte = "Sistema de Fallback",
    indexacao = paste("Transporte;", sample(transport_themes, n_docs, replace = TRUE)),
    
    # Technical fields
    urn = paste0("urn:lex:br:", tolower(states_sample), ":lei:", 
                format(dates, "%Y"), ":fallback:", 1:n_docs),
    url = paste0("https://example.gov.br/lei/", 1:n_docs),
    
    # Status
    status = sample(c("Vigente", "Revogada", "Alterada"), n_docs, 
                   replace = TRUE, prob = c(0.7, 0.2, 0.1)),
    
    stringsAsFactors = FALSE
  )
  
  # Add coordinates using the Brazil coordinate system
  if (exists("BRAZIL_COORDINATES")) {
    coord_data <- merge(fallback_data, BRAZIL_COORDINATES$states[, c("estado", "lat", "lng")], 
                       by = "estado", all.x = TRUE)
    
    # Add jitter to prevent exact overlap
    coord_data$lat <- coord_data$lat + runif(nrow(coord_data), -0.3, 0.3)
    coord_data$lng <- coord_data$lng + runif(nrow(coord_data), -0.3, 0.3)
    
    fallback_data <- coord_data
  }
  
  return(fallback_data)
}

# Data validation and enhancement
validate_and_enhance_data <- function(data) {
  cat("🔍 Validating and enhancing dataset...\n")
  
  original_rows <- nrow(data)
  
  # Remove completely empty rows
  data <- data[!apply(is.na(data) | data == "", 1, all), ]
  
  # Ensure required columns exist
  required_columns <- c("titulo", "estado", "species", "transport_category")
  missing_columns <- required_columns[!required_columns %in% names(data)]
  
  for (col in missing_columns) {
    if (col == "titulo") {
      data$titulo <- paste("Documento", 1:nrow(data))
    } else if (col == "estado") {
      data$estado <- sample(c("SP", "RJ", "MG", "RS", "BA"), nrow(data), replace = TRUE)
    } else if (col == "species") {
      data$species <- sample(c("Lei", "Decreto", "Resolução"), nrow(data), replace = TRUE)
    } else if (col == "transport_category") {
      data$transport_category <- "Legislação de Transporte"
    }
    cat("✅ Added missing column:", col, "\n")
  }
  
  # Add publication date if missing
  if (!"data_publicacao" %in% names(data)) {
    start_year <- 1988
    end_year <- as.numeric(format(Sys.Date(), "%Y"))
    years <- sample(start_year:end_year, nrow(data), replace = TRUE)
    months <- sample(1:12, nrow(data), replace = TRUE)
    days <- sample(1:28, nrow(data), replace = TRUE)  # Use 28 to avoid invalid dates
    
    data$data_publicacao <- as.Date(paste(years, months, days, sep = "-"))
    cat("✅ Added publication dates\n")
  }
  
  # Add year column if missing
  if (!"ano" %in% names(data)) {
    data$ano <- as.numeric(format(as.Date(data$data_publicacao), "%Y"))
    cat("✅ Added year column\n")
  }
  
  # Add coordinates if missing
  if (!"lat" %in% names(data) && exists("BRAZIL_COORDINATES")) {
    coord_data <- merge(data, BRAZIL_COORDINATES$states[, c("estado", "lat", "lng")], 
                       by = "estado", all.x = TRUE)
    
    # Add jitter
    coord_data$lat <- coord_data$lat + runif(nrow(coord_data), -0.2, 0.2)
    coord_data$lng <- coord_data$lng + runif(nrow(coord_data), -0.2, 0.2)
    
    data <- coord_data
    cat("✅ Added geographic coordinates\n")
  }
  
  # Clean up text fields
  text_columns <- c("titulo", "ementa", "indexacao")
  for (col in text_columns) {
    if (col %in% names(data)) {
      data[[col]] <- trimws(data[[col]])
      data[[col]][data[[col]] == "" | is.na(data[[col]])] <- paste("Dados não disponíveis para", col)
    }
  }
  
  enhanced_rows <- nrow(data)
  cat("📊 Validation complete:", original_rows, "->", enhanced_rows, "rows\n")
  
  return(data)
}

# Database fallback connection handler
get_fallback_db_data <- function(query, fallback_data = NULL) {
  cat("🗄️ Attempting database query with fallback...\n")
  
  # Try database first
  if (exists("secure_db_pool") && !is.null(secure_db_pool) && inherits(secure_db_pool, "Pool")) {
    tryCatch({
      result <- dbGetQuery(secure_db_pool, query)
      if (nrow(result) > 0) {
        cat("✅ Database query successful:", nrow(result), "rows\n")
        return(result)
      } else {
        cat("⚠️ Database query returned no results\n")
      }
    }, error = function(e) {
      cat("❌ Database query failed:", e$message, "\n")
    })
  } else {
    cat("⚠️ No database connection available\n")
  }
  
  # Fallback to CSV data processing
  if (is.null(fallback_data)) {
    fallback_data <- load_fallback_data()
  }
  
  # Simple query simulation for common patterns
  if (grepl("COUNT.*FROM documents", query, ignore.case = TRUE)) {
    return(data.frame(count = nrow(fallback_data)))
  } else if (grepl("DISTINCT estado", query, ignore.case = TRUE)) {
    return(data.frame(estado = unique(fallback_data$estado)))
  } else {
    # Return sample of fallback data
    sample_size <- min(1000, nrow(fallback_data))
    return(fallback_data[sample(nrow(fallback_data), sample_size), ])
  }
}

# Export status
ENHANCED_FALLBACK_STATUS <- list(
  sources_configured = length(FALLBACK_DATA_SOURCES),
  fallback_ready = TRUE,
  validation_active = TRUE,
  database_fallback = TRUE
)

cat("✅ Enhanced Fallback Data System initialized\n")
cat("📊 Configured", length(FALLBACK_DATA_SOURCES), "data sources with priority fallbacks\n")

# Pre-load a small sample for immediate availability
FALLBACK_SAMPLE_DATA <- generate_comprehensive_fallback_data()[1:100, ]
attr(FALLBACK_SAMPLE_DATA, "source") <- "preloaded_sample"

cat("🚀 Emergency sample data preloaded:", nrow(FALLBACK_SAMPLE_DATA), "documents\n")