# Unified Data Service Module for Monitor Legislativo
# ====================================================
# This module consolidates all data loading logic into a single, clean interface
# replacing the emergency patches and multiple fallback systems

library(DBI)
library(RPostgres)  # Use RPostgres instead of RPostgreSQL
library(pool)
library(readr)
library(dplyr)
library(stringr)

# Configuration
DATA_SERVICE_CONFIG <- list(
  db_timeout = as.numeric(Sys.getenv("DB_TIMEOUT", "5")),
  max_results = 10000,
  default_page_size = 50,
  enable_logging = TRUE
)

# Logging function
log_message <- function(message, level = "INFO") {
  if (DATA_SERVICE_CONFIG$enable_logging) {
    timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
    cat(sprintf("[%s] %s: %s\n", timestamp, level, message))
  }
}

# Main data retrieval function - single source of truth
get_documents <- function(filters = list(), limit = NULL, offset = NULL) {
  log_message("Retrieving documents with filters", "INFO")

  # Try database first (production path)
  db_result <- tryCatch({
    get_documents_from_database(filters, limit, offset)
  }, error = function(e) {
    log_message(paste("Database query failed:", e$message), "WARN")
    NULL
  })

  if (!isTRUE(is.null(db_result)) && nrow(db_result) > 0) {
    log_message(sprintf("Retrieved %d documents from database", nrow(db_result)), "INFO")
    return(db_result)
  }

  # Fallback to CSV if database fails
  csv_result <- tryCatch({
    get_documents_from_csv(filters, limit, offset)
  }, error = function(e) {
    log_message(paste("CSV loading failed:", e$message), "ERROR")
    NULL
  })

  if (!isTRUE(is.null(csv_result)) && nrow(csv_result) > 0) {
    log_message(sprintf("Retrieved %d documents from CSV fallback", nrow(csv_result)), "INFO")
    return(csv_result)
  }

  # Return empty dataset with proper structure if all sources fail
  log_message("All data sources failed, returning empty dataset", "ERROR")
  return(create_empty_dataset())
}

# Database retrieval with connection pooling
get_documents_from_database <- function(filters = list(), limit = NULL, offset = NULL) {
  # Get database connection from pool
  con <- get_db_connection()
  if (is.null(con)) {
    stop("Database connection unavailable")
  }

  # Build query with parameterized statements (prevent SQL injection)
  query <- build_safe_query(filters, limit, offset)

  result <- tryCatch({
    dbGetQuery(con, query$statement, query$params)
  }, finally = {
    # Return connection to pool
    release_db_connection(con)
  })

  # Standardize column names
  result <- standardize_columns(result)

  return(result)
}

# CSV retrieval with efficient filtering
get_documents_from_csv <- function(filters = list(), limit = NULL, offset = NULL) {
  csv_path <- file.path(getwd(), DATA_SERVICE_CONFIG$csv_path)

  if (!file.exists(csv_path)) {
    stop(paste("CSV file not found:", csv_path))
  }

  # Read CSV with proper encoding for Portuguese text
  data <- read_csv(csv_path,
                   locale = locale(encoding = "UTF-8"),
                   show_col_types = FALSE)

  # Standardize column names
  data <- standardize_columns(data)

  # Apply filters
  data <- apply_filters(data, filters)

  # Apply pagination
  if (!is.null(offset)) {
    data <- data %>% slice((offset + 1):n())
  }

  if (!is.null(limit)) {
    data <- data %>% slice(1:min(limit, n()))
  }

  return(data)
}

# Load demo data for testing/demo environments
load_demo_data <- function(filters = list(), limit = NULL, offset = NULL) {
  demo_path <- file.path(getwd(), DATA_SERVICE_CONFIG$demo_csv_path)

  if (file.exists(demo_path)) {
    return(get_documents_from_csv(filters, limit, offset))
  } else {
    # Create small synthetic dataset for demos
    log_message("Creating synthetic demo dataset", "INFO")
    return(create_demo_dataset(100))
  }
}

# Standardize column names across all data sources (Portuguese-only)
# NOTE: All column names use Portuguese to match database schema
# This eliminates translation overhead and maintains consistency
standardize_columns <- function(data) {
  # Map column name variations to standard Portuguese names
  column_name_variants <- c(
    "título" = "titulo",        # Normalize accented variant
    "data_publicacao" = "data", # Normalize date column variants
    "ementa" = "resumo",        # Normalize summary column variants
    "tipo_documento" = "tipo",  # Normalize document type variants
    "uf" = "estado",            # Normalize state abbreviation
    "cidade" = "municipio"      # Normalize municipality variants
  )

  # Rename variant columns if they exist
  for (variant in names(column_name_variants)) {
    if (variant %in% names(data)) {
      standard_name <- column_name_variants[variant]
      names(data)[names(data) == variant] <- standard_name
    }
  }

  # Ensure required columns exist (using Portuguese names)
  required_cols <- c("id", "titulo", "tipo", "estado", "data")
  for (col in required_cols) {
    if (!(col %in% names(data))) {
      data[[col]] <- NA
    }
  }

  return(data)
}

# Apply filters to dataset (using Portuguese column names)
apply_filters <- function(data, filters) {
  if (length(filters) == 0) {
    return(data)
  }

  # Search text filter (titulo and resumo)
  if (!isTRUE(is.null(filters$search)) && nchar(filters$search) > 0) {
    search_pattern <- str_to_lower(filters$search)
    data <- data %>%
      filter(
        str_detect(str_to_lower(titulo), search_pattern) |
        (exists("resumo", where = data) && str_detect(str_to_lower(resumo), search_pattern))
      )
  }

  # Category filter (categoria)
  if (!isTRUE(is.null(filters$categoria)) && filters$categoria != "Todos") {
    data <- data %>% filter(categoria == filters$categoria)
  }

  # State filter (estado)
  if (!isTRUE(is.null(filters$estado)) && filters$estado != "Todos") {
    data <- data %>% filter(estado == filters$estado)
  }

  # Date range filter (data)
  if (!isTRUE(is.null(filters$data_inicio)) && !is.null(filters$data_fim)) {
    data <- data %>%
      filter(data >= filters$data_inicio & data <= filters$data_fim)
  }

  # Document type filter (tipo)
  if (!isTRUE(is.null(filters$tipo)) && filters$tipo != "Todos") {
    data <- data %>% filter(tipo == filters$tipo)
  }

  return(data)
}

# Build safe parameterized query (Portuguese column names)
# This supports server-side pagination with optimized counting
build_safe_query <- function(filters, limit = NULL, offset = NULL, table_name = "documents") {
  base_query <- paste("SELECT * FROM", table_name, "WHERE 1=1")
  params <- list()
  param_counter <- 1

  # Add filter conditions (using Portuguese column names from database)
  if (!isTRUE(is.null(filters$search)) && nchar(filters$search) > 0) {
    base_query <- paste0(base_query, " AND (titulo ILIKE $", param_counter,
                        " OR resumo ILIKE $", param_counter, ")")
    params[[param_counter]] <- paste0("%", filters$search, "%")
    param_counter <- param_counter + 1
  }

  if (!isTRUE(is.null(filters$categoria)) && filters$categoria != "Todos") {
    base_query <- paste0(base_query, " AND categoria = $", param_counter)
    params[[param_counter]] <- filters$categoria
    param_counter <- param_counter + 1
  }

  if (!isTRUE(is.null(filters$estado)) && filters$estado != "Todos") {
    base_query <- paste0(base_query, " AND estado = $", param_counter)
    params[[param_counter]] <- filters$estado
    param_counter <- param_counter + 1
  }

  if (!isTRUE(is.null(filters$tipo)) && filters$tipo != "Todos") {
    base_query <- paste0(base_query, " AND tipo = $", param_counter)
    params[[param_counter]] <- filters$tipo
    param_counter <- param_counter + 1
  }

  # Add pagination
  if (!is.null(limit)) {
    base_query <- paste0(base_query, " LIMIT ", as.integer(limit))
  }

  if (!is.null(offset)) {
    base_query <- paste0(base_query, " OFFSET ", as.integer(offset))
  }

  return(list(statement = base_query, params = params))
}

# Build optimized count query for pagination
# This creates an efficient COUNT(*) query without loading data
build_count_query <- function(filters, table_name = "documents") {
  base_query <- paste("SELECT COUNT(*) as total FROM", table_name, "WHERE 1=1")
  params <- list()
  param_counter <- 1

  # Add same filter conditions as main query (but no ORDER BY, LIMIT, OFFSET)
  if (!isTRUE(is.null(filters$search)) && nchar(filters$search) > 0) {
    base_query <- paste0(base_query, " AND (titulo ILIKE $", param_counter,
                        " OR resumo ILIKE $", param_counter, ")")
    params[[param_counter]] <- paste0("%", filters$search, "%")
    param_counter <- param_counter + 1
  }

  if (!isTRUE(is.null(filters$categoria)) && filters$categoria != "Todos") {
    base_query <- paste0(base_query, " AND categoria = $", param_counter)
    params[[param_counter]] <- filters$categoria
    param_counter <- param_counter + 1
  }

  if (!isTRUE(is.null(filters$estado)) && filters$estado != "Todos") {
    base_query <- paste0(base_query, " AND estado = $", param_counter)
    params[[param_counter]] <- filters$estado
    param_counter <- param_counter + 1
  }

  if (!isTRUE(is.null(filters$tipo)) && filters$tipo != "Todos") {
    base_query <- paste0(base_query, " AND tipo = $", param_counter)
    params[[param_counter]] <- filters$tipo
    param_counter <- param_counter + 1
  }

  return(list(statement = base_query, params = params))
}

# Build paginated query for library search
# Returns both the query and count query for efficient server-side pagination
build_paginated_library_query <- function(
  search_term = "",
  tipo = "Todos",
  estado = "Todos",
  year_min = NULL,
  year_max = NULL,
  date_start = NULL,
  date_end = NULL,
  sort_by = "data DESC",
  limit = 100,
  offset = 0,
  table_name = "documents"
) {
  # Build WHERE conditions
  conditions <- c("1=1")

  # Search term filter (titulo and resumo)
  if (nchar(search_term) > 0) {
    search_escaped <- gsub("'", "''", search_term)
    conditions <- c(conditions, sprintf(
      "(titulo ILIKE '%%%s%%' OR resumo ILIKE '%%%s%%')",
      search_escaped, search_escaped
    ))
  }

  # Document type filter
  if (tipo != "Todos" && nchar(tipo) > 0) {
    tipo_escaped <- gsub("'", "''", tipo)
    conditions <- c(conditions, sprintf("tipo = '%s'", tipo_escaped))
  }

  # State filter
  if (estado != "Todos" && nchar(estado) > 0) {
    estado_escaped <- gsub("'", "''", estado)
    conditions <- c(conditions, sprintf("estado = '%s'", estado_escaped))
  }

  # Year range filter
  if (!is.null(year_min) && !is.null(year_max)) {
    conditions <- c(conditions, sprintf(
      "EXTRACT(YEAR FROM data) BETWEEN %d AND %d",
      as.integer(year_min), as.integer(year_max)
    ))
  }

  # Date range filter
  if (!is.null(date_start)) {
    conditions <- c(conditions, sprintf("data >= '%s'", as.character(date_start)))
  }
  if (!is.null(date_end)) {
    conditions <- c(conditions, sprintf("data <= '%s'", as.character(date_end)))
  }

  where_clause <- paste(conditions, collapse = " AND ")

  # Build main query with pagination
  main_query <- sprintf(
    "SELECT id, titulo, tipo, data, estado FROM %s WHERE %s ORDER BY %s LIMIT %d OFFSET %d",
    table_name, where_clause, sort_by, as.integer(limit), as.integer(offset)
  )

  # Build count query (no ORDER BY, LIMIT, OFFSET for efficiency)
  count_query <- sprintf(
    "SELECT COUNT(*) as total FROM %s WHERE %s",
    table_name, where_clause
  )

  return(list(
    main_query = main_query,
    count_query = count_query
  ))
}

# Clean Database Connection Management
# ====================================

# Single source of truth for database configuration
get_db_config <- function() {
  # Prefer DATABASE_URL if available
  database_url <- Sys.getenv("DATABASE_URL", "")
  if (nzchar(database_url)) {
    log_message("Using DATABASE_URL for connection", "INFO")
    return(list(url = database_url))
  }

  # Fallback to individual PG* environment variables
  log_message("Using individual PG* environment variables", "INFO")
  return(list(
    host = Sys.getenv("PGHOST", "localhost"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "railway"),
    user = Sys.getenv("PGUSER", "postgres"),
    password = Sys.getenv("PGPASSWORD", ""),
    sslmode = Sys.getenv("PGSSLMODE", "disable")  # Railway internal usually no SSL
  ))
}

# Create database connection pool with only supported arguments
db_connection_pool <- NULL

# FIX v49: Safe %||% operator that prevents extent=0 error
`%||%` <- function(x, y) {
  if (isTRUE(is.null(x))) return(y)
  if (isTRUE(length(x) == 0L)) return(y)
  return(x)
}

# Parse DATABASE_URL into individual parameters (RPostgres doesn't support url= parameter)
# Supports both standard format and Cloud SQL Unix socket format
parse_database_url <- function(url = Sys.getenv("DATABASE_URL", "")) {
  if (!nzchar(url)) return(NULL)

  # Try standard format: postgresql://user:pass@host:port/dbname?options
  m <- regexec("^postgres(?:ql)?://([^:]+):([^@]+)@([^:/]+)(?::(\\d+))?/([^?]+)(?:\\?(.+))?$", url, perl = TRUE)
  parts <- regmatches(url, m)[[1]]

  # If standard format failed, try Cloud SQL Unix socket format: postgresql://user:pass@/dbname?host=...
  if (length(parts) == 0) {
    m <- regexec("^postgres(?:ql)?://([^:]+):([^@]+)@/([^?]+)(?:\\?(.+))?$", url, perl = TRUE)
    parts <- regmatches(url, m)[[1]]
    if (length(parts) == 0) return(NULL)

    # Parse query string to get host parameter
    qs <- if (length(parts) >= 5 && nzchar(parts[5])) utils::URLdecode(parts[5]) else ""
    kv <- if (nzchar(qs)) {
      params <- strsplit(qs, "&")[[1]]
      setNames(sub("^[^=]+=", "", params), sub("=.*$", "", params))
    } else list()

    # Return Cloud SQL format with Unix socket host
    return(list(
      user = parts[2],
      password = parts[3],
      dbname = parts[4],
      host = kv$host %||% "/cloudsql/mackmonitor:southamerica-east1:mackmonitor-db",
      port = 5432L,
      options = kv
    ))
  }

  # Standard format parsing
  qs <- if (length(parts) >= 7 && nzchar(parts[7])) utils::URLdecode(parts[7]) else ""
  kv <- if (nzchar(qs)) setNames(sub("^[^=]+=", "", strsplit(qs, "&")[[1]]),
                                 sub("=.*$", "", strsplit(qs, "&")[[1]])) else list()
  list(
    user = parts[2], password = parts[3], host = parts[4],
    port = if (length(parts) >= 5 && nzchar(parts[5])) as.integer(parts[5]) else 5432L,
    dbname = parts[6], options = kv
  )
}

create_db_pool <- function() {
  cfg <- get_db_config()

  tryCatch({
    if (!is.null(cfg$url)) {
      # Parse DATABASE_URL into individual parameters (RPostgres doesn't support url= parameter)
      parsed <- parse_database_url(cfg$url)
      if (is.null(parsed)) stop("Invalid DATABASE_URL format")

      pool <- pool::dbPool(
        drv = RPostgres::Postgres(),
        host = parsed$host,
        port = parsed$port,
        dbname = parsed$dbname,
        user = parsed$user,
        password = parsed$password,
        sslmode = parsed$options$sslmode %||% "prefer",
        minSize = 2,
        maxSize = 8,
        idleTimeout = 600000  # 10 minutes
      )
    } else {
      # Use individual parameters
      pool <- pool::dbPool(
        drv = RPostgres::Postgres(),
        host = cfg$host,
        port = cfg$port,
        dbname = cfg$dbname,
        user = cfg$user,
        password = cfg$password,
        sslmode = cfg$sslmode %||% "prefer",
        minSize = 2,
        maxSize = 8,
        idleTimeout = 600000  # 10 minutes
      )
    }

    # Configure session parameters after connection
    init_session_config(pool)

    # Test the pool with startup probe
    # FIX v50: Safe with isTRUE()
    test_result <- pool::dbGetQuery(pool, "SELECT 1 as test")
    if (isTRUE(is.null(test_result)) || isTRUE(nrow(test_result) == 0)) {
      stop("Database startup probe failed")
    }

    # Test document count using known candidate tables
    doc_count <- 0
    doc_count_verified <- FALSE
    table_candidates <- c(
      "documents",
      "brazilian_legislative_complete",
      "lexml_parsed_enhanced",
      "legislative_data"
    )

    for (tbl in table_candidates) {
      query <- sprintf("SELECT COUNT(*) AS count FROM %s", tbl)
      count_result <- tryCatch({
        pool::dbGetQuery(pool, query)
      }, error = function(e) NULL)

      if (!isTRUE(is.null(count_result)) && nrow(count_result) > 0) {
        doc_count <- suppressWarnings(as.numeric(count_result$count[1]))
        if (!is.na(doc_count)) {
          doc_count_verified <- TRUE
          break
        }
      }
    }

    if (!doc_count_verified) {
      log_message("Could not verify document count from known tables; continuing with pool initialization", "WARN")
      doc_count <- 0
    }

    log_message(paste("Database pool created successfully, documents:", doc_count), "INFO")
    return(pool)

  }, error = function(e) {
    log_message(paste("Failed to create database pool:", e$message), "ERROR")
    return(NULL)
  })
}

# Initialize session configuration (timeouts after connection)
init_session_config <- function(pool) {
  tryCatch({
    pool::dbExecute(pool, "SET lock_timeout = '5s'")
    pool::dbExecute(pool, "SET statement_timeout = '120s'")
    pool::dbExecute(pool, "SET idle_in_transaction_session_timeout = '30s'")
    pool::dbExecute(pool, "SET client_min_messages = WARNING")
    log_message("Session configuration applied successfully", "INFO")
  }, error = function(e) {
    log_message(paste("Could not set session parameters:", e$message), "WARN")
  })
}

# Get database connection (creates pool if needed)
get_db_connection <- function() {
  if (is.null(db_connection_pool)) {
    db_connection_pool <<- create_db_pool()
  }
  return(db_connection_pool)
}

release_db_connection <- function(con) {
  # In a real pool implementation, this would return the connection to the pool
  # For now, we keep a single persistent connection
  # Don't disconnect here as we're reusing the connection
}

# Create empty dataset with proper structure (Portuguese column names)
create_empty_dataset <- function() {
  data.frame(
    id = integer(),
    titulo = character(),
    tipo = character(),
    estado = character(),
    data = as.Date(character()),
    resumo = character(),
    autor = character(),
    urn = character(),
    municipio = character(),
    stringsAsFactors = FALSE
  )
}

# Create minimal demo dataset (Portuguese column names)
create_demo_dataset <- function(n = 100) {
  data.frame(
    id = 1:n,
    titulo = paste("Lei Demo", 1:n),
    tipo = sample(c("Lei", "Decreto", "Portaria"), n, replace = TRUE),
    estado = sample(c("SP", "RJ", "MG", "RS", "PR"), n, replace = TRUE),
    data = seq(Sys.Date() - 365, Sys.Date(), length.out = n),
    resumo = paste("Este é um documento legislativo demo número", 1:n),
    autor = paste("Autor", sample(1:20, n, replace = TRUE)),
    urn = paste0("urn:demo:", 1:n),
    municipio = sample(c("São Paulo", "Rio de Janeiro", "Belo Horizonte"), n, replace = TRUE),
    stringsAsFactors = FALSE
  )
}

# Chart data preparation (moved from CRITICAL_CHART_FIXES.R)
# FIX v50: Safe with isTRUE()
prepare_chart_data <- function(data, chart_type = "bar") {
  if (isTRUE(is.null(data)) || isTRUE(nrow(data) == 0)) {
    return(create_empty_chart_data(chart_type))
  }

  # Ensure data is properly formatted for charts
  data <- standardize_columns(data)

  switch(chart_type,
    "timeline" = prepare_timeline_data(data),
    "geographic" = prepare_geographic_data(data),
    "category" = prepare_category_data(data),
    "bar" = prepare_bar_chart_data(data),
    prepare_bar_chart_data(data)  # default
  )
}

prepare_timeline_data <- function(data) {
  data %>%
    mutate(data = as.Date(data)) %>%
    group_by(data) %>%
    summarise(count = n(), .groups = 'drop') %>%
    arrange(data)
}

prepare_geographic_data <- function(data) {
  data %>%
    group_by(estado) %>%
    summarise(
      count = n(),
      documents = list(titulo),
      .groups = 'drop'
    )
}

prepare_category_data <- function(data) {
  data %>%
    group_by(categoria) %>%
    summarise(count = n(), .groups = 'drop') %>%
    arrange(desc(count))
}

prepare_bar_chart_data <- function(data) {
  data %>%
    group_by(tipo) %>%
    summarise(count = n(), .groups = 'drop') %>%
    arrange(desc(count)) %>%
    head(10)
}

create_empty_chart_data <- function(chart_type) {
  switch(chart_type,
    "timeline" = data.frame(data = as.Date(character()), count = integer()),
    "geographic" = data.frame(estado = character(), count = integer()),
    "category" = data.frame(categoria = character(), count = integer()),
    data.frame(label = character(), count = integer())
  )
}

# Analytics data function (replacing analytics_data_fixed_csv)
# FIX v50: Safe with isTRUE()
# NOTE: Uses Portuguese column names (data, resumo)
get_analytics_data <- function() {
  # Get all documents for analytics
  data <- get_documents(limit = DATA_SERVICE_CONFIG$max_results)

  if (isTRUE(is.null(data)) || isTRUE(!is.data.frame(data)) || isTRUE(nrow(data) == 0)) {
    log_message("No data available for analytics", "WARN")
    return(create_empty_dataset())
  }

  # Prepare for analytics (using Portuguese column names)
  data <- data %>%
    mutate(
      ano = format(as.Date(data), "%Y"),
      mes = format(as.Date(data), "%Y-%m"),
      tem_resumo = !is.na(resumo) & nchar(resumo) > 0
    )

  return(data)
}

# Export functions
list(
  get_documents = get_documents,
  get_analytics_data = get_analytics_data,
  prepare_chart_data = prepare_chart_data,
  build_paginated_library_query = build_paginated_library_query,
  build_count_query = build_count_query,
  build_safe_query = build_safe_query,
  log_message = log_message
)
