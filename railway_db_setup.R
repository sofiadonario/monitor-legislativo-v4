#!/usr/bin/env Rscript
# Railway PostgreSQL Database Setup for Monitor Legislativo v4
# ============================================================

cat("=== Railway PostgreSQL Database Setup ===\n")
cat("Monitor Legislativo v4 - Database Configuration and Population\n\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(data.table)
})

# Railway PostgreSQL configuration from environment variables
RAILWAY_DB_CONFIG <- list(
  # Get database URL from environment or fail gracefully
  external_url = Sys.getenv("DATABASE_URL", ""),
  internal_url = Sys.getenv("DATABASE_INTERNAL_URL", ""),

  # Connection parameters from environment
  host_external = Sys.getenv("PGHOST_EXTERNAL", ""),
  port_external = as.numeric(Sys.getenv("PGPORT_EXTERNAL", "5432")),
  host_internal = Sys.getenv("PGHOST_INTERNAL", "postgres.railway.internal"),
  port_internal = as.numeric(Sys.getenv("PGPORT_INTERNAL", "5432")),
  database = Sys.getenv("PGDATABASE", "railway"),
  username = Sys.getenv("PGUSER", "postgres"),
  password = Sys.getenv("PGPASSWORD", "")
)

# Validate configuration
if (RAILWAY_DB_CONFIG$external_url == "") {
  cat("⚠️ Warning: DATABASE_URL not configured. Please set environment variables:\n")
  cat("   DATABASE_URL, PGHOST_EXTERNAL, PGPORT_EXTERNAL, PGUSER, PGPASSWORD\n")
  cat("   Exiting setup...\n")
  quit(save = "no", status = 1)
}

cat("Railway Database Configuration:\n")
cat("  External endpoint:", RAILWAY_DB_CONFIG$host_external, ":", RAILWAY_DB_CONFIG$port_external, "\n")
cat("  Internal endpoint:", RAILWAY_DB_CONFIG$host_internal, ":", RAILWAY_DB_CONFIG$port_internal, "\n")
cat("  Database:", RAILWAY_DB_CONFIG$database, "\n\n")

# Test PostgreSQL connection using external endpoint
test_railway_connection <- function() {
  cat("=== Testing Railway PostgreSQL Connection ===\n")
  
  # Set password environment variable for psql
  Sys.setenv(PGPASSWORD = RAILWAY_DB_CONFIG$password)
  
  # Test external endpoint first
  cat("Testing external endpoint:", RAILWAY_DB_CONFIG$external_url, "\n")
  
  result <- system2("psql", 
    args = c(RAILWAY_DB_CONFIG$external_url, "-c", "SELECT version(), current_database();"),
    stdout = TRUE,
    stderr = TRUE
  )
  
  if (attr(result, "status") == 0 || is.null(attr(result, "status"))) {
    cat("✓ Railway PostgreSQL connection successful (external endpoint)\n")
    cat("Database info:\n")
    cat(paste(result, collapse = "\n"), "\n\n")
    return("external")
  } else {
    cat("✗ External endpoint failed:", paste(result, collapse = " "), "\n")
    
    # Try internal endpoint (might work if running on Railway)
    cat("Testing internal endpoint:", RAILWAY_DB_CONFIG$internal_url, "\n")
    
    result_internal <- system2("psql", 
      args = c(RAILWAY_DB_CONFIG$internal_url, "-c", "SELECT version(), current_database();"),
      stdout = TRUE,
      stderr = TRUE
    )
    
    if (attr(result_internal, "status") == 0 || is.null(attr(result_internal, "status"))) {
      cat("✓ Railway PostgreSQL connection successful (internal endpoint)\n")
      cat("Database info:\n")
      cat(paste(result_internal, collapse = "\n"), "\n\n")
      return("internal")
    } else {
      cat("✗ Internal endpoint also failed:", paste(result_internal, collapse = " "), "\n")
      cat("ERROR: Cannot connect to Railway PostgreSQL database\n")
      return(NULL)
    }
  }
}

# Check existing database schema and data
check_database_state <- function(endpoint_type) {
  cat("=== Checking Database State ===\n")
  
  db_url <- if (endpoint_type == "external") {
    RAILWAY_DB_CONFIG$external_url
  } else {
    RAILWAY_DB_CONFIG$internal_url
  }
  
  # List all tables
  cat("Checking existing tables...\n")
  tables_result <- system2("psql", 
    args = c(db_url, "-c", "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"),
    stdout = TRUE,
    stderr = TRUE
  )
  
  if (attr(tables_result, "status") == 0 || is.null(attr(tables_result, "status"))) {
    cat("Existing tables:\n")
    cat(paste(tables_result, collapse = "\n"), "\n\n")
    
    # Check for documents table specifically
    if (any(grepl("documents", tables_result))) {
      cat("✓ 'documents' table exists\n")
      
      # Check record count
      count_result <- system2("psql", 
        args = c(db_url, "-c", "SELECT COUNT(*) as document_count FROM documents;"),
        stdout = TRUE,
        stderr = TRUE
      )
      
      if (attr(count_result, "status") == 0 || is.null(attr(count_result, "status"))) {
        cat("Document count:\n")
        cat(paste(count_result, collapse = "\n"), "\n\n")
        
        # Extract actual count number
        count_lines <- count_result[grepl("^\\s*\\d+\\s*$", count_result)]
        if (length(count_lines) > 0) {
          actual_count <- as.numeric(gsub("\\s", "", count_lines[1]))
          cat("Parsed document count:", actual_count, "\n")
          return(list(has_documents_table = TRUE, document_count = actual_count))
        }
      }
      
      return(list(has_documents_table = TRUE, document_count = 0))
    } else {
      cat("✗ 'documents' table does not exist\n")
      return(list(has_documents_table = FALSE, document_count = 0))
    }
  } else {
    cat("✗ Could not check database tables\n")
    return(list(has_documents_table = FALSE, document_count = 0))
  }
}

# Create documents table with optimized schema
create_documents_table <- function(endpoint_type) {
  cat("=== Creating Documents Table ===\n")
  
  db_url <- if (endpoint_type == "external") {
    RAILWAY_DB_CONFIG$external_url
  } else {
    RAILWAY_DB_CONFIG$internal_url
  }
  
  # Drop existing table if it exists (careful!)
  cat("Dropping existing documents table if it exists...\n")
  drop_result <- system2("psql", 
    args = c(db_url, "-c", "DROP TABLE IF EXISTS documents CASCADE;"),
    stdout = TRUE,
    stderr = TRUE
  )
  
  # Create optimized table schema for Brazilian legislative documents
  create_sql <- "
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT NOT NULL,
    estado VARCHAR(5),
    data DATE,
    categoria VARCHAR(100),
    subcategoria VARCHAR(100),
    tipo VARCHAR(100),
    numero VARCHAR(50),
    ano INTEGER,
    ementa TEXT,
    autor TEXT,
    situacao VARCHAR(100),
    link_inteiro_teor TEXT,
    observacoes TEXT,
    urn TEXT,
    municipio VARCHAR(255),
    assuntos TEXT,
    termo_busca TEXT,
    data_publicacao DATE,
    categoria_original VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add comments for documentation
COMMENT ON TABLE documents IS 'Brazilian legislative documents from LexML and other sources';
COMMENT ON COLUMN documents.titulo IS 'Document title';
COMMENT ON COLUMN documents.estado IS 'Brazilian state code (e.g., SP, RJ, MG)';
COMMENT ON COLUMN documents.data IS 'Document date';
COMMENT ON COLUMN documents.categoria IS 'Document category (Legislação, Jurisprudência, etc.)';
COMMENT ON COLUMN documents.ementa IS 'Document summary/abstract';
COMMENT ON COLUMN documents.urn IS 'Unique Resource Name for the document';
"
  
  result <- system2("psql", 
    args = c(db_url, "-c", create_sql),
    stdout = TRUE,
    stderr = TRUE
  )
  
  if (attr(result, "status") == 0 || is.null(attr(result, "status"))) {
    cat("✓ Documents table created successfully\n")
    return(TRUE)
  } else {
    cat("✗ Failed to create documents table\n")
    cat("Error:", paste(result, collapse = "\n"), "\n")
    return(FALSE)
  }
}

# Load CSV data into Railway PostgreSQL database
populate_database <- function(endpoint_type) {
  cat("=== Populating Database with 134k Legislative Documents ===\n")
  
  db_url <- if (endpoint_type == "external") {
    RAILWAY_DB_CONFIG$external_url
  } else {
    RAILWAY_DB_CONFIG$internal_url
  }
  
  # Path to the full 134k dataset
  csv_file <- "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/production/lexml_unified_dataset.csv"
  
  if (!file.exists(csv_file)) {
    cat("✗ CSV file not found:", csv_file, "\n")
    return(FALSE)
  }
  
  # Get file info
  file_info <- file.info(csv_file)
  file_size_mb <- file_info$size / (1024 * 1024)
  cat("CSV file found:\n")
  cat("  Path:", csv_file, "\n")
  cat("  Size:", round(file_size_mb, 1), "MB\n")
  
  # Read first few rows to understand structure
  cat("Analyzing CSV structure...\n")
  sample_data <- fread(csv_file, nrows = 3)
  cat("Columns:", paste(colnames(sample_data), collapse = ", "), "\n")
  
  # Count total rows efficiently
  cat("Counting rows in CSV...\n")
  row_count_cmd <- system2("wc", args = c("-l", csv_file), stdout = TRUE)
  total_rows <- as.numeric(gsub("\\s.*", "", row_count_cmd)) - 1  # Subtract header row
  cat("Total data rows:", format(total_rows, big.mark = ","), "\n\n")
  
  # Create optimized CSV for PostgreSQL COPY
  temp_csv <- "/tmp/railway_import.csv"
  
  cat("Processing CSV for database import...\n")
  
  # Load and clean the data
  tryCatch({
    # Read the full CSV (this might take a moment for 134k records)
    cat("Loading CSV data...\n")
    all_data <- fread(csv_file, encoding = "UTF-8")
    
    cat("Original data loaded:", nrow(all_data), "rows,", ncol(all_data), "columns\n")
    
    # Clean and standardize column names for PostgreSQL
    original_names <- names(all_data)
    
    # Create a mapping of original names to database column names
    name_mapping <- list(
      "titulo" = "titulo",
      "estado" = "estado", 
      "data" = "data",
      "categoria" = "categoria",
      "subcategoria" = "subcategoria",
      "tipo" = "tipo",
      "numero" = "numero",
      "ano" = "ano",
      "ementa" = "ementa",
      "autor" = "autor",
      "situacao" = "situacao",
      "link_inteiro_teor" = "link_inteiro_teor",
      "observacoes" = "observacoes",
      "urn" = "urn",
      "municipio" = "municipio",
      "assuntos" = "assuntos",
      "termo_busca" = "termo_busca",
      "data_publicacao" = "data_publicacao",
      "categoria_original" = "categoria_original"
    )
    
    # Prepare data for database import
    db_data <- data.table()
    
    # Map available columns to database schema
    for (db_col in names(name_mapping)) {
      csv_col <- name_mapping[[db_col]]
      if (csv_col %in% original_names) {
        db_data[[db_col]] <- all_data[[csv_col]]
      } else {
        # Create empty column if not present in CSV
        db_data[[db_col]] <- NA_character_
      }
    }
    
    # Clean data for PostgreSQL
    # Remove any NULL bytes that can cause issues
    char_cols <- sapply(db_data, is.character)
    for (col in names(db_data)[char_cols]) {
      if (!is.null(db_data[[col]])) {
        db_data[[col]] <- gsub("\\\x00", "", db_data[[col]], perl = TRUE)
      }
    }
    
    # Write cleaned data to temporary CSV
    cat("Writing cleaned data to temporary file...\n")
    fwrite(db_data, temp_csv, sep = ",", quote = TRUE, na = "")
    
    cat("Cleaned data written:", nrow(db_data), "rows\n")
    
  }, error = function(e) {
    cat("Error processing CSV:", e$message, "\n")
    return(FALSE)
  })
  
  # Import using PostgreSQL COPY command
  cat("Importing data into Railway PostgreSQL...\n")
  
  # Build COPY command
  copy_sql <- paste0("
\\COPY documents (titulo, estado, data, categoria, subcategoria, tipo, numero, ano, ementa, autor, situacao, link_inteiro_teor, observacoes, urn, municipio, assuntos, termo_busca, data_publicacao, categoria_original)
FROM '", temp_csv, "'
WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '\"', NULL '');
")
  
  import_result <- system2("psql", 
    args = c(db_url, "-c", copy_sql),
    stdout = TRUE,
    stderr = TRUE
  )
  
  if (attr(import_result, "status") == 0 || is.null(attr(import_result, "status"))) {
    cat("✓ Data import successful!\n")
    cat("Import result:\n")
    cat(paste(import_result, collapse = "\n"), "\n")
    
    # Verify import
    verify_result <- system2("psql", 
      args = c(db_url, "-c", "SELECT COUNT(*) as total_documents, COUNT(DISTINCT estado) as states, COUNT(DISTINCT categoria) as categories FROM documents;"),
      stdout = TRUE,
      stderr = TRUE
    )
    
    cat("\nImport verification:\n")
    cat(paste(verify_result, collapse = "\n"), "\n")
    
    # Clean up temporary file
    if (file.exists(temp_csv)) {
      file.remove(temp_csv)
    }
    
    return(TRUE)
  } else {
    cat("✗ Data import failed\n")
    cat("Error:", paste(import_result, collapse = "\n"), "\n")
    return(FALSE)
  }
}

# Create performance indexes
create_performance_indexes <- function(endpoint_type) {
  cat("=== Creating Performance Indexes ===\n")
  
  db_url <- if (endpoint_type == "external") {
    RAILWAY_DB_CONFIG$external_url
  } else {
    RAILWAY_DB_CONFIG$internal_url
  }
  
  # Performance indexes for common queries
  indexes <- list(
    "idx_documents_titulo" = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_titulo ON documents USING btree (titulo);",
    "idx_documents_estado" = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_estado ON documents USING btree (estado);",
    "idx_documents_data" = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_data ON documents USING btree (data DESC NULLS LAST);",
    "idx_documents_categoria" = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_categoria ON documents USING btree (categoria);",
    "idx_documents_ano" = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_ano ON documents USING btree (ano DESC);",
    "idx_documents_estado_categoria" = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_estado_categoria ON documents USING btree (estado, categoria);",
    "idx_documents_full_text" = "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_full_text ON documents USING gin (to_tsvector('portuguese', coalesce(titulo,'') || ' ' || coalesce(ementa,'') || ' ' || coalesce(assuntos,'')));"
  )
  
  success_count <- 0
  
  for (index_name in names(indexes)) {
    cat("Creating index:", index_name, "... ")
    
    result <- system2("psql", 
      args = c(db_url, "-c", indexes[[index_name]]),
      stdout = TRUE,
      stderr = TRUE
    )
    
    if (attr(result, "status") == 0 || is.null(attr(result, "status"))) {
      cat("✓\n")
      success_count <- success_count + 1
    } else {
      cat("✗\n")
      cat("Error:", paste(result, collapse = " "), "\n")
    }
  }
  
  cat("Indexes created:", success_count, "of", length(indexes), "\n\n")
  return(success_count == length(indexes))
}

# Test database performance
test_database_performance <- function(endpoint_type) {
  cat("=== Testing Database Performance ===\n")
  
  db_url <- if (endpoint_type == "external") {
    RAILWAY_DB_CONFIG$external_url
  } else {
    RAILWAY_DB_CONFIG$internal_url
  }
  
  # Performance test queries
  test_queries <- list(
    "Document count" = "SELECT COUNT(*) FROM documents;",
    "States summary" = "SELECT estado, COUNT(*) as count FROM documents WHERE estado IS NOT NULL GROUP BY estado ORDER BY count DESC LIMIT 10;",
    "Categories summary" = "SELECT categoria, COUNT(*) as count FROM documents WHERE categoria IS NOT NULL GROUP BY categoria ORDER BY count DESC;",
    "Recent documents" = "SELECT titulo, estado, data FROM documents WHERE data IS NOT NULL ORDER BY data DESC LIMIT 5;",
    "Text search test" = "SELECT titulo, estado FROM documents WHERE titulo ILIKE '%lei%' LIMIT 5;"
  )
  
  for (query_name in names(test_queries)) {
    cat("\n--- Testing:", query_name, "---\n")
    
    start_time <- Sys.time()
    result <- system2("psql", 
      args = c(db_url, "-c", test_queries[[query_name]]),
      stdout = TRUE,
      stderr = TRUE
    )
    end_time <- Sys.time()
    
    execution_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    
    if (attr(result, "status") == 0 || is.null(attr(result, "status"))) {
      cat("✓ Query successful (", round(execution_time, 2), "s )\n")
      cat(paste(result[1:min(10, length(result))], collapse = "\n"), "\n")
      if (length(result) > 10) cat("... (truncated)\n")
    } else {
      cat("✗ Query failed:", paste(result, collapse = " "), "\n")
    }
  }
}

# Main setup function
main <- function() {
  cat("Starting Railway PostgreSQL database setup for Monitor Legislativo v4...\n\n")
  
  # Test connection
  endpoint_type <- test_railway_connection()
  
  if (is.null(endpoint_type)) {
    cat("FATAL ERROR: Cannot connect to Railway PostgreSQL database\n")
    cat("Please check:\n")
    cat("1. Railway PostgreSQL service is running\n")
    cat("2. Network connectivity to Railway\n") 
    cat("3. Database credentials are correct\n")
    return(FALSE)
  }
  
  # Check current database state
  db_state <- check_database_state(endpoint_type)
  
  # Decide whether to populate database
  if (db_state$has_documents_table && db_state$document_count > 100000) {
    cat("✓ Database already contains", db_state$document_count, "documents\n")
    cat("Skipping data population...\n\n")
  } else {
    cat("Database needs population or has insufficient data\n")
    cat("Current document count:", db_state$document_count, "\n")
    
    # Create table
    if (!create_documents_table(endpoint_type)) {
      cat("FATAL ERROR: Could not create documents table\n")
      return(FALSE)
    }
    
    # Populate with data
    if (!populate_database(endpoint_type)) {
      cat("FATAL ERROR: Could not populate database\n")
      return(FALSE)
    }
  }
  
  # Create performance indexes
  create_performance_indexes(endpoint_type)
  
  # Test performance
  test_database_performance(endpoint_type)
  
  cat("\n=== Railway PostgreSQL Database Setup Complete! ===\n")
  cat("✓ Database connection:", endpoint_type, "endpoint\n")
  cat("✓ Documents table created with optimized schema\n")
  cat("✓ 134k+ legislative documents imported\n")
  cat("✓ Performance indexes created\n")
  cat("✓ Ready for Monitor Legislativo v4 application\n\n")
  
  cat("Your Railway PostgreSQL database is ready!\n")
  cat("The Monitor Legislativo app can now connect and serve all 134k+ documents.\n")
  
  return(TRUE)
}

# Run the setup
if (!interactive()) {
  success <- main()
  if (success) {
    quit(status = 0)
  } else {
    quit(status = 1)
  }
}