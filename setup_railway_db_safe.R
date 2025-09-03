#!/usr/bin/env Rscript
# Safe Railway PostgreSQL Database Setup for Monitor Legislativo v4
# ==================================================================

cat("=== Safe Railway PostgreSQL Database Setup ===\n")
cat("Monitor Legislativo v4 - Database Setup with Data Cleaning\n\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(data.table)
})

# Railway configuration
DB_CONFIG <- list(
  external_url = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway",
  internal_url = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway"
)

# Test connection function
test_connection <- function() {
  cat("Testing Railway PostgreSQL connection...\n")
  
  # Set password for psql
  Sys.setenv(PGPASSWORD = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY")
  
  # Test external endpoint
  result <- system2("psql", 
    args = c(DB_CONFIG$external_url, "-c", "SELECT current_database(), version();"),
    stdout = TRUE,
    stderr = TRUE
  )
  
  if (attr(result, "status") == 0 || is.null(attr(result, "status"))) {
    cat("✓ Connected to Railway PostgreSQL (external endpoint)\n")
    return("external")
  }
  
  # Test internal endpoint
  result_internal <- system2("psql", 
    args = c(DB_CONFIG$internal_url, "-c", "SELECT current_database(), version();"),
    stdout = TRUE,
    stderr = TRUE
  )
  
  if (attr(result_internal, "status") == 0 || is.null(attr(result_internal, "status"))) {
    cat("✓ Connected to Railway PostgreSQL (internal endpoint)\n")
    return("internal")
  }
  
  cat("✗ Cannot connect to Railway PostgreSQL database\n")
  return(NULL)
}

# Check database state
check_db_state <- function(endpoint_type) {
  cat("Checking database state...\n")
  
  db_url <- if (endpoint_type == "external") DB_CONFIG$external_url else DB_CONFIG$internal_url
  
  # Check if documents table exists and get count
  result <- system2("psql", 
    args = c(db_url, "-c", "SELECT COUNT(*) FROM documents;"),
    stdout = TRUE,
    stderr = TRUE
  )
  
  if (attr(result, "status") == 0 || is.null(attr(result, "status"))) {
    # Parse count from result
    count_lines <- result[grepl("^\\s*\\d+\\s*$", result)]
    if (length(count_lines) > 0) {
      count <- as.numeric(gsub("\\s", "", count_lines[1]))
      cat("✓ Documents table exists with", count, "records\n")
      return(count)
    }
  }
  
  cat("✗ Documents table does not exist or is empty\n")
  return(0)
}

# Create documents table
create_table <- function(endpoint_type) {
  cat("Creating documents table...\n")
  
  db_url <- if (endpoint_type == "external") DB_CONFIG$external_url else DB_CONFIG$internal_url
  
  # Simple, clean table structure
  create_sql <- "
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT,
    estado VARCHAR(5),
    data DATE,
    categoria VARCHAR(100),
    tipo VARCHAR(100),
    ementa TEXT,
    autor TEXT,
    urn TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
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
    return(FALSE)
  }
}

# Safely load and clean CSV data
load_clean_data <- function() {
  cat("Loading and cleaning CSV data...\n")
  
  csv_file <- "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/production/lexml_unified_dataset.csv"
  
  if (!file.exists(csv_file)) {
    cat("✗ CSV file not found:", csv_file, "\n")
    return(NULL)
  }
  
  # Load data in chunks to handle large file
  tryCatch({
    cat("Reading CSV file...\n")
    
    # First read just the header to understand structure
    header <- read.csv(csv_file, nrows = 1, stringsAsFactors = FALSE)
    cat("CSV columns:", paste(names(header), collapse = ", "), "\n")
    
    # Read full data with error handling
    all_data <- read.csv(csv_file, stringsAsFactors = FALSE, fileEncoding = "UTF-8")
    cat("Loaded", nrow(all_data), "rows from CSV\n")
    
    # Clean data to prevent database issues
    cat("Cleaning data...\n")
    
    # Remove null bytes and other problematic characters
    clean_text <- function(x) {
      if (is.character(x)) {
        # Remove null bytes, replace with empty string
        x <- gsub("\\0", "", x, perl = TRUE)
        # Remove other control characters
        x <- gsub("[\\x01-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", "", x, perl = TRUE)
        # Trim whitespace
        x <- trimws(x)
      }
      return(x)
    }
    
    # Apply cleaning to all character columns
    char_cols <- sapply(all_data, is.character)
    all_data[char_cols] <- lapply(all_data[char_cols], clean_text)
    
    # Select and rename columns for database
    clean_data <- data.frame(
      titulo = if("titulo" %in% names(all_data)) all_data$titulo else "",
      estado = if("estado" %in% names(all_data)) all_data$estado else "",
      data = if("data" %in% names(all_data)) all_data$data else as.Date(NA),
      categoria = if("categoria" %in% names(all_data)) all_data$categoria else "",
      tipo = if("tipo" %in% names(all_data)) all_data$tipo else "",
      ementa = if("ementa" %in% names(all_data)) all_data$ementa else "",
      autor = if("autor" %in% names(all_data)) all_data$autor else "",
      urn = if("urn" %in% names(all_data)) all_data$urn else "",
      stringsAsFactors = FALSE
    )
    
    # Remove rows with completely empty titles
    clean_data <- clean_data[!is.na(clean_data$titulo) & clean_data$titulo != "", ]
    
    cat("Cleaned data:", nrow(clean_data), "valid rows\n")
    
    return(clean_data)
    
  }, error = function(e) {
    cat("Error loading CSV:", e$message, "\n")
    return(NULL)
  })
}

# Populate database with cleaned data
populate_db <- function(endpoint_type, clean_data) {
  cat("Populating database with cleaned data...\n")
  
  db_url <- if (endpoint_type == "external") DB_CONFIG$external_url else DB_CONFIG$internal_url
  
  # Write to temporary CSV for bulk import
  temp_csv <- "/tmp/clean_data.csv"
  
  tryCatch({
    # Write cleaned data
    write.csv(clean_data, temp_csv, row.names = FALSE, na = "")
    
    cat("Temporary file created:", temp_csv, "\n")
    cat("File size:", round(file.size(temp_csv) / (1024*1024), 1), "MB\n")
    
    # Use COPY command for bulk insert
    copy_sql <- paste0("
\\COPY documents (titulo, estado, data, categoria, tipo, ementa, autor, urn)
FROM '", temp_csv, "'
WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '\"', NULL '');
")
    
    result <- system2("psql", 
      args = c(db_url, "-c", copy_sql),
      stdout = TRUE,
      stderr = TRUE
    )
    
    if (attr(result, "status") == 0 || is.null(attr(result, "status"))) {
      cat("✓ Data imported successfully\n")
      
      # Verify import
      verify_result <- system2("psql", 
        args = c(db_url, "-c", "SELECT COUNT(*) FROM documents;"),
        stdout = TRUE,
        stderr = TRUE
      )
      
      cat("Import verification:\n")
      cat(paste(verify_result, collapse = "\n"), "\n")
      
      # Clean up temp file
      if (file.exists(temp_csv)) file.remove(temp_csv)
      
      return(TRUE)
    } else {
      cat("✗ Data import failed\n")
      cat("Error:", paste(result, collapse = "\n"), "\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("Error during population:", e$message, "\n")
    return(FALSE)
  })
}

# Create basic indexes
create_indexes <- function(endpoint_type) {
  cat("Creating performance indexes...\n")
  
  db_url <- if (endpoint_type == "external") DB_CONFIG$external_url else DB_CONFIG$internal_url
  
  indexes <- list(
    "CREATE INDEX IF NOT EXISTS idx_docs_titulo ON documents(titulo);",
    "CREATE INDEX IF NOT EXISTS idx_docs_estado ON documents(estado);", 
    "CREATE INDEX IF NOT EXISTS idx_docs_categoria ON documents(categoria);",
    "CREATE INDEX IF NOT EXISTS idx_docs_data ON documents(data DESC);"
  )
  
  success_count <- 0
  for (idx_sql in indexes) {
    result <- system2("psql", 
      args = c(db_url, "-c", idx_sql),
      stdout = TRUE,
      stderr = TRUE
    )
    
    if (attr(result, "status") == 0 || is.null(attr(result, "status"))) {
      success_count <- success_count + 1
    }
  }
  
  cat("✓ Created", success_count, "of", length(indexes), "indexes\n")
  return(success_count > 0)
}

# Main execution
main <- function() {
  cat("Starting Railway database setup...\n\n")
  
  # Test connection
  endpoint_type <- test_connection()
  if (is.null(endpoint_type)) {
    cat("FATAL: Cannot connect to database\n")
    return(FALSE)
  }
  
  # Check current state
  current_count <- check_db_state(endpoint_type)
  
  if (current_count > 100000) {
    cat("✓ Database already populated with", current_count, "documents\n")
  } else {
    cat("Database needs population (current count:", current_count, ")\n")
    
    # Create table
    if (!create_table(endpoint_type)) {
      return(FALSE)
    }
    
    # Load and clean data
    clean_data <- load_clean_data()
    if (is.null(clean_data)) {
      return(FALSE)
    }
    
    # Populate database
    if (!populate_db(endpoint_type, clean_data)) {
      return(FALSE)
    }
  }
  
  # Create indexes
  create_indexes(endpoint_type)
  
  # Final verification
  final_count <- check_db_state(endpoint_type)
  
  cat("\n=== Setup Complete ===\n")
  cat("✓ Railway PostgreSQL database ready\n")
  cat("✓ Final document count:", final_count, "\n")
  cat("✓ Monitor Legislativo app can now connect to database\n\n")
  
  return(TRUE)
}

# Run setup
if (!interactive()) {
  success <- main()
  quit(status = if(success) 0 else 1)
}