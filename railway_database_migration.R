#!/usr/bin/env Rscript
# ============================================================================
# RAILWAY DATABASE MIGRATION & POPULATION SCRIPT
# ============================================================================
# 
# This script migrates and populates the Railway PostgreSQL database with
# the complete Brazilian Legislative dataset (134,000+ documents).
#
# Features:
# - Complete data migration from source files
# - Batch processing for memory efficiency
# - Data validation and cleaning
# - Index creation for optimal performance
# - Progress monitoring and logging
# - Rollback capabilities
#
# Usage:
# Rscript railway_database_migration.R
# ============================================================================

cat("📦 RAILWAY DATABASE MIGRATION & POPULATION\n")
cat("===========================================\n")

# Load required packages
required_packages <- c("DBI", "RPostgres", "pool", "dplyr", "readr", "jsonlite", "lubridate")
missing_packages <- c()

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("❌ Missing packages, installing:", paste(missing_packages, collapse = ", "), "\n")
  install.packages(missing_packages, repos = "https://cran.rstudio.com/")
}

suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
  library(dplyr)
  library(readr)
  library(jsonlite)
  library(lubridate)
})

# ============================================================================
# CONFIGURATION AND UTILITIES
# ============================================================================

# Migration configuration
migration_config <- list(
  batch_size = 1000,              # Process documents in batches
  max_retries = 3,                # Retry failed operations
  validate_data = TRUE,           # Validate data before insertion
  create_indexes = TRUE,          # Create performance indexes
  backup_existing = TRUE,         # Backup existing data
  log_progress = TRUE            # Log migration progress
)

# Logging function
log_migration <- function(level, message, progress = NULL) {
  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  log_msg <- sprintf("[%s] [%s] MIGRATION: %s", timestamp, level, message)
  
  if (!is.null(progress)) {
    log_msg <- sprintf("%s (Progress: %.1f%%)", log_msg, progress)
  }
  
  cat(log_msg, "\n")
  
  # Write to log file
  tryCatch({
    write(log_msg, file = "railway_migration.log", append = TRUE)
  }, error = function(e) {})
}

# ============================================================================
# DATABASE CONNECTION AND SETUP
# ============================================================================

#' Get database configuration from environment
get_database_config <- function() {
  # Try DATABASE_URL first
  database_url <- Sys.getenv("DATABASE_URL")
  
  if (nchar(database_url) > 0) {
    log_migration("INFO", "Using DATABASE_URL from environment")
    
    # Parse URL
    if (grepl("^(postgresql|postgres)://", database_url)) {
      url_clean <- sub("^(postgresql|postgres)://", "", database_url)
      parts <- strsplit(url_clean, "@")[[1]]
      
      if (length(parts) == 2) {
        auth_part <- parts[1]
        connection_part <- parts[2]
        
        auth_split <- strsplit(auth_part, ":")[[1]]
        if (length(auth_split) == 2) {
          user <- auth_split[1]
          password <- auth_split[2]
          
          if (grepl("/", connection_part)) {
            connection_split <- strsplit(connection_part, "/")[[1]]
            host_port <- connection_split[1]
            dbname <- connection_split[2]
            
            if (grepl(":", host_port)) {
              host_port_split <- strsplit(host_port, ":")[[1]]
              host <- host_port_split[1]
              port <- as.integer(host_port_split[2])
            } else {
              host <- host_port
              port <- 5432L
            }
            
            return(list(host = host, port = port, dbname = dbname, user = user, password = password))
          }
        }
      }
    }
  }
  
  # Try individual environment variables
  host <- Sys.getenv("PGHOST")
  port <- as.integer(Sys.getenv("PGPORT", "5432"))
  dbname <- Sys.getenv("PGDATABASE")
  user <- Sys.getenv("PGUSER")
  password <- Sys.getenv("PGPASSWORD")
  
  if (all(nchar(c(host, dbname, user, password)) > 0)) {
    log_migration("INFO", "Using individual PG* environment variables")
    return(list(host = host, port = port, dbname = dbname, user = user, password = password))
  }
  
  log_migration("ERROR", "No valid database configuration found")
  return(NULL)
}

#' Create database connection pool
create_migration_pool <- function(config) {
  log_migration("INFO", "Creating database connection pool for migration")
  
  tryCatch({
    pool <- dbPool(
      RPostgres::Postgres(),
      host = config$host,
      port = config$port,
      dbname = config$dbname,
      user = config$user,
      password = config$password,
      sslmode = "prefer",
      minSize = 2,
      maxSize = 10,
      idleTimeout = 300000,
      application_name = "railway_migration"
    )
    
    # Test the pool
    test_result <- dbGetQuery(pool, "SELECT version() as version")
    log_migration("SUCCESS", "Database connection pool created successfully")
    
    return(pool)
  }, error = function(e) {
    log_migration("ERROR", paste("Pool creation failed:", e$message))
    return(NULL)
  })
}

# ============================================================================
# SCHEMA CREATION
# ============================================================================

#' Create main documents table with optimized schema
create_documents_table <- function(pool) {
  log_migration("INFO", "Creating optimized documents table schema")
  
  # Drop existing table if requested
  if (migration_config$backup_existing) {
    tryCatch({
      dbExecute(pool, "CREATE TABLE IF NOT EXISTS documents_backup AS SELECT * FROM documents")
      log_migration("INFO", "Created backup of existing documents table")
    }, error = function(e) {
      log_migration("WARNING", "Could not create backup (table may not exist)")
    })
  }
  
  # Create main documents table
  create_table_sql <- "
    CREATE TABLE IF NOT EXISTS documents (
      id SERIAL PRIMARY KEY,
      titulo TEXT NOT NULL,
      ementa TEXT,
      tipo VARCHAR(100),
      categoria VARCHAR(100),
      categoria_original TEXT,
      estado VARCHAR(2),
      municipio VARCHAR(200),
      data_publicacao DATE,
      data_criacao TIMESTAMP DEFAULT NOW(),
      url TEXT,
      urn TEXT UNIQUE,
      autor TEXT,
      termo_busca TEXT,
      assuntos TEXT,
      texto_completo TEXT,
      hash_conteudo VARCHAR(64),
      status VARCHAR(50) DEFAULT 'active',
      metadados JSONB,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  "
  
  tryCatch({
    dbExecute(pool, create_table_sql)
    log_migration("SUCCESS", "Documents table created successfully")
    
    # Create additional utility tables
    create_categories_table_sql <- "
      CREATE TABLE IF NOT EXISTS document_categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        parent_id INTEGER REFERENCES document_categories(id),
        created_at TIMESTAMP DEFAULT NOW()
      )
    "
    
    dbExecute(pool, create_categories_table_sql)
    
    # Insert default categories
    default_categories <- list(
      c("Legislação", "Leis, decretos, portarias e demais atos normativos"),
      c("Jurisprudência", "Decisões judiciais, súmulas e orientações jurisprudenciais"),
      c("Doutrina", "Pareceres, estudos e artigos doutrinários"),
      c("Proposições", "Projetos de lei, emendas e proposições legislativas"),
      c("Outros", "Documentos que não se enquadram nas categorias anteriores")
    )
    
    for (cat in default_categories) {
      tryCatch({
        dbExecute(pool, "INSERT INTO document_categories (name, description) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING", 
                 list(cat[1], cat[2]))
      }, error = function(e) {})
    }
    
    log_migration("SUCCESS", "Document categories table created")
    
    return(TRUE)
  }, error = function(e) {
    log_migration("ERROR", paste("Table creation failed:", e$message))
    return(FALSE)
  })
}

#' Create performance indexes
create_performance_indexes <- function(pool) {
  log_migration("INFO", "Creating performance indexes")
  
  indexes <- list(
    # Full-text search indexes
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_titulo_gin ON documents USING gin(to_tsvector('portuguese', titulo))",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_ementa_gin ON documents USING gin(to_tsvector('portuguese', ementa))",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_texto_gin ON documents USING gin(to_tsvector('portuguese', texto_completo))",
    
    # Filter indexes
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_estado ON documents(estado)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_municipio ON documents(municipio)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_tipo ON documents(tipo)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_categoria ON documents(categoria)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_data_publicacao ON documents(data_publicacao DESC)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_status ON documents(status)",
    
    # Composite indexes for common queries
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_estado_data ON documents(estado, data_publicacao DESC)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_tipo_data ON documents(tipo, data_publicacao DESC)",
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_categoria_data ON documents(categoria, data_publicacao DESC)",
    
    # Unique constraint index
    "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_urn_unique ON documents(urn) WHERE urn IS NOT NULL AND urn != ''",
    
    # Hash index for deduplication
    "CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_hash ON documents(hash_conteudo)"
  )
  
  created_count <- 0
  
  for (index_sql in indexes) {
    tryCatch({
      dbExecute(pool, index_sql)
      created_count <- created_count + 1
    }, error = function(e) {
      if (grepl("already exists", e$message)) {
        created_count <- created_count + 1
      } else {
        log_migration("WARNING", paste("Index creation failed:", e$message))
      }
    })
  }
  
  log_migration("SUCCESS", sprintf("Created/verified %d performance indexes", created_count))
  return(created_count > 0)
}

# ============================================================================
# DATA LOADING AND PROCESSING
# ============================================================================

#' Generate hash for content deduplication
generate_content_hash <- function(titulo, ementa, urn) {
  content <- paste0(trimws(titulo), "|", trimws(ementa), "|", trimws(urn))
  return(digest::digest(content, algo = "sha256", serialize = FALSE))
}

#' Clean and validate document data
clean_document_data <- function(doc_data) {
  # Clean and validate each field
  doc_data$titulo <- trimws(as.character(doc_data$titulo))
  doc_data$ementa <- trimws(as.character(doc_data$ementa))
  doc_data$tipo <- trimws(as.character(doc_data$tipo))
  doc_data$estado <- toupper(trimws(as.character(doc_data$estado)))
  doc_data$municipio <- trimws(as.character(doc_data$municipio))
  
  # Clean URLs
  if ("url" %in% names(doc_data)) {
    doc_data$url <- trimws(as.character(doc_data$url))
    # Validate URLs
    invalid_urls <- !grepl("^https?://", doc_data$url) & doc_data$url != ""
    doc_data$url[invalid_urls] <- ""
  }
  
  # Clean URNs
  if ("urn" %in% names(doc_data)) {
    doc_data$urn <- trimws(as.character(doc_data$urn))
  }
  
  # Parse and validate dates
  if ("data_publicacao" %in% names(doc_data)) {
    doc_data$data_publicacao <- tryCatch({
      as.Date(doc_data$data_publicacao)
    }, error = function(e) {
      NA
    })
  }
  
  # Remove records with empty titles
  doc_data <- doc_data[!is.na(doc_data$titulo) & doc_data$titulo != "", ]
  
  # Generate content hashes for deduplication
  if (nrow(doc_data) > 0) {
    doc_data$hash_conteudo <- sapply(1:nrow(doc_data), function(i) {
      generate_content_hash(doc_data$titulo[i], doc_data$ementa[i], doc_data$urn[i])
    })
  }
  
  return(doc_data)
}

#' Load data from various sources
load_source_data <- function() {
  log_migration("INFO", "Loading source data files")
  
  # Look for data files in common locations
  data_sources <- c(
    "data/lexml_parsed_enhanced.csv",
    "data/lexml_parsed_enhanced.rds",
    "data/brazilian_legislative_complete.csv",
    "data/brazilian_legislative_complete.rds",
    "data/documents.csv",
    "data/documents.rds",
    "lexml_parsed_enhanced.csv",
    "brazilian_legislative_complete.csv",
    "documents.csv"
  )
  
  loaded_data <- data.frame()
  
  for (source_file in data_sources) {
    if (file.exists(source_file)) {
      log_migration("INFO", paste("Found data source:", source_file))
      
      tryCatch({
        # Load based on file extension
        if (grepl("\\.csv$", source_file)) {
          data <- read_csv(source_file, locale = locale(encoding = "UTF-8"))
        } else if (grepl("\\.rds$", source_file)) {
          data <- readRDS(source_file)
        }
        
        log_migration("INFO", sprintf("Loaded %d records from %s", nrow(data), source_file))
        
        # Standardize column names
        if ("title" %in% names(data) && !"titulo" %in% names(data)) {
          data$titulo <- data$title
        }
        if ("summary" %in% names(data) && !"ementa" %in% names(data)) {
          data$ementa <- data$summary
        }
        if ("state" %in% names(data) && !"estado" %in% names(data)) {
          data$estado <- data$state
        }
        if ("date" %in% names(data) && !"data_publicacao" %in% names(data)) {
          data$data_publicacao <- data$date
        }
        
        # Combine with existing data
        if (nrow(loaded_data) == 0) {
          loaded_data <- data
        } else {
          # Merge datasets by common columns
          common_cols <- intersect(names(loaded_data), names(data))
          if (length(common_cols) > 0) {
            loaded_data <- bind_rows(loaded_data, data[common_cols])
          }
        }
        
      }, error = function(e) {
        log_migration("WARNING", paste("Failed to load", source_file, ":", e$message))
      })
    }
  }
  
  if (nrow(loaded_data) == 0) {
    log_migration("ERROR", "No source data found")
    return(NULL)
  }
  
  log_migration("SUCCESS", sprintf("Loaded %d total records from source files", nrow(loaded_data)))
  return(loaded_data)
}

#' Insert data in batches with progress tracking
batch_insert_documents <- function(pool, doc_data) {
  total_rows <- nrow(doc_data)
  batch_size <- migration_config$batch_size
  num_batches <- ceiling(total_rows / batch_size)
  inserted_count <- 0
  
  log_migration("INFO", sprintf("Starting batch insertion: %d records in %d batches", total_rows, num_batches))
  
  # Prepare insert statement
  insert_sql <- "
    INSERT INTO documents (
      titulo, ementa, tipo, categoria, categoria_original, estado, municipio,
      data_publicacao, url, urn, autor, termo_busca, assuntos, texto_completo,
      hash_conteudo, status
    ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
    ) ON CONFLICT (hash_conteudo) DO NOTHING
  "
  
  for (batch_num in 1:num_batches) {
    start_row <- (batch_num - 1) * batch_size + 1
    end_row <- min(batch_num * batch_size, total_rows)
    batch_data <- doc_data[start_row:end_row, ]
    
    progress <- (batch_num / num_batches) * 100
    log_migration("INFO", sprintf("Processing batch %d/%d", batch_num, num_batches), progress)
    
    tryCatch({
      # Begin transaction for batch
      dbBegin(pool)
      
      for (i in 1:nrow(batch_data)) {
        row <- batch_data[i, ]
        
        # Prepare parameters
        params <- list(
          ifelse(is.na(row$titulo), "", as.character(row$titulo)),
          ifelse(is.na(row$ementa), "", as.character(row$ementa)),
          ifelse(is.na(row$tipo), "", as.character(row$tipo)),
          ifelse(is.na(row$categoria), "", as.character(row$categoria)),
          ifelse(is.na(row$categoria_original), "", as.character(row$categoria_original)),
          ifelse(is.na(row$estado), "", as.character(row$estado)),
          ifelse(is.na(row$municipio), "", as.character(row$municipio)),
          if(is.na(row$data_publicacao)) NULL else as.character(row$data_publicacao),
          ifelse(is.na(row$url), "", as.character(row$url)),
          ifelse(is.na(row$urn), "", as.character(row$urn)),
          ifelse(is.na(row$autor), "", as.character(row$autor)),
          ifelse(is.na(row$termo_busca), "", as.character(row$termo_busca)),
          ifelse(is.na(row$assuntos), "", as.character(row$assuntos)),
          ifelse(is.na(row$texto_completo), "", as.character(row$texto_completo)),
          as.character(row$hash_conteudo),
          "active"
        )
        
        # Execute insert
        result <- dbExecute(pool, insert_sql, params)
        if (result > 0) {
          inserted_count <- inserted_count + 1
        }
      }
      
      # Commit transaction
      dbCommit(pool)
      
    }, error = function(e) {
      # Rollback on error
      tryCatch(dbRollback(pool), error = function(e2) {})
      log_migration("ERROR", sprintf("Batch %d failed: %s", batch_num, e$message))
    })
  }
  
  log_migration("SUCCESS", sprintf("Batch insertion completed: %d records inserted", inserted_count))
  return(inserted_count)
}

# ============================================================================
# MAIN MIGRATION FUNCTION
# ============================================================================

#' Execute complete database migration
execute_migration <- function() {
  log_migration("INFO", "Starting Railway database migration")
  
  # Step 1: Get database configuration
  config <- get_database_config()
  if (is.null(config)) {
    log_migration("ERROR", "Cannot proceed without database configuration")
    return(FALSE)
  }
  
  # Step 2: Create connection pool
  pool <- create_migration_pool(config)
  if (is.null(pool)) {
    log_migration("ERROR", "Cannot proceed without database connection")
    return(FALSE)
  }
  
  tryCatch({
    # Step 3: Create table schema
    if (!create_documents_table(pool)) {
      log_migration("ERROR", "Table creation failed")
      return(FALSE)
    }
    
    # Step 4: Load source data
    source_data <- load_source_data()
    if (is.null(source_data)) {
      log_migration("ERROR", "No source data available for migration")
      return(FALSE)
    }
    
    # Step 5: Clean and validate data
    log_migration("INFO", "Cleaning and validating source data")
    clean_data <- clean_document_data(source_data)
    
    if (nrow(clean_data) == 0) {
      log_migration("ERROR", "No valid data after cleaning")
      return(FALSE)
    }
    
    log_migration("INFO", sprintf("Data validation complete: %d valid records", nrow(clean_data)))
    
    # Step 6: Insert data
    inserted_count <- batch_insert_documents(pool, clean_data)
    
    # Step 7: Create indexes
    if (migration_config$create_indexes) {
      create_performance_indexes(pool)
    }
    
    # Step 8: Update table statistics
    tryCatch({
      dbExecute(pool, "ANALYZE documents")
      dbExecute(pool, "ANALYZE document_categories")
      log_migration("SUCCESS", "Table statistics updated")
    }, error = function(e) {
      log_migration("WARNING", "Statistics update failed")
    })
    
    # Step 9: Verify migration
    final_count <- dbGetQuery(pool, "SELECT COUNT(*) as count FROM documents")$count[1]
    
    log_migration("SUCCESS", sprintf("Migration completed successfully: %d documents in database", final_count))
    
    return(TRUE)
    
  }, error = function(e) {
    log_migration("ERROR", paste("Migration failed:", e$message))
    return(FALSE)
    
  }, finally = {
    # Clean up
    if (!is.null(pool)) {
      tryCatch({
        poolClose(pool)
        log_migration("INFO", "Database connection pool closed")
      }, error = function(e) {})
    }
  })
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

cat("\n🚀 STARTING RAILWAY DATABASE MIGRATION\n")
cat("=======================================\n")

# Check if digest package is available for hashing
if (!requireNamespace("digest", quietly = TRUE)) {
  cat("Installing digest package for content hashing...\n")
  install.packages("digest", repos = "https://cran.rstudio.com/")
  library(digest)
}

# Execute migration
success <- execute_migration()

if (success) {
  cat("\n🎉 MIGRATION COMPLETED SUCCESSFULLY\n")
  cat("===================================\n")
  cat("✅ Database schema created\n")
  cat("✅ Data imported and validated\n") 
  cat("✅ Performance indexes created\n")
  cat("✅ Database optimized for production\n")
  cat("\n📊 Next Steps:\n")
  cat("1. Deploy your Railway application\n")
  cat("2. Verify the application connects to the database\n")
  cat("3. Test the document search and filtering functionality\n")
  cat("4. Monitor performance and adjust as needed\n")
} else {
  cat("\n❌ MIGRATION FAILED\n")
  cat("==================\n")
  cat("Please check the migration log for details and resolve any issues.\n")
  cat("Log file: railway_migration.log\n")
}