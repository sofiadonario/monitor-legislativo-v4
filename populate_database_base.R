#!/usr/bin/env Rscript
# Railway Database Population Script (Base R version)
# ===================================================

cat("==============================================\n")
cat("RAILWAY DATABASE POPULATION - FULL DATASET\n")
cat("==============================================\n")

# Check if required packages are available
has_dbi <- requireNamespace("DBI", quietly = TRUE)
has_postgres <- requireNamespace("RPostgres", quietly = TRUE)

if (!has_dbi || !has_postgres) {
  cat("❌ Required database packages not available\n")
  cat("   DBI available:", has_dbi, "\n")
  cat("   RPostgres available:", has_postgres, "\n")
  cat("   Install with: install.packages(c('DBI', 'RPostgres'))\n")
  quit(status = 1)
}

# Load required libraries
library(DBI)
library(RPostgres)

# Database configuration
DB_CONFIG <- list(
  host = "nozomi.proxy.rlwy.net",
  port = 44844,
  database = "railway",
  user = "postgres",
  password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
)

# Test dataset path
csv_path <- "data_current/processed/production/lexml_unified_dataset.csv"

# Check if dataset exists
if (!file.exists(csv_path)) {
  cat("❌ Dataset not found at:", csv_path, "\n")
  cat("   Please ensure the full dataset is available\n")
  quit(status = 1)
}

cat("✅ Found dataset at:", csv_path, "\n")

# Connect to database
cat("\n📡 Connecting to Railway PostgreSQL...\n")
conn <- tryCatch({
  dbConnect(
    RPostgres::Postgres(),
    host = DB_CONFIG$host,
    port = DB_CONFIG$port,
    dbname = DB_CONFIG$database,
    user = DB_CONFIG$user,
    password = DB_CONFIG$password,
    sslmode = "prefer",
    connect_timeout = 30
  )
}, error = function(e) {
  cat("❌ Failed to connect to database:", e$message, "\n")
  quit(status = 1)
})

cat("✅ Connected to Railway database\n")

# Check if documents table exists
table_exists <- dbExistsTable(conn, "documents")
if (!table_exists) {
  cat("\n🔧 Creating documents table...\n")
  create_table_sql <- "
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      titulo TEXT,
      autoridade TEXT,
      data DATE,
      tipo TEXT,
      estado TEXT,
      municipio TEXT,
      categoria TEXT,
      urn TEXT,
      ementa TEXT,
      publicacao_data TEXT,
      jurisdiction_level TEXT,
      population BIGINT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  "
  dbExecute(conn, create_table_sql)
  cat("✅ Documents table created\n")
}

# Check current document count
current_count <- tryCatch({
  result <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
  result$count[1]
}, error = function(e) {
  cat("⚠️ Could not get current count:", e$message, "\n")
  0
})

cat("📊 Current documents in database:", format(current_count, big.mark = ","), "\n")

# If database already has many documents, ask if we should proceed
if (current_count > 50000) {
  cat("⚠️ Database already contains many documents. Skipping population.\n")
  cat("   To force repopulation, manually truncate the documents table first.\n")
  dbDisconnect(conn)
  quit(status = 0)
}

# Load dataset in chunks for memory efficiency
cat("\n📁 Loading dataset in chunks for efficient processing...\n")

# First, get the total number of lines
total_lines <- as.numeric(system(paste("wc -l", shQuote(csv_path), "| cut -d' ' -f1"), intern = TRUE)) - 1
cat("📊 Total documents to process:", format(total_lines, big.mark = ","), "\n")

# Define chunk size
chunk_size <- 10000
n_chunks <- ceiling(total_lines / chunk_size)

cat("\n📤 Processing", n_chunks, "chunks of", format(chunk_size, big.mark = ","), "documents\n")

# Process in chunks
successful_inserts <- 0

for (chunk_i in 1:min(n_chunks, 15)) {  # Limit to first 15 chunks for safety
  cat("   Processing chunk", chunk_i, "/", min(n_chunks, 15), "...\n")
  
  skip_lines <- (chunk_i - 1) * chunk_size
  
  tryCatch({
    # Read chunk
    chunk_data <- read.csv(
      csv_path, 
      skip = skip_lines, 
      nrows = chunk_size,
      header = if(chunk_i == 1) TRUE else FALSE,
      stringsAsFactors = FALSE,
      encoding = "UTF-8"
    )
    
    # If not first chunk, set proper column names
    if (chunk_i > 1 && file.exists(csv_path)) {
      # Get header from first line
      header_line <- readLines(csv_path, n = 1)
      col_names <- strsplit(header_line, ",")[[1]]
      col_names <- gsub('"', '', col_names)  # Remove quotes if present
      names(chunk_data) <- col_names[1:ncol(chunk_data)]
    }
    
    # Skip if no data
    if (nrow(chunk_data) == 0) {
      cat("     No data in chunk, skipping\\n")
      next
    }
    
    # Clean and prepare data
    required_cols <- c("id", "titulo", "autoridade", "data", "tipo", "estado", "municipio", "categoria")
    
    # Add missing columns with defaults
    for (col in required_cols) {
      if (!col %in% names(chunk_data)) {
        chunk_data[[col]] <- NA_character_
      }
    }
    
    # Ensure ID column
    if (is.na(chunk_data$id) || all(chunk_data$id == "")) {
      chunk_data$id <- paste0("DOC_", seq_len(nrow(chunk_data)) + skip_lines)
    }
    
    # Clean data
    chunk_data$titulo[is.na(chunk_data$titulo)] <- "Sem título"
    chunk_data$autoridade[is.na(chunk_data$autoridade)] <- "Não especificada"
    chunk_data$tipo[is.na(chunk_data$tipo)] <- "Outro"
    chunk_data$estado[is.na(chunk_data$estado)] <- "BR"
    chunk_data$municipio[is.na(chunk_data$municipio)] <- ""
    chunk_data$categoria[is.na(chunk_data$categoria)] <- "Geral"
    
    # Convert date column
    if ("data" %in% names(chunk_data)) {
      chunk_data$data <- as.Date(chunk_data$data)
    }
    
    # Select only the columns we need
    final_data <- chunk_data[, required_cols, drop = FALSE]
    
    # Insert into database
    dbWriteTable(conn, "documents", final_data, append = TRUE, overwrite = FALSE)
    
    successful_inserts <- successful_inserts + nrow(final_data)
    cat("     ✅ Inserted", format(nrow(final_data), big.mark = ","), "documents\\n")
    
  }, error = function(e) {
    cat("     ⚠️ Chunk", chunk_i, "failed:", e$message, "\\n")
  })
  
  # Small delay to avoid overwhelming the database
  Sys.sleep(0.5)
}

# Final verification
final_count <- tryCatch({
  result <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
  result$count[1]
}, error = function(e) {
  cat("⚠️ Could not get final count:", e$message, "\n")
  0
})

cat("\n📊 Database population summary:\n")
cat("   Starting count:", format(current_count, big.mark = ","), "\n")
cat("   Documents processed:", format(successful_inserts, big.mark = ","), "\n") 
cat("   Final count:", format(final_count, big.mark = ","), "\n")

# Create basic indexes
cat("\n🔧 Creating performance indexes...\n")
indexes <- c(
  "CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado)",
  "CREATE INDEX IF NOT EXISTS idx_documents_municipio ON documents(municipio)", 
  "CREATE INDEX IF NOT EXISTS idx_documents_categoria ON documents(categoria)",
  "CREATE INDEX IF NOT EXISTS idx_documents_data ON documents(data)"
)

for (idx_sql in indexes) {
  tryCatch({
    dbExecute(conn, idx_sql)
    idx_name <- sub("CREATE INDEX IF NOT EXISTS ", "", sub(" ON.*", "", idx_sql))
    cat("   ✅", idx_name, "\n")
  }, error = function(e) {
    cat("   ⚠️ Index creation failed:", e$message, "\n")
  })
}

# Update statistics
tryCatch({
  dbExecute(conn, "ANALYZE documents")
  cat("✅ Database statistics updated\n")
}, error = function(e) {
  cat("⚠️ Statistics update failed:", e$message, "\n")
})

# Disconnect
dbDisconnect(conn)

cat("\n🎉 Database population complete!\n")
cat("   Final document count:", format(final_count, big.mark = ","), "\n")

if (final_count > 100000) {
  cat("✅ SUCCESS: Database populated with 100k+ documents!\n")
} else if (final_count > 50000) {
  cat("✅ GOOD: Database populated with 50k+ documents\n")
} else {
  cat("⚠️ LIMITED: Only", format(final_count, big.mark = ","), "documents populated\n")
}

cat("==============================================\n")