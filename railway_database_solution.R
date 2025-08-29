# Railway Database Solution - Upload Full Dataset to Railway PostgreSQL
# This script uploads the complete 134k+ document dataset to Railway's database

cat("=== RAILWAY DATABASE SOLUTION ===\n")

# Check if we can connect to Railway PostgreSQL
railway_db_available <- FALSE

tryCatch({
  # Try to get Railway DATABASE_URL from environment
  db_url <- Sys.getenv("DATABASE_URL")
  if(db_url != "") {
    cat("✅ Railway DATABASE_URL found\n")
    railway_db_available <- TRUE
  } else {
    cat("⚠️ Railway DATABASE_URL not found (running locally)\n")
  }
}, error = function(e) {
  cat("❌ Database connection check failed:", e$message, "\n")
})

if(railway_db_available) {
  cat("\n📊 Loading full dataset for database upload...\n")
  
  # Load the complete dataset
  full_data <- read.csv("data_current/processed/production/lexml_unified_dataset.csv", 
                       stringsAsFactors = FALSE)
  cat("✅ Loaded", nrow(full_data), "documents\n")
  
  # Install required database packages if needed
  if(!requireNamespace("DBI", quietly = TRUE)) {
    install.packages("DBI")
  }
  if(!requireNamespace("RPostgreSQL", quietly = TRUE)) {
    install.packages("RPostgreSQL")
  }
  
  tryCatch({
    # Connect to Railway PostgreSQL
    library(DBI)
    library(RPostgreSQL)
    
    con <- dbConnect(RPostgreSQL::PostgreSQL(), 
                     dbname = sub(".*/(\\w+)\\?.*", "\\1", db_url),
                     host = sub(".*@([^:]+):.*", "\\1", db_url),
                     port = as.numeric(sub(".*:(\\d+)/.*", "\\1", db_url)),
                     user = sub(".*://([^:]+):.*", "\\1", db_url),
                     password = sub(".*://[^:]+:([^@]+)@.*", "\\1", db_url))
    
    cat("✅ Connected to Railway PostgreSQL\n")
    
    # Create table if it doesn't exist
    dbExecute(con, "
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        titulo TEXT,
        tipo TEXT,
        data DATE,
        urn TEXT UNIQUE,
        autor TEXT,
        assuntos TEXT,
        classificacao TEXT,
        jurisdicao TEXT,
        autoridade TEXT,
        ementa TEXT,
        url TEXT,
        categoria TEXT,
        estado TEXT,
        municipio TEXT,
        ano INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    ")
    
    # Upload data in chunks to avoid memory issues
    chunk_size <- 1000
    total_chunks <- ceiling(nrow(full_data) / chunk_size)
    
    cat("📤 Uploading data in", total_chunks, "chunks...\n")
    
    for(i in 1:total_chunks) {
      start_row <- ((i - 1) * chunk_size) + 1
      end_row <- min(i * chunk_size, nrow(full_data))
      chunk <- full_data[start_row:end_row, ]
      
      # Select only the columns we need
      upload_data <- data.frame(
        titulo = chunk$titulo,
        tipo = chunk$tipo,
        data = as.Date(chunk$data),
        urn = chunk$urn,
        autor = chunk$autor,
        assuntos = chunk$assuntos,
        classificacao = chunk$classificacao,
        jurisdicao = chunk$jurisdicao,
        autoridade = chunk$autoridade,
        ementa = chunk$ementa,
        url = chunk$url,
        categoria = chunk$categoria,
        estado = chunk$estado,
        municipio = chunk$municipio,
        ano = as.numeric(chunk$ano),
        stringsAsFactors = FALSE
      )
      
      # Upload chunk (use ON CONFLICT to handle duplicates)
      dbWriteTable(con, "documents", upload_data, append = TRUE, row.names = FALSE)
      
      cat(sprintf("  Chunk %d/%d uploaded (%d-%d)\n", i, total_chunks, start_row, end_row))
    }
    
    # Verify upload
    total_docs <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")$count
    cat("✅ Database upload complete:", total_docs, "documents in database\n")
    
    # Create indexes for better performance
    dbExecute(con, "CREATE INDEX IF NOT EXISTS idx_documents_categoria ON documents(categoria)")
    dbExecute(con, "CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado)")
    dbExecute(con, "CREATE INDEX IF NOT EXISTS idx_documents_data ON documents(data)")
    dbExecute(con, "CREATE INDEX IF NOT EXISTS idx_documents_titulo ON documents USING gin(to_tsvector('portuguese', titulo))")
    dbExecute(con, "CREATE INDEX IF NOT EXISTS idx_documents_ementa ON documents USING gin(to_tsvector('portuguese', ementa))")
    
    cat("✅ Database indexes created for optimal search performance\n")
    
    dbDisconnect(con)
    
  }, error = function(e) {
    cat("❌ Database upload failed:", e$message, "\n")
  })
  
} else {
  cat("\n💡 RAILWAY DATABASE SETUP INSTRUCTIONS:\n")
  cat("1. Add a PostgreSQL database to your Railway project\n") 
  cat("2. The DATABASE_URL environment variable will be automatically set\n")
  cat("3. Deploy this solution to upload all 134k+ documents to the database\n")
  cat("4. Modify app.R to query the database instead of CSV files\n")
}

cat("\n=== SOLUTION COMPLETE ===\n")