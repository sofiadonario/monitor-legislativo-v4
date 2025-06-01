#!/usr/bin/env Rscript
# Script to populate Railway PostgreSQL database with full 134k+ documents
# ==================================================================

cat("=================================================\n")
cat("RAILWAY DATABASE POPULATION - FULL 134K DATASET\n")
cat("=================================================\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(data.table)
})

# Database configuration (from robust_connection.R)
DB_CONFIG <- list(
  url = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway",
  host = "nozomi.proxy.rlwy.net",
  port = 44844,
  database = "railway",
  user = "postgres",
  password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
)

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
    sslmode = "prefer"
  )
}, error = function(e) {
  cat("❌ Failed to connect to database:", e$message, "\n")
  quit(status = 1)
})

cat("✅ Connected to Railway database\n")

# Check current document count
current_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")[1, 1]
cat("\n📊 Current documents in database:", format(current_count, big.mark = ","), "\n")

# Load the full dataset
csv_path <- "data_current/processed/production/lexml_unified_dataset.csv"
if (!file.exists(csv_path)) {
  cat("❌ Dataset not found at:", csv_path, "\n")
  dbDisconnect(conn)
  quit(status = 1)
}

cat("\n📁 Loading full dataset from:", csv_path, "\n")
data <- fread(csv_path, encoding = "UTF-8", showProgress = TRUE)
cat("✅ Loaded", format(nrow(data), big.mark = ","), "documents\n")

# Ensure required columns exist
required_cols <- c("id", "titulo", "autoridade", "data", "tipo", "estado", "municipio", "categoria")
missing_cols <- required_cols[!required_cols %in% names(data)]

if (length(missing_cols) > 0) {
  cat("⚠️ Missing columns:", paste(missing_cols, collapse = ", "), "\n")
  cat("   Adding default values for missing columns\n")
  
  for (col in missing_cols) {
    data[[col]] <- NA_character_
  }
}

# Clean and prepare data
cat("\n🧹 Cleaning data...\n")

# Ensure ID column exists and is unique
if (!"id" %in% names(data) || any(is.na(data$id))) {
  data$id <- paste0("DOC_", seq_len(nrow(data)))
}

# Convert dates to proper format
if ("data" %in% names(data)) {
  data$data <- as.Date(data$data, format = "%Y-%m-%d")
}

# Fill missing values with defaults
data[is.na(titulo), titulo := "Sem título"]
data[is.na(autoridade), autoridade := "Não especificada"]
data[is.na(tipo), tipo := "Outro"]
data[is.na(estado), estado := "BR"]
data[is.na(municipio), municipio := ""]
data[is.na(categoria), categoria := "Geral"]

cat("✅ Data cleaned and prepared\n")

# Clear existing data (optional - comment out if you want to append)
cat("\n🗑️ Clearing existing documents...\n")
dbExecute(conn, "TRUNCATE TABLE documents CASCADE")
cat("✅ Table cleared\n")

# Insert data in batches for performance
batch_size <- 5000
n_batches <- ceiling(nrow(data) / batch_size)

cat("\n📤 Inserting data in", n_batches, "batches of", format(batch_size, big.mark = ","), "documents\n")

for (i in seq_len(n_batches)) {
  start_idx <- (i - 1) * batch_size + 1
  end_idx <- min(i * batch_size, nrow(data))
  
  batch_data <- data[start_idx:end_idx, ]
  
  tryCatch({
    dbWriteTable(conn, "documents", batch_data, append = TRUE, overwrite = FALSE)
    cat("   Batch", i, "/", n_batches, "- Inserted rows", 
        format(start_idx, big.mark = ","), "to", 
        format(end_idx, big.mark = ","), "\n")
  }, error = function(e) {
    cat("   ⚠️ Batch", i, "failed:", e$message, "\n")
  })
}

# Verify final count
final_count <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")[1, 1]
cat("\n✅ Database population complete!\n")
cat("📊 Final document count:", format(final_count, big.mark = ","), "\n")

# Create indexes for performance
cat("\n🔧 Creating indexes for performance...\n")

indexes <- c(
  "CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado)",
  "CREATE INDEX IF NOT EXISTS idx_documents_municipio ON documents(municipio)",
  "CREATE INDEX IF NOT EXISTS idx_documents_categoria ON documents(categoria)",
  "CREATE INDEX IF NOT EXISTS idx_documents_data ON documents(data)",
  "CREATE INDEX IF NOT EXISTS idx_documents_tipo ON documents(tipo)"
)

for (idx_sql in indexes) {
  tryCatch({
    dbExecute(conn, idx_sql)
    cat("   ✅", sub("CREATE INDEX IF NOT EXISTS ", "", sub(" ON.*", "", idx_sql)), "\n")
  }, error = function(e) {
    cat("   ⚠️ Index creation failed:", e$message, "\n")
  })
}

# Update statistics
cat("\n📈 Updating database statistics...\n")
dbExecute(conn, "ANALYZE documents")

# Disconnect
dbDisconnect(conn)

cat("\n🎉 SUCCESS! Database populated with full 134k+ dataset\n")
cat("================================================\n")