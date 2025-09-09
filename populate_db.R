#!/usr/bin/env Rscript

cat("=== RAILWAY DATABASE POPULATION ===\n")
cat("Starting at:", format(Sys.time()), "\n\n")

# Check if required packages are available
if (!require(DBI, quietly = TRUE)) {
  cat("Installing DBI...\n")
  install.packages("DBI", repos = "https://cloud.r-project.org/", quiet = TRUE)
  library(DBI)
}

if (!require(RPostgres, quietly = TRUE)) {
  cat("Installing RPostgres...\n")
  install.packages("RPostgres", repos = "https://cloud.r-project.org/", quiet = TRUE)
  library(RPostgres)
}

# Connection parameters - use internal URL when on Railway
db_host <- "postgres.railway.internal"
db_port <- 5432
db_name <- "railway"
db_user <- "postgres"
db_pass <- "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"

cat("Connecting to PostgreSQL at", db_host, "...\n")

# Connect to database
con <- tryCatch({
  dbConnect(
    RPostgres::Postgres(),
    host = db_host,
    port = db_port,
    dbname = db_name,
    user = db_user,
    password = db_pass,
    sslmode = "prefer"
  )
}, error = function(e) {
  cat("❌ Connection failed:", e$message, "\n")
  cat("\nTrying external URL instead...\n")
  
  # Try external URL as fallback
  dbConnect(
    RPostgres::Postgres(),
    host = "nozomi.proxy.rlwy.net",
    port = 44844,
    dbname = db_name,
    user = db_user,
    password = db_pass,
    sslmode = "prefer"
  )
})

if (is.null(con)) {
  stop("Could not connect to database")
}

cat("✅ Connected to PostgreSQL\n\n")

# Check if documents table exists and has data
existing_tables <- dbListTables(con)
cat("Existing tables:", paste(existing_tables, collapse = ", "), "\n")

if ("documents" %in% existing_tables) {
  count <- dbGetQuery(con, "SELECT COUNT(*) as n FROM documents")$n
  cat("Documents table exists with", format(count, big.mark = ","), "records\n")
  
  if (count >= 100000) {
    cat("✅ Database already populated!\n")
    dbDisconnect(con)
    quit(status = 0)
  } else {
    cat("Table exists but needs more data. Dropping and recreating...\n")
    dbExecute(con, "DROP TABLE documents CASCADE")
  }
}

# Load CSV data
csv_file <- "data_current/processed/production/lexml_unified_dataset.csv"

if (!file.exists(csv_file)) {
  # Try alternative paths
  csv_file <- "lexml_unified_dataset.csv"
  if (!file.exists(csv_file)) {
    cat("❌ CSV file not found!\n")
    cat("Tried:\n")
    cat("  - data_current/processed/production/lexml_unified_dataset.csv\n")
    cat("  - lexml_unified_dataset.csv\n")
    dbDisconnect(con)
    stop("CSV file not found")
  }
}

cat("📁 Loading CSV from:", csv_file, "\n")
cat("   File size:", round(file.size(csv_file) / (1024^2), 1), "MB\n")

# Read CSV in chunks for better memory management
cat("📊 Reading CSV file...\n")

# First, get column names
header <- read.csv(csv_file, nrows = 1)
cat("   Columns:", paste(names(header), collapse = ", "), "\n")

# Read full dataset
data <- read.csv(csv_file, stringsAsFactors = FALSE, encoding = "UTF-8")
cat("✅ Loaded", format(nrow(data), big.mark = ","), "documents\n")

# Create table and write data
cat("\n💾 Writing to PostgreSQL...\n")

# Create table with appropriate structure
dbExecute(con, "
CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  titulo TEXT,
  estado VARCHAR(10),
  data DATE,
  categoria VARCHAR(100),
  tipo VARCHAR(100),
  ementa TEXT,
  autor TEXT,
  urn TEXT,
  assunto TEXT,
  texto TEXT,
  municipio VARCHAR(100),
  ano INTEGER,
  mes INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)")

# Prepare data for insertion
# Handle date conversion
if ("data" %in% names(data)) {
  data$data <- as.Date(data$data, format = "%Y-%m-%d")
}

# Extract year and month if not present
if (!"ano" %in% names(data) && "data" %in% names(data)) {
  data$ano <- as.integer(format(data$data, "%Y"))
}

if (!"mes" %in% names(data) && "data" %in% names(data)) {
  data$mes <- as.integer(format(data$data, "%m"))
}

# Write data in chunks
chunk_size <- 10000
total_rows <- nrow(data)
chunks <- ceiling(total_rows / chunk_size)

cat("📦 Writing in", chunks, "chunks of", format(chunk_size, big.mark = ","), "rows...\n")

for (i in 1:chunks) {
  start_idx <- (i - 1) * chunk_size + 1
  end_idx <- min(i * chunk_size, total_rows)
  
  chunk_data <- data[start_idx:end_idx, ]
  
  dbWriteTable(con, "documents", chunk_data, append = TRUE, row.names = FALSE)
  
  cat("   Chunk", i, "/", chunks, "written (", 
      format(end_idx, big.mark = ","), "/", 
      format(total_rows, big.mark = ","), "rows)\n")
}

cat("✅ All data written to database\n\n")

# Create indexes for performance
cat("🔧 Creating indexes...\n")

indexes <- c(
  "CREATE INDEX idx_documents_titulo ON documents(titulo)",
  "CREATE INDEX idx_documents_estado ON documents(estado)",
  "CREATE INDEX idx_documents_data ON documents(data)",
  "CREATE INDEX idx_documents_categoria ON documents(categoria)",
  "CREATE INDEX idx_documents_tipo ON documents(tipo)",
  "CREATE INDEX idx_documents_ano ON documents(ano)",
  "CREATE INDEX idx_documents_mes ON documents(mes)"
)

for (idx in indexes) {
  tryCatch({
    dbExecute(con, idx)
    cat("   ✅", sub("CREATE INDEX (\\w+).*", "\\1", idx), "created\n")
  }, error = function(e) {
    cat("   ⚠️ Index creation failed:", e$message, "\n")
  })
}

# Final verification
cat("\n📊 Final verification:\n")
final_count <- dbGetQuery(con, "SELECT COUNT(*) as n FROM documents")$n
cat("   Total documents:", format(final_count, big.mark = ","), "\n")

# Sample data check
sample <- dbGetQuery(con, "SELECT titulo, estado, data FROM documents LIMIT 3")
cat("\n   Sample records:\n")
print(sample)

# State distribution
states <- dbGetQuery(con, "
  SELECT estado, COUNT(*) as count 
  FROM documents 
  GROUP BY estado 
  ORDER BY count DESC 
  LIMIT 5
")
cat("\n   Top 5 states:\n")
print(states)

dbDisconnect(con)

cat("\n🎉 DATABASE POPULATION COMPLETE!\n")
cat("✅ Your Railway PostgreSQL now has", format(final_count, big.mark = ","), "documents\n")
cat("✅ The app should now show all documents correctly\n")
cat("\nCompleted at:", format(Sys.time()), "\n")