#!/usr/bin/env Rscript

# Database Population Script for Google Cloud SQL
# ================================================
# Populates Cloud SQL PostgreSQL with the full 134k dataset

cat("\n=== GOOGLE CLOUD SQL DATABASE POPULATION ===\n\n")

# Check if required packages are available
required_packages <- c("DBI", "RPostgres", "data.table")
missing <- character()

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing <- c(missing, pkg)
  }
}

if (length(missing) > 0) {
  cat("❌ Missing packages:", paste(missing, collapse = ", "), "\n")
  cat("📦 Install with: install.packages(c('", paste(missing, collapse = "', '"), "'))\n")
  quit(status = 1)
}

# Load libraries
library(DBI)
library(RPostgres)
library(data.table)

# Database connection parameters - Google Cloud SQL
db_params <- list(
  host = "34.39.228.246",  # Cloud SQL public IP
  port = 5432,
  dbname = "monitor_legislativo",
  user = "monitor_user",
  password = "Sdonario1"
)

cat("🔌 Connecting to Google Cloud SQL PostgreSQL...\n")
cat("   Host:", db_params$host, "Port:", db_params$port, "\n")
cat("   Database:", db_params$dbname, "\n")

tryCatch({
  # Connect to database
  con <- dbConnect(
    RPostgres::Postgres(),
    host = db_params$host,
    port = db_params$port,
    dbname = db_params$dbname,
    user = db_params$user,
    password = db_params$password,
    sslmode = "require"  # Cloud SQL requires SSL
  )

  cat("✅ Connected to Cloud SQL PostgreSQL successfully!\n")

  # Check for existing data
  existing_tables <- dbListTables(con)
  cat("📋 Existing tables:", paste(existing_tables, collapse = ", "), "\n")

  # Check if we already have legislative data
  has_data <- FALSE
  table_name <- "documents"  # Changed from legislative_data to match schema

  if (table_name %in% existing_tables) {
    count_result <- dbGetQuery(con, paste("SELECT COUNT(*) as count FROM", table_name))
    record_count <- count_result$count[1]
    cat("📊 Existing records in", table_name, ":", format(record_count, big.mark = ","), "\n")

    if (record_count >= 100000) {
      has_data <- TRUE
      cat("✅ Database already has substantial data - no need to populate\n")
    }
  }

  if (!has_data) {
    # Load CSV data
    csv_file <- "data_current/processed/production/lexml_unified_dataset.csv"
    if (!file.exists(csv_file)) {
      cat("❌ CSV file not found:", csv_file, "\n")
      quit(status = 1)
    }

    cat("📁 Loading CSV data from:", csv_file, "\n")
    cat("⏳ This may take a few minutes for 134k records...\n")

    # Use data.table for faster loading
    legislative_data <- fread(csv_file, encoding = "UTF-8", showProgress = TRUE)
    cat("✅ Loaded", format(nrow(legislative_data), big.mark = ","), "records from CSV\n")

    # Create/replace table
    cat("💾 Writing data to PostgreSQL database...\n")
    dbExecute(con, paste("DROP TABLE IF EXISTS", table_name))

    # Write in chunks for better performance
    chunk_size <- 5000  # Smaller chunks for network transfer
    total_rows <- nrow(legislative_data)
    chunks <- ceiling(total_rows / chunk_size)

    cat("📦 Writing in", chunks, "chunks of", chunk_size, "records each...\n")

    # Write first chunk to create table structure
    first_chunk <- legislative_data[1:min(chunk_size, total_rows)]
    dbWriteTable(con, table_name, first_chunk, row.names = FALSE, overwrite = TRUE)
    cat("   ✅ Table created with first chunk\n")

    # Write remaining chunks
    if (total_rows > chunk_size) {
      for (i in 2:chunks) {
        start_row <- (i - 1) * chunk_size + 1
        end_row <- min(i * chunk_size, total_rows)
        chunk_data <- legislative_data[start_row:end_row]

        dbWriteTable(con, table_name, chunk_data, row.names = FALSE, append = TRUE)

        progress <- round((i / chunks) * 100, 1)
        if (i %% 5 == 0) {  # Report every 5 chunks
          cat("   📊 Progress:", progress, "% (chunk", i, "of", chunks, ")\n")
        }
      }
    }

    # Verify data was written
    final_count <- dbGetQuery(con, paste("SELECT COUNT(*) as count FROM", table_name))
    cat("✅ Database populated with", format(final_count$count[1], big.mark = ","), "records\n")

    # Create performance indexes
    cat("🔧 Creating database indexes for performance...\n")
    indexes <- list(
      "titulo" = "titulo",
      "estado" = "estado",
      "data" = "data",
      "categoria" = "categoria",
      "urn" = "urn"
    )

    for (idx_name in names(indexes)) {
      idx_sql <- sprintf("CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s (%s)",
                        table_name, idx_name, table_name, indexes[[idx_name]])
      tryCatch({
        dbExecute(con, idx_sql)
        cat("   ✅ Index on", indexes[[idx_name]], "created\n")
      }, error = function(e) {
        cat("   ⚠️  Index on", indexes[[idx_name]], "failed:", e$message, "\n")
      })
    }

    # Create brazilian_states reference table
    cat("🗺️  Creating Brazilian states reference table...\n")
    states_sql <- "
CREATE TABLE IF NOT EXISTS brazilian_states (
  abbrev VARCHAR(2) PRIMARY KEY,
  name VARCHAR(50) NOT NULL,
  region VARCHAR(20) NOT NULL,
  capital VARCHAR(50) NOT NULL,
  lat DECIMAL(10,8),
  lng DECIMAL(11,8)
);

INSERT INTO brazilian_states (abbrev, name, region, capital, lat, lng) VALUES
('AC', 'Acre', 'Norte', 'Rio Branco', -8.77, -70.55),
('AL', 'Alagoas', 'Nordeste', 'Maceió', -9.71, -36.82),
('AP', 'Amapá', 'Norte', 'Macapá', 0.00, -51.77),
('AM', 'Amazonas', 'Norte', 'Manaus', -3.07, -65.74),
('BA', 'Bahia', 'Nordeste', 'Salvador', -12.96, -41.58),
('CE', 'Ceará', 'Nordeste', 'Fortaleza', -5.20, -39.73),
('DF', 'Distrito Federal', 'Centro-Oeste', 'Brasília', -15.83, -47.86),
('ES', 'Espírito Santo', 'Sudeste', 'Vitória', -19.19, -40.34),
('GO', 'Goiás', 'Centro-Oeste', 'Goiânia', -16.64, -49.31),
('MA', 'Maranhão', 'Nordeste', 'São Luís', -2.55, -45.28),
('MT', 'Mato Grosso', 'Centro-Oeste', 'Cuiabá', -15.60, -56.10),
('MS', 'Mato Grosso do Sul', 'Centro-Oeste', 'Campo Grande', -20.51, -54.54),
('MG', 'Minas Gerais', 'Sudeste', 'Belo Horizonte', -18.10, -45.00),
('PA', 'Pará', 'Norte', 'Belém', -5.53, -52.00),
('PB', 'Paraíba', 'Nordeste', 'João Pessoa', -7.06, -36.78),
('PR', 'Paraná', 'Sul', 'Curitiba', -24.89, -51.22),
('PE', 'Pernambuco', 'Nordeste', 'Recife', -8.28, -38.95),
('PI', 'Piauí', 'Nordeste', 'Teresina', -8.28, -43.68),
('RJ', 'Rio de Janeiro', 'Sudeste', 'Rio de Janeiro', -22.84, -43.68),
('RN', 'Rio Grande do Norte', 'Nordeste', 'Natal', -5.22, -36.95),
('RS', 'Rio Grande do Sul', 'Sul', 'Porto Alegre', -30.01, -52.09),
('RO', 'Rondônia', 'Norte', 'Porto Velho', -8.83, -62.76),
('RR', 'Roraima', 'Norte', 'Boa Vista', 2.73, -61.33),
('SC', 'Santa Catarina', 'Sul', 'Florianópolis', -27.33, -50.16),
('SP', 'São Paulo', 'Sudeste', 'São Paulo', -23.55, -48.64),
('SE', 'Sergipe', 'Nordeste', 'Aracaju', -10.90, -37.86),
('TO', 'Tocantins', 'Norte', 'Palmas', -10.25, -48.25)
ON CONFLICT (abbrev) DO NOTHING;
"
    tryCatch({
      dbExecute(con, states_sql)
      cat("   ✅ Brazilian states table created\n")
    }, error = function(e) {
      cat("   ⚠️  States table creation failed:", e$message, "\n")
    })
  }

  # Final verification
  cat("\n📊 Final database status:\n")
  all_tables <- dbListTables(con)
  for (table in all_tables) {
    tryCatch({
      count <- dbGetQuery(con, paste("SELECT COUNT(*) as count FROM", table))
      cat("   -", table, ":", format(count$count[1], big.mark = ","), "records\n")
    }, error = function(e) {
      cat("   -", table, ": ERROR reading count\n")
    })
  }

  dbDisconnect(con)
  cat("\n🎉 DATABASE POPULATION COMPLETE!\n")
  cat("✅ Your application can now use the full PostgreSQL database with 134k+ documents\n")
  cat("🌐 Cloud Run URL: https://mackmonitor-667999538255.southamerica-east1.run.app\n")

}, error = function(e) {
  cat("❌ Database connection failed:", e$message, "\n")
  cat("\n🔄 Troubleshooting:\n")
  cat("   - Check if Cloud SQL instance is running\n")
  cat("   - Verify network connectivity to", db_params$host, "\n")
  cat("   - Confirm database credentials are correct\n")
  cat("   - Check if your IP is authorized in Cloud SQL\n")
  quit(status = 1)
})

cat("\n=== POPULATION COMPLETE ===\n")
