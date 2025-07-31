#!/usr/bin/env Rscript

# Database Fix Script for Railway
# This script adds the estado_codigo column and standardizes state data

cat("🔄 Starting database fix...\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
})

# Get database URL from environment
database_url <- Sys.getenv("DATABASE_URL")

if (nchar(database_url) == 0) {
  stop("❌ DATABASE_URL not found in environment variables")
}

cat("✅ DATABASE_URL found\n")

# Parse DATABASE_URL
parse_database_url <- function(url) {
  # Remove postgresql:// prefix
  url <- gsub("^postgresql://", "", url)
  
  # Split user:password@host:port/database
  if (grepl("@", url)) {
    parts <- strsplit(url, "@")[[1]]
    auth_part <- parts[1]
    host_part <- parts[2]
    
    # Extract user and password
    if (grepl(":", auth_part)) {
      auth_split <- strsplit(auth_part, ":")[[1]]
      user <- auth_split[1]
      password <- auth_split[2]
    } else {
      user <- auth_part
      password <- ""
    }
    
    # Extract host, port, and database
    if (grepl("/", host_part)) {
      host_db_split <- strsplit(host_part, "/")[[1]]
      host_port <- host_db_split[1]
      database <- host_db_split[2]
      
      if (grepl(":", host_port)) {
        host_port_split <- strsplit(host_port, ":")[[1]]
        host <- host_port_split[1]
        port <- as.integer(host_port_split[2])
      } else {
        host <- host_port
        port <- 5432L
      }
    } else {
      host <- host_part
      port <- 5432L
      database <- "postgres"
    }
    
    return(list(
      host = host,
      port = port,
      database = database,
      user = user,
      password = password
    ))
  }
  
  return(NULL)
}

# Connect to database
cat("🔄 Parsing database URL...\n")
parsed_url <- parse_database_url(database_url)

if (is.null(parsed_url)) {
  stop("❌ Failed to parse DATABASE_URL")
}

cat("🔄 Connecting to database...\n")
cat("  Host:", parsed_url$host, "\n")
cat("  Database:", parsed_url$database, "\n")

tryCatch({
  conn <- dbConnect(
    RPostgres::Postgres(),
    host = parsed_url$host,
    port = parsed_url$port,
    dbname = parsed_url$database,
    user = parsed_url$user,
    password = parsed_url$password
  )
  
  cat("✅ Connected to database\n")
  
  # Step 1: Add estado_codigo column
  cat("🔄 Adding estado_codigo column...\n")
  dbExecute(conn, "ALTER TABLE documents ADD COLUMN IF NOT EXISTS estado_codigo TEXT;")
  cat("✅ Column added\n")
  
  # Step 2: Update state codes
  cat("🔄 Standardizing state codes...\n")
  dbExecute(conn, "
    UPDATE documents SET estado_codigo = CASE
        WHEN estado = 'Acre' THEN 'AC'
        WHEN estado = 'Alagoas' THEN 'AL'
        WHEN estado = 'Amapá' THEN 'AP'
        WHEN estado = 'Amazonas' THEN 'AM'
        WHEN estado = 'Bahia' THEN 'BA'
        WHEN estado = 'Ceará' THEN 'CE'
        WHEN estado = 'Distrito Federal' THEN 'DF'
        WHEN estado = 'Espírito Santo' THEN 'ES'
        WHEN estado = 'Goiás' THEN 'GO'
        WHEN estado = 'Maranhão' THEN 'MA'
        WHEN estado = 'Mato Grosso' THEN 'MT'
        WHEN estado = 'Mato Grosso do Sul' THEN 'MS'
        WHEN estado = 'Minas Gerais' THEN 'MG'
        WHEN estado = 'Pará' THEN 'PA'
        WHEN estado = 'Paraíba' THEN 'PB'
        WHEN estado = 'Paraná' THEN 'PR'
        WHEN estado = 'Pernambuco' THEN 'PE'
        WHEN estado = 'Piauí' THEN 'PI'
        WHEN estado = 'Rio de Janeiro' THEN 'RJ'
        WHEN estado = 'Rio Grande do Norte' THEN 'RN'
        WHEN estado = 'Rio Grande do Sul' THEN 'RS'
        WHEN estado = 'Rondônia' THEN 'RO'
        WHEN estado = 'Roraima' THEN 'RR'
        WHEN estado = 'Santa Catarina' THEN 'SC'
        WHEN estado = 'São Paulo' THEN 'SP'
        WHEN estado = 'Sergipe' THEN 'SE'
        WHEN estado = 'Tocantins' THEN 'TO'
        WHEN estado IN ('AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
                       'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
                       'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO') THEN estado
        WHEN estado IN ('Federal', 'Brasil', 'BR', 'Brazil') THEN 'BR'
        ELSE estado
    END
    WHERE estado IS NOT NULL;
  ")
  cat("✅ State codes standardized\n")
  
  # Step 3: Verification
  cat("🔄 Verifying state distribution...\n")
  result <- dbGetQuery(conn, "
    SELECT 
        estado_codigo,
        estado,
        COUNT(*) as document_count
    FROM documents 
    WHERE estado_codigo IS NOT NULL 
    GROUP BY estado_codigo, estado 
    ORDER BY document_count DESC;
  ")
  
  cat("📊 Final state distribution:\n")
  for (i in 1:nrow(result)) {
    cat("  ", result$estado_codigo[i], " (", result$estado[i], "): ", result$document_count[i], " documents\n")
  }
  
  cat("\n✅ Database fix complete! Found", nrow(result), "states with documents.\n")
  cat("🗺️ The map should now display correctly with all states!\n")
  
  # Close connection
  dbDisconnect(conn)
  cat("🔐 Database connection closed\n")
  
}, error = function(e) {
  cat("❌ Error:", e$message, "\n")
  if (exists("conn")) {
    dbDisconnect(conn)
  }
  stop("Database fix failed")
})

cat("🎉 Script completed successfully!\n")