# Setup Railway PostgreSQL Database
# Monitor Legislativo v4 - Unified Architecture

# Load required libraries
library(DBI)
library(RPostgreSQL)

# Database connection
DATABASE_URL <- "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway"

# Parse connection string
parse_db_url <- function(url) {
  pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):([^/]+)/(.+)"
  matches <- regmatches(url, regexec(pattern, url))[[1]]
  
  list(
    user = matches[2],
    password = matches[3],
    host = matches[4],
    port = as.numeric(matches[5]),
    dbname = matches[6]
  )
}

# Connect to database
setup_railway_database <- function() {
  cat("🔗 Connecting to Railway PostgreSQL...\n")
  
  tryCatch({
    # Parse connection details
    db_config <- parse_db_url(DATABASE_URL)
    
    # Connect to database
    con <- dbConnect(
      RPostgreSQL::PostgreSQL(),
      user = db_config$user,
      password = db_config$password,
      host = db_config$host,
      port = db_config$port,
      dbname = db_config$dbname
    )
    
    cat("✅ Connected successfully!\n")
    cat("🔧 Setting up database schema...\n")
    
    # Create tables
    setup_sql <- "
    -- Documents table for LexML data
    CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        urn VARCHAR(500) UNIQUE NOT NULL,
        title TEXT NOT NULL,
        content TEXT,
        document_type VARCHAR(100),
        date_published DATE,
        source VARCHAR(100),
        url TEXT,
        metadata JSONB,
        geographic_scope TEXT,
        transport_category TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Search cache table
    CREATE TABLE IF NOT EXISTS search_cache (
        id SERIAL PRIMARY KEY,
        query_hash VARCHAR(64) UNIQUE NOT NULL,
        query_text TEXT NOT NULL,
        results JSONB NOT NULL,
        source VARCHAR(50) DEFAULT 'lexml',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP
    );
    
    -- Performance indexes
    CREATE INDEX IF NOT EXISTS idx_documents_urn ON documents(urn);
    CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type);
    CREATE INDEX IF NOT EXISTS idx_documents_date ON documents(date_published);
    CREATE INDEX IF NOT EXISTS idx_search_cache_hash ON search_cache(query_hash);
    "
    
    dbExecute(con, setup_sql)
    
    # Insert sample data
    sample_data <- data.frame(
      urn = c(
        "urn:lex:br:federal:lei:2023-01-01;14521",
        "urn:lex:br:federal:decreto:2023-02-15;11789",
        "urn:lex:br:federal:lei:2023-03-20;14567"
      ),
      title = c(
        "Lei do Transporte Público Sustentável",
        "Regulamento da Mobilidade Urbana",
        "Marco Legal do Transporte Ferroviário"
      ),
      content = c(
        "Estabelece diretrizes para o transporte público sustentável no Brasil...",
        "Regulamenta a política nacional de mobilidade urbana e transporte coletivo...",
        "Estabelece o marco legal para o desenvolvimento do transporte ferroviário..."
      ),
      document_type = c("lei", "decreto", "lei"),
      date_published = as.Date(c("2023-01-01", "2023-02-15", "2023-03-20")),
      source = c("lexml", "lexml", "lexml"),
      url = c(
        "https://lexml.gov.br/urn/urn:lex:br:federal:lei:2023-01-01;14521",
        "https://lexml.gov.br/urn/urn:lex:br:federal:decreto:2023-02-15;11789",
        "https://lexml.gov.br/urn/urn:lex:br:federal:lei:2023-03-20;14567"
      ),
      transport_category = c("transporte_publico", "mobilidade_urbana", "transporte_ferroviario"),
      metadata = c(
        '{"keywords": ["transporte", "sustentabilidade", "mobilidade"]}',
        '{"keywords": ["mobilidade", "urbana", "coletivo"]}',
        '{"keywords": ["ferroviário", "logística", "infraestrutura"]}'
      ),
      stringsAsFactors = FALSE
    )
    
    # Insert sample data
    dbWriteTable(con, "documents", sample_data, append = TRUE, row.names = FALSE)
    
    # Verify setup
    doc_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")$count
    
    cat("✅ Database setup completed!\n")
    cat(sprintf("📄 Documents: %d\n", doc_count))
    
    dbDisconnect(con)
    
    return(TRUE)
    
  }, error = function(e) {
    cat(sprintf("❌ Database setup failed: %s\n", e$message))
    return(FALSE)
  })
}

# Run setup
cat("🚀 Railway PostgreSQL Database Setup\n")
cat("========================================\n")

if (setup_railway_database()) {
  cat("\n🎉 Database setup successful!\n")
  cat("✅ Your Railway stack is ready!\n")
  cat("\nNext steps:\n")
  cat("1. Test your unified app\n")
  cat("2. Verify search functionality\n") 
  cat("3. Test database connectivity\n")
} else {
  cat("\n❌ Database setup failed!\n")
  cat("Please check your Railway PostgreSQL service.\n")
}