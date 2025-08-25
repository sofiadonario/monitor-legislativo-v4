#!/usr/bin/env Rscript

cat("\n🔍 RAILWAY DATABASE CHECK\n")
cat("=" , rep("=", 40), "\n", sep="")

# Check environment variable
db_url <- Sys.getenv("DATABASE_URL")

if (db_url == "") {
  cat("❌ DATABASE_URL not set\n")
  cat("   Please set the DATABASE_URL environment variable\n")
  cat("   Format: postgresql://user:pass@host:port/database\n")
} else {
  cat("✅ DATABASE_URL is set\n")
  # Mask password for security
  masked_url <- gsub("://[^:]+:[^@]+@", "://****:****@", db_url)
  cat("   URL:", masked_url, "\n")
}

# Try to connect if packages are available
if (requireNamespace("DBI", quietly = TRUE) && requireNamespace("RPostgres", quietly = TRUE)) {
  cat("\n📊 Attempting database connection...\n")
  
  tryCatch({
    con <- DBI::dbConnect(
      RPostgres::Postgres(),
      dbname = "railway",
      host = "nozomi.proxy.rlwy.net",
      port = 44844,
      user = "postgres",
      password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY",
      sslmode = "require"
    )
    
    cat("✅ Connection successful!\n")
    
    # Check tables
    tables <- DBI::dbListTables(con)
    cat("\n📋 Available tables:\n")
    for (table in tables) {
      count <- DBI::dbGetQuery(con, paste0("SELECT COUNT(*) as n FROM ", table))$n
      cat("   -", table, ":", format(count, big.mark=","), "rows\n")
    }
    
    DBI::dbDisconnect(con)
    
  }, error = function(e) {
    cat("❌ Connection failed:", e$message, "\n")
  })
} else {
  cat("\n⚠️  DBI/RPostgres packages not available for full diagnostics\n")
  cat("   Run: install.packages(c('DBI', 'RPostgres'))\n")
}

cat("\n✅ Check complete\n")