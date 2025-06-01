# Simple test to verify database connection and documents view
library(DBI)
library(RPostgres)
library(pool)

# Get DATABASE_URL from environment
database_url <- Sys.getenv("DATABASE_URL")

if (nchar(database_url) > 0) {
  cat("✅ DATABASE_URL found\n")
  
  # Parse DATABASE_URL
  parsed <- regmatches(database_url, regexec("postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)", database_url))[[1]]
  
  if (length(parsed) == 6) {
    db_user <- parsed[2]
    db_password <- parsed[3]
    db_host <- parsed[4]
    db_port <- as.numeric(parsed[5])
    db_name <- parsed[6]
    
    cat("✅ Connection details parsed successfully\n")
    cat("  Host:", db_host, "\n")
    cat("  Port:", db_port, "\n")
    cat("  Database:", db_name, "\n")
    
    tryCatch({
      # Create connection pool
      pool <- dbPool(
        drv = RPostgres::Postgres(),
        host = db_host,
        port = db_port,
        dbname = db_name,
        user = db_user,
        password = db_password,
        minSize = 1,
        maxSize = 3
      )
      
      cat("✅ Database pool created successfully\n")
      
      # Test documents view
      count_result <- dbGetQuery(pool, "SELECT COUNT(*) as count FROM documents")
      cat("✅ Documents view query successful\n")
      cat("  Total documents:", count_result$count[1], "\n")
      
      # Test species distribution
      species_result <- dbGetQuery(pool, "SELECT species, COUNT(*) as count FROM documents GROUP BY species ORDER BY count DESC")
      cat("✅ Species distribution:\n")
      for(i in 1:nrow(species_result)) {
        cat("  ", species_result$species[i], ":", species_result$count[i], "\n")
      }
      
      # Test state distribution (top 5)
      state_result <- dbGetQuery(pool, "SELECT estado, COUNT(*) as count FROM documents WHERE estado IS NOT NULL GROUP BY estado ORDER BY count DESC LIMIT 5")
      cat("✅ Top 5 states by document count:\n")
      for(i in 1:nrow(state_result)) {
        cat("  ", state_result$estado[i], ":", state_result$count[i], "\n")
      }
      
      # Test sample data
      sample_result <- dbGetQuery(pool, "SELECT titulo, tipo, species, estado FROM documents LIMIT 3")
      cat("✅ Sample documents:\n")
      for(i in 1:nrow(sample_result)) {
        cat("  ", substr(sample_result$titulo[i], 1, 50), "... (", sample_result$tipo[i], ", ", sample_result$species[i], ", ", sample_result$estado[i], ")\n")
      }
      
      # Close pool
      poolClose(pool)
      cat("✅ Database connection test SUCCESSFUL\n")
      cat("🎉 Ready for Shiny app deployment!\n")
      
    }, error = function(e) {
      cat("❌ Database connection test FAILED:", e$message, "\n")
    })
    
  } else {
    cat("❌ Failed to parse DATABASE_URL\n")
  }
} else {
  cat("❌ DATABASE_URL environment variable not found\n")
}