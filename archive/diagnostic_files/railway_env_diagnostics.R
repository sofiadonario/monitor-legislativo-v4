# RAILWAY ENVIRONMENT DIAGNOSTICS
# ===============================
# Diagnostic script to identify Railway environment variable injection issues

cat("🔍 RAILWAY ENVIRONMENT DIAGNOSTICS\n")
cat(paste(rep("=", 50), collapse = ""), "\n")

# Check Railway-specific environment variables
railway_vars <- c(
  "RAILWAY_ENVIRONMENT",
  "RAILWAY_PROJECT_ID", 
  "RAILWAY_SERVICE_ID",
  "RAILWAY_SERVICE_NAME",
  "RAILWAY_DEPLOYMENT_ID"
)

cat("🚂 RAILWAY PLATFORM VARIABLES:\n")
for (var in railway_vars) {
  val <- Sys.getenv(var)
  if (val != "") {
    if (var == "RAILWAY_PROJECT_ID") {
      cat("✅", var, ":", substr(val, 1, 8), "...\n")  # Truncate for security
    } else {
      cat("✅", var, ":", val, "\n")
    }
  } else {
    cat("❌", var, ": NOT SET\n")
  }
}

# Check database environment variables
db_vars <- c(
  "DATABASE_URL",
  "PGHOST",
  "PGPORT", 
  "PGDATABASE",
  "PGUSER",
  "PGPASSWORD"
)

cat("\n🗄️ DATABASE ENVIRONMENT VARIABLES:\n")
for (var in db_vars) {
  val <- Sys.getenv(var)
  if (val != "") {
    if (var %in% c("PGPASSWORD", "DATABASE_URL")) {
      cat("✅", var, ": ***SET*** (", nchar(val), " chars)\n")
    } else {
      cat("✅", var, ":", val, "\n")
    }
  } else {
    cat("❌", var, ": NOT SET\n")
  }
}

# Check application environment variables
app_vars <- c(
  "PORT",
  "R_CONFIG_ACTIVE",
  "SHINY_LOG_LEVEL"
)

cat("\n🎯 APPLICATION ENVIRONMENT VARIABLES:\n")
for (var in app_vars) {
  val <- Sys.getenv(var)
  if (val != "") {
    cat("✅", var, ":", val, "\n")
  } else {
    cat("❌", var, ": NOT SET\n")
  }
}

# Database connection test
cat("\n🧪 DATABASE CONNECTION TEST:\n")
if (Sys.getenv("DATABASE_URL") != "") {
  cat("🔍 Testing DATABASE_URL connection...\n")
  tryCatch({
    library(DBI)
    library(RPostgres)
    conn <- dbConnect(RPostgres::Postgres(), dbname = Sys.getenv("DATABASE_URL"))
    result <- dbGetQuery(conn, "SELECT COUNT(*) as count FROM documents")
    dbDisconnect(conn)
    cat("✅ DATABASE_URL connection successful:", format(result$count[1], big.mark = ","), "documents\n")
  }, error = function(e) {
    cat("❌ DATABASE_URL connection failed:", e$message, "\n")
  })
} else {
  cat("⚠️ DATABASE_URL not available for testing\n")
}

# Recommendations
cat("\n💡 DIAGNOSTIC RESULTS:\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

db_env_set <- all(sapply(db_vars, function(x) Sys.getenv(x) != ""))
railway_env_set <- any(sapply(railway_vars, function(x) Sys.getenv(x) != ""))

if (db_env_set) {
  cat("✅ Database environment variables are properly set\n")
  cat("   → Railway PostgreSQL service attachment is working\n")
} else {
  cat("🚨 Database environment variables are MISSING\n")
  cat("   → Check Railway PostgreSQL service attachment\n")
  cat("   → Verify railway.toml configuration\n")
  cat("   → Ensure database service is linked to this deployment\n")
}

if (railway_env_set) {
  cat("✅ Railway platform variables detected\n")
  cat("   → Application is running on Railway platform\n")
} else {
  cat("⚠️ Railway platform variables not detected\n")
  cat("   → May be running locally or on different platform\n")
}

cat("\n📋 NEXT STEPS:\n")
if (!db_env_set && !railway_env_set) {
  cat("1. Verify this is running on Railway platform\n")
  cat("2. Check railway.toml is in repository root\n")
  cat("3. Ensure PostgreSQL service is attached to Railway project\n")
} else if (!db_env_set) {
  cat("1. In Railway dashboard, verify PostgreSQL service is attached\n")
  cat("2. Check service variables in Railway dashboard\n")
  cat("3. Redeploy to refresh environment variables\n")
} else {
  cat("✅ Environment appears to be configured correctly\n")
}

cat(paste(rep("=", 50), collapse = ""), "\n")