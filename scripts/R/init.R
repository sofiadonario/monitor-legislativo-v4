# INITIALIZATION SCRIPT FOR RAILWAY DEPLOYMENT
# This ensures all components load in the correct order

cat("🚀 INITIALIZING MACKMONITOR FOR RAILWAY...\n")

# 1. First, load the Railway database fix (most critical)
if (file.exists("RAILWAY_DATABASE_FIX.R")) {
  cat("✅ Loading Railway database connection...\n")
  source("RAILWAY_DATABASE_FIX.R", local = FALSE)
}

# 2. Then load the dashboard NULL fix
if (file.exists("dashboard_null_fix.R")) {
  cat("✅ Loading dashboard NULL fix...\n")
  source("dashboard_null_fix.R", local = FALSE)
}

# 3. Skip other integrations that might interfere
cat("✅ Skipping conflicting integrations for Railway deployment\n")

# 4. Load the main app
if (file.exists("app.R")) {
  cat("✅ Loading main application...\n")
  source("app.R", local = FALSE)
}

cat("🎯 INITIALIZATION COMPLETE - Dashboard should display data correctly\n")