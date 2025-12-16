# INITIALIZATION SCRIPT FOR CLOUD RUN DEPLOYMENT
# This ensures all components load in the correct order

cat("🚀 INITIALIZING MACKMONITOR FOR CLOUD RUN...\n")

# 1. First, load the Cloud Run database fix (most critical)
if (file.exists("CLOUD_RUN_DATABASE_FIX.R")) {
  cat("✅ Loading Cloud Run database connection...\n")
  source("CLOUD_RUN_DATABASE_FIX.R", local = FALSE)
}

# 2. Then load the dashboard NULL fix
if (file.exists("dashboard_null_fix.R")) {
  cat("✅ Loading dashboard NULL fix...\n")
  source("dashboard_null_fix.R", local = FALSE)
}

# 3. Skip other integrations that might interfere
cat("✅ Skipping conflicting integrations for Cloud Run deployment\n")

# 4. Load the main app
if (file.exists("app.R")) {
  cat("✅ Loading main application...\n")
  source("app.R", local = FALSE)
}

cat("🎯 INITIALIZATION COMPLETE - Dashboard should display data correctly\n")