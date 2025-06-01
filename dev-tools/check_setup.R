# Setup Verification Script
# This checks if everything is ready for deployment

cat("\n📋 SETUP VERIFICATION FOR ACADEMIC LEGISLATIVE MONITOR\n")
cat("=" , rep("=", 50), "\n", sep = "")

# 1. Check R version
cat("\n1️⃣ R Version Check:\n")
r_version <- R.version.string
cat("   ", r_version, "\n")
if (as.numeric(R.version$major) >= 4) {
  cat("   ✅ R version is 4.0 or higher\n")
} else {
  cat("   ⚠️  R version is below 4.0, please update\n")
}

# 2. Check working directory
cat("\n2️⃣ Working Directory:\n")
cat("   ", getwd(), "\n")

# 3. Check for required files
cat("\n3️⃣ Required Files:\n")
required_files <- c(
  "app.R", "config.yml", ".Rprofile",
  "R/auth.R", "R/api_client.R", "R/database.R",
  "R/data_processor.R", "R/map_generator.R", "R/export_utils.R"
)

all_present <- TRUE
for (file in required_files) {
  if (file.exists(file)) {
    cat("   ✅", file, "\n")
  } else {
    cat("   ❌", file, "- MISSING\n")
    all_present <- FALSE
  }
}

# 4. Check for rsconnect package
cat("\n4️⃣ Deployment Package:\n")
if ("rsconnect" %in% installed.packages()[,"Package"]) {
  cat("   ✅ rsconnect is installed\n")
  library(rsconnect)
  
  # Check for configured accounts
  accounts <- rsconnect::accounts()
  if (nrow(accounts) > 0) {
    cat("   ✅ Shinyapps.io account configured:", accounts$name[1], "\n")
  } else {
    cat("   ⚠️  No Shinyapps.io account configured\n")
    cat("   Run: rsconnect::setAccountInfo(...) with your credentials\n")
  }
} else {
  cat("   ❌ rsconnect not installed\n")
  cat("   Run: install.packages('rsconnect')\n")
}

# 5. Check for key packages
cat("\n5️⃣ Key R Packages:\n")
key_packages <- c("shiny", "shinydashboard", "leaflet", "DBI", "httr", "digest")
for (pkg in key_packages) {
  if (pkg %in% installed.packages()[,"Package"]) {
    cat("   ✅", pkg, "\n")
  } else {
    cat("   ❌", pkg, "- Not installed\n")
  }
}

# 6. Directory structure
cat("\n6️⃣ Directory Structure:\n")
dirs <- c("R", "data", "www")
for (dir in dirs) {
  if (dir.exists(dir)) {
    cat("   ✅", dir, "/ exists\n")
  } else {
    cat("   ⚠️ ", dir, "/ missing - creating...\n")
    dir.create(dir, showWarnings = FALSE)
  }
}

# Summary
cat("\n📊 SUMMARY:\n")
cat("=" , rep("=", 50), "\n", sep = "")

if (all_present) {
  cat("✅ All files present - ready for deployment!\n")
  cat("\nNext steps:\n")
  cat("1. If you haven't already, create account at https://www.shinyapps.io/\n")
  cat("2. Configure account: rsconnect::setAccountInfo(...)\n")
  cat("3. Run deployment: source('deploy_simple.R')\n")
} else {
  cat("❌ Some files are missing!\n")
  cat("\nPossible issues:\n")
  cat("1. You might be in the wrong directory\n")
  cat("2. Files weren't copied properly\n")
  cat("\nTry:\n")
  cat("setwd('C:/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/academic-map-app/r-shiny-app')\n")
  cat("Then run this script again: source('check_setup.R')\n")
}

cat("\n")