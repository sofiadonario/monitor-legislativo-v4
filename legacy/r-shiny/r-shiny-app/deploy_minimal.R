# Minimal Deployment Script
# Deploy with minimal packages to identify issues

cat("🚀 MINIMAL DEPLOYMENT - TROUBLESHOOTING MODE\n")
cat("=============================================\n\n")

# Load only essential packages
if (!require(rsconnect)) {
  install.packages("rsconnect")
  library(rsconnect)
}

cat("📦 Creating minimal app version...\n")

# Create a minimal .Rprofile for deployment
minimal_rprofile <- '# Minimal R Profile for Deployment Troubleshooting
options(repos = c(CRAN = "https://cloud.r-project.org/"))

# Essential packages only
essential_packages <- c(
  "shiny",
  "shinydashboard", 
  "DT",
  "dplyr",
  "httr",
  "jsonlite",
  "leaflet",
  "digest"
)

# Install missing packages
new_packages <- essential_packages[!(essential_packages %in% installed.packages()[,"Package"])]
if(length(new_packages)) {
  install.packages(new_packages, dependencies = TRUE)
}

# Load packages quietly
suppressMessages({
  lapply(essential_packages, library, character.only = TRUE)
})

# Basic settings
options(shiny.maxRequestSize = 30*1024^2)
'

# Backup original .Rprofile
if (file.exists(".Rprofile")) {
  file.copy(".Rprofile", ".Rprofile.backup", overwrite = TRUE)
  cat("✅ Backed up original .Rprofile\n")
}

# Write minimal .Rprofile
writeLines(minimal_rprofile, ".Rprofile")
cat("✅ Created minimal .Rprofile\n")

# Create minimal config.yml (commenting out problematic sections)
minimal_config <- 'apis:
  federal:
    camara:
      name: "Câmara dos Deputados"
      base_url: "https://dadosabertos.camara.leg.br/api/v2"
      rate_limit: 60
      endpoints:
        proposicoes: "/proposicoes"

app:
  name: "Monitor Legislativo Acadêmico"
  version: "1.0.0"
  cache_duration: 24
  max_results_per_query: 100

database:
  type: "SQLite"
  file: "data/legislative.db"
'

# Backup and replace config
if (file.exists("config.yml")) {
  file.copy("config.yml", "config.yml.backup", overwrite = TRUE)
  cat("✅ Backed up original config.yml\n")
}

writeLines(minimal_config, "config.yml")
cat("✅ Created minimal config.yml\n")

# Deploy with minimal setup
cat("\n🚀 Deploying minimal version...\n")
cat("This version has fewer packages and simplified config\n\n")

tryCatch({
  rsconnect::deployApp(
    appDir = ".",
    appName = "academic-legislative-monitor-test",
    appTitle = "Academic Monitor (Test)",
    forceUpdate = TRUE,
    launch.browser = TRUE
  )
  
  cat("\n✅ MINIMAL DEPLOYMENT SUCCESSFUL!\n")
  cat("🔗 Test the minimal version first\n")
  cat("📋 Login with: admin / admin123\n\n")
  
  cat("🔄 To restore full version:\n")
  cat("1. If minimal works, gradually add packages back\n")
  cat("2. Restore files: file.copy('.Rprofile.backup', '.Rprofile', overwrite=TRUE)\n")
  cat("3. Restore config: file.copy('config.yml.backup', 'config.yml', overwrite=TRUE)\n")
  
}, error = function(e) {
  cat("\n❌ Even minimal deployment failed!\n")
  cat("Error:", e$message, "\n\n")
  
  cat("📝 Check logs with: rsconnect::showLogs()\n")
  cat("🔍 The issue might be:\n")
  cat("   - Account/authentication problem\n")
  cat("   - Network connectivity\n")
  cat("   - App name conflict\n")
  cat("   - File permission issues\n")
  
  # Restore original files
  if (file.exists(".Rprofile.backup")) {
    file.copy(".Rprofile.backup", ".Rprofile", overwrite = TRUE)
  }
  if (file.exists("config.yml.backup")) {
    file.copy("config.yml.backup", "config.yml", overwrite = TRUE)
  }
})

cat("\n=== MINIMAL DEPLOYMENT COMPLETE ===\n")