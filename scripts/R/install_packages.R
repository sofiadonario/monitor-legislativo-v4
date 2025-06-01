# Package Installation for Railway Deployment
# Ensures all required packages for comprehensive framework are available
# Date: 2025-07-26

cat("📦 Installing packages for Railway deployment...\n")

# Core packages that MUST be available
core_packages <- c(
  "shiny",
  "shinydashboard", 
  "DT",
  "dplyr",
  "jsonlite",
  "plotly",
  "ggplot2",
  "leaflet",
  "stringr",
  "markdown"
)

# Comprehensive framework packages
framework_packages <- c(
  "arrow",        # For parquet file reading
  "data.table",   # For efficient data processing
  "lubridate",    # For date handling
  "purrr"         # For functional programming
)

# Database packages
db_packages <- c(
  "DBI",
  "RPostgres",
  "pool"
)

# All required packages
all_packages <- c(core_packages, framework_packages, db_packages)

# Function to install package safely
install_package_safe <- function(pkg) {
  if (!require(pkg, quietly = TRUE, character.only = TRUE)) {
    cat("📦 Installing", pkg, "...\n")
    tryCatch({
      install.packages(pkg, repos = "https://cran.rstudio.com/", 
                      dependencies = TRUE, quiet = TRUE)
      library(pkg, character.only = TRUE)
      cat("✅", pkg, "installed successfully\n")
      return(TRUE)
    }, error = function(e) {
      cat("❌ Failed to install", pkg, ":", e$message, "\n")
      return(FALSE)
    })
  } else {
    cat("✅", pkg, "already available\n")
    return(TRUE)
  }
}

# Install all packages
cat("🚀 Starting package installation...\n")
installation_results <- sapply(all_packages, install_package_safe)

# Summary
successful_installs <- sum(installation_results)
total_packages <- length(all_packages)

cat("\n📊 Installation Summary:\n")
cat("✅ Successfully installed/verified:", successful_installs, "packages\n")
cat("📦 Total packages required:", total_packages, "\n")

if (successful_installs == total_packages) {
  cat("🎉 All packages ready for Railway deployment!\n")
} else {
  failed_packages <- names(installation_results)[!installation_results]
  cat("⚠️ Failed to install:", length(failed_packages), "packages\n")
  cat("❌ Failed packages:", paste(failed_packages, collapse = ", "), "\n")
  cat("💡 The app will use fallback modes for missing packages\n")
}

cat("✅ Package installation script completed\n")