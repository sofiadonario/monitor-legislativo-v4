# Install R packages for Monitor Legislativo v4
# Uses user library to avoid permission issues

# Set up user library path
user_lib <- path.expand("~/R/library")
if (!dir.exists(user_lib)) {
  dir.create(user_lib, recursive = TRUE)
}
.libPaths(c(user_lib, .libPaths()))

cat("📦 Installing R packages to user library:\n")
cat("📍 Library path:", user_lib, "\n\n")

# Set CRAN mirror
options(repos = c(CRAN = "https://cloud.r-project.org/"))

# Essential packages for R Shiny
essential_packages <- c(
  "shiny",
  "shinydashboard", 
  "DT",
  "dplyr",
  "httr",
  "jsonlite"
)

# Full package list
all_packages <- c(
  # Core Shiny
  "shiny", "shinydashboard", "DT", "shinyjs", "shinyWidgets",
  
  # Data manipulation
  "dplyr", "tidyr", "stringr", "lubridate", "purrr",
  
  # Web and APIs
  "httr", "jsonlite", "yaml", "curl",
  
  # Geographic data
  "sf", "leaflet",
  
  # Database
  "DBI", "RSQLite",
  
  # Authentication
  "digest",
  
  # Export
  "openxlsx", "xml2", "htmltools",
  
  # Visualization
  "ggplot2", "viridis", "scales"
)

# Function to install packages safely
install_package_safe <- function(pkg) {
  tryCatch({
    if (!require(pkg, character.only = TRUE, quietly = TRUE)) {
      cat("📦 Installing", pkg, "...\n")
      install.packages(pkg, lib = user_lib, dependencies = TRUE, quiet = FALSE)
      cat("✅", pkg, "installed successfully\n")
      return(TRUE)
    } else {
      cat("✅", pkg, "already installed\n")
      return(TRUE)
    }
  }, error = function(e) {
    cat("❌ Failed to install", pkg, ":", e$message, "\n")
    return(FALSE)
  })
}

# Install essential packages first
cat("🔧 Installing essential packages...\n")
essential_success <- sapply(essential_packages, install_package_safe)

if (all(essential_success)) {
  cat("\n✅ Essential packages installed successfully!\n")
  cat("🔧 Installing additional packages...\n\n")
  
  # Install remaining packages
  remaining_packages <- setdiff(all_packages, essential_packages)
  additional_success <- sapply(remaining_packages, install_package_safe)
  
  if (all(c(essential_success, additional_success))) {
    cat("\n🎉 All packages installed successfully!\n")
  } else {
    cat("\n⚠️ Some additional packages failed to install, but essentials are working\n")
  }
} else {
  cat("\n❌ Essential package installation failed\n")
  failed_essential <- names(essential_success)[!essential_success]
  cat("Failed packages:", paste(failed_essential, collapse = ", "), "\n")
}

# Test basic functionality
cat("\n🧪 Testing basic functionality...\n")
tryCatch({
  library(shiny)
  library(shinydashboard)
  library(DT)
  library(dplyr)
  library(httr)
  library(jsonlite)
  cat("✅ Core packages load successfully\n")
}, error = function(e) {
  cat("❌ Package loading test failed:", e$message, "\n")
})

cat("\n📋 Installation complete!\n")
cat("📍 Packages installed in:", user_lib, "\n")

# Show installed packages
installed_pkgs <- installed.packages(lib.loc = user_lib)[, "Package"]
cat("📦 Installed packages:", length(installed_pkgs), "\n")
cat("✅ Setup ready for Shiny app!\n")