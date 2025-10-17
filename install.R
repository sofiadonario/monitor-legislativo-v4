# install.R - Railway build-time package installation

cat("========================================\n")
cat("Installing R package dependencies...\n")
cat("========================================\n")

# Core packages required for the app to boot
pkgs <- c(
  # Shiny ecosystem
  "shiny",
  "shinydashboard",

  # Data tables and visualization
  "DT",
  "leaflet",
  "plotly",
  "ggplot2",

  # Data manipulation
  "dplyr",
  "data.table",
  "tidyr",
  "stringr",
  "lubridate",

  # Database
  "DBI",
  "RPostgres",
  "pool",

  # Spatial/geographic
  "sf",
  "geobr",

  # Utilities
  "jsonlite",
  "httr",
  "glue",
  "digest",
  "htmltools",
  "RColorBrewer",
  "readr"
)

cat(sprintf("Installing %d packages...\n", length(pkgs)))

# Install with parallel compilation for speed
install.packages(
  pkgs,
  repos = "https://cloud.r-project.org",
  Ncpus = parallel::detectCores(),
  dependencies = TRUE
)

cat("========================================\n")
cat("Package installation complete!\n")
cat("========================================\n")

# Verify critical packages
critical <- c("shiny", "shinydashboard", "DT", "DBI", "RPostgres")
for (pkg in critical) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    stop(sprintf("CRITICAL: Package '%s' failed to install!", pkg))
  }
}

cat("✅ All critical packages verified\n")
