# Railway Path Fix for Maps Module
# This file helps locate the correct paths in Railway deployment

# Function to find the app root directory
find_app_root <- function() {
  # Common locations in Railway/Docker deployments
  possible_roots <- c(
    getwd(),
    "/srv/shiny-server",
    "/app",
    "/usr/app",
    "/home/app",
    dirname(getwd()),
    file.path(dirname(getwd()), "app"),
    "."
  )
  
  # Look for app.R in each location
  for (root in possible_roots) {
    if (file.exists(file.path(root, "app.R"))) {
      return(normalizePath(root, mustWork = FALSE))
    }
  }
  
  # If not found, return current directory
  return(getwd())
}

# Function to safely source a file with multiple path attempts
safe_source <- function(file_path, local = FALSE) {
  app_root <- find_app_root()
  
  # Try multiple path combinations
  paths_to_try <- c(
    file_path,  # As provided
    file.path(app_root, file_path),  # From app root
    file.path(getwd(), file_path),  # From working directory
    file.path("..", file_path),  # One level up
    file.path("../..", file_path)  # Two levels up
  )
  
  for (path in paths_to_try) {
    if (file.exists(path)) {
      cat("✅ Found file at:", path, "\n")
      source(path, local = local)
      return(TRUE)
    }
  }
  
  cat("❌ Could not find file:", file_path, "\n")
  cat("   Tried paths:\n")
  for (path in paths_to_try) {
    cat("   -", path, "(exists:", file.exists(path), ")\n")
  }
  return(FALSE)
}

# Export functions
assign("find_app_root", find_app_root, envir = .GlobalEnv)
assign("safe_source", safe_source, envir = .GlobalEnv)