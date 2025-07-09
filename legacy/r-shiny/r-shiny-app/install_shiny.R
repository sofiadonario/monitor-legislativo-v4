# Install Shiny for Monitor Legislativo v4
cat("🚀 Installing Shiny package...\n")

# Set up user library
user_lib <- path.expand("~/R/library")
if (!dir.exists(user_lib)) {
  dir.create(user_lib, recursive = TRUE)
  cat("📁 Created user library:", user_lib, "\n")
}

# Set library paths
.libPaths(c(user_lib, .libPaths()))
cat("📍 Library paths:", .libPaths(), "\n")

# Set CRAN mirror
options(repos = c(CRAN = "https://cloud.r-project.org/"))

# Try to install shiny with minimal dependencies
cat("📦 Installing shiny package...\n")
tryCatch({
  install.packages("shiny", lib = user_lib, dependencies = c("Depends", "Imports"), quiet = FALSE)
  cat("✅ Shiny installation completed\n")
}, error = function(e) {
  cat("❌ Shiny installation failed:", e$message, "\n")
  
  # Try with even fewer dependencies
  cat("🔄 Trying with minimal dependencies...\n")
  tryCatch({
    install.packages("shiny", lib = user_lib, dependencies = FALSE, quiet = FALSE)
    cat("✅ Shiny basic installation completed\n")
  }, error = function(e2) {
    cat("❌ Minimal installation also failed:", e2$message, "\n")
  })
})

# Test if shiny can be loaded
cat("\n🧪 Testing Shiny installation...\n")
tryCatch({
  library(shiny, lib.loc = user_lib)
  cat("✅ Shiny loads successfully!\n")
  
  # Test basic functionality
  cat("📋 Shiny version:", packageVersion("shiny"), "\n")
  
  # Create a simple test
  test_ui <- fluidPage(h1("Test"))
  cat("✅ Basic Shiny UI creation works\n")
  
}, error = function(e) {
  cat("❌ Shiny failed to load:", e$message, "\n")
})

cat("\n🎯 Installation summary:\n")
cat("Library path:", user_lib, "\n")
installed_packages <- installed.packages(lib.loc = user_lib)
if (nrow(installed_packages) > 0) {
  cat("Installed packages:", nrow(installed_packages), "\n")
  if ("shiny" %in% installed_packages[,"Package"]) {
    cat("✅ Shiny is installed\n")
  } else {
    cat("❌ Shiny not found in installed packages\n")
  }
} else {
  cat("❌ No packages found in user library\n")
}