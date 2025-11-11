# Test script to verify Estado Mapeado module loads correctly
cat("=== Testing Estado Mapeado Module ===\n")

# Test 1: Check if files exist
cat("\n1. Checking if module files exist...\n")
ui_file <- "modules/maps/estado_mapeado_ui.R"
server_file <- "modules/maps/estado_mapeado_server.R"

if (file.exists(ui_file)) {
  cat("✅ UI module file exists:", ui_file, "\n")
} else {
  cat("❌ UI module file NOT found:", ui_file, "\n")
}

if (file.exists(server_file)) {
  cat("✅ Server module file exists:", server_file, "\n")
} else {
  cat("❌ Server module file NOT found:", server_file, "\n")
}

# Test 2: Try to source the modules
cat("\n2. Attempting to load modules...\n")

tryCatch({
  source(ui_file)
  cat("✅ UI module loaded successfully\n")

  if (exists("estadoMapeadoUI")) {
    cat("✅ estadoMapeadoUI function is available\n")
  } else {
    cat("❌ estadoMapeadoUI function not found after sourcing\n")
  }
}, error = function(e) {
  cat("❌ Error loading UI module:", e$message, "\n")
})

tryCatch({
  source(server_file)
  cat("✅ Server module loaded successfully\n")

  if (exists("estadoMapeadoServer")) {
    cat("✅ estadoMapeadoServer function is available\n")
  } else {
    cat("❌ estadoMapeadoServer function not found after sourcing\n")
  }
}, error = function(e) {
  cat("❌ Error loading Server module:", e$message, "\n")
})

# Test 3: Check required packages
cat("\n3. Checking required packages...\n")
required_packages <- c("shiny", "leaflet", "sf", "DBI", "dplyr", "DT")

for (pkg in required_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat("✅", pkg, "is installed\n")
  } else {
    cat("⚠️", pkg, "is NOT installed (required)\n")
  }
}

cat("\n=== Module Test Complete ===\n")
cat("\nIf all tests passed, restart your Shiny app to see the new 'Mapa por Estado' tab.\n")
cat("The tab should appear in: Geographic → Mapa por Estado\n")
