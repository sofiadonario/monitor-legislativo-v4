# ANALYTICS DATA EMERGENCY OVERRIDE
# =================================
# This file provides emergency fallback for analytics_data reactive function
# when CSV files are missing on Railway deployment

cat("🚨 ANALYTICS DATA EMERGENCY OVERRIDE ACTIVATED\n")
cat("==============================================\n")

# Override analytics_data reactive function to use emergency data
create_emergency_analytics_data_reactive <- function() {

  cat("Creating emergency analytics_data reactive function...\n")

  # Create the emergency reactive function
  emergency_analytics_reactive <- function() {
    cat("=== EMERGENCY ANALYTICS DATA DEBUG ===\n")

    # Try the original fixed CSV function first
    tryCatch({
      if (exists("analytics_data_fixed_csv")) {
        result <- analytics_data_fixed_csv()
        if (!is.null(result) && nrow(result) > 0) {
          cat("✅ Using CSV fixed data:", nrow(result), "documents\n")
          return(result)
        }
      }
    }, error = function(e) {
      cat("⚠️ CSV fixed data failed:", e$message, "\n")
    })

    # Try emergency data as fallback
    tryCatch({
      if (exists("emergency_analytics_data")) {
        result <- emergency_analytics_data()
        if (!is.null(result) && nrow(result) > 0) {
          cat("✅ Using EMERGENCY data:", nrow(result), "documents\n")

          # Ensure column compatibility with existing app
          if (!"category" %in% colnames(result) && "categoria" %in% colnames(result)) {
            result$category <- result$categoria
          }
          if (!"state" %in% colnames(result) && "estado" %in% colnames(result)) {
            result$state <- result$estado
          }
          if (!"year" %in% colnames(result) && "ano" %in% colnames(result)) {
            result$year <- as.numeric(result$ano)
          }
          if (!"title" %in% colnames(result) && "titulo" %in% colnames(result)) {
            result$title <- result$titulo
          }
          if (!"summary" %in% colnames(result) && "ementa" %in% colnames(result)) {
            result$summary <- result$ementa
          }
          if (!"document_type" %in% colnames(result) && "tipo" %in% colnames(result)) {
            result$document_type <- result$tipo
          }
          if (!"authority" %in% colnames(result) && "autoridade" %in% colnames(result)) {
            result$authority <- result$autoridade
          }
          if (!"date" %in% colnames(result) && "data" %in% colnames(result)) {
            result$date <- result$data
          }

          cat("✅ Column mapping applied for emergency data\n")
          return(result)
        }
      }
    }, error = function(e) {
      cat("❌ Emergency analytics data failed:", e$message, "\n")
    })

    # Ultimate fallback - create minimal structure
    cat("⚠️ Creating minimal fallback data structure\n")
    fallback_data <- data.frame(
      titulo = "Dados Temporariamente Indisponíveis",
      title = "Data Temporarily Unavailable",
      categoria = "Sistema",
      category = "System",
      modal = "geral",
      estado = "SP",
      state = "SP",
      ano = "2025",
      year = 2025,
      data = Sys.Date(),
      date = Sys.Date(),
      tipo = "Aviso",
      document_type = "Notice",
      autoridade = "Sistema",
      authority = "System",
      ementa = "Dados estão sendo carregados. Tente novamente em alguns instantes.",
      summary = "Data is being loaded. Please try again in a few moments.",
      stringsAsFactors = FALSE
    )

    return(fallback_data)
  }

  return(emergency_analytics_reactive)
}

# Create and store the emergency function
analytics_data_EMERGENCY_REACTIVE <<- create_emergency_analytics_data_reactive()

cat("✅ Emergency analytics_data reactive function created\n")
cat("==============================================\n")

# Function to override the analytics_data in existing app
override_analytics_data_with_emergency <- function() {

  cat("🔄 Attempting to override analytics_data with emergency version...\n")

  # Check if we're in a Shiny context
  if (exists("reactive", where = "package:shiny")) {

    # Create emergency reactive version
    tryCatch({
      analytics_data_original <<- if(exists("analytics_data")) analytics_data else NULL

      # Override with emergency version
      analytics_data <<- reactive({
        analytics_data_EMERGENCY_REACTIVE()
      })

      cat("✅ analytics_data reactive function overridden with emergency version\n")

    }, error = function(e) {
      cat("❌ Failed to override analytics_data reactive:", e$message, "\n")
    })

  } else {
    cat("⚠️ Not in Shiny context, emergency override will be available when needed\n")
  }
}

# Test emergency reactive function
cat("Testing emergency reactive function...\n")
tryCatch({
  test_result <- analytics_data_EMERGENCY_REACTIVE()
  cat("✅ Emergency reactive test successful:", nrow(test_result), "documents\n")
}, error = function(e) {
  cat("❌ Emergency reactive test failed:", e$message, "\n")
})

cat("==============================================\n")
cat("🏁 ANALYTICS EMERGENCY OVERRIDE READY\n")
cat("==============================================\n")
cat("Call override_analytics_data_with_emergency() to activate\n")
cat("==============================================\n")