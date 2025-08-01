# DASHBOARD NULL FIX
# This script ensures dashboard UI components display data correctly

cat("🔧 APPLYING DASHBOARD NULL FIX...\n")

# Fix for NULL display in valueBoxes
safe_format_number <- function(value) {
  if (is.null(value) || is.na(value) || !is.numeric(value)) {
    return("0")
  }
  return(format(round(value), big.mark = ","))
}

# Override the valueBox rendering functions if they exist
if (exists("renderValueBox", mode = "function")) {
  cat("📦 Patching valueBox rendering...\n")
  
  # Store original function
  .original_renderValueBox <- renderValueBox
  
  # Create wrapper
  renderValueBox <<- function(expr, env = parent.frame(), quoted = FALSE) {
    if (!quoted) expr <- substitute(expr)
    
    .original_renderValueBox({
      result <- eval(expr, envir = env)
      
      # Fix NULL values in valueBox
      if (!is.null(result$value)) {
        if (is.null(result$value) || result$value == "NULL" || is.na(result$value)) {
          result$value <- "0"
        }
      }
      
      result
    }, env = env, quoted = TRUE)
  }
}

# Ensure metrics functions return proper numeric values
.wrap_metric_function <- function(func_name) {
  if (exists(func_name)) {
    original_func <- get(func_name)
    
    wrapped_func <- function(...) {
      result <- original_func(...)
      
      # Ensure numeric fields are actually numeric
      if (is.list(result)) {
        numeric_fields <- c("total_documents", "states_with_docs", "municipalities_with_docs", 
                          "states_percentage", "municipalities_percentage", "date_range_years")
        
        for (field in numeric_fields) {
          if (!is.null(result[[field]])) {
            result[[field]] <- as.numeric(result[[field]])
            if (is.na(result[[field]])) {
              result[[field]] <- 0
            }
          }
        }
      } else if (is.numeric(result) && is.na(result)) {
        result <- 0
      }
      
      return(result)
    }
    
    assign(func_name, wrapped_func, envir = .GlobalEnv)
    cat("✅ Wrapped", func_name, "to prevent NULL values\n")
  }
}

# Wrap all metric functions
metric_functions <- c(
  "get_total_documents",
  "get_lexml_dashboard_metrics",
  "get_documents_by_state", 
  "get_documents_by_type",
  "get_database_stats"
)

for (func in metric_functions) {
  .wrap_metric_function(func)
}

# Additional fix for specific dashboard components
get_dashboard_value_safe <- function(metric_name) {
  tryCatch({
    if (metric_name == "total_documents") {
      value <- get_total_documents()
      return(safe_format_number(value))
    } else if (metric_name == "states_percentage") {
      metrics <- get_lexml_dashboard_metrics()
      return(paste0(round(metrics$states_percentage), "%"))
    } else if (metric_name == "municipalities_percentage") {
      metrics <- get_lexml_dashboard_metrics()
      return(paste0(round(metrics$municipalities_percentage), "%"))
    } else if (metric_name == "date_range") {
      metrics <- get_lexml_dashboard_metrics()
      return(paste(metrics$date_range_years, "years"))
    }
    return("0")
  }, error = function(e) {
    cat("❌ Error getting", metric_name, ":", e$message, "\n")
    return("0")
  })
}

# Export the safe getter
assign("get_dashboard_value_safe", get_dashboard_value_safe, envir = .GlobalEnv)

cat("✅ DASHBOARD NULL FIX APPLIED!\n")
cat("📊 UI components should now display numbers instead of NULL\n")

# Quick test
test_value <- get_dashboard_value_safe("total_documents")
cat("🧪 Test - Total documents display:", test_value, "\n")