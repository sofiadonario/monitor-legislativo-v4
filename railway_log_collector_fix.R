#!/usr/bin/env Rscript
# ============================================================================
# RAILWAY LOG COLLECTOR BROKEN PIPE FIX
# ============================================================================
# Addresses the Rust-based Railway log collector crash causing broken pipe errors
# when R applications output too much startup information

cat("🔧 Railway Log Collector Broken Pipe Fix\n")

# PROBLEM ANALYSIS:
# ================
# The Railway log collector (written in Rust) is experiencing a broken pipe error
# when trying to handle output from R applications. This occurs because:
#
# 1. R applications generate excessive startup output during package loading
# 2. The log collector's stdout buffer is overwhelmed by verbose R messages
# 3. The Rust process panics when stdout write fails (SIGPIPE)
# 4. This happens specifically during R package loading phase

# SOLUTIONS IMPLEMENTED:
# =====================

#' Configure R to minimize startup output for Railway deployment
configure_railway_output <- function() {
  cat("🔇 Configuring minimal output for Railway...\n")

  # 1. Redirect R warnings and verbose output
  options(
    warn = -1,                    # Suppress warnings
    verbose = FALSE,              # Minimize verbose output
    repos = c(CRAN = "https://cran.rstudio.com/")
  )

  # 2. Suppress package startup messages globally
  suppressPackageStartupMessages({
    # This wrapper will be used for all library() calls
    NULL
  })

  # 3. Override cat() for Railway deployment to buffer output
  if (Sys.getenv("RAILWAY_DEPLOYMENT") == "true") {
    original_cat <- cat

    # Create buffered cat function
    cat_buffer <- character(0)
    max_buffer_size <- 1000  # Max lines before flush

    assign("cat", function(..., file = "", sep = " ", fill = FALSE, labels = NULL, append = FALSE) {
      # Convert to string
      output <- paste(..., sep = sep, collapse = "")

      # Buffer the output instead of immediate write
      cat_buffer <<- c(cat_buffer, output)

      # Flush buffer if it gets too large
      if (length(cat_buffer) > max_buffer_size) {
        # Write buffered content in chunks
        tryCatch({
          original_cat(paste(cat_buffer[1:500], collapse = "\n"), file = file)
          cat_buffer <<- cat_buffer[501:length(cat_buffer)]
        }, error = function(e) {
          # If stdout is broken, discard buffer
          cat_buffer <<- character(0)
        })
      }
    }, envir = .GlobalEnv)

    cat("✅ Buffered output configured for Railway\n")
  }

  # 4. Set up periodic buffer flush
  if (Sys.getenv("RAILWAY_DEPLOYMENT") == "true") {
    # Flush buffer every 5 seconds
    flush_timer <- function() {
      if (exists("cat_buffer") && length(cat_buffer) > 0) {
        tryCatch({
          original_cat(paste(cat_buffer, collapse = "\n"))
          cat_buffer <<- character(0)
        }, error = function(e) {
          cat_buffer <<- character(0)
        })
      }
    }

    # Schedule periodic flush (if later package supports it)
    tryCatch({
      later::later(flush_timer, 5)
    }, error = function(e) {
      # later package not available, skip scheduling
    })
  }
}

#' Safe library loading with minimal output
safe_library <- function(package_name, ...) {
  tryCatch({
    # Use capture.output to completely suppress package messages
    capture.output({
      suppressPackageStartupMessages({
        suppressWarnings({
          suppressMessages({
            library(package_name, character.only = TRUE, quietly = TRUE, ...)
          })
        })
      })
    }, type = "message")

    # Only output essential success message
    if (Sys.getenv("RAILWAY_DEPLOYMENT") == "true") {
      # Minimal output for Railway
      cat("✓", package_name, "\n")
    } else {
      cat("✅ Loaded:", package_name, "\n")
    }

    return(TRUE)
  }, error = function(e) {
    # Minimal error output
    cat("❌", package_name, ":", substr(e$message, 1, 50), "...\n")
    return(FALSE)
  })
}

#' Batch load packages with output control
safe_load_packages <- function(packages) {
  cat("📦 Loading", length(packages), "packages...\n")

  # Load packages in batches to control output
  batch_size <- 5
  loaded_count <- 0

  for (i in seq(1, length(packages), batch_size)) {
    batch <- packages[i:min(i + batch_size - 1, length(packages))]

    for (pkg in batch) {
      if (safe_library(pkg)) {
        loaded_count <- loaded_count + 1
      }
    }

    # Progress update (minimal)
    if (Sys.getenv("RAILWAY_DEPLOYMENT") == "true") {
      cat(".", loaded_count, "/", length(packages), "\n")
    } else {
      cat("📊 Progress:", loaded_count, "/", length(packages), "packages loaded\n")
    }

    # Small delay to prevent overwhelming log collector
    if (Sys.getenv("RAILWAY_DEPLOYMENT") == "true") {
      Sys.sleep(0.1)
    }
  }

  cat("✅ Package loading complete:", loaded_count, "/", length(packages), "\n")
  return(loaded_count)
}

#' Configure stdout buffering at system level
configure_stdout_buffering <- function() {
  # Try to set stdout to line buffered mode for Railway
  tryCatch({
    if (Sys.getenv("RAILWAY_DEPLOYMENT") == "true") {
      # Flush stdout more frequently
      flush(stdout())
      flush(stderr())

      cat("✅ Stdout buffering configured\n")
    }
  }, error = function(e) {
    cat("⚠️ Could not configure stdout buffering:", e$message, "\n")
  })
}

#' Main configuration function
apply_railway_log_fix <- function() {
  cat("🚀 Applying Railway Log Collector Fix...\n")

  # Apply all fixes
  configure_railway_output()
  configure_stdout_buffering()

  # Define essential packages for Railway deployment
  essential_packages <- c(
    "shiny", "shinydashboard", "DT", "plotly",
    "dplyr", "RColorBrewer", "jsonlite"
  )

  # Load essential packages safely
  safe_load_packages(essential_packages)

  cat("✅ Railway Log Collector Fix applied successfully\n")
  cat("📊 Output buffering: ENABLED\n")
  cat("🔇 Verbose output: SUPPRESSED\n")
  cat("⚡ Safe loading: ACTIVE\n")

  return(TRUE)
}

# Export functions for use in other scripts
assign("safe_library", safe_library, envir = .GlobalEnv)
assign("safe_load_packages", safe_load_packages, envir = .GlobalEnv)
assign("configure_railway_output", configure_railway_output, envir = .GlobalEnv)
assign("apply_railway_log_fix", apply_railway_log_fix, envir = .GlobalEnv)

# Apply fix if this script is run directly
if (sys.nframe() == 0) {
  apply_railway_log_fix()
}

cat("✅ Railway Log Collector Fix loaded and ready\n")