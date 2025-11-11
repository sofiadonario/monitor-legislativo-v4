#!/usr/bin/env Rscript
# =============================================================================
# R Code Formatting and Linting Automation Script
# Applies comprehensive formatting and linting to the entire R codebase.
#
# This script:
# 1. Uses styler to format R code according to tidyverse style guide
# 2. Uses lintr to check for linting issues and code quality problems
# 3. Generates a formatting report
#
# Usage:
#   Rscript scripts/format_r.R [--dry-run] [--path=PATH] [--help]
# =============================================================================

# Load required libraries
suppressPackageStartupMessages({
  if (!require("optparse", quietly = TRUE)) {
    install.packages("optparse", repos = "https://cran.r-project.org")
    library(optparse)
  }
  
  # Check and install formatting packages if needed
  required_packages <- c("styler", "lintr", "here")
  for (pkg in required_packages) {
    if (!require(pkg, character.only = TRUE, quietly = TRUE)) {
      cat("Installing", pkg, "...\n")
      install.packages(pkg, repos = "https://cran.r-project.org")
      library(pkg, character.only = TRUE, quietly = TRUE)
    }
  }
})

# Command line options
option_list <- list(
  make_option(c("--dry-run"), action = "store_true", default = FALSE,
              help = "Show what would be done without making changes"),
  make_option(c("--path"), type = "character", default = NULL,
              help = "Specific path to format (default: entire project)"),
  make_option(c("--verbose"), action = "store_true", default = FALSE,
              help = "Enable verbose output"),
  make_option(c("--help"), action = "store_true", default = FALSE,
              help = "Show this help message")
)

# Parse arguments
opt_parser <- OptionParser(
  option_list = option_list,
  description = "Format and lint R code in the Monitor Legislativo v4 project",
  epilogue = "Examples:\n  Rscript scripts/format_r.R --dry-run\n  Rscript scripts/format_r.R --path=scripts/R/"
)
args <- parse_args(opt_parser)

# Show help if requested
if (args$help) {
  print_help(opt_parser)
  quit(status = 0)
}

# =============================================================================
# Configuration and Setup
# =============================================================================

# Find project root
script_path <- here::here()
if (!file.exists(file.path(script_path, ".lintr"))) {
  stop("Could not find .lintr file. Make sure you're running from the project root.")
}

# Global variables for tracking results
errors <- character(0)
warnings <- character(0)
fixes_applied <- character(0)
files_processed <- 0
total_files <- 0

# Directories to exclude
exclude_dirs <- c(
  "legacy", "archive", "cache", "logs", "temp_venv", "check_env",
  "lexml_env", "reload_env", "node_modules", ".git", ".Rproj.user",
  "__pycache__", ".pytest_cache", "htmlcov", "build", "dist", 
  ".venv", "venv", ".tox", ".nox", "packrat", "renv"
)

# =============================================================================
# Utility Functions
# =============================================================================

#' Print formatted message with emoji and timestamp
#' @param emoji The emoji to use
#' @param message The message to print
#' @param level Message level (info, warning, error)
print_message <- function(emoji, message, level = "info") {
  timestamp <- format(Sys.time(), "%H:%M:%S")
  if (level == "error") {
    cat(sprintf("[%s] %s ❌ %s\n", timestamp, emoji, message))
  } else if (level == "warning") {
    cat(sprintf("[%s] %s ⚠️  %s\n", timestamp, emoji, message))
  } else {
    cat(sprintf("[%s] %s %s\n", timestamp, emoji, message))
  }
}

#' Find all R files in the specified path
#' @param search_path Path to search (default: project root)
#' @return Vector of R file paths
find_r_files <- function(search_path = script_path) {
  print_message("🔍", "Finding R files...")
  
  # Get all R files
  r_files <- list.files(
    path = search_path,
    pattern = "\\.R$",
    recursive = TRUE,
    full.names = TRUE,
    ignore.case = TRUE
  )
  
  # Filter out excluded directories and files
  r_files_filtered <- r_files[!sapply(r_files, function(f) {
    path_parts <- unlist(strsplit(f, .Platform$file.sep))
    any(exclude_dirs %in% path_parts) ||
      grepl("\\.(tmp|bak|orig|backup)$", f) ||
      basename(f) %in% c("packrat.lock", "renv.lock")
  })]
  
  total_files <<- length(r_files_filtered)
  
  if (args$verbose) {
    cat("   📄 Found", length(r_files_filtered), "R files:\n")
    if (length(r_files_filtered) <= 10) {
      for (f in r_files_filtered) {
        cat("      ", gsub(paste0(script_path, .Platform$file.sep), "", f), "\n")
      }
    } else {
      for (f in head(r_files_filtered, 5)) {
        cat("      ", gsub(paste0(script_path, .Platform$file.sep), "", f), "\n")
      }
      cat("      ... and", length(r_files_filtered) - 5, "more files\n")
    }
  }
  
  return(r_files_filtered)
}

#' Format R files using styler
#' @param files Vector of R file paths
#' @return TRUE if successful, FALSE otherwise
format_with_styler <- function(files) {
  print_message("🎨", "Formatting R code with styler...")
  
  if (length(files) == 0) {
    print_message("ℹ️", "No R files found to format")
    return(TRUE)
  }
  
  success <- TRUE
  formatted_count <- 0
  
  tryCatch({
    for (file in files) {
      files_processed <<- files_processed + 1
      
      if (args$verbose) {
        relative_path <- gsub(paste0(script_path, .Platform$file.sep), "", file)
        cat(sprintf("   [%d/%d] Processing: %s\n", files_processed, total_files, relative_path))
      }
      
      if (args$dry_run) {
        # In dry-run mode, check if file would be changed
        tryCatch({
          # Read original file
          original_content <- readLines(file, warn = FALSE)
          
          # Create temporary styled version
          temp_file <- tempfile(fileext = ".R")
          file.copy(file, temp_file)
          
          # Style the temp file
          styler::style_file(temp_file, strict = TRUE, scope = "tokens")
          styled_content <- readLines(temp_file, warn = FALSE)
          
          # Compare content
          if (!identical(original_content, styled_content)) {
            formatted_count <- formatted_count + 1
            if (args$verbose) {
              cat("      Would format this file\n")
            }
          }
          
          # Clean up
          unlink(temp_file)
          
        }, error = function(e) {
          warning_msg <- paste("Could not check formatting for", basename(file), ":", e$message)
          warnings <<- c(warnings, warning_msg)
          if (args$verbose) {
            cat("      ⚠️ ", warning_msg, "\n")
          }
        })
      } else {
        # Actually format the file
        tryCatch({
          # Check if file needs formatting
          original_content <- readLines(file, warn = FALSE)
          
          styler::style_file(file, strict = TRUE, scope = "tokens")
          
          # Check if file was changed
          new_content <- readLines(file, warn = FALSE)
          if (!identical(original_content, new_content)) {
            formatted_count <- formatted_count + 1
            if (args$verbose) {
              cat("      ✅ Formatted\n")
            }
          } else if (args$verbose) {
            cat("      Already formatted\n")
          }
          
        }, error = function(e) {
          error_msg <- paste("Failed to format", basename(file), ":", e$message)
          errors <<- c(errors, error_msg)
          success <- FALSE
          if (args$verbose) {
            cat("      ❌", error_msg, "\n")
          }
        })
      }
    }
    
    if (formatted_count > 0) {
      if (args$dry_run) {
        print_message("📋", paste("Would format", formatted_count, "files"))
        warnings <<- c(warnings, paste("styler: Would format", formatted_count, "files"))
      } else {
        print_message("✅", paste("Formatted", formatted_count, "files with styler"))
        fixes_applied <<- c(fixes_applied, paste("styler: Formatted", formatted_count, "files"))
      }
    } else {
      print_message("✅", "All R files already properly formatted")
    }
    
  }, error = function(e) {
    error_msg <- paste("styler formatting failed:", e$message)
    errors <<- c(errors, error_msg)
    print_message("", error_msg, "error")
    success <- FALSE
  })
  
  return(success)
}

#' Lint R files using lintr
#' @param files Vector of R file paths
#' @return TRUE if successful, FALSE otherwise
lint_with_lintr <- function(files) {
  print_message("🔍", "Linting R code with lintr...")
  
  if (length(files) == 0) {
    print_message("ℹ️", "No R files found to lint")
    return(TRUE)
  }
  
  total_issues <- 0
  files_with_issues <- 0
  success <- TRUE
  
  tryCatch({
    for (file in files) {
      if (args$verbose) {
        relative_path <- gsub(paste0(script_path, .Platform$file.sep), "", file)
        cat(sprintf("   Linting: %s\n", relative_path))
      }
      
      tryCatch({
        # Lint the file
        lints <- lintr::lint(file)
        
        if (length(lints) > 0) {
          files_with_issues <- files_with_issues + 1
          total_issues <- total_issues + length(lints)
          
          if (args$verbose) {
            cat(sprintf("      Found %d issues:\n", length(lints)))
            for (lint in lints) {
              cat(sprintf("        Line %d: %s [%s]\n", 
                         lint$line_number, lint$message, lint$linter))
            }
          }
        } else if (args$verbose) {
          cat("      ✅ No issues found\n")
        }
        
      }, error = function(e) {
        error_msg <- paste("Failed to lint", basename(file), ":", e$message)
        errors <<- c(errors, error_msg)
        success <- FALSE
        if (args$verbose) {
          cat("      ❌", error_msg, "\n")
        }
      })
    }
    
    if (total_issues > 0) {
      warning_msg <- sprintf("Found %d linting issues in %d files", total_issues, files_with_issues)
      print_message("⚠️", warning_msg, "warning")
      warnings <<- c(warnings, paste("lintr:", warning_msg))
    } else {
      print_message("✅", "No linting issues found")
    }
    
  }, error = function(e) {
    error_msg <- paste("lintr linting failed:", e$message)
    errors <<- c(errors, error_msg)
    print_message("", error_msg, "error")
    success <- FALSE
  })
  
  return(success)
}

#' Check if required R packages are available
#' @return TRUE if all dependencies are available
check_dependencies <- function() {
  print_message("🔍", "Checking R package dependencies...")
  
  required_packages <- c("styler", "lintr")
  missing_packages <- character(0)
  
  for (pkg in required_packages) {
    if (require(pkg, character.only = TRUE, quietly = TRUE)) {
      if (args$verbose) {
        cat("   ✅", pkg, "is available\n")
      }
    } else {
      cat("   ❌", pkg, "is not available\n")
      missing_packages <- c(missing_packages, pkg)
    }
  }
  
  if (length(missing_packages) > 0) {
    print_message("", paste("Missing packages:", paste(missing_packages, collapse = ", ")), "error")
    cat("Install them with: install.packages(c(", 
        paste(paste0("\"", missing_packages, "\""), collapse = ", "), "))\n")
    return(FALSE)
  }
  
  return(TRUE)
}

#' Print summary of formatting session
print_summary <- function() {
  cat("\n", paste(rep("=", 60), collapse = ""), "\n")
  cat("📊 R FORMATTING SUMMARY\n")
  cat(paste(rep("=", 60), collapse = ""), "\n")
  
  cat("📈 Files processed:", files_processed, "/", total_files, "\n")
  
  if (length(fixes_applied) > 0) {
    cat(sprintf("✅ Fixes applied (%d):\n", length(fixes_applied)))
    for (fix in fixes_applied) {
      cat("   •", fix, "\n")
    }
  }
  
  if (length(warnings) > 0) {
    cat(sprintf("\n⚠️  Warnings (%d):\n", length(warnings)))
    for (warning in warnings) {
      cat("   •", warning, "\n")
    }
  }
  
  if (length(errors) > 0) {
    cat(sprintf("\n❌ Errors (%d):\n", length(errors)))
    for (error in errors) {
      cat("   •", error, "\n")
    }
  }
  
  if (isTRUE(length(fixes_applied) == 0) && isTRUE(length(warnings) == 0) && length(errors) == 0) {
    cat("🎉 All R code is already properly formatted and linted!\n")
  }
  
  cat("\n💡 Next steps:\n")
  if (args$dry_run && (isTRUE(length(warnings) > 0) || length(fixes_applied) > 0)) {
    cat("   • Run without --dry-run to apply changes\n")
  }
  cat("   • Run pre-commit install to enable automatic formatting\n")
  cat("   • Consider setting up RStudio to use styler for formatting\n")
  cat("   • Review .lintr configuration if needed\n")
}

# =============================================================================
# Main Function
# =============================================================================

#' Main formatting function
format_all <- function() {
  print_message("🚀", "Starting R code formatting and linting...")
  cat("📁 Project root:", script_path, "\n")
  
  if (args$dry_run) {
    print_message("🔍", "Running in DRY RUN mode - no changes will be made")
  }
  
  # Check dependencies
  if (!check_dependencies()) {
    return(FALSE)
  }
  
  # Determine search path
  search_path <- if (!is.null(args$path)) {
    if (file.exists(args$path)) {
      args$path
    } else {
      file.path(script_path, args$path)
    }
  } else {
    script_path
  }
  
  if (!file.exists(search_path)) {
    print_message("", paste("Path does not exist:", search_path), "error")
    return(FALSE)
  }
  
  # Find R files
  r_files <- find_r_files(search_path)
  
  if (length(r_files) == 0) {
    print_message("ℹ️", "No R files found to process")
    return(TRUE)
  }
  
  cat("\n")
  
  # Run formatting and linting
  success <- TRUE
  
  # 1. Format with styler
  if (!format_with_styler(r_files)) {
    success <- FALSE
  }
  
  cat("\n")
  
  # 2. Lint with lintr
  if (!lint_with_lintr(r_files)) {
    success <- FALSE
  }
  
  return(success)
}

# =============================================================================
# Script Execution
# =============================================================================

# Main execution
tryCatch({
  success <- format_all()
  print_summary()
  
  if (!success) {
    quit(status = 1)
  }
  
}, interrupt = function(e) {
  cat("\n\n⚠️  R formatting interrupted by user\n")
  quit(status = 1)
}, error = function(e) {
  cat("\n\n❌ Unexpected error:", e$message, "\n")
  quit(status = 1)
})

cat("\n🎯 R code formatting and linting completed!\n")