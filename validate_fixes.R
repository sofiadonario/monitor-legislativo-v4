# Validation script for Docker build fixes
# This script checks the key components that were modified

cat("=== Docker Build Validation Script ===\n")

# Check if we're in the expected Ubuntu environment
if (file.exists("/etc/os-release")) {
  os_info <- readLines("/etc/os-release")
  ubuntu_line <- grep("Ubuntu", os_info, value = TRUE)
  if (length(ubuntu_line) > 0) {
    cat("OS:", ubuntu_line[1], "\n")
  }
}

# Check system library availability
cat("\n=== System Library Check ===\n")

# Check PROJ libraries
proj_check <- system("ldconfig -p | grep libproj", intern = TRUE, ignore.stderr = TRUE)
if (length(proj_check) > 0) {
  cat("PROJ libraries found:\n")
  for (lib in proj_check) {
    cat("  ", lib, "\n")
  }
} else {
  cat("WARNING: No PROJ libraries detected in ldconfig\n")
}

# Check ICU libraries
icu_check <- system("ldconfig -p | grep libicu", intern = TRUE, ignore.stderr = TRUE)
if (length(icu_check) > 0) {
  cat("ICU libraries found:\n")
  for (lib in head(icu_check, 3)) {
    cat("  ", lib, "\n")
  }
  if (length(icu_check) > 3) {
    cat("  ... and", length(icu_check) - 3, "more\n")
  }
} else {
  cat("WARNING: No ICU libraries detected in ldconfig\n")
}

cat("\n=== R Package Validation ===\n")

# Check key package versions and loading
packages_to_check <- c("stringi", "stringr", "scales", "ggplot2", "DBI", "sf")

for (pkg in packages_to_check) {
  if (pkg %in% rownames(installed.packages())) {
    version <- as.character(packageVersion(pkg))
    cat(sprintf("✓ %s: %s", pkg, version))

    # Special checks
    if (pkg == "scales" && packageVersion(pkg) >= "1.4.0") {
      cat(" (>= 1.4.0 ✓)")
    }

    # Try loading the package
    tryCatch({
      suppressPackageStartupMessages(library(pkg, character.only = TRUE))
      cat(" [loads OK]")
    }, error = function(e) {
      cat(" [LOAD FAILED:", e$message, "]")
    })
    cat("\n")
  } else {
    cat(sprintf("✗ %s: NOT INSTALLED\n", pkg))
  }
}

# Special sf linkage check
if ("sf" %in% rownames(installed.packages())) {
  cat("\n=== sf Library Linkage Check ===\n")

  # Find sf.so location
  sf_so_paths <- c(
    file.path(R.home("library"), "sf", "libs", "sf.so"),
    system.file("libs", "sf.so", package = "sf")
  )

  sf_so <- NULL
  for (path in sf_so_paths) {
    if (file.exists(path)) {
      sf_so <- path
      break
    }
  }

  if (!is.null(sf_so)) {
    cat("sf.so found at:", sf_so, "\n")

    # Check linkage
    ldd_result <- system(paste("ldd", sf_so, "2>/dev/null | grep -E '(libproj|libgdal|libgeos)'"),
                        intern = TRUE, ignore.stderr = TRUE)

    if (length(ldd_result) > 0) {
      cat("Key library linkages:\n")
      for (link in ldd_result) {
        cat("  ", trimws(link), "\n")
      }

      # Check specifically for PROJ version
      proj_links <- grep("libproj", ldd_result, value = TRUE)
      if (length(proj_links) > 0) {
        if (any(grepl("libproj\\.so\\.25", proj_links))) {
          cat("✓ sf links to libproj.so.25 (correct for Ubuntu 24.04)\n")
        } else if (any(grepl("libproj\\.so\\.22", proj_links))) {
          cat("✗ sf links to libproj.so.22 (INCORRECT - will cause runtime failure)\n")
        } else {
          cat("? sf links to unknown PROJ version\n")
        }
      }
    } else {
      cat("Could not determine sf.so linkage\n")
    }
  } else {
    cat("sf.so not found in expected locations\n")
  }
}

cat("\n=== Validation Complete ===\n")
cat("If running in Docker container, all packages should load successfully\n")
cat("and sf should link to libproj.so.25 for Ubuntu 24.04 compatibility.\n")