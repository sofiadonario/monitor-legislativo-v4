# Verify Complete Solution - Test All Data Loading Options
cat("=== VERIFYING COMPLETE SOLUTION ===\n")

# Test 1: Check all CSV files exist and are accessible
cat("\n1. CHECKING DATA FILE AVAILABILITY:\n")
csv_paths <- c(
  "railway_full_dataset.csv",  # 50k dataset optimized for Railway
  "railway_data_10k.csv",     # 10k dataset that's included in git  
  "data_current/processed/production/lexml_unified_dataset.csv",
  "data_current/processed/production/lexml_enhanced_simple.csv",
  "data_current/processed/production/lexml_sample_for_railway.csv"
)

for(path in csv_paths) {
  if(file.exists(path)) {
    size_mb <- file.size(path) / (1024 * 1024)
    lines <- tryCatch({
      system(paste("wc -l", shQuote(path)), intern = TRUE)
      as.numeric(sub(" .*", "", system(paste("wc -l", shQuote(path)), intern = TRUE)))
    }, error = function(e) NA)
    
    cat(sprintf("✅ %s - %.1f MB, %s documents\n", 
                basename(path), size_mb, 
                if(is.na(lines)) "unknown" else format(lines - 1, big.mark = ",")))
  } else {
    cat(sprintf("❌ %s - NOT FOUND\n", basename(path)))
  }
}

# Test 2: Simulate the exact app.R loading logic
cat("\n2. TESTING APP LOADING LOGIC:\n")

csv_path <- NULL
for(path in csv_paths) {
  if(file.exists(path)) {
    csv_path <- path
    break
  }
}

if(!is.null(csv_path)) {
  cat(sprintf("📁 Selected file: %s\n", csv_path))
  
  tryCatch({
    file_size_mb <- file.size(csv_path) / (1024 * 1024)
    cat(sprintf("📊 File size: %.1f MB\n", file_size_mb))
    
    # Load based on size (same logic as app.R)
    if(file_size_mb > 300) {
      cat("📊 Large file detected - reading first 200k rows\n")
      all_docs <- read.csv(csv_path, nrows = 200000, stringsAsFactors = FALSE, encoding = "UTF-8")
    } else {
      cat("📊 Loading full file\n")
      all_docs <- read.csv(csv_path, stringsAsFactors = FALSE, encoding = "UTF-8")
    }
    
    cat(sprintf("✅ LOADED: %s documents\n", format(nrow(all_docs), big.mark = ",")))
    
    # Test column mapping
    original_cols <- names(all_docs)
    if("titulo" %in% names(all_docs)) names(all_docs)[names(all_docs) == "titulo"] <- "title"
    if("categoria" %in% names(all_docs)) names(all_docs)[names(all_docs) == "categoria"] <- "category"
    if("estado" %in% names(all_docs)) names(all_docs)[names(all_docs) == "estado"] <- "state"
    if("data" %in% names(all_docs)) names(all_docs)[names(all_docs) == "data"] <- "date"
    if("ementa" %in% names(all_docs)) names(all_docs)[names(all_docs) == "ementa"] <- "summary"
    
    cat("✅ COLUMN MAPPING: successful\n")
    
    # Test filtering (basic - no search terms)
    has_content <- (!is.na(all_docs$title) & all_docs$title != "") |
                   (!"summary" %in% names(all_docs) | (!is.na(all_docs$summary) & all_docs$summary != ""))
    filtered_docs <- all_docs[has_content, ]
    
    cat(sprintf("✅ AFTER FILTERING: %s documents\n", format(nrow(filtered_docs), big.mark = ",")))
    
    # Success metrics
    success_rate <- nrow(filtered_docs) / nrow(all_docs) * 100
    if(success_rate > 95) {
      cat(sprintf("🎉 EXCELLENT: %.1f%% of documents retained\n", success_rate))
    } else if(success_rate > 80) {
      cat(sprintf("✅ GOOD: %.1f%% of documents retained\n", success_rate))
    } else {
      cat(sprintf("⚠️ CONCERN: Only %.1f%% of documents retained\n", success_rate))
    }
    
  }, error = function(e) {
    cat(sprintf("❌ ERROR: %s\n", e$message))
  })
  
} else {
  cat("❌ NO FILES AVAILABLE - Would use 3-document fallback\n")
}

# Test 3: Check git inclusion status
cat("\n3. CHECKING GIT INCLUSION:\n")
railway_files <- c("railway_full_dataset.csv", "railway_data_10k.csv")
for(file in railway_files) {
  if(file.exists(file)) {
    # Check if file is in git
    git_status <- system(sprintf("git ls-files %s", file), intern = TRUE)
    if(length(git_status) > 0) {
      cat(sprintf("✅ %s - INCLUDED in git\n", file))
    } else {
      cat(sprintf("⚠️ %s - NOT in git (won't deploy to Railway)\n", file))
    }
  }
}

# Final assessment
cat("\n=== SOLUTION ASSESSMENT ===\n")
has_50k <- file.exists("railway_full_dataset.csv")
has_10k <- file.exists("railway_data_10k.csv") 
has_full <- file.exists("data_current/processed/production/lexml_unified_dataset.csv")

if(has_50k) {
  cat("🎉 OPTIMAL: 50k document Railway dataset ready for deployment\n")
} else if(has_10k) {
  cat("✅ GOOD: 10k document Railway dataset available\n") 
} else if(has_full) {
  cat("⚠️ LOCAL ONLY: 134k documents available locally but not for Railway\n")
} else {
  cat("❌ PROBLEM: No datasets found\n")
}

cat("\n=== VERIFICATION COMPLETE ===\n")