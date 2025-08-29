#!/bin/bash
# Verify the fix for document display issue

echo "=== Verifying Document Display Fix ==="
echo ""
echo "Changes made to app.R:"
echo "1. Line 350: Modified title filtering to be less aggressive"
echo "2. Line 536: Changed default limit from 100 to 999999"
echo "3. Line 413: Added check for positive limit before applying"
echo ""
echo "Testing data loading..."

R --quiet --no-save << 'EOF'
# Test the data loading with the fixed logic
cat("Testing fixed filtering logic...\n")

# Simulate the app's data loading
csv_path <- "data_current/processed/production/lexml_unified_dataset.csv"
if(file.exists(csv_path)) {
  cat("Loading data from:", csv_path, "\n")
  all_docs <- read.csv(csv_path, stringsAsFactors = FALSE, nrows = 1000)
  
  # Apply column mapping like the app does
  if("titulo" %in% names(all_docs)) names(all_docs)[names(all_docs) == "titulo"] <- "title"
  if("ementa" %in% names(all_docs)) names(all_docs)[names(all_docs) == "ementa"] <- "summary"
  
  cat("Loaded", nrow(all_docs), "documents for testing\n")
  
  # Test old filtering (would remove many documents)
  old_filter <- all_docs[!is.na(all_docs$title) & all_docs$title != "", ]
  cat("Old filter would keep:", nrow(old_filter), "documents\n")
  
  # Test new filtering (keeps more documents)
  has_content <- (!is.na(all_docs$title) & all_docs$title != "") |
                 (!"summary" %in% names(all_docs) | (!is.na(all_docs$summary) & all_docs$summary != ""))
  new_filter <- all_docs[has_content, ]
  cat("New filter keeps:", nrow(new_filter), "documents\n")
  
  cat("\nImprovement:", nrow(new_filter) - nrow(old_filter), "more documents displayed\n")
} else {
  cat("Data file not found at:", csv_path, "\n")
}
EOF

echo ""
echo "=== Summary ==="
echo "The fix addresses the issue where 134k documents were loaded but only ~15 displayed."
echo "The main problems were:"
echo "1. Aggressive title filtering removing documents with empty titles"
echo "2. Default limit of 100 documents in get_library_documents function"
echo ""
echo "Now the app should display all documents that have either a title OR summary."
echo "To test: Run the Shiny app and check the Library tab document count."