#!/bin/bash
# ==============================================================================
# AUTOMATED BOOLEAN OPERATOR FIXER
# ==============================================================================
# Fixes ALL unsafe || and && operations across the entire codebase
# Uses sed to wrap conditions in isTRUE() to prevent extent=0 errors
# ==============================================================================

echo "🔧 AUTOMATED BOOLEAN OPERATOR FIXER"
echo "==================================="
echo ""

# Find all R files (excluding renv, .Rproj.user, etc.)
echo "📂 Finding all R files..."
files=$(find . -name "*.R" -type f \
  ! -path "./renv/*" \
  ! -path "./.Rproj.user/*" \
  ! -path "./data_current/*" \
  ! -path "./legacy/*" \
  ! -path "./archive/*" \
  ! -path "./backup/*" \
  ! -name "fix_all_booleans.*")

file_count=$(echo "$files" | wc -l | tr -d ' ')
echo "✅ Found $file_count R files to process"
echo ""

total_files_changed=0
total_lines_changed=0

# Process each file
for file in $files; do
  # Count lines with || or && before fixing
  before_count=$(grep -c "||\\|&&" "$file" 2>/dev/null || echo "0")

  if [ "$before_count" -eq 0 ]; then
    continue
  fi

  # Create backup
  cp "$file" "${file}.bak"

  # Apply fixes using sed
  # Pattern 1: is.null(x) || ... -> isTRUE(is.null(x)) || ...
  sed -i.tmp 's/is\.null(\([^)]*\)) ||/isTRUE(is.null(\1)) ||/g' "$file"
  sed -i.tmp 's/is\.null(\([^)]*\)) &&/isTRUE(is.null(\1)) \&\&/g' "$file"

  # Pattern 2: || is.null(x) -> || isTRUE(is.null(x))
  sed -i.tmp 's/|| is\.null(\([^)]*\))/|| isTRUE(is.null(\1))/g' "$file"
  sed -i.tmp 's/\&\& is\.null(\([^)]*\))/\&\& isTRUE(is.null(\1))/g' "$file"

  # Pattern 3: is.na(x) || ... -> isTRUE(is.na(x)) || ...
  sed -i.tmp 's/is\.na(\([^)]*\)) ||/isTRUE(is.na(\1)) ||/g' "$file"
  sed -i.tmp 's/is\.na(\([^)]*\)) &&/isTRUE(is.na(\1)) \&\&/g' "$file"

  # Pattern 4: || is.na(x) -> || isTRUE(is.na(x))
  sed -i.tmp 's/|| is\.na(\([^)]*\))/|| isTRUE(is.na(\1))/g' "$file"
  sed -i.tmp 's/\&\& is\.na(\([^)]*\))/\&\& isTRUE(is.na(\1))/g' "$file"

  # Pattern 5: length(x) == 0 || ... -> isTRUE(length(x) == 0) || ...
  sed -i.tmp 's/length(\([^)]*\)) == 0 ||/isTRUE(length(\1) == 0) ||/g' "$file"
  sed -i.tmp 's/length(\([^)]*\)) == 0 &&/isTRUE(length(\1) == 0) \&\&/g' "$file"

  # Pattern 6: nrow(x) == 0, > 0, etc
  sed -i.tmp 's/nrow(\([^)]*\)) == 0 ||/isTRUE(nrow(\1) == 0) ||/g' "$file"
  sed -i.tmp 's/nrow(\([^)]*\)) > 0 ||/isTRUE(nrow(\1) > 0) ||/g' "$file"
  sed -i.tmp 's/nrow(\([^)]*\)) == 0 &&/isTRUE(nrow(\1) == 0) \&\&/g' "$file"
  sed -i.tmp 's/nrow(\([^)]*\)) > 0 &&/isTRUE(nrow(\1) > 0) \&\&/g' "$file"

  # Pattern 7: !nzchar(x) || ... -> isTRUE(!nzchar(x)) || ...
  sed -i.tmp 's/!nzchar(\([^)]*\)) ||/isTRUE(!nzchar(\1)) ||/g' "$file"
  sed -i.tmp 's/!nzchar(\([^)]*\)) &&/isTRUE(!nzchar(\1)) \&\&/g' "$file"

  # Clean up temp file
  rm -f "${file}.tmp"

  # Count changes
  after_count=$(grep -c "||\\|&&" "$file" 2>/dev/null || echo "0")
  lines_changed=$((before_count - after_count))

  if [ "$lines_changed" -gt 0 ] || ! cmp -s "$file" "${file}.bak"; then
    total_files_changed=$((total_files_changed + 1))
    total_lines_changed=$((total_lines_changed + lines_changed))
    echo "  ✓ $file (modified)"
  else
    # Restore from backup if no changes
    mv "${file}.bak" "$file"
  fi
done

echo ""
echo "==================================="
echo "✅ COMPLETE"
echo "   Files processed: $file_count"
echo "   Files changed: $total_files_changed"
echo "==================================="

exit 0
