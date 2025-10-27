#!/usr/bin/env python3
"""
AUTOMATED BOOLEAN OPERATOR FIXER
Fixes ALL unsafe || and && operations across the entire codebase
Wraps conditions in isTRUE() to prevent extent=0 errors
"""

import os
import re
from pathlib import Path

print("🔧 AUTOMATED BOOLEAN OPERATOR FIXER")
print("===================================\n")

# Find all R files
print("📂 Finding all R files...")
exclude_dirs = {'renv', '.Rproj.user', 'data_current', 'legacy', 'archive', 'backup'}
r_files = []

for root, dirs, files in os.walk('.'):
    # Remove excluded directories from search
    dirs[:] = [d for d in dirs if d not in exclude_dirs]

    for file in files:
        if file.endswith('.R') and file != 'fix_all_booleans.R':
            r_files.append(os.path.join(root, file))

print(f"✅ Found {len(r_files)} R files to process\n")

total_files_changed = 0
total_replacements = 0

# Patterns to fix
patterns = [
    # is.null(x) || ... -> isTRUE(is.null(x)) || ...
    (r'(?<!isTRUE\()is\.null\(([^)]+)\)\s*\|\|', r'isTRUE(is.null(\1)) ||'),
    (r'(?<!isTRUE\()is\.null\(([^)]+)\)\s*&&', r'isTRUE(is.null(\1)) &&'),
    (r'\|\|\s*is\.null\(([^)]+)\)', r'|| isTRUE(is.null(\1))'),
    (r'&&\s*is\.null\(([^)]+)\)', r'&& isTRUE(is.null(\1))'),

    # is.na(x) || ... -> isTRUE(is.na(x)) || ...
    (r'(?<!isTRUE\()is\.na\(([^)]+)\)\s*\|\|', r'isTRUE(is.na(\1)) ||'),
    (r'(?<!isTRUE\()is\.na\(([^)]+)\)\s*&&', r'isTRUE(is.na(\1)) &&'),
    (r'\|\|\s*is\.na\(([^)]+)\)', r'|| isTRUE(is.na(\1))'),
    (r'&&\s*is\.na\(([^)]+)\)', r'&& isTRUE(is.na(\1))'),

    # length(x) == 0 || ... -> isTRUE(length(x) == 0) || ...
    (r'(?<!isTRUE\()length\(([^)]+)\)\s*==\s*0\s*\|\|', r'isTRUE(length(\1) == 0) ||'),
    (r'(?<!isTRUE\()length\(([^)]+)\)\s*==\s*0\s*&&', r'isTRUE(length(\1) == 0) &&'),
    (r'(?<!isTRUE\()length\(([^)]+)\)\s*>\s*0\s*\|\|', r'isTRUE(length(\1) > 0) ||'),
    (r'(?<!isTRUE\()length\(([^)]+)\)\s*>\s*0\s*&&', r'isTRUE(length(\1) > 0) &&'),

    # nrow(x) comparisons
    (r'(?<!isTRUE\()nrow\(([^)]+)\)\s*==\s*0\s*\|\|', r'isTRUE(nrow(\1) == 0) ||'),
    (r'(?<!isTRUE\()nrow\(([^)]+)\)\s*==\s*0\s*&&', r'isTRUE(nrow(\1) == 0) &&'),
    (r'(?<!isTRUE\()nrow\(([^)]+)\)\s*>\s*0\s*\|\|', r'isTRUE(nrow(\1) > 0) ||'),
    (r'(?<!isTRUE\()nrow\(([^)]+)\)\s*>\s*0\s*&&', r'isTRUE(nrow(\1) > 0) &&'),

    # !nzchar(x) || ... -> isTRUE(!nzchar(x)) || ...
    (r'(?<!isTRUE\()!nzchar\(([^)]+)\)\s*\|\|', r'isTRUE(!nzchar(\1)) ||'),
    (r'(?<!isTRUE\()!nzchar\(([^)]+)\)\s*&&', r'isTRUE(!nzchar(\1)) &&'),
]

# Process each file
for file_path in r_files:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        original_content = content
        replacements_in_file = 0

        # Apply all patterns
        for pattern, replacement in patterns:
            new_content = re.sub(pattern, replacement, content)
            if new_content != content:
                replacements_in_file += content.count(pattern)
                content = new_content

        # Write back if changed
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            total_files_changed += 1
            total_replacements += replacements_in_file
            print(f"  ✓ {file_path}")

    except Exception as e:
        print(f"  ✗ {file_path} - ERROR: {e}")

print(f"\n===================================")
print(f"✅ COMPLETE")
print(f"   Files processed: {len(r_files)}")
print(f"   Files changed: {total_files_changed}")
print(f"   Total replacements: {total_replacements}")
print(f"===================================")
