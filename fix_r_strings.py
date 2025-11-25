#!/usr/bin/env python3
import re

# Read the R file
with open('R/database/query_optimizer.R', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the multiline string issues where backslash-newline is used incorrectly
# Pattern: cat(\"...text\
# \") should become cat("...text\n")

# Replace cat(\" with cat("
content = content.replace('cat(\\"', 'cat("')

# Replace patterns like \\"\n") with ")\n at end of lines
content = re.sub(r'\\"\\n\\"\\)', '\\n")', content)

# Fix the pattern where strings are split across lines with backslash
# Look for patterns like: text\
# ") and replace with text\n")
content = re.sub(r'([^\\])\\\n\s*\\"\\)', r'\1\\n")', content)

# Also fix standalone \") at line start
content = re.sub(r'^\s*\\"\\)$', '', content, flags=re.MULTILINE)

# Write fixed content
with open('R/database/query_optimizer.R', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed R string literals")
