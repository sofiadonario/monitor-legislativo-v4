#!/usr/bin/env python3
"""Fix duplicate timestamps in SQL file"""

import re

# Read the file
with open('REAL_DATA_MIGRATION.sql', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix pattern: "YYYY-MM-DD HH:MM:SS HH:MM:SS" -> "YYYY-MM-DD HH:MM:SS"
pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \d{2}:\d{2}:\d{2}'
fixed_content = re.sub(pattern, r'\1', content)

# Write back
with open('REAL_DATA_MIGRATION_FIXED.sql', 'w', encoding='utf-8') as f:
    f.write(fixed_content)

print("✅ Fixed timestamps and saved to REAL_DATA_MIGRATION_FIXED.sql")