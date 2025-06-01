#!/usr/bin/env python3
"""Check maximum lengths in CSV data"""

import csv
from collections import defaultdict

CSV_FILE = "data/processed/lexml_parsed_enhanced_fixed.csv"

# Read CSV and check max lengths
max_lengths = defaultdict(int)

with open(CSV_FILE, 'r', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        for key, value in row.items():
            if value:
                max_lengths[key] = max(max_lengths[key], len(str(value)))

print("Maximum field lengths in CSV:")
for field, length in sorted(max_lengths.items()):
    print(f"  {field}: {length} characters")