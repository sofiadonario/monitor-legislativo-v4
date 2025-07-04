"""
Real Legislative Data - 889 Documents from LexML Brasil
=====================================================

This file contains 889 real legislative documents extracted from LexML Brasil
for use as fallback data when the LexML API is unavailable.

Data source: lexml_transport_results_20250606_123100.csv
Generated: 2025-06-23
Total documents: 889
"""

import csv
import os
from pathlib import Path

def load_legislative_data():
    """Load legislative data from CSV file"""
    csv_path = Path(__file__).parent.parent.parent / 'public' / 'lexml_transport_results_20250606_123100.csv'
    
    if not csv_path.exists():
        # Fallback to dist directory
        csv_path = Path(__file__).parent.parent.parent / 'dist' / 'lexml_transport_results_20250606_123100.csv'
    
    results = []
    
    if csv_path.exists():
        try:
            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if i >= 889:  # Only take first 889 results
                        break
                    
                    # Extract document type from title
                    title = row['title']
                    doc_type = 'LEI'
                    if 'decreto' in title.lower():
                        doc_type = 'DECRETO'
                    elif 'mpv' in title.lower() or 'medida provisória' in title.lower():
                        doc_type = 'MPV'
                    elif 'portaria' in title.lower():
                        doc_type = 'PORTARIA'
                    elif 'resolução' in title.lower():
                        doc_type = 'RESOLUCAO'
                    elif 'acordão' in title.lower():
                        doc_type = 'ACORDAO'
                    
                    # Extract year from URN
                    year = '2020'
                    if 'urn:lex:br' in row['urn']:
                        urn_parts = row['urn'].split(':')
                        for part in urn_parts:
                            if len(part) == 4 and part.isdigit() and 1900 <= int(part) <= 2025:
                                year = part
                                break
                    
                    result = {
                        'id': row['urn'],
                        'title': row['title'],
                        'summary': f'Documento relacionado a {row["search_term"]}',
                        'type': doc_type,
                        'date': f'{year}-01-01',
                        'chamber': 'Federal',
                        'state': 'BR',
                        'url': row['url'],
                        'keywords': [row['search_term']]
                    }
                    results.append(result)
                    
        except Exception as e:
            print(f"Error loading CSV: {e}")
            return []
    
    return results

# Load the data when module is imported
realLegislativeData = load_legislative_data()

print(f"Loaded {len(realLegislativeData)} real legislative documents from LexML Brasil")