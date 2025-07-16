#!/usr/bin/env python3
"""
Fixed LexML Runner - Standalone version with JSON serialization fix
"""

import os
import sys
import json
import csv
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Only import what we need
from lexml_web_scraper_final import LexMLWebScraperFinal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle datetime objects"""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def run_collection():
    """
    Run collection with fixed serialization
    """
    
    print("🚀 STARTING LEXML COLLECTION")
    print("=" * 60)
    
    # Create output directory
    output_dir = "data/processed"
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize scraper
    scraper = LexMLWebScraperFinal()
    
    # Get all search terms for complete collection
    search_terms = scraper.search_terms  # All terms
    
    print(f"🔍 Collecting data for {len(search_terms)} terms (complete collection)...")
    print(f"Terms: {', '.join(search_terms[:10])}{'...' if len(search_terms) > 10 else ''}")
    
    start_time = datetime.now()
    all_results = []
    
    try:
        # Process each term individually
        for i, term in enumerate(search_terms, 1):
            print(f"\n📝 Processing term {i}/{len(search_terms)}: {term}")
            
            try:
                # Search with higher limit
                results = scraper.search_term(term, max_results=500)
                all_results.extend(results)
                
                print(f"  ✅ {len(results)} documents collected")
                
                # Brief pause between terms
                time.sleep(1)
                
            except Exception as e:
                print(f"  ❌ Error processing term '{term}': {e}")
                continue
        
        # Remove duplicates
        unique_results = []
        seen_urns = set()
        
        for result in all_results:
            urn = result.get('urn', '')
            title = result.get('title', '')
            
            identifier = urn if urn else title
            if identifier and identifier not in seen_urns:
                seen_urns.add(identifier)
                unique_results.append(result)
        
        print(f"\n📊 Deduplication: {len(all_results)} -> {len(unique_results)} unique documents")
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save CSV
        csv_file = os.path.join(output_dir, f'lexml_complete_dataset_{timestamp}.csv')
        scraper.save_results(unique_results, csv_file)
        
        # Save JSON with custom encoder
        json_file = os.path.join(output_dir, f'lexml_complete_dataset_{timestamp}.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(unique_results, f, ensure_ascii=False, indent=2, cls=DateTimeEncoder)
        
        # Create execution summary
        execution_time = datetime.now() - start_time
        
        summary = {
            'execution_info': {
                'timestamp': datetime.now().isoformat(),
                'execution_time': str(execution_time),
                'terms_processed': len(search_terms),
                'total_documents': len(unique_results),
                'files_generated': {
                    'csv': csv_file,
                    'json': json_file
                }
            },
            'collection_stats': {
                'documents_by_term': {},
                'documents_by_type': {},
                'year_range': {}
            }
        }
        
        # Analyze results
        for result in unique_results:
            # By term
            term = result.get('search_term', 'unknown')
            summary['collection_stats']['documents_by_term'][term] = summary['collection_stats']['documents_by_term'].get(term, 0) + 1
            
            # By type
            doc_type = result.get('urn_type', 'unknown')
            summary['collection_stats']['documents_by_type'][doc_type] = summary['collection_stats']['documents_by_type'].get(doc_type, 0) + 1
            
            # Year range
            date_str = result.get('enacting_date', '')
            if date_str and len(date_str) >= 4:
                year = date_str[:4]
                if year.isdigit():
                    summary['collection_stats']['year_range'][year] = summary['collection_stats']['year_range'].get(year, 0) + 1
        
        # Save summary
        summary_file = os.path.join(output_dir, f'collection_summary_{timestamp}.json')
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2, cls=DateTimeEncoder)
        
        # Print final report
        print(f"\n🎉 COLLECTION COMPLETED SUCCESSFULLY!")
        print(f"📊 Results Summary:")
        print(f"  - Total documents: {len(unique_results):,}")
        print(f"  - Execution time: {execution_time}")
        print(f"  - Terms processed: {len(search_terms)}")
        print(f"\n📁 Files generated:")
        print(f"  - CSV: {csv_file}")
        print(f"  - JSON: {json_file}")
        print(f"  - Summary: {summary_file}")
        
        print(f"\n📋 Document Types:")
        for doc_type, count in summary['collection_stats']['documents_by_type'].items():
            print(f"  - {doc_type}: {count}")
        
        print(f"\n🔍 Top Terms by Results:")
        sorted_terms = sorted(summary['collection_stats']['documents_by_term'].items(), 
                            key=lambda x: x[1], reverse=True)
        for term, count in sorted_terms[:5]:
            print(f"  - {term}: {count}")
        
        return unique_results
        
    except Exception as e:
        print(f"❌ Error during collection: {e}")
        logger.error(f"Collection failed: {e}")
        return []

def main():
    """Main function"""
    
    try:
        results = run_collection()
        
        if results:
            print(f"\n✅ SUCCESS: {len(results)} documents processed and saved to ./data/processed")
        else:
            print(f"\n❌ FAILED: No documents were collected")
            
    except KeyboardInterrupt:
        print("\n⚠️ Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()