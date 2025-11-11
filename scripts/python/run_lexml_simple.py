#!/usr/bin/env python3
"""
Simple LexML Runner - Standalone version without heavy dependencies
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

def run_simple_collection():
    """
    Run simple collection without heavy dependencies
    """
    
    print("🚀 STARTING SIMPLE LEXML COLLECTION")
    print("=" * 60)
    
    # Create output directory
    output_dir = "data/processed"
    os.makedirs(output_dir, exist_ok=True)
    
    # Initialize scraper
    scraper = LexMLWebScraperFinal()
    
    # Start collection
    print("🔍 Starting collection with all terms...")
    start_time = datetime.now()
    
    try:
        # Run collection for all terms
        all_results = scraper.search_all_terms(max_results_per_term=1000)
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save CSV
        csv_file = os.path.join(output_dir, f'lexml_complete_dataset_{timestamp}.csv')
        scraper.save_results(all_results, csv_file)
        
        # Save JSON
        json_file = os.path.join(output_dir, f'lexml_complete_dataset_{timestamp}.json')
        scraper.save_results_json(all_results, json_file)
        
        # Generate report
        scraper.generate_report(all_results)
        
        # Save execution stats
        execution_time = datetime.now() - start_time
        
        stats = {
            'execution_date': datetime.now().isoformat(),
            'execution_time': str(execution_time),
            'total_documents': len(all_results),
            'unique_terms': len(scraper.search_terms),
            'files_generated': {
                'csv': csv_file,
                'json': json_file
            },
            'scraper_stats': scraper.stats
        }
        
        stats_file = os.path.join(output_dir, f'execution_stats_{timestamp}.json')
        with open(stats_file, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        
        print(f"\n🎉 COLLECTION COMPLETED SUCCESSFULLY!")
        print(f"📊 Total documents collected: {len(all_results):,}")
        print(f"⏱️ Execution time: {execution_time}")
        print(f"📁 Files saved in: {output_dir}")
        print(f"💾 CSV file: {csv_file}")
        print(f"💾 JSON file: {json_file}")
        print(f"📈 Stats file: {stats_file}")
        
        return all_results
        
    except Exception as e:
        print(f"❌ Error during collection: {e}")
        logger.error(f"Collection failed: {e}")
        return []

def main():
    """Main function"""
    
    try:
        results = run_simple_collection()
        
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