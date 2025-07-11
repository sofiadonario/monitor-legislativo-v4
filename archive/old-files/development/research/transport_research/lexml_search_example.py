#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Example script for using LexML Integration
Demonstrates searching for transport-related legislation
"""

import sys
import logging
from pathlib import Path

# Add core directory to path
sys.path.insert(0, str(Path(__file__).parent))

from core.api.lexml_integration import LexMLIntegration


def run_transport_legislation_search():
    """
    Run a comprehensive search for transport-related legislation
    """
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('data/lexml_results/search_log.txt'),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger(__name__)
    
    # Create integration instance
    logger.info("Initializing LexML integration...")
    lexml = LexMLIntegration(output_dir="data/lexml_results")
    
    try:
        # Perform search
        logger.info("Starting search for transport-related legislation...")
        results = lexml.search_all_terms("transport_terms.txt")
        
        if not results:
            logger.warning("No results found!")
            return
        
        # Save results to CSV
        csv_file = lexml.save_results(results)
        logger.info(f"Results saved to CSV: {csv_file}")
        
        # Generate summary report
        report_file = lexml.generate_summary_report(results)
        logger.info(f"Summary report generated: {report_file}")
        
        # Print summary statistics
        print("\n" + "="*60)
        print("SEARCH COMPLETED - SUMMARY STATISTICS")
        print("="*60)
        print(f"Total searches performed: {lexml.stats['total_searches']}")
        print(f"Successful API calls: {lexml.stats['api_successes']}")
        print(f"Failed API calls: {lexml.stats['api_failures']}")
        print(f"Fallback scraper uses: {lexml.stats['fallback_uses']}")
        print(f"Total unique results: {lexml.stats['total_results']}")
        print(f"Duplicate results removed: {lexml.stats['duplicates_removed']}")
        
        # Show top document types
        doc_types = {}
        for result in results:
            doc_type = result.get('document_type', 'Unknown')
            doc_types[doc_type] = doc_types.get(doc_type, 0) + 1
        
        print("\nTop Document Types:")
        for doc_type, count in sorted(doc_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  - {doc_type}: {count}")
        
        # Show search performance
        if lexml.stats['total_searches'] > 0:
            api_success_rate = (lexml.stats['api_successes'] / lexml.stats['total_searches']) * 100
            print(f"\nAPI Success Rate: {api_success_rate:.1f}%")
        
        print("\nAll results have been saved to the data/lexml_results directory.")
        
    except Exception as e:
        logger.error(f"Error during search: {e}", exc_info=True)
        sys.exit(1)


def search_specific_terms(terms: list):
    """
    Search for specific terms only
    
    Args:
        terms: List of search terms
    """
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    
    # Create temporary terms file
    temp_file = Path("temp_search_terms.txt")
    with open(temp_file, 'w', encoding='utf-8') as f:
        for term in terms:
            f.write(f'"{term}"\n')
    
    try:
        # Create integration and search
        lexml = LexMLIntegration()
        results = lexml.search_all_terms(str(temp_file))
        
        # Save results
        if results:
            csv_file = lexml.save_results(results, "specific_terms_results.csv")
            print(f"Results saved to: {csv_file}")
            print(f"Found {len(results)} results")
        else:
            print("No results found")
    
    finally:
        # Clean up
        if temp_file.exists():
            temp_file.unlink()


if __name__ == "__main__":
    # Run full search by default
    run_transport_legislation_search()
    
    # Example of searching specific terms
    # search_specific_terms(["transporte rodoviário", "combustível sustentável"])