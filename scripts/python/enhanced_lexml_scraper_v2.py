#!/usr/bin/env python3
"""
Enhanced LexML Scraper v2.0 - Using LexML Refinado Package
==========================================================

Modern implementation of the LexML scraper using the new lexml_refinado package.
This script demonstrates how to migrate from the old standalone scraper to
use the new comprehensive package with enhanced features.

Key Improvements:
- Uses the new EnhancedLexMLStrategy from lexml_refinado package
- Comprehensive document analysis and classification
- Better error handling and logging
- Support for multiple categories and filters
- Advanced analytics and quality assessment
- Database integration capabilities

Author: MackIntegridade Research Team
Date: 2025-08-08
Version: 2.0.0 (Package-based)
"""

import sys
import logging
import argparse
from typing import Dict, List, Optional, Any
from datetime import datetime
import json
from pathlib import Path

# Add package to path if running from development
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

try:
    # Import the new lexml_refinado package
    from lexml_refinado import (
        EnhancedLexMLStrategy,
        RefinedDocumentClassifier,
        get_version_info,
        configure_logging
    )
    from lexml_refinado.database import DatabaseManager
    from lexml_refinado.utils import ConfigManager
    
    PACKAGE_AVAILABLE = True
    logger = logging.getLogger(__name__)
    
except ImportError as e:
    print(f"Error: Could not import lexml_refinado package: {e}")
    print("Please install the package first:")
    print("  cd src/lexml_refinado")
    print("  pip install -e .")
    sys.exit(1)

def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None):
    """Setup logging configuration."""
    configure_logging(log_level, 'structured')
    
    # Add file handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        logging.getLogger().addHandler(file_handler)

class EnhancedLexMLScraperV2:
    """
    Enhanced LexML scraper using the lexml_refinado package.
    
    This class serves as a wrapper and demonstration of the new package
    capabilities, showing how to migrate from standalone scrapers to
    the comprehensive analysis system.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize the enhanced scraper.
        
        Args:
            config_file: Optional configuration file path
        """
        # Load configuration if provided
        self.config = {}
        if config_file and Path(config_file).exists():
            self.config = ConfigManager.load_config(config_file)
            logger.info(f"Configuration loaded from: {config_file}")
        
        # Initialize the core strategy
        self.strategy = EnhancedLexMLStrategy()
        
        # Initialize classifier for additional analysis
        self.classifier = RefinedDocumentClassifier()
        
        # Database connection (optional)
        self.database = None
        if 'database' in self.config:
            try:
                self.database = DatabaseManager(
                    connection_string=self.config['database'].get('connection_string')
                )
                if self.database.connect():
                    logger.info("Database connection established")
                else:
                    logger.warning("Failed to connect to database")
                    self.database = None
            except Exception as e:
                logger.warning(f"Database initialization failed: {e}")
                self.database = None
        
        # Statistics tracking
        self.execution_stats = {
            'start_time': None,
            'end_time': None,
            'total_searches': 0,
            'total_documents': 0,
            'successful_classifications': 0,
            'database_saves': 0,
            'errors': []
        }
        
        logger.info("Enhanced LexML Scraper v2.0 initialized")
        
        # Display version info
        version_info = get_version_info()
        logger.info(f"Using lexml_refinado version: {version_info['lexml_refinado_version']}")
    
    def scrape_by_categories(
        self,
        categories: Optional[List[str]] = None,
        max_results_per_category: int = 100,
        include_all_document_types: bool = True,
        save_to_database: bool = False
    ) -> Dict[str, Any]:
        """
        Scrape documents organized by categories using the enhanced strategy.
        
        Args:
            categories: List of categories to search (None for all)
            max_results_per_category: Maximum results per category
            include_all_document_types: Whether to include all document types
            save_to_database: Whether to save results to database
            
        Returns:
            Dictionary with comprehensive results and statistics
        """
        self.execution_stats['start_time'] = datetime.now()
        logger.info("Starting category-based document scraping...")
        
        try:
            # Execute comprehensive search using the package
            results = self.strategy.execute_comprehensive_search(
                categories=categories,
                max_results_per_category=max_results_per_category,
                include_all_document_types=include_all_document_types
            )
            
            # Update statistics
            self.execution_stats['total_searches'] = len(categories) if categories else 10
            self.execution_stats['total_documents'] = len(results['results'])
            
            # Additional processing and analysis
            enhanced_results = self._enhance_results(results)
            
            # Save to database if requested and available
            if save_to_database and self.database:
                self._save_to_database(enhanced_results['results'])
            
            self.execution_stats['end_time'] = datetime.now()
            
            # Add execution statistics to results
            enhanced_results['execution_stats'] = self.execution_stats.copy()
            
            logger.info(f"Scraping completed successfully!")
            logger.info(f"Total documents found: {self.execution_stats['total_documents']}")
            
            return enhanced_results
            
        except Exception as e:
            logger.error(f"Scraping failed: {e}")
            self.execution_stats['errors'].append({
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            raise
    
    def scrape_by_terms(
        self,
        search_terms: List[str],
        max_results_per_term: int = 50,
        enhanced_analysis: bool = True
    ) -> Dict[str, Any]:
        """
        Scrape documents by specific search terms.
        
        Args:
            search_terms: List of search terms
            max_results_per_term: Maximum results per term
            enhanced_analysis: Whether to perform enhanced analysis
            
        Returns:
            Dictionary with search results and analysis
        """
        self.execution_stats['start_time'] = datetime.now()
        logger.info(f"Starting term-based scraping for {len(search_terms)} terms...")
        
        all_results = []
        term_statistics = {}
        
        for term in search_terms:
            try:
                logger.info(f"Searching for term: '{term}'")
                
                # Use the strategy's search capabilities
                # Note: This would need to be implemented in the strategy
                # For now, we'll use a custom approach
                term_results = self._search_single_term(term, max_results_per_term)
                
                all_results.extend(term_results)
                term_statistics[term] = {
                    'documents_found': len(term_results),
                    'search_timestamp': datetime.now().isoformat()
                }
                
            except Exception as e:
                logger.error(f"Error searching term '{term}': {e}")
                self.execution_stats['errors'].append({
                    'term': term,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        # Remove duplicates based on URN
        unique_results = self._remove_duplicates(all_results)
        
        # Enhanced analysis if requested
        if enhanced_analysis:
            unique_results = self._perform_enhanced_analysis(unique_results)
        
        self.execution_stats['end_time'] = datetime.now()
        self.execution_stats['total_documents'] = len(unique_results)
        
        return {
            'results': unique_results,
            'term_statistics': term_statistics,
            'execution_stats': self.execution_stats.copy(),
            'total_unique_documents': len(unique_results)
        }
    
    def _enhance_results(self, base_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance results with additional analysis and metadata.
        
        Args:
            base_results: Base results from strategy
            
        Returns:
            Enhanced results with additional analysis
        """
        logger.info("Enhancing results with additional analysis...")
        
        enhanced_results = base_results.copy()
        
        # Add document-level enhancements
        for i, document in enumerate(enhanced_results['results']):
            try:
                # Additional classification if not already done
                if 'classification' not in document:
                    classification = self.classifier.classify_document(
                        document.get('urn', ''),
                        document.get('title', ''),
                        document.get('document_summary', ''),
                        document.get('document_type_full', '')
                    )
                    document['classification'] = classification
                    self.execution_stats['successful_classifications'] += 1
                
                # Add processing metadata
                document['processing_metadata'] = {
                    'processed_at': datetime.now().isoformat(),
                    'processor_version': '2.0',
                    'enhanced': True
                }
                
            except Exception as e:
                logger.warning(f"Failed to enhance document {i}: {e}")
                self.execution_stats['errors'].append({
                    'document_index': i,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        # Add corpus-level statistics
        enhanced_results['corpus_analysis'] = self._analyze_corpus(enhanced_results['results'])
        
        return enhanced_results
    
    def _search_single_term(self, term: str, max_results: int) -> List[Dict[str, Any]]:
        """
        Search for a single term (placeholder implementation).
        
        This would integrate with the existing strategy or implement
        direct search functionality.
        """
        # This is a placeholder - in a real implementation, this would
        # use the strategy's search capabilities or implement direct search
        logger.warning(f"Single term search for '{term}' - placeholder implementation")
        return []
    
    def _remove_duplicates(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate documents based on URN."""
        seen_urns = set()
        unique_results = []
        
        for doc in results:
            urn = doc.get('urn', '')
            if urn and urn not in seen_urns:
                seen_urns.add(urn)
                unique_results.append(doc)
            elif not urn:
                # For documents without URN, use title as fallback
                title = doc.get('title', '')[:100]
                if title and title not in seen_urns:
                    seen_urns.add(title)
                    unique_results.append(doc)
        
        return unique_results
    
    def _perform_enhanced_analysis(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Perform enhanced NLP and ML analysis on results."""
        logger.info("Performing enhanced analysis on results...")
        
        # This would integrate with the NLP and ML modules
        # For now, just add basic analysis
        for doc in results:
            doc['enhanced_analysis'] = {
                'analyzed_at': datetime.now().isoformat(),
                'analysis_version': '2.0'
            }
        
        return results
    
    def _analyze_corpus(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the corpus for patterns and statistics."""
        if not results:
            return {}
        
        # Basic corpus statistics
        corpus_stats = {
            'total_documents': len(results),
            'document_types': {},
            'states': {},
            'years': {},
            'categories': {}
        }
        
        for doc in results:
            # Count document types
            doc_type = doc.get('document_type_full', 'Unknown')
            corpus_stats['document_types'][doc_type] = corpus_stats['document_types'].get(doc_type, 0) + 1
            
            # Count states
            state = doc.get('state', 'Unknown')
            corpus_stats['states'][state] = corpus_stats['states'].get(state, 0) + 1
            
            # Extract year from date
            date_str = doc.get('enacting_date', '')
            if date_str and len(date_str) >= 4:
                year = date_str[:4]
                corpus_stats['years'][year] = corpus_stats['years'].get(year, 0) + 1
            
            # Count categories if available
            classification = doc.get('classification', {})
            category = classification.get('main_category', 'Unknown')
            corpus_stats['categories'][category] = corpus_stats['categories'].get(category, 0) + 1
        
        return corpus_stats
    
    def _save_to_database(self, results: List[Dict[str, Any]]) -> bool:
        """Save results to database."""
        if not self.database:
            logger.warning("Database not available for saving")
            return False
        
        try:
            logger.info(f"Saving {len(results)} documents to database...")
            
            # Prepare data for database insertion
            db_records = []
            for doc in results:
                db_record = {
                    'urn': doc.get('urn'),
                    'title': doc.get('title'),
                    'document_summary': doc.get('document_summary'),
                    'document_type_full': doc.get('document_type_full'),
                    'enacting_date': doc.get('enacting_date'),
                    'state': doc.get('state'),
                    'country': doc.get('country', 'br'),
                    'url': doc.get('url'),
                    'date_searched': datetime.now().strftime('%Y-%m-%d'),
                    # Add classification data if available
                    'main_category': doc.get('classification', {}).get('main_category'),
                    'document_type_classified': doc.get('classification', {}).get('document_type'),
                    'document_subtype': doc.get('classification', {}).get('document_subtype')
                }
                db_records.append(db_record)
            
            # Bulk insert
            success = self.database.bulk_insert(
                'lexml_documents',
                db_records,
                on_conflict='ignore'
            )
            
            if success:
                self.execution_stats['database_saves'] = len(results)
                logger.info(f"Successfully saved {len(results)} documents to database")
            else:
                logger.error("Failed to save documents to database")
            
            return success
            
        except Exception as e:
            logger.error(f"Database save failed: {e}")
            return False
    
    def save_results(
        self,
        results: Dict[str, Any],
        output_file: Optional[str] = None,
        format: str = 'csv'
    ) -> str:
        """
        Save results to file using the package's save functionality.
        
        Args:
            results: Results to save
            output_file: Output file path
            format: Output format ('csv', 'json')
            
        Returns:
            Path to saved file
        """
        logger.info(f"Saving results in {format} format...")
        
        # Use the strategy's save method for CSV
        if format == 'csv':
            saved_file = self.strategy.save_enhanced_results(results, output_file)
            logger.info(f"Results saved to: {saved_file}")
            return saved_file
        
        elif format == 'json':
            if not output_file:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = f'lexml_results_{timestamp}.json'
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Results saved to: {output_file}")
            return output_file
        
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance and execution statistics."""
        stats = self.execution_stats.copy()
        
        if stats['start_time'] and stats['end_time']:
            duration = stats['end_time'] - stats['start_time']
            stats['total_execution_time'] = duration.total_seconds()
            
            if stats['total_documents'] > 0:
                stats['avg_documents_per_second'] = stats['total_documents'] / stats['total_execution_time']
        
        # Add package version info
        stats['package_info'] = get_version_info()
        
        return stats

def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description='Enhanced LexML Scraper v2.0 using lexml_refinado package'
    )
    
    parser.add_argument(
        '--categories',
        nargs='+',
        help='Categories to scrape (or "all" for all categories)'
    )
    
    parser.add_argument(
        '--terms',
        nargs='+',
        help='Specific search terms'
    )
    
    parser.add_argument(
        '--max-results',
        type=int,
        default=100,
        help='Maximum results per category/term'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output file path'
    )
    
    parser.add_argument(
        '--format',
        choices=['csv', 'json'],
        default='csv',
        help='Output format'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--save-to-database',
        action='store_true',
        help='Save results to database'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    
    parser.add_argument(
        '--log-file',
        type=str,
        help='Log file path'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, args.log_file)
    
    try:
        # Initialize scraper
        scraper = EnhancedLexMLScraperV2(args.config)
        
        # Execute scraping based on arguments
        if args.categories:
            # Category-based scraping
            if 'all' in args.categories:
                categories = None
            else:
                categories = args.categories
                
            results = scraper.scrape_by_categories(
                categories=categories,
                max_results_per_category=args.max_results,
                save_to_database=args.save_to_database
            )
            
        elif args.terms:
            # Term-based scraping
            results = scraper.scrape_by_terms(
                search_terms=args.terms,
                max_results_per_term=args.max_results
            )
            
        else:
            # Default: scrape all categories with small sample
            logger.info("No specific categories or terms specified. Using default scraping...")
            results = scraper.scrape_by_categories(
                categories=None,
                max_results_per_category=25,
                save_to_database=args.save_to_database
            )
        
        # Save results
        output_file = scraper.save_results(results, args.output, args.format)
        
        # Display statistics
        stats = scraper.get_performance_stats()
        print("\n" + "="*50)
        print("EXECUTION SUMMARY")
        print("="*50)
        print(f"Total documents found: {stats['total_documents']}")
        print(f"Successful classifications: {stats['successful_classifications']}")
        print(f"Database saves: {stats['database_saves']}")
        print(f"Total execution time: {stats.get('total_execution_time', 'N/A')} seconds")
        print(f"Results saved to: {output_file}")
        print(f"Errors encountered: {len(stats['errors'])}")
        
        if stats['errors']:
            print("\nErrors:")
            for error in stats['errors'][-3:]:  # Show last 3 errors
                print(f"  - {error}")
        
        print("="*50)
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Scraping interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Scraping failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main())