#!/usr/bin/env python3
"""
Command Line Interface for LexML Refinado
=========================================

Comprehensive CLI for Brazilian legislative document analysis system.
Provides easy-to-use commands for document scraping, classification,
analysis, and database operations.

Commands:
---------
- scrape: Scrape documents from LexML
- classify: Classify documents using trained models
- analyze: Perform comprehensive document analysis
- database: Database management operations
- train: Train machine learning models
- export: Export data in various formats

Author: MackIntegridade Research Team
Date: 2025-08-08
Version: 2.0.0
"""

import sys
import argparse
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import json

# Import core components
try:
    from . import __version__, get_version_info
    from .enhanced_strategy import EnhancedLexMLStrategy
    from .classification_system import RefinedDocumentClassifier
    from .nlp import BrazilianLegalNLP
    from .ml import DocumentClassifier
    from .database import DatabaseManager
    from .utils import ConfigManager, setup_logging
except ImportError as e:
    print(f"Error importing core components: {e}")
    sys.exit(1)

# Setup logging
logger = logging.getLogger(__name__)

def setup_argument_parser() -> argparse.ArgumentParser:
    """Setup command line argument parser."""
    
    parser = argparse.ArgumentParser(
        prog='lexml-refinado',
        description='Brazilian Legislative Document Analysis System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  lexml-refinado scrape --categories all --max-results 1000
  lexml-refinado classify documents.csv --model trained_model.joblib
  lexml-refinado analyze --input documents.csv --output analysis_results.json
  lexml-refinado database --operation health-check
  lexml-refinado train --data training_data.csv --output model.joblib
        """
    )
    
    # Global options
    parser.add_argument(
        '--version', 
        action='version', 
        version=f'LexML Refinado {__version__}'
    )
    
    parser.add_argument(
        '--config', 
        type=str,
        help='Configuration file path (YAML or JSON)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Logging level'
    )
    
    parser.add_argument(
        '--log-file',
        type=str,
        help='Log file path (default: stdout)'
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scrape command
    scrape_parser = subparsers.add_parser(
        'scrape',
        help='Scrape documents from LexML'
    )
    scrape_parser.add_argument(
        '--categories',
        nargs='+',
        help='Categories to scrape (or "all" for all categories)'
    )
    scrape_parser.add_argument(
        '--max-results',
        type=int,
        default=100,
        help='Maximum results per category'
    )
    scrape_parser.add_argument(
        '--output',
        type=str,
        default='lexml_results.csv',
        help='Output file path'
    )
    scrape_parser.add_argument(
        '--include-all-types',
        action='store_true',
        help='Include all document types'
    )
    
    # Classify command
    classify_parser = subparsers.add_parser(
        'classify',
        help='Classify documents using trained models'
    )
    classify_parser.add_argument(
        'input_file',
        help='Input file with documents to classify'
    )
    classify_parser.add_argument(
        '--model',
        type=str,
        help='Path to trained model file'
    )
    classify_parser.add_argument(
        '--output',
        type=str,
        help='Output file for classifications'
    )
    classify_parser.add_argument(
        '--confidence-threshold',
        type=float,
        default=0.5,
        help='Confidence threshold for predictions'
    )
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Perform comprehensive document analysis'
    )
    analyze_parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Input file or directory with documents'
    )
    analyze_parser.add_argument(
        '--output',
        type=str,
        help='Output file for analysis results'
    )
    analyze_parser.add_argument(
        '--analysis-type',
        choices=['basic', 'comprehensive', 'advanced'],
        default='comprehensive',
        help='Type of analysis to perform'
    )
    analyze_parser.add_argument(
        '--include-nlp',
        action='store_true',
        help='Include NLP analysis'
    )
    analyze_parser.add_argument(
        '--include-ml',
        action='store_true',
        help='Include ML analysis'
    )
    
    # Database command
    database_parser = subparsers.add_parser(
        'database',
        help='Database management operations'
    )
    database_parser.add_argument(
        '--operation',
        choices=['health-check', 'stats', 'search', 'export', 'import'],
        required=True,
        help='Database operation to perform'
    )
    database_parser.add_argument(
        '--connection-string',
        type=str,
        help='Database connection string'
    )
    database_parser.add_argument(
        '--query',
        type=str,
        help='Search query (for search operation)'
    )
    database_parser.add_argument(
        '--input-file',
        type=str,
        help='Input file (for import operation)'
    )
    database_parser.add_argument(
        '--output-file',
        type=str,
        help='Output file (for export operation)'
    )
    
    # Train command
    train_parser = subparsers.add_parser(
        'train',
        help='Train machine learning models'
    )
    train_parser.add_argument(
        '--data',
        type=str,
        required=True,
        help='Training data file'
    )
    train_parser.add_argument(
        '--model-type',
        choices=['classification', 'topic-modeling', 'similarity'],
        default='classification',
        help='Type of model to train'
    )
    train_parser.add_argument(
        '--algorithm',
        choices=['random_forest', 'svm', 'xgboost', 'neural_network'],
        default='random_forest',
        help='ML algorithm to use'
    )
    train_parser.add_argument(
        '--output',
        type=str,
        help='Output path for trained model'
    )
    train_parser.add_argument(
        '--validation-split',
        type=float,
        default=0.2,
        help='Validation split ratio'
    )
    
    # Export command
    export_parser = subparsers.add_parser(
        'export',
        help='Export data in various formats'
    )
    export_parser.add_argument(
        '--source',
        choices=['database', 'file'],
        required=True,
        help='Data source'
    )
    export_parser.add_argument(
        '--input',
        type=str,
        help='Input file or database connection'
    )
    export_parser.add_argument(
        '--output',
        type=str,
        required=True,
        help='Output file path'
    )
    export_parser.add_argument(
        '--format',
        choices=['csv', 'json', 'excel', 'parquet'],
        default='csv',
        help='Output format'
    )
    export_parser.add_argument(
        '--filters',
        type=str,
        help='JSON string with filters to apply'
    )
    
    return parser

def command_scrape(args) -> int:
    """Execute scrape command."""
    try:
        logger.info("Starting document scraping...")
        
        # Initialize scraper
        strategy = EnhancedLexMLStrategy()
        
        # Determine categories
        if args.categories and 'all' in args.categories:
            categories = None  # Use all available categories
        else:
            categories = args.categories
        
        # Execute scraping
        results = strategy.execute_comprehensive_search(
            categories=categories,
            max_results_per_category=args.max_results,
            include_all_document_types=args.include_all_types
        )
        
        # Save results
        output_file = strategy.save_enhanced_results(results, args.output)
        
        logger.info(f"Scraping completed successfully!")
        logger.info(f"Results saved to: {output_file}")
        logger.info(f"Documents found: {len(results['results'])}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Scraping failed: {e}")
        return 1

def command_classify(args) -> int:
    """Execute classify command."""
    try:
        logger.info("Starting document classification...")
        
        # Load documents
        import pandas as pd
        
        if args.input_file.endswith('.csv'):
            df = pd.read_csv(args.input_file)
        elif args.input_file.endswith('.json'):
            df = pd.read_json(args.input_file)
        else:
            raise ValueError("Unsupported input file format")
        
        # Extract text column (assume 'title' or 'document_summary')
        text_column = None
        for col in ['title', 'document_summary', 'text', 'content']:
            if col in df.columns:
                text_column = col
                break
        
        if text_column is None:
            raise ValueError("No suitable text column found in input file")
        
        documents = df[text_column].fillna('').tolist()
        
        # Load or create classifier
        if args.model:
            classifier = DocumentClassifier()
            classifier.load_model(args.model)
        else:
            # Use default refined classifier
            classifier = RefinedDocumentClassifier()
            
            # Perform basic classification
            classifications = []
            for doc in documents:
                if hasattr(classifier, 'classify_document'):
                    result = classifier.classify_document('', doc, '', '')
                    classifications.append(result)
                else:
                    # Fallback for different classifier interface
                    classifications.append({'main_category': 'unknown'})
            
            # Create results DataFrame
            results_df = df.copy()
            for key in ['main_category', 'document_type', 'document_subtype']:
                results_df[key] = [c.get(key, '') for c in classifications]
            
            # Save results
            output_file = args.output or 'classifications.csv'
            results_df.to_csv(output_file, index=False)
            
            logger.info(f"Classification completed!")
            logger.info(f"Results saved to: {output_file}")
            
            return 0
        
        # For ML classifier
        predictions = classifier.predict(documents, return_confidence=True)
        
        # Add predictions to DataFrame
        if hasattr(predictions, 'predictions'):
            df['predicted_category'] = predictions.predictions
            df['confidence'] = predictions.confidence_scores
        else:
            df['predicted_category'] = predictions
        
        # Filter by confidence if specified
        if hasattr(predictions, 'confidence_scores'):
            high_confidence = predictions.confidence_scores >= args.confidence_threshold
            df['high_confidence'] = high_confidence
        
        # Save results
        output_file = args.output or 'classifications.csv'
        df.to_csv(output_file, index=False)
        
        logger.info(f"Classification completed!")
        logger.info(f"Results saved to: {output_file}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Classification failed: {e}")
        return 1

def command_analyze(args) -> int:
    """Execute analyze command."""
    try:
        logger.info(f"Starting {args.analysis_type} document analysis...")
        
        # Load documents
        import pandas as pd
        
        if args.input.endswith('.csv'):
            df = pd.read_csv(args.input)
        elif args.input.endswith('.json'):
            df = pd.read_json(args.input)
        else:
            raise ValueError("Unsupported input file format")
        
        # Extract documents
        text_column = None
        for col in ['title', 'document_summary', 'text', 'content']:
            if col in df.columns:
                text_column = col
                break
        
        if text_column is None:
            raise ValueError("No suitable text column found")
        
        documents = df[text_column].fillna('').tolist()
        
        analysis_results = []
        
        # NLP Analysis
        if args.include_nlp:
            logger.info("Performing NLP analysis...")
            nlp = BrazilianLegalNLP()
            
            for i, doc in enumerate(documents):
                analysis = nlp.analyze_text(doc, args.analysis_type)
                analysis_dict = {
                    'document_id': i,
                    'nlp_analysis': {
                        'word_count': analysis.word_count,
                        'sentence_count': analysis.sentence_count,
                        'readability_score': analysis.readability_score,
                        'regulatory_complexity': analysis.regulatory_complexity,
                        'primary_topics': analysis.primary_topics
                    }
                }
                analysis_results.append(analysis_dict)
        
        # Save results
        output_file = args.output or 'analysis_results.json'
        
        if output_file.endswith('.json'):
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, indent=2, ensure_ascii=False)
        elif output_file.endswith('.csv'):
            # Flatten results for CSV
            flat_results = []
            for result in analysis_results:
                flat_result = {'document_id': result['document_id']}
                if 'nlp_analysis' in result:
                    flat_result.update(result['nlp_analysis'])
                flat_results.append(flat_result)
            
            pd.DataFrame(flat_results).to_csv(output_file, index=False)
        
        logger.info(f"Analysis completed!")
        logger.info(f"Results saved to: {output_file}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return 1

def command_database(args) -> int:
    """Execute database command."""
    try:
        logger.info(f"Executing database operation: {args.operation}")
        
        # Initialize database manager
        db = DatabaseManager(connection_string=args.connection_string)
        
        if not db.connect():
            logger.error("Failed to connect to database")
            return 1
        
        if args.operation == 'health-check':
            health = db.health_check()
            print(json.dumps(health, indent=2))
            
        elif args.operation == 'stats':
            stats = db.get_document_statistics()
            print(json.dumps(stats, indent=2, default=str))
            
        elif args.operation == 'search':
            if not args.query:
                logger.error("Search query is required for search operation")
                return 1
            
            results = db.search_documents(args.query)
            print(f"Found {len(results)} documents")
            
            if args.output_file:
                results.to_csv(args.output_file, index=False)
                logger.info(f"Search results saved to: {args.output_file}")
            else:
                print(results.head())
        
        elif args.operation == 'export':
            if not args.output_file:
                logger.error("Output file is required for export operation")
                return 1
            
            documents = db.get_documents()
            documents.to_csv(args.output_file, index=False)
            logger.info(f"Database exported to: {args.output_file}")
        
        elif args.operation == 'import':
            if not args.input_file:
                logger.error("Input file is required for import operation")
                return 1
            
            import pandas as pd
            df = pd.read_csv(args.input_file)
            success = db.bulk_insert('lexml_documents', df)
            
            if success:
                logger.info(f"Successfully imported {len(df)} documents")
            else:
                logger.error("Import failed")
                return 1
        
        return 0
        
    except Exception as e:
        logger.error(f"Database operation failed: {e}")
        return 1

def command_train(args) -> int:
    """Execute train command."""
    try:
        logger.info(f"Training {args.model_type} model with {args.algorithm}...")
        
        # Load training data
        import pandas as pd
        df = pd.read_csv(args.data)
        
        # Extract documents and labels
        text_column = None
        for col in ['title', 'document_summary', 'text', 'content']:
            if col in df.columns:
                text_column = col
                break
        
        label_column = None
        for col in ['label', 'category', 'class', 'target']:
            if col in df.columns:
                label_column = col
                break
        
        if not text_column or not label_column:
            logger.error("Could not find text and label columns in training data")
            return 1
        
        documents = df[text_column].fillna('').tolist()
        labels = df[label_column].tolist()
        
        # Train model
        if args.model_type == 'classification':
            from .ml import DocumentClassifier, ClassificationConfig
            
            config = ClassificationConfig(
                algorithm=args.algorithm,
                validation_split=args.validation_split
            )
            
            classifier = DocumentClassifier(config)
            classifier.fit(documents, labels)
            
            # Save model
            output_file = args.output or f'{args.algorithm}_model.joblib'
            classifier.save_model(output_file)
            
            logger.info(f"Model training completed!")
            logger.info(f"Model saved to: {output_file}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        return 1

def command_export(args) -> int:
    """Execute export command."""
    try:
        logger.info(f"Exporting data from {args.source} to {args.format}...")
        
        # Load data
        if args.source == 'database':
            db = DatabaseManager(connection_string=args.input)
            if not db.connect():
                logger.error("Failed to connect to database")
                return 1
            
            # Apply filters if provided
            filters = None
            if args.filters:
                filters = json.loads(args.filters)
            
            df = db.get_documents(filters=filters)
            
        elif args.source == 'file':
            import pandas as pd
            
            if args.input.endswith('.csv'):
                df = pd.read_csv(args.input)
            elif args.input.endswith('.json'):
                df = pd.read_json(args.input)
            else:
                raise ValueError("Unsupported input file format")
        
        # Export in specified format
        if args.format == 'csv':
            df.to_csv(args.output, index=False)
        elif args.format == 'json':
            df.to_json(args.output, orient='records', indent=2)
        elif args.format == 'excel':
            df.to_excel(args.output, index=False)
        elif args.format == 'parquet':
            df.to_parquet(args.output)
        
        logger.info(f"Export completed!")
        logger.info(f"Data exported to: {args.output}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Export failed: {e}")
        return 1

def main() -> int:
    """Main CLI entry point."""
    parser = setup_argument_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.log_level, 'simple', args.log_file)
    
    # Load configuration if provided
    if args.config:
        try:
            config = ConfigManager.load_config(args.config)
            logger.info(f"Configuration loaded from: {args.config}")
        except Exception as e:
            logger.warning(f"Failed to load configuration: {e}")
    
    # Display version info
    logger.info(f"LexML Refinado v{__version__}")
    
    # Execute command
    if args.command == 'scrape':
        return command_scrape(args)
    elif args.command == 'classify':
        return command_classify(args)
    elif args.command == 'analyze':
        return command_analyze(args)
    elif args.command == 'database':
        return command_database(args)
    elif args.command == 'train':
        return command_train(args)
    elif args.command == 'export':
        return command_export(args)
    else:
        parser.print_help()
        return 1

def classify_documents() -> int:
    """Entry point for lexml-classify command."""
    # Quick classification command
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: lexml-classify <input_file> [--output <output_file>]")
        return 1
    
    input_file = sys.argv[1]
    output_file = 'classifications.csv'
    
    if '--output' in sys.argv:
        idx = sys.argv.index('--output')
        if idx + 1 < len(sys.argv):
            output_file = sys.argv[idx + 1]
    
    try:
        # Quick classification
        import pandas as pd
        df = pd.read_csv(input_file)
        
        classifier = RefinedDocumentClassifier()
        
        classifications = []
        for _, row in df.iterrows():
            title = row.get('title', '')
            summary = row.get('document_summary', '')
            urn = row.get('urn', '')
            
            result = classifier.classify_document(urn, title, summary, '')
            classifications.append(result)
        
        # Add classifications to DataFrame
        for key in ['main_category', 'document_type', 'document_subtype']:
            df[key] = [c.get(key, '') for c in classifications]
        
        df.to_csv(output_file, index=False)
        print(f"Classifications saved to: {output_file}")
        
        return 0
        
    except Exception as e:
        print(f"Classification failed: {e}")
        return 1

def analyze_corpus() -> int:
    """Entry point for lexml-analyze command."""
    # Quick corpus analysis command
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: lexml-analyze <input_file> [--output <output_file>]")
        return 1
    
    input_file = sys.argv[1]
    output_file = 'analysis_results.json'
    
    if '--output' in sys.argv:
        idx = sys.argv.index('--output')
        if idx + 1 < len(sys.argv):
            output_file = sys.argv[idx + 1]
    
    try:
        # Quick analysis
        import pandas as pd
        import json
        
        df = pd.read_csv(input_file)
        
        nlp = BrazilianLegalNLP()
        
        # Analyze corpus
        documents = df['title'].fillna('').tolist()
        corpus_analysis = nlp.analyze_corpus(documents)
        
        # Save results
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(corpus_analysis, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"Analysis results saved to: {output_file}")
        
        return 0
        
    except Exception as e:
        print(f"Analysis failed: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())