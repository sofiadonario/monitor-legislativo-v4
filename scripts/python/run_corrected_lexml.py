#!/usr/bin/env python3
"""
Run LexML Collection with Corrected Implementation
Uses the fixed scraper from lexml_overview that actually works
"""

import os
import sys
import time
import logging
from datetime import datetime

# Import the corrected scraper from main directory
from lexml_scraper_final_corrigido import LexMLScraperFinalCorrigido

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('corrected_collection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def load_search_terms():
    """Load search terms from the file"""
    terms_file = os.path.join('lexml_overview', 'Termos de Busca para Monitor Legislativo - Transporte de Carga.txt')
    
    try:
        with open(terms_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Extract terms from the file structure
        terms = []
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith('* '):
                # Extract term between quotes or until AND
                term = line[2:].strip()
                if '"' in term:
                    # Extract term between quotes
                    import re
                    matches = re.findall(r'"([^"]*)"', term)
                    terms.extend(matches)
                else:
                    # Extract term until AND or EOF
                    term = term.split(' AND ')[0].strip()
                    if term and not term.startswith('('):
                        terms.append(term)
        
        # Remove duplicates and filter
        unique_terms = list(set(terms))
        filtered_terms = [term for term in unique_terms if len(term) > 2 and term.replace(' ', '').isalpha()]
        
        logger.info(f"Loaded {len(filtered_terms)} search terms")
        return filtered_terms
        
    except FileNotFoundError:
        logger.warning("Terms file not found, using default terms")
        return ["transporte de carga", "transporte rodoviário", "caminhão", "frete", "logística"]

def run_complete_collection():
    """Run complete collection with all search terms"""
    
    print("🚀 STARTING CORRECTED LEXML COLLECTION")
    print("=" * 60)
    print(f"⏰ Started at: {datetime.now()}")
    
    # Create output directory
    output_dir = "data/processed"
    os.makedirs(output_dir, exist_ok=True)
    
    # Load search terms
    search_terms = load_search_terms()
    print(f"🔍 Total terms to process: {len(search_terms)}")
    print(f"📁 Output directory: {output_dir}")
    
    # Initialize the corrected scraper
    scraper = LexMLScraperFinalCorrigido()
    all_documents = []
    
    # Process each term
    for i, term in enumerate(search_terms, 1):
        print(f"\n📝 [{i}/{len(search_terms)}] Processing: '{term}'")
        
        try:
            # Search with reasonable limit (500 documents per term)
            documents = scraper.search_documents(term, max_results=500)
            all_documents.extend(documents)
            
            print(f"  ✅ {len(documents)} documents collected")
            
            # Save partial results for each term
            if documents:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                partial_filename = os.path.join(output_dir, f"lexml_partial_{term.replace(' ', '_')}_{timestamp}.csv")
                scraper.save_to_csv(documents, partial_filename)
                print(f"  💾 Saved to: {partial_filename}")
            
        except Exception as e:
            logger.error(f"Error processing term '{term}': {str(e)}")
            print(f"  ❌ Error: {str(e)}")
            continue
        
        # Rate limiting between terms
        if i < len(search_terms):
            print(f"  ⏳ Waiting 3 seconds...")
            time.sleep(3)
    
    # Save consolidated results
    if all_documents:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Remove duplicates
        unique_docs = []
        seen_urns = set()
        
        for doc in all_documents:
            urn = doc.get('urn', '')
            title = doc.get('title', '')
            
            identifier = urn if urn else title
            if identifier and identifier not in seen_urns:
                seen_urns.add(identifier)
                unique_docs.append(doc)
        
        # Save final consolidated file
        consolidated_filename = os.path.join(output_dir, f"lexml_corrected_complete_{timestamp}.csv")
        scraper.save_to_csv(unique_docs, consolidated_filename)
        
        # Save statistics
        stats = {
            'execution_time': str(datetime.now()),
            'total_terms_processed': len(search_terms),
            'total_documents_found': len(all_documents),
            'unique_documents': len(unique_docs),
            'duplicate_rate': (len(all_documents) - len(unique_docs)) / len(all_documents) if all_documents else 0,
            'files_generated': {
                'consolidated_csv': consolidated_filename,
                'partial_files': f"{len(search_terms)} partial CSV files"
            }
        }
        
        import json
        stats_filename = os.path.join(output_dir, f"lexml_corrected_stats_{timestamp}.json")
        with open(stats_filename, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        
        print(f"\n🎉 COLLECTION COMPLETED SUCCESSFULLY!")
        print(f"📊 Results Summary:")
        print(f"  - Total documents found: {len(all_documents):,}")
        print(f"  - Unique documents: {len(unique_docs):,}")
        print(f"  - Duplicate rate: {stats['duplicate_rate']:.1%}")
        print(f"  - Terms processed: {len(search_terms)}")
        print(f"\n📁 Files generated:")
        print(f"  - Consolidated: {consolidated_filename}")
        print(f"  - Statistics: {stats_filename}")
        print(f"  - Partial files: {len(search_terms)} files in {output_dir}")
        
        # Show document type breakdown
        type_counts = {}
        for doc in unique_docs:
            doc_type = doc.get('urn_type', 'unknown')
            type_counts[doc_type] = type_counts.get(doc_type, 0) + 1
        
        print(f"\n📋 Document Types:")
        for doc_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {doc_type}: {count}")
        
        return unique_docs
        
    else:
        print(f"\n❌ NO DOCUMENTS COLLECTED")
        return []

def main():
    """Main function"""
    try:
        results = run_complete_collection()
        
        if results:
            print(f"\n✅ SUCCESS: {len(results)} documents processed and saved to ./data/processed")
        else:
            print(f"\n❌ FAILED: No documents were collected")
            
    except KeyboardInterrupt:
        print("\n⚠️ Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        logger.error(f"Collection failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()