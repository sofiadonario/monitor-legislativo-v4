#!/usr/bin/env python3
"""
Run comprehensive LexML data collection using enhanced strategy
"""

import sys
import os
import time
import pandas as pd
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lexml_enhanced_strategy import LexMLFinalStrategy
from process_search_terms import clean_search_terms

def run_comprehensive_collection():
    """
    Run comprehensive data collection across all cleaned search terms
    """
    print("=== Starting Comprehensive LexML Collection ===")
    
    # Initialize strategy
    strategy = LexMLFinalStrategy()
    
    # Load cleaned terms
    cleaned_terms = clean_search_terms('termos_busca.txt')
    print(f"Total terms to process: {len(cleaned_terms)}")
    
    # Prioritize most important terms
    priority_terms = [
        "transporte de carga",
        "transporte rodoviário de carga", 
        "veículos pesados",
        "caminhão",
        "gás natural veicular",
        "biometano",
        "diesel",
        "biodiesel",
        "eficiência energética",
        "emissões",
        "CONTRAN",
        "ANTT",
        "IPI",
        "ICMS",
        "Rota 2030",
        "máquinas agrícolas",
        "transportador autônomo",
        "empresa de transporte"
    ]
    
    # Add priority terms that exist in cleaned terms to front of list
    final_terms = []
    for priority in priority_terms:
        for term in cleaned_terms:
            if priority.lower() in term.lower() and term not in final_terms:
                final_terms.append(term)
    
    # Add remaining terms
    for term in cleaned_terms:
        if term not in final_terms:
            final_terms.append(term)
    
    print(f"Processing {len(final_terms)} terms with priority ordering")
    
    # Collection parameters
    max_results_per_term = 50  # Balance between coverage and speed
    all_results = []
    
    # Progress tracking
    start_time = datetime.now()
    processed_count = 0
    
    for i, term in enumerate(final_terms):
        try:
            print(f"\n[{i+1}/{len(final_terms)}] Processing: '{term}'")
            
            # Search for documents
            results = strategy.search_documents(
                search_term=term,
                max_results=max_results_per_term
            )
            
            if results:
                all_results.extend(results)
                print(f"  ✓ Found {len(results)} documents")
            else:
                print(f"  ⚠ No results found")
            
            processed_count += 1
            
            # Progress reporting
            if processed_count % 5 == 0:
                elapsed = datetime.now() - start_time
                avg_time = elapsed.total_seconds() / processed_count
                remaining = len(final_terms) - processed_count
                estimated_remaining = remaining * avg_time / 60  # minutes
                
                print(f"\n--- Progress Report ---")
                print(f"Processed: {processed_count}/{len(final_terms)} ({processed_count/len(final_terms)*100:.1f}%)")
                print(f"Total documents collected: {len(all_results)}")
                print(f"Average time per term: {avg_time:.1f}s")
                print(f"Estimated time remaining: {estimated_remaining:.1f} minutes")
            
            # Rate limiting to be respectful to the server
            time.sleep(2)
            
        except Exception as e:
            print(f"  ❌ Error processing '{term}': {e}")
            continue
    
    print(f"\n=== Collection Complete ===")
    print(f"Total terms processed: {processed_count}")
    print(f"Total documents collected: {len(all_results)}")
    
    if all_results:
        # Convert to DataFrame
        df = pd.DataFrame(all_results)
        
        # Remove duplicates based on URN
        if 'urn' in df.columns:
            initial_count = len(df)
            df = df.drop_duplicates(subset=['urn'], keep='first')
            final_count = len(df)
            print(f"Removed {initial_count - final_count} duplicates")
            print(f"Final unique documents: {final_count}")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f'lexml_comprehensive_results_{timestamp}.csv'
        df.to_csv(output_file, index=False, encoding='utf-8')
        print(f"✓ Results saved to: {output_file}")
        
        # Generate summary statistics
        print("\n--- Collection Summary ---")
        print(f"Columns: {list(df.columns)}")
        
        if 'urn_type' in df.columns:
            print("\nDocument types:")
            type_counts = df['urn_type'].value_counts()
            for doc_type, count in type_counts.items():
                print(f"  {doc_type}: {count}")
        
        if 'search_term' in df.columns:
            print(f"\nTop terms by results:")
            term_counts = df['search_term'].value_counts().head(10)
            for term, count in term_counts.items():
                print(f"  {term}: {count}")
        
        # Save summary
        summary_file = f'collection_summary_{timestamp}.txt'
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"LexML Comprehensive Collection Summary\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            f.write(f"Total terms processed: {processed_count}\n")
            f.write(f"Total documents collected: {len(all_results)}\n")
            f.write(f"Unique documents after deduplication: {len(df)}\n\n")
            
            if 'urn_type' in df.columns:
                f.write("Document types:\n")
                for doc_type, count in df['urn_type'].value_counts().items():
                    f.write(f"  {doc_type}: {count}\n")
        
        print(f"✓ Summary saved to: {summary_file}")
        
        return output_file, len(df)
    else:
        print("❌ No results collected")
        return None, 0

if __name__ == "__main__":
    output_file, document_count = run_comprehensive_collection()
    
    if output_file:
        print(f"\n🎉 Collection successful!")
        print(f"📄 File: {output_file}")  
        print(f"📊 Documents: {document_count}")
    else:
        print(f"\n❌ Collection failed")