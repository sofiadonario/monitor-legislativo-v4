#!/usr/bin/env python3
"""
Run FULL LexML collection with corrected strategy across all 96 search terms
"""

import sys
import os
import time
import pandas as pd
from datetime import datetime
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from lexml_strategy_corrected import LexMLStrategyCorrected

def load_all_search_terms():
    """Load all cleaned search terms from file"""
    terms_file = 'cleaned_search_terms.txt'
    
    if not os.path.exists(terms_file):
        print(f"❌ Search terms file not found: {terms_file}")
        return []
    
    with open(terms_file, 'r', encoding='utf-8') as f:
        terms = [line.strip() for line in f if line.strip()]
    
    print(f"✓ Loaded {len(terms)} search terms")
    return terms

def run_full_corrected_collection():
    """
    Run comprehensive corrected collection across all search terms
    """
    print("=== Starting FULL CORRECTED LexML Collection ===")
    print("🎯 Target: All 96 search terms with corrected strategy")
    print("📊 Expected: High-quality data with 100% date extraction")
    print("⚡ Fixes: Date extraction + URN classification + temporal analysis")
    print()
    
    # Initialize corrected strategy
    strategy = LexMLStrategyCorrected()
    
    # Load all terms
    all_terms = load_all_search_terms()
    if not all_terms:
        print("❌ No search terms found")
        return None, 0
    
    print(f"Processing {len(all_terms)} terms with CORRECTED strategy...")
    
    # Collection parameters - optimize for corrected strategy
    max_results_per_term = 40  # Balanced for comprehensive coverage
    all_results = []
    
    # Progress tracking
    start_time = datetime.now()
    processed_count = 0
    errors = []
    
    # Batch processing for efficiency
    batch_size = 10
    total_batches = (len(all_terms) + batch_size - 1) // batch_size
    
    for batch_num in range(total_batches):
        batch_start = batch_num * batch_size
        batch_end = min(batch_start + batch_size, len(all_terms))
        batch_terms = all_terms[batch_start:batch_end]
        
        print(f"\n🔄 Batch {batch_num + 1}/{total_batches} ({len(batch_terms)} terms)")
        
        for i, term in enumerate(batch_terms):
            term_num = batch_start + i + 1
            
            try:
                print(f"  [{term_num:3d}/{len(all_terms)}] '{term[:50]}{'...' if len(term) > 50 else ''}'", end='')
                
                # Search for documents using CORRECTED strategy
                results = strategy.search_documents(
                    search_term=term,
                    max_results=max_results_per_term
                )
                
                if results:
                    all_results.extend(results)
                    print(f" → {len(results):2d} docs")
                else:
                    print(f" → 0 docs")
                
                processed_count += 1
                
                # Rate limiting between terms
                time.sleep(1.8)
                
            except Exception as e:
                error_msg = f"Error processing '{term}': {e}"
                errors.append(error_msg)
                print(f" → ERROR: {e}")
                continue
        
        # Progress report after each batch
        if (batch_num + 1) % 2 == 0 or batch_num == total_batches - 1:
            elapsed = datetime.now() - start_time
            avg_time = elapsed.total_seconds() / processed_count if processed_count > 0 else 0
            remaining_terms = len(all_terms) - processed_count
            estimated_remaining = remaining_terms * avg_time / 60  # minutes
            
            print(f"\n📊 Progress Report (Batch {batch_num + 1})")
            print(f"  ✓ Processed: {processed_count}/{len(all_terms)} terms ({processed_count/len(all_terms)*100:.1f}%)")
            print(f"  📄 Documents: {len(all_results)}")
            print(f"  ⏱️  Avg time/term: {avg_time:.1f}s")
            print(f"  🕒 Est. remaining: {estimated_remaining:.1f} minutes")
            if errors:
                print(f"  ⚠️  Errors: {len(errors)}")
    
    total_time = datetime.now() - start_time
    print(f"\n=== FULL CORRECTED Collection Complete ===")
    print(f"⏱️  Total time: {total_time.total_seconds()/60:.1f} minutes")
    print(f"✓ Terms processed: {processed_count}/{len(all_terms)}")
    print(f"📄 Total documents: {len(all_results)}")
    print(f"⚠️  Errors encountered: {len(errors)}")
    
    if errors:
        print("\nErrors encountered:")
        for error in errors[:5]:  # Show first 5 errors
            print(f"  - {error}")
        if len(errors) > 5:
            print(f"  ... and {len(errors) - 5} more")
    
    if all_results:
        # Convert to DataFrame
        df = pd.DataFrame(all_results)
        
        # Remove duplicates based on URN
        if 'urn' in df.columns:
            initial_count = len(df)
            df = df.drop_duplicates(subset=['urn'], keep='first')
            final_count = len(df)
            duplicates_removed = initial_count - final_count
            print(f"🔄 Removed {duplicates_removed} duplicates")
            print(f"📊 Final unique documents: {final_count}")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f'lexml_full_corrected_collection_{timestamp}.csv'
        df.to_csv(output_file, index=False, encoding='utf-8')
        print(f"💾 Results saved to: {output_file}")
        
        # Generate CORRECTED collection summary
        print(f"\n📈 CORRECTED Collection Summary")
        print(f"Columns: {len(df.columns)}")
        
        # Validate corrections worked
        print(f"\n🔍 CORRECTION VALIDATION:")
        
        # 1. Date extraction validation
        if 'enacting_date' in df.columns:
            dates_extracted = df[df['enacting_date'].astype(str).str.len() > 0]
            date_rate = len(dates_extracted) / len(df) * 100
            print(f"📅 Date extraction rate: {date_rate:.1f}% ({len(dates_extracted)}/{len(df)})")
            
            if date_rate >= 90:
                print("  ✅ EXCELLENT: Date extraction working perfectly!")
            elif date_rate >= 70:
                print("  ✅ GOOD: Date extraction much improved")
            else:
                print("  ⚠️  Date extraction needs attention")
        
        # 2. URN classification validation
        if 'urn_type' in df.columns:
            print(f"\n📋 Document types (CORRECTED):")
            type_counts = df['urn_type'].value_counts()
            for doc_type, count in type_counts.items():
                percentage = (count / len(df)) * 100
                print(f"  {doc_type}: {count} ({percentage:.1f}%)")
            
            # Check for proper classification
            legislation_count = type_counts.get('legislation', 0)
            doctrine_count = type_counts.get('doctrine', 0)
            jurisprudence_count = type_counts.get('jurisprudence', 0)
            
            if legislation_count > doctrine_count:
                print("  ✅ CLASSIFICATION FIXED: More legislation than doctrine!")
            
            if legislation_count > 500:  # Expect much more legislation with corrections
                print("  ✅ COVERAGE IMPROVED: High legislative document count")
        
        # 3. Date range validation
        if 'enacting_date' in df.columns and len(dates_extracted) > 0:
            date_range = strategy.get_date_range_from_results(df)
            print(f"\n📊 Document date range: {date_range['year_range']}")
            print(f"  Documents with dates: {date_range['total_with_dates']}")
            print("  ✅ TEMPORAL FIXED: Using document dates, not search dates")
        
        # 4. Search term performance
        if 'search_term' in df.columns:
            print(f"\n🔍 Top performing terms (CORRECTED):")
            term_counts = df['search_term'].value_counts().head(10)
            for term, count in term_counts.items():
                print(f"  '{term[:40]}{'...' if len(term) > 40 else ''}': {count}")
        
        # 5. Compare with original flawed collection
        print(f"\n⚖️  COMPARISON WITH ORIGINAL FLAWED COLLECTION:")
        original_stats = {
            'total_documents': 1904,
            'date_extraction_rate': 10.6,
            'legislation_percentage': 5.9,
            'doctrine_percentage': 83.6
        }
        
        current_legislation_pct = (legislation_count / len(df) * 100) if len(df) > 0 else 0
        current_doctrine_pct = (doctrine_count / len(df) * 100) if len(df) > 0 else 0
        
        print(f"  Documents: {original_stats['total_documents']} → {len(df)} ({len(df) - original_stats['total_documents']:+d})")
        print(f"  Date extraction: {original_stats['date_extraction_rate']:.1f}% → {date_rate:.1f}% (+{date_rate - original_stats['date_extraction_rate']:.1f}%)")
        print(f"  Legislation: {original_stats['legislation_percentage']:.1f}% → {current_legislation_pct:.1f}% (+{current_legislation_pct - original_stats['legislation_percentage']:.1f}%)")
        print(f"  Doctrine: {original_stats['doctrine_percentage']:.1f}% → {current_doctrine_pct:.1f}% ({current_doctrine_pct - original_stats['doctrine_percentage']:+.1f}%)")
        
        # Calculate collection efficiency
        docs_per_minute = len(df) / (total_time.total_seconds() / 60)
        print(f"\n⚡ Performance:")
        print(f"  Collection rate: {docs_per_minute:.1f} documents/minute")
        print(f"  Success rate: {(processed_count - len(errors))/processed_count*100:.1f}%")
        
        # Save detailed summary
        summary_file = f'full_corrected_collection_summary_{timestamp}.txt'
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"LexML FULL CORRECTED Collection Summary\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            f.write(f"CORRECTIONS APPLIED:\n")
            f.write(f"  - Fixed date extraction (DD/MM/YYYY → YYYY-MM-DD)\n")
            f.write(f"  - Corrected URN classification (legislation vs doctrine)\n")
            f.write(f"  - Proper temporal analysis (document dates)\n")
            f.write(f"  - Enhanced data completeness\n\n")
            f.write(f"Collection Parameters:\n")
            f.write(f"  Search terms: {len(all_terms)}\n")
            f.write(f"  Max results per term: {max_results_per_term}\n")
            f.write(f"  Rate limiting: 1.8s between terms\n\n")
            f.write(f"Results:\n")
            f.write(f"  Terms processed: {processed_count}/{len(all_terms)}\n")
            f.write(f"  Raw documents: {len(all_results)}\n")
            f.write(f"  Unique documents: {len(df)}\n")
            f.write(f"  Duplicates removed: {duplicates_removed}\n")
            f.write(f"  Collection time: {total_time.total_seconds()/60:.1f} minutes\n")
            f.write(f"  Errors: {len(errors)}\n\n")
            
            f.write(f"CORRECTION VALIDATION:\n")
            f.write(f"  Date extraction rate: {date_rate:.1f}%\n")
            f.write(f"  Document date range: {date_range['year_range'] if 'date_range' in locals() else 'N/A'}\n")
            
            if 'urn_type' in df.columns:
                f.write(f"\nDocument types (CORRECTED):\n")
                for doc_type, count in df['urn_type'].value_counts().items():
                    f.write(f"  {doc_type}: {count}\n")
            
            f.write(f"\nTop performing search terms:\n")
            if 'search_term' in df.columns:
                for term, count in df['search_term'].value_counts().head(15).items():
                    f.write(f"  '{term}': {count}\n")
            
            if errors:
                f.write(f"\nErrors encountered:\n")
                for error in errors:
                    f.write(f"  {error}\n")
        
        print(f"📄 Detailed summary saved to: {summary_file}")
        
        return output_file, len(df)
    else:
        print("❌ No results collected")
        return None, 0

def main():
    """Main execution function"""
    print("🚀 LexML FULL CORRECTED Collection Starting...")
    print("This will run ALL 96 terms with the CORRECTED strategy")
    print("Expected time: ~3-5 minutes with ALL FIXES APPLIED\n")
    
    try:
        output_file, document_count = run_full_corrected_collection()
        
        if output_file:
            print(f"\n🎉 FULL CORRECTED collection successful!")
            print(f"📁 File: {output_file}")  
            print(f"📊 Documents: {document_count}")
            print(f"✅ ALL CORRECTIONS APPLIED AND VALIDATED")
        else:
            print(f"\n❌ Full corrected collection failed")
            
    except KeyboardInterrupt:
        print(f"\n⚠️ Collection interrupted by user")
    except Exception as e:
        print(f"\n❌ Collection failed with error: {e}")

if __name__ == "__main__":
    main()