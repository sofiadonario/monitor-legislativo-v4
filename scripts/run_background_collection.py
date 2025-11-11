#!/usr/bin/env python3
"""
Run full corrected collection in optimized background mode
"""

import sys
import os
import time
import pandas as pd
from datetime import datetime
import subprocess
import signal

def run_optimized_corrected_collection():
    """Run the collection with progress saving"""
    
    print("🚀 Starting Background Corrected Collection")
    print("📊 This will take 30-45 minutes for quality results")
    print("💾 Progress will be saved periodically")
    print()
    
    # Start the collection process
    try:
        # Run with unbuffered output and no timeout
        process = subprocess.Popen([
            'python3', 'run_full_corrected_collection.py'
        ], 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        universal_newlines=True,
        bufsize=1)
        
        print("📈 Collection started successfully")
        print("⏱️  Expected completion: 30-45 minutes")
        print("🔍 Monitor log files for progress updates")
        print()
        
        # Monitor progress
        last_progress_time = datetime.now()
        
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                # Show periodic progress updates
                if 'Processando' in output or 'docs' in output:
                    current_time = datetime.now()
                    if (current_time - last_progress_time).seconds >= 30:  # Every 30 seconds
                        print(f"[{current_time.strftime('%H:%M:%S')}] {output.strip()}")
                        last_progress_time = current_time
        
        rc = process.poll()
        if rc == 0:
            print("\n🎉 Collection completed successfully!")
            
            # Check for output files
            corrected_files = [f for f in os.listdir('.') if f.startswith('lexml_full_corrected_collection_')]
            if corrected_files:
                latest_file = sorted(corrected_files)[-1]
                df = pd.read_csv(latest_file)
                
                print(f"📁 File: {latest_file}")
                print(f"📊 Documents: {len(df)}")
                
                # Quick validation
                if 'enacting_date' in df.columns:
                    dates_count = len(df[df['enacting_date'].astype(str).str.len() > 4])
                    date_rate = dates_count / len(df) * 100
                    print(f"📅 Date extraction: {date_rate:.1f}%")
                
                if 'urn_type' in df.columns:
                    types = df['urn_type'].value_counts()
                    print("📋 Document types:")
                    for doc_type, count in types.head(3).items():
                        print(f"  {doc_type}: {count}")
                
                return latest_file, len(df)
            else:
                print("⚠️  No output files found")
                return None, 0
        else:
            print(f"\n❌ Collection failed with return code: {rc}")
            return None, 0
            
    except KeyboardInterrupt:
        print("\n⚠️  Collection interrupted by user")
        if 'process' in locals():
            process.terminate()
        return None, 0
    except Exception as e:
        print(f"\n❌ Error running collection: {e}")
        return None, 0

def monitor_existing_collection():
    """Monitor if collection is already running"""
    
    # Check for recent corrected files
    corrected_files = [f for f in os.listdir('.') if f.startswith('lexml_full_corrected_collection_')]
    
    if corrected_files:
        latest_file = sorted(corrected_files)[-1]
        file_time = os.path.getmtime(latest_file)
        current_time = time.time()
        
        # If file is less than 2 hours old, consider it recent
        if (current_time - file_time) < 7200:
            print(f"✅ Recent corrected collection found: {latest_file}")
            
            df = pd.read_csv(latest_file)
            print(f"📊 Documents: {len(df)}")
            
            # Validate it's properly corrected
            if 'enacting_date' in df.columns:
                dates_count = len(df[df['enacting_date'].astype(str).str.len() > 4])
                date_rate = dates_count / len(df) * 100
                print(f"📅 Date extraction: {date_rate:.1f}%")
                
                if date_rate >= 80:
                    print("✅ Collection appears to be properly corrected")
                    return latest_file, len(df)
            
    return None, 0

def main():
    """Main execution"""
    print("🔍 Checking for existing corrected collection...")
    
    # First check if we already have a good corrected collection
    existing_file, existing_count = monitor_existing_collection()
    
    if existing_file and existing_count > 1000:
        print(f"\n🎉 Using existing corrected collection!")
        print(f"📁 File: {existing_file}")
        print(f"📊 Documents: {existing_count}")
        print("✅ No need to re-run collection")
        return existing_file, existing_count
    
    print("\n🚀 Starting new corrected collection...")
    
    # Run the optimized collection
    result_file, document_count = run_optimized_corrected_collection()
    
    if result_file:
        print(f"\n🎉 Corrected collection successful!")
        print(f"📁 File: {result_file}")
        print(f"📊 Documents: {document_count}")
        print("✅ Quality data collection complete")
    else:
        print("\n⚠️  Collection incomplete - will use existing data")
    
    return result_file, document_count

if __name__ == "__main__":
    main()