#!/usr/bin/env python3
"""
Start fresh corrected collection and monitor progress
"""

import subprocess
import os
import time
from datetime import datetime

def start_fresh_collection():
    """Start the fresh collection in background"""
    
    print("🚀 Starting Fresh Corrected Collection")
    print("📊 This will collect from scratch using corrected strategy")
    print("⏱️  Expected time: 30-45 minutes")
    print("📝 Progress will be logged to collection_progress.log")
    print()
    
    # Remove any existing log
    if os.path.exists("collection_progress.log"):
        os.remove("collection_progress.log")
    
    # Start collection process
    try:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting collection process...")
        
        process = subprocess.Popen([
            'python3', 'run_full_corrected_collection.py'
        ], 
        stdout=open('collection_progress.log', 'w'),
        stderr=subprocess.STDOUT,
        bufsize=1)
        
        print(f"✅ Collection started successfully (PID: {process.pid})")
        print(f"📄 Progress log: collection_progress.log")
        print(f"🔍 Monitor with: tail -f collection_progress.log")
        print()
        
        # Monitor for a few minutes to ensure it's running
        print("📈 Initial progress monitoring (first 5 minutes):")
        
        start_time = time.time()
        last_log_size = 0
        
        while time.time() - start_time < 300:  # 5 minutes
            # Check if process is still running
            if process.poll() is not None:
                print(f"⚠️  Process ended unexpectedly (return code: {process.returncode})")
                break
            
            # Check log growth
            if os.path.exists("collection_progress.log"):
                current_size = os.path.getsize("collection_progress.log")
                if current_size > last_log_size:
                    # Read new content
                    with open("collection_progress.log", 'r') as f:
                        f.seek(last_log_size)
                        new_content = f.read()
                        
                    # Show relevant progress lines
                    for line in new_content.split('\n'):
                        if any(keyword in line for keyword in ['→', 'docs', 'Batch', 'Complete']):
                            timestamp = datetime.now().strftime('%H:%M:%S')
                            print(f"[{timestamp}] {line.strip()}")
                    
                    last_log_size = current_size
            
            time.sleep(10)  # Check every 10 seconds
        
        if process.poll() is None:
            print(f"\n✅ Collection running successfully in background")
            print(f"📊 Process ID: {process.pid}")
            print(f"⏱️  Estimated completion: {(datetime.now().hour + 1) % 24:02d}:{datetime.now().minute:02d}")
            print(f"📄 Check progress: tail -f collection_progress.log")
            print(f"🔍 Check results: ls -la lexml_full_corrected_collection_*.csv")
            
            return True
        else:
            print(f"\n❌ Collection process ended")
            return False
            
    except Exception as e:
        print(f"❌ Error starting collection: {e}")
        return False

def check_existing_progress():
    """Check if collection is already running or completed"""
    
    # Check for running processes
    try:
        result = subprocess.run(['pgrep', '-f', 'run_full_corrected_collection'], 
                              capture_output=True, text=True)
        if result.stdout.strip():
            print("✅ Collection is already running!")
            print(f"📊 Process ID: {result.stdout.strip()}")
            if os.path.exists("collection_progress.log"):
                print("📄 Monitor progress: tail -f collection_progress.log")
            return True
    except:
        pass
    
    # Check for recent completed files
    corrected_files = [f for f in os.listdir('.') if f.startswith('lexml_full_corrected_collection_')]
    if corrected_files:
        latest_file = sorted(corrected_files)[-1]
        file_time = os.path.getmtime(latest_file)
        current_time = time.time()
        
        # If file is less than 1 hour old, consider it recent
        if (current_time - file_time) < 3600:
            print(f"✅ Recent fresh collection found: {latest_file}")
            file_age = (current_time - file_time) / 60
            print(f"⏱️  Generated {file_age:.1f} minutes ago")
            return True
    
    return False

def main():
    """Main execution"""
    print("🔍 Checking for existing fresh collection...")
    
    if check_existing_progress():
        print("\n✅ Fresh collection already in progress or recently completed")
        print("📋 This provides the comparison data you requested")
    else:
        print("\n🚀 Starting new fresh collection...")
        if start_fresh_collection():
            print("\n🎉 Fresh collection started successfully!")
            print("📊 You now have both:")
            print("   1. Corrected existing data")
            print("   2. Fresh collection with corrected strategy (running)")
            print("🔍 Perfect for comparison!")
        else:
            print("\n❌ Failed to start fresh collection")

if __name__ == "__main__":
    main()