#!/usr/bin/env python3
"""
Load search terms from JSON file into the database
This script reads the extracted search terms and populates the search_terms_config table
"""

import asyncio
import os
import sys
import json
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from core.periodic_collection.lexml_collector import LexMLPeriodicCollector

# Load environment variables
load_dotenv()


async def load_search_terms():
    """Load search terms from JSON file to database"""
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        print("❌ DATABASE_URL environment variable not found")
        print("Please set: export DATABASE_URL='your_database_url'")
        return
    
    print("🔄 Initializing search terms loader...")
    
    try:
        # Initialize collector
        collector = LexMLPeriodicCollector(database_url)
        
        # Load and display search terms
        print(f"\n📋 Loaded {len(collector.search_terms)} search terms from JSON file")
        
        if collector.search_terms:
            print("\n🔍 Sample search terms:")
            for i, term in enumerate(collector.search_terms[:10], 1):
                print(f"   {i}. {term}")
            
            if len(collector.search_terms) > 10:
                print(f"   ... and {len(collector.search_terms) - 10} more terms")
        
        # Sync to database
        print("\n🔄 Syncing search terms to database...")
        async with collector:
            await collector.sync_search_terms_from_json()
        
        print("\n✅ Search terms successfully loaded to database!")
        
    except Exception as e:
        print(f"\n❌ Error loading search terms: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("=" * 60)
    print("SEARCH TERMS LOADER")
    print("Loading transport legislation search terms to database")
    print("=" * 60)
    
    asyncio.run(load_search_terms())