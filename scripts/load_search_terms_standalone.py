#!/usr/bin/env python3
"""
Standalone script to load search terms into the database
"""

import asyncio
import os
import json
from pathlib import Path
from datetime import datetime
import asyncpg
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


async def load_search_terms():
    """Load search terms from JSON file to database"""
    database_url = os.getenv('DATABASE_URL')
    if not database_url:
        print("❌ DATABASE_URL environment variable not found")
        return
    
    # Load search terms from JSON
    json_path = Path(__file__).parent.parent / 'core' / 'periodic_collection' / 'search_terms.json'
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            search_terms = data.get('search_terms', [])
            
        print(f"📋 Loaded {len(search_terms)} search terms from JSON file")
        print("\n🔍 Sample search terms:")
        for i, term in enumerate(search_terms[:10], 1):
            print(f"   {i}. {term}")
        
        if len(search_terms) > 10:
            print(f"   ... and {len(search_terms) - 10} more terms")
        
        # Connect to database
        print("\n🔄 Connecting to database...")
        conn = await asyncpg.connect(database_url)
        
        try:
            # Get existing terms
            existing_terms = await conn.fetch("""
                SELECT term_name FROM search_terms_config
            """)
            existing_set = {row['term_name'] for row in existing_terms}
            
            # Add new terms
            added_count = 0
            for term in search_terms:
                if term not in existing_set:
                    await conn.execute("""
                        INSERT INTO search_terms_config 
                        (term_name, cql_query, description, collection_frequency, 
                         priority_level, is_active, created_at)
                        VALUES ($1, $2, $3, $4, $5, true, NOW())
                    """, 
                        term[:100],  # term_name (truncated)
                        term,        # cql_query (full term)
                        f'Transport legislation search: {term[:50]}',
                        'monthly',
                        2            # priority_level
                    )
                    added_count += 1
            
            print(f"\n✅ Added {added_count} new search terms to database!")
            
            # Show total count
            total_count = await conn.fetchval("SELECT COUNT(*) FROM search_terms_config")
            print(f"📊 Total search terms in database: {total_count}")
            
        finally:
            await conn.close()
            
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("=" * 60)
    print("SEARCH TERMS LOADER (Standalone)")
    print("=" * 60)
    
    asyncio.run(load_search_terms())