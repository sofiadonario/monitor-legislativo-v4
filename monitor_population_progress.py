#!/usr/bin/env python3
"""
Monitor database population progress
"""

import psycopg2
import time
from datetime import datetime

DB_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def check_progress():
    """Check current population progress"""
    try:
        conn = psycopg2.connect(DB_URL)
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM documents")
            current_count = cur.fetchone()[0]
            
            # Get category distribution
            cur.execute("""
                SELECT dc.name, COUNT(*) as count
                FROM documents d
                JOIN document_categories dc ON d.category_id = dc.id
                GROUP BY dc.name
                ORDER BY count DESC
            """)
            categories = cur.fetchall()
            
        conn.close()
        
        target = 134014
        progress = (current_count / target) * 100
        
        print(f"📊 Progress: {current_count:,}/{target:,} documents ({progress:.1f}%)")
        print("📋 Current categories:")
        for cat, count in categories:
            cat_pct = (count / current_count) * 100
            print(f"   {cat}: {count:,} ({cat_pct:.1f}%)")
        
        if current_count >= target:
            print("✅ POPULATION COMPLETE!")
            return True
        else:
            remaining = target - current_count
            print(f"⏳ Remaining: {remaining:,} documents")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def main():
    print("🔍 MONITORING DATABASE POPULATION PROGRESS...")
    print("Target: 134,014 deduplicated documents")
    print("="*50)
    
    completed = check_progress()
    
    if not completed:
        print("\n💡 To complete population, run:")
        print("python3 complete_database_population.py")
        print("\n📝 Expected final distribution:")
        print("   Jurisprudência: ~54,617 documents (40.8%)")
        print("   Legislação: ~51,086 documents (38.1%)")
        print("   Outros: ~13,850 documents (10.3%)")
        print("   Doutrina: ~12,809 documents (9.6%)")
        print("   Proposições: ~1,651 documents (1.2%)")

if __name__ == "__main__":
    main()