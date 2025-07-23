#!/usr/bin/env python3
import psycopg2
import time

# Database connection parameters
DB_PARAMS = {
    'host': 'nozomi.proxy.rlwy.net',
    'port': 44844,
    'database': 'railway',
    'user': 'postgres',
    'password': 'smNCedRjMKeNsoqpurLWXjGEUZxORwVY'
}

def check_status():
    """Check import status"""
    conn = psycopg2.connect(**DB_PARAMS)
    cur = conn.cursor()
    
    # Total count
    cur.execute("SELECT COUNT(*) FROM lexml_documents")
    total = cur.fetchone()[0]
    
    print(f"\n=== IMPORT STATUS ===")
    print(f"Total records imported: {total:,} / 134,014")
    print(f"Progress: {(total/134014)*100:.1f}%")
    
    # Category breakdown
    print("\n=== CATEGORY BREAKDOWN ===")
    cur.execute("""
        SELECT categoria, COUNT(*) 
        FROM lexml_documents 
        GROUP BY categoria 
        ORDER BY COUNT(*) DESC
    """)
    for cat, count in cur.fetchall():
        print(f"  {cat}: {count:,}")
    
    # Modal breakdown
    print("\n=== MODAL BREAKDOWN ===")
    cur.execute("""
        SELECT modal, COUNT(*) 
        FROM lexml_documents 
        GROUP BY modal 
        ORDER BY COUNT(*) DESC
    """)
    for modal, count in cur.fetchall():
        print(f"  {modal}: {count:,}")
    
    # Recent records
    print("\n=== RECENT IMPORTS ===")
    cur.execute("""
        SELECT categoria, modal, COUNT(*) 
        FROM lexml_documents 
        GROUP BY categoria, modal 
        ORDER BY COUNT(*) DESC 
        LIMIT 5
    """)
    for cat, modal, count in cur.fetchall():
        print(f"  {cat} - {modal}: {count:,}")
    
    cur.close()
    conn.close()
    
    return total

if __name__ == "__main__":
    check_status()