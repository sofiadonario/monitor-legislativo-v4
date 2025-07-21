#!/usr/bin/env python3
"""
Analyze data issues in Railway PostgreSQL database
"""

import psycopg2
import re

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def analyze_issues():
    """Analyze different types of data issues"""
    try:
        print("🔍 Analyzing data issues in Railway PostgreSQL...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # 1. Check estado values with '-' pattern
        print("\n1️⃣ Estado values containing '-':")
        cursor.execute("""
            SELECT DISTINCT estado, COUNT(*) as count
            FROM documents 
            WHERE estado LIKE '%-%'
            GROUP BY estado
            ORDER BY count DESC
        """)
        estado_issues = cursor.fetchall()
        for estado, count in estado_issues:
            print(f"   '{estado}' - {count} records")
        
        # 2. Check municipality values that look like regions
        print("\n2️⃣ Municipality values that look like regions:")
        cursor.execute("""
            SELECT DISTINCT municipality, COUNT(*) as count
            FROM documents 
            WHERE municipality LIKE '%Região%' 
               OR municipality LIKE '%região%'
            GROUP BY municipality
            ORDER BY count DESC
            LIMIT 10
        """)
        region_issues = cursor.fetchall()
        for mun, count in region_issues:
            print(f"   '{mun}' - {count} records")
        
        # 3. Check empty estado with filled municipality
        print("\n3️⃣ Empty estado with filled municipality:")
        cursor.execute("""
            SELECT COUNT(*) 
            FROM documents 
            WHERE (estado IS NULL OR estado = '') 
            AND municipality IS NOT NULL 
            AND municipality != ''
        """)
        empty_estado_count = cursor.fetchone()[0]
        print(f"   Total: {empty_estado_count} records")
        
        # Sample of these records
        cursor.execute("""
            SELECT id, estado, municipality, tipo, titulo
            FROM documents 
            WHERE (estado IS NULL OR estado = '') 
            AND municipality IS NOT NULL 
            AND municipality != ''
            LIMIT 5
        """)
        samples = cursor.fetchall()
        for sample in samples:
            print(f"   ID {sample[0]}: Estado='{sample[1]}', Municipality='{sample[2]}', Tipo={sample[3]}")
        
        # 4. Check patterns in problematic estado values
        print("\n4️⃣ Patterns in problematic estado values:")
        patterns = [
            (r'^(.+)-\s*([A-Z]{2})$', 'Municipality-STATE (no space)'),
            (r'^(.+)\s*-\s*([A-Z]{2})$', 'Municipality - STATE'),
            (r'^([A-Z]{2})\s*-\s*(.+)$', 'STATE - Municipality'),
        ]
        
        for pattern, description in patterns:
            cursor.execute("""
                SELECT estado, COUNT(*) as count
                FROM documents 
                WHERE estado ~ %s
                GROUP BY estado
                ORDER BY count DESC
                LIMIT 5
            """, (pattern,))
            results = cursor.fetchall()
            if results:
                print(f"\n   Pattern: {description}")
                for estado, count in results:
                    print(f"     '{estado}' - {count} records")
        
        # 5. Check metadata for original values
        print("\n5️⃣ Checking metadata for original values:")
        cursor.execute("""
            SELECT 
                estado,
                municipality,
                metadata->>'original_state' as orig_state,
                metadata->>'original_municipality' as orig_mun
            FROM documents 
            WHERE estado LIKE '%-%'
            LIMIT 3
        """)
        metadata_samples = cursor.fetchall()
        for sample in metadata_samples:
            print(f"   Current: estado='{sample[0]}', municipality='{sample[1]}'")
            print(f"   Original: state='{sample[2]}', municipality='{sample[3]}'")
            print()
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    analyze_issues()