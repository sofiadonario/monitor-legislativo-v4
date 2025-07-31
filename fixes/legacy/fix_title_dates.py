#!/usr/bin/env python3
"""
Fix the date formatting issues in titles
"""

import psycopg2
import re

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def fix_title_dates():
    """Fix date formatting in titles"""
    try:
        print("🔧 Fixing date formatting in titles...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # First, let's see what we're dealing with
        print("\n🔍 Checking titles with date issues...")
        cursor.execute("""
            SELECT id, titulo
            FROM documents 
            WHERE titulo LIKE '%de  de  de%'
            LIMIT 5
        """)
        
        samples = cursor.fetchall()
        print(f"Found {len(samples)} sample titles with issues:")
        for id, title in samples:
            print(f"   ID {id}: {title[:80]}...")
        
        # Restore the original pattern and fix it properly
        # The issue is that the previous regex was too aggressive
        
        # First, let's get the original titles from a similar record
        cursor.execute("""
            SELECT id, titulo, municipality
            FROM documents 
            WHERE municipality = 'Ponte Nova'
              AND titulo LIKE '%Lei n° 2414%'
            LIMIT 1
        """)
        
        sample = cursor.fetchone()
        if sample:
            print(f"\nSample record to analyze: {sample[1]}")
        
        # Fix the pattern - looking at the original data, it seems like "deMarçode" should be "de Março de"
        months = {
            'Janeiro': 'Janeiro',
            'Fevereiro': 'Fevereiro',
            'Março': 'Março',
            'Abril': 'Abril',
            'Maio': 'Maio',
            'Junho': 'Junho',
            'Julho': 'Julho',
            'Agosto': 'Agosto',
            'Setembro': 'Setembro',
            'Outubro': 'Outubro',
            'Novembro': 'Novembro',
            'Dezembro': 'Dezembro'
        }
        
        # Get all titles that need fixing
        cursor.execute("""
            SELECT DISTINCT id, titulo
            FROM documents 
            WHERE titulo LIKE '%de  de  de%'
               OR titulo ~ '\\d+\\s*de[A-Z]'
               OR titulo ~ '[a-z]de\\s*\\d'
        """)
        
        titles_to_fix = cursor.fetchall()
        print(f"\n📝 Found {len(titles_to_fix)} titles to fix")
        
        fixed_count = 0
        for id, title in titles_to_fix:
            fixed_title = title
            
            # Fix patterns like "09 deMarçode 2000"
            for month in months.keys():
                # Pattern: number + "de" + month + "de" + number
                pattern = f'(\\d+)\\s*de{month}de\\s*(\\d+)'
                replacement = f'\\1 de {month} de \\2'
                fixed_title = re.sub(pattern, replacement, fixed_title)
                
                # Also fix if it's already partially fixed
                pattern2 = f'de\\s+de\\s+{month}\\s+de'
                replacement2 = f'de {month} de'
                fixed_title = re.sub(pattern2, replacement2, fixed_title)
            
            # Fix any "de  de  de" patterns that might remain
            fixed_title = re.sub(r'de\s+de\s+de', 'de', fixed_title)
            
            # Only update if we actually changed something
            if fixed_title != title:
                cursor.execute("""
                    UPDATE documents
                    SET titulo = %s
                    WHERE id = %s
                """, (fixed_title, id))
                fixed_count += 1
                
                if fixed_count <= 3:
                    print(f"   Fixed ID {id}:")
                    print(f"     Before: {title[:80]}...")
                    print(f"     After:  {fixed_title[:80]}...")
        
        conn.commit()
        print(f"\n✅ Fixed {fixed_count} titles")
        
        # Verify the fix
        print("\n📊 Verification:")
        cursor.execute("""
            SELECT id, titulo
            FROM documents 
            WHERE municipality = 'Ponte Nova'
            LIMIT 3
        """)
        
        samples = cursor.fetchall()
        for id, title in samples:
            print(f"   ID {id}: {title[:80]}...")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    fix_title_dates()