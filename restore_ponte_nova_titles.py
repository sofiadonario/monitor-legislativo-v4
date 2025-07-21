#!/usr/bin/env python3
"""
Restore and properly fix Ponte Nova titles
"""

import psycopg2
import re

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Mapping of IDs to their correct titles (from CSV data)
TITLE_FIXES = {
    624: "Lei n° 2414, de 09 de Março de 2000",
    625: "Lei n° 3422, de 26 de Março de 2010",
    626: "Decreto n° 12404, de 14 de Março de 2022",
    627: "Decreto n° 12402, de 04 de Março de 2022",
    628: "Decreto Municipal n° 13448, de 21 de Março de 2024",
}

def fix_date_format(text):
    """Fix date format in text like '09 deMarçode 2000' to '09 de Março de 2000'"""
    # Month names in Portuguese
    months = [
        'Janeiro', 'Fevereiro', 'Março', 'Abril', 'Maio', 'Junho',
        'Julho', 'Agosto', 'Setembro', 'Outubro', 'Novembro', 'Dezembro'
    ]
    
    fixed_text = text
    for month in months:
        # Fix pattern like "deMarçode" to "de Março de"
        pattern = f'de{month}de'
        replacement = f'de {month} de'
        fixed_text = re.sub(pattern, replacement, fixed_text, flags=re.IGNORECASE)
        
        # Also fix pattern like "09 deMarço" to "09 de Março"
        pattern2 = f'(\\d+)\\s*de{month}'
        replacement2 = f'\\1 de {month}'
        fixed_text = re.sub(pattern2, replacement2, fixed_text, flags=re.IGNORECASE)
        
        # Fix pattern like "Marçode 2000" to "Março de 2000"
        pattern3 = f'{month}de\\s*(\\d+)'
        replacement3 = f'{month} de \\1'
        fixed_text = re.sub(pattern3, replacement3, fixed_text, flags=re.IGNORECASE)
    
    return fixed_text

def restore_titles():
    """Restore and fix titles"""
    try:
        print("🔧 Restoring and fixing Ponte Nova titles...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # First, apply the specific fixes we know
        print("\n1️⃣ Applying known title fixes...")
        for id, correct_title in TITLE_FIXES.items():
            cursor.execute("""
                UPDATE documents
                SET titulo = %s
                WHERE id = %s
            """, (correct_title, id))
            print(f"   ✅ Fixed ID {id}: {correct_title}")
        
        # Now look for any other titles with similar patterns
        print("\n2️⃣ Fixing other titles with date formatting issues...")
        cursor.execute("""
            SELECT id, titulo
            FROM documents 
            WHERE titulo ~ 'de[A-Z][a-záêçõ]+de'
               OR titulo ~ '\\d+\\s*de[A-Z]'
               OR titulo LIKE '%de  de  de%'
        """)
        
        titles_to_fix = cursor.fetchall()
        print(f"   Found {len(titles_to_fix)} titles with potential date issues")
        
        fixed_count = 0
        for id, title in titles_to_fix:
            if id not in TITLE_FIXES:  # Don't re-fix the ones we already fixed
                fixed_title = fix_date_format(title)
                
                # Fix any remaining "de  de  de" patterns
                fixed_title = re.sub(r'de\s+de\s+de', 'de', fixed_title)
                
                if fixed_title != title:
                    cursor.execute("""
                        UPDATE documents
                        SET titulo = %s
                        WHERE id = %s
                    """, (fixed_title, id))
                    fixed_count += 1
                    
                    if fixed_count <= 3:
                        print(f"   Fixed ID {id}:")
                        print(f"     Before: {title[:60]}...")
                        print(f"     After:  {fixed_title[:60]}...")
        
        print(f"   ✅ Fixed {fixed_count} additional titles")
        
        # Fix any spacing issues in content (similar patterns)
        print("\n3️⃣ Checking content for similar issues...")
        cursor.execute("""
            UPDATE documents
            SET conteudo = regexp_replace(
                conteudo,
                'de([A-ZÁÊÇÕ][a-záêçõ]+)de',
                'de \\1 de',
                'g'
            )
            WHERE conteudo ~ 'de[A-ZÁÊÇÕ][a-záêçõ]+de'
        """)
        
        if cursor.rowcount > 0:
            print(f"   ✅ Fixed content spacing in {cursor.rowcount} records")
        
        # Commit all changes
        conn.commit()
        
        # Verify the fixes
        print("\n📊 Verification of Ponte Nova records:")
        cursor.execute("""
            SELECT id, estado, municipality, titulo
            FROM documents 
            WHERE municipality = 'Ponte Nova'
            ORDER BY id
            LIMIT 5
        """)
        
        samples = cursor.fetchall()
        for id, estado, municipality, title in samples:
            print(f"   ID {id}: Estado='{estado}', Municipality='{municipality}'")
            print(f"      Title: {title}")
        
        # Check for any remaining issues
        print("\n🔍 Checking for remaining date formatting issues...")
        cursor.execute("""
            SELECT COUNT(*)
            FROM documents 
            WHERE titulo ~ 'de[A-Z][a-záêçõ]+de'
               OR titulo ~ '\\d+\\s*de[A-Z]'
               OR titulo LIKE '%de  %  de%'
        """)
        
        remaining = cursor.fetchone()[0]
        print(f"   Remaining titles with potential issues: {remaining}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    restore_titles()