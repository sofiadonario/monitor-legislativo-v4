#!/usr/bin/env python3
"""
Fix the remaining camelCase patterns with simple string replacement
"""

import psycopg2

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Direct string replacements
REPLACEMENTS = {
    'PonteNova': 'Ponte Nova',
    'SantaAna': 'Santa Ana', 
    'edoDepartamento': 'e do Departamento',
    'referidaLei': 'referida Lei',
    'FundoPIS': 'Fundo PIS',
    'dasLeisdoTrabalho': 'das Leis do Trabalho',
    'oAcordodeParissob': 'o Acordo de Paris sob',
}

def fix_remaining():
    """Fix remaining camelCase patterns with simple REPLACE"""
    try:
        print("🔧 Fixing remaining camelCase patterns with direct replacement...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        total_fixed = 0
        
        # Fix each pattern in content and summary fields
        for old_text, new_text in REPLACEMENTS.items():
            print(f"\n📝 Fixing '{old_text}' → '{new_text}':")
            
            # Fix in conteudo field
            cursor.execute("""
                UPDATE documents
                SET conteudo = REPLACE(conteudo, %s, %s)
                WHERE conteudo LIKE %s
            """, (old_text, new_text, f'%{old_text}%'))
            
            content_fixes = cursor.rowcount
            if content_fixes > 0:
                print(f"   ✅ Fixed in content: {content_fixes} records")
                total_fixed += content_fixes
            
            # Fix in document_summary field
            cursor.execute("""
                UPDATE documents
                SET document_summary = REPLACE(document_summary, %s, %s)
                WHERE document_summary LIKE %s
            """, (old_text, new_text, f'%{old_text}%'))
            
            summary_fixes = cursor.rowcount
            if summary_fixes > 0:
                print(f"   ✅ Fixed in summary: {summary_fixes} records")
                total_fixed += summary_fixes
            
            # Also check titles just in case
            cursor.execute("""
                UPDATE documents
                SET titulo = REPLACE(titulo, %s, %s)
                WHERE titulo LIKE %s
            """, (old_text, new_text, f'%{old_text}%'))
            
            title_fixes = cursor.rowcount
            if title_fixes > 0:
                print(f"   ✅ Fixed in titles: {title_fixes} records")
                total_fixed += title_fixes
        
        # Also fix some common patterns that might exist
        print(f"\n📝 Applying additional pattern fixes...")
        
        # Fix "doAcordo" → "do Acordo", "daLei" → "da Lei", etc.
        common_patterns = [
            ('doAcordo', 'do Acordo'),
            ('daLei', 'da Lei'),
            ('doTrabalho', 'do Trabalho'),
            ('daSaude', 'da Saúde'),
            ('daSaúde', 'da Saúde'),
            ('doMeioAmbiente', 'do Meio Ambiente'),
            ('daEducacao', 'da Educação'),
            ('daEducação', 'da Educação'),
        ]
        
        for old_pattern, new_pattern in common_patterns:
            cursor.execute("""
                UPDATE documents
                SET conteudo = REPLACE(conteudo, %s, %s),
                    document_summary = REPLACE(document_summary, %s, %s)
                WHERE conteudo LIKE %s OR document_summary LIKE %s
            """, (old_pattern, new_pattern, old_pattern, new_pattern, 
                  f'%{old_pattern}%', f'%{old_pattern}%'))
            
            if cursor.rowcount > 0:
                print(f"   ✅ Fixed pattern '{old_pattern}' → '{new_pattern}': {cursor.rowcount} records")
                total_fixed += cursor.rowcount
        
        # Commit changes
        conn.commit()
        
        print(f"\n✅ Total fixes applied: {total_fixed}")
        
        # Verify the fixes
        print(f"\n📊 Verification:")
        
        for pattern in REPLACEMENTS.keys():
            cursor.execute("""
                SELECT COUNT(*) FROM documents 
                WHERE conteudo LIKE %s 
                   OR document_summary LIKE %s
                   OR titulo LIKE %s
            """, (f'%{pattern}%', f'%{pattern}%', f'%{pattern}%'))
            
            remaining = cursor.fetchone()[0]
            if remaining == 0:
                print(f"   ✅ '{pattern}': Completely fixed!")
            else:
                print(f"   ⚠️ '{pattern}': {remaining} instances still remain")
        
        # Show sample of fixed content
        print(f"\n📋 Sample of fixed records:")
        cursor.execute("""
            SELECT id, municipality, titulo, 
                   SUBSTRING(conteudo FROM 1 FOR 100) as content_sample
            FROM documents 
            WHERE conteudo LIKE '%Ponte Nova%'
               OR document_summary LIKE '%Ponte Nova%'
            LIMIT 3
        """)
        
        samples = cursor.fetchall()
        for id, mun, title, content in samples:
            print(f"   ID {id}: Municipality='{mun}'")
            print(f"      Title: {title[:60]}...")
            print(f"      Content sample: {content[:80]}...")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    fix_remaining()