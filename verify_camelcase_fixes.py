#!/usr/bin/env python3
"""
Verify that camelCase fixes have been applied correctly
"""

import psycopg2

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def verify_fixes():
    """Verify the camelCase fixes"""
    try:
        print("🔍 Verifying camelCase fixes...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Check for remaining camelCase patterns
        patterns_to_check = [
            'PonteNova', 'SantaAna', 'edoDepartamento', 'referidaLei', 
            'FundoPIS', 'dasLeisdoTrabalho', 'OuroPreto', 'BeloHorizonte'
        ]
        
        print("\n📊 Checking for remaining camelCase patterns:")
        
        for pattern in patterns_to_check:
            cursor.execute("""
                SELECT COUNT(*) FROM documents 
                WHERE titulo LIKE %s 
                   OR conteudo LIKE %s 
                   OR municipality LIKE %s
                   OR document_summary LIKE %s
            """, (f'%{pattern}%', f'%{pattern}%', f'%{pattern}%', f'%{pattern}%'))
            
            remaining = cursor.fetchone()[0]
            if remaining == 0:
                print(f"   ✅ '{pattern}': No remaining instances")
            else:
                print(f"   ⚠️ '{pattern}': {remaining} instances still remain")
                
                # Show where they remain
                cursor.execute("""
                    SELECT id, 
                           CASE WHEN titulo LIKE %s THEN 'titulo' ELSE '' END,
                           CASE WHEN conteudo LIKE %s THEN 'conteudo' ELSE '' END,
                           CASE WHEN municipality LIKE %s THEN 'municipality' ELSE '' END,
                           CASE WHEN document_summary LIKE %s THEN 'summary' ELSE '' END
                    FROM documents 
                    WHERE titulo LIKE %s 
                       OR conteudo LIKE %s 
                       OR municipality LIKE %s
                       OR document_summary LIKE %s
                    LIMIT 3
                """, (f'%{pattern}%', f'%{pattern}%', f'%{pattern}%', f'%{pattern}%',
                      f'%{pattern}%', f'%{pattern}%', f'%{pattern}%', f'%{pattern}%'))
                
                samples = cursor.fetchall()
                for sample in samples:
                    fields = [f for f in sample[1:] if f]
                    print(f"      ID {sample[0]}: Found in {', '.join(fields)}")
        
        # Check for properly fixed patterns
        print("\n📋 Sample of properly fixed content:")
        
        fixed_patterns = ['Ponte Nova', 'Santa Ana', 'e do Departamento', 'das Leis do Trabalho']
        
        for pattern in fixed_patterns:
            cursor.execute("""
                SELECT id, titulo, municipality
                FROM documents 
                WHERE conteudo LIKE %s OR document_summary LIKE %s
                LIMIT 2
            """, (f'%{pattern}%', f'%{pattern}%'))
            
            samples = cursor.fetchall()
            if samples:
                print(f"\n   Pattern '{pattern}':")
                for id, title, mun in samples:
                    print(f"      ID {id}: Municipality='{mun}', Title: {title[:50]}...")
        
        # Look for any other potential camelCase patterns we might have missed
        print("\n🔍 Searching for other potential camelCase patterns...")
        
        cursor.execute("""
            SELECT DISTINCT 
                regexp_split_to_table(conteudo, '\\s+') as word,
                COUNT(*) as frequency
            FROM documents 
            WHERE conteudo ~ '[a-z][A-Z]' 
               OR conteudo ~ '[A-Z][a-z]+[A-Z]'
            GROUP BY word
            HAVING word ~ '[a-z][A-Z]' 
               OR word ~ '[A-Z][a-z]+[A-Z]'
               AND LENGTH(word) > 5
               AND word !~ '[0-9]'
            ORDER BY frequency DESC
            LIMIT 10
        """)
        
        potential_patterns = cursor.fetchall()
        if potential_patterns:
            print(f"   Found {len(potential_patterns)} other potential patterns:")
            for word, freq in potential_patterns:
                # Clean up word (remove punctuation)
                clean_word = word.strip('.,;:()[]"')
                if len(clean_word) > 5 and clean_word.isalpha():
                    print(f"      '{clean_word}' ({freq} times)")
        
        # Final statistics
        print("\n📊 Final Database Statistics:")
        
        cursor.execute("SELECT COUNT(*) FROM documents")
        total = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE municipality IS NOT NULL AND municipality != ''
        """)
        with_municipality = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM documents 
            WHERE estado IS NOT NULL AND estado != '' AND estado !~ '-'
        """)
        with_clean_estado = cursor.fetchone()[0]
        
        print(f"   Total documents: {total}")
        print(f"   Documents with municipality: {with_municipality}")
        print(f"   Documents with clean estado: {with_clean_estado}")
        print(f"   Percentage with location data: {((with_municipality + with_clean_estado) / total * 100):.1f}%")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    verify_fixes()