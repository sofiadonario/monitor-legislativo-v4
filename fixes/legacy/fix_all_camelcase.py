#!/usr/bin/env python3
"""
Fix all camelCase patterns found in the database
"""

import psycopg2
import re

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Define fixes for specific patterns found
SPECIFIC_FIXES = {
    'PonteNova': 'Ponte Nova',
    'SantaAna': 'Santa Ana',
    'edoDepartamento': 'e do Departamento',
    'referidaLei': 'referida Lei',
    'FundoPIS': 'Fundo PIS',
    'oAcordodeParissob': 'o Acordo de Paris sob',  # This one needs manual review
    'dasLeisdoTrabalho': 'das Leis do Trabalho',
}

# Additional municipality patterns that might exist
MUNICIPALITY_FIXES = {
    # Known Brazilian cities that might appear in camelCase
    'OuroPreto': 'Ouro Preto',
    'BeloHorizonte': 'Belo Horizonte',
    'PortoAlegre': 'Porto Alegre',
    'RiodeJaneiro': 'Rio de Janeiro',
    'RioDeJaneiro': 'Rio de Janeiro',
    'SaoPaulo': 'São Paulo',
    'SãoPaulo': 'São Paulo',
    'PortoVelho': 'Porto Velho',
    'CampoGrande': 'Campo Grande',
    'BoaVista': 'Boa Vista',
    'RioBranco': 'Rio Branco',
    'SantaMaria': 'Santa Maria',
    'SantoAndre': 'Santo André',
    'SantoAndré': 'Santo André',
    'SaoBernardo': 'São Bernardo',
    'SãoBernardo': 'São Bernardo',
    'NovaIguacu': 'Nova Iguaçu',
    'NovaIguaçu': 'Nova Iguaçu',
    'JuizdeFora': 'Juiz de Fora',
    'MontesClaros': 'Montes Claros',
    'RibeiraoPreto': 'Ribeirão Preto',
    'RibeirãoPreto': 'Ribeirão Preto',
    'VilaVelha': 'Vila Velha',
    'CaxiasdoSul': 'Caxias do Sul',
    'PassoFundo': 'Passo Fundo',
    'SantaCruz': 'Santa Cruz',
    'VoltaRedonda': 'Volta Redonda',
    'NovoHamburgo': 'Novo Hamburgo',
    'SaoLeopoldo': 'São Leopoldo',
    'SãoLeopoldo': 'São Leopoldo',
    'PedraAzul': 'Pedra Azul',
    'AguasLindas': 'Águas Lindas',
    'ÁguasLindas': 'Águas Lindas',
    'PraiaGrande': 'Praia Grande',
    'CaboFrio': 'Cabo Frio',
    'SantaCruzdo Sul': 'Santa Cruz do Sul',
    'NovaFriburgo': 'Nova Friburgo',
    'BelfordRoxo': 'Belford Roxo',
    'SãoJosé': 'São José',
    'SaoJose': 'São José',
    'PortoSeguro': 'Porto Seguro',
}

# Combine all fixes
ALL_FIXES = {**SPECIFIC_FIXES, **MUNICIPALITY_FIXES}

def apply_camelcase_fixes():
    """Apply all camelCase fixes to the database"""
    try:
        print("🔧 Applying all camelCase fixes...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        total_fixed = 0
        
        # Apply fixes to different fields
        fields_to_fix = [
            ('titulo', 'titles'),
            ('conteudo', 'content'),
            ('municipality', 'municipality'),
            ('document_description', 'description'),
            ('document_summary', 'summary'),
            ('search_term', 'search_term')
        ]
        
        for field, field_name in fields_to_fix:
            print(f"\n📝 Fixing {field_name}...")
            field_fixes = 0
            
            for original, fixed in ALL_FIXES.items():
                # Use word boundaries to avoid partial matches
                cursor.execute(f"""
                    UPDATE documents
                    SET {field} = regexp_replace({field}, '\\y{re.escape(original)}\\y', %s, 'g')
                    WHERE {field} ~ '\\y{re.escape(original)}\\y'
                """, (fixed,))
                
                if cursor.rowcount > 0:
                    print(f"   ✅ Fixed '{original}' → '{fixed}': {cursor.rowcount} records")
                    field_fixes += cursor.rowcount
            
            total_fixed += field_fixes
            print(f"   Total fixes in {field_name}: {field_fixes}")
        
        # Special handling for metadata JSON fields
        print(f"\n📝 Fixing metadata...")
        metadata_fixes = 0
        
        for original, fixed in ALL_FIXES.items():
            # Fix original_municipality in metadata
            cursor.execute("""
                UPDATE documents
                SET metadata = jsonb_set(
                    metadata,
                    '{original_municipality}',
                    to_jsonb(%s)
                )
                WHERE metadata->>'original_municipality' = %s
            """, (fixed, original))
            
            if cursor.rowcount > 0:
                print(f"   ✅ Fixed metadata original_municipality '{original}' → '{fixed}': {cursor.rowcount} records")
                metadata_fixes += cursor.rowcount
            
            # Fix original_state in metadata (less likely but check anyway)
            cursor.execute("""
                UPDATE documents
                SET metadata = jsonb_set(
                    metadata,
                    '{original_state}',
                    to_jsonb(%s)
                )
                WHERE metadata->>'original_state' = %s
            """, (fixed, original))
            
            if cursor.rowcount > 0:
                print(f"   ✅ Fixed metadata original_state '{original}' → '{fixed}': {cursor.rowcount} records")
                metadata_fixes += cursor.rowcount
        
        total_fixed += metadata_fixes
        print(f"   Total fixes in metadata: {metadata_fixes}")
        
        # Apply some general pattern fixes for common issues
        print(f"\n📝 Applying general camelCase pattern fixes...")
        
        # Fix patterns like "doTrabalho" → "do Trabalho"
        cursor.execute("""
            UPDATE documents
            SET conteudo = regexp_replace(
                conteudo,
                '\\b(do|da|de|dos|das)([A-Z][a-z]+)',
                '\\1 \\2',
                'g'
            )
            WHERE conteudo ~ '\\b(do|da|de|dos|das)[A-Z][a-z]+'
        """)
        
        if cursor.rowcount > 0:
            print(f"   ✅ Fixed preposition patterns in content: {cursor.rowcount} records")
            total_fixed += cursor.rowcount
        
        # Same for document_summary
        cursor.execute("""
            UPDATE documents
            SET document_summary = regexp_replace(
                document_summary,
                '\\b(do|da|de|dos|das)([A-Z][a-z]+)',
                '\\1 \\2',
                'g'
            )
            WHERE document_summary ~ '\\b(do|da|de|dos|das)[A-Z][a-z]+'
        """)
        
        if cursor.rowcount > 0:
            print(f"   ✅ Fixed preposition patterns in summary: {cursor.rowcount} records")
            total_fixed += cursor.rowcount
        
        # Commit all changes
        conn.commit()
        
        print(f"\n✅ Total fixes applied: {total_fixed} field updates")
        
        # Verification
        print("\n📊 Verification:")
        
        # Check specific patterns
        patterns_to_check = ['PonteNova', 'SantaAna', 'OuroPreto', 'BeloHorizonte']
        
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
                print(f"   ✅ No remaining '{pattern}' patterns found")
            else:
                print(f"   ⚠️ {remaining} '{pattern}' patterns still remain")
        
        # Show sample of fixed records
        print("\n📋 Sample of records with fixes:")
        cursor.execute("""
            SELECT id, municipality, titulo
            FROM documents 
            WHERE municipality = 'Ponte Nova' 
               OR titulo LIKE '%Ponte Nova%'
            LIMIT 3
        """)
        
        samples = cursor.fetchall()
        for id, mun, title in samples:
            print(f"   ID {id}: Municipality='{mun}'")
            print(f"      Title: {title[:70]}...")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    apply_camelcase_fixes()