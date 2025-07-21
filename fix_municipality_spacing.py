#!/usr/bin/env python3
"""
Fix municipality name spacing issues in Railway PostgreSQL database
"""

import psycopg2
import re

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

# Comprehensive list of Brazilian municipalities that might have spacing issues
MUNICIPALITY_FIXES = {
    # Actual issues found
    "PonteNova": "Ponte Nova",
    
    # Common patterns that might exist
    "BeloHorizonte": "Belo Horizonte",
    "PortoAlegre": "Porto Alegre",
    "RiodeJaneiro": "Rio de Janeiro",
    "SaoPaulo": "São Paulo",
    "SãoPaulo": "São Paulo",
    "PortoVelho": "Porto Velho",
    "CampoGrande": "Campo Grande",
    "BoaVista": "Boa Vista",
    "RioBranco": "Rio Branco",
    "SantaMaria": "Santa Maria",
    "SantoAndre": "Santo André",
    "SantoAndré": "Santo André",
    "SaoBernardo": "São Bernardo",
    "SãoBernardo": "São Bernardo",
    "SaoCaetano": "São Caetano",
    "SãoCaetano": "São Caetano",
    "NovaIguacu": "Nova Iguaçu",
    "NovaIguaçu": "Nova Iguaçu",
    "VitoriadeConquista": "Vitória de Conquista",
    "VitóriadaConquista": "Vitória da Conquista",
    "JuizdeFora": "Juiz de Fora",
    "FeiradeSantana": "Feira de Santana",
    "RibeiraoPreto": "Ribeirão Preto",
    "RibeirãoPreto": "Ribeirão Preto",
    "SaoJose": "São José",
    "SãoJosé": "São José",
    "SaoLuis": "São Luís",
    "SãoLuís": "São Luís",
    "SaoGoncalo": "São Gonçalo",
    "SãoGonçalo": "São Gonçalo",
    "CaxiasdoSul": "Caxias do Sul",
    "PassoFundo": "Passo Fundo",
    "SantaCruz": "Santa Cruz",
    "VoltaRedonda": "Volta Redonda",
    "NovoHamburgo": "Novo Hamburgo",
    "SaoLeopoldo": "São Leopoldo",
    "SãoLeopoldo": "São Leopoldo",
    "VilaVelha": "Vila Velha",
    "PedraAzul": "Pedra Azul",
    "AguasLindas": "Águas Lindas",
    "ÁguasLindas": "Águas Lindas",
    "MontesClaros": "Montes Claros",
    "GovernadorValadares": "Governador Valadares",
    "IlheusdaCosta": "Ilhéus da Costa",
    "Ilhéus": "Ilhéus",
    "PortoSeguro": "Porto Seguro",
    "AltoParaiso": "Alto Paraíso",
    "AltoParaíso": "Alto Paraíso",
    "BomJesus": "Bom Jesus",
    "SantaRita": "Santa Rita",
    "NovaLima": "Nova Lima",
    "SaoVicente": "São Vicente",
    "SãoVicente": "São Vicente",
    "PraiaGrande": "Praia Grande",
    "SantoAngelo": "Santo Ângelo",
    "SantoÂngelo": "Santo Ângelo",
    "CaboFrio": "Cabo Frio",
    "TerraRoxa": "Terra Roxa",
    "MatoGrosso": "Mato Grosso",
    "BelaVista": "Bela Vista",
    "AltoAraguaia": "Alto Araguaia",
    "NovaOdessa": "Nova Odessa",
    "NovaFriburgo": "Nova Friburgo",
}

def fix_municipality_spacing():
    """Fix municipality name spacing issues"""
    try:
        print("🔧 Fixing municipality name spacing issues...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        total_fixed = 0
        
        # Apply known fixes
        print("\n1️⃣ Applying known municipality name fixes...")
        for incorrect, correct in MUNICIPALITY_FIXES.items():
            cursor.execute("""
                UPDATE documents
                SET municipality = %s
                WHERE municipality = %s
            """, (correct, incorrect))
            
            if cursor.rowcount > 0:
                print(f"   ✅ Fixed '{incorrect}' → '{correct}': {cursor.rowcount} records")
                total_fixed += cursor.rowcount
        
        # Fix patterns with "de", "do", "da" missing spaces
        print("\n2️⃣ Fixing 'de/do/da' patterns...")
        patterns = [
            (r'([a-zA-Z]+)(de)([A-Z][a-zA-Z]+)', r'\1 \2 \3'),
            (r'([a-zA-Z]+)(do)([A-Z][a-zA-Z]+)', r'\1 \2 \3'),
            (r'([a-zA-Z]+)(da)([A-Z][a-zA-Z]+)', r'\1 \2 \3'),
        ]
        
        for pattern, replacement in patterns:
            cursor.execute("""
                SELECT DISTINCT municipality
                FROM documents
                WHERE municipality ~ %s
            """, (pattern,))
            
            municipalities = cursor.fetchall()
            for (mun,) in municipalities:
                fixed = re.sub(pattern, replacement, mun)
                if fixed != mun:
                    cursor.execute("""
                        UPDATE documents
                        SET municipality = %s
                        WHERE municipality = %s
                    """, (fixed, mun))
                    
                    if cursor.rowcount > 0:
                        print(f"   ✅ Fixed '{mun}' → '{fixed}': {cursor.rowcount} records")
                        total_fixed += cursor.rowcount
        
        # Also check and fix any similar issues in titles
        print("\n3️⃣ Checking for date spacing issues in titles...")
        
        # Fix dates like "09 deMarçode 2000"
        cursor.execute("""
            UPDATE documents
            SET titulo = regexp_replace(
                regexp_replace(
                    titulo,
                    '(\d+)\s*de([A-Z][a-záêçõ]+)de\s*(\d+)',
                    '\1 de \2 de \3',
                    'g'
                ),
                '([a-z])de\s+',
                '\1 de ',
                'g'
            )
            WHERE titulo ~ '\d+\s*de[A-Z][a-záêçõ]+de\s*\d+'
        """)
        
        if cursor.rowcount > 0:
            print(f"   ✅ Fixed date spacing in titles: {cursor.rowcount} records")
        
        # Commit all changes
        conn.commit()
        
        print(f"\n✅ Total fixes applied: {total_fixed} municipality records")
        
        # Verify the fixes
        print("\n📊 Verification:")
        
        # Check PonteNova specifically
        cursor.execute("""
            SELECT COUNT(*) FROM documents WHERE municipality = 'PonteNova'
        """)
        pontenova_old = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT COUNT(*) FROM documents WHERE municipality = 'Ponte Nova'
        """)
        pontenova_new = cursor.fetchone()[0]
        
        print(f"   'PonteNova' remaining: {pontenova_old}")
        print(f"   'Ponte Nova' count: {pontenova_new}")
        
        # Show sample of fixed records
        print("\n📋 Sample of fixed records:")
        cursor.execute("""
            SELECT id, estado, municipality, titulo
            FROM documents 
            WHERE municipality = 'Ponte Nova'
            LIMIT 3
        """)
        samples = cursor.fetchall()
        for sample in samples:
            print(f"   ID {sample[0]}: Estado='{sample[1]}', Municipality='{sample[2]}'")
            print(f"      Title: {sample[3][:60]}...")
        
        # Check for any remaining potential issues
        print("\n🔍 Checking for remaining potential issues...")
        cursor.execute("""
            SELECT DISTINCT municipality, COUNT(*) as count
            FROM documents 
            WHERE municipality ~ '[a-z][A-Z]'
              AND municipality NOT LIKE '%ª Região%'
              AND municipality != ''
            GROUP BY municipality
            ORDER BY count DESC
        """)
        
        remaining = cursor.fetchall()
        if remaining:
            print(f"   Found {len(remaining)} potential remaining issues:")
            for mun, count in remaining[:5]:
                print(f"   '{mun}' ({count} records)")
        else:
            print("   ✅ No remaining camelCase issues found!")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    fix_municipality_spacing()