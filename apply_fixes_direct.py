#!/usr/bin/env python3
"""
Apply data fixes directly to Railway PostgreSQL database
"""

import psycopg2

DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"

def apply_fixes():
    """Apply fixes directly"""
    try:
        print("🔧 Applying data fixes to Railway PostgreSQL...")
        conn = psycopg2.connect(DATABASE_URL)
        cursor = conn.cursor()
        
        # Fix 1: Parse "PonteNova- MG" pattern
        print("\n1️⃣ Fixing municipality-state patterns...")
        cursor.execute("""
            UPDATE documents
            SET 
                municipality = TRIM(SUBSTRING(estado FROM '^(.+)-\\s*[A-Z]{2}$')),
                estado = TRIM(SUBSTRING(estado FROM '-\\s*([A-Z]{2})$'))
            WHERE estado ~ '^(.+)-\\s*[A-Z]{2}$'
              AND (municipality IS NULL OR municipality = '')
        """)
        print(f"   ✅ Fixed {cursor.rowcount} records")
        
        # Fix 2: Extract state from region names
        print("\n2️⃣ Extracting states from region names...")
        cursor.execute("""
            UPDATE documents
            SET 
                estado = CASE 
                    WHEN municipality LIKE '%Rio de Janeiro%' THEN 'RJ'
                    WHEN municipality LIKE '%Minas Gerais%' THEN 'MG'
                    WHEN municipality LIKE '%Maranhão%' THEN 'MA'
                    WHEN municipality LIKE '%Paraíba%' THEN 'PB'
                    WHEN municipality LIKE '%Pará%' THEN 'PA'
                    WHEN municipality LIKE '%Amapá%' THEN 'AP'
                    WHEN municipality LIKE '%Mato Grosso do Sul%' THEN 'MS'
                    WHEN municipality LIKE '%São Paulo%' THEN 'SP'
                    WHEN municipality LIKE '%Bahia%' THEN 'BA'
                    WHEN municipality LIKE '%Pernambuco%' THEN 'PE'
                    WHEN municipality LIKE '%Ceará%' THEN 'CE'
                    WHEN municipality LIKE '%Rio Grande do Sul%' THEN 'RS'
                    WHEN municipality LIKE '%Paraná%' THEN 'PR'
                    WHEN municipality LIKE '%Santa Catarina%' THEN 'SC'
                    WHEN municipality LIKE '%Goiás%' THEN 'GO'
                    WHEN municipality LIKE '%Distrito Federal%' THEN 'DF'
                    WHEN municipality LIKE '%Espírito Santo%' THEN 'ES'
                    WHEN municipality LIKE '%Rio Grande do Norte%' THEN 'RN'
                    WHEN municipality LIKE '%Alagoas%' THEN 'AL'
                    WHEN municipality LIKE '%Sergipe%' THEN 'SE'
                    WHEN municipality LIKE '%Rondônia%' THEN 'RO'
                    WHEN municipality LIKE '%Acre%' THEN 'AC'
                    WHEN municipality LIKE '%Amazonas%' THEN 'AM'
                    WHEN municipality LIKE '%Roraima%' THEN 'RR'
                    WHEN municipality LIKE '%Tocantins%' THEN 'TO'
                    WHEN municipality LIKE '%Mato Grosso%' AND municipality NOT LIKE '%Sul%' THEN 'MT'
                    WHEN municipality LIKE '%Piauí%' THEN 'PI'
                    ELSE estado
                END,
                metadata = jsonb_set(
                    COALESCE(metadata, '{}'::jsonb),
                    '{tribunal_region}',
                    to_jsonb(municipality)
                )
            WHERE municipality ~ '\\d+ª Região'
              AND (estado IS NULL OR estado = '')
        """)
        print(f"   ✅ Updated {cursor.rowcount} records")
        
        # Fix 3: Clear municipality for region entries
        print("\n3️⃣ Clearing municipality field for region entries...")
        cursor.execute("""
            UPDATE documents
            SET municipality = ''
            WHERE municipality ~ '\\d+ª Região'
        """)
        print(f"   ✅ Cleared {cursor.rowcount} records")
        
        # Fix 4: Infer states from URLs and titles
        print("\n4️⃣ Inferring states from URLs and titles...")
        cursor.execute("""
            UPDATE documents
            SET estado = CASE 
                WHEN url LIKE '%sp.%' OR titulo LIKE '%São Paulo%' THEN 'SP'
                WHEN url LIKE '%rj.%' OR titulo LIKE '%Rio de Janeiro%' THEN 'RJ'
                WHEN url LIKE '%mg.%' OR titulo LIKE '%Minas Gerais%' THEN 'MG'
                WHEN url LIKE '%rs.%' OR titulo LIKE '%Rio Grande do Sul%' THEN 'RS'
                WHEN url LIKE '%pr.%' OR titulo LIKE '%Paraná%' THEN 'PR'
                WHEN url LIKE '%sc.%' OR titulo LIKE '%Santa Catarina%' THEN 'SC'
                WHEN url LIKE '%ba.%' OR titulo LIKE '%Bahia%' THEN 'BA'
                WHEN url LIKE '%pe.%' OR titulo LIKE '%Pernambuco%' THEN 'PE'
                WHEN url LIKE '%ce.%' OR titulo LIKE '%Ceará%' THEN 'CE'
                WHEN url LIKE '%go.%' OR titulo LIKE '%Goiás%' THEN 'GO'
                WHEN url LIKE '%df.%' OR titulo LIKE '%Distrito Federal%' OR titulo LIKE '%Brasília%' THEN 'DF'
                WHEN url LIKE '%es.%' OR titulo LIKE '%Espírito Santo%' THEN 'ES'
                WHEN url LIKE '%ma.%' OR titulo LIKE '%Maranhão%' THEN 'MA'
                WHEN url LIKE '%pb.%' OR titulo LIKE '%Paraíba%' THEN 'PB'
                WHEN url LIKE '%pa.%' OR titulo LIKE '%Pará%' THEN 'PA'
                WHEN url LIKE '%ap.%' OR titulo LIKE '%Amapá%' THEN 'AP'
                WHEN url LIKE '%ms.%' OR titulo LIKE '%Mato Grosso do Sul%' THEN 'MS'
                WHEN url LIKE '%mt.%' OR titulo LIKE '%Mato Grosso%' AND titulo NOT LIKE '%Sul%' THEN 'MT'
                WHEN url LIKE '%rn.%' OR titulo LIKE '%Rio Grande do Norte%' THEN 'RN'
                WHEN url LIKE '%al.%' OR titulo LIKE '%Alagoas%' THEN 'AL'
                WHEN url LIKE '%se.%' OR titulo LIKE '%Sergipe%' THEN 'SE'
                WHEN url LIKE '%ro.%' OR titulo LIKE '%Rondônia%' THEN 'RO'
                WHEN url LIKE '%ac.%' OR titulo LIKE '%Acre%' THEN 'AC'
                WHEN url LIKE '%am.%' OR titulo LIKE '%Amazonas%' THEN 'AM'
                WHEN url LIKE '%rr.%' OR titulo LIKE '%Roraima%' THEN 'RR'
                WHEN url LIKE '%to.%' OR titulo LIKE '%Tocantins%' THEN 'TO'
                WHEN url LIKE '%pi.%' OR titulo LIKE '%Piauí%' THEN 'PI'
                ELSE estado
            END
            WHERE estado IS NULL OR estado = ''
        """)
        print(f"   ✅ Updated {cursor.rowcount} records")
        
        # Commit changes
        conn.commit()
        print("\n✅ All fixes applied successfully!")
        
        # Show statistics
        print("\n📊 Final Database Statistics:")
        
        cursor.execute("SELECT COUNT(*) FROM documents")
        total = cursor.fetchone()[0]
        print(f"   Total documents: {total}")
        
        cursor.execute("SELECT COUNT(*) FROM documents WHERE estado IS NOT NULL AND estado != '' AND estado !~ '-'")
        good_estado = cursor.fetchone()[0]
        print(f"   Documents with clean estado: {good_estado}")
        
        cursor.execute("SELECT COUNT(*) FROM documents WHERE municipality IS NOT NULL AND municipality != ''")
        with_municipality = cursor.fetchone()[0]
        print(f"   Documents with municipality: {with_municipality}")
        
        cursor.execute("SELECT COUNT(*) FROM documents WHERE estado LIKE '%-%'")
        problematic = cursor.fetchone()[0]
        print(f"   Remaining problematic estados: {problematic}")
        
        # Show samples
        print("\n📋 Sample of fixed PonteNova records:")
        cursor.execute("""
            SELECT id, estado, municipality, titulo
            FROM documents 
            WHERE municipality = 'PonteNova'
            LIMIT 3
        """)
        samples = cursor.fetchall()
        for sample in samples:
            print(f"   ID {sample[0]}: Estado='{sample[1]}', Municipality='{sample[2]}'")
            print(f"      Title: {sample[3][:60]}...")
        
        print("\n📋 Sample of records with inferred states:")
        cursor.execute("""
            SELECT id, estado, municipality, tipo, titulo
            FROM documents 
            WHERE estado IN ('RJ', 'MG', 'SP', 'MA', 'PB', 'PA')
              AND tipo = 'jurisprudence'
            LIMIT 5
        """)
        samples = cursor.fetchall()
        for sample in samples:
            print(f"   ID {sample[0]}: Estado='{sample[1]}', Municipality='{sample[2]}', Tipo='{sample[3]}'")
            print(f"      Title: {sample[4][:60]}...")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    apply_fixes()