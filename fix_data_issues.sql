-- Fix data issues in Railway PostgreSQL database
-- This script fixes municipality/state parsing issues

-- 1. Fix "PonteNova- MG" pattern (municipality-state without proper spacing)
UPDATE documents
SET 
    municipality = TRIM(SUBSTRING(estado FROM '^(.+)-\s*[A-Z]{2}$')),
    estado = TRIM(SUBSTRING(estado FROM '-\s*([A-Z]{2})$'))
WHERE estado ~ '^(.+)-\s*[A-Z]{2}$'
  AND (municipality IS NULL OR municipality = '');

-- 2. Fix region data in municipality field for jurisprudence documents
-- These should have the state extracted from the region name
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
    -- Keep the region info but mark it properly in metadata
    metadata = jsonb_set(
        COALESCE(metadata, '{}'::jsonb),
        '{tribunal_region}',
        to_jsonb(municipality)
    )
WHERE municipality ~ '\d+ª Região'
  AND (estado IS NULL OR estado = '');

-- 3. Clear municipality field for region entries (they're not actual municipalities)
UPDATE documents
SET municipality = ''
WHERE municipality ~ '\d+ª Região';

-- 4. Fix any remaining empty states where we can infer from metadata
UPDATE documents
SET estado = COALESCE(
    metadata->>'state',
    CASE 
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
)
WHERE estado IS NULL OR estado = '';

-- 5. Update metadata to track the fixes applied
UPDATE documents
SET metadata = jsonb_set(
    COALESCE(metadata, '{}'::jsonb),
    '{data_fixes_applied}',
    '"2025-07-21_municipality_state_parsing"'
)
WHERE id IN (
    SELECT id FROM documents 
    WHERE estado ~ '^(.+)-\s*[A-Z]{2}$'
       OR municipality ~ '\d+ª Região'
       OR (estado IS NULL OR estado = '')
);

-- Show summary of fixes
SELECT 
    'Fixed municipality-state parsing' as fix_type,
    COUNT(*) as records_affected
FROM documents
WHERE metadata->>'data_fixes_applied' = '2025-07-21_municipality_state_parsing'

UNION ALL

SELECT 
    'Records with proper estado now' as fix_type,
    COUNT(*) as records_affected
FROM documents
WHERE estado IS NOT NULL AND estado != '' AND estado !~ '-'

UNION ALL

SELECT 
    'Records with municipality data' as fix_type,
    COUNT(*) as records_affected
FROM documents
WHERE municipality IS NOT NULL AND municipality != ''

UNION ALL

SELECT 
    'Remaining problematic estados' as fix_type,
    COUNT(*) as records_affected
FROM documents
WHERE estado LIKE '%-%';