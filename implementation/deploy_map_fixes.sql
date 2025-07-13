-- Complete Map Rendering Fix Deployment Script
-- This script applies all fixes needed to resolve the map rendering issue

BEGIN;

-- Step 1: Apply state standardization
\echo 'Step 1: Applying state standardization...'

-- Add estado_codigo column if it doesn't exist
ALTER TABLE documents 
ADD COLUMN IF NOT EXISTS estado_codigo TEXT;

-- Standardize all state codes
UPDATE documents SET estado_codigo = CASE
    WHEN estado = 'Acre' THEN 'AC'
    WHEN estado = 'Alagoas' THEN 'AL'
    WHEN estado = 'Amapá' THEN 'AP'
    WHEN estado = 'Amazonas' THEN 'AM'
    WHEN estado = 'Bahia' THEN 'BA'
    WHEN estado = 'Ceará' THEN 'CE'
    WHEN estado = 'Distrito Federal' THEN 'DF'
    WHEN estado = 'Espírito Santo' THEN 'ES'
    WHEN estado = 'Goiás' THEN 'GO'
    WHEN estado = 'Maranhão' THEN 'MA'
    WHEN estado = 'Mato Grosso' THEN 'MT'
    WHEN estado = 'Mato Grosso do Sul' THEN 'MS'
    WHEN estado = 'Minas Gerais' THEN 'MG'
    WHEN estado = 'Pará' THEN 'PA'
    WHEN estado = 'Paraíba' THEN 'PB'
    WHEN estado = 'Paraná' THEN 'PR'
    WHEN estado = 'Pernambuco' THEN 'PE'
    WHEN estado = 'Piauí' THEN 'PI'
    WHEN estado = 'Rio de Janeiro' THEN 'RJ'
    WHEN estado = 'Rio Grande do Norte' THEN 'RN'
    WHEN estado = 'Rio Grande do Sul' THEN 'RS'
    WHEN estado = 'Rondônia' THEN 'RO'
    WHEN estado = 'Roraima' THEN 'RR'
    WHEN estado = 'Santa Catarina' THEN 'SC'
    WHEN estado = 'São Paulo' THEN 'SP'
    WHEN estado = 'Sergipe' THEN 'SE'
    WHEN estado = 'Tocantins' THEN 'TO'
    WHEN estado IN ('AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
                    'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
                    'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO') THEN estado
    WHEN estado LIKE '%São Paulo%' OR estado LIKE '%Sao Paulo%' THEN 'SP'
    WHEN estado LIKE '%Rio de Janeiro%' OR estado LIKE '%Rio.Janeiro%' THEN 'RJ'
    WHEN estado LIKE '%Minas Gerais%' THEN 'MG'
    WHEN estado LIKE '%Rio Grande do Sul%' OR estado LIKE '%Rio.Grande.Sul%' THEN 'RS'
    WHEN estado LIKE '%Rio Grande do Norte%' OR estado LIKE '%Rio.Grande.Norte%' THEN 'RN'
    WHEN estado LIKE '%Mato Grosso do Sul%' OR estado LIKE '%Mato.Grosso.Sul%' THEN 'MS'
    WHEN estado LIKE '%Mato Grosso%' THEN 'MT'
    WHEN estado LIKE '%Santa Catarina%' THEN 'SC'
    WHEN estado LIKE '%Espírito Santo%' OR estado LIKE '%Espirito Santo%' THEN 'ES'
    WHEN estado LIKE '%Distrito Federal%' THEN 'DF'
    WHEN estado IN ('Federal', 'Brasil', 'BR', 'Brazil') THEN 'BR'
    ELSE estado
END
WHERE estado IS NOT NULL;

-- Standardize estado field to use consistent full names
UPDATE documents SET estado = CASE
    WHEN estado_codigo = 'AC' THEN 'Acre'
    WHEN estado_codigo = 'AL' THEN 'Alagoas'
    WHEN estado_codigo = 'AP' THEN 'Amapá'
    WHEN estado_codigo = 'AM' THEN 'Amazonas'
    WHEN estado_codigo = 'BA' THEN 'Bahia'
    WHEN estado_codigo = 'CE' THEN 'Ceará'
    WHEN estado_codigo = 'DF' THEN 'Distrito Federal'
    WHEN estado_codigo = 'ES' THEN 'Espírito Santo'
    WHEN estado_codigo = 'GO' THEN 'Goiás'
    WHEN estado_codigo = 'MA' THEN 'Maranhão'
    WHEN estado_codigo = 'MT' THEN 'Mato Grosso'
    WHEN estado_codigo = 'MS' THEN 'Mato Grosso do Sul'
    WHEN estado_codigo = 'MG' THEN 'Minas Gerais'
    WHEN estado_codigo = 'PA' THEN 'Pará'
    WHEN estado_codigo = 'PB' THEN 'Paraíba'
    WHEN estado_codigo = 'PR' THEN 'Paraná'
    WHEN estado_codigo = 'PE' THEN 'Pernambuco'
    WHEN estado_codigo = 'PI' THEN 'Piauí'
    WHEN estado_codigo = 'RJ' THEN 'Rio de Janeiro'
    WHEN estado_codigo = 'RN' THEN 'Rio Grande do Norte'
    WHEN estado_codigo = 'RS' THEN 'Rio Grande do Sul'
    WHEN estado_codigo = 'RO' THEN 'Rondônia'
    WHEN estado_codigo = 'RR' THEN 'Roraima'
    WHEN estado_codigo = 'SC' THEN 'Santa Catarina'
    WHEN estado_codigo = 'SP' THEN 'São Paulo'
    WHEN estado_codigo = 'SE' THEN 'Sergipe'
    WHEN estado_codigo = 'TO' THEN 'Tocantins'
    WHEN estado_codigo = 'BR' THEN 'Federal'
    ELSE estado
END
WHERE estado_codigo IS NOT NULL;

-- Step 2: Update legislative_data table for consistency
\echo 'Step 2: Updating legislative_data table...'

-- Clear and repopulate legislative_data with corrected data
DELETE FROM legislative_data;

INSERT INTO legislative_data (
    titulo, numero, tipo, data, estado, autor, fonte_original, url, ano
)
SELECT 
    titulo as titulo,
    NULL as numero,
    tipo as tipo,
    data_publicacao::date as data,
    estado as estado,
    autor as autor,
    'LexML' as fonte_original,
    url as url,
    EXTRACT(YEAR FROM data_publicacao) as ano
FROM documents 
WHERE titulo IS NOT NULL;

-- Step 3: Add cache-busting metadata for app refresh
\echo 'Step 3: Adding cache-busting metadata...'

UPDATE documents SET 
    updated_at = CURRENT_TIMESTAMP,
    metadata = metadata || jsonb_build_object(
        'map_fix_applied', CURRENT_TIMESTAMP::text,
        'estado_codigo_standardized', TRUE,
        'data_version', 'v3_map_fix'
    )
WHERE id <= 100;  -- Update first 100 records to trigger refresh

-- Step 4: Verification queries
\echo 'Step 4: Running verification queries...'

-- Check state standardization results
SELECT 'STATE STANDARDIZATION RESULTS' as status;
SELECT 
    COUNT(*) as total_documents,
    COUNT(CASE WHEN estado_codigo IS NOT NULL THEN 1 END) as with_estado_codigo,
    ROUND(COUNT(CASE WHEN estado_codigo IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as coverage
FROM documents;

-- Show state distribution for map
SELECT 'STATES AVAILABLE FOR MAP' as status;
SELECT 
    estado_codigo,
    estado,
    COUNT(*) as document_count
FROM documents 
WHERE estado_codigo IS NOT NULL 
  AND estado_codigo != 'BR'
GROUP BY estado_codigo, estado 
ORDER BY document_count DESC
LIMIT 15;

-- Check data quality for mapping
SELECT 'DATA QUALITY FOR MAPPING' as status;
SELECT 
    COUNT(*) as mappable_documents
FROM documents 
WHERE estado_codigo IS NOT NULL 
  AND estado_codigo != ''
  AND estado_codigo != 'BR'
  AND titulo IS NOT NULL 
  AND titulo != '';

-- Show total by state codes (what the map will display)
SELECT 'MAP WILL SHOW THESE STATE COUNTS' as status;
SELECT 
    estado_codigo as state_code,
    COUNT(*) as documents
FROM documents 
WHERE estado_codigo IS NOT NULL 
  AND estado_codigo != ''
  AND estado_codigo != 'BR'
GROUP BY estado_codigo 
ORDER BY documents DESC;

COMMIT;

\echo 'Map rendering fixes applied successfully!'
\echo 'The R Shiny application should now display the interactive map correctly.'