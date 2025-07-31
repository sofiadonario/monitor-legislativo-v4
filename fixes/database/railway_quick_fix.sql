-- Quick Railway Database Fix
-- Add estado_codigo column and standardize states to get all 27 Brazilian states

-- Step 1: Add estado_codigo column
ALTER TABLE documents ADD COLUMN IF NOT EXISTS estado_codigo TEXT;

-- Step 2: Standardize all state codes
UPDATE documents SET estado_codigo = CASE
    -- Standard full state names to codes
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
    
    -- Handle existing abbreviations
    WHEN estado IN ('AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
                    'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
                    'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO') THEN estado
                    
    -- Handle Federal/National level
    WHEN estado IN ('Federal', 'Brasil', 'BR', 'Brazil') THEN 'BR'
    
    -- Default: use estado as is
    ELSE estado
END
WHERE estado IS NOT NULL;

-- Step 3: Update estado field to use standardized full names
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

-- Step 4: Verification - show all states (should have 27 + Federal)
SELECT 'Final state distribution:' as status;
SELECT 
    estado_codigo,
    estado,
    COUNT(*) as document_count
FROM documents 
WHERE estado_codigo IS NOT NULL 
GROUP BY estado_codigo, estado 
ORDER BY document_count DESC;