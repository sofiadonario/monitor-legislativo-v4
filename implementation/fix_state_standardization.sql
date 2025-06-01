-- Fix State Standardization for Map Rendering
-- This script standardizes all state names to ensure proper map rendering

-- Add standardized state code column if it doesn't exist
ALTER TABLE documents 
ADD COLUMN IF NOT EXISTS estado_codigo TEXT;

-- Create comprehensive state mapping
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
    
    -- Handle abbreviated codes (if already present)
    WHEN estado IN ('AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
                    'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
                    'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO') THEN estado
    
    -- Handle variations and formatting issues
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
    
    -- Federal/National level
    WHEN estado IN ('Federal', 'Brasil', 'BR', 'Brazil') THEN 'BR'
    
    -- Default: keep original if no match
    ELSE estado
END
WHERE estado IS NOT NULL;

-- Also update estado field to use standardized full names for consistency
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

-- Update legislative_data table to match
UPDATE legislative_data SET estado = CASE
    WHEN estado = 'AC' THEN 'Acre'
    WHEN estado = 'AL' THEN 'Alagoas'
    WHEN estado = 'AP' THEN 'Amapá'
    WHEN estado = 'AM' THEN 'Amazonas'
    WHEN estado = 'BA' THEN 'Bahia'
    WHEN estado = 'CE' THEN 'Ceará'
    WHEN estado = 'DF' THEN 'Distrito Federal'
    WHEN estado = 'ES' THEN 'Espírito Santo'
    WHEN estado = 'GO' THEN 'Goiás'
    WHEN estado = 'MA' THEN 'Maranhão'
    WHEN estado = 'MT' THEN 'Mato Grosso'
    WHEN estado = 'MS' THEN 'Mato Grosso do Sul'
    WHEN estado = 'MG' THEN 'Minas Gerais'
    WHEN estado = 'PA' THEN 'Pará'
    WHEN estado = 'PB' THEN 'Paraíba'
    WHEN estado = 'PR' THEN 'Paraná'
    WHEN estado = 'PE' THEN 'Pernambuco'
    WHEN estado = 'PI' THEN 'Piauí'
    WHEN estado = 'RJ' THEN 'Rio de Janeiro'
    WHEN estado = 'RN' THEN 'Rio Grande do Norte'
    WHEN estado = 'RS' THEN 'Rio Grande do Sul'
    WHEN estado = 'RO' THEN 'Rondônia'
    WHEN estado = 'RR' THEN 'Roraima'
    WHEN estado = 'SC' THEN 'Santa Catarina'
    WHEN estado = 'SP' THEN 'São Paulo'
    WHEN estado = 'SE' THEN 'Sergipe'
    WHEN estado = 'TO' THEN 'Tocantins'
    WHEN estado IN ('Federal', 'Brasil', 'BR', 'Brazil') THEN 'Federal'
    ELSE estado
END
WHERE estado IS NOT NULL;

-- Verification queries
SELECT 'STATE STANDARDIZATION COMPLETE' as status;

-- Check state distribution after standardization
SELECT 'State distribution after standardization' as metric;
SELECT estado, estado_codigo, COUNT(*) as count 
FROM documents 
WHERE estado IS NOT NULL 
GROUP BY estado, estado_codigo 
ORDER BY count DESC;

-- Check for any unmapped states
SELECT 'Unmapped states (need attention)' as metric;
SELECT DISTINCT estado, estado_codigo
FROM documents 
WHERE estado IS NOT NULL 
  AND (estado_codigo IS NULL OR estado_codigo = estado);

-- Total document count by standardized states
SELECT 'Total documents by standardized state codes' as metric;
SELECT estado_codigo, COUNT(*) as document_count
FROM documents 
WHERE estado_codigo IS NOT NULL 
  AND estado_codigo != 'BR'
GROUP BY estado_codigo 
ORDER BY document_count DESC;

COMMIT;