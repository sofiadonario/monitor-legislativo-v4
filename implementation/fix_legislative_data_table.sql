-- Update legislative_data table with corrected documents data
-- This table seems to be what the R Shiny app actually uses for some queries

-- First check current structure
SELECT 'LEGISLATIVE_DATA TABLE CURRENT STATE' as status;
SELECT COUNT(*) as total_records FROM legislative_data;
SELECT estado, COUNT(*) as count FROM legislative_data GROUP BY estado ORDER BY count DESC LIMIT 10;

-- Clear the old data
DELETE FROM legislative_data;

-- Insert corrected data from documents table into legislative_data table format
INSERT INTO legislative_data (
    titulo, numero, tipo, data, estado, autor, fonte_original, url, ano
)
SELECT 
    titulo as titulo,
    NULL as numero,  -- extract from title if needed
    tipo as tipo,
    data_publicacao::date as data,
    estado as estado,
    autor as autor,
    'LexML' as fonte_original,
    url as url,
    EXTRACT(YEAR FROM data_publicacao) as ano
FROM documents 
WHERE titulo IS NOT NULL;

-- Verify the update
SELECT 'LEGISLATIVE_DATA TABLE AFTER UPDATE' as status;
SELECT COUNT(*) as total_records FROM legislative_data;

-- Check state distribution (should show Amazonas with documents)
SELECT 'State distribution in legislative_data' as metric;
SELECT estado, COUNT(*) as count 
FROM legislative_data 
WHERE estado NOT IN ('Federal', 'BR', '')
  AND estado IS NOT NULL
GROUP BY estado 
ORDER BY count DESC 
LIMIT 15;

-- Check if Amazonas data is there
SELECT 'Amazonas data in legislative_data' as metric;
SELECT titulo, estado, url, data
FROM legislative_data 
WHERE estado = 'Amazonas'
ORDER BY data DESC;

-- Check URL availability
SELECT 'URL availability in legislative_data' as metric;
SELECT 
    COUNT(*) as total,
    COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) as with_url,
    ROUND(COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM legislative_data;

COMMIT;