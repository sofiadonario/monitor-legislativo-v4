-- Fix States, Municipalities, and URL/Summary Display Issues
-- Properly extract states and municipalities from locality field

-- First, let's check what we have
SELECT 'Current data overview' as status;
SELECT 
    COUNT(*) as total_docs,
    COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) as with_url,
    COUNT(CASE WHEN conteudo IS NOT NULL AND conteudo != '' THEN 1 END) as with_summary,
    COUNT(CASE WHEN estado = 'Brasil' THEN 1 END) as brasil_only,
    COUNT(CASE WHEN estado != 'Brasil' AND estado IS NOT NULL THEN 1 END) as with_proper_state
FROM documents;

-- Show sample localities to understand patterns
SELECT 'Sample localities' as status;
SELECT DISTINCT locality, COUNT(*) as count 
FROM documents 
WHERE locality IS NOT NULL AND locality != 'Brasil' 
GROUP BY locality 
ORDER BY count DESC 
LIMIT 15;

-- Now fix the state and municipality extraction with proper logic
UPDATE documents SET
    -- Extract state from locality field with comprehensive mapping
    estado = CASE
        -- Direct state names
        WHEN locality LIKE '%Acre%' THEN 'Acre'
        WHEN locality LIKE '%Alagoas%' THEN 'Alagoas'
        WHEN locality LIKE '%Amapá%' OR locality LIKE '%Amapa%' THEN 'Amapá'
        WHEN locality LIKE '%Amazonas%' THEN 'Amazonas'
        WHEN locality LIKE '%Bahia%' THEN 'Bahia'
        WHEN locality LIKE '%Ceará%' OR locality LIKE '%Ceara%' THEN 'Ceará'
        WHEN locality LIKE '%Distrito Federal%' THEN 'Distrito Federal'
        WHEN locality LIKE '%Espírito Santo%' OR locality LIKE '%Espirito Santo%' THEN 'Espírito Santo'
        WHEN locality LIKE '%Goiás%' OR locality LIKE '%Goias%' THEN 'Goiás'
        WHEN locality LIKE '%Maranhão%' OR locality LIKE '%Maranhao%' THEN 'Maranhão'
        WHEN locality LIKE '%Mato Grosso do Sul%' THEN 'Mato Grosso do Sul'
        WHEN locality LIKE '%Mato Grosso%' THEN 'Mato Grosso'
        WHEN locality LIKE '%Minas Gerais%' THEN 'Minas Gerais'
        WHEN locality LIKE '%Pará%' OR locality LIKE '%Para%' THEN 'Pará'
        WHEN locality LIKE '%Paraíba%' OR locality LIKE '%Paraiba%' THEN 'Paraíba'
        WHEN locality LIKE '%Paraná%' OR locality LIKE '%Parana%' THEN 'Paraná'
        WHEN locality LIKE '%Pernambuco%' THEN 'Pernambuco'
        WHEN locality LIKE '%Piauí%' OR locality LIKE '%Piaui%' THEN 'Piauí'
        WHEN locality LIKE '%Rio de Janeiro%' THEN 'Rio de Janeiro'
        WHEN locality LIKE '%Rio Grande do Norte%' THEN 'Rio Grande do Norte'
        WHEN locality LIKE '%Rio Grande do Sul%' THEN 'Rio Grande do Sul'
        WHEN locality LIKE '%Rondônia%' OR locality LIKE '%Rondonia%' THEN 'Rondônia'
        WHEN locality LIKE '%Roraima%' THEN 'Roraima'
        WHEN locality LIKE '%Santa Catarina%' THEN 'Santa Catarina'
        WHEN locality LIKE '%São Paulo%' OR locality LIKE '%Sao Paulo%' THEN 'São Paulo'
        WHEN locality LIKE '%Sergipe%' THEN 'Sergipe'
        WHEN locality LIKE '%Tocantins%' THEN 'Tocantins'
        
        -- State abbreviations
        WHEN locality LIKE '% - AC%' OR locality LIKE '%AC %' THEN 'Acre'
        WHEN locality LIKE '% - AL%' OR locality LIKE '%AL %' THEN 'Alagoas'
        WHEN locality LIKE '% - AP%' OR locality LIKE '%AP %' THEN 'Amapá'
        WHEN locality LIKE '% - AM%' OR locality LIKE '%AM %' THEN 'Amazonas'
        WHEN locality LIKE '% - BA%' OR locality LIKE '%BA %' THEN 'Bahia'
        WHEN locality LIKE '% - CE%' OR locality LIKE '%CE %' THEN 'Ceará'
        WHEN locality LIKE '% - DF%' OR locality LIKE '%DF %' THEN 'Distrito Federal'
        WHEN locality LIKE '% - ES%' OR locality LIKE '%ES %' THEN 'Espírito Santo'
        WHEN locality LIKE '% - GO%' OR locality LIKE '%GO %' THEN 'Goiás'
        WHEN locality LIKE '% - MA%' OR locality LIKE '%MA %' THEN 'Maranhão'
        WHEN locality LIKE '% - MS%' OR locality LIKE '%MS %' THEN 'Mato Grosso do Sul'
        WHEN locality LIKE '% - MT%' OR locality LIKE '%MT %' THEN 'Mato Grosso'
        WHEN locality LIKE '% - MG%' OR locality LIKE '%MG %' THEN 'Minas Gerais'
        WHEN locality LIKE '% - PA%' OR locality LIKE '%PA %' THEN 'Pará'
        WHEN locality LIKE '% - PB%' OR locality LIKE '%PB %' THEN 'Paraíba'
        WHEN locality LIKE '% - PR%' OR locality LIKE '%PR %' THEN 'Paraná'
        WHEN locality LIKE '% - PE%' OR locality LIKE '%PE %' THEN 'Pernambuco'
        WHEN locality LIKE '% - PI%' OR locality LIKE '%PI %' THEN 'Piauí'
        WHEN locality LIKE '% - RJ%' OR locality LIKE '%RJ %' THEN 'Rio de Janeiro'
        WHEN locality LIKE '% - RN%' OR locality LIKE '%RN %' THEN 'Rio Grande do Norte'
        WHEN locality LIKE '% - RS%' OR locality LIKE '%RS %' THEN 'Rio Grande do Sul'
        WHEN locality LIKE '% - RO%' OR locality LIKE '%RO %' THEN 'Rondônia'
        WHEN locality LIKE '% - RR%' OR locality LIKE '%RR %' THEN 'Roraima'
        WHEN locality LIKE '% - SC%' OR locality LIKE '%SC %' THEN 'Santa Catarina'
        WHEN locality LIKE '% - SP%' OR locality LIKE '%SP %' THEN 'São Paulo'
        WHEN locality LIKE '% - SE%' OR locality LIKE '%SE %' THEN 'Sergipe'
        WHEN locality LIKE '% - TO%' OR locality LIKE '%TO %' THEN 'Tocantins'
        
        -- Regional courts with state mappings
        WHEN locality LIKE '%1ª Região%' THEN 'Rio de Janeiro'
        WHEN locality LIKE '%2ª Região%' THEN 'São Paulo'
        WHEN locality LIKE '%3ª Região%' THEN 'Minas Gerais'
        WHEN locality LIKE '%4ª Região%' THEN 'Rio Grande do Sul'
        WHEN locality LIKE '%5ª Região%' THEN 'Bahia'
        WHEN locality LIKE '%6ª Região%' THEN 'Pernambuco'
        WHEN locality LIKE '%7ª Região%' THEN 'Ceará'
        WHEN locality LIKE '%8ª Região%' THEN 'Pará'
        WHEN locality LIKE '%9ª Região%' THEN 'Paraná'
        WHEN locality LIKE '%10ª Região%' THEN 'Distrito Federal'
        WHEN locality LIKE '%11ª Região%' THEN 'Amazonas'
        WHEN locality LIKE '%12ª Região%' THEN 'Santa Catarina'
        WHEN locality LIKE '%13ª Região%' THEN 'Paraíba'
        WHEN locality LIKE '%14ª Região%' THEN 'Rondônia'
        WHEN locality LIKE '%15ª Região%' THEN 'São Paulo'
        WHEN locality LIKE '%16ª Região%' THEN 'Maranhão'
        WHEN locality LIKE '%17ª Região%' THEN 'Espírito Santo'
        WHEN locality LIKE '%18ª Região%' THEN 'Goiás'
        WHEN locality LIKE '%19ª Região%' THEN 'Alagoas'
        WHEN locality LIKE '%20ª Região%' THEN 'Sergipe'
        WHEN locality LIKE '%21ª Região%' THEN 'Rio Grande do Norte'
        WHEN locality LIKE '%22ª Região%' THEN 'Piauí'
        WHEN locality LIKE '%23ª Região%' THEN 'Mato Grosso'
        WHEN locality LIKE '%24ª Região%' THEN 'Mato Grosso do Sul'
        
        ELSE 'Federal'
    END,
    
    -- Extract municipality from locality field
    municipality = CASE
        WHEN locality LIKE '%-%' AND locality NOT LIKE '%Região%' THEN
            TRIM(SPLIT_PART(locality, '-', 1))
        ELSE NULL
    END

WHERE locality IS NOT NULL;

-- Also extract from URN patterns for additional coverage
UPDATE documents SET
    estado = CASE
        WHEN estado = 'Federal' AND urn LIKE '%acre%' THEN 'Acre'
        WHEN estado = 'Federal' AND urn LIKE '%alagoas%' THEN 'Alagoas'
        WHEN estado = 'Federal' AND urn LIKE '%amapa%' THEN 'Amapá'
        WHEN estado = 'Federal' AND urn LIKE '%amazonas%' THEN 'Amazonas'
        WHEN estado = 'Federal' AND urn LIKE '%bahia%' THEN 'Bahia'
        WHEN estado = 'Federal' AND urn LIKE '%ceara%' THEN 'Ceará'
        WHEN estado = 'Federal' AND urn LIKE '%distrito.federal%' THEN 'Distrito Federal'
        WHEN estado = 'Federal' AND urn LIKE '%espirito.santo%' THEN 'Espírito Santo'
        WHEN estado = 'Federal' AND urn LIKE '%goias%' THEN 'Goiás'
        WHEN estado = 'Federal' AND urn LIKE '%maranhao%' THEN 'Maranhão'
        WHEN estado = 'Federal' AND urn LIKE '%mato.grosso.sul%' THEN 'Mato Grosso do Sul'
        WHEN estado = 'Federal' AND urn LIKE '%mato.grosso%' THEN 'Mato Grosso'
        WHEN estado = 'Federal' AND urn LIKE '%minas.gerais%' THEN 'Minas Gerais'
        WHEN estado = 'Federal' AND urn LIKE '%para%' THEN 'Pará'
        WHEN estado = 'Federal' AND urn LIKE '%paraiba%' THEN 'Paraíba'
        WHEN estado = 'Federal' AND urn LIKE '%parana%' THEN 'Paraná'
        WHEN estado = 'Federal' AND urn LIKE '%pernambuco%' THEN 'Pernambuco'
        WHEN estado = 'Federal' AND urn LIKE '%piaui%' THEN 'Piauí'
        WHEN estado = 'Federal' AND urn LIKE '%rio.de.janeiro%' THEN 'Rio de Janeiro'
        WHEN estado = 'Federal' AND urn LIKE '%rio.grande.norte%' THEN 'Rio Grande do Norte'
        WHEN estado = 'Federal' AND urn LIKE '%rio.grande.sul%' THEN 'Rio Grande do Sul'
        WHEN estado = 'Federal' AND urn LIKE '%rondonia%' THEN 'Rondônia'
        WHEN estado = 'Federal' AND urn LIKE '%roraima%' THEN 'Roraima'
        WHEN estado = 'Federal' AND urn LIKE '%santa.catarina%' THEN 'Santa Catarina'
        WHEN estado = 'Federal' AND urn LIKE '%sao.paulo%' THEN 'São Paulo'
        WHEN estado = 'Federal' AND urn LIKE '%sergipe%' THEN 'Sergipe'
        WHEN estado = 'Federal' AND urn LIKE '%tocantins%' THEN 'Tocantins'
        ELSE estado
    END;

-- Extract municipality from URN for municipal documents
UPDATE documents SET
    municipality = CASE
        WHEN municipality IS NULL AND urn LIKE '%;municipal:%' THEN
            -- Extract municipality from URN pattern like urn:lex:br;state;municipality:municipal:
            UPPER(SUBSTRING(
                SPLIT_PART(SPLIT_PART(urn, ';', 3), ':', 1)
            ))
        ELSE municipality
    END;

-- Ensure URL column is properly mapped for R Shiny access
-- The URL should already be there, but let's make sure it's accessible
SELECT 'URL Status Check' as status;
SELECT 
    COUNT(*) as total_docs,
    COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) as with_url,
    COUNT(CASE WHEN url LIKE 'https://www.lexml.gov.br%' THEN 1 END) as valid_lexml_urls
FROM documents;

-- Ensure document summary (ementa) is in the conteudo field for R Shiny
UPDATE documents SET
    conteudo = COALESCE(document_summary, conteudo)
WHERE conteudo IS NULL OR conteudo = '';

-- Final comprehensive verification
SELECT 'FINAL RESULTS AFTER STATE/MUNICIPALITY FIX' as status;

-- State distribution
SELECT 'State distribution' as metric;
SELECT 
    estado,
    COUNT(*) as documents
FROM documents 
GROUP BY estado 
ORDER BY documents DESC 
LIMIT 15;

-- Municipality coverage
SELECT 'Municipality coverage' as metric;
SELECT 
    COUNT(CASE WHEN municipality IS NOT NULL AND municipality != '' THEN 1 END) as with_municipality,
    COUNT(*) as total,
    ROUND(COUNT(CASE WHEN municipality IS NOT NULL AND municipality != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

-- Sample municipalities
SELECT 'Sample municipalities' as metric;
SELECT municipality, estado, COUNT(*) as count
FROM documents 
WHERE municipality IS NOT NULL AND municipality != ''
GROUP BY municipality, estado
ORDER BY count DESC
LIMIT 10;

-- Data completeness summary
SELECT 'Data completeness summary' as metric;
SELECT 
    'URLs' as field,
    COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) as filled,
    ROUND(COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents
UNION ALL
SELECT 
    'Document Summaries' as field,
    COUNT(CASE WHEN conteudo IS NOT NULL AND conteudo != '' THEN 1 END) as filled,
    ROUND(COUNT(CASE WHEN conteudo IS NOT NULL AND conteudo != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents
UNION ALL
SELECT 
    'States (Non-Federal)' as field,
    COUNT(CASE WHEN estado != 'Federal' AND estado IS NOT NULL THEN 1 END) as filled,
    ROUND(COUNT(CASE WHEN estado != 'Federal' AND estado IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

COMMIT;