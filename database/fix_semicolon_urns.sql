-- Fix estado classification for semicolon URNs
-- Part 1: Fix municipal laws from Rio Grande do Sul
UPDATE documents
SET estado = 'RS'
WHERE estado = 'Federal'
  AND urn LIKE 'urn:lex:br;rio.grande.sul;%:municipal:%';

-- Part 2: Classify Regional Labor Courts as special category
UPDATE documents
SET estado = 'Justiça Trabalho'
WHERE estado = 'Federal'
  AND urn LIKE 'urn:lex:br;justica.trabalho;regiao%';

-- Show results
SELECT 
    'Classification Results' as report,
    estado,
    COUNT(*) as count
FROM documents
WHERE urn LIKE 'urn:lex:br;rio.grande.sul;%:municipal:%'
   OR urn LIKE 'urn:lex:br;justica.trabalho;regiao%'
GROUP BY estado
ORDER BY count DESC;
