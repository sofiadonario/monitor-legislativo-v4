-- Fix municipality extraction from URN patterns
-- Complete the municipality extraction that had a SQL syntax error

-- Extract municipality from URN for municipal documents (fixed syntax)
UPDATE documents SET
    municipality = CASE
        WHEN municipality IS NULL AND urn LIKE '%;municipal:%' THEN
            -- Extract municipality from URN pattern like urn:lex:br;state;municipality:municipal:
            UPPER(SPLIT_PART(SPLIT_PART(urn, ';', 3), ':', 1))
        ELSE municipality
    END;

-- Additional municipality extraction from locality patterns we might have missed
UPDATE documents SET
    municipality = CASE
        WHEN municipality IS NULL AND locality LIKE '%-%' AND locality NOT LIKE '%Região%' THEN
            TRIM(SPLIT_PART(locality, '-', 1))
        ELSE municipality
    END;

-- Clean up municipality names (remove common suffixes and normalize)
UPDATE documents SET
    municipality = CASE
        WHEN municipality LIKE '%.%' THEN REPLACE(municipality, '.', ' ')
        ELSE municipality
    END
WHERE municipality IS NOT NULL;

-- Capitalize municipality names properly
UPDATE documents SET
    municipality = INITCAP(municipality)
WHERE municipality IS NOT NULL;

-- Final verification
SELECT 'MUNICIPALITY EXTRACTION RESULTS' as status;

SELECT 
    'Municipality coverage after fix' as metric,
    COUNT(CASE WHEN municipality IS NOT NULL AND municipality != '' THEN 1 END) as with_municipality,
    COUNT(*) as total,
    ROUND(COUNT(CASE WHEN municipality IS NOT NULL AND municipality != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

-- Top municipalities
SELECT 'Top municipalities by state' as status;
SELECT municipality, estado, COUNT(*) as count
FROM documents 
WHERE municipality IS NOT NULL AND municipality != ''
GROUP BY municipality, estado
ORDER BY count DESC
LIMIT 15;

-- State distribution verification (should show Amazonas and others)
SELECT 'State distribution verification' as status;
SELECT estado, COUNT(*) as documents
FROM documents 
WHERE estado != 'Federal'
GROUP BY estado 
ORDER BY documents DESC;

COMMIT;