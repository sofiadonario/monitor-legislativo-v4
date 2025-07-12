-- Force R Shiny App to Refresh Data
-- Add a timestamp to ensure app picks up changes

-- Update a metadata field to force cache invalidation
UPDATE documents SET 
    updated_at = CURRENT_TIMESTAMP,
    metadata = metadata || jsonb_build_object(
        'cache_buster', EXTRACT(EPOCH FROM CURRENT_TIMESTAMP),
        'last_refresh', CURRENT_TIMESTAMP::text,
        'data_version', 'v2_corrected_final'
    )
WHERE id <= 10;

-- Verify the changes that should be visible to R Shiny
SELECT 'R SHINY DATA VERIFICATION' as status;

-- States with documents (should show Amazonas with 3 docs)
SELECT 'States with documents' as metric;
SELECT estado, COUNT(*) as documents 
FROM documents 
WHERE estado NOT IN ('Federal', 'Brasil', '')
  AND estado IS NOT NULL
GROUP BY estado 
ORDER BY documents DESC
LIMIT 10;

-- URLs availability (should be 100%)
SELECT 'URL availability' as metric;
SELECT 
    COUNT(*) as total_docs,
    COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) as with_url,
    ROUND(COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

-- Document summaries availability (should be 99.9%)
SELECT 'Document summaries availability' as metric;
SELECT 
    COUNT(*) as total_docs,
    COUNT(CASE WHEN conteudo IS NOT NULL AND conteudo != '' THEN 1 END) as with_summary,
    ROUND(COUNT(CASE WHEN conteudo IS NOT NULL AND conteudo != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

-- Sample of Amazonas data for verification
SELECT 'Amazonas sample data' as metric;
SELECT titulo, estado, url, LEFT(conteudo, 80) as ementa_preview
FROM documents 
WHERE estado = 'Amazonas'
ORDER BY id;

-- Municipality data verification
SELECT 'Municipality data' as metric;
SELECT municipality, estado, COUNT(*) as count
FROM documents 
WHERE municipality IS NOT NULL AND municipality != ''
GROUP BY municipality, estado
ORDER BY count DESC
LIMIT 5;

COMMIT;