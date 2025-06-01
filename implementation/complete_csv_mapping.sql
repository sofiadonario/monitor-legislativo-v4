-- Complete CSV Field Mapping Implementation
-- Add missing columns and map all CSV fields to documents table

-- First, add missing columns to lexml_documents_corrected table
ALTER TABLE lexml_documents_corrected 
ADD COLUMN IF NOT EXISTS locality TEXT,
ADD COLUMN IF NOT EXISTS authority TEXT,
ADD COLUMN IF NOT EXISTS authority_level TEXT;

-- Add missing columns to documents table for better data display
ALTER TABLE documents
ADD COLUMN IF NOT EXISTS municipality TEXT,
ADD COLUMN IF NOT EXISTS justice TEXT,
ADD COLUMN IF NOT EXISTS region TEXT,
ADD COLUMN IF NOT EXISTS court_class TEXT,
ADD COLUMN IF NOT EXISTS document_type_full TEXT,
ADD COLUMN IF NOT EXISTS document_description TEXT,
ADD COLUMN IF NOT EXISTS document_summary TEXT,
ADD COLUMN IF NOT EXISTS search_term TEXT,
ADD COLUMN IF NOT EXISTS locality TEXT,
ADD COLUMN IF NOT EXISTS authority TEXT,
ADD COLUMN IF NOT EXISTS authority_level TEXT,
ADD COLUMN IF NOT EXISTS document_number TEXT;

-- Update lexml_documents_corrected with missing CSV fields by re-importing the data
-- Since we can't easily re-import, let's extract what we can from existing data

-- Now update documents table with comprehensive mapping from lexml_documents_corrected
UPDATE documents SET
    -- Basic identification
    search_term = ldc.search_term,
    
    -- Geographic data
    municipality = ldc.municipality,
    estado = COALESCE(
        ldc.state,
        -- Extract from locality field
        CASE 
            WHEN ldc.locality LIKE '%São Paulo%' OR ldc.locality LIKE '%SP%' THEN 'São Paulo'
            WHEN ldc.locality LIKE '%Rio de Janeiro%' OR ldc.locality LIKE '%RJ%' THEN 'Rio de Janeiro'
            WHEN ldc.locality LIKE '%Minas Gerais%' OR ldc.locality LIKE '%MG%' THEN 'Minas Gerais'
            WHEN ldc.locality LIKE '%Rio Grande do Sul%' OR ldc.locality LIKE '%RS%' THEN 'Rio Grande do Sul'
            WHEN ldc.locality LIKE '%Bahia%' OR ldc.locality LIKE '%BA%' THEN 'Bahia'
            WHEN ldc.locality LIKE '%Paraná%' OR ldc.locality LIKE '%PR%' THEN 'Paraná'
            WHEN ldc.locality LIKE '%Santa Catarina%' OR ldc.locality LIKE '%SC%' THEN 'Santa Catarina'
            WHEN ldc.locality LIKE '%Distrito Federal%' OR ldc.locality LIKE '%DF%' THEN 'Distrito Federal'
            WHEN ldc.locality = 'Brasil' OR ldc.locality IS NULL THEN 'Federal'
            ELSE 'Federal'
        END,
        -- Extract from URN if still null
        CASE 
            WHEN ldc.urn LIKE '%sao.paulo%' THEN 'São Paulo'
            WHEN ldc.urn LIKE '%rio.de.janeiro%' OR ldc.urn LIKE '%rio.janeiro%' THEN 'Rio de Janeiro'
            WHEN ldc.urn LIKE '%minas.gerais%' THEN 'Minas Gerais'
            WHEN ldc.urn LIKE '%rio.grande.sul%' THEN 'Rio Grande do Sul'
            WHEN ldc.urn LIKE '%bahia%' THEN 'Bahia'
            WHEN ldc.urn LIKE '%parana%' THEN 'Paraná'
            WHEN ldc.urn LIKE '%santa.catarina%' THEN 'Santa Catarina'
            WHEN ldc.urn LIKE '%distrito.federal%' THEN 'Distrito Federal'
            ELSE 'Federal'
        END
    ),
    locality = ldc.locality,
    
    -- Justice/Court data
    justice = ldc.justice,
    region = ldc.region,
    court_class = ldc.court_class,
    
    -- Document metadata
    document_type_full = ldc.document_type_full,
    document_description = ldc.document_description,
    document_summary = ldc.document_summary,
    document_number = ldc.document_number,
    
    -- Authority information
    authority = ldc.authority,
    authority_level = ldc.authority_level,
    autor = COALESCE(ldc.authority, ldc.document_type_full, documents.autor),
    
    -- Content (ementa) - prioritize document_summary
    conteudo = COALESCE(ldc.document_summary, ldc.document_description, documents.conteudo),
    
    -- Update metadata with complete information
    metadata = jsonb_build_object(
        'search_term', ldc.search_term,
        'date_searched', ldc.date_searched,
        'country', ldc.country,
        'state', ldc.state,
        'municipality', ldc.municipality,
        'locality', ldc.locality,
        'justice', ldc.justice,
        'region', ldc.region,
        'court_class', ldc.court_class,
        'document_type_full', ldc.document_type_full,
        'authority', ldc.authority,
        'authority_level', ldc.authority_level,
        'source_type', 'corrected_lexml_complete',
        'has_summary', CASE WHEN ldc.document_summary IS NOT NULL AND ldc.document_summary != '' THEN true ELSE false END,
        'has_description', CASE WHEN ldc.document_description IS NOT NULL AND ldc.document_description != '' THEN true ELSE false END,
        'geographic_level', CASE 
            WHEN ldc.municipality IS NOT NULL AND ldc.municipality != '' THEN 'municipal'
            WHEN ldc.state IS NOT NULL AND ldc.state != '' THEN 'state'
            WHEN ldc.justice IS NOT NULL AND ldc.justice != '' THEN 'judicial'
            ELSE 'federal'
        END
    )
FROM lexml_documents_corrected ldc
WHERE documents.urn = ldc.urn;

-- Create indexes for better performance on new columns
CREATE INDEX IF NOT EXISTS idx_documents_municipality ON documents(municipality);
CREATE INDEX IF NOT EXISTS idx_documents_justice ON documents(justice);
CREATE INDEX IF NOT EXISTS idx_documents_authority ON documents(authority);
CREATE INDEX IF NOT EXISTS idx_documents_search_term ON documents(search_term);

-- Final comprehensive verification
SELECT 'COMPLETE CSV MAPPING RESULTS' as status;

-- Check all field completeness
SELECT 'Field completeness summary' as metric;

SELECT 
    'Estados' as field,
    COUNT(CASE WHEN estado IS NOT NULL AND estado != '' THEN 1 END) as filled,
    COUNT(*) as total,
    ROUND(COUNT(CASE WHEN estado IS NOT NULL AND estado != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents
UNION ALL
SELECT 
    'Municipalities' as field,
    COUNT(CASE WHEN municipality IS NOT NULL AND municipality != '' THEN 1 END) as filled,
    COUNT(*) as total,
    ROUND(COUNT(CASE WHEN municipality IS NOT NULL AND municipality != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents
UNION ALL
SELECT 
    'URLs' as field,
    COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) as filled,
    COUNT(*) as total,
    ROUND(COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents
UNION ALL
SELECT 
    'Document Summaries (Ementa)' as field,
    COUNT(CASE WHEN document_summary IS NOT NULL AND document_summary != '' THEN 1 END) as filled,
    COUNT(*) as total,
    ROUND(COUNT(CASE WHEN document_summary IS NOT NULL AND document_summary != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents
UNION ALL
SELECT 
    'Authority Information' as field,
    COUNT(CASE WHEN authority IS NOT NULL AND authority != '' THEN 1 END) as filled,
    COUNT(*) as total,
    ROUND(COUNT(CASE WHEN authority IS NOT NULL AND authority != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents
UNION ALL
SELECT 
    'Justice/Court Data' as field,
    COUNT(CASE WHEN justice IS NOT NULL AND justice != '' THEN 1 END) as filled,
    COUNT(*) as total,
    ROUND(COUNT(CASE WHEN justice IS NOT NULL AND justice != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

-- Sample of complete data
SELECT 'Sample of complete mapped data' as status;
SELECT 
    titulo,
    estado,
    municipality,
    authority,
    justice,
    LEFT(document_summary, 100) || '...' as ementa_preview,
    url
FROM documents 
WHERE document_summary IS NOT NULL 
LIMIT 3;

-- Geographic distribution
SELECT 'Geographic distribution' as status;
SELECT 
    estado,
    COUNT(*) as documents,
    COUNT(CASE WHEN municipality IS NOT NULL AND municipality != '' THEN 1 END) as with_municipality
FROM documents 
GROUP BY estado 
ORDER BY documents DESC;

COMMIT;