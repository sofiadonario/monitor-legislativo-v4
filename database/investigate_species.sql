-- Investigation of Document Species within Legislation and Jurisprudence Genders
-- This script analyzes the database to identify document subtypes/species

-- First, let's see the current tipo distribution
SELECT 'CURRENT DOCUMENT TYPES (tipo field)' as analysis;
SELECT tipo, COUNT(*) as count 
FROM documents 
GROUP BY tipo 
ORDER BY count DESC;

-- Now let's look at the metadata to find more detailed document types
SELECT 'DOCUMENT TYPES FROM METADATA' as analysis;
SELECT 
    tipo as gender,
    metadata->>'document_type' as document_type_metadata,
    COUNT(*) as count
FROM documents
WHERE metadata->>'document_type' IS NOT NULL
GROUP BY tipo, metadata->>'document_type'
ORDER BY tipo, count DESC;

-- Let's examine the document_type_full field
SELECT 'DOCUMENT TYPES FROM document_type_full FIELD' as analysis;
SELECT 
    tipo as gender,
    document_type_full,
    COUNT(*) as count
FROM documents
WHERE document_type_full IS NOT NULL
GROUP BY tipo, document_type_full
ORDER BY tipo, count DESC
LIMIT 50;

-- Let's look at the authority field to understand document sources
SELECT 'AUTHORITIES PRODUCING DOCUMENTS' as analysis;
SELECT 
    tipo as gender,
    authority,
    COUNT(*) as count
FROM documents
WHERE authority IS NOT NULL
GROUP BY tipo, authority
ORDER BY tipo, count DESC
LIMIT 30;

-- Analyze the titulo field for patterns (especially for legislation)
SELECT 'LEGISLATION SPECIES FROM TITLE PATTERNS' as analysis;
SELECT 
    CASE 
        WHEN titulo ~* 'lei complementar' THEN 'Lei Complementar'
        WHEN titulo ~* 'lei ordin[aá]ria' THEN 'Lei Ordinária'
        WHEN titulo ~* 'lei\s+\d' AND titulo !~* 'decreto|medida' THEN 'Lei'
        WHEN titulo ~* 'decreto legislativo' THEN 'Decreto Legislativo'
        WHEN titulo ~* 'decreto-lei' THEN 'Decreto-Lei'
        WHEN titulo ~* 'decreto\s+\d' AND titulo !~* 'lei' THEN 'Decreto'
        WHEN titulo ~* 'medida provis[oó]ria|mpv' THEN 'Medida Provisória'
        WHEN titulo ~* 'portaria' THEN 'Portaria'
        WHEN titulo ~* 'resolu[çc][aã]o' THEN 'Resolução'
        WHEN titulo ~* 'instru[çc][aã]o normativa' THEN 'Instrução Normativa'
        WHEN titulo ~* 'circular' THEN 'Circular'
        WHEN titulo ~* 'edital' THEN 'Edital'
        WHEN titulo ~* 'emenda constitucional' THEN 'Emenda Constitucional'
        WHEN titulo ~* 'constitui[çc][aã]o' THEN 'Constituição'
        ELSE 'Outros'
    END as species,
    COUNT(*) as count
FROM documents
WHERE tipo = 'legislation'
GROUP BY species
ORDER BY count DESC;

-- Analyze jurisprudence for species based on court types and decisions
SELECT 'JURISPRUDENCE SPECIES FROM AUTHORITY PATTERNS' as analysis;
SELECT 
    CASE 
        WHEN authority ~* 'supremo tribunal federal|stf' THEN 'STF - Supremo Tribunal Federal'
        WHEN authority ~* 'superior tribunal de justi[çc]a|stj' THEN 'STJ - Superior Tribunal de Justiça'
        WHEN authority ~* 'tribunal superior|tst|tse' THEN 'Tribunais Superiores'
        WHEN authority ~* 'tribunal regional federal|trf' THEN 'TRF - Tribunal Regional Federal'
        WHEN authority ~* 'tribunal de justi[çc]a|tj' THEN 'TJ - Tribunal de Justiça'
        WHEN authority ~* 'tribunal regional do trabalho|trt' THEN 'TRT - Tribunal Regional do Trabalho'
        WHEN authority ~* 'tribunal regional eleitoral|tre' THEN 'TRE - Tribunal Regional Eleitoral'
        WHEN authority ~* 'turma|c[aâ]mara' THEN 'Turmas e Câmaras'
        ELSE 'Outros Órgãos Judiciários'
    END as species,
    COUNT(*) as count
FROM documents
WHERE tipo = 'jurisprudence'
GROUP BY species
ORDER BY count DESC;

-- Let's also check the URN patterns for more insights
SELECT 'SPECIES FROM URN PATTERNS (SAMPLE)' as analysis;
SELECT 
    tipo as gender,
    SUBSTRING(urn FROM 'urn:lex:br:[^:]+:([^:;]+)') as urn_document_type,
    COUNT(*) as count
FROM documents
WHERE urn IS NOT NULL
GROUP BY tipo, urn_document_type
ORDER BY tipo, count DESC
LIMIT 30;

-- Summary of findings
SELECT 'SUMMARY - GENDER DISTRIBUTION' as analysis;
SELECT 
    tipo as gender,
    COUNT(*) as total_documents,
    COUNT(DISTINCT estado) as states_covered,
    COUNT(DISTINCT authority) as unique_authorities,
    MIN(data_publicacao) as oldest_document,
    MAX(data_publicacao) as newest_document
FROM documents
GROUP BY tipo;

-- Detailed species proposal for legislation
SELECT 'PROPOSED LEGISLATION SPECIES' as analysis;
WITH legislation_species AS (
    SELECT 
        id,
        titulo,
        CASE 
            WHEN titulo ~* 'lei complementar' OR urn ~* 'lei\.complementar' THEN 'Lei Complementar'
            WHEN titulo ~* 'emenda constitucional' OR urn ~* 'emenda\.constitucional' THEN 'Emenda Constitucional'
            WHEN titulo ~* 'medida provis[óo]ria|mpv' OR urn ~* 'medida\.provisoria' THEN 'Medida Provisória'
            WHEN titulo ~* 'decreto-lei' OR urn ~* 'decreto\.lei' THEN 'Decreto-Lei'
            WHEN titulo ~* 'decreto legislativo' THEN 'Decreto Legislativo'
            WHEN titulo ~* 'decreto' OR urn ~* ':decreto[^:]' THEN 'Decreto'
            WHEN titulo ~* 'portaria' OR urn ~* ':portaria' THEN 'Portaria'
            WHEN titulo ~* 'resolu[çc][ãa]o' OR urn ~* ':resolucao' THEN 'Resolução'
            WHEN titulo ~* 'instru[çc][ãa]o normativa' THEN 'Instrução Normativa'
            WHEN titulo ~* 'lei\s+\d' OR urn ~* ':lei[^:]' THEN 'Lei Ordinária'
            ELSE 'Outros Atos Normativos'
        END as species
    FROM documents
    WHERE tipo = 'legislation'
)
SELECT species, COUNT(*) as count
FROM legislation_species
GROUP BY species
ORDER BY count DESC;

-- Detailed species proposal for jurisprudence
SELECT 'PROPOSED JURISPRUDENCE SPECIES' as analysis;
WITH jurisprudence_species AS (
    SELECT 
        id,
        titulo,
        authority,
        CASE 
            WHEN titulo ~* 's[úu]mula vinculante' THEN 'Súmula Vinculante'
            WHEN titulo ~* 's[úu]mula' THEN 'Súmula'
            WHEN titulo ~* 'ac[óo]rd[ãa]o' OR urn ~* ':acordao' THEN 'Acórdão'
            WHEN titulo ~* 'decis[ãa]o monocr[áa]tica' THEN 'Decisão Monocrática'
            WHEN titulo ~* 'senten[çc]a' THEN 'Sentença'
            WHEN titulo ~* 'despacho' THEN 'Despacho'
            WHEN authority ~* 'supremo|stf' THEN 'Decisão STF'
            WHEN authority ~* 'superior.*justi[çc]a|stj' THEN 'Decisão STJ'
            WHEN authority ~* 'trf|regional federal' THEN 'Decisão TRF'
            WHEN authority ~* 'tribunal.*justi[çc]a|tj' THEN 'Decisão TJ'
            ELSE 'Outras Decisões Judiciais'
        END as species
    FROM documents
    WHERE tipo = 'jurisprudence'
)
SELECT species, COUNT(*) as count
FROM jurisprudence_species
GROUP BY species
ORDER BY count DESC;