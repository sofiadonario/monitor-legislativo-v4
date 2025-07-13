-- Add species column and populate with document classifications
-- Based on the investigation results, implementing refined species categorization

-- Step 1: Add the species column
ALTER TABLE documents ADD COLUMN IF NOT EXISTS species TEXT;

-- Step 2: Update legislation documents with species classification
UPDATE documents 
SET species = CASE 
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
END
WHERE tipo = 'legislation';

-- Step 3: Update jurisprudence documents with species classification
UPDATE documents 
SET species = CASE 
    WHEN titulo ~* 'súmula vinculante' THEN 'Súmula Vinculante'
    WHEN titulo ~* 'súmula' THEN 'Súmula'
    WHEN titulo ~* 'acórdão' OR urn ~* ':acordao' OR document_type_full ~* 'acordao' THEN 'Acórdão'
    WHEN titulo ~* 'decisão monocrática' THEN 'Decisão Monocrática'
    WHEN titulo ~* 'sentença' THEN 'Sentença'
    WHEN titulo ~* 'despacho' THEN 'Despacho'
    ELSE 'Outras Decisões Judiciais'
END
WHERE tipo = 'jurisprudence';

-- Step 4: Handle any null tipo records
UPDATE documents 
SET species = 'Documento Não Classificado'
WHERE tipo IS NULL OR tipo = '';

-- Step 5: Verification queries
SELECT 'SPECIES DISTRIBUTION BY GENDER' as analysis;
SELECT 
    tipo as gender,
    species,
    COUNT(*) as count
FROM documents
GROUP BY tipo, species
ORDER BY tipo, count DESC;

SELECT 'TOTAL COUNTS VERIFICATION' as analysis;
SELECT 
    tipo as gender,
    COUNT(*) as total_documents,
    COUNT(DISTINCT species) as unique_species
FROM documents
GROUP BY tipo;