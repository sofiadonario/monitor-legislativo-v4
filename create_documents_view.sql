-- Create a unified documents view that combines all category tables
-- This view will be used by the Shiny app which expects a single 'documents' table

-- Drop the view if it exists
DROP VIEW IF EXISTS documents CASCADE;

-- Create a comprehensive view that unions all category tables
CREATE OR REPLACE VIEW documents AS
SELECT 
    id,
    titulo,
    tipo,
    'Não Classificado' as species,
    CASE 
        WHEN jurisdicao = 'federal' THEN 'BR'
        WHEN jurisdicao = 'estadual' THEN 'Estado'
        ELSE COALESCE(jurisdicao, 'BR')
    END as estado,
    CASE 
        WHEN jurisdicao = 'federal' THEN 'BR'
        WHEN jurisdicao = 'estadual' THEN 'Estado'
        ELSE COALESCE(jurisdicao, 'BR')
    END as estado_codigo,
    COALESCE(localidade, '') as municipality,
    data as data_publicacao,
    url,
    urn,
    COALESCE(ementa, '') as conteudo,
    COALESCE(ementa, '') as document_summary,
    categoria || ' - ' || modal as document_type_full,
    termo_busca as search_term,
    autoridade as autor,
    origem as fonte,
    categoria as transport_category,
    data_coleta as created_at,
    data_coleta as updated_at,
    localidade as locality,
    autoridade as authority,
    jurisdicao as authority_level,
    CAST(numero AS TEXT) as document_number,
    jurisdicao as justice,
    '' as region,
    '' as court_class,
    ementa as document_description,
    '{}' as metadata
FROM (
    -- Doutrina tables
    SELECT * FROM lexml_doutrina_aereo
    UNION ALL
    SELECT * FROM lexml_doutrina_geral
    UNION ALL
    SELECT * FROM lexml_doutrina_maritimo
    UNION ALL
    SELECT * FROM lexml_doutrina_rodoviario
    UNION ALL
    -- Jurisprudencia tables
    SELECT * FROM lexml_jurisprudencia_aereo
    UNION ALL
    SELECT * FROM lexml_jurisprudencia_geral
    UNION ALL
    SELECT * FROM lexml_jurisprudencia_maritimo
    UNION ALL
    SELECT * FROM lexml_jurisprudencia_rodoviario
    UNION ALL
    -- Legislacao tables
    SELECT * FROM lexml_legislacao_aereo
    UNION ALL
    SELECT * FROM lexml_legislacao_geral
    UNION ALL
    SELECT * FROM lexml_legislacao_maritimo
    UNION ALL
    SELECT * FROM lexml_legislacao_rodoviario
    UNION ALL
    -- Outros tables
    SELECT * FROM lexml_outros_aereo
    UNION ALL
    SELECT * FROM lexml_outros_geral
    UNION ALL
    SELECT * FROM lexml_outros_maritimo
    UNION ALL
    SELECT * FROM lexml_outros_rodoviario
    UNION ALL
    -- Proposicoes tables
    SELECT * FROM lexml_proposicoes_aereo
    UNION ALL
    SELECT * FROM lexml_proposicoes_geral
    UNION ALL
    SELECT * FROM lexml_proposicoes_maritimo
    UNION ALL
    SELECT * FROM lexml_proposicoes_rodoviario
) AS all_documents;

-- Create indexes on the base tables to improve view performance
-- (The indexes should already exist from create_all_indexes.sql)

-- Grant permissions
GRANT SELECT ON documents TO postgres;

-- Create a simple count check
SELECT 'Total documents in view:' as info, COUNT(*) as count FROM documents;