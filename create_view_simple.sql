-- Create simplified documents view
CREATE OR REPLACE VIEW documents AS
SELECT 
    id,
    titulo,
    tipo,
    'Não Classificado' as species,
    COALESCE(jurisdicao, 'BR') as estado,
    COALESCE(jurisdicao, 'BR') as estado_codigo,
    COALESCE(localidade, '') as municipality,
    data as data_publicacao,
    url,
    urn,
    COALESCE(ementa, '') as conteudo,
    COALESCE(ementa, '') as document_summary,
    tipo as document_type_full,
    termo_busca as search_term,
    autor,
    'LexML' as fonte,
    classificacao as transport_category,
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
    SELECT * FROM lexml_doutrina_aereo
    UNION ALL
    SELECT * FROM lexml_doutrina_geral
    UNION ALL
    SELECT * FROM lexml_doutrina_maritimo
    UNION ALL
    SELECT * FROM lexml_doutrina_rodoviario
    UNION ALL
    SELECT * FROM lexml_jurisprudencia_aereo
    UNION ALL
    SELECT * FROM lexml_jurisprudencia_geral
    UNION ALL
    SELECT * FROM lexml_jurisprudencia_maritimo
    UNION ALL
    SELECT * FROM lexml_jurisprudencia_rodoviario
    UNION ALL
    SELECT * FROM lexml_legislacao_aereo
    UNION ALL
    SELECT * FROM lexml_legislacao_geral
    UNION ALL
    SELECT * FROM lexml_legislacao_maritimo
    UNION ALL
    SELECT * FROM lexml_legislacao_rodoviario
    UNION ALL
    SELECT * FROM lexml_outros_aereo
    UNION ALL
    SELECT * FROM lexml_outros_geral
    UNION ALL
    SELECT * FROM lexml_outros_maritimo
    UNION ALL
    SELECT * FROM lexml_outros_rodoviario
    UNION ALL
    SELECT * FROM lexml_proposicoes_aereo
    UNION ALL
    SELECT * FROM lexml_proposicoes_geral
    UNION ALL
    SELECT * FROM lexml_proposicoes_maritimo
    UNION ALL
    SELECT * FROM lexml_proposicoes_rodoviario
) AS all_documents;