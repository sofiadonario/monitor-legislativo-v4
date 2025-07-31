-- Drop existing incomplete view
DROP VIEW IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed CASCADE;

-- Create COMPLETE unified documents view from ALL lexml_* tables
CREATE VIEW documents AS

-- LEGISLAÇÃO - Geral
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Legislação Geral') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Geral' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação Geral - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_legislacao_geral

UNION ALL

-- LEGISLAÇÃO - Aéreo
SELECT 
  id + 100000,
  titulo,
  tipo,
  'Legislação' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Legislação Aéreo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Aéreo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação Aéreo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_legislacao_aereo

UNION ALL

-- LEGISLAÇÃO - Marítimo
SELECT 
  id + 200000,
  titulo,
  tipo,
  'Legislação' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Legislação Marítimo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Marítimo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação Marítimo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_legislacao_maritimo

UNION ALL

-- LEGISLAÇÃO - Rodoviário
SELECT 
  id + 300000,
  titulo,
  tipo,
  'Legislação' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Legislação Rodoviário') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Rodoviário' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação Rodoviário - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_legislacao_rodoviario

UNION ALL

-- JURISPRUDÊNCIA - Geral
SELECT 
  id + 400000,
  titulo,
  tipo,
  'Jurisprudência' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Jurisprudência Geral') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Geral' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência Geral - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_jurisprudencia_geral

UNION ALL

-- JURISPRUDÊNCIA - Aéreo
SELECT 
  id + 500000,
  titulo,
  tipo,
  'Jurisprudência' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Jurisprudência Aéreo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Aéreo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência Aéreo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_jurisprudencia_aereo

UNION ALL

-- JURISPRUDÊNCIA - Marítimo
SELECT 
  id + 600000,
  titulo,
  tipo,
  'Jurisprudência' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Jurisprudência Marítimo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Marítimo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência Marítimo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_jurisprudencia_maritimo

UNION ALL

-- JURISPRUDÊNCIA - Rodoviário
SELECT 
  id + 700000,
  titulo,
  tipo,
  'Jurisprudência' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Jurisprudência Rodoviário') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Rodoviário' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência Rodoviário - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_jurisprudencia_rodoviario

UNION ALL

-- DOUTRINA - Geral
SELECT 
  id + 800000,
  titulo,
  tipo,
  'Doutrina' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Doutrina Geral') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Geral' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Doutrina' as court_class,
  CONCAT('Doutrina Geral - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_doutrina_geral

UNION ALL

-- DOUTRINA - Aéreo
SELECT 
  id + 900000,
  titulo,
  tipo,
  'Doutrina' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Doutrina Aéreo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Aéreo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Doutrina' as court_class,
  CONCAT('Doutrina Aéreo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_doutrina_aereo

UNION ALL

-- DOUTRINA - Marítimo
SELECT 
  id + 1000000,
  titulo,
  tipo,
  'Doutrina' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Doutrina Marítimo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Marítimo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Doutrina' as court_class,
  CONCAT('Doutrina Marítimo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_doutrina_maritimo

UNION ALL

-- DOUTRINA - Rodoviário
SELECT 
  id + 1100000,
  titulo,
  tipo,
  'Doutrina' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Doutrina Rodoviário') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Rodoviário' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Doutrina' as court_class,
  CONCAT('Doutrina Rodoviário - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_doutrina_rodoviario

UNION ALL

-- OUTROS - Geral
SELECT 
  id + 1200000,
  titulo,
  tipo,
  'Outros' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Outros Geral') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Geral' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Outros' as court_class,
  CONCAT('Outros Geral - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_outros_geral

UNION ALL

-- OUTROS - Aéreo
SELECT 
  id + 1300000,
  titulo,
  tipo,
  'Outros' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Outros Aéreo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Aéreo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Outros' as court_class,
  CONCAT('Outros Aéreo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_outros_aereo

UNION ALL

-- OUTROS - Marítimo
SELECT 
  id + 1400000,
  titulo,
  tipo,
  'Outros' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Outros Marítimo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Marítimo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Outros' as court_class,
  CONCAT('Outros Marítimo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_outros_maritimo

UNION ALL

-- OUTROS - Rodoviário
SELECT 
  id + 1500000,
  titulo,
  tipo,
  'Outros' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Outros Rodoviário') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Rodoviário' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Outros' as court_class,
  CONCAT('Outros Rodoviário - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_outros_rodoviario

UNION ALL

-- PROPOSIÇÕES - Geral
SELECT 
  id + 1600000,
  titulo,
  tipo,
  'Proposições' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Proposições Geral') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Geral' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Proposições' as court_class,
  CONCAT('Proposições Geral - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_proposicoes_geral

UNION ALL

-- PROPOSIÇÕES - Aéreo
SELECT 
  id + 1700000,
  titulo,
  tipo,
  'Proposições' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Proposições Aéreo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Aéreo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Proposições' as court_class,
  CONCAT('Proposições Aéreo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_proposicoes_aereo

UNION ALL

-- PROPOSIÇÕES - Marítimo
SELECT 
  id + 1800000,
  titulo,
  tipo,
  'Proposições' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Proposições Marítimo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Marítimo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Proposições' as court_class,
  CONCAT('Proposições Marítimo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_proposicoes_maritimo

UNION ALL

-- PROPOSIÇÕES - Rodoviário
SELECT 
  id + 1900000,
  titulo,
  tipo,
  'Proposições' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Proposições Rodoviário') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Rodoviário' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Proposições' as court_class,
  CONCAT('Proposições Rodoviário - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_proposicoes_rodoviario;

-- Create compatibility view
CREATE VIEW lexml_parsed_enhanced_fixed AS SELECT * FROM documents;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_documents_species ON documents(species);
CREATE INDEX IF NOT EXISTS idx_documents_transport ON documents(transport_category);
CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado);
CREATE INDEX IF NOT EXISTS idx_documents_data ON documents(data_publicacao);

-- Verify the complete view
SELECT 'Complete documents view created from ALL 20 lexml_* tables' as status;
SELECT COUNT(*) as total_documents FROM documents;
SELECT species, transport_category, COUNT(*) as count 
FROM documents 
GROUP BY species, transport_category 
ORDER BY species, transport_category;