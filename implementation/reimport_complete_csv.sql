-- Complete CSV Re-import with ALL Fields
-- Update lexml_documents_corrected table with missing CSV fields

-- First, add the missing columns if they don't exist
ALTER TABLE lexml_documents_corrected 
ADD COLUMN IF NOT EXISTS locality TEXT,
ADD COLUMN IF NOT EXISTS authority TEXT,
ADD COLUMN IF NOT EXISTS authority_level TEXT;

-- Update existing records with missing field data
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1982-05-27;5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2019-05-03;882';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2021-03-05;1035';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-05-08;963';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2000-08-28;2021-5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2016-05-10;8756';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2010-05-05;7168';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.legislativo:2018-02-06;5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2011-05-10;7475';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2024-05-28;12034';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2017-05-25;9059';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2019-05-03;882';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2016-05-06;seq-sf-1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-05-11;10345';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-05-22;10368';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2013-05-08;12808';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2013-05-16;12814';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2012-05-17;12648';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1999-05-05;15';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2017-05-12;9051';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1999-05-13;3057';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1973-05-11;72219';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1998-05-20;9638';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1998-05-18;1660';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2021-05-18;10703';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1998-05-26;9647';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2007-05-29;11478';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2013-05-31;8022';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1983-05-10;175';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1983-05-19;213';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2011-05-12;seq-sf-1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2000-05-02;2021-1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1942-05-26;4345';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2008-05-08;6450';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2016-05-12;727';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2019-05-22;883';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2021-05-18;10702';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:2020-05-27;4';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1982-05-28;6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:2014-05-29;10';
UPDATE lexml_documents_corrected SET 
    locality = NULL,
    authority = NULL,
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'NULL';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1992-01-16;13727';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;ms:2012-05-29;30926-4156078';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1993-12-22;15355';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;ms:2011-12-06;30061-3999083';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;rms:2023-09-18;71279-2343447';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;plenario:acordao;ms:1957-09-09;4503-1423458';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;rms:2013-10-17;43781-1353102';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:2002-02-27;1026';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. Corte Especial',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;corte.especial:acordao;ms:2021-05-05;27173-2051834';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2016-05-17;5301';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;ms:2011-09-13;30149-4039097';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;ms:2011-09-06;30130-4003331';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2010-06-18;7514';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.1:acordao:2000-06-12;128890';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.1:acordao:2009-09-17;377514';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Seção de Dissídios Individuais',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;secao.dissidios.individuais.1:acordao:2023-06-27;0011088-26.2023.5.03.0000';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior Eleitoral. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.eleitoral;plenario:acordao;ms:2008-09-09;ms-3738';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;ms:2012-02-28;30450-4181047';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Seção',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;secao.1:acordao;ms:2013-04-24;19571-1287566';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. Corte Especial',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;corte.especial:acordao;ms:2021-09-01;27637-2090296';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;plenario:acordao;ms:2004-03-11;23490-3562474';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;ms:2011-08-30;26740-2531239';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2013-07-04;5893';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Seção de Dissídios Individuais',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;secao.dissidios.individuais.1:acordao:2023-07-31;0010610-18.2023.5.03.0000';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;ms:2011-09-13;30070-4028537';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2009-11-19;6454';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;ms:2011-09-06;30186-4008848';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2006-08-30;1591';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Órgão Especial',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;orgao.especial:acordao;roms:2000-10-05;442103-1998-5555-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 5ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.5:acordao:2012-05-23;589123';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;ms:2019-09-17;36082-5675317';
UPDATE lexml_documents_corrected SET 
    locality = 'Sant''Ana do Livramento - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;sant.ana.livramento:municipal:lei:2001-09-06;4232';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2024-03-26;969';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2020-10-06;48054';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.9:acordao:2015-03-13;00014518120125010068';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;ag:2022-06-22;11540-2018-131-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;ag:2024-05-02;1000348-2017-447-2-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2014-12-17;0000593-78.2012.5.03.0073';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2015-03-03;0010005-96.2013.5.03.0073';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;ag:2024-05-15;658-2022-31-12-0';
UPDATE lexml_documents_corrected SET 
    locality = 'São Martinho - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;sao.martinho:municipal:lei:2019-06-06;3069';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;rr:2014-12-10;540-2012-447-2-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2018-02-20;0011233-77.2016.5.03.0178';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;ed:2021-03-02;57500-2008-442-2-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2024-05-08;0010813-93.2022.5.03.0006';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;ed:2019-04-30;214400-2007-444-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;rr:2022-12-14;1001345-2019-371-2-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2023-08-17;0010590-25.2022.5.03.0109';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2021-05-07;0010474-63.2020.5.03.0020';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2022-01-19;42930';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2024-06-24;0010613-14.2022.5.03.0030';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;rr:2015-05-13;43-2012-132-5-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Subseção Especializada em Dissídios Individuais 1',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;subsecao.especializada.dissidios.individuais.1:acordao;agr:2020-11-05;152200-2004-29-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;airr:2023-08-29;697-2021-5-23-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;airr:2017-04-19;160-2015-122-5-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2021-08-24;566-2017-3-10-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2019-09-11;53000-2009-441-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Seção de Dissídios Coletivos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;secao.dissidios.coletivos:acordao;ed:2007-04-12;1387756-2004-900-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-01-12;10936';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2016-06-01;152200-2004-29-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2018-11-07;206-2015-145-6-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;arr:2018-03-14;1241-2015-444-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;rr:2018-08-08;636-2011-15-11-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Subseção Especializada em Dissídios Individuais 1',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;subsecao.especializada.dissidios.individuais.1:acordao;e:2012-03-29;152300-2004-29-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;arr:2016-11-16;171800-2009-446-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2021-05-26;1821-2015-19-11-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;airr:2014-04-23;13500-2006-443-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 3ª Câmara. 1ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.3;turma.ordinaria.1:acordao:2016-06-21;3301-002.999,6425066';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Subseção Especializada em Dissídios Individuais 2',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;subsecao.especializada.dissidios.individuais.2:acordao;ro:2018-02-27;22111-2016-0-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;rr:2023-03-29;10534-2021-138-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2016-01-11;13243';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-04-04;10312';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2023-04-17;11493';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2012-12-04;seq-sf-2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.legislativo:2021-04-30;17';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2023-04-06;11474';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2013-04-04;612';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.legislativo:2010-04-07;215';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:2022-04-13;5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-04-28;10332';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-04-28;11053';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2012-04-03;563';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2010-04-23;487';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2013-04-01;7975';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2002-04-11;4195';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2012-04-03;7716';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2022-08-04;43625';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2021-11-04;42688';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Ciência,TecnologiaeInovação; Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.ciencia.tecnologia.inovacao,ministerio.planejamento.orcamento.gestao:portaria.interministerial:2011-08-04;272';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2013-07-04;241';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2009-06-04;6868';
UPDATE lexml_documents_corrected SET 
    locality = 'Canela - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;canela:municipal:lei:2020-05-04;4439';
UPDATE lexml_documents_corrected SET 
    locality = 'Rio Grande - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;rio.grande:municipal:decreto:2014-04-04;12693';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2021-04-27;42039';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2017-04-11;38126';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2021-10-04;42578';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2018-07-04;47444';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2018-07-04;47445';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2014-12-04;36099';
UPDATE lexml_documents_corrected SET 
    locality = 'Amazonas',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;amazonas:estadual:lei:2024-01-04;6700';
UPDATE lexml_documents_corrected SET 
    locality = 'Venâncio Aires - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;venancio.aires:municipal:lei:2018-06-04;6134';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2013-04-24;133';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Rita do Sapucaí - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;santa.rita.sapucai:municipal:lei:2019-09-04;5255';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2015-12-04;8582';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho.4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;ag:2023-02-14;20614-2020-14-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2018-04-25;39008';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-03-31;11026';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1998-06-26;1637-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1997-06-27;1565-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1997-06-12;1561-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:resolucao:1959-05-27;6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1990-06-06;99274';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2000-12-21;2052-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1997-11-27;1577-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1990-06-06;99281';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2006-06-06;5796';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1984-06-20;89817';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1968-06-06;62838';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1985-06-11;91317';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1973-06-27;72411';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1998-11-25;1685-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1986-06-25;7498';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1958-06-16;43909';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1990-06-27;99355';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1957-06-19;41666';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1989-06-05;97800';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1978-06-29;81871';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2019-06-10;9830';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2000-06-29;2052';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1992-06-23;574';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2015-06-05;8463';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1997-06-12;2252';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2002-06-10;4262';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1965-06-04;56414';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1987-06-04;94403';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1965-06-15;56467';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1978-06-28;6540';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2003-06-26;4767';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1930-06-12;19241';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1911-06-07;8768';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1903-06-10;4862';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1911-06-28;2416';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1867-06-26;3900';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1898-06-11;2907';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1991-06-25;153';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1979-06-25;83611';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1978-06-07;81771';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-04-08;1697';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2016-08-09;5968';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-09-11;4378';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-09-19;4541';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2019;1254';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2016-12-13;6674';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2019-06-13;3542';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2022-04-13;1224';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pls:2016;275';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2019;1224';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2019-02-05;388';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2011-06-28;1695';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2024-06-06;24786';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2024;1500';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;aresp:2016-09-15;905875-1563579';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;plenario:acordao;adi:2021-09-08;6476-5949232';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2023-10-10;3573-2014-482-1-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2022-08-10;100941-2018-482-1-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2023-06-13;2041463-2306626';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2021-11-17;919-2016-35-7-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;ag:2024-06-05;2947-2016-2-22-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2023-05-10;1001046-2017-712-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2023-12-05;86-2017-3-17-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2024-08-02;14948';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:2023-03-16;2';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2023-12-26;48738';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2023;2308';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2024-09-27;14990';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2024-07-26;24940';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2022;725';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2023;3173';
UPDATE lexml_documents_corrected SET 
    locality = 'Amazonas',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;amazonas:estadual:lei:2025-01-14;7369';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-10-09;4907';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2024;1086';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1990-03-07;2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-07-06;3452';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2022;1878';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.resolucao;prs:2023;24';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2008-12-10;242340-2003-18-2-40';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-11-28;5751';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:1856-04-25;25';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2022;1880';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2024;3027';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 4ª Câmara. 3ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.4;turma.ordinaria.3:acordao:2009-07-07;3403-000.053,4639876';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 4ª Câmara. 3ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.4;turma.ordinaria.3:acordao:2009-07-08;3403-000.054,4733878';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Segundo Conselho de Contribuintes. 3ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:segundo.conselho.contribuintes;camara.3;turma.ordinaria:acordao:2005-08-10;203-10.361,4657893';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Segundo Conselho de Contribuintes. 3ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:segundo.conselho.contribuintes;camara.3;turma.ordinaria:acordao:2005-08-10;203-10.359,4705749';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Segundo Conselho de Contribuintes. 3ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:segundo.conselho.contribuintes;camara.3;turma.ordinaria:acordao:2005-08-10;203-10.360,4705740';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 4ª Câmara. 1ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.4;turma.ordinaria.1:acordao:2019-05-22;3401-006.210,7776677';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-12-28;5816';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2005-06-08;256100-1999-16-5-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2008-05-28;2115200-2002-902-2-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2016-02-26;0010503-98.2015.5.03.0114';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2023;5816';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 4ª Câmara. 3ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.4;turma.ordinaria.3:acordao:2013-05-21;3403-002.190,4897460';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;airr:2006-10-04;29140-2005-88-3-40';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2015-08-19;1009-2012-138-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2015-11-18;2960';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2016-08-17;2109';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:emenda.constitucional:2023-12-20;132';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2025-01-22;15103';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 3ª Turma Especial',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;turma.especial.3:acordao:2010-09-29;3803-000.700,4621693';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2024-09-25;0010118-08.2024.5.03.0027';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1942-08-25;10322';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1994-05-30;seq-sf-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2013-10-01;6468';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;airr:2011-11-09;45300-2009-203-4-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2012-07-02;0001431-73.2011.5.03.0067';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2011-08-10;0000803-62.2010.5.03.0021';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;ag:2023-12-13;1000616-2022-63-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2016-10-05;1196-2010-6-5-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2021-08-25;1007-2017-101-10-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2023-12-15;0010386-24.2021.5.03.0009';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2024-02-26;0010372-25.2023.5.03.0153';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2024-04-15;0010405-72.2023.5.03.0037';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;rr:2018-12-05;10326-2014-44-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2023-03-14;2028250-2262524';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2023-08-22;2071747-2327820';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1962-07-12;48934-';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto.lei:1946-12-31;16665';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;re:1952-08-05;18771-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2009-06-09;1101578-942965';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1951-07-20;15908-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1956-12-06;30575-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;re:1957-10-08;33831-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1955-06-02;28298-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1959-07-09;39087-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2020-09-08;1714568-1979978';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;resp:2022-10-04;1823417-2253763';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:2019-05-28;1789002-1844032';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;aresp:2022-12-13;767766-2253283';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1981-09-08;94985-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1970-03-17;69598-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;plenario:acordao;re:1966-08-18;34756-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;plenario:acordao;re:1959-07-13;29448-';
UPDATE lexml_documents_corrected SET 
    locality = '24ª Região - Mato Grosso do Sul',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.24:tribunal.regional.trabalho;turma.2:acordao:2013-07-03;0000301-70.2012.5.24.0021';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2022-12-06;2022552-2239712';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;re:1951-04-24;18351-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2021-09-15;11240-2014-51-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;rr:2016-05-18;427-2014-66-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1975-03-18;65663-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.2:acordao;re:1982-11-23;78071-1438856';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Terceiro Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:terceiro.conselho.contribuintes;camara.2;turma.ordinaria:acordao:1995-06-27;302-33052,4817572';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2020-09-09;20732-2017-292-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;rr:2013-02-27;165-2010-152-3-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2023-10-26;0010136-86.2017.5.03.0152';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2017-06-21;0011345-43.2016.5.03.0179';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2017-10-06;0010227-50.2016.5.03.0173';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.6:acordao:2022-03-29;0012206-13.2017.5.03.0173';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2022-06-07;0010589-58.2019.5.03.0040';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2022-09-05;0010039-13.2021.5.03.0131';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2022-11-17;0011032-42.2021.5.03.0071';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2023-02-13;0010566-11.2017.5.03.0064';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2023-05-18;0010353-07.2021.5.03.0018';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.decreto.legislativo;pds:2015;386';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;aresp:2023-10-09;1865155-2356021';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2008-06-10;6790';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2012-09-18;453882-1219933';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2003-08-12;514675-501063';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2003-08-19;528222-513040';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Seção',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;secao.1:acordao;eresp:2011-02-23;887360-1097227';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:2001-08-21;308734-440937';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2024-04-25;48805';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Terceiro Conselho de Contribuintes. 3ª Câmara. Turma Ordinaria',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:terceiro.conselho.contribuintes;camara.3;turma.ordinaria:acordao:1999-04-13;303-29.079,4695937';
UPDATE lexml_documents_corrected SET 
    locality = 'Veranópolis - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;veranopolis:municipal:decreto:2020-11-17;6742';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;aresp:2017-06-20;1026274-1672557';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:1950-01-07;630';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pls:1995;321';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Criminal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.criminal.2:acordao:2010-06-18;430292';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:2023-08-15;4170';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1940-11-11;6518';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.decreto.legislativo;pdc:2005-02-16;1550';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.decreto.legislativo;pdc:2005-03-03;1560';
UPDATE lexml_documents_corrected SET 
    locality = 'Cabedelo - PB',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;paraiba;cabedelo:municipal:lei:1973-06-22;219';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.3:acordao:2017-10-26;01180000720025010043';
UPDATE lexml_documents_corrected SET 
    locality = 'Vacaria - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;vacaria:municipal:lei:1960-03-07;429';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:2008-11-04;887360-893477';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:2009-03-19;965583-925409';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1941-06-21;7422';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1939-12-09;4991';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2002-07-11;10517';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2020-12-03;5345';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1860-09-05;2636-a';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1882-02-18;8434';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;resp:2010-03-04;494372-1005115';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2008-12-04;1081788-914557';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Recursal dos Juizados Especiais Cíveis e Criminais do DF',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.recursal.juizados.especiais.civeis.criminais.df.2:acordao:2005-06-15;218772';
UPDATE lexml_documents_corrected SET 
    locality = '24ª Região - Mato Grosso do Sul',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.24:tribunal.regional.trabalho;turma.2:acordao:2010-11-10;0071300-95.2009.5.24.0007';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:1953-11-19;20879-';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2024-10-08;14993';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-03-21;11003';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2020-04-27;2193';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2023-07-13;24396';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2021-10-26;3733';
UPDATE lexml_documents_corrected SET 
    locality = 'Amazonas',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;amazonas:estadual:lei:2024-09-30;7096';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2021-11-03;3865';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2022;1879';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2020;528';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-08-01;847';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-30;838';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1981-09-30;17758';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2011-06-09;2927';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2004-12-24;417';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1999-11-12;316';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1966-11-21;65';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2011-06-06;2928';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1947-10-13;23838';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1996-08-30;1517';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1996-10-31;1517-2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1996-10-01;1517-1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1996-11-29;1517-3';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1996-12-18;1557';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1997-01-16;1557-5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1997-02-13;1557-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1997-03-14;9445';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:1964-06-08;973';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2018-05-30;838';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2018-07-31;847';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1959-11-16;47235';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2014-05-07;4640';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1997-08-14;2302';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2004-01-30;4969';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2005-12-29;5650';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2006-12-26;5998';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2007-12-19;6311';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2008-12-29;6717';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2010-01-26;7077';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2016-03-23;13263';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1952-11-05;31721';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2019-10-16;899';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2005-06-15;252';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2023-06-30;1178';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-06-12;981';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1276';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2021-04-28;1046';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-03-19;925';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2022-02-22;1101';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2021-04-28;1045';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2021-07-30;1059';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024-04-30;1214';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-03-22;927';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-04-08;950';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2025;1288';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1237';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1243';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1223';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1244';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1281';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-04-03;945';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1540';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1507';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1549';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1535';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1477';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1559';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1998;1477';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1998;1604';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1512';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1475';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1463';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1554';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1482';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1480';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1479';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1469';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1565';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1998;1569';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1998;1475';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1473';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;832';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1976-06-09;77789';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1983-10-06;88821';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2018-05-27;832';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2018-08-08;13703';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1983-10-06;2063';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1986-06-20;92804';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1975-12-26;1438';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1980-07-10;6813';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1963-02-20;51727';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1977-11-17;80760';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2007-01-05;11442';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1977-11-17;1582';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2009-03-04;11909';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1997-08-06;9478';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2017-08-18;795';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2022-05-18;1118';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:emenda.constitucional:2015-04-16;87';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2023-01-12;1159';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2023-11-22;1197';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1257';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1986-01-31;92353';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1985-02-14;90958';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2019-08-08;9964';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2024;2798';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-08-29;4196';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2024-12-20;25073';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1991-07-10;174';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1974-07-23;1338';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2009-07-22;6909';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2014-07-09;651';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2010-07-27;497';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2024-07-10;12106';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1969-07-17;64833';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1998-05-07;39575';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho.7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2011-11-18;00728006920035010001';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1978-12-07;1642';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.legislativo:1976-05-25;43';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;rr:2010-06-09;2317800-2001-7-9-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 1ª Seção de Julgamento. 4ª Câmara. 1ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.1;camara.4;turma.ordinaria.1:acordao:2017-07-26;1401-002.005,6911261';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2010-06-11;12249';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1976-07-13;17986';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais:acordao:2020-07-29;2001-003.578,8434356';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais:acordao:2020-07-29;2001-003.565,8434358';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;ag:2001-08-07;355821-416016';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 4ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.4;turma.ordinaria:acordao:2003-07-01;104-19.422,4677734';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 3ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.3;turma.ordinaria:acordao:2007-11-07;103-23.263,4651526';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2012-09-17;12715';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes.7ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.7;turma.ordinaria:acordao:2007-03-28;107-08.941,4648828';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2009-11-20;45218';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.2;turma.ordinaria:acordao:2002-11-07;102-45.837,4657251';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. Câmara Superior de Recursos Fiscais. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;camara.superior.recursos.fiscais;turma.1:acordao:2001-07-24;csrf/01-03.458,4636006';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.2;turma.ordinaria:acordao:2005-07-07;102-46.947,4710686';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:constituicao:1947-07-14;1947';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Segundo Conselho de Contribuintes. 3ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:segundo.conselho.contribuintes;camara.3;turma.ordinaria:acordao:1995-12-07;203-02546,4820984';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.2;turma.ordinaria:acordao:2001-07-25;102-44.905,4725648';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 4ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.4;turma.ordinaria:acordao:2004-07-07;104-20.060,4652001';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2017-06-30;22549';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2014-11-13;13043';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 1ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.1;turma.ordinaria:acordao:2007-11-07;101-96.417,4652054';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 2ª Seção de Julgamento. 3ª Câmara. 1ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.2;camara.3;turma.ordinaria.1:acordao:2010-07-08;2301-001.591,7428327';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 2ª Turma Especial',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;turma.especial.2:acordao:2014-07-24;3802-003.387,5634249';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.2;turma.ordinaria:acordao:2000-12-07;102-44572,4655042';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.2;turma.ordinaria:acordao:2000-06-07;102-44306,4661462';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.2;turma.ordinaria:acordao:2000-06-07;102-44302,4690751';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.2;turma.ordinaria:acordao:2000-06-07;102-44301,4692383';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:1999-06-07;115623';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 10ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.10:acordao:2022-08-09;0010548-82.2021.5.03.0085';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;ag:2002-11-05;420976-470172';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Recursal dos Juizados Especiais Cíveis e Criminais do DF',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.recursal.juizados.especiais.civeis.criminais.df.1:acordao:2001-08-14;144063';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:1999-03-09;127961-260997';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:2001-09-03;144127';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.3:acordao;re:1966-05-05;31038-';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 5ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.5:acordao:1998-09-03;110469';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.4:acordao:2011-05-02;00849007220085010521';
UPDATE lexml_documents_corrected SET 
    locality = '13ª Região - Paraíba',
    authority = 'Tribunal Regional do Trabalho. Tribunal Pleno',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.13:tribunal.regional.trabalho;tribunal.pleno:acordao:2008-07-15;101036';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2021-05-19;1050';
UPDATE lexml_documents_corrected SET 
    locality = 'Arinos - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;arinos:municipal:lei:1971-04-29;100';
UPDATE lexml_documents_corrected SET 
    locality = 'Itabirito - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;itabirito:municipal:lei:1996-03-27;1951';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2012-05-30;58093';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1957-08-02;416';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1981-12-03;6812';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1972-01-28;961';
UPDATE lexml_documents_corrected SET 
    locality = 'Domingos Martins - ES',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;espirito.santo;domingos.martins:municipal:lei:1967-06-16;252';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1942-04-17;4272';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1973-12-04;73249';
UPDATE lexml_documents_corrected SET 
    locality = 'Domingos Martins - ES',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;espirito.santo;domingos.martins:municipal:lei:1975-03-25;687';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1986-12-10;2305';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:2002-10-21;1150';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto.lei:1941-09-09;12162';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1984-09-19;5468';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1964-03-23;603';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1950-11-09;28844';
UPDATE lexml_documents_corrected SET 
    locality = 'Catanduva - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;catanduva:municipal:lei:1982-05-14;1892';
UPDATE lexml_documents_corrected SET 
    locality = 'Itabirito - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;itabirito:municipal:lei:2003-09-11;2293';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1956-07-12;39568';
UPDATE lexml_documents_corrected SET 
    locality = 'Catanduva - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;catanduva:municipal:lei:2007-10-04;4464';
UPDATE lexml_documents_corrected SET 
    locality = 'Itabirito - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;itabirito:municipal:lei:1991-04-03;1630';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto.lei:1944-11-21;14298';
UPDATE lexml_documents_corrected SET 
    locality = 'Arinos - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;arinos:municipal:lei:1970-04-13;86';
UPDATE lexml_documents_corrected SET 
    locality = 'Ponte Nova - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;ponte.nova:municipal:lei:1948-06-25;21';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Recursal dos Juizados Especiais Cíveis e Criminais do DF',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.recursal.juizados.especiais.civeis.criminais.df.1:acordao:1999-06-29;117182';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2013-12-30;46413';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto.lei:1945-11-16;1413';
UPDATE lexml_documents_corrected SET 
    locality = 'Boa Vista - RR',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;roraima;boa.vista:municipal:lei:2024-08-15;2640';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2014-11-19;13044';
UPDATE lexml_documents_corrected SET 
    locality = '16ª Região - Maranhão',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.16:tribunal.regional.trabalho;turma.2:acordao:2013-07-02;0099100-96.2009.5.16.0015';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2005-10-13;3681';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2013-12-27;21067';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Recursal dos Juizados Especiais Cíveis e Criminais do DF',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.recursal.juizados.especiais.civeis.criminais.df.1:acordao:1999-12-14;122998';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2016-12-23;762';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;831';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1987-12-23;2404';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1938-10-19;9654';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1966-11-14;29';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1980-08-18;1801';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1939-01-20;1062';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1937-02-03;388';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1988-02-12;2414';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1970-12-30;1142';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1933-10-07;6112';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1931-09-29;20454';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1912-11-13;9875';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:1948-12-20;322';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1928-01-20;18076';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1934-01-19;6274';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2010-09-02;1057828-1050275';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;ag:2023-05-24;1001429-2015-311-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Passo do Sobrado - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;passo.sobrado:municipal:decreto:2009-05-13;31';
UPDATE lexml_documents_corrected SET 
    locality = 'Estrela - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;estrela:municipal:lei:2007-06-13;4447';
UPDATE lexml_documents_corrected SET 
    locality = 'Santo Antônio do Planalto - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;santo.antonio.planalto:municipal:lei:2013-12-03;1263';
UPDATE lexml_documents_corrected SET 
    locality = 'Passo do Sobrado - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;passo.sobrado:municipal:decreto:2014-12-29;115';
UPDATE lexml_documents_corrected SET 
    locality = 'São Sebastião do Caí - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;sao.sebastiao.cai:municipal:lei:2015-01-27;3767';
UPDATE lexml_documents_corrected SET 
    locality = 'Dom Pedro de Alcântara - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;dom.pedro.alcantara:municipal:lei:2010-12-20;1134';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2012-09-28;7816';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2013-12-23;8171';
UPDATE lexml_documents_corrected SET 
    locality = 'Passo do Sobrado - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;passo.sobrado:municipal:lei:2009-05-12;1103';
UPDATE lexml_documents_corrected SET 
    locality = 'Fazenda Vilanova - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;fazenda.vilanova:municipal:lei:2014-04-03;1473';
UPDATE lexml_documents_corrected SET 
    locality = 'Dom Pedro de Alcântara - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;dom.pedro.alcantara:municipal:lei:2013-02-07;1328';
UPDATE lexml_documents_corrected SET 
    locality = 'Arroio do Padre - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;arroio.padre:municipal:lei:2013-08-07;1361';
UPDATE lexml_documents_corrected SET 
    locality = 'Ernestina - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;ernestina:municipal:lei:2019-11-06;2655';
UPDATE lexml_documents_corrected SET 
    locality = 'Lagarto - SE',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sergipe;lagarto:municipal:lei:1971-12-03;259';
UPDATE lexml_documents_corrected SET 
    locality = 'Passa Sete - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;passa.sete:municipal:lei:2007-10-30;751';
UPDATE lexml_documents_corrected SET 
    locality = 'Capela de Santana - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;capela.santana:municipal:lei:2009-04-29;1100';
UPDATE lexml_documents_corrected SET 
    locality = 'Fazenda Vilanova - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;fazenda.vilanova:municipal:lei:2014-06-10;1500';
UPDATE lexml_documents_corrected SET 
    locality = 'Sobradinho - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;sobradinho:municipal:lei:2011-12-09;3580';
UPDATE lexml_documents_corrected SET 
    locality = 'Mococa - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;mococa:municipal:lei:1974-06-24;1089';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2015-02-24;0000446-88.2014.5.03.0103';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;rr:2013-08-14;880-2011-662-9-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;rr:2019-08-07;21259-2017-402-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;rr:2005-03-16;13400-1998-9-5-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:1998-12-09;430722-1998-5555-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2008-06-17;931556-854523';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2021-10-05;1925025-2101591';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2017-03-29;53800-2012-14-17-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2025-02-03;0010600-45.2023.5.03.0041';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.5:acordao;hc:2021-04-06;635509-2040925';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2010-08-05;00732001320065010055';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;rr:2019-03-13;10287-2014-44-15-0';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2007-05-09;00178006320065010071';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2009-05-06;01227009520065010201';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2009-09-24;00700002720065010401';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2010-04-12;00831009820065010223';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2010-06-10;01081005820065010043';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2010-08-25;01546001920085010010';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2008-07-25;00857005220075010322';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2009-05-19;00404000720065010224';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1986-11-11;8976';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1986-07-04;8847';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1985-07-25;8545';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1988-03-22;9471';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1987-06-16;9183';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1987-05-12;9154';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1988-12-23;6030';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1984-11-22;8280';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2000-07-26;13414';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1988-08-12;9589';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1996-09-27;8963';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1961-05-05;50555';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2014-12-01;18577';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1997-06-13;9301';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1997-05-23;9282';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2012-04-24;17569';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1985-08-02;23752';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1980-12-30;16503';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:1998-11-05;144850-261495';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2000-08-08;212142-368099';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:1999-09-14;220004-297915';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1999-09-23;10250';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:1997-11-07;128752-208914';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1227';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2023-12-29;1202';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2009-01-27;350';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2013-03-26;535';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1984-02-28;23474';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2010-06-02;986';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2013-04-22;1491';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2005-08-11;163';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1999-12-23;350';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-11-28;657';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2008-02-01;613';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2009-03-04;779';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2009-02-04;775';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1997-12-30;025';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1998-05-11;154';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2001-12-26;600';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2001-02-02;021';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1983-06-27;22860';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1997-12-09;003';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2009-04-06;792';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2010-05-06;981';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1998-10-05;315';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2000-07-20;274';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1999-08-05;238';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1997-12-31;033';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2000-04-07;086';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2008-12-19;751';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2004-09-29;085';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2005-01-27;144';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2006-02-03;208';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2001-12-26;596';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2010-04-30;2366';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2000-08-31;335';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1998-08-14;261';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-12-26;784';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2009-11-03;903';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-01-30;036';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2013-07-03;4190';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;ai:2012-05-22;842865-4157324';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2001;2165';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Administração Federal e Reforma do Estado',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.administracao.federal.reforma.estado:instrucao.normativa:1998-04-29;3';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Administração Federal e Reforma do Estado',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.administracao.federal.reforma.estado:instrucao.normativa:1998-05-28;4';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Administração Federal e Reforma do Estado',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.administracao.federal.reforma.estado:instrucao.normativa:1998-04-29;1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal:instrucao.normativa:2001-12-05;98';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Administração Federal e Reforma do Estado',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.administracao.federal.reforma.estado:instrucao.normativa:1998-07-17;5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal:instrucao.normativa:1995-04-07;19';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao:instrucao.normativa:2010-01-18;2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao:instrucao.normativa:2010-01-15;1';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Corregedoria',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;corregedoria:instrucao.normativa:2013-05-23;1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2007-05-02;736';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho:instrucao.normativa:2003-12-11;1';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho:instrucao.normativa:1998-07-01;1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal:instrucao.normativa:1994-02-07;2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2016-05-30;1646';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2012-05-10;1268';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2012-01-11;1238';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Instituto Nacional do Seguro Social',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:instituto.nacional.seguro.social:instrucao.normativa:2007-04-09;17';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2018-06-13;1810';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal:instrucao.normativa:1994-03-14;10';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Administração Federal e Reforma do Estado',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.administracao.federal.reforma.estado:instrucao.normativa:1997-09-05;12';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2013-12-19;1425';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2017-01-31;1688';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão. Secretaria de Logística e Tecnologia da Informação',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao;secretaria.logistica.tecnologia.informacao:instrucao.normativa:2009-10-15;3';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Administração Federal e Reforma do Estado',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.administracao.federal.reforma.estado:instrucao.normativa:1995-11-21;8';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Administração Federal e Reforma do Estado',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.administracao.federal.reforma.estado:instrucao.normativa:1997-06-16;6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2005-08-23;563';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2007-11-19;785';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2008-04-02;836';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2009-07-29;960';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2013-12-06;1417';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2014-03-10;1456';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2016-12-02;1676';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2016-12-22;1678';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal:instrucao.normativa:1993-06-11;5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Instituto Nacional do Seguro Social',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:instituto.nacional.seguro.social:instrucao.normativa:2009-10-09;41';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Instituto Nacional do Seguro Social',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:instituto.nacional.seguro.social:instrucao.normativa:2010-11-09;48';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão. Secretaria de Logística e Tecnologia da Informação',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao;secretaria.logistica.tecnologia.informacao:instrucao.normativa:2009-11-11;4';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal:instrucao.normativa:1993-06-11;6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério de Orçamento e Gestão. Secretaria de Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.orcamento.gestao;secretaria.gestao:instrucao.normativa:2010-03-18;5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:instrucao.normativa:2008-03-18;831';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2006-12-29;11438';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2007-05-31;11484';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2011-08-09;4611';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1991-12-23;8313';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1280';
UPDATE lexml_documents_corrected SET 
    locality = 'Arroio Grande - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;arroio.grande:municipal:decreto:2013-12-06;406';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;airr:2013-09-04;1634-2011-142-3-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2023-07-05;0010215-21.2023.5.03.0131';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2016-08-31;293-2015-111-18-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2013-04-02;0000356-43.2012.5.03.0041';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2025-02-26;0010465-42.2024.5.03.0156';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2018-08-15;10529-2015-111-18-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2011-03-22;0001123-60.2010.5.03.0103';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2012-05-02;0000211-18.2011.5.03.0042';
UPDATE lexml_documents_corrected SET 
    locality = '8ª Região - Pará e Amapá',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.8:tribunal.regional.trabalho;turma.1:acordao:2014-03-25;0001143-30.2012.5.08.0010';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.6:acordao:2015-08-04;0000995-44.2012.5.03.0079';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2017-03-22;989-2015-111-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2016-06-01;208-2015-111-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;ag:2023-06-07;1077-2017-8-23-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2016-06-29;193-2015-111-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;ag:2023-05-24;542-2020-141-14-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2011-12-02;0000690-02.2010.5.03.0024';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2016-10-19;143-2015-111-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2016-11-23;181-2015-111-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2017-04-05;10039-2015-111-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2020-11-18;10386-2017-127-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;arr:2015-04-29;2107-2011-28-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2005-01-13;11097';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2004;60';
UPDATE lexml_documents_corrected SET 
    locality = 'Uberaba - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;uberaba:municipal:lei:2008-04-19;10354';
UPDATE lexml_documents_corrected SET 
    locality = 'Uberaba - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;uberaba:municipal:lei:2006-02-25;9900';
UPDATE lexml_documents_corrected SET 
    locality = 'Catanduva - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;catanduva:municipal:lei:2007-05-25;4403';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2014-09-24;13033';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2005-05-20;5448';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2018-05-08;9365';
UPDATE lexml_documents_corrected SET 
    locality = 'Rondônia',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rondonia:estadual:lei:2009-12-21;2214';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2004-12-06;5297';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2014-05-28;647';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2004-12-06;227';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2014-10-20;4882';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-10-22;10527';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2015-02-10;5051';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2012-06-27;7768';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2005-05-18;11116';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2015-08-13;5409';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2024-01-30;11902';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2005-06-06;5457';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2008-10-21;6606';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2022-10-11;67169';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2015-08-13;5410';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2007-12-12;1109';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2023-01-01;1157';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2021-05-28;10708';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2022-09-06;12568';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto.legislativo:2021-12-17;2354';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2021-09-13;10507';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2008-05-14;6458';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2016-02-24;46957';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1996-09-17;1508-9';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1966-09-02;59170';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2010-09-10;7297';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2004-09-30;5222';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2008-09-26;6582';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2024-09-11;12175';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1870-09-15;4598';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1967-09-29;5323';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1975-09-03;1418';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1997-09-10;9493';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2008-09-17;11774';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1964-09-29;4419';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2004-09-30;219';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1977-09-23;1575';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:1967;78';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:1964;154';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:1997;1508';
UPDATE lexml_documents_corrected SET 
    locality = 'Carneirinho - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;carneirinho:municipal:decreto:2006-09-11;966';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2009-06-09;7002';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1975-10-09;76407';
UPDATE lexml_documents_corrected SET 
    locality = 'Jari - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;jari:municipal:lei:2015-09-09;2112';
UPDATE lexml_documents_corrected SET 
    locality = 'Sant''Ana do Livramento - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;sant.ana.livramento:municipal:decreto:1995-05-09;1985';
UPDATE lexml_documents_corrected SET 
    locality = 'Erval Seco - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;erval.seco:municipal:decreto:2000-10-09;28';
UPDATE lexml_documents_corrected SET 
    locality = 'Arvorezinha - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;arvorezinha:municipal:decreto:2013-07-09;1998';
UPDATE lexml_documents_corrected SET 
    locality = 'Progresso - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;progresso:municipal:lei:2017-03-09;2278';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho.9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.9:acordao:2016-03-07;00015922520115010072';
UPDATE lexml_documents_corrected SET 
    locality = 'Passa Sete - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;passa.sete:municipal:lei:2008-09-09;815';
UPDATE lexml_documents_corrected SET 
    locality = 'Paverama - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;paverama:municipal:lei:2007-04-09;1801';
UPDATE lexml_documents_corrected SET 
    locality = 'Vila Maria - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;vila.maria:municipal:lei:2010-03-09;2616';
UPDATE lexml_documents_corrected SET 
    locality = 'Engenho Velho - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;engenho.velho:municipal:lei:2013-04-09;780';
UPDATE lexml_documents_corrected SET 
    locality = 'Ajuricaba - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;ajuricaba:municipal:lei:2014-04-09;2511';
UPDATE lexml_documents_corrected SET 
    locality = 'São Jerônimo - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;sao.jeronimo:municipal:lei:2018-05-09;3651';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.2:acordao:2010-09-09;00660003319965010013';
UPDATE lexml_documents_corrected SET 
    locality = 'Bossoroca - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;bossoroca:municipal:lei:2020-04-09;4492';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 10ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.10:acordao:2022-09-29;0010638-24.2021.5.03.0010';
UPDATE lexml_documents_corrected SET 
    locality = 'Palmitinho - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;palmitinho:municipal:decreto:2019-10-09;69';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2014-09-01;46590';
UPDATE lexml_documents_corrected SET 
    locality = 'Horizontina - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;horizontina:municipal:decreto:2010-07-09;3515';
UPDATE lexml_documents_corrected SET 
    locality = 'Pinhal Grande - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;pinhal.grande:municipal:lei:2014-04-09;2186';
UPDATE lexml_documents_corrected SET 
    locality = 'Nova Candelária - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;nova.candelaria:municipal:lei:2018-10-09;1131';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Seção',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;secao.1:acordao;ms:2022-03-23;28123-2148316';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2022-01-27;0011944-27.2016.5.03.0164';
UPDATE lexml_documents_corrected SET 
    locality = 'MinasGerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2022-07-01;48456';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2020-01-28;0010795-18.2018.5.03.0134';
UPDATE lexml_documents_corrected SET 
    locality = 'MinasGerais',
    authority = 'Assembléia Legislativa',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:assembleia.legislativa:deliberacao:2008-12-01;2435';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.6:acordao:2023-01-31;0010730-89.2018.5.03.0112';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2018-01-31;0010232-86.2016.5.03.0136';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2023-01-31;01000647220215010246';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2022-01-26;0010019-76.2021.5.03.0016';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2018-12-11;0010157-10.2017.5.03.0040';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2022-07-06;0010150-67.2021.5.03.0043';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 10ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.10:acordao:2020-01-29;0012237-87.2016.5.03.0134';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.5:acordao:2011-01-17;00702009420095010056';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 10ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.10:acordao:2011-01-31;0000304-32.2010.5.03.0004';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.8:acordao:2012-11-22;00014227520105010076';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.6:acordao:2023-01-31;0011018-12.2017.5.03.0164';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;rr:2023-06-21;1-2013-761-4-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2020-02-06;0010977-26.2017.5.03.0041';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2004-02-17;504994-541840';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2024-08-01;0010391-40.2024.5.03.0074';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.3:acordao:2018-03-23;00000160720175010421';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:2006-03-14;719866-674769';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2016-09-01;0010126-39.2015.5.03.0111';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2016-09-01;0010673-44.2015.5.03.0058';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2018-09-05;0010394-47.2017.5.03.0039';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2017-06-09;0011035-62.2016.5.03.0106';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2021-05-21;0011407-18.2015.5.03.0018';
UPDATE lexml_documents_corrected SET 
    locality = 'MinasGerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2023-06-30;48646';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2023-06-15;0011340-34.2019.5.03.0173';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2024-03-11;0010480-27.2023.5.03.0065';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2019-07-10;0011143-40.2017.5.03.0144';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2022-09-05;0010201-09.2021.5.03.0066';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2023-05-17;0011328-20.2018.5.03.0152';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2014-11-11;0010077-70.2014.5.03.0163';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2016-09-02;0010432-96.2015.5.03.0017';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2006-08-28;01551-2006-148-03-00-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;ag:2023-06-07;101847-2019-481-1-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2022-04-01;0010216-08.2021.5.03.0153';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - MinasGerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2014-03-26;0000653-29.2013.5.03.0069';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho.1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;rr:2015-05-06;150500-2008-53-1-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Terceiro Conselho de Contribuintes.1ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:terceiro.conselho.contribuintes;camara.1;turma.ordinaria:acordao:2008-07-10;301-34652,4717487';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-09-18;4516';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2010-05-07;7172';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2015-03-26;1865';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 5ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.5;turma.ordinaria:acordao:2006-11-08;105-16.112,4660308';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;rr:2008-10-01;75600-2005-22-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;rr:2016-03-09;133700-2007-443-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;rr:2011-09-14;41600-2006-29-1-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;airr:2021-02-10;1137-2013-7-9-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.5:acordao;rms:2021-08-10;63567-2079364';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2017;18';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2016;2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2022;39';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2018;45';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2006-12-21;7703';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2023;25';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2001-07-16;10264';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024-04-10;1212';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pls:1999;491';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2001-02-12;10186';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2005-02-09;11101';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2000;74';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2009-12-23;6719';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2020-07-15;14026';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1993-12-07;8742';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2006-12-22;11428';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1979-12-19;6766';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2000-12-19;10098';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1993-07-20;8685';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2013;8';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2017;31';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2008;114';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2004;10';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pls:1989;249';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1974-05-24;6050';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2008-12-24;11887';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1989-07-10;7797';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1976-10-19;6367';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2012;114';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2000;21';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:1999;45';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2007-11-13;2419';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2006;37';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2002;106';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2012;34';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:1996;47';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2003;89';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:1991;109';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2008-03-18;28880';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2006-12-19;3923';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1965-07-22;56602';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1984-02-28;23476';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2010-05-10;55791';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2009-08-12;54672';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2010-12-20;56539';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2007-06-15;51901';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2008-07-24;53276';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1969-03-11;496';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:1992-05-05;8575';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2018-08-16;9475';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2001-07-20;2746';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:2004-11-04;209514';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1975-12-11;6288';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2020-03-19;0010487-11.2015.5.03.0029';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2017-09-25;6007';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2015-03-25;36420';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1995-09-18;16758';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2019-10-17;0010108-58.2017.5.03.0075';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2020-10-16;41352';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2016-10-26;37730';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1996-02-26;17159';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 4ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.4:acordao:1999-05-31;116247';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto.legislativo:2021-05-18;2503';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto.legislativo:2021-05-18;2504';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2010-12-30;32711';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2011-01-18;56672';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2008-05-15;53001';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1988-05-18;96044';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2006-01-13;26525';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 4ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.4:acordao:2003-05-19;176413';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1994-08-08;15826';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2012-08-08;58284';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:1997-10-27;1729';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1977-02-03;79205';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2023-01-27;48567';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2022-03-29;11389';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2011-11-10;3186';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2022-10-25;18520';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2013-07-09;622';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2013-10-31;12877';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2013-08-20;8079';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2011-11-10;3187';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2013-03-18;58977';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2014-01-17;8183';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:2011-07-26;14105';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2012-06-21;17629';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2013-06-19;59302';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2022-09-26;67121';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1980-11-19;16162';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2024-06-11;24806';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2022-02-14;1100';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2022-06-14;14367';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2021-12-13;10949';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2020-08-27;9149';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2014-06-18;13000';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2019-04-04;7711';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-10-25;5174';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2021;327';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2024-10-10;14995';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2001-01-10;3724';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1980-12-10;85471';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1999-06-02;1781-10';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1978-03-10;81439';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1923-10-06;16163';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1969-04-10;64338';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1959-09-10;3632';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1976-06-10;77808';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1974-05-10;74045';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1985-10-18;7386';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1968-12-10;63762';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1979-12-10;1727';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2002-07-10;4296';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1994-10-21;1287';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1997-12-10;9532';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1978-10-05;72';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1976-10-04;78528';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1965-10-15;57076';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1995-10-27;55';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei.complementar:2021-10-27;186';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1998-10-29;1715-2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1994-10-20;60';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1994-10-20;61';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1994-10-20;62';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1994-10-20;63';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei.complementar:2023-10-24;201';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1997-10-09;95';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1997-10-09;96';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1975-10-22;76496';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1973-10-16;72934';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2015-10-23;698';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1978-10-09;82390';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1981-10-14;86480';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2013-10-09;12865';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1969-10-13;949';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1998-10-01;1715-1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1999-10-22;1898-15';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2000-10-24;1961-28';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1921-10-19;15052';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2001-10-17;10295';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2013-07-02;556';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2008-02-22;300';
UPDATE lexml_documents_corrected SET 
    locality = 'Rondônia',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rondonia:estadual:lei:2009-10-14;2160';
UPDATE lexml_documents_corrected SET 
    locality = 'Domingos Martins - ES',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;espirito.santo;domingos.martins:municipal:lei:2014-11-03;2649';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2020-08-24;892';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2012-07-24;495';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-09-05;492';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2005-12-15;176';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2006-04-05;215';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2004-10-06;347';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-11-26;644';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2018-11-05;830';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2024-07-12;15415';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2021-03-01;920';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2017-05-15;17145';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2001-06-04;185';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2014-07-10;618';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2016-10-05;737';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2021-03-23;926';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2021-04-06;929';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2024-02-19;9340';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2015-07-02;16655';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2019-06-27;9864';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2006-10-30;233';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2016-05-03;13280';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1998-07-27;242';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1993-12-08;seq-sf-6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2002-12-11;4508';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1992-04-30;13927';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2024-04-19;1086';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2017-04-25;7482';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1999-07-16;226';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2012-07-27;500';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2015-12-08;13203';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2007-03-01;249';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1974-12-19;6194';
UPDATE lexml_documents_corrected SET 
    locality = 'Mangaratiba - RJ',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.janeiro;mangaratiba:municipal:lei:2016-04-07;999';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1952-07-10;241';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1967-01-31;117';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1993-12-27;7747';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1988-08-23;28571';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1985-11-25;7408';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:1994-05-26;186';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:1999-04-15;13201';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:1999-11-17;11223';
UPDATE lexml_documents_corrected SET 
    locality = 'Uberaba - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;uberaba:municipal:lei:1985-10-09;3652';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:1998-08-18;29135-226194';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2018-05-27;833';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2018-08-24;13711';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:1984-11-26;8750';
UPDATE lexml_documents_corrected SET 
    locality = 'Uberaba - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;uberaba:municipal:lei:2004-11-12;9436';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1966-11-18;49';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1967-05-31;60788';
UPDATE lexml_documents_corrected SET 
    locality = 'Catanduva - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;catanduva:municipal:lei:2010-06-16;5018';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.1:acordao:2008-10-15;327789';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2005-11-23;646784-662206';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1987-08-28;27297';
UPDATE lexml_documents_corrected SET 
    locality = 'Itabirito - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;itabirito:municipal:lei:2015-06-01;3073';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1918-05-07;13021';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2015-12-22;8614';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;resp:2000-10-19;247203-380979';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:1997-07-15;1553';
UPDATE lexml_documents_corrected SET 
    locality = 'Itabirito - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;itabirito:municipal:lei:2015-07-03;3080';
UPDATE lexml_documents_corrected SET 
    locality = 'Catanduva - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;catanduva:municipal:lei:2009-11-03;4846';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1961-07-03;50903';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei.complementar:2021-09-22;183';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei.complementar:2006-02-09;121';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2022-01-05;18330';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-07-07;11124';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2022-01-05;14299';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-08-22;4051';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2010-07-02;402';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2023;4653';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2021-10-05;712';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2019;712';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.normativa:2023-04-24;1061';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Seção',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;secao.1:acordao;ms:2022-03-23;28120-2147826';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2000;27';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2022;1271';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 5ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.5:acordao:2010-05-12;422359';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2014-05-28;665-2010-64-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2015-10-14;1305-2010-60-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2016-07-27;22257';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2017-03-31;13429';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2023-06-14;11565';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2021-09-08;10789';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2018-12-17;9613';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-07-22;10437';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2023-12-20;11835';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1992-01-08;417';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1991-01-11;99999';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1966-08-03;58979';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-10-07;10512';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1989-08-17;9898';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1965-04-26;56077';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1977-04-19;79550';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-10-07;10511';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1969-12-15;65875';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1995-03-31;1435';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2024-02-14;11918';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2018-10-17;9533';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2023-01-01;11374';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2023-08-04;11629';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2002-12-04;4496';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1970-06-12;66707';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1934-04-11;24111';
UPDATE lexml_documents_corrected SET 
    locality = 'Carneirinho - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;carneirinho:municipal:decreto:2010-04-20;1315';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1941-12-18;8408';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2017-01-23;8967';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2020-08-13;10459';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1978-02-03;81307';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1948-11-04;25777';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1908-03-19;6894';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-01-29;10954';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1991-01-11;100000';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1969-05-20;64560';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1910-11-11;8373';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-07-01;11118';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1995-07-12;11888';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2023-03-01;11426';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1967-04-28;60659';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1942-10-26;10707';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2021-08-24;10776';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-07-14;11132';
UPDATE lexml_documents_corrected SET 
    locality = 'Armazém- SC',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina;armazem:municipal:lei:2010-06-23;1408';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2004-12-20;13226';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:1980-12-22;5844';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1959-03-16;45574';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1937-09-21;507';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:1968-05-21;4164';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:1998-01-08;10683';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:1998-01-08;10685';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1959-07-14;46419';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2006-04-24;323';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1938-12-27;3489';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1917-10-11;12673';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:1906-10-19;1017';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2012-06-19;15839';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1908-03-25;1584';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:1951-08-27;517';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1956-05-08;39137';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1956-03-21;38916';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1917-10-11;12672';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1940-12-03;2827';
UPDATE lexml_documents_corrected SET 
    locality = 'Uberaba - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;uberaba:municipal:lei:2004-08-02;9326';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto.lei:1943-08-04;13497';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1956-06-01;39298';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1961-04-15;50466';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1921-02-25;3316';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1951-01-17;196';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2007-06-27;01159-2006-072-03-00-2';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1984-03-13;5403';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2005-08-03;00196-2005-040-03-00-8';
UPDATE lexml_documents_corrected SET 
    locality = '8ª Região - Pará e Amapá',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.8:tribunal.regional.trabalho;turma.3:acordao:2014-03-26;0010246-21.2013.5.08.0206';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;rr:2012-08-15;214000-2007-2-15-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2014-09-30;0000037-74.2014.5.03.0148';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2004-04-13;01155-2003-039-03-00-7';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2005-04-06;01955-1998-104-03-00-4';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2005-11-10;00365-2005-043-03-00-9';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2002-04-02;01509-2001-019-03-00-7';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2005-11-10;01172-2005-041-03-00-2';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2009-10-01;00440-2008-032-03-00-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2009-11-17;0050900-41.2009.5.03.0073';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2012-05-23;0001282-86.2010.5.03.0043';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.4:acordao:2023-11-27;0010892-49.2023.5.03.0067';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2023-11-29;0010979-07.2023.5.03.0131';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2024-05-08;0010235-66.2024.5.03.0134';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2019-07-12;0010077-05.2019.5.03.0031';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2022-02-02;0011154-75.2019.5.03.0087';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.4:acordao:2023-05-31;0010100-03.2023.5.03.0033';
UPDATE lexml_documents_corrected SET 
    locality = 'Roque Gonzales - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;roque.gonzales:municipal:lei:2018-10-03;2977';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2025-03-12;0011423-11.2024.5.03.0097';
UPDATE lexml_documents_corrected SET 
    locality = '8ª Região - Pará e Amapá',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.8:tribunal.regional.trabalho;turma.4:acordao:2016-10-18;0001237-37.2015.5.08.0118';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal Militar. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.militar;plenario:acordao:1999-04-15;320_1999010065313';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2002-03-05;6199';
UPDATE lexml_documents_corrected SET 
    locality = 'Mococa - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;mococa:municipal:decreto:1980-01-15;949';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:1962-07-05;6825';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2004-02-04;01453-2003-044-03-00-2';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2010-02-03;0051400-72.2008.5.03.0096';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2012-04-24;0001717-78.2011.5.03.0058';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2023-09-29;0010741-96.2022.5.03.0074';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2018-07-30;0011624-89.2016.5.03.0062';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2019-02-14;0010583-71.2018.5.03.0077';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2021-09-13;0010967-33.2020.5.03.0087';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2022-05-11;0010904-98.2021.5.03.0078';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pls:1995;224';
UPDATE lexml_documents_corrected SET 
    locality = 'Arroio do Tigre - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;arroio.tigre:municipal:lei:2009-04-28;1934';
UPDATE lexml_documents_corrected SET 
    locality = 'Arroio do Tigre - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;arroio.tigre:municipal:lei:2009-11-18;1991';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1977-06-08;79797';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1974-08-30;6094';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1974-10-16;1119';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1964-08-26;54208';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2007-09-20;15988';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2007-10-31;16052';
UPDATE lexml_documents_corrected SET 
    locality = 'Catanduva - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;catanduva:municipal:lei:1998-12-14;3462';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1991-04-02;2883';
UPDATE lexml_documents_corrected SET 
    locality = 'Sete Lagoas - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;sete.lagoas:municipal:lei:1990-04-02;4206';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1967-02-09;3560';
UPDATE lexml_documents_corrected SET 
    locality = '16ª Região - Maranhão',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.16:tribunal.regional.trabalho;turma.1:acordao:2011-03-02;0247900-75.2009.5.16.0012';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2010-05-13;45365';
UPDATE lexml_documents_corrected SET 
    locality = 'Sete Lagoas - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;sete.lagoas:municipal:lei:1999-07-02;5889';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1975-09-23;6242';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2014-11-12;46648';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2020-09-15;6668';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 4ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.4:acordao:2013-03-06;660293';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2005-09-27;26241';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1984-12-19;7290';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2010-01-14;18726';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1963-09-24;2903';
UPDATE lexml_documents_corrected SET 
    locality = 'Catanduva - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;catanduva:municipal:lei:2008-03-10;4521';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:1960-01-07;2034';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2013-07-10;0001194-47.2011.5.03.0129';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:1993-10-26;577';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. Câmara Criminal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;camara.criminal:acordao:2000-03-29;127592';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2008-03-05;00856-2007-036-03-00-3';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2015-10-21;0001424-61.2014.5.03.0072';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2020-07-08;0010942-68.2017.5.03.0105';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2018-02-22;0010132-50.2016.5.03.0163';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.6:acordao:2015-04-14;0000916-45.2014.5.03.0160';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;ag:2020-03-11;11010-2015-83-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;airr:2014-06-18;316600-2010-0-3-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2018-08-24;0010163-25.2017.5.03.0102';
UPDATE lexml_documents_corrected SET 
    locality = '8ª Região - Pará e Amapá',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.8:tribunal.regional.trabalho;turma.2:acordao:2016-10-19;0010486-15.2015.5.08.0117';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2012-09-05;1097-2010-65-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;ag:2018-11-21;17-2015-129-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;ag:2024-03-13;10503-2013-168-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2017-08-30;1756-2014-89-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2015-04-29;237-2013-64-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;airr:2015-12-02;1032-2012-28-3-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.4:acordao:2013-02-20;0000705-83.2011.5.03.0040';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;airr:2017-08-30;10529-2014-114-15-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2012-11-20;0001183-91.2011.5.03.0040';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;ag:2021-03-17;11259-2017-179-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;rr:2015-05-27;54-2011-122-5-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;ag:2022-05-24;11548-2018-122-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;ag:2023-05-03;11313-2017-86-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;ag:2019-02-27;235-2013-31-7-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2020-02-05;1808-2016-654-9-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;ag:2024-06-19;11909-2013-87-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;ag:2022-06-22;1402-2017-5-9-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.6:acordao:2009-06-02;0163300-67.2008.5.03.0029';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;ag:2020-09-02;10003-2016-109-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2020-08-26;10356-2016-168-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;airr:2018-03-07;2259-2014-34-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;airr:2015-10-21;860-2011-102-5-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.5:acordao;hc:2023-06-19;811661-2309271';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;ag:2015-06-29;578-2012-56-12-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;rr:2014-04-02;2014-2010-40-3-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2020-03-05;0010310-54.2019.5.03.0046';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.6:acordao;hc:2014-05-20;285848-1355575';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;rr:2016-06-15;334-2012-122-8-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;airr:2017-10-11;10993-2014-128-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2015-03-11;14-2012-144-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1883-08-25;8998';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1883-02-24;8897';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1930-12-03;9784';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1935-06-21;7225';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1932-12-22;5766';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1933-04-20;5882';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1938-04-01;9079';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1980-12-10;85465';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1969-01-08;63965';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Segundo Conselho de Contribuintes. 1ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:segundo.conselho.contribuintes;camara.1;turma.ordinaria:acordao:1991-02-20;201-66869,4818679';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2011-11-16;2997';
UPDATE lexml_documents_corrected SET 
    locality = '8ª Região - Pará e Amapá',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.8:tribunal.regional.trabalho;turma.2:acordao:2011-12-07;0000555-82.2010.5.08.0013';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:2005-04-05;725983-612266';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:2000-03-20;125952';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;airr:2019-11-27;11953-2016-104-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Segundo Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:segundo.conselho.contribuintes;camara.2;turma.ordinaria:acordao:1991-12-11;202-04709,4835111';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 4ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.4:acordao:2001-06-28;142874';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1997-06-13;1508-18';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1997-07-11;1508-19';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:1997-08-12;1508-20';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Segundo Conselho de Contribuintes. 2ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:segundo.conselho.contribuintes;camara.2;turma.ordinaria:acordao:1986-09-17;202-01.063,6758933';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 2ª Câmara. 1ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.2;turma.ordinaria.1:acordao:2017-03-29;3201-002.638,6744279';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Segundo Conselho de Contribuintes. 3ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:segundo.conselho.contribuintes;camara.3;turma.ordinaria:acordao:2004-09-14;203-09742,4838528';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 4ª Câmara. 2ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.4;turma.ordinaria.2:acordao:2016-06-21;3402-003.102,6437593';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 2ª Seção de Julgamento. 1ª Câmara. 2ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.2;camara.1;turma.ordinaria.2:acordao:2009-10-30;2102-000.392,4612579';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2024-02-27;1802289-2394885';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:2004-11-04;667950-584536';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 2ª Câmara. 1ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.2;turma.ordinaria.1:acordao:2014-05-28;3201-001.646,5748559';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2010-08-18;2044';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1995-05-19;36884';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;ag:2006-02-02;703431-666353';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Procuradoria-Geral',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:procuradoria.geral:resolucao:2020-10-16;2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2004-01-16;001';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1951-02-14;8';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1997-11-20;123';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1984-02-20;1';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1985-02-21;1';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:2013-11-21;492';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1980-11-24;14';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2001-11-07;477';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2001-03-30;100';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-12-22;676';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-07-19;391';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1998-12-24;426';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:resolucao:2003-12-11;3';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:2013-02-14;471';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-04-24;219';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-04-10;182';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2000-03-02;057';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-05-23;270';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-05-23;278';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-11-07;614';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-05-29;288';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-05-23;272';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-08-30;486';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1994-11-22;17';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1994-12-22;21';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1999-10-28;176';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1992-03-17;2';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:1996-02-22;56';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-09-18;476';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-11-06;609';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-05-08;253';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-12-04;644';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-03-26;120';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-10-22;556';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-07-01;308';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:camara.municipal:resolucao:2008-01-15;367';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-09-18;474';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-05-22;238';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2003-12-24;680';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2019;49';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2021;44';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2023-12-29;1204';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2019;42';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2020;22';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1278';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1252';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1282';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1275';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2017-10-20;38571';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2010-12-08;32563';
UPDATE lexml_documents_corrected SET 
    locality = 'Ponte Nova - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;ponte.nova:municipal:lei:2003-07-24;2674';
UPDATE lexml_documents_corrected SET 
    locality = 'Ponte Nova - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;ponte.nova:municipal:lei:2012-04-09;3671';
UPDATE lexml_documents_corrected SET 
    locality = 'Ponte Nova - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;ponte.nova:municipal:lei:1991-11-09;1683';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2006-03-28;26683';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1962-11-06;40995';
UPDATE lexml_documents_corrected SET 
    locality = 'Uberaba - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;uberaba:municipal:lei:1988-12-20;4209';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Recursal dos Juizados Especiais Cíveis e Criminais do DF',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.recursal.juizados.especiais.civeis.criminais.df.1:acordao:2001-08-14;144043';
UPDATE lexml_documents_corrected SET 
    locality = 'Miguel Pereira - RJ',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.janeiro;miguel.pereira:municipal:decreto:2011-08-18;3894';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:1964-11-13;8408';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1960-11-23;37545';
UPDATE lexml_documents_corrected SET 
    locality = 'Terra de Areia - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;terra.areia:municipal:lei:1995-12-06;528';
UPDATE lexml_documents_corrected SET 
    locality = 'Herval - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;herval:municipal:lei:2018-04-05;1409';
UPDATE lexml_documents_corrected SET 
    locality = 'Pedras Altas - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;pedras.altas:municipal:decreto:2017-01-04;1772';
UPDATE lexml_documents_corrected SET 
    locality = 'Machadinho - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;machadinho:municipal:lei:2018-08-02;2999';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Margarida do Sul - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;santa.margarida.sul:municipal:lei:2019-05-28;980';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Recursal dos Juizados Especiais Cíveis e Criminais do DF',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.recursal.juizados.especiais.civeis.criminais.df.2:acordao:2010-09-28;459047';
UPDATE lexml_documents_corrected SET 
    locality = 'Capão da Canoa - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;capao.canoa:municipal:lei:2019-12-06;3468';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2005-11-30;6280';
UPDATE lexml_documents_corrected SET 
    locality = 'Anápolis - GO',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;goias;anapolis:municipal:lei:1983-11-25;21';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Vitória do Palmar - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;santa.vitoria.palmar:municipal:lei:2019-01-03;6060';
UPDATE lexml_documents_corrected SET 
    locality = 'Terra de Areia - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;terra.areia:municipal:lei:1995-10-19;520';
UPDATE lexml_documents_corrected SET 
    locality = 'Coronel Bicaco - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;coronel.bicaco:municipal:lei:2010-09-14;3199';
UPDATE lexml_documents_corrected SET 
    locality = 'Parobé - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;parobe:municipal:decreto:2013-03-07;25';
UPDATE lexml_documents_corrected SET 
    locality = 'Parobé - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;parobe:municipal:decreto:2013-03-27;32';
UPDATE lexml_documents_corrected SET 
    locality = 'Itaqui - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;itaqui:municipal:lei:2014-04-25;4036';
UPDATE lexml_documents_corrected SET 
    locality = 'Itaqui - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;itaqui:municipal:lei:2015-03-18;4096';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal Militar. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.militar;plenario:acordao:1987-02-18;40_1986010447423';
UPDATE lexml_documents_corrected SET 
    locality = 'Butiá - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;butia:municipal:decreto:2007-02-16;7';
UPDATE lexml_documents_corrected SET 
    locality = 'Getúlio Vargas - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;getulio.vargas:municipal:lei:2012-04-13;4472';
UPDATE lexml_documents_corrected SET 
    locality = 'Mostardas - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;mostardas:municipal:lei:2017-06-06;3640';
UPDATE lexml_documents_corrected SET 
    locality = 'São Gabriel - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;sao.gabriel:municipal:lei:2015-05-06;3659';
UPDATE lexml_documents_corrected SET 
    locality = 'Canoninhas - SC',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina;canoinhas:municipal:lei:2009-12-22;4484';
UPDATE lexml_documents_corrected SET 
    locality = 'Canoninhas - SC',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina;canoinhas:municipal:lei:2017-04-03;6002';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:decreto:2019-09-20;13474';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:decreto:2020-07-10;13846';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 4ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.4:acordao:2006-11-13;266616';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2009-12-14;0100900-79.2007.5.03.0149';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Terceiro Conselho de Contribuintes. 3ª Câmara. Turma Ordinaria',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:terceiro.conselho.contribuintes;camara.3;turma.ordinaria:acordao:1995-04-25;303-28182,4818003';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Primeiro Conselho de Contribuintes. 6ª Câmara. Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:primeiro.conselho.contribuintes;camara.6;turma.ordinaria:acordao:1999-10-19;106-11001,4688542';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.2:acordao:2003-09-01;181756';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 4ª Câmara. 1ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.4;turma.ordinaria.1:acordao:2018-07-26;3401-005.210,7413696';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.2:acordao:2013-09-11;712275';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2018-05-22;1571571-1727452';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Criminal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.criminal.1:acordao:2006-01-12;239663';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2015-10-06;1521006-1475201';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 5ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.5:acordao:2012-12-13;642529';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;aresp:2020-02-20;1574249-1926417';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;aresp:2022-10-10;694701-2222342';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;rr:2016-06-22;1028-2012-585-9-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;rr:2015-11-18;146500-2008-751-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.decreto.legislativo;pdc:2009-06-30;1664';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.decreto.legislativo;pdc:2010-07-07;2828';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2024-06-10;2111400-2445754';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;ag:2021-09-15;978-2012-291-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;airr:2021-09-29;11323-2017-7-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.5:acordao;rr:2017-05-24;1364-2012-802-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:2007-01-02;12521';
UPDATE lexml_documents_corrected SET 
    locality = 'Domingos Martins - ES',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;espirito.santo;domingos.martins:municipal:lei.complementar:2012-06-26;23';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2008-10-06;44917';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:1996-09-02;46729-130343';
UPDATE lexml_documents_corrected SET 
    locality = 'Mangaratiba - RJ',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.janeiro;mangaratiba:municipal:lei:2022-03-28;1391';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2018-07-05;843';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2018-12-10;13755';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2018-11-08;9557';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-07-06;843';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei.conversao;plv:2018-10-24;27';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:2018-06-06;12';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2020;4121';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2019-03-27;1780';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-07-05;3398';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;arr:2018-12-18;10702-2016-105-3-0';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.5:acordao:2017-05-10;00109048420155010201';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2012-08-02;15855';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:1995;15';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2013;27';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2013;24';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2013;19';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2013;12';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2013;11';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2012;28';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2012;22';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2011;14';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2011;11';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2011;4';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2009;18';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2009;5';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2008;7';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2008;3';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2007;27';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2007;24';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2006;25';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2006;21';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2006;16';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2006;10';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2006;6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2005;29';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2005;25';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2005;23';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2005;19';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2005;15';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2005;10';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2005;7';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2004;45';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2004;22';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2004;7';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2004;21';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2004;1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2004;4';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2001;7';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2000;9';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2000;10';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:1998;4';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei.conversao;plv:2000;6';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1997-09-23;2327';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 4ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.4:acordao:2008-02-07;295728';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2008-03-26;299964';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2010-09-15;449688';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:1996-06-13;69789-126646';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2005-03-28;211514';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2011-04-27;500367';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2007-08-22;280139';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2007-10-10;285650';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:2008-04-16;302500';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Criminal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.criminal.2:acordao:2010-07-15;435975';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 4ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.4:acordao:2005-04-14;212787';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2005-09-01;225413';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2006-03-27;241702';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:2009-11-04;401078';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2006-03-13;240193';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Câmara Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;camara.civel.3:acordao:2010-10-25;458606';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2011-05-18;505831';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 4ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.4:acordao:2011-08-17;528766';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.1:acordao:2007-08-22;285060';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. Corte Especial',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;corte.especial:acordao;mi:2006-05-22;193-700410';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.2:acordao:1998-12-18;102871';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.1:acordao:1997-12-11;104472';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2005-05-30;217574';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2005-06-20;219103';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.2:acordao:2006-09-27;256520';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Seção',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;secao.1:acordao;ms:1999-06-09;6229-278693';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:2011-04-18;498955';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:2012-02-08;566799';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;resp:2004-05-04;379136-546819';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2005-11-14;232667';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 6ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.6:acordao:2006-03-13;240391';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Recursal dos Juizados Especiais Cíveis e Criminais do DF',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.recursal.juizados.especiais.civeis.criminais.df.1:acordao:2011-03-15;490363';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:2003-12-19;11831';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:2017-06-07;3355';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2022-01-05;18324';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei.complementar:2003-06-27;8';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2022-01-05;7056';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2023-02-28;1163';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2017-06-06;7807';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:2007-04-03;12885';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2004-05-25;3644';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2010-08-17;7773';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2023-03-01;1163';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2023-01-02;1157';
UPDATE lexml_documents_corrected SET 
    locality = 'Caxias do Sul - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;caxias.sul:municipal:lei:2001-11-26;5748';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2012-07-16;17649';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2003-12-11;2749';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2016-02-18;4444';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2019-05-29;3214';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2019-08-14;4475';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2011-12-14;2958';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2022-09-16;48510';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2004-02-06;14608';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2022-09-30;48517';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2022-12-30;48557';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2017-07-05;8014';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2017-10-19;8905';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2023-12-28;48741';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2024-12-26;48970';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2014-06-11;16402';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2023-03-08;48584';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei.conversao;plv:2023-04-25;9';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Supremo Tribunal Federal. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:supremo.tribunal.federal;turma.1:acordao;re:2020-03-03;1243794-5843232';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.3:acordao:2018-05-22;01876004120075010302';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;aresp:2019-02-26;1079466-1808649';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2022-12-21;1147';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2013-08-06;1109298-1311457';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1981-06-03;21339';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2013-12-20;1664';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1976-01-15;17709';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1978-05-11;19183';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2007-07-20;15908';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1998-04-30;132';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2004-07-02;14796';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2021-12-21;2997';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2016-12-01;2178';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2015-12-18;2012';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:2007-05-07;12928';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2008-06-20;1412';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2007-09-25;44622';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2014-04-03;1695';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2020-11-30;2804';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2017-12-13;2355';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2007-12-28;1166';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2014-04-28;1720';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2023-03-10;13760';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2019-12-02;2642';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2020-02-18;8574';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2020-06-15;8915';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2023-03-10;13761';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2021-07-28;2913';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2008-05-16;44813';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2022-12-07;13206';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2023-05-26;3201';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2022-07-29;3087';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2017-04-27;2225';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2020-05-28;2694';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2021-05-28;2872';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2022-05-30;3037';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2024-05-27;3331';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2013-04-29;1520';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2018-12-28;2500';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2022-12-09;3149';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2023-12-20;3296';
UPDATE lexml_documents_corrected SET 
    locality = 'Itabirito - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;itabirito:municipal:lei:2008-12-05;2708';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:2014-05-26;60491';
UPDATE lexml_documents_corrected SET 
    locality = '16ª Região - Maranhão',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.16:tribunal.regional.trabalho;turma.1:acordao:2010-02-03;0038500-46.2008.5.16.0015';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.6:acordao:2015-11-19;00008058020145010301';
UPDATE lexml_documents_corrected SET 
    locality = 'Bento Gonçalves - RS',
    authority = 'Câmara Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;bento.goncalves:camara.municipal:resolucao:2015-10-28;166';
UPDATE lexml_documents_corrected SET 
    locality = 'Vespasiano Corrêa - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;vespasiano.correa:municipal:lei:2011-04-04;15';
UPDATE lexml_documents_corrected SET 
    locality = 'Vespasiano Corrêa - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;vespasiano.correa:municipal:lei:2019-12-24;1513';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2003-05-06;3152';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;airr:2013-04-17;340-2010-130-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:2022-12-19;17612';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;rr:2020-10-14;1001874-2018-271-2-0';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.6:acordao:2010-06-16;01631001520065010020';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;airr:2023-09-06;21071-2017-611-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Rosa - RS',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.grande.sul;santa.rosa:municipal:lei:2020-12-30;5617';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.9:acordao:2017-01-24;00114234820155010431';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;rr:2015-06-17;27740-2009-19-11-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;ag:2023-03-15;4000-2009-751-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Seção de Dissídios Coletivos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;secao.dissidios.coletivos:acordao;ro:2015-06-08;20484-2010-0-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Seção de Dissídios Coletivos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;secao.dissidios.coletivos:acordao;ro:2013-12-09;7357-2010-0-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Seção de Dissídios Coletivos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;secao.dissidios.coletivos:acordao;ro:2014-06-09;9267-2011-0-4-0';
UPDATE lexml_documents_corrected SET 
    locality = '24ª Região - Mato Grosso do Sul',
    authority = 'Tribunal Regional do Trabalho. Tribunal Pleno',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.24:tribunal.regional.trabalho;tribunal.pleno:acordao:2011-01-27;0125000-26.2008.5.24.0005';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.1:acordao:2012-07-25;00953006920095010341';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 10ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.10:acordao:2023-07-11;0010186-55.2022.5.03.0179';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2018-09-26;0010802-84.2018.5.03.0077';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2018-11-23;0010420-91.2018.5.03.0077';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2019-07-24;0011117-46.2018.5.03.0099';
UPDATE lexml_documents_corrected SET 
    locality = '1ª Região - Rio de Janeiro',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.1:tribunal.regional.trabalho;turma.7:acordao:2016-03-31;00103953620155010531';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.1:acordao;rr:2022-05-04;10268-2015-129-15-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Seção de Dissídios Coletivos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;secao.dissidios.coletivos:acordao;rodc:2007-05-10;2010000-2006-0-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;airr:2016-11-09;1783-2010-261-1-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.4:acordao:2025-02-20;0010380-72.2024.5.03.0086';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;rr:2021-04-07;20557-2015-281-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2004-12-08;2022';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. Seção de Dissídios Coletivos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;secao.dissidios.coletivos:acordao;roaa:2003-10-09;9759700-2003-900-11-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2024-12-11;15042';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:2011-12-16;2655';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2019-11-28;10144';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2023-06-05;11548';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:2007-07-24;13030';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:2009-09-18;16773';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-05-19;11075';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2018-03-15;9308';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2015-11-26;8576';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2013-06-11;5113';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2019-06-27;9888';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2019-11-06;10102';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-07-21;11141';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2009-04-29;30317';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2018-05-17;47409';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2010-05-28;7421';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2001-08-23;5209';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2009-11-03;6332';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2012-05-25;3955';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2008-04-15;3256';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2021;2122';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2017-12-26;13576';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2009-12-03;45229';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2007-03-19;479';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pls:2008;33';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.resolucao;prs:2019;69';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2009-12-29;12187';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1996-06-21;8867';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2008-12-16;6921';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1995-02-16;8298';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1997-12-15;4289';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:1992-12-17;7379';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:2002-09-26;11370';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:1998-05-12;657';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2000-01-12;9956';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2014-08-12;5378';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1945-01-16;7249';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:1996-07-11;1147';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2012-04-10;33606';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2000-08-30;4849';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:1950-11-27;702';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1998-10-22;4412';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1977-10-14;5255';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2020-05-25;6585';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:2007-03-15;1824';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2000-01-14;2526';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2004-12-16;6098';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1998-07-08;4376';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:1999-03-31;4502';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2017-09-14;8337';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2015-08-06;7984';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 1ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.1:acordao:2005-06-20;219374';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:1999-06-16;756';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1987-01-20;10090';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2016-10-20;8220';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:2005-12-27;3724';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:1975-10-24;719';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2007-07-05;6600';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei:2016-07-14;8172';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:decreto:1992-10-09;35824';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2021-09-27;3314';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;aresp:2016-05-19;245778-1538051';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1940-01-15;5131';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2020-05-06;2427';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2009-03-04;4776';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Recursal dos Juizados Especiais Cíveis e Criminais do DF',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.recursal.juizados.especiais.civeis.criminais.df.2:acordao:2013-01-22;648526';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.2:acordao:2011-10-26;545571';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2014-03-11;1249363-1335784';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 5ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.5:acordao:2011-05-04;501492';
UPDATE lexml_documents_corrected SET 
    locality = 'Itabirito - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;itabirito:municipal:lei:1993-02-26;1746';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2011-05-31;15477';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1961-01-13;49944';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1961-05-02;50519';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:resolucao:1993-10-01;75';
UPDATE lexml_documents_corrected SET 
    locality = 'Ponte Nova - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;ponte.nova:municipal:lei:1998-10-27;2285';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1967-01-12;60056';
UPDATE lexml_documents_corrected SET 
    locality = 'Ponte Nova - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;ponte.nova:municipal:lei:1999-12-17;2389';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2022-03-29;11014';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2001-10-04;163529-414754';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1918-02-14;12877';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1952-01-02;1537';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1941-01-15;2946';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2013-05-14;8002';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:2005-07-21;15694';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1970-08-10;1117';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1956-11-01;40260';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1877-01-18;6468';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1965-08-09;56690';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1946-08-23;9652';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2012-11-12;7840';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1964-12-11;4568';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1918-03-06;12896';
UPDATE lexml_documents_corrected SET 
    locality = 'São Paulo',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo:estadual:lei:1949-10-03;473';
UPDATE lexml_documents_corrected SET 
    locality = 'Carneirinho - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;carneirinho:municipal:lei:2011-04-19;1107';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.lei:1946-04-29;9213';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1970-01-05;1265';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1881-09-24;8259';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 3ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.3:acordao:2008-10-01;324905';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:1963-09-11;2860';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:lei:1964-12-04;3235';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:1996-12-26;38578';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:1993-10-26;15154';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:decreto:2007-11-14;28435';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2006-05-22;00927-2005-031-03-00-4';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Distrital',
    authority_level = 'federal',
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:distrital:lei:1993-01-07;407';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.4:acordao:2006-04-19;01881-2004-032-03-00-6';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2015-07-14;0002008-39.2014.5.03.0037';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2012-11-27;0000050-04.2012.5.03.0129';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2001-02-14;ro0019991';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2014-08-26;0000516-13.2013.5.03.0145';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2017-03-24;0011027-43.2016.5.03.0023';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2017-09-29;0010618-46.2017.5.03.0148';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2022-05-11;0010368-78.2021.5.03.0081';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2000-09-11;ro006333';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2018-08-17;0010179-52.2017.5.03.0110';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2016-08-19;0010382-21.2015.5.03.0001';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2020-09-15;0010712-45.2016.5.03.0110';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.4:acordao:2014-07-16;0001004-70.2013.5.03.0111';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2012-03-07;0001353-83.2010.5.03.0077';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2020-10-29;0010346-22.2016.5.03.0040';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2002-02-05;ro0116199';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.4:acordao:2013-04-24;0000581-57.2012.5.03.0043';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2020-07-22;0010957-96.2016.5.03.0032';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2022-11-07;0010437-36.2021.5.03.0138';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2021-01-29;0011799-30.2016.5.03.0112';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2005-02-22;00760-2004-100-03-00-0';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 10ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.10:acordao:2020-09-30;0010529-74.2017.5.03.0131';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2021-05-21;0011291-22.2019.5.03.0131';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2021-09-03;0012184-90.2017.5.03.0031';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2021-10-21;0011835-90.2017.5.03.0030';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2000-02-17;ro9913730';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2017-01-30;0002104-84.2013.5.03.0103';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Departamento Administrativo do Serviço Público',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:departamento.administrativo.servico.publico:portaria:1973-03-16;40';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal:portaria:2002-03-08;325';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2011-05-31;118';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão. Secretaria de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao;secretaria.recursos.humanos:portaria:2009-07-16;1816';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Educação',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.educacao:portaria:2005-10-25;3768';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal:portaria:1994-01-06;53';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao:portaria:2017-02-02;42';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Gabinete de Segurança Institucional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;gabinete.seguranca.institucional:portaria:2006-08-04;13';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Educação',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.educacao:portaria:2009-08-14;787';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Meio Ambiente',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.meio.ambiente:portaria:2003-09-23;379';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao:portaria:2014-02-07;27';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:portaria:2013-04-12;472';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento e Orçamento',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento:portaria:2014-06-25;220';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Gabinete de Segurança Institucional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;gabinete.seguranca.institucional:portaria:2003-08-07;24';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Consultoria-Geral da União',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;consultoria.geral.uniao:portaria:2015-11-23;20';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento e Orçamento',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento:portaria:2013-03-26;87';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2008-07-07;207';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal:portaria:2003-09-23;1432';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao:portaria:2013-03-20;81';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao:portaria:2012-10-08;433';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2009-10-19;1056';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2009-08-04;763';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2009-08-04;764';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Consultoria-Geral da União',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;consultoria.geral.uniao:portaria:2015-11-06;19';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Corregedoria-Geral da AGU',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;corregedoria.geral.agu:portaria:2012-02-23;37';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Secretaria-Geral',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;secretaria.geral:portaria:2011-09-28;439';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2012-06-08;468';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2012-10-15;821';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2014-01-23;47';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2009-12-29;1329';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2012-11-01;866';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Advocacia-Geral da União. Procuradoria-Geral Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:advocacia.geral.uniao;procuradoria.geral.federal:portaria:2013-11-21;751';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal do Brasil',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal.brasil:portaria:2010-09-28;1813';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2007-06-18;184';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2002-06-18;246';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2009-11-24;418';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2010-03-22;139';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2012-09-25;457';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2013-01-03;2';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério da Fazenda. Secretaria da Receita Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.fazenda;secretaria.receita.federal:portaria:2000-11-27;1590';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2015-09-02;16690';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:oficio.circular:1991-12-11;44';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 9ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.9:acordao:2025-02-05;0010455-26.2014.5.03.0163';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.7:acordao:2023-03-13;0010849-32.2021.5.03.0181';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Subsecretaria de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;subsecretaria.recursos.humanos:oficio.circular:1994-02-02;7';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2023-04-27;0010702-06.2022.5.03.0105';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional de Energia Elétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-01-31;039';
UPDATE lexml_documents_corrected SET 
    locality = 'Mangaratiba - RJ',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.janeiro;mangaratiba:municipal:lei:2017-09-05;1045';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2022-09-12;0010317-49.2022.5.03.0108';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Turma Recursal de Juiz de Fora',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.recursal.juiz.fora:acordao:2023-05-29;0010593-38.2022.5.03.0025';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal Militar. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.militar;plenario:acordao:1994-08-11;210_1994010002278';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.6:acordao:2023-09-06;0010641-57.2022.5.03.0005';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2022-12-18;0010055-65.2022.5.03.0184';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2022-04-29;0010376-66.2020.5.03.0024';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2023-03-24;0010025-22.2022.5.03.0025';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2023-06-02;0010245-65.2022.5.03.0010';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2024-08-29;0010348-41.2022.5.03.0182';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.1:acordao:2023-10-17;0010544-05.2023.5.03.0011';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2023-12-15;0010791-30.2022.5.03.0137';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 10ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.10:acordao:2023-06-27;0010751-04.2022.5.03.0184';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:lei:2008-11-12;13465';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2024-04-19;0010691-23.2021.5.03.0004';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1990-10-13;99606';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-01-30;76';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-01-30;77';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-03-04;78';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-03-04;79';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-03-04;80';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-06;100';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-06;101';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-06;102';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-06;103';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-06;104';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-06;105';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-06;106';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-06;107';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-27;109';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-24;110';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Presidência da República. Secretaria de Administração Federal. Departamento de Recursos Humanos',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:presidencia.republica;secretaria.administracao.federal;departamento.recursos.humanos:orientacao.normativa:1991-05-24;113';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2002-02-13;4130';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2012-03-20;7703';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2005-12-29;414';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2004-11-22;296';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Ministério do Planejamento, Orçamento e Gestão',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:ministerio.planejamento.orcamento.gestao:portaria:2013-10-21;369';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto.legislativo:2024-02-29;1';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2005-08-31;1316';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2004-12-01;1933';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:2013-08-26;8083';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 5ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.5:acordao:2008-03-12;298050';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2018-05-08;1708181-1780365';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;aresp:2023-03-27;2174577-2270166';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2004-12-15;2067';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2004-11-03;1703';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2006-04-19;567';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2006-02-15;140';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2007-10-10;2153';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;aresp:2017-03-21;47686-1607294';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2024-06-18;2093778-2458512';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2019-08-06;1779362-1868285';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2022-02-22;1814146-2139158';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:medida.provisoria:2017-09-18;800';
UPDATE lexml_documents_corrected SET 
    locality = 'Minas Gerais',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais:estadual:decreto:2016-07-01;47018';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2010-05-05;970';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2014-11-19;3212';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2004-11-17;1819';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2004-12-01;1926';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2005-07-13;981';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal de Contas da União. Plenário',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.contas.uniao;plenario:acordao:2005-08-10;1121';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;resp:2020-10-13;1889364-1994228';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;aresp:2021-05-10;1705448-2052795';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;pl:2024;4158';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. Corte Especial',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;corte.especial:acordao;sls:2015-12-02;1964-1501051';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;aresp:2018-03-13;1066294-1702065';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1995-02-24;8989';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-11-25;1010';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024-02-06;1206';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. Seção Especializada I',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;secao.especializada.1:acordao:1999-03-23;01483-1996-011-03-00-8';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 5ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.5:acordao:2001-11-06;00156-1996-032-03-00-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Ponte Nova - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;ponte.nova:municipal:lei:2019-10-11;4315';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.3:acordao:2013-03-07;0099800-16.1996.5.03.0007';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.4:acordao:2013-09-25;0027800-28.2006.5.03.0149';
UPDATE lexml_documents_corrected SET 
    locality = '16ª Região - Maranhão',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.16:tribunal.regional.trabalho;turma.2:acordao:2016-06-07;0199700-62.2013.5.16.0023';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.2:acordao:2015-01-22;0000062-34.2011.5.03.0135';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;resp:2024-04-16;1967252-2429805';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.3:acordao;aresp:2016-03-15;813686-1524095';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:lei.complementar:2022-07-05;226';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;rr:2018-03-20;190-2014-222-5-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;rr:2018-11-27;2128-2012-242-9-0';
UPDATE lexml_documents_corrected SET 
    locality = '24ª Região - Mato Grosso do Sul',
    authority = 'Tribunal Regional do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.24:tribunal.regional.trabalho;turma.2:acordao:2013-12-04;0001300-54.2010.5.24.0001';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.4:acordao;rr:2021-06-08;10890-2016-18-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;ed:2020-10-20;107100-1998-16-2-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.2:acordao;aresp:2022-09-27;2076095-2212753';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2023-05-16;2580';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2007;24';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;rr:2016-05-11;1314-2011-802-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2015-09-09;374-2012-871-4-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2022-03-09;11048-2019-8-18-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 6ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.6:acordao;rr:2017-04-05;184100-2009-32-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.2:acordao;rr:2015-04-08;36-2011-103-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 3ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.3:acordao;rr:2021-09-01;20-2018-669-9-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 1ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.1:acordao;rms:2019-03-25;44501-1816511';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2009-01-14;11903';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Senado Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:senado.federal:projeto.lei;plc:2013;127';
UPDATE lexml_documents_corrected SET 
    locality = '3ª Região - Minas Gerais',
    authority = 'Tribunal Regional do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;justica.trabalho;regiao.3:tribunal.regional.trabalho;turma.8:acordao:2016-06-09;0010445-49.2015.5.03.0097';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. 3ª Seção de Julgamento. 3ª Câmara. 2ª Turma Ordinária',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;secao.julgamento.3;camara.3;turma.ordinaria.2:acordao:2020-09-22;3302-009.336,8549740';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2022-08-22;2329';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2006-12-06;7621';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2007-02-13;141';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2007-03-15;457';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2008-07-02;3648';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 8ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.8:acordao;rr:2016-08-24;1475-2014-144-6-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Tribunal Superior do Trabalho. 7ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:tribunal.superior.trabalho;turma.7:acordao;rr:2014-06-04;617-2011-19-3-0';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Câmara dos Deputados',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:camara.deputados:projeto.lei;pl:2003-11-20;2562';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Superior Tribunal de Justiça. 4ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:superior.tribunal.justica;turma.4:acordao;resp:2018-11-27;1155590-1789335';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2001-07-12;10260';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1997-11-20;9514';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2017-10-06;13487';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-07-16;992';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-04-03;943';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1226';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2023-09-27;1190';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2024;1269';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:2001-02-06;10179';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:projeto.lei;pln:2017;8';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1973-12-31;6015';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:lei:1994-11-18;8934';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2017-04-27;776';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1969-02-05;64065';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1974-02-20;73686';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Federal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:federal:decreto:1974-02-12;73618';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2004-02-03;003';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2004-06-02;135';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1999-02-09;024';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:1998-02-05;016';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2004-01-15;002';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2007-02-07;432';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2004-05-06;222';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2010-05-31;2420';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2008-02-28;616';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Conselho Administrativo de Recursos Fiscais. Câmara Superior de Recursos Fiscais.2ª Turma',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:conselho.administrativo.recursos.fiscais;camara.superior.recursos.fiscais;turma.2:acordao:2008-05-05;02-03.019,4637254';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2000-12-22;561';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2010-02-03;933';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2011-02-03;1111';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2008-02-07;1235';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2009-06-19;1971';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-04-04;164';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2006-02-14;427';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2001-02-08;049';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2011-02-03;1107';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2014-12-02;4945';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-10-02;536';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2013-11-13;1651';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2011-02-03;1106';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2012-02-03;1256';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2009-02-10;1797';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2022-02-23;11194';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2008-02-18;1246';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2010-07-02;1024';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao:2002-05-02;241';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2010-08-05;2490';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.homologatoria:2013-01-24;1454';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Agência Nacional deEnergiaElétrica',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:agencia.nacional.energia.eletrica:resolucao.autorizativa:2005-08-02;271';
UPDATE lexml_documents_corrected SET 
    locality = 'Divinópolis - MG',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;minas.gerais;divinopolis:municipal:decreto:2007-07-17;7707';
UPDATE lexml_documents_corrected SET 
    locality = 'Hortolândia - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;hortolandia:municipal:lei:2007-06-06;1891';
UPDATE lexml_documents_corrected SET 
    locality = 'Mangaratiba - RJ',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.janeiro;mangaratiba:municipal:lei:2007-05-14;571';
UPDATE lexml_documents_corrected SET 
    locality = 'Campinas - SP',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;sao.paulo;campinas:municipal:decreto:1989-08-11;9890';
UPDATE lexml_documents_corrected SET 
    locality = 'Santa Catarina',
    authority = 'Estadual',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;santa.catarina:estadual:lei:2005-03-08;13340';
UPDATE lexml_documents_corrected SET 
    locality = 'Mangaratiba - RJ',
    authority = 'Municipal',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;rio.janeiro;mangaratiba:municipal:lei:2021-09-01;1354';
UPDATE lexml_documents_corrected SET 
    locality = 'Distrito Federal',
    authority = 'Tribunal de Justiça do Distrito Federal e dos Territórios. 2ª Turma Cível',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br;distrito.federal:tribunal.justica.distrito.federal.territorios;turma.civel.2:acordao:2011-11-17;556607';
UPDATE lexml_documents_corrected SET 
    locality = 'Brasil',
    authority = 'Congresso Nacional',
    authority_level = NULL,
    state = COALESCE(NULL, state),
    municipality = COALESCE(NULL, municipality)
WHERE urn = 'urn:lex:br:congresso.nacional:medida.provisoria;mpv:2020-06-30;987';


-- Now update documents table with complete mapping
UPDATE documents SET
    -- Geographic data with proper locality mapping
    estado = COALESCE(
        ldc.locality,
        ldc.state,
        CASE 
            WHEN ldc.authority LIKE '%São Paulo%' OR ldc.authority LIKE '%SP%' THEN 'São Paulo'
            WHEN ldc.authority LIKE '%Rio de Janeiro%' OR ldc.authority LIKE '%RJ%' THEN 'Rio de Janeiro'
            WHEN ldc.authority LIKE '%Minas Gerais%' OR ldc.authority LIKE '%MG%' THEN 'Minas Gerais'
            WHEN ldc.authority LIKE '%Rio Grande do Sul%' OR ldc.authority LIKE '%RS%' THEN 'Rio Grande do Sul'
            WHEN ldc.authority LIKE '%Bahia%' OR ldc.authority LIKE '%BA%' THEN 'Bahia'
            WHEN ldc.authority LIKE '%Paraná%' OR ldc.authority LIKE '%PR%' THEN 'Paraná'
            WHEN ldc.authority LIKE '%Santa Catarina%' OR ldc.authority LIKE '%SC%' THEN 'Santa Catarina'
            WHEN ldc.authority LIKE '%Distrito Federal%' OR ldc.authority LIKE '%DF%' THEN 'Distrito Federal'
            WHEN ldc.authority LIKE '%Federal%' OR ldc.authority LIKE '%Congresso%' OR ldc.authority LIKE '%Senado%' THEN 'Federal'
            ELSE 'Federal'
        END
    ),
    
    municipality = ldc.municipality,
    locality = ldc.locality,
    authority = ldc.authority,
    authority_level = ldc.authority_level,
    autor = COALESCE(ldc.authority, ldc.document_type_full, documents.autor),
    
    -- Update metadata with ALL CSV fields
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
        'source_type', 'complete_csv_mapping',
        'geographic_level', CASE 
            WHEN ldc.municipality IS NOT NULL AND ldc.municipality != '' THEN 'municipal'
            WHEN ldc.locality IS NOT NULL AND ldc.locality != '' THEN 'state'
            WHEN ldc.justice IS NOT NULL AND ldc.justice != '' THEN 'judicial'
            ELSE 'federal'
        END,
        'all_csv_fields_mapped', true
    )
FROM lexml_documents_corrected ldc
WHERE documents.urn = ldc.urn;

-- Final verification with ALL fields
SELECT 'COMPLETE CSV MAPPING VERIFICATION' as status;

SELECT 
    'Total documents' as metric,
    COUNT(*) as count
FROM documents;

SELECT 
    'Documents with locality' as metric,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE locality IS NOT NULL AND locality != '';

SELECT 
    'Documents with authority' as metric,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE authority IS NOT NULL AND authority != '';

SELECT 
    'Documents with municipalities' as metric,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE municipality IS NOT NULL AND municipality != '';

-- Authority distribution
SELECT 'Authority distribution (top 10)' as status;
SELECT authority, COUNT(*) as count 
FROM documents 
WHERE authority IS NOT NULL AND authority != ''
GROUP BY authority 
ORDER BY count DESC 
LIMIT 10;

-- Locality distribution  
SELECT 'Locality/State distribution' as status;
SELECT locality, COUNT(*) as count 
FROM documents 
WHERE locality IS NOT NULL AND locality != ''
GROUP BY locality 
ORDER BY count DESC 
LIMIT 10;

COMMIT;
