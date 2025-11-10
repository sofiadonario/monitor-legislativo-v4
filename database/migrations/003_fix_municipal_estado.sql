-- ============================================================================
-- FIX MUNICIPAL DOCUMENTS WITH WRONG ESTADO - Migration 003
-- ============================================================================
--
-- Purpose: Fix municipal documents incorrectly tagged as "Federal"
-- Issue: ~750 municipal docs have estado='Federal' but URN shows state/municipality
-- Impact: Corrects geographic hierarchy for municipal documents
--
-- Example URN: urn:lex:br;rio.janeiro;nova.friburgo:municipal:lei...
--   Current:  estado='Federal', municipio=NULL
--   Fixed:    estado='RJ', municipio='Nova Friburgo'
--
-- Author: Data Quality Team
-- Date: 2025-11-10
-- ============================================================================

\timing on
\set ON_ERROR_STOP on

BEGIN;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'FIXING MUNICIPAL DOCUMENTS WITH INCORRECT ESTADO';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Correcting municipal docs tagged as Federal';
    RAISE NOTICE 'Extracting correct estado and municipio from URN';
    RAISE NOTICE 'Started at: %', clock_timestamp();
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- BACKUP DATA BEFORE CHANGES
-- ============================================================================
CREATE TABLE IF NOT EXISTS estado_municipio_backup_20251110 AS
SELECT id, estado, municipio, urn
FROM documents
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND (estado = 'Federal' OR municipio IS NULL OR municipio = '');

DO $$ BEGIN RAISE NOTICE '✓ Created backup table'; END $$;

-- ============================================================================
-- 1. FIX RIO DE JANEIRO MUNICIPALITIES
-- ============================================================================
DO $$ BEGIN RAISE NOTICE ''; RAISE NOTICE 'Fixing Rio de Janeiro municipalities...'; END $$;

UPDATE documents
SET
    estado = 'RJ',
    municipio = CASE
        WHEN urn LIKE '%rio.janeiro;angra.reis:%' THEN 'Angra dos Reis'
        WHEN urn LIKE '%rio.janeiro;aperibe:%' THEN 'Aperibé'
        WHEN urn LIKE '%rio.janeiro;araruama:%' THEN 'Araruama'
        WHEN urn LIKE '%rio.janeiro;areal:%' THEN 'Areal'
        WHEN urn LIKE '%rio.janeiro;armacao.buzios:%' THEN 'Armação dos Búzios'
        WHEN urn LIKE '%rio.janeiro;arraial.cabo:%' THEN 'Arraial do Cabo'
        WHEN urn LIKE '%rio.janeiro;barra.mansa:%' THEN 'Barra Mansa'
        WHEN urn LIKE '%rio.janeiro;barra.pirai:%' THEN 'Barra do Piraí'
        WHEN urn LIKE '%rio.janeiro;belford.roxo:%' THEN 'Belford Roxo'
        WHEN urn LIKE '%rio.janeiro;bom.jardim:%' THEN 'Bom Jardim'
        WHEN urn LIKE '%rio.janeiro;bom.jesus.itabapoana:%' THEN 'Bom Jesus do Itabapoana'
        WHEN urn LIKE '%rio.janeiro;cabo.frio:%' THEN 'Cabo Frio'
        WHEN urn LIKE '%rio.janeiro;cachoeiras.macacu:%' THEN 'Cachoeiras de Macacu'
        WHEN urn LIKE '%rio.janeiro;cambuci:%' THEN 'Cambuci'
        WHEN urn LIKE '%rio.janeiro;campos.goytacazes:%' THEN 'Campos dos Goytacazes'
        WHEN urn LIKE '%rio.janeiro;cantagalo:%' THEN 'Cantagalo'
        WHEN urn LIKE '%rio.janeiro;carapebus:%' THEN 'Carapebus'
        WHEN urn LIKE '%rio.janeiro;cardoso.moreira:%' THEN 'Cardoso Moreira'
        WHEN urn LIKE '%rio.janeiro;carmo:%' THEN 'Carmo'
        WHEN urn LIKE '%rio.janeiro;casimiro.abreu:%' THEN 'Casimiro de Abreu'
        WHEN urn LIKE '%rio.janeiro;comendador.levy.gasparian:%' THEN 'Comendador Levy Gasparian'
        WHEN urn LIKE '%rio.janeiro;conceicao.macabu:%' THEN 'Conceição de Macabu'
        WHEN urn LIKE '%rio.janeiro;cordeiro:%' THEN 'Cordeiro'
        WHEN urn LIKE '%rio.janeiro;duas.barras:%' THEN 'Duas Barras'
        WHEN urn LIKE '%rio.janeiro;duque.caxias:%' THEN 'Duque de Caxias'
        WHEN urn LIKE '%rio.janeiro;engenheiro.paulo.frontin:%' THEN 'Engenheiro Paulo de Frontin'
        WHEN urn LIKE '%rio.janeiro;guapimirim:%' THEN 'Guapimirim'
        WHEN urn LIKE '%rio.janeiro;iguaba.grande:%' THEN 'Iguaba Grande'
        WHEN urn LIKE '%rio.janeiro;itaborai:%' THEN 'Itaboraí'
        WHEN urn LIKE '%rio.janeiro;itaguai:%' THEN 'Itaguaí'
        WHEN urn LIKE '%rio.janeiro;italva:%' THEN 'Italva'
        WHEN urn LIKE '%rio.janeiro;itaocara:%' THEN 'Itaocara'
        WHEN urn LIKE '%rio.janeiro;itaperuna:%' THEN 'Itaperuna'
        WHEN urn LIKE '%rio.janeiro;itatiaia:%' THEN 'Itatiaia'
        WHEN urn LIKE '%rio.janeiro;japeri:%' THEN 'Japeri'
        WHEN urn LIKE '%rio.janeiro;laje.muriae:%' THEN 'Laje do Muriaé'
        WHEN urn LIKE '%rio.janeiro;macae:%' THEN 'Macaé'
        WHEN urn LIKE '%rio.janeiro;macuco:%' THEN 'Macuco'
        WHEN urn LIKE '%rio.janeiro;mage:%' THEN 'Magé'
        WHEN urn LIKE '%rio.janeiro;mangaratiba:%' THEN 'Mangaratiba'
        WHEN urn LIKE '%rio.janeiro;marica:%' THEN 'Maricá'
        WHEN urn LIKE '%rio.janeiro;mendes:%' THEN 'Mendes'
        WHEN urn LIKE '%rio.janeiro;mesquita:%' THEN 'Mesquita'
        WHEN urn LIKE '%rio.janeiro;miguel.pereira:%' THEN 'Miguel Pereira'
        WHEN urn LIKE '%rio.janeiro;miracema:%' THEN 'Miracema'
        WHEN urn LIKE '%rio.janeiro;natividade:%' THEN 'Natividade'
        WHEN urn LIKE '%rio.janeiro;nilopolis:%' THEN 'Nilópolis'
        WHEN urn LIKE '%rio.janeiro;niteroi:%' THEN 'Niterói'
        WHEN urn LIKE '%rio.janeiro;nova.friburgo:%' THEN 'Nova Friburgo'
        WHEN urn LIKE '%rio.janeiro;nova.iguacu:%' THEN 'Nova Iguaçu'
        WHEN urn LIKE '%rio.janeiro;paracambi:%' THEN 'Paracambi'
        WHEN urn LIKE '%rio.janeiro;paraiba.sul:%' THEN 'Paraíba do Sul'
        WHEN urn LIKE '%rio.janeiro;paraty:%' THEN 'Paraty'
        WHEN urn LIKE '%rio.janeiro;paty.alferes:%' THEN 'Paty do Alferes'
        WHEN urn LIKE '%rio.janeiro;petropolis:%' THEN 'Petrópolis'
        WHEN urn LIKE '%rio.janeiro;pinheiral:%' THEN 'Pinheiral'
        WHEN urn LIKE '%rio.janeiro;pirai:%' THEN 'Piraí'
        WHEN urn LIKE '%rio.janeiro;porciuncula:%' THEN 'Porciúncula'
        WHEN urn LIKE '%rio.janeiro;porto.real:%' THEN 'Porto Real'
        WHEN urn LIKE '%rio.janeiro;quatis:%' THEN 'Quatis'
        WHEN urn LIKE '%rio.janeiro;queimados:%' THEN 'Queimados'
        WHEN urn LIKE '%rio.janeiro;quissamã:%' THEN 'Quissamã'
        WHEN urn LIKE '%rio.janeiro;resende:%' THEN 'Resende'
        WHEN urn LIKE '%rio.janeiro;rio.bonito:%' THEN 'Rio Bonito'
        WHEN urn LIKE '%rio.janeiro;rio.claro:%' THEN 'Rio Claro'
        WHEN urn LIKE '%rio.janeiro;rio.flores:%' THEN 'Rio das Flores'
        WHEN urn LIKE '%rio.janeiro;rio.ostras:%' THEN 'Rio das Ostras'
        WHEN urn LIKE '%rio.janeiro;rio.janeiro:%' THEN 'Rio de Janeiro'
        WHEN urn LIKE '%rio.janeiro;santa.maria.madalena:%' THEN 'Santa Maria Madalena'
        WHEN urn LIKE '%rio.janeiro;santo.antonio.padua:%' THEN 'Santo Antônio de Pádua'
        WHEN urn LIKE '%rio.janeiro;sao.fidelis:%' THEN 'São Fidélis'
        WHEN urn LIKE '%rio.janeiro;sao.francisco.itabapoana:%' THEN 'São Francisco de Itabapoana'
        WHEN urn LIKE '%rio.janeiro;sao.goncalo:%' THEN 'São Gonçalo'
        WHEN urn LIKE '%rio.janeiro;sao.joao.barra:%' THEN 'São João de Barra'
        WHEN urn LIKE '%rio.janeiro;sao.joao.meriti:%' THEN 'São João de Meriti'
        WHEN urn LIKE '%rio.janeiro;sao.jose.ubá:%' THEN 'São José de Ubá'
        WHEN urn LIKE '%rio.janeiro;sao.jose.vale.rio.preto:%' THEN 'São José do Vale do Rio Preto'
        WHEN urn LIKE '%rio.janeiro;sao.pedro.aldeia:%' THEN 'São Pedro da Aldeia'
        WHEN urn LIKE '%rio.janeiro;sao.sebastiao.alto:%' THEN 'São Sebastião do Alto'
        WHEN urn LIKE '%rio.janeiro;sapucaia:%' THEN 'Sapucaia'
        WHEN urn LIKE '%rio.janeiro;saquarema:%' THEN 'Saquarema'
        WHEN urn LIKE '%rio.janeiro;seropedica:%' THEN 'Seropédica'
        WHEN urn LIKE '%rio.janeiro;silva.jardim:%' THEN 'Silva Jardim'
        WHEN urn LIKE '%rio.janeiro;sumidouro:%' THEN 'Sumidouro'
        WHEN urn LIKE '%rio.janeiro;tangua:%' THEN 'Tanguá'
        WHEN urn LIKE '%rio.janeiro;teresopolis:%' THEN 'Teresópolis'
        WHEN urn LIKE '%rio.janeiro;trajano.moraes:%' THEN 'Trajano de Moraes'
        WHEN urn LIKE '%rio.janeiro;tres.rios:%' THEN 'Três Rios'
        WHEN urn LIKE '%rio.janeiro;valenca:%' THEN 'Valença'
        WHEN urn LIKE '%rio.janeiro;varre.sai:%' THEN 'Varre-Sai'
        WHEN urn LIKE '%rio.janeiro;vassouras:%' THEN 'Vassouras'
        WHEN urn LIKE '%rio.janeiro;volta.redonda:%' THEN 'Volta Redonda'
    END
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND urn LIKE 'urn:lex:br;rio.janeiro;%'
  AND estado = 'Federal';

DO $$ BEGIN RAISE NOTICE '✓ Fixed RJ municipalities'; END $$;

-- ============================================================================
-- 2. FIX RIO GRANDE DO SUL MUNICIPALITIES
-- ============================================================================
DO $$ BEGIN RAISE NOTICE 'Fixing Rio Grande do Sul municipalities...'; END $$;

UPDATE documents
SET
    estado = 'RS',
    municipio = regexp_replace(
        regexp_replace(
            substring(urn from 'urn:lex:br;rio\.grande\.sul;([^:]+):'),
            '\.', ' ', 'g'
        ),
        '([a-z])([A-Z])', '\1 \2', 'g'
    )
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND urn LIKE 'urn:lex:br;rio.grande.sul;%'
  AND estado = 'Federal';

DO $$ BEGIN RAISE NOTICE '✓ Fixed RS municipalities'; END $$;

-- ============================================================================
-- 3. FIX ESPÍRITO SANTO MUNICIPALITIES
-- ============================================================================
DO $$ BEGIN RAISE NOTICE 'Fixing Espírito Santo municipalities...'; END $$;

UPDATE documents
SET
    estado = 'ES',
    municipio = regexp_replace(
        regexp_replace(
            substring(urn from 'urn:lex:br;espirito\.santo;([^:]+):'),
            '\.', ' ', 'g'
        ),
        '([a-z])([A-Z])', '\1 \2', 'g'
    )
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND urn LIKE 'urn:lex:br;espirito.santo;%'
  AND estado = 'Federal';

DO $$ BEGIN RAISE NOTICE '✓ Fixed ES municipalities'; END $$;

-- ============================================================================
-- 4. FIX PARANÁ MUNICIPALITIES
-- ============================================================================
DO $$ BEGIN RAISE NOTICE 'Fixing Paraná municipalities...'; END $$;

UPDATE documents
SET
    estado = 'PR',
    municipio = regexp_replace(
        regexp_replace(
            substring(urn from 'urn:lex:br;parana;([^:]+):'),
            '\.', ' ', 'g'
        ),
        '([a-z])([A-Z])', '\1 \2', 'g'
    )
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND urn LIKE 'urn:lex:br;parana;%'
  AND estado = 'Federal';

DO $$ BEGIN RAISE NOTICE '✓ Fixed PR municipalities'; END $$;

-- ============================================================================
-- 5. FIX ANY OTHER STATES WITH MISCLASSIFIED MUNICIPAL DOCS
-- ============================================================================
DO $$ BEGIN RAISE NOTICE 'Fixing other states...'; END $$;

-- Generic fix for any remaining municipal docs tagged as Federal
UPDATE documents
SET
    estado = CASE
        WHEN urn LIKE 'urn:lex:br;sao.paulo;%' THEN 'SP'
        WHEN urn LIKE 'urn:lex:br;minas.gerais;%' THEN 'MG'
        WHEN urn LIKE 'urn:lex:br;bahia;%' THEN 'BA'
        WHEN urn LIKE 'urn:lex:br;ceara;%' THEN 'CE'
        WHEN urn LIKE 'urn:lex:br;pernambuco;%' THEN 'PE'
        WHEN urn LIKE 'urn:lex:br;santa.catarina;%' THEN 'SC'
        WHEN urn LIKE 'urn:lex:br;goias;%' THEN 'GO'
        WHEN urn LIKE 'urn:lex:br;amazonas;%' THEN 'AM'
        WHEN urn LIKE 'urn:lex:br;para;%' THEN 'PA'
        WHEN urn LIKE 'urn:lex:br;maranhao;%' THEN 'MA'
        WHEN urn LIKE 'urn:lex:br;rio.grande.norte;%' THEN 'RN'
        WHEN urn LIKE 'urn:lex:br;paraiba;%' THEN 'PB'
        WHEN urn LIKE 'urn:lex:br;alagoas;%' THEN 'AL'
        WHEN urn LIKE 'urn:lex:br;sergipe;%' THEN 'SE'
        WHEN urn LIKE 'urn:lex:br;tocantins;%' THEN 'TO'
        WHEN urn LIKE 'urn:lex:br;mato.grosso;%' THEN 'MT'
        WHEN urn LIKE 'urn:lex:br;mato.grosso.sul;%' THEN 'MS'
        WHEN urn LIKE 'urn:lex:br;rondonia;%' THEN 'RO'
        WHEN urn LIKE 'urn:lex:br;acre;%' THEN 'AC'
        WHEN urn LIKE 'urn:lex:br;roraima;%' THEN 'RR'
        WHEN urn LIKE 'urn:lex:br;amapa;%' THEN 'AP'
        WHEN urn LIKE 'urn:lex:br;piaui;%' THEN 'PI'
        WHEN urn LIKE 'urn:lex:br;distrito.federal;%' THEN 'DF'
    END,
    municipio = regexp_replace(
        regexp_replace(
            substring(urn from 'urn:lex:br;[^;]+;([^:]+):'),
            '\.', ' ', 'g'
        ),
        '([a-z])([A-Z])', '\1 \2', 'g'
    )
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND estado = 'Federal'
  AND urn ~ 'urn:lex:br;[^;]+;[^:]+:';

DO $$ BEGIN RAISE NOTICE '✓ Fixed remaining states'; END $$;

-- ============================================================================
-- VERIFICATION
-- ============================================================================

DO $$
DECLARE
    fixed_count INTEGER;
    remaining_federal INTEGER;
BEGIN
    -- Count fixed documents
    SELECT COUNT(*) INTO fixed_count
    FROM documents
    WHERE id IN (SELECT id FROM estado_municipio_backup_20251110)
      AND estado != 'Federal';

    -- Count remaining Federal municipal docs (should be 0)
    SELECT COUNT(*) INTO remaining_federal
    FROM documents
    WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
      AND estado = 'Federal';

    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MIGRATION 003 COMPLETE';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Documents fixed: %', fixed_count;
    RAISE NOTICE 'Remaining Federal municipal docs: % (should be 0)', remaining_federal;
    RAISE NOTICE 'Completed at: %', clock_timestamp();
    RAISE NOTICE '============================================================================';
END $$;

-- Show sample fixed documents
SELECT
    estado,
    municipio,
    urn
FROM documents
WHERE id IN (SELECT id FROM estado_municipio_backup_20251110 LIMIT 20)
ORDER BY estado, municipio
LIMIT 20;

COMMIT;

-- ============================================================================
-- ROLLBACK SCRIPT
-- ============================================================================
/*
BEGIN;

UPDATE documents d
SET
    estado = b.estado,
    municipio = b.municipio
FROM estado_municipio_backup_20251110 b
WHERE d.id = b.id;

DROP TABLE estado_municipio_backup_20251110;

COMMIT;
*/
