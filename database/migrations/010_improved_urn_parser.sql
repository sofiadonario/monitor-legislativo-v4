-- ==============================================================================
-- MIGRATION 010: IMPROVED URN PARSER FOR GEOGRAPHIC EXTRACTION
-- ==============================================================================
-- Implements hierarchical URN parsing to reduce unidentified documents
-- from ~11% to <2% by extracting geographic information from LexML URN structures
--
-- Author: Data Science Team
-- Date: 2025-11-11
-- Expected Impact: +9% geographic coverage improvement
-- ==============================================================================

DO $$
DECLARE
    before_unidentified INTEGER;
    after_unidentified INTEGER;
    before_nacional INTEGER;
    before_estadual INTEGER;
    before_null INTEGER;
    total_docs INTEGER;
    updated_count INTEGER;
BEGIN
    -- =========================================================================
    -- STEP 1: BASELINE METRICS
    -- =========================================================================

    SELECT COUNT(*) INTO total_docs FROM documents;

    SELECT COUNT(*) INTO before_unidentified
    FROM documents
    WHERE estado_mapeado IS NULL
       OR estado_mapeado = 'Nacional'
       OR estado_mapeado = 'Estadual'
       OR estado_mapeado = 'Não Identificado';

    SELECT COUNT(*) INTO before_nacional FROM documents WHERE estado_mapeado = 'Nacional';
    SELECT COUNT(*) INTO before_estadual FROM documents WHERE estado_mapeado = 'Estadual';
    SELECT COUNT(*) INTO before_null FROM documents WHERE estado_mapeado IS NULL;

    RAISE NOTICE '========================================';
    RAISE NOTICE 'BASELINE METRICS';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Total documents: %', total_docs;
    RAISE NOTICE 'Unidentified before: % (%.2f%%)', before_unidentified,
                 (before_unidentified * 100.0 / total_docs);
    RAISE NOTICE '  - Nacional: %', before_nacional;
    RAISE NOTICE '  - Estadual (generic): %', before_estadual;
    RAISE NOTICE '  - NULL: %', before_null;
    RAISE NOTICE '';

    -- =========================================================================
    -- STEP 2: UPDATE ESTADO_MAPEADO USING HIERARCHICAL URN PARSING
    -- =========================================================================

    RAISE NOTICE 'Starting URN parsing update...';

    UPDATE documents
    SET estado_mapeado = CASE

        -- =====================================================================
        -- PRIORITY 1: Federal/National Legislation
        -- =====================================================================
        -- Pattern: :federal: or :congresso.nacional:
        WHEN LOWER(urn) LIKE '%:federal:%'
          OR LOWER(urn) LIKE '%:congresso.nacional:%' THEN 'Nacional'

        -- =====================================================================
        -- PRIORITY 2: Explicit State Code - Pattern :estado:XX:
        -- =====================================================================
        -- This is the most common and explicit state pattern in LexML URNs
        WHEN urn ~* ':estado:([a-z]{2}):' THEN
            UPPER(substring(urn from ':estado:([a-z]{2}):'))

        -- =====================================================================
        -- PRIORITY 3: Municipal with Parent State  - Pattern :estado:XX:municipal:
        -- =====================================================================
        WHEN urn ~* ':estado:([a-z]{2}):municipal:' THEN
            UPPER(substring(urn from ':estado:([a-z]{2}):municipal:'))

        -- =====================================================================
        -- PRIORITY 4: Generic State Code Search - Pattern :br:XX:
        -- =====================================================================
        WHEN urn ~* ':br:([a-z]{2}):' THEN
            UPPER(substring(urn from ':br:([a-z]{2}):'))

        -- =====================================================================
        -- PRIORITY 5: State Assembleia Legislativa
        -- =====================================================================
        -- Pattern: assembleia.legislativa:XX or assembleia:XX
        WHEN urn ~* 'assembleia[._]legislativa:([a-z]{2})' THEN
            UPPER(substring(urn from 'assembleia[._]legislativa:([a-z]{2})'))

        -- =====================================================================
        -- PRIORITY 6: Specific State Patterns
        -- =====================================================================

        -- Distrito Federal
        WHEN LOWER(urn) LIKE '%distrito.federal%'
          OR LOWER(urn) LIKE '%distrito_federal%' THEN 'DF'

        -- State names in URN (fallback - lower confidence)
        WHEN LOWER(urn) LIKE '%sao.paulo%' OR LOWER(urn) LIKE '%sao_paulo%' THEN 'SP'
        WHEN LOWER(urn) LIKE '%rio.de.janeiro%' OR LOWER(urn) LIKE '%rio_de_janeiro%' THEN 'RJ'
        WHEN LOWER(urn) LIKE '%minas.gerais%' OR LOWER(urn) LIKE '%minas_gerais%' THEN 'MG'
        WHEN LOWER(urn) LIKE '%bahia%' THEN 'BA'
        WHEN LOWER(urn) LIKE '%rio.grande.do.sul%' OR LOWER(urn) LIKE '%rio_grande_do_sul%' THEN 'RS'
        WHEN LOWER(urn) LIKE '%parana%' THEN 'PR'
        WHEN LOWER(urn) LIKE '%pernambuco%' THEN 'PE'
        WHEN LOWER(urn) LIKE '%ceara%' THEN 'CE'
        WHEN LOWER(urn) LIKE '%para%' THEN 'PA'
        WHEN LOWER(urn) LIKE '%santa.catarina%' OR LOWER(urn) LIKE '%santa_catarina%' THEN 'SC'
        WHEN LOWER(urn) LIKE '%goias%' THEN 'GO'
        WHEN LOWER(urn) LIKE '%maranhao%' THEN 'MA'
        WHEN LOWER(urn) LIKE '%paraiba%' THEN 'PB'
        WHEN LOWER(urn) LIKE '%espirito.santo%' OR LOWER(urn) LIKE '%espirito_santo%' THEN 'ES'
        WHEN LOWER(urn) LIKE '%piaui%' THEN 'PI'
        WHEN LOWER(urn) LIKE '%alagoas%' THEN 'AL'
        WHEN LOWER(urn) LIKE '%rio.grande.do.norte%' OR LOWER(urn) LIKE '%rio_grande_do_norte%' THEN 'RN'
        WHEN LOWER(urn) LIKE '%mato.grosso.do.sul%' OR LOWER(urn) LIKE '%mato_grosso_do_sul%' THEN 'MS'
        WHEN LOWER(urn) LIKE '%mato.grosso%' OR LOWER(urn) LIKE '%mato_grosso%' THEN 'MT'
        WHEN LOWER(urn) LIKE '%sergipe%' THEN 'SE'
        WHEN LOWER(urn) LIKE '%rondonia%' THEN 'RO'
        WHEN LOWER(urn) LIKE '%tocantins%' THEN 'TO'
        WHEN LOWER(urn) LIKE '%acre%' THEN 'AC'
        WHEN LOWER(urn) LIKE '%amapa%' THEN 'AP'
        WHEN LOWER(urn) LIKE '%roraima%' THEN 'RR'
        WHEN LOWER(urn) LIKE '%amazonas%' THEN 'AM'

        -- =====================================================================
        -- DEFAULT: Keep existing value if no pattern matches
        -- =====================================================================
        ELSE estado_mapeado
    END
    WHERE
        -- Only update records that are currently unidentified or generic
        (estado_mapeado IS NULL
         OR estado_mapeado = 'Estadual'
         OR estado_mapeado = 'Não Identificado'
         OR estado_mapeado = 'Nacional')
        AND urn IS NOT NULL;

    GET DIAGNOSTICS updated_count = ROW_COUNT;

    RAISE NOTICE 'Updated % records', updated_count;
    RAISE NOTICE '';

    -- =========================================================================
    -- STEP 3: POST-UPDATE METRICS
    -- =========================================================================

    SELECT COUNT(*) INTO after_unidentified
    FROM documents
    WHERE estado_mapeado IS NULL
       OR estado_mapeado = 'Nacional'
       OR estado_mapeado = 'Estadual'
       OR estado_mapeado = 'Não Identificado';

    RAISE NOTICE '========================================';
    RAISE NOTICE 'RESULTS';
    RAISE NOTICE '========================================';
    RAISE NOTICE 'Unidentified after: % (%.2f%%)', after_unidentified,
                 (after_unidentified * 100.0 / total_docs);
    RAISE NOTICE 'Improvement: % documents (%.2f%% reduction)',
                 (before_unidentified - after_unidentified),
                 ((before_unidentified - after_unidentified) * 100.0 / before_unidentified);
    RAISE NOTICE '';

    -- Show new distribution
    RAISE NOTICE 'New Geographic Distribution:';
    FOR rec IN (
        SELECT
            COALESCE(estado_mapeado, 'NULL') as estado,
            COUNT(*) as count,
            ROUND(100.0 * COUNT(*) / total_docs, 2) as pct
        FROM documents
        GROUP BY estado_mapeado
        ORDER BY COUNT(*) DESC
        LIMIT 15
    ) LOOP
        RAISE NOTICE '  % : % (%.2f%%)', rec.estado, rec.count, rec.pct;
    END LOOP;

    RAISE NOTICE '';
    RAISE NOTICE '✅ Migration 010 completed successfully!';
    RAISE NOTICE '========================================';

END $$;
