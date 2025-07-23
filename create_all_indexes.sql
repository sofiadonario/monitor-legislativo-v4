-- Create indexes for all category-specific tables

-- Function to create standard indexes for any table
CREATE OR REPLACE FUNCTION create_indexes_for_table(table_name text) RETURNS void AS $$
BEGIN
    -- Basic column indexes
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_data ON %I(data)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_categoria ON %I(categoria)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_modal ON %I(modal)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_jurisdicao ON %I(jurisdicao)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_termo_busca ON %I(termo_busca)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_tipo ON %I(tipo)', table_name, table_name);
    
    -- Composite indexes
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_categoria_modal ON %I(categoria, modal)', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_categoria_data ON %I(categoria, data)', table_name, table_name);
    
    -- Full-text search indexes
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_titulo_gin ON %I USING gin(to_tsvector(''portuguese'', titulo))', table_name, table_name);
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%s_ementa_gin ON %I USING gin(to_tsvector(''portuguese'', coalesce(ementa, '''')))', table_name, table_name);
    
    -- Analyze table
    EXECUTE format('ANALYZE %I', table_name);
    
    RAISE NOTICE 'Created indexes for table %', table_name;
END;
$$ LANGUAGE plpgsql;

-- Create indexes for all tables
SELECT create_indexes_for_table('lexml_doutrina_aereo');
SELECT create_indexes_for_table('lexml_doutrina_geral');
SELECT create_indexes_for_table('lexml_doutrina_maritimo');
SELECT create_indexes_for_table('lexml_doutrina_rodoviario');

SELECT create_indexes_for_table('lexml_jurisprudencia_aereo');
SELECT create_indexes_for_table('lexml_jurisprudencia_geral');
SELECT create_indexes_for_table('lexml_jurisprudencia_maritimo');
SELECT create_indexes_for_table('lexml_jurisprudencia_rodoviario');

SELECT create_indexes_for_table('lexml_legislacao_aereo');
SELECT create_indexes_for_table('lexml_legislacao_geral');
SELECT create_indexes_for_table('lexml_legislacao_maritimo');
SELECT create_indexes_for_table('lexml_legislacao_rodoviario');

SELECT create_indexes_for_table('lexml_outros_aereo');
SELECT create_indexes_for_table('lexml_outros_geral');
SELECT create_indexes_for_table('lexml_outros_maritimo');
SELECT create_indexes_for_table('lexml_outros_rodoviario');

SELECT create_indexes_for_table('lexml_proposicoes_aereo');
SELECT create_indexes_for_table('lexml_proposicoes_geral');
SELECT create_indexes_for_table('lexml_proposicoes_maritimo');
SELECT create_indexes_for_table('lexml_proposicoes_rodoviario');

-- Drop the function
DROP FUNCTION create_indexes_for_table(text);