-- Create category-specific tables for all CSV files

-- Drop existing tables if they exist
DROP TABLE IF EXISTS lexml_doutrina_aereo CASCADE;
DROP TABLE IF EXISTS lexml_doutrina_geral CASCADE;
DROP TABLE IF EXISTS lexml_doutrina_maritimo CASCADE;
DROP TABLE IF EXISTS lexml_doutrina_rodoviario CASCADE;

DROP TABLE IF EXISTS lexml_jurisprudencia_aereo CASCADE;
DROP TABLE IF EXISTS lexml_jurisprudencia_geral CASCADE;
DROP TABLE IF EXISTS lexml_jurisprudencia_maritimo CASCADE;
DROP TABLE IF EXISTS lexml_jurisprudencia_rodoviario CASCADE;

DROP TABLE IF EXISTS lexml_legislacao_aereo CASCADE;
DROP TABLE IF EXISTS lexml_legislacao_geral CASCADE;
DROP TABLE IF EXISTS lexml_legislacao_maritimo CASCADE;
DROP TABLE IF EXISTS lexml_legislacao_rodoviario CASCADE;

DROP TABLE IF EXISTS lexml_outros_aereo CASCADE;
DROP TABLE IF EXISTS lexml_outros_geral CASCADE;
DROP TABLE IF EXISTS lexml_outros_maritimo CASCADE;
DROP TABLE IF EXISTS lexml_outros_rodoviario CASCADE;

DROP TABLE IF EXISTS lexml_proposicoes_aereo CASCADE;
DROP TABLE IF EXISTS lexml_proposicoes_geral CASCADE;
DROP TABLE IF EXISTS lexml_proposicoes_maritimo CASCADE;
DROP TABLE IF EXISTS lexml_proposicoes_rodoviario CASCADE;

-- Create a function to create standard table structure
CREATE OR REPLACE FUNCTION create_lexml_table(table_name text) RETURNS void AS $$
BEGIN
    EXECUTE format('
        CREATE TABLE %I (
            id SERIAL PRIMARY KEY,
            titulo TEXT NOT NULL,
            tipo VARCHAR(100),
            data DATE,
            urn VARCHAR(500) UNIQUE,
            autor TEXT,
            assuntos TEXT,
            classificacao TEXT,
            jurisdicao VARCHAR(50),
            autoridade TEXT,
            ementa TEXT,
            url TEXT,
            localidade VARCHAR(255),
            numero INTEGER,
            ano INTEGER,
            termo_busca VARCHAR(100),
            data_coleta TIMESTAMP,
            origem VARCHAR(50),
            categoria VARCHAR(50) NOT NULL,
            modal VARCHAR(50) NOT NULL
        )', table_name);
END;
$$ LANGUAGE plpgsql;

-- Create all tables
SELECT create_lexml_table('lexml_doutrina_aereo');
SELECT create_lexml_table('lexml_doutrina_geral');
SELECT create_lexml_table('lexml_doutrina_maritimo');
SELECT create_lexml_table('lexml_doutrina_rodoviario');

SELECT create_lexml_table('lexml_jurisprudencia_aereo');
SELECT create_lexml_table('lexml_jurisprudencia_geral');
SELECT create_lexml_table('lexml_jurisprudencia_maritimo');
SELECT create_lexml_table('lexml_jurisprudencia_rodoviario');

SELECT create_lexml_table('lexml_legislacao_aereo');
SELECT create_lexml_table('lexml_legislacao_geral');
SELECT create_lexml_table('lexml_legislacao_maritimo');
SELECT create_lexml_table('lexml_legislacao_rodoviario');

SELECT create_lexml_table('lexml_outros_aereo');
SELECT create_lexml_table('lexml_outros_geral');
SELECT create_lexml_table('lexml_outros_maritimo');
SELECT create_lexml_table('lexml_outros_rodoviario');

SELECT create_lexml_table('lexml_proposicoes_aereo');
SELECT create_lexml_table('lexml_proposicoes_geral');
SELECT create_lexml_table('lexml_proposicoes_maritimo');
SELECT create_lexml_table('lexml_proposicoes_rodoviario');

-- Drop the function as it's no longer needed
DROP FUNCTION create_lexml_table(text);

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;