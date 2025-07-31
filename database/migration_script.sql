-- Drop all existing tables
DROP TABLE IF EXISTS documents CASCADE;
DROP TABLE IF EXISTS documents_backup_889 CASCADE;
DROP TABLE IF EXISTS legislative_data CASCADE;
DROP TABLE IF EXISTS lexml_documents_corrected CASCADE;
DROP TABLE IF EXISTS lexml_parsed_enhanced CASCADE;
DROP TABLE IF EXISTS lexml_parsed_enhanced_backup_889 CASCADE;

-- Drop any existing new tables
DROP TABLE IF EXISTS lexml_documents CASCADE;
DROP TABLE IF EXISTS categorias CASCADE;
DROP TABLE IF EXISTS modais CASCADE;
DROP TABLE IF EXISTS jurisdicoes CASCADE;
DROP TABLE IF EXISTS termos_busca CASCADE;

-- Create lookup tables first
CREATE TABLE categorias (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE modais (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE jurisdicoes (
    id SERIAL PRIMARY KEY,
    nome VARCHAR(50) UNIQUE NOT NULL
);

CREATE TABLE termos_busca (
    id SERIAL PRIMARY KEY,
    termo VARCHAR(100) UNIQUE NOT NULL
);

-- Create main documents table
CREATE TABLE lexml_documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT NOT NULL,
    tipo VARCHAR(100),
    data DATE,
    urn VARCHAR(500) UNIQUE NOT NULL,
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
);

-- Insert lookup data
INSERT INTO categorias (nome) VALUES 
    ('Jurisprudência'),
    ('Legislação'),
    ('Outros'),
    ('Doutrina'),
    ('Proposições');

INSERT INTO modais (nome) VALUES 
    ('geral'),
    ('rodoviário'),
    ('marítimo'),
    ('aéreo');

INSERT INTO jurisdicoes (nome) VALUES 
    ('Federal'),
    ('State'),
    ('Municipal'),
    ('Distrital');

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;