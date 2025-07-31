-- Drop and recreate the table with URN as nullable
DROP TABLE IF EXISTS lexml_documents CASCADE;

-- Create main documents table with nullable URN
CREATE TABLE lexml_documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT NOT NULL,
    tipo VARCHAR(100),
    data DATE,
    urn VARCHAR(500) UNIQUE,  -- Made nullable
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

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO postgres;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO postgres;