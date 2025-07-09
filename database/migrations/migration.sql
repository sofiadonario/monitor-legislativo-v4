
-- Railway PostgreSQL Migration
-- Drop and recreate tables
DROP TABLE IF EXISTS documents CASCADE;

CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    urn VARCHAR(500) UNIQUE,
    titulo TEXT,
    conteudo TEXT,
    tipo VARCHAR(100),
    data_publicacao DATE,
    estado VARCHAR(10),
    autor VARCHAR(200),
    fonte VARCHAR(100),
    url TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_documents_urn ON documents(urn);
CREATE INDEX idx_documents_tipo ON documents(tipo);
CREATE INDEX idx_documents_estado ON documents(estado);
CREATE INDEX idx_documents_data ON documents(data_publicacao);

-- Insert data

INSERT INTO documents (urn, titulo, conteudo, tipo, data_publicacao, estado, autor, fonte, url, metadata)
VALUES ('urn:lex:br:federal:lei:2023-01-01;14521', 'Lei do Transporte Público Sustentável', 'Estabelece diretrizes para o transporte público sustentável no Brasil.', 'lei', '2023-01-01', 'BR', 'Congresso Nacional', 'LexML', 'https://lexml.gov.br/urn/urn:lex:br:federal:lei:2023-01-01;14521', '{"keywords": ["transporte", "sustentabilidade"]}')
ON CONFLICT (urn) DO NOTHING;

INSERT INTO documents (urn, titulo, conteudo, tipo, data_publicacao, estado, autor, fonte, url, metadata)
VALUES ('urn:lex:br:sp:lei:2023-03-20;17456', 'Lei Estadual de Transporte Metropolitano - SP', 'Estabelece o sistema de transporte metropolitano no estado de São Paulo.', 'lei', '2023-03-20', 'SP', 'Assembleia Legislativa de São Paulo', 'LexML', 'https://lexml.gov.br/urn/urn:lex:br:sp:lei:2023-03-20;17456', '{"keywords": ["metropolitano", "integra\u00e7\u00e3o"]}')
ON CONFLICT (urn) DO NOTHING;

INSERT INTO documents (urn, titulo, conteudo, tipo, data_publicacao, estado, autor, fonte, url, metadata)
VALUES ('urn:lex:br:rj:decreto:2023-04-10;48789', 'Decreto de Mobilidade Ativa - RJ', 'Regulamenta a política de mobilidade ativa no estado do Rio de Janeiro.', 'decreto', '2023-04-10', 'RJ', 'Governo do Estado do Rio de Janeiro', 'LexML', 'https://lexml.gov.br/urn/urn:lex:br:rj:decreto:2023-04-10;48789', '{"keywords": ["mobilidade", "ativa"]}')
ON CONFLICT (urn) DO NOTHING;
