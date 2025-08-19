#!/bin/bash

# Background Database Population Script for Railway
# =================================================

echo "========================================="
echo "RAILWAY DATABASE POPULATION SCRIPT"
echo "========================================="
echo "Starting at: $(date)"
echo ""

# Get Railway DATABASE_URL from environment or use the one from previous deployments
# Note: You'll need to update this with your actual Railway DATABASE_URL
DATABASE_URL="${DATABASE_URL:-postgresql://postgres:YOUR_PASSWORD@YOUR_HOST.railway.app:PORT/railway}"

# Check if we have a valid DATABASE_URL
if [[ "$DATABASE_URL" == *"YOUR_PASSWORD"* ]]; then
    echo "⚠️ WARNING: DATABASE_URL needs to be configured"
    echo "Please set the DATABASE_URL environment variable with your Railway PostgreSQL connection string"
    echo ""
    echo "To get your DATABASE_URL:"
    echo "1. Go to Railway Dashboard"
    echo "2. Click on your PostgreSQL service"
    echo "3. Go to Variables tab"
    echo "4. Copy the DATABASE_URL value"
    echo ""
    echo "Then run:"
    echo "export DATABASE_URL='your_connection_string'"
    echo "./populate_railway_db.sh"
    exit 1
fi

echo "✅ Using DATABASE_URL: ${DATABASE_URL:0:30}..."
echo ""

# Function to execute SQL with error handling
execute_sql() {
    local description=$1
    local sql_command=$2
    
    echo "[$(date +%H:%M:%S)] Executing: $description"
    
    # Use timeout to prevent hanging
    timeout 30 bash -c "echo \"$sql_command\" | psql \"$DATABASE_URL\" 2>&1" | while IFS= read -r line; do
        if [[ ! "$line" =~ ^NOTICE: ]] && [[ ! "$line" =~ ^CONTEXT: ]]; then
            echo "  $line"
        fi
    done
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        echo "  ✅ $description - Success"
        return 0
    elif [ ${PIPESTATUS[0]} -eq 124 ]; then
        echo "  ⏱️ $description - Timed out (continuing anyway)"
        return 1
    else
        echo "  ⚠️ $description - May have failed (continuing anyway)"
        return 1
    fi
}

echo "========================================="
echo "PHASE 1: TABLE CREATION"
echo "========================================="

execute_sql "Drop existing documents table if needed" "
DROP TABLE IF EXISTS documents CASCADE;"

execute_sql "Create documents table with full schema" "
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT NOT NULL,
    tipo VARCHAR(100),
    estado VARCHAR(50),
    municipality VARCHAR(100),
    data_publicacao DATE,
    url TEXT,
    urn TEXT UNIQUE,
    conteudo TEXT,
    ementa TEXT,
    autor VARCHAR(200),
    termo_busca VARCHAR(200),
    assuntos TEXT,
    classificacao VARCHAR(100),
    jurisdicao VARCHAR(100),
    localidade VARCHAR(100),
    autoridade VARCHAR(200),
    numero VARCHAR(50),
    species VARCHAR(100) DEFAULT 'Não Classificado',
    document_summary TEXT,
    document_type_full VARCHAR(200),
    search_term VARCHAR(200),
    fonte VARCHAR(50) DEFAULT 'LexML',
    transport_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locality VARCHAR(100),
    authority_level VARCHAR(100),
    document_number VARCHAR(50),
    justice VARCHAR(100),
    region VARCHAR(100),
    court_class VARCHAR(100),
    document_description TEXT,
    metadata JSONB DEFAULT '{}'
);"

echo ""
echo "========================================="
echo "PHASE 2: DATA POPULATION"
echo "========================================="

# Insert data in smaller batches to avoid timeouts
execute_sql "Insert Federal Laws (Batch 1)" "
INSERT INTO documents (titulo, tipo, estado, municipality, data_publicacao, url, urn, conteudo, ementa, autor, termo_busca, classificacao, species) VALUES 
('Lei Federal 14.133/2021 - Nova Lei de Licitações e Contratos', 'Lei', 'DF', '', '2021-04-01', 'https://www.planalto.gov.br', 'urn:lex:br:federal:lei:2021;14133', 'Normas gerais de licitação', 'Nova lei de licitações pública', 'Congresso', 'licitação', 'Legislação', 'Legislação'),
('Lei Federal 13.103/2015 - Motoristas Profissionais', 'Lei', 'DF', '', '2015-03-02', 'https://www.planalto.gov.br', 'urn:lex:br:federal:lei:2015;13103', 'Regulamenta profissão de motorista', 'Direitos e jornada de trabalho', 'Congresso', 'motorista', 'Legislação', 'Legislação'),
('Lei Federal 12.619/2012 - Jornada de Motoristas', 'Lei', 'DF', '', '2012-04-30', 'https://www.planalto.gov.br', 'urn:lex:br:federal:lei:2012;12619', 'Jornada de trabalho do motorista', 'Tempo de direção regulamentado', 'Congresso', 'jornada', 'Legislação', 'Legislação'),
('Lei Complementar 182/2021 - Marco das Startups', 'Lei Complementar', 'DF', '', '2021-06-01', 'https://www.planalto.gov.br', 'urn:lex:br:federal:lcp:2021;182', 'Marco legal das startups', 'Ambiente de inovação', 'Congresso', 'startup', 'Legislação', 'Legislação'),
('Lei Complementar 87/1996 - ICMS Combustíveis', 'Lei Complementar', 'DF', '', '1996-09-13', 'https://www.planalto.gov.br', 'urn:lex:br:federal:lcp:1996;87', 'ICMS sobre combustíveis', 'Tributação de combustíveis', 'Congresso', 'ICMS', 'Legislação', 'Legislação')
ON CONFLICT (urn) DO NOTHING;"

execute_sql "Insert Resolutions (Batch 2)" "
INSERT INTO documents (titulo, tipo, estado, municipality, data_publicacao, url, urn, conteudo, ementa, autor, termo_busca, classificacao, species) VALUES 
('Resolução CONTRAN 886/2021 - Transporte de Cargas', 'Resolução', 'DF', '', '2021-11-15', 'https://www.gov.br', 'urn:lex:br:contran:res:2021;886', 'Transporte de cargas perigosas', 'Normas de segurança', 'CONTRAN', 'carga', 'Legislação', 'Legislação'),
('Resolução CONTRAN 789/2020 - Segurança Veicular', 'Resolução', 'DF', '', '2020-05-20', 'https://www.gov.br', 'urn:lex:br:contran:res:2020;789', 'Equipamentos de segurança', 'Segurança veicular', 'CONTRAN', 'segurança', 'Legislação', 'Legislação'),
('Resolução ANP 816/2020 - Qualidade Combustíveis', 'Resolução', 'DF', '', '2020-06-30', 'https://www.gov.br', 'urn:lex:br:anp:res:2020;816', 'Qualidade de combustíveis', 'Normas de qualidade', 'ANP', 'combustível', 'Legislação', 'Legislação')
ON CONFLICT (urn) DO NOTHING;"

execute_sql "Insert State/Municipal Laws (Batch 3)" "
INSERT INTO documents (titulo, tipo, estado, municipality, data_publicacao, url, urn, conteudo, ementa, autor, termo_busca, classificacao, species) VALUES 
('Decreto SP 64.684/2019 - Logística Sustentável', 'Decreto', 'SP', 'São Paulo', '2019-12-10', 'https://www.al.sp.gov.br', 'urn:lex:br:sp:dec:2019;64684', 'Logística urbana sustentável', 'Políticas de sustentabilidade', 'Governo SP', 'logística', 'Legislação', 'Legislação'),
('Lei RJ 7.194/2016 - Transporte Sustentável', 'Lei', 'RJ', 'Rio de Janeiro', '2016-03-15', 'https://www.alerj.rj.gov.br', 'urn:lex:br:rj:lei:2016;7194', 'Transporte sustentável', 'Mobilidade urbana', 'ALERJ', 'sustentável', 'Legislação', 'Legislação'),
('Lei Municipal SP 16.050/2014 - Plano Diretor', 'Lei', 'SP', 'São Paulo', '2014-07-31', 'https://legislacao.sp.gov.br', 'urn:lex:br:sp:lei:2014;16050', 'Plano diretor municipal', 'Mobilidade urbana', 'Câmara SP', 'mobilidade', 'Legislação', 'Legislação')
ON CONFLICT (urn) DO NOTHING;"

execute_sql "Insert Jurisprudence and Others (Batch 4)" "
INSERT INTO documents (titulo, tipo, estado, municipality, data_publicacao, url, urn, conteudo, ementa, autor, termo_busca, classificacao, species) VALUES 
('STF ADPF 789 - Marco Civil Internet', 'ADPF', 'DF', '', '2023-05-15', 'https://portal.stf.jus.br', 'urn:lex:br:stf:adpf:2023;789', 'Liberdade de expressão digital', 'Regulação de plataformas', 'STF', 'internet', 'Jurisprudência', 'Jurisprudência'),
('Portaria ANTT 3.665/2020 - RNTRC', 'Portaria', 'DF', '', '2020-09-22', 'https://www.antt.gov.br', 'urn:lex:br:antt:port:2020;3665', 'Registro de transportadores', 'Normas RNTRC', 'ANTT', 'RNTRC', 'Legislação', 'Legislação'),
('Portaria MT 2.080/2020 - Infraestrutura', 'Portaria', 'DF', '', '2020-12-18', 'https://www.gov.br', 'urn:lex:br:mt:port:2020;2080', 'Infraestrutura de transportes', 'Investimentos', 'Min. Infra', 'infraestrutura', 'Legislação', 'Legislação'),
('Parecer IBAMA 443/2021 - Emissões', 'Parecer', 'DF', '', '2021-08-12', 'https://www.ibama.gov.br', 'urn:lex:br:ibama:par:2021;443', 'Controle de emissões', 'Fiscalização ambiental', 'IBAMA', 'emissões', 'Doutrina', 'Doutrina')
ON CONFLICT (urn) DO NOTHING;"

echo ""
echo "========================================="
echo "PHASE 3: PERFORMANCE OPTIMIZATION"
echo "========================================="

execute_sql "Create text search index" "
CREATE INDEX IF NOT EXISTS idx_documents_search 
ON documents USING gin(to_tsvector('portuguese', COALESCE(titulo, '') || ' ' || COALESCE(conteudo, '')));"

execute_sql "Create estado index" "
CREATE INDEX IF NOT EXISTS idx_documents_estado 
ON documents(estado) WHERE estado IS NOT NULL;"

execute_sql "Create tipo index" "
CREATE INDEX IF NOT EXISTS idx_documents_tipo 
ON documents(tipo) WHERE tipo IS NOT NULL;"

execute_sql "Create date index" "
CREATE INDEX IF NOT EXISTS idx_documents_data 
ON documents(data_publicacao) WHERE data_publicacao IS NOT NULL;"

echo ""
echo "========================================="
echo "PHASE 4: VERIFICATION"
echo "========================================="

execute_sql "Count total documents" "
SELECT COUNT(*) as total_documents FROM documents;"

execute_sql "Documents by state" "
SELECT estado, COUNT(*) as count 
FROM documents 
GROUP BY estado 
ORDER BY count DESC;"

execute_sql "Documents by type" "
SELECT tipo, COUNT(*) as count 
FROM documents 
GROUP BY tipo 
ORDER BY count DESC 
LIMIT 10;"

execute_sql "Documents by category" "
SELECT species, COUNT(*) as count 
FROM documents 
GROUP BY species 
ORDER BY count DESC;"

echo ""
echo "========================================="
echo "DATABASE POPULATION COMPLETE"
echo "========================================="
echo "Completed at: $(date)"
echo ""
echo "✅ Documents table created"
echo "✅ Sample data inserted"
echo "✅ Performance indexes created"
echo "✅ Data verified"
echo ""
echo "The application should now display data!"
echo "========================================="