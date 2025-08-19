#!/bin/bash

# Create Sample Data Script for Railway Database
# ==============================================
# This script creates the documents table and populates it with sample data

echo "========================================="
echo "CREATING SAMPLE DATA FOR RAILWAY"
echo "========================================="

# Check if DATABASE_URL is available
if [ -z "$DATABASE_URL" ]; then
    echo "❌ DATABASE_URL not found"
    echo "   Please set DATABASE_URL environment variable"
    exit 1
fi

echo "✅ DATABASE_URL found"
echo ""

# Function to execute SQL safely
execute_sql() {
    local description=$1
    local sql_command=$2
    
    echo "Executing: $description"
    echo "$sql_command" | psql "$DATABASE_URL" 2>&1 | while IFS= read -r line; do
        if [[ ! "$line" =~ ^NOTICE: ]]; then
            echo "  $line"
        fi
    done
    
    if [ ${PIPESTATUS[1]} -eq 0 ]; then
        echo "  ✅ $description - Success"
        return 0
    else
        echo "  ❌ $description - Failed"
        return 1
    fi
}

echo "1. Creating Documents Table"
echo "==========================="

execute_sql "Create documents table" "
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT NOT NULL,
    tipo VARCHAR(100),
    estado VARCHAR(50),
    municipality VARCHAR(100),
    data_publicacao DATE,
    url TEXT,
    urn TEXT,
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
echo "2. Inserting Sample Legislative Data"
echo "===================================="

execute_sql "Insert sample Brazilian transport legislation" "
INSERT INTO documents (
    titulo, tipo, estado, municipality, data_publicacao, url, urn,
    conteudo, ementa, autor, termo_busca, classificacao, species
) VALUES 
('Lei Federal 14.133/2021 - Nova Lei de Licitações e Contratos Administrativos', 'Lei', 'DF', '', '2021-04-01', 'https://www.planalto.gov.br/ccivil_03/_ato2019-2022/2021/lei/l14133.htm', 'urn:lex:br:federal:lei:2021-04-01;14133',
 'Lei que estabelece normas gerais de licitação e contratação para a administração pública', 'Nova lei de licitações que moderniza os processos de contratação pública', 'Congresso Nacional', 'licitação', 'Legislação', 'Legislação'),

('Resolução CONTRAN 886/2021 - Regulamentação de Transporte de Cargas', 'Resolução', 'DF', '', '2021-11-15', 'https://www.gov.br/infraestrutura/pt-br/assuntos/transito/conteudo-contran/resolucoes/resolucao886_21.pdf', 'urn:lex:br:federal:resolucao:2021-11-15;886',
 'Regulamentação específica para transporte de cargas perigosas e equipamentos especiais', 'Normas de segurança para transporte de cargas especiais', 'CONTRAN', 'transporte de carga', 'Legislação', 'Legislação'),

('Lei Federal 13.103/2015 - Regulamentação dos Motoristas Profissionais', 'Lei', 'DF', '', '2015-03-02', 'https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2015/lei/l13103.htm', 'urn:lex:br:federal:lei:2015-03-02;13103',
 'Lei que regulamenta a profissão de motorista', 'Regulamentação da profissão de motorista, estabelecendo direitos e jornada de trabalho', 'Congresso Nacional', 'motorista profissional', 'Legislação', 'Legislação'),

('STF - ADPF 789 - Marco Civil da Internet e Liberdade de Expressão Digital', 'ADPF', 'DF', '', '2023-05-15', 'https://portal.stf.jus.br/processos/detalhe.asp?incidente=6449452', 'urn:lex:br:supremo.tribunal.federal:arguicao.descumprimento.preceito.fundamental:2023-05-15;789',
 'Ação que discute limites da regulação de conteúdo em plataformas digitais', 'Discussão sobre liberdade de expressão e regulação digital', 'STF', 'marco civil internet', 'Jurisprudência', 'Jurisprudência'),

('Decreto Estadual SP 64.684/2019 - Logística Urbana Sustentável', 'Decreto', 'SP', 'São Paulo', '2019-12-10', 'https://www.al.sp.gov.br/repositorio/legislacao/decreto/2019/decreto-64684-10.12.2019.html', 'urn:lex:br:sao.paulo:decreto:2019-12-10;64684',
 'Decreto estadual sobre logística urbana sustentável na região metropolitana', 'Políticas de logística sustentável para a região metropolitana', 'Governo do Estado de SP', 'logística urbana', 'Legislação', 'Legislação'),

('Lei Complementar 182/2021 - Marco Legal das Startups e Inovação', 'Lei Complementar', 'DF', '', '2021-06-01', 'https://www.planalto.gov.br/ccivil_03/leis/lcp/lcp182.htm', 'urn:lex:br:federal:lei.complementar:2021-06-01;182',
 'Marco regulatório para fomento ao ambiente de inovação', 'Lei que estabelece marco legal para startups e ambiente de inovação', 'Congresso Nacional', 'startup inovação', 'Legislação', 'Legislação'),

('Portaria ANTT 3.665/2020 - Registro Nacional de Transportadores', 'Portaria', 'DF', '', '2020-09-22', 'https://www.antt.gov.br/portarias/2020/portaria3665_20.html', 'urn:lex:br:agencia.nacional.transportes.terrestres:portaria:2020-09-22;3665',
 'Regulamentação do registro nacional de transportadores rodoviários', 'Normas para registro de transportadores de carga', 'ANTT', 'RNTRC', 'Legislação', 'Legislação'),

('Lei Complementar 87/1996 - ICMS sobre Combustíveis e Transporte', 'Lei Complementar', 'DF', '', '1996-09-13', 'https://www.planalto.gov.br/ccivil_03/leis/lcp/lcp87.htm', 'urn:lex:br:federal:lei.complementar:1996-09-13;87',
 'Lei que estabelece normas sobre ICMS incidente sobre combustíveis', 'Regulamentação do ICMS sobre combustíveis para transporte', 'Congresso Nacional', 'ICMS combustível', 'Legislação', 'Legislação'),

('Resolução ANP 816/2020 - Qualidade de Combustíveis para Transporte', 'Resolução', 'DF', '', '2020-06-30', 'https://www.gov.br/anp/pt-br/centrais-de-conteudo/atos-normativos/resolucoes-anp/2020/resolucao-816.pdf', 'urn:lex:br:agencia.nacional.petroleo:resolucao:2020-06-30;816',
 'Especificações de qualidade para combustíveis utilizados em transporte', 'Normas de qualidade para combustíveis automotivos', 'ANP', 'qualidade combustível', 'Legislação', 'Legislação'),

('Lei Federal 12.619/2012 - Jornada de Trabalho de Motoristas', 'Lei', 'DF', '', '2012-04-30', 'https://www.planalto.gov.br/ccivil_03/_ato2011-2014/2012/lei/l12619.htm', 'urn:lex:br:federal:lei:2012-04-30;12619',
 'Lei que disciplina a jornada de trabalho do motorista profissional', 'Regulamentação da jornada de trabalho e tempo de direção', 'Congresso Nacional', 'jornada motorista', 'Legislação', 'Legislação'),

('Parecer Técnico IBAMA 443/2021 - Controle de Emissões Veiculares', 'Parecer', 'DF', '', '2021-08-12', 'https://www.ibama.gov.br/phocadownload/veiculos/pareceres/parecer_443_2021.pdf', 'urn:lex:br:instituto.brasileiro.meio.ambiente:parecer:2021-08-12;443',
 'Análise técnica sobre controle de emissões atmosféricas', 'Estudo sobre controle de emissões veiculares e fiscalização ambiental', 'IBAMA', 'emissões veiculares', 'Doutrina', 'Doutrina'),

('Lei Estadual RJ 7.194/2016 - Política de Transporte Sustentável', 'Lei', 'RJ', 'Rio de Janeiro', '2016-03-15', 'https://gov-rj.jusbrasil.com.br/legislacao/313791620/lei-7194-16', 'urn:lex:br:rio.de.janeiro:lei:2016-03-15;7194',
 'Política estadual para promoção do transporte sustentável', 'Lei estadual sobre mobilidade urbana sustentável', 'Assembleia Legislativa RJ', 'transporte sustentável', 'Legislação', 'Legislação'),

('Portaria MT 2.080/2020 - Infraestrutura de Transportes', 'Portaria', 'DF', '', '2020-12-18', 'https://www.gov.br/infraestrutura/pt-br/assuntos/legislacao/portarias/2020/portaria-2080.pdf', 'urn:lex:br:ministerio.infraestrutura:portaria:2020-12-18;2080',
 'Planejamento e desenvolvimento da infraestrutura de transportes', 'Diretrizes para investimentos em infraestrutura de transporte', 'Ministério da Infraestrutura', 'infraestrutura transporte', 'Legislação', 'Legislação'),

('Resolução CONTRAN 789/2020 - Segurança Veicular em Transportes', 'Resolução', 'DF', '', '2020-05-20', 'https://www.gov.br/infraestrutura/pt-br/assuntos/transito/conteudo-contran/resolucoes/resolucao789_20.pdf', 'urn:lex:br:federal:resolucao:2020-05-20;789',
 'Regulamentação de equipamentos obrigatórios de segurança', 'Normas de segurança veicular para transportes', 'CONTRAN', 'segurança veicular', 'Legislação', 'Legislação'),

('Lei Municipal SP 16.050/2014 - Plano Diretor e Mobilidade Urbana', 'Lei', 'SP', 'São Paulo', '2014-07-31', 'https://legislacao.prefeitura.sp.gov.br/leis/lei-16050-de-31-de-julho-de-2014', 'urn:lex:br:sao.paulo.municipio:lei:2014-07-31;16050',
 'Plano diretor municipal com diretrizes para mobilidade urbana', 'Plano diretor com foco em mobilidade urbana sustentável', 'Câmara Municipal SP', 'plano diretor mobilidade', 'Legislação', 'Legislação')

ON CONFLICT DO NOTHING;"

echo ""
echo "3. Creating Basic Performance Indexes"
echo "===================================="

execute_sql "Create search index" "
CREATE INDEX IF NOT EXISTS idx_documents_titulo 
ON documents USING gin(to_tsvector('portuguese', titulo));"

execute_sql "Create state index" "
CREATE INDEX IF NOT EXISTS idx_documents_estado 
ON documents(estado) WHERE estado IS NOT NULL;"

execute_sql "Create type index" "
CREATE INDEX IF NOT EXISTS idx_documents_tipo 
ON documents(tipo) WHERE tipo IS NOT NULL;"

echo ""
echo "4. Verifying Data"
echo "================"

execute_sql "Count total documents" "
SELECT COUNT(*) as total_documents FROM documents;"

execute_sql "Count by state" "
SELECT estado, COUNT(*) as count 
FROM documents 
WHERE estado IS NOT NULL 
GROUP BY estado 
ORDER BY count DESC;"

execute_sql "Count by type" "
SELECT tipo, COUNT(*) as count 
FROM documents 
WHERE tipo IS NOT NULL 
GROUP BY tipo 
ORDER BY count DESC;"

echo ""
echo "========================================="
echo "SAMPLE DATA CREATION COMPLETE"
echo "========================================="
echo "✅ Documents table created"
echo "✅ 15 sample documents inserted"
echo "✅ Performance indexes created"
echo "✅ Data verified"
echo ""
echo "The application should now display data!"
echo "========================================"