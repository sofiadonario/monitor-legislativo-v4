# DATASET LEXML - TRANSPORTE E DESCARBONIZAÇÃO

## 📋 DESCRIÇÃO GERAL

Este dataset contém 134.014 registros extraídos do LexML, focados no projeto de pesquisa "Governança das Políticas Públicas de transporte: infraestrutura, tecnologia e eletrificação".

**Data de criação:** 22/07/2025
**Período dos dados:** 1829-2025 (196 anos)
**Taxa de relevância:** 92.3% (filtrado para o projeto)

## 📊 ESTRUTURA DO DATASET

### CATEGORIAS DE DOCUMENTOS:
- **Jurisprudência:** 54.617 registros (40.8%)
- **Legislação:** 51.086 registros (38.1%)
- **Outros:** 13.850 registros (10.3%)
- **Doutrina:** 12.810 registros (9.6%)
- **Proposições:** 1.651 registros (1.2%)

### MODAIS DE TRANSPORTE:
- **Geral:** 82.297 registros (61.4%)
- **Rodoviário:** 46.074 registros (34.4%)
- **Marítimo:** 3.569 registros (2.7%)
- **Aéreo:** 2.074 registros (1.5%)

## 📁 ARQUIVOS INCLUÍDOS

### 1. DATASET PRINCIPAL
- `lexml_dataset_limpo_classificado_20250722_102507.csv` - Dataset completo em CSV
- `lexml_dataset_completo_20250722_102507.xlsx` - Excel com todas as abas organizadas

### 2. DATASETS POR CATEGORIA E MODAL (20 arquivos)

#### DOUTRINA:
- `lexml_doutrina_geral_20250722_102507.csv` (10.124 registros)
- `lexml_doutrina_rodoviário_20250722_102507.csv` (1.846 registros)
- `lexml_doutrina_marítimo_20250722_102507.csv` (602 registros)
- `lexml_doutrina_aéreo_20250722_102507.csv` (238 registros)

#### JURISPRUDÊNCIA:
- `lexml_jurisprudência_geral_20250722_102507.csv` (26.981 registros)
- `lexml_jurisprudência_rodoviário_20250722_102507.csv` (25.794 registros)
- `lexml_jurisprudência_marítimo_20250722_102507.csv` (810 registros)
- `lexml_jurisprudência_aéreo_20250722_102507.csv` (1.032 registros)

#### LEGISLAÇÃO:
- `lexml_legislação_geral_20250722_102507.csv` (37.218 registros)
- `lexml_legislação_rodoviário_20250722_102507.csv` (11.706 registros)
- `lexml_legislação_marítimo_20250722_102507.csv` (1.618 registros)
- `lexml_legislação_aéreo_20250722_102507.csv` (544 registros)

#### OUTROS:
- `lexml_outros_geral_20250722_102507.csv` (7.097 registros)
- `lexml_outros_rodoviário_20250722_102507.csv` (5.981 registros)
- `lexml_outros_marítimo_20250722_102507.csv` (526 registros)
- `lexml_outros_aéreo_20250722_102507.csv` (246 registros)

#### PROPOSIÇÕES:
- `lexml_proposições_geral_20250722_102507.csv` (877 registros)
- `lexml_proposições_rodoviário_20250722_102507.csv` (747 registros)
- `lexml_proposições_marítimo_20250722_102507.csv` (13 registros)
- `lexml_proposições_aéreo_20250722_102507.csv` (14 registros)

### 3. DOCUMENTAÇÃO
- `lexml_stats_detalhadas_20250722_102507.txt` - Estatísticas completas
- `README_DATASET_FINAL.md` - Este arquivo

## 🔍 CAMPOS DO DATASET

Cada registro contém os seguintes campos:
- **titulo:** Título do documento
- **tipo:** Tipo de documento (Lei, Decreto, Artigo, etc.)
- **data:** Data do documento
- **urn:** URN do documento no LexML
- **autor:** Autor do documento
- **assuntos:** Assuntos/palavras-chave
- **classificacao:** Classificação jurídica
- **jurisdicao:** Jurisdição (Federal, Estadual, Municipal)
- **autoridade:** Autoridade emissora
- **ementa:** Ementa/resumo
- **url:** URL no LexML
- **localidade:** Localidade
- **numero:** Número do documento
- **ano:** Ano do documento
- **termo_busca:** Termo usado na busca
- **data_coleta:** Data da coleta
- **origem:** Origem da extração
- **categoria:** Categoria do documento (Legislação, Jurisprudência, etc.)
- **modal:** Modal de transporte (geral, rodoviário, marítimo, aéreo)

## 🎯 CRITÉRIOS DE RELEVÂNCIA

O dataset foi filtrado para incluir apenas registros relevantes ao projeto de pesquisa, baseado em palavras-chave relacionadas a:

### TRANSPORTE:
- Transporte, logística, mobilidade, frete, carga
- Modais: rodoviário, aéreo, marítimo, ferroviário
- Veículos: caminhão, ônibus, carreta, etc.

### SUSTENTABILIDADE:
- Descarbonização, emissões, carbono, CO2
- Eletrificação, veículos elétricos, híbridos
- Biocombustíveis, biodiesel, etanol

### REGULAMENTAÇÃO:
- ANTT, ANTAQ, ANAC, DNIT, CONTRAN
- ANP, IBAMA, CONAMA
- Políticas públicas, normas, regulamentação

### TECNOLOGIA:
- Inovação, automação, tecnologia
- Infraestrutura, terminais, postos

## 📈 DISTRIBUIÇÃO TEMPORAL

O dataset abrange quase 2 séculos de dados:
- **1820s-1980s:** Dados históricos (16.791 registros)
- **1990s:** 12.591 registros
- **2000s:** 32.661 registros  
- **2010s:** 53.488 registros (pico)
- **2020s:** 16.027 registros

## 🔧 METODOLOGIA

### EXTRAÇÃO:
- **Fonte:** Portal LexML (www.lexml.gov.br)
- **Método:** Web scraping da interface web
- **Termos:** 115 termos específicos do projeto
- **Paginação:** Completa (todos os resultados disponíveis)

### LIMPEZA:
- Remoção de registros irrelevantes (7.7%)
- Filtros baseados em palavras-chave do projeto
- Remoção de duplicatas

### CLASSIFICAÇÃO:
- **Categoria:** Baseada no tipo de documento
- **Modal:** Baseada em análise de conteúdo por palavras-chave

## 📞 CONTATO

Dataset criado para o projeto de pesquisa "Governança das Políticas Públicas de transporte: infraestrutura, tecnologia e eletrificação".

**Data de criação:** 22 de julho de 2025
**Versão:** 1.0 Final

