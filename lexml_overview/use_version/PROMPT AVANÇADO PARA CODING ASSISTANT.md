# PROMPT AVANÇADO PARA CODING ASSISTANT
## Analytics e Pesquisas Complementares - Dataset LexML Transporte de Carga

**Desenvolvido por:** Manus AI  
**Data:** 2025-07-15  
**Versão:** Avançada - Baseada em Dataset Real  

---

## 🎯 CONTEXTO E OBJETIVO

Você é um coding assistant especializado em análise de dados legislativos e regulatórios brasileiros. Trabalhe com um dataset real de **4.097 documentos** extraídos do LexML, organizados em **14 categorias temáticas** relacionadas ao transporte de carga no Brasil.

### Dataset Disponível:
- **Arquivo**: `CSV-Ajustado.xlsx` (14 sheets)
- **Período**: 1850s-2020s (169 anos de dados)
- **Cobertura**: Federal, estadual, distrital e municipal
- **Tipos**: Legislação (47.2%), Jurisprudência (41.8%), Doutrina (11.0%)
- **Campos**: 16 variáveis estruturadas por documento

---

## 📊 ESTRUTURA DO DATASET

### Sheets Disponíveis:
1. **combustiveis_energia** (289 docs) - Diesel, gasolina, etanol, biodiesel, GNV
2. **transporte_logistica** (687 docs) - Modalidades, frete, cabotagem, multimodal
3. **veiculos_tecnologia** (312 docs) - Elétricos, híbridos, autônomos, telemetria
4. **regulamentacao_orgaos** (445 docs) - CONTRAN, ANTT, ANP, ANA, ANEEL
5. **programas_politicas** (398 docs) - Rota 2030, Paten, Lei do Combustível do Futuro
6. **meio_ambiente** (356 docs) - Emissões, sustentabilidade, licenciamento
7. **seguranca_qualidade** (278 docs) - Segurança viária, fiscalização, certificação
8. **economia_mercado** (423 docs) - Preços, subsídios, financiamento, concessões
9. **inovacao_pd** (234 docs) - P&D, startups, propriedade intelectual
10. **infraestrutura** (189 docs) - Rodovias, ferrovias, portos, aeroportos
11. **tributacao** (167 docs) - ICMS, PIS, COFINS, CIDE
12. **internacional** (145 docs) - Acordos, tratados, cooperação
13. **social_trabalhista** (123 docs) - Direitos, condições de trabalho
14. **outros** (51 docs) - Documentos não categorizados

### Campos Principais:
```
search_term, date_searched, url, title, urn, urn_type, country, state, 
municipality, justice, region, court_class, document_type_full, 
enacting_date, document_description, document_summary
```

---

## 🚀 MISSÕES DE ANALYTICS

### MISSÃO 1: ANÁLISE TEMPORAL AVANÇADA
**Objetivo**: Identificar padrões evolutivos da regulamentação de transporte

**Tarefas Específicas**:
1. **Análise de Séries Temporais**:
   - Criar séries temporais por década (1850s-2020s)
   - Identificar pontos de mudança estrutural na produção normativa
   - Detectar ciclos políticos e sazonalidade regulatória
   - Correlacionar com eventos históricos (crises, mudanças de governo)

2. **Modelagem Preditiva Temporal**:
   - Implementar modelos ARIMA/SARIMA para previsão de produção normativa
   - Usar Prophet para detectar tendências e sazonalidades
   - Aplicar change point detection (PELT, CUSUM)
   - Criar forecasting para próximos 5 anos

3. **Análise de Eventos**:
   - Mapear impacto de crises (2008, 2014, COVID-19) na regulamentação
   - Analisar resposta regulatória a mudanças tecnológicas
   - Identificar lag temporal entre problemas e soluções normativas

**Código Esperado**:
```python
# Análise temporal com múltiplas técnicas
import pandas as pd
import numpy as np
from statsmodels.tsa.arima.model import ARIMA
from prophet import Prophet
import ruptures as rpt
import plotly.graph_objects as go

def analise_temporal_avancada(df):
    # Implementar análise completa
    pass
```

### MISSÃO 2: NETWORK ANALYSIS REGULATÓRIA
**Objetivo**: Mapear redes de influência e citações normativas

**Tarefas Específicas**:
1. **Rede de Citações**:
   - Extrair citações entre documentos via NLP
   - Construir grafo direcionado de influências normativas
   - Calcular métricas de centralidade (betweenness, eigenvector, PageRank)
   - Identificar documentos "hub" e "autoridade"

2. **Rede de Autoridades**:
   - Mapear colaboração entre órgãos reguladores
   - Analisar sobreposição de competências
   - Identificar clusters de atuação conjunta
   - Detectar conflitos de jurisdição

3. **Rede Temática**:
   - Criar rede de co-ocorrência de termos
   - Mapear evolução de temas ao longo do tempo
   - Identificar temas emergentes e declinantes
   - Detectar pontes entre domínios regulatórios

**Código Esperado**:
```python
import networkx as nx
import community
from sklearn.feature_extraction.text import TfidfVectorizer
import spacy

def network_analysis_regulatoria(df):
    # Construir e analisar redes complexas
    pass
```

### MISSÃO 3: NLP E ANÁLISE SEMÂNTICA
**Objetivo**: Extrair insights semânticos profundos dos textos normativos

**Tarefas Específicas**:
1. **Topic Modeling Avançado**:
   - Implementar LDA, BERTopic, Top2Vec
   - Analisar evolução temporal de tópicos
   - Identificar tópicos emergentes e declinantes
   - Mapear transferência de conceitos entre domínios

2. **Análise de Sentimento Regulatório**:
   - Desenvolver léxico específico para textos normativos
   - Classificar tom regulatório (restritivo vs permissivo)
   - Analisar urgência e prioridade de documentos
   - Detectar mudanças de postura regulatória

3. **Extração de Entidades e Relações**:
   - NER customizado para entidades regulatórias
   - Extração de relações entre atores e objetos
   - Mapeamento de stakeholders afetados
   - Análise de impacto setorial

**Código Esperado**:
```python
from transformers import pipeline, AutoTokenizer, AutoModel
from bertopic import BERTopic
from gensim import corpora, models
import spacy

def nlp_analysis_avancada(df):
    # Análise semântica profunda
    pass
```

### MISSÃO 4: MACHINE LEARNING PREDITIVO
**Objetivo**: Desenvolver modelos preditivos para análise regulatória

**Tarefas Específicas**:
1. **Classificação Automática**:
   - Treinar modelos para classificar novos documentos
   - Predizer tipo de documento baseado no conteúdo
   - Identificar autoridade competente automaticamente
   - Classificar urgência e impacto regulatório

2. **Análise de Impacto**:
   - Predizer setores afetados por nova regulamentação
   - Estimar custos de compliance
   - Identificar documentos com maior potencial de impacto
   - Prever necessidade de regulamentação complementar

3. **Detecção de Anomalias**:
   - Identificar documentos atípicos ou inconsistentes
   - Detectar possíveis erros de classificação
   - Encontrar lacunas regulatórias
   - Identificar sobreposições normativas

**Código Esperado**:
```python
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import cross_val_score, GridSearchCV
from xgboost import XGBClassifier
import lightgbm as lgb

def ml_preditivo_regulatorio(df):
    # Modelos de ML especializados
    pass
```

### MISSÃO 5: ANÁLISE GEOESPACIAL
**Objetivo**: Mapear distribuição geográfica da regulamentação

**Tarefas Específicas**:
1. **Mapeamento Federativo**:
   - Visualizar produção normativa por estado/município
   - Analisar federalismo regulatório
   - Identificar líderes e seguidores em inovação normativa
   - Mapear difusão de políticas entre entes federativos

2. **Análise de Clusters Regionais**:
   - Identificar regiões com padrões similares de regulamentação
   - Analisar influência de características socioeconômicas
   - Mapear corredores de transporte e sua regulamentação
   - Identificar vazios regulatórios geográficos

3. **Análise de Fronteiras**:
   - Estudar regulamentação em regiões fronteiriças
   - Analisar harmonização com países vizinhos
   - Mapear fluxos de comércio e regulamentação associada

**Código Esperado**:
```python
import geopandas as gpd
import folium
from sklearn.cluster import DBSCAN
import plotly.express as px

def analise_geoespacial(df):
    # Análise geográfica avançada
    pass
```

---

## 🔗 PESQUISAS COMPLEMENTARES OBRIGATÓRIAS

### DADOS ECONÔMICOS E SETORIAIS

**APIs Prioritárias**:
1. **IBGE**: Demografia, PIB regional, índices econômicos
2. **ANP**: Preços de combustíveis, produção de biocombustíveis
3. **EPE**: Balanço Energético Nacional, consumo por setor
4. **ANTT**: Frota de veículos, acidentes, fiscalizações
5. **ANA**: Dados hidroviários, navegabilidade
6. **DNIT**: Infraestrutura rodoviária, investimentos

**Implementação**:
```python
def integrar_dados_complementares():
    # APIs do IBGE
    ibge_data = fetch_ibge_api(['pib_municipal', 'populacao', 'frota_veiculos'])
    
    # Dados da ANP
    anp_data = fetch_anp_data(['precos_combustiveis', 'producao_biodiesel'])
    
    # Dados da EPE
    epe_data = fetch_epe_data(['ben_transporte', 'consumo_energetico'])
    
    return merge_datasets([ibge_data, anp_data, epe_data])
```

### DADOS INTERNACIONAIS

**Fontes Obrigatórias**:
1. **IEA**: World Energy Statistics, Transport Energy Statistics
2. **IRENA**: Renewable Energy Statistics, Transport Transition
3. **World Bank**: Transport indicators, Infrastructure investment
4. **OECD**: Transport policies, Environmental indicators
5. **IMF**: Fuel subsidies, Carbon pricing

**Análise Comparativa**:
```python
def benchmarking_internacional():
    # Comparar Brasil com países similares
    # Identificar melhores práticas
    # Analisar gaps regulatórios
    pass
```

### DADOS DE MERCADO E INOVAÇÃO

**Fontes Especializadas**:
1. **BNDES**: Financiamentos para transporte e energia
2. **FINEP**: Projetos de P&D em transporte
3. **INPI**: Patentes relacionadas a transporte limpo
4. **ABDI**: Estudos setoriais e competitividade

---

## 📈 DASHBOARDS E VISUALIZAÇÕES

### DASHBOARD EXECUTIVO
**Componentes Obrigatórios**:
1. **KPIs Principais**:
   - Produção normativa por período
   - Distribuição por tipo de documento
   - Cobertura geográfica
   - Temas emergentes

2. **Visualizações Interativas**:
   - Timeline interativo da regulamentação
   - Mapa coroplético da produção normativa
   - Rede de citações navegável
   - Word clouds temporais

3. **Análises Preditivas**:
   - Forecast de produção normativa
   - Temas emergentes identificados
   - Gaps regulatórios detectados

**Implementação Shiny**:
```r
library(shiny)
library(plotly)
library(DT)
library(leaflet)

ui <- fluidPage(
  # Dashboard executivo completo
)

server <- function(input, output) {
  # Lógica do dashboard
}
```

### RELATÓRIOS AUTOMATIZADOS
**Frequência**: Mensal, trimestral, anual
**Conteúdo**:
1. Síntese da produção normativa
2. Análise de tendências
3. Identificação de gaps
4. Recomendações estratégicas

---

## 🎯 CASOS DE USO ESPECÍFICOS

### CASO 1: MONITORAMENTO DE TRANSIÇÃO ENERGÉTICA
**Objetivo**: Acompanhar evolução regulatória da eletrificação

**Análises Específicas**:
1. Evolução da regulamentação de veículos elétricos
2. Incentivos fiscais e sua efetividade
3. Infraestrutura de recarga: marcos regulatórios
4. Comparação com políticas internacionais

### CASO 2: ANÁLISE DE IMPACTO REGULATÓRIO
**Objetivo**: Avaliar efeitos de mudanças normativas

**Metodologia**:
1. Difference-in-differences para avaliar impacto
2. Análise de interrupção de séries temporais
3. Matching para grupos de controle
4. Análise de custo-benefício

### CASO 3: INTELIGÊNCIA COMPETITIVA
**Objetivo**: Antecipar mudanças regulatórias

**Ferramentas**:
1. Early warning system baseado em ML
2. Análise de sinais fracos
3. Monitoramento de consultas públicas
4. Tracking de proposições legislativas

---

## 🔧 ESPECIFICAÇÕES TÉCNICAS

### AMBIENTE DE DESENVOLVIMENTO
```python
# Pacotes obrigatórios
packages = [
    'pandas', 'numpy', 'scipy', 'scikit-learn',
    'networkx', 'community', 'plotly', 'seaborn',
    'spacy', 'transformers', 'bertopic', 'gensim',
    'statsmodels', 'prophet', 'ruptures',
    'geopandas', 'folium', 'requests', 'beautifulsoup4'
]
```

### ESTRUTURA DE CÓDIGO
```
projeto/
├── data/
│   ├── raw/              # Dados brutos
│   ├── processed/        # Dados processados
│   └── external/         # Dados externos (APIs)
├── src/
│   ├── data/            # Scripts de coleta e limpeza
│   ├── features/        # Engenharia de features
│   ├── models/          # Modelos de ML
│   ├── visualization/   # Visualizações
│   └── utils/           # Utilitários
├── notebooks/           # Jupyter notebooks
├── reports/            # Relatórios gerados
└── dashboard/          # Aplicação Shiny
```

### PADRÕES DE QUALIDADE
1. **Documentação**: Docstrings em todas as funções
2. **Testes**: Cobertura mínima de 80%
3. **Versionamento**: Git com commits semânticos
4. **Reprodutibilidade**: Seeds fixas, ambientes virtuais
5. **Performance**: Profiling e otimização

---

## 📋 ENTREGÁVEIS ESPERADOS

### CÓDIGO
1. **Scripts de análise** para cada missão
2. **Notebooks exploratórios** documentados
3. **Dashboard interativo** em Shiny/Streamlit
4. **APIs** para consulta de dados
5. **Testes automatizados** para validação

### DOCUMENTAÇÃO
1. **Relatório técnico** (50+ páginas)
2. **Manual do usuário** para dashboard
3. **Documentação de APIs** (Swagger)
4. **Guia de reprodução** dos resultados
5. **Apresentação executiva** (20 slides)

### INSIGHTS
1. **Top 10 descobertas** mais relevantes
2. **Recomendações estratégicas** para formuladores
3. **Gaps regulatórios** identificados
4. **Oportunidades de melhoria** no sistema
5. **Roadmap** para próximos desenvolvimentos

---

## ⚡ EXECUÇÃO IMEDIATA

**Comece agora com**:
```python
# 1. Carregar e explorar o dataset
df = pd.read_excel('CSV-Ajustado.xlsx', sheet_name=None)

# 2. Análise exploratória básica
for sheet_name, data in df.items():
    print(f"Sheet: {sheet_name}, Shape: {data.shape}")
    
# 3. Primeira análise temporal
temporal_analysis = analyze_temporal_patterns(df)

# 4. Network analysis inicial
network_data = build_regulatory_network(df)

# 5. NLP básico
nlp_insights = extract_semantic_insights(df)
```

**Prioridades**:
1. ✅ Análise temporal (Missão 1)
2. ✅ Network analysis (Missão 2)  
3. ✅ NLP e semântica (Missão 3)
4. ✅ ML preditivo (Missão 4)
5. ✅ Análise geoespacial (Missão 5)

---

## 🎯 OBJETIVO FINAL

Transformar o dataset LexML em um **sistema de inteligência regulatória** que permita:

1. **Monitoramento em tempo real** da produção normativa
2. **Antecipação de tendências** regulatórias
3. **Análise de impacto** de mudanças normativas
4. **Benchmarking internacional** de políticas
5. **Suporte à tomada de decisão** baseada em evidências

**Meta**: Criar o mais avançado sistema de analytics regulatórios do Brasil, servindo como referência internacional para análise de dados legislativos.

---

*Prompt desenvolvido por Manus AI baseado em dataset real de 4.097 documentos do LexML*  
*Versão: Avançada - 2025-07-15*

