# Monitor Legislativo R SDK

<img src="https://img.shields.io/badge/R-276DC3?style=for-the-badge&logo=r&logoColor=white" alt="R"> <img src="https://img.shields.io/badge/API-v4.0-blue?style=for-the-badge" alt="API Version"> <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">

O Monitor Legislativo R SDK é uma biblioteca abrangente que fornece acesso programático ao maior banco de dados de legislação brasileira, contendo mais de **134.000 documentos legislativos** autênticos. Desenvolvido especificamente para pesquisadores acadêmicos, o SDK oferece ferramentas poderosas para análise, visualização e exportação de dados legislativos brasileiros.

## 🚀 Características Principais

- **134k+ Documentos**: Acesso completo à legislação brasileira de todos os níveis
- **Busca Avançada**: Processamento de linguagem natural em português com operadores booleanos
- **Análise Geográfica**: Mapeamento e análise espacial com dados do IBGE
- **Citações ABNT**: Geração automática de citações acadêmicas padrão brasileiro
- **Análise Temporal**: Estudos longitudinais e análise de tendências
- **Exportação Múltipla**: Suporte a CSV, JSON, Excel, BibTeX, RIS e outros formatos
- **Integração Tidyverse**: Compatibilidade total com dplyr, ggplot2 e ecosystem R moderno
- **Cache Inteligente**: Otimização automática para melhor performance
- **Documentação Completa**: Vinhetas detalhadas e exemplos práticos

## 📦 Instalação

### Instalação via GitHub (Recomendado)

```r
# Instalar devtools se necessário
if (!require(devtools)) install.packages("devtools")

# Instalar o SDK
devtools::install_github("monitor-legislativo/r-sdk")
```

### Dependências

O SDK requer R >= 4.0.0 e as seguintes dependências principais:

```r
# Dependências principais (instaladas automaticamente)
install.packages(c(
  "httr2", "jsonlite", "dplyr", "tibble", "purrr",
  "stringr", "lubridate", "ggplot2", "cli", "glue"
))

# Dependências opcionais para funcionalidades avançadas
install.packages(c(
  "sf", "readr", "keyring", "writexl", "arrow"
))
```

## 🔧 Configuração Rápida

### 1. Obter Chave de API

```r
# Registre-se gratuitamente em:
# https://monitor-legislativo.br/api/register
```

### 2. Configurar SDK

```r
library(monitor.legislativo)

# Configurar chave de API
ml_set_api_key("sua_chave_de_api_aqui")

# Verificar autenticação
auth_info <- ml_authenticate()
print(auth_info)
```

### 3. Primeira Busca

```r
# Busca básica
resultados <- ml_search("lei de licitações")
print(resultados)

# Busca avançada com filtros
resultados_avancados <- ml_search(
  query = "transporte público",
  filters = list(
    category = "Lei",
    state = "SP", 
    date_start = "2020-01-01"
  ),
  limit = 100
)
```

## 📊 Exemplos de Uso

### Análise Temporal

```r
library(ggplot2)

# Analisar evolução da legislação ambiental
trends <- ml_analyze_trends(
  query = "meio ambiente",
  time_granularity = "month",
  date_range = c("2020-01-01", "2023-12-31")
)

# Visualizar tendências
ggplot(trends$time_series, aes(x = date, y = volume)) +
  geom_line(color = "forestgreen", size = 1) +
  labs(title = "Evolução da Legislação Ambiental (2020-2023)",
       x = "Período", y = "Número de Documentos") +
  theme_minimal()
```

### Análise Geográfica

```r
# Análise por estados
geo_analysis <- ml_geographic_analysis(
  query = "educação",
  geographic_level = "state",
  aggregation = "count"
)

# Top 10 estados
top_states <- geo_analysis %>%
  arrange(desc(document_count)) %>%
  head(10)

# Visualização
ggplot(top_states, aes(x = reorder(name, document_count), y = document_count)) +
  geom_col(fill = "steelblue") +
  coord_flip() +
  labs(title = "Legislação Educacional por Estado",
       x = "Estado", y = "Número de Documentos")
```

### Citações Acadêmicas

```r
# Gerar citações ABNT
docs <- ml_search("sustentabilidade", limit = 5)
citacoes <- ml_generate_citations(docs, citation_style = "abnt")

# Criar bibliografia completa
bibliografia <- ml_create_bibliography(
  documents = docs,
  title = "Bibliografia: Sustentabilidade na Legislação Brasileira",
  sort_by = "date"
)

# Exportar para BibTeX
ml_export_bibtex(docs, "sustentabilidade.bib", format = "bibtex")
```

### Exportação de Dados

```r
# Exportar para múltiplos formatos
ml_export_data(resultados, "dados.csv", format = "csv")
ml_export_data(resultados, "dados.json", format = "json")
ml_export_data(resultados, "dados.xlsx", format = "excel")

# Download em lote com organização
ml_bulk_download(
  document_ids = resultados$id,
  output_dir = "dataset_legislacao",
  organize_by = "category",
  include_citations = TRUE
)
```

### Dataset Personalizado

```r
# Criar dataset temático completo
dataset <- ml_create_dataset(
  search_params = list(
    query = "covid-19 OR coronavirus",
    filters = list(date_start = "2020-01-01"),
    limit = 1000
  ),
  processing = list(
    include_geographic = TRUE,
    include_temporal_analysis = TRUE,
    include_citations = TRUE
  ),
  dataset_name = "Legislacao_COVID19_Brasil",
  description = "Legislação brasileira relacionada à pandemia COVID-19"
)
```

## 📚 Documentação Completa

### Vinhetas Disponíveis

```r
# Guia inicial
vignette("getting-started", package = "monitor.legislativo")

# Técnicas avançadas de busca
vignette("advanced-search", package = "monitor.legislativo")

# Análise geográfica
vignette("geographic-analysis", package = "monitor.legislativo")

# Análise temporal
vignette("temporal-analysis", package = "monitor.legislativo")

# Gestão de citações
vignette("citation-management", package = "monitor.legislativo")
```

### Funções Principais

| Categoria | Função | Descrição |
|-----------|--------|-----------|
| **Autenticação** | `ml_set_api_key()` | Configurar chave de API |
| | `ml_authenticate()` | Autenticar e verificar limites |
| **Busca** | `ml_search()` | Busca geral de documentos |
| | `ml_search_advanced()` | Busca com operadores booleanos |
| | `ml_search_similar()` | Encontrar documentos similares |
| **Documentos** | `ml_get_document()` | Obter documento específico |
| | `ml_get_documents()` | Obter múltiplos documentos |
| | `ml_filter_documents()` | Filtrar resultados |
| **Geografia** | `ml_geographic_analysis()` | Análise espacial |
| | `ml_get_states()` | Dados dos estados brasileiros |
| | `ml_get_municipalities()` | Dados municipais |
| **Analytics** | `ml_analyze_trends()` | Análise temporal |
| | `ml_get_metrics()` | Métricas da plataforma |
| | `ml_dashboard_data()` | Dados para dashboards |
| **Citações** | `ml_generate_citations()` | Gerar citações ABNT/APA |
| | `ml_create_bibliography()` | Criar bibliografia |
| | `ml_export_bibtex()` | Exportar para gestores de referência |
| **Exportação** | `ml_export_data()` | Exportar dados |
| | `ml_bulk_download()` | Download em lote |
| | `ml_create_dataset()` | Criar dataset personalizado |

## 🔍 Casos de Uso Acadêmico

### Pesquisa em Direito

```r
# Análise jurisprudencial
jurisprudencia <- ml_search_advanced(
  query = "jurisprudência AND (STF OR STJ OR TST)",
  search_fields = c("title", "content"),
  boost_legal_terms = TRUE
)

# Análise de precedentes
precedentes <- ml_search_similar(
  content = "Este acórdão estabelece precedente sobre...",
  similarity_threshold = 0.8
)
```

### Ciência Política

```r
# Análise de políticas públicas por período eleitoral
eleicoes_2018 <- ml_search(
  "política pública",
  filters = list(date_start = "2018-01-01", date_end = "2018-12-31")
)

eleicoes_2022 <- ml_search(
  "política pública", 
  filters = list(date_start = "2022-01-01", date_end = "2022-12-31")
)

# Comparação estatística
comparacao <- ml_comparative_analysis(
  period1 = c("2018-01-01", "2018-12-31"),
  period2 = c("2022-01-01", "2022-12-31"),
  comparison_metrics = c("volume", "diversity", "geographic")
)
```

### Estudos Socioambientais

```r
# Mapeamento da legislação ambiental
ambiental_geo <- ml_geographic_analysis(
  query = "licenciamento ambiental OR impacto ambiental",
  geographic_level = "municipality",
  include_geometry = TRUE
)

# Criar mapa coroplético
mapa <- ml_create_choropleth_map(
  data = ambiental_geo,
  fill_variable = "document_count",
  title = "Densidade de Legislação Ambiental por Município"
)
```

## ⚡ Performance e Otimização

### Cache Automático

```r
# Habilitar cache para melhor performance
ml_set_options(cache_enabled = TRUE, timeout = 60)

# Busca é automaticamente cached
resultados1 <- ml_search("energia solar")  # Primeira busca
resultados2 <- ml_search("energia solar")  # Usa cache (mais rápido)
```

### Processamento em Lotes

```r
# Para grandes volumes de dados
grandes_resultados <- ml_search("sustentabilidade", limit = 5000)

# Processar em lotes para melhor performance
chunks <- split(grandes_resultados$id, ceiling(seq_along(grandes_resultados$id) / 100))

documentos_completos <- map_dfr(chunks, function(chunk) {
  ml_get_documents(chunk, batch_size = 50)
})
```

## 🔒 Segurança e Boas Práticas

### Armazenamento Seguro de Credenciais

```r
# Nunca exponha chaves de API no código
# Use armazenamento seguro:
ml_set_api_key("sua_chave", store_securely = TRUE)

# Ou variáveis de ambiente:
Sys.setenv(MONITOR_LEGISLATIVO_API_KEY = "sua_chave")
ml_set_api_key(Sys.getenv("MONITOR_LEGISLATIVO_API_KEY"))
```

### Gestão de Rate Limits

```r
# Verificar uso atual
auth_info <- ml_authenticate(check_usage = TRUE)
print(auth_info$usage_stats)

# O SDK automaticamente respeita rate limits
# Para uso intensivo, considere pausas:
Sys.sleep(0.1)  # Entre requisições
```

## 🤝 Suporte e Comunidade

### Obter Ajuda

- **Documentação**: [https://monitor-legislativo.br/r-sdk](https://monitor-legislativo.br/r-sdk)
- **Email**: api-support@monitor-legislativo.br
- **GitHub Issues**: [https://github.com/monitor-legislativo/r-sdk/issues](https://github.com/monitor-legislativo/r-sdk/issues)
- **Fórum**: [https://forum.monitor-legislativo.br](https://forum.monitor-legislativo.br)

### Contribuir

Contribuições são bem-vindas! Veja [CONTRIBUTING.md](CONTRIBUTING.md) para diretrizes.

### Citar este Trabalho

```r
# Gerar citação do próprio SDK
sdk_citation <- ml_generate_citations(
  list(
    title = "Monitor Legislativo R SDK: Access to Brazilian Legislative Data",
    author = "Monitor Legislativo Research Team",
    year = "2024",
    url = "https://github.com/monitor-legislativo/r-sdk"
  ),
  citation_style = "abnt"
)

print(sdk_citation)
```

## 📄 Licença

Este projeto está licenciado sob a Licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🙏 Agradecimentos

- Equipe do Monitor Legislativo
- Comunidade R brasileira
- Pesquisadores e acadêmicos que contribuem com feedback
- IBGE pelos dados geográficos oficiais

---

**Monitor Legislativo R SDK** - Democratizando o acesso aos dados legislativos brasileiros para pesquisa acadêmica.

*Desenvolvido com ❤️ pela equipe do Monitor Legislativo*