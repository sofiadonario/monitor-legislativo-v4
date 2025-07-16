# Fontes de Dados Energéticos para Análise Regulatória do Transporte

**Autor:** Manus AI  
**Data:** 2025-07-12  
**Versão:** 1.0  

## Resumo Executivo

Este documento consolida todas as principais fontes de dados sobre energia, combustíveis e transição energética relevantes para análise regulatória do transporte de carga. Inclui agências nacionais, institutos de pesquisa e organizações internacionais com suas respectivas APIs, datasets e metodologias de integração.

## 1. Agências Reguladoras Nacionais

### 1.1 ANP - Agência Nacional do Petróleo, Gás Natural e Biocombustíveis

**Portal Principal**: https://www.gov.br/anp/pt-br  
**Portal de Dados Abertos**: https://dados.gov.br/organization/agencia-nacional-do-petroleo-gas-natural-e-biocombustiveis-anp  
**API**: https://dados.gov.br/api/publico/conjuntos-dados/

#### Principais Datasets

| Dataset | Descrição | Frequência | Formato |
|---------|-----------|------------|---------|
| Preços de Combustíveis | Preços semanais por região e município | Semanal | CSV, JSON |
| Produção de Petróleo | Produção por campo e operadora | Mensal | CSV, XLS |
| Refino e Distribuição | Capacidade e movimentação | Mensal | CSV |
| Biocombustíveis | Produção de etanol e biodiesel | Mensal | CSV |
| Qualidade de Combustíveis | Análises laboratoriais | Mensal | CSV |
| Infraestrutura | Postos, bases, dutos | Anual | CSV, SHP |

#### Implementação em R
```r
# Pacote para acessar dados da ANP
library(httr)
library(jsonlite)
library(tidyverse)

get_anp_fuel_prices <- function(year = NULL, state = NULL) {
  base_url <- "https://dados.gov.br/api/publico/conjuntos-dados/"
  endpoint <- "serie-historica-de-precos-de-combustiveis"
  
  params <- list()
  if (!is.null(year)) params$ano <- year
  if (!is.null(state)) params$estado <- state
  
  response <- GET(paste0(base_url, endpoint), query = params)
  
  if (status_code(response) == 200) {
    data <- fromJSON(content(response, "text"))
    return(data)
  } else {
    stop("Erro ao acessar dados da ANP: ", status_code(response))
  }
}
```

### 1.2 EPE - Empresa de Pesquisa Energética

**Portal Principal**: https://www.epe.gov.br/  
**Portal de Dados**: https://www.epe.gov.br/pt/publicacoes-dados-abertos  
**API**: https://www.epe.gov.br/api/

#### Principais Publicações

| Publicação | Descrição | Frequência | Relevância para Transporte |
|------------|-----------|------------|---------------------------|
| Balanço Energético Nacional (BEN) | Matriz energética completa | Anual | ⭐⭐⭐⭐⭐ |
| Plano Decenal de Expansão (PDE) | Projeções de demanda | Anual | ⭐⭐⭐⭐ |
| Anuário Estatístico de Energia | Dados do setor elétrico | Anual | ⭐⭐⭐ |
| Estudos de Demanda | Projeções setoriais | Anual | ⭐⭐⭐⭐⭐ |
| Nota Técnica - Transporte | Análises específicas | Irregular | ⭐⭐⭐⭐⭐ |

### 1.3 ANEEL - Agência Nacional de Energia Elétrica

**Portal Principal**: https://www.gov.br/aneel/pt-br  
**Portal de Dados**: https://dadosabertos.aneel.gov.br/  

#### Dados Relevantes para Transporte

| Dataset | Descrição | Relevância |
|---------|-----------|------------|
| Infraestrutura de Recarga | Estações para veículos elétricos | ⭐⭐⭐⭐⭐ |
| Tarifas de Energia | Custos por região | ⭐⭐⭐⭐ |
| Geração Distribuída | Micro e minigeração | ⭐⭐⭐ |
| Qualidade de Energia | Indicadores de continuidade | ⭐⭐⭐ |

### 1.4 MME - Ministério de Minas e Energia

**Portal Principal**: https://www.gov.br/mme/pt-br  
**Portal de Dados**: https://www.gov.br/mme/pt-br/acesso-a-informacao/dados-abertos  

#### Programas e Dados Estratégicos

- **RenovaBio**: Programa nacional de biocombustíveis
- **Programa Nacional de Produção e Uso do Biodiesel (PNPB)**
- **Resenha Energética Brasileira**: Síntese anual
- **Boletim Mensal de Combustíveis Renováveis**

## 2. Institutos de Pesquisa Nacionais

### 2.1 INPE - Instituto Nacional de Pesquisas Espaciais

**Portal**: https://www.gov.br/inpe/pt-br  
**Dados Ambientais**: http://terrabrasilis.dpi.inpe.br/

#### Datasets Ambientais Relevantes

| Sistema | Descrição | Aplicação no Transporte |
|---------|-----------|------------------------|
| PRODES | Monitoramento do desmatamento | Impacto de biocombustíveis |
| SEEG | Emissões de GEE por setor | Emissões do transporte |
| Queimadas | Monitoramento de focos | Qualidade do ar |

### 2.2 IPT - Instituto de Pesquisas Tecnológicas

**Portal**: https://www.ipt.br/  

#### Áreas de Pesquisa Relevantes

- **Centro de Tecnologia em Combustíveis**
- **Laboratório de Biocombustíveis**
- **Pesquisa em Mobilidade Elétrica**
- **Materiais Avançados para Energia**

### 2.3 CETESB - Companhia Ambiental do Estado de São Paulo

**Portal**: https://cetesb.sp.gov.br/  
**Dados de Qualidade do Ar**: https://qualar.cetesb.sp.gov.br/

#### Monitoramento Ambiental

- **Qualidade do Ar**: Estações de monitoramento
- **Emissões Veiculares**: Inventários de emissões
- **Programa de Controle da Poluição do Ar por Veículos Automotores (PROCONVE)**

## 3. Organizações Internacionais

### 3.1 IEA - International Energy Agency

**Portal Principal**: https://www.iea.org/  
**Portal de Dados**: https://www.iea.org/data-and-statistics  
**API**: https://www.iea.org/api/

#### Principais Bases de Dados

| Base de Dados | Descrição | Cobertura | API Disponível |
|---------------|-----------|-----------|----------------|
| World Energy Statistics | Estatísticas energéticas globais | 150+ países | ✅ |
| Energy Transition Indicators | Indicadores de transição | Global | ✅ |
| Transport Biofuels | Biocombustíveis para transporte | Global | ✅ |
| EV Data Explorer | Veículos elétricos | 40+ países | ✅ |
| Energy Efficiency Indicators | Eficiência energética | Global | ✅ |

#### Implementação em R
```r
# Função para acessar dados da IEA
get_iea_data <- function(indicator, country = "BRAZIL", start_year = 2000) {
  
  # Configurar autenticação (requer API key)
  api_key <- Sys.getenv("IEA_API_KEY")
  
  if (api_key == "") {
    stop("API key da IEA não configurada. Configure IEA_API_KEY no ambiente.")
  }
  
  base_url <- "https://api.iea.org/stats"
  
  params <- list(
    indicator = indicator,
    country = country,
    startYear = start_year,
    endYear = year(Sys.Date()),
    key = api_key
  )
  
  response <- GET(base_url, query = params)
  
  if (status_code(response) == 200) {
    data <- fromJSON(content(response, "text"))
    return(data)
  } else {
    stop("Erro ao acessar IEA: ", status_code(response))
  }
}

# Indicadores principais para transporte
transport_indicators <- c(
  "TOTTRANSPET",  # Total transport energy consumption
  "TOTBIOGAS",    # Total biogasoline
  "TOTBIODIES",   # Total biodiesel
  "ELECCONS",     # Electricity consumption
  "RENEWCONS"     # Renewable energy consumption
)
```

### 3.2 IRENA - International Renewable Energy Agency

**Portal Principal**: https://www.irena.org/  
**Portal de Dados**: https://www.irena.org/Data  
**API**: https://www.irena.org/api/

#### Principais Datasets

| Dataset | Descrição | Relevância |
|---------|-----------|------------|
| Global Energy Transformation | Dados de transição energética | ⭐⭐⭐⭐⭐ |
| Renewable Energy Statistics | Estatísticas de renováveis | ⭐⭐⭐⭐ |
| Innovation and Technology | Inovação em renováveis | ⭐⭐⭐⭐ |
| Energy Transition Scenarios | Cenários de transição | ⭐⭐⭐⭐⭐ |

### 3.3 OECD - Organisation for Economic Co-operation and Development

**Portal**: https://www.oecd.org/  
**Dados**: https://data.oecd.org/  

#### Indicadores Relevantes

- **Transport CO2 Emissions**: Emissões de CO2 do transporte
- **Energy Intensity**: Intensidade energética
- **Renewable Energy**: Participação de renováveis
- **Energy Prices and Taxes**: Preços e impostos energéticos

## 4. Organizações Setoriais Especializadas

### 4.1 ICCT - International Council on Clean Transportation

**Portal**: https://theicct.org/  

#### Áreas de Especialização

- **Vehicle Efficiency Standards**: Padrões de eficiência veicular
- **Zero Emission Zones**: Zonas de emissão zero
- **Heavy-Duty Vehicle Emissions**: Emissões de veículos pesados
- **Biofuel Sustainability**: Sustentabilidade de biocombustíveis
- **Electric Vehicle Policy**: Políticas para veículos elétricos

### 4.2 GBEP - Global Bioenergy Partnership

**Portal**: http://www.globalbioenergy.org/  

#### Indicadores de Sustentabilidade

- **Environmental Indicators**: Indicadores ambientais
- **Social Indicators**: Indicadores sociais
- **Economic Indicators**: Indicadores econômicos
- **Country Reports**: Relatórios por país

### 4.3 IEA Bioenergy

**Portal**: https://www.ieabioenergy.com/  

#### Dados Especializados

- **Bioenergy Country Reports**: Relatórios por país
- **Technology Roadmaps**: Roadmaps tecnológicos
- **Sustainability Criteria**: Critérios de sustentabilidade
- **Market Reports**: Relatórios de mercado

## 5. Agências Regionais (Europa e América do Norte)

### 5.1 EEA - European Environment Agency

**Portal**: https://www.eea.europa.eu/  
**Dados**: https://www.eea.europa.eu/data-and-maps  

#### Dados de Transporte e Ambiente

- **Transport and Environment Reporting Information System (TERM)**
- **Air Quality Data**
- **Climate Change Mitigation**
- **Sustainable Transport**

### 5.2 EPA - Environmental Protection Agency (EUA)

**Portal**: https://www.epa.gov/  
**Dados**: https://www.epa.gov/data  

#### Datasets de Transporte

- **Transportation and Climate Division**
- **Fuel Economy Data**
- **Alternative Fuel Infrastructure**
- **SmartWay Program Data**

### 5.3 DOE - Department of Energy (EUA)

**Portal**: https://www.energy.gov/  
**Dados**: https://www.energy.gov/data/open-energy-data  

#### Centros de Dados Especializados

- **Alternative Fuels Data Center (AFDC)**
- **Vehicle Technologies Office**
- **Bioenergy Research Centers**
- **Clean Cities Program**

## 6. Implementação Integrada

### 6.1 Pipeline de Coleta Automatizada

```r
# Classe principal para integração de dados energéticos
EnergyDataCollector <- R6Class("EnergyDataCollector",
  
  public = list(
    
    # Configuração inicial
    initialize = function() {
      private$setup_apis()
      private$validate_credentials()
    },
    
    # Coletar dados nacionais
    collect_national_data = function(years = 2000:2025) {
      
      results <- list()
      
      # ANP - Combustíveis
      cat("Coletando dados da ANP...\n")
      results$anp <- private$collect_anp_comprehensive(years)
      
      # EPE - Energia
      cat("Coletando dados da EPE...\n")
      results$epe <- private$collect_epe_comprehensive(years)
      
      # ANEEL - Energia Elétrica
      cat("Coletando dados da ANEEL...\n")
      results$aneel <- private$collect_aneel_data(years)
      
      # INPE - Dados Ambientais
      cat("Coletando dados do INPE...\n")
      results$inpe <- private$collect_inpe_data(years)
      
      return(results)
    },
    
    # Coletar dados internacionais
    collect_international_data = function(countries = c("BRAZIL"), years = 2000:2025) {
      
      results <- list()
      
      # IEA
      cat("Coletando dados da IEA...\n")
      results$iea <- private$collect_iea_comprehensive(countries, years)
      
      # IRENA
      cat("Coletando dados da IRENA...\n")
      results$irena <- private$collect_irena_data(countries, years)
      
      # OECD
      cat("Coletando dados da OECD...\n")
      results$oecd <- private$collect_oecd_data(countries, years)
      
      return(results)
    },
    
    # Integrar todos os dados
    integrate_all_sources = function() {
      
      # Coletar dados
      national_data <- self$collect_national_data()
      international_data <- self$collect_international_data()
      
      # Padronizar estruturas
      standardized_data <- private$standardize_all_data(national_data, international_data)
      
      # Validar qualidade
      quality_report <- private$generate_quality_report(standardized_data)
      
      # Criar dataset integrado
      integrated_dataset <- private$create_integrated_dataset(standardized_data)
      
      return(list(
        data = integrated_dataset,
        quality_report = quality_report,
        metadata = private$generate_metadata()
      ))
    }
  ),
  
  private = list(
    
    api_credentials = list(),
    base_urls = list(),
    rate_limits = list(),
    
    # Configurar APIs
    setup_apis = function() {
      private$base_urls <- list(
        anp = "https://dados.gov.br/api/publico/conjuntos-dados/",
        epe = "https://www.epe.gov.br/api/",
        aneel = "https://dadosabertos.aneel.gov.br/api/",
        iea = "https://api.iea.org/stats/",
        irena = "https://www.irena.org/api/",
        oecd = "https://stats.oecd.org/restsdmx/sdmx.ashx/"
      )
      
      private$rate_limits <- list(
        anp = 60,      # requests per minute
        epe = 30,
        aneel = 60,
        iea = 100,
        irena = 50,
        oecd = 100
      )
    },
    
    # Validar credenciais
    validate_credentials = function() {
      
      required_keys <- c("IEA_API_KEY", "IRENA_API_KEY")
      
      for (key in required_keys) {
        if (Sys.getenv(key) == "") {
          warning("API key não configurada: ", key)
        }
      }
    },
    
    # Métodos específicos de coleta
    collect_anp_comprehensive = function(years) {
      
      anp_data <- list()
      
      # Preços de combustíveis
      anp_data$fuel_prices <- map_dfr(years, ~{
        private$get_anp_fuel_prices(.x)
      })
      
      # Produção de biocombustíveis
      anp_data$biofuel_production <- map_dfr(years, ~{
        private$get_anp_biofuel_production(.x)
      })
      
      # Infraestrutura
      anp_data$infrastructure <- private$get_anp_infrastructure()
      
      return(anp_data)
    },
    
    # Padronização de dados
    standardize_all_data = function(national_data, international_data) {
      
      # Estrutura padrão
      standard_structure <- list(
        year = integer(),
        country = character(),
        indicator = character(),
        value = numeric(),
        unit = character(),
        source = character()
      )
      
      # Padronizar dados nacionais
      standardized_national <- private$standardize_national_data(national_data)
      
      # Padronizar dados internacionais
      standardized_international <- private$standardize_international_data(international_data)
      
      # Combinar
      combined_data <- bind_rows(standardized_national, standardized_international)
      
      return(combined_data)
    },
    
    # Gerar relatório de qualidade
    generate_quality_report = function(data) {
      
      quality_metrics <- list(
        
        # Completude por fonte
        completeness_by_source = data %>%
          group_by(source) %>%
          summarise(
            total_records = n(),
            missing_values = sum(is.na(value)),
            completeness_rate = 1 - (missing_values / total_records),
            .groups = "drop"
          ),
        
        # Cobertura temporal
        temporal_coverage = data %>%
          group_by(source, indicator) %>%
          summarise(
            min_year = min(year, na.rm = TRUE),
            max_year = max(year, na.rm = TRUE),
            years_covered = n_distinct(year),
            .groups = "drop"
          ),
        
        # Consistência de unidades
        unit_consistency = data %>%
          group_by(indicator) %>%
          summarise(
            unique_units = n_distinct(unit),
            units = paste(unique(unit), collapse = ", "),
            .groups = "drop"
          ),
        
        # Outliers por indicador
        outliers = data %>%
          group_by(indicator) %>%
          mutate(
            z_score = abs((value - mean(value, na.rm = TRUE)) / sd(value, na.rm = TRUE))
          ) %>%
          filter(z_score > 3) %>%
          select(year, country, indicator, value, z_score, source)
      )
      
      return(quality_metrics)
    }
  )
)
```

### 6.2 Exemplo de Uso Completo

```r
# Inicializar coletor
collector <- EnergyDataCollector$new()

# Coletar e integrar todos os dados
integrated_results <- collector$integrate_all_sources()

# Acessar dados integrados
energy_data <- integrated_results$data
quality_report <- integrated_results$quality_report

# Análise específica para transporte
transport_energy_analysis <- energy_data %>%
  filter(str_detect(indicator, "transport|fuel|biofuel|electric")) %>%
  arrange(year, indicator)

# Visualização
library(ggplot2)

transport_trends <- ggplot(transport_energy_analysis, 
                          aes(x = year, y = value, color = source)) +
  geom_line(size = 1) +
  facet_wrap(~indicator, scales = "free_y") +
  labs(
    title = "Tendências Energéticas no Transporte - Fontes Integradas",
    subtitle = "Dados de ANP, EPE, IEA, IRENA e outras fontes",
    x = "Ano",
    y = "Valor",
    color = "Fonte"
  ) +
  theme_minimal() +
  theme(legend.position = "bottom")

print(transport_trends)
```

## 7. Cronograma de Implementação

### Fase 1 (Semanas 1-2): Configuração Básica
- Configurar credenciais de APIs
- Implementar coletores básicos para ANP e EPE
- Validar acesso a dados nacionais

### Fase 2 (Semanas 3-4): Expansão Nacional
- Integrar ANEEL e INPE
- Implementar padronização de dados
- Criar pipeline de validação

### Fase 3 (Semanas 5-6): Dados Internacionais
- Implementar coletores IEA e IRENA
- Integrar dados OECD
- Harmonizar estruturas de dados

### Fase 4 (Semanas 7-8): Integração e Qualidade
- Criar dataset integrado final
- Implementar relatórios de qualidade
- Desenvolver visualizações

## 8. Considerações Finais

Esta estrutura abrangente de fontes de dados energéticos proporciona uma base sólida para análises integradas de regulamentação e transição energética no transporte de carga. A implementação gradual e sistemática garantirá qualidade e confiabilidade dos dados coletados.

### Benefícios da Integração

1. **Visão Holística**: Compreensão completa do nexo energia-transporte-regulamentação
2. **Benchmarking Internacional**: Comparação com melhores práticas globais
3. **Análise Preditiva**: Antecipação de tendências regulatórias
4. **Suporte à Decisão**: Base empírica para políticas públicas

### Próximos Passos Recomendados

1. Priorizar implementação de coletores ANP e EPE
2. Estabelecer parcerias com agências para acesso privilegiado
3. Desenvolver dashboards específicos para energia
4. Criar alertas automáticos para mudanças significativas



### 1.5 ANA - Agência Nacional de Águas e Saneamento Básico

**Portal Principal**: https://www.gov.br/ana/pt-br  
**Portal de Dados**: https://dadosabertos.ana.gov.br/  
**SNIRH**: https://www.snirh.gov.br/hidroweb/

#### Relevância para Transporte de Carga

A ANA possui dados fundamentais para o transporte hidroviário e para compreender os impactos ambientais do transporte terrestre, especialmente relacionados à qualidade da água e recursos hídricos.

#### Principais Datasets

| Dataset | Descrição | Frequência | Relevância para Transporte |
|---------|-----------|------------|---------------------------|
| Hidroweb | Dados hidrológicos históricos | Diária | ⭐⭐⭐⭐ |
| Navegabilidade | Condições de navegação | Mensal | ⭐⭐⭐⭐⭐ |
| Qualidade da Água | Monitoramento de qualidade | Mensal | ⭐⭐⭐ |
| Outorgas de Uso | Autorizações de uso da água | Contínua | ⭐⭐⭐ |
| Atlas Brasil | Abastecimento urbano | Anual | ⭐⭐ |
| Portos e Terminais | Infraestrutura hidroviária | Anual | ⭐⭐⭐⭐⭐ |

#### Dados Específicos para Transporte Hidroviário

**Navegabilidade das Hidrovias**:
- **Rio Amazonas**: Condições de navegação, calado disponível
- **Rio Paraguai**: Hidrovia Paraguai-Paraná
- **Rio São Francisco**: Navegabilidade e obras de infraestrutura
- **Rio Tocantins**: Condições para transporte de grãos
- **Rio Tietê-Paraná**: Sistema hidroviário interior

**Infraestrutura Portuária Interior**:
- **Terminais Hidroviários**: Localização e capacidade
- **Portos Fluviais**: Movimentação de cargas
- **Eclusas**: Operação e manutenção
- **Dragagem**: Programas de manutenção de calado

#### Implementação em R

```r
# Função para acessar dados da ANA
library(httr)
library(jsonlite)
library(xml2)

get_ana_hidroweb_data <- function(station_code, start_date, end_date, data_type = "3") {
  
  # URL base do Hidroweb
  base_url <- "https://www.snirh.gov.br/hidroweb/rest/api/documento/convencionais"
  
  # Parâmetros da requisição
  params <- list(
    codEstacao = station_code,
    dataInicio = start_date,
    dataFim = end_date,
    tipoDados = data_type  # 3 = Cota, 1 = Vazão
  )
  
  # Fazer requisição
  response <- GET(base_url, query = params)
  
  if (status_code(response) == 200) {
    data <- fromJSON(content(response, "text"))
    return(data)
  } else {
    warning("Erro ao acessar dados da ANA: ", status_code(response))
    return(NULL)
  }
}

# Função para dados de navegabilidade
get_ana_navigation_data <- function(waterway, year = NULL) {
  
  # Estações estratégicas por hidrovia
  strategic_stations <- list(
    "amazonas" = c("14990000", "17050001", "17730000"),
    "paraguai" = c("66260001", "66280000", "66290000"),
    "sao_francisco" = c("48020000", "48770000", "49705000"),
    "tocantins" = c("23250000", "25500000", "26062000"),
    "tiete_parana" = c("61760000", "61851000", "61898000")
  )
  
  if (!waterway %in% names(strategic_stations)) {
    stop("Hidrovia não reconhecida. Use: ", paste(names(strategic_stations), collapse = ", "))
  }
  
  stations <- strategic_stations[[waterway]]
  
  # Coletar dados de todas as estações
  navigation_data <- map_dfr(stations, ~{
    
    station_data <- get_ana_hidroweb_data(
      station_code = .x,
      start_date = paste0(year %||% year(Sys.Date()), "-01-01"),
      end_date = paste0(year %||% year(Sys.Date()), "-12-31"),
      data_type = "3"  # Cota
    )
    
    if (!is.null(station_data)) {
      station_data$station_code <- .x
      station_data$waterway <- waterway
    }
    
    return(station_data)
  })
  
  return(navigation_data)
}

# Função para análise de navegabilidade
analyze_navigation_conditions <- function(navigation_data) {
  
  # Definir cotas críticas por hidrovia (em metros)
  critical_levels <- list(
    "amazonas" = list(min_draft = 2.5, optimal_draft = 4.0),
    "paraguai" = list(min_draft = 1.5, optimal_draft = 2.5),
    "sao_francisco" = list(min_draft = 1.0, optimal_draft = 1.8),
    "tocantins" = list(min_draft = 2.0, optimal_draft = 3.0),
    "tiete_parana" = list(min_draft = 2.5, optimal_draft = 3.5)
  )
  
  # Analisar condições por hidrovia
  navigation_analysis <- navigation_data %>%
    group_by(waterway, station_code) %>%
    summarise(
      avg_level = mean(water_level, na.rm = TRUE),
      min_level = min(water_level, na.rm = TRUE),
      max_level = max(water_level, na.rm = TRUE),
      days_below_critical = sum(water_level < critical_levels[[waterway[1]]]$min_draft, na.rm = TRUE),
      days_optimal = sum(water_level >= critical_levels[[waterway[1]]]$optimal_draft, na.rm = TRUE),
      navigability_index = days_optimal / n(),
      .groups = "drop"
    )
  
  return(navigation_analysis)
}
```

#### Integração com Dados de Transporte

```r
# Função para correlacionar dados hídricos com transporte de carga
correlate_water_transport <- function(ana_data, transport_data) {
  
  # Preparar dados de navegabilidade
  navigation_summary <- ana_data %>%
    group_by(year, waterway) %>%
    summarise(
      avg_navigability = mean(navigability_index, na.rm = TRUE),
      critical_periods = sum(days_below_critical > 30),
      .groups = "drop"
    )
  
  # Preparar dados de transporte hidroviário
  waterway_transport <- transport_data %>%
    filter(str_detect(tolower(document_summary), "hidroviário|fluvial|navegação|porto")) %>%
    count(year, name = "waterway_regulations")
  
  # Combinar datasets
  combined_analysis <- navigation_summary %>%
    left_join(waterway_transport, by = "year") %>%
    replace_na(list(waterway_regulations = 0))
  
  # Análise de correlação
  correlation_results <- combined_analysis %>%
    group_by(waterway) %>%
    summarise(
      correlation_nav_reg = cor(avg_navigability, waterway_regulations, use = "complete.obs"),
      correlation_critical_reg = cor(critical_periods, waterway_regulations, use = "complete.obs"),
      .groups = "drop"
    )
  
  return(list(
    combined_data = combined_analysis,
    correlations = correlation_results
  ))
}
```

#### Indicadores de Sustentabilidade Hídrica

```r
# KPIs de sustentabilidade hídrica para transporte
calculate_water_sustainability_kpis <- function(ana_data, transport_regulations) {
  
  kpis <- list(
    
    # 1. Índice de Disponibilidade Hídrica para Transporte
    water_availability_index = ana_data %>%
      group_by(year, waterway) %>%
      summarise(
        availability_score = mean(navigability_index, na.rm = TRUE),
        reliability_score = 1 - (sd(navigability_index, na.rm = TRUE) / mean(navigability_index, na.rm = TRUE)),
        sustainability_index = (availability_score + reliability_score) / 2,
        .groups = "drop"
      ),
    
    # 2. Pressão Regulatória sobre Recursos Hídricos
    regulatory_pressure = transport_regulations %>%
      filter(str_detect(tolower(document_summary), "água|hídrico|qualidade|poluição")) %>%
      count(year, name = "water_related_regulations") %>%
      mutate(
        regulatory_intensity = water_related_regulations / lag(water_related_regulations, default = 1) - 1
      ),
    
    # 3. Eficiência do Transporte Hidroviário
    waterway_efficiency = ana_data %>%
      group_by(waterway) %>%
      summarise(
        avg_availability = mean(navigability_index, na.rm = TRUE),
        capacity_utilization = avg_availability * 0.8,  # Fator de utilização
        efficiency_score = capacity_utilization / max(capacity_utilization, na.rm = TRUE),
        .groups = "drop"
      )
  )
  
  return(kpis)
}
```

#### Dados de Qualidade da Água

A ANA também monitora a qualidade da água em pontos estratégicos, relevante para avaliar impactos ambientais do transporte:

**Parâmetros Monitorados**:
- **Físico-químicos**: pH, oxigênio dissolvido, turbidez
- **Nutrientes**: Nitrogênio, fósforo
- **Metais**: Ferro, manganês, alumínio
- **Microbiológicos**: Coliformes, E. coli

**Relevância para Transporte**:
- Impacto de derramamentos de combustível
- Poluição por lavagem de veículos
- Qualidade da água em terminais portuários
- Monitoramento de áreas de influência de rodovias

#### Outorgas e Licenciamento

```r
# Análise de outorgas relacionadas ao transporte
analyze_transport_water_permits <- function() {
  
  # Tipos de outorga relevantes para transporte
  transport_related_permits <- c(
    "Captação para abastecimento de terminais",
    "Lançamento de efluentes portuários", 
    "Dragagem de canais de navegação",
    "Construção de pontes e viadutos",
    "Terminais de combustível"
  )
  
  # Análise temporal de outorgas
  permits_analysis <- get_ana_permits_data() %>%
    filter(purpose %in% transport_related_permits) %>%
    group_by(year, purpose) %>%
    summarise(
      total_permits = n(),
      total_volume = sum(authorized_volume, na.rm = TRUE),
      avg_duration = mean(permit_duration, na.rm = TRUE),
      .groups = "drop"
    )
  
  return(permits_analysis)
}
```

