# Relatório Técnico - Análise de Políticas Públicas de Transporte

**Data:** 16/07/2025 21:00:33
**Dataset:** ../data_current/raw/dataset_14072025.xlsx

## Metodologia

### Fonte dos Dados
- Base: LexML (Rede Virtual de Bibliotecas)
- Período: 1850-2024
- Tipos: Legislação, Doutrina, Jurisprudência, Outros

### Processamento
1. Extração de anos das URNs usando regex
2. Limpeza e padronização de nomes de órgãos
3. Classificação por períodos históricos
4. Análise de qualidade e completude

## Resultados Detalhados

### Estatísticas Gerais
- **Total de registros:** 1,957
- **Registros com dados temporais:** 928 (47.4%)
- **Período de cobertura:** 1856 - 2024
- **Anos únicos:** 84

### Qualidade dos Dados
- **Title:** 99.6% completo
- **Urn:** 47.7% completo
- **Urn_type:** 99.8% completo
- **Country:** 99.6% completo
- **Duplicatas:** 20 registros (1.0%)

### Limitações
- Dependência da qualidade dos metadados do LexML
- Possível subrepresentação de documentos mais antigos
- Variação na completude dos campos ao longo do tempo
