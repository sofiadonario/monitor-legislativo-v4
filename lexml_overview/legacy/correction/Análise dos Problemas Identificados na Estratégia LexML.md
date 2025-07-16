# Análise dos Problemas Identificados na Estratégia LexML

## Problemas Identificados

### 1. Extração de Datas Incompleta
- **Problema**: Apenas 201 de 1.904 documentos têm o campo `enacting_date` preenchido
- **Causa**: As datas estão presentes nos títulos/conteúdo mas não estão sendo extraídas corretamente
- **Evidência**: Títulos contêm padrões como "Data 27/05/1982", "Data 03/05/2019"
- **Impacto**: Impossibilita análise temporal adequada

### 2. Date Range Incorreto
- **Problema**: Campo `date_searched` refere-se à data da busca (2025-07-12), não à data do documento
- **Causa**: Confusão conceitual entre data de coleta e data de promulgação
- **Impacto**: Análise temporal baseada em data errada

### 3. Classificação Incorreta de Tipos de Documento
- **Problema**: Documentos legislativos sendo classificados como "doutrina"
- **Evidência**: Decretos, MPs, Resoluções marcados como `urn_type: doutrina`
- **Exemplos**:
  - `urn:lex:br:senado.federal:resolucao:1982-05-27;5` → deveria ser "legislation"
  - `urn:lex:br:federal:decreto:2016-05-10;8756` → deveria ser "legislation"
- **Impacto**: Estatísticas distorcidas (83.6% doutrina vs 5.9% legislação)

### 4. Cobertura Possivelmente Baixa
- **Problema**: Apenas 200 resultados legislativos para 80+ termos parece baixo
- **Causa Provável**: Classificação incorreta mascarando documentos legislativos
- **Necessidade**: Verificar se há mais documentos não capturados

## Padrões Identificados nos Dados

### Estrutura dos Títulos
Os títulos seguem padrões específicos que contêm as datas:
```
"Decreto nº 8.756 de 10/05/2016 DEC-8756-2016-05-10 Data 10/05/2016 Ementa..."
"MPV 882/2019 [ MPV 882/2019 ]. Infraestrutura de Transportes Data 03/05/2019 Ementa..."
"Resolução do Senado Federal nº 5 de 27/05/1982 RSF-5-1982-05-27 Data 27/05/1982 Ementa..."
```

### Padrões de Data Identificados
1. `Data DD/MM/AAAA` - Formato mais comum
2. `de DD/MM/AAAA` - No início do título
3. `AAAA-MM-DD` - Na URN e códigos

### URNs com Problemas de Parsing
Exemplos de URNs mal classificadas:
- `urn:lex:br:senado.federal:resolucao:1982-05-27;5` → Resolução do Senado (legislação)
- `urn:lex:br:federal:decreto:2016-05-10;8756` → Decreto Federal (legislação)
- `urn:lex:br:congresso.nacional:medida.provisoria;mpv:2019-05-03;882` → MP (legislação)

## Correções Necessárias

### 1. Melhorar Extração de Datas
- Implementar regex para capturar padrões "Data DD/MM/AAAA"
- Extrair datas dos títulos e URNs
- Normalizar formato para AAAA-MM-DD

### 2. Corrigir Classificação de URNs
- Revisar lógica de parsing para identificar corretamente:
  - `senado.federal` → legislation
  - `congresso.nacional` → legislation  
  - `federal:decreto` → legislation
  - `federal:medida.provisoria` → legislation

### 3. Melhorar Cobertura
- Verificar se limitação de 40 resultados por termo está adequada
- Investigar se há documentos não sendo capturados
- Considerar busca por páginas adicionais

### 4. Validar Estrutura HTML
- Analisar estrutura real das páginas de resultado
- Verificar se há campos de data não sendo capturados
- Otimizar seletores de extração

