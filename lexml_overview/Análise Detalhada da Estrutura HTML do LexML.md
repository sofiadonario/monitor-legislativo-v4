# Análise Detalhada da Estrutura HTML do LexML

## Observações da Interface de Resultados

### URL de Busca
`https://www.lexml.gov.br/busca/search?keyword=transporte+de+carga&f1-tipoDocumento=`

### Total de Resultados
**6813 Itens** confirmados na interface

### Estrutura Visual Identificada

#### Cabeçalho dos Resultados
- **Pesquisa:** transporte de carga
- **Resultados:** 6813 Itens
- **Paginação:** Página 1, 2, 3, 4, 5... Próxima

#### Filtros Laterais
- **Categoria do Documento:**
  - Doutrina (258)
  - Jurisprudência (5678)
  - Legislação (684)
  - Outras Manifestações (4)
  - Proposições Legislativas (189)

- **Localidade:**
  - Brasil (6075)
  - Distrito Federal (201)
  - Estados (173)
  - Municípios (106)

- **Autoridade:**
  - Distrital (201)
  - Estadual (173)
  - Federal (6075)
  - Municipal (106)

#### Estrutura dos Resultados Individuais

**Resultado 1 (Legislação):**
- **Número:** 1
- **Localidade:** Brasil
- **Autoridade:** Congresso Nacional
- **Título:** MPV 833/2018 (com link)
- **Descrição:** [MPV 833/2018 : LEI-13711-2018-08-24]. Isenção de pedágio por eixos suspensos no transporte de carga
- **Data:** 27/05/2018
- **Ementa:** [Texto completo da ementa]
- **URN:** urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833
- **Botão:** Adicionar

**Resultado 2 (Legislação):**
- **Número:** 2
- **Localidade:** Brasil
- **Autoridade:** Congresso Nacional
- **Título:** MPV 832/2018 (com link)
- **Descrição:** [MPV 832/2018 > VET 30/2018 : LEI-13703-2018-08-08]. Política de Preços Mínimos do Transporte Rodoviário de Cargas
- **Data:** 27/05/2018
- **Ementa:** Institui a Política de Preços Mínimos do Transporte Rodoviário de Cargas.
- **URN:** urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;832
- **Botão:** Adicionar

**Resultado 3 (Doutrina):**
- **Número:** 3
- **Tipo:** Artigo de revista
- **Autor:** Machado, Paulo Affonso Leme, 1939
- **Título:** Transporte de cargas perigosas (com link)
- **Data:** 1986
- **Assuntos:** Poder público. Substância perigosa. Responsabilidade civil...
- **Classificação:** DIREITO PRIVADO - 342::DIREITO COMERCIAL - 342.2::Transporte. Comunicação - 342.263::Mercadorias - 342.2633
- **Botão:** Adicionar

### Padrões Identificados

#### Campos Comuns a Todos os Resultados:
1. **Número sequencial** (1, 2, 3...)
2. **Botão "Adicionar"**
3. **Título** (sempre com link)
4. **Data** (formato DD/MM/AAAA)

#### Campos Específicos por Tipo:

**Legislação/Jurisprudência:**
- Localidade
- Autoridade
- Ementa
- URN

**Doutrina:**
- Tipo
- Autor
- Assuntos
- Classificação

### Estrutura HTML Presumida

Baseado na visualização, os resultados parecem estar organizados em:
- **Tabela principal** com resultados
- **Células** contendo os diferentes campos
- **Links** nos títulos
- **Texto estruturado** com rótulos (Localidade, Autoridade, etc.)

### Próximos Passos para Análise
1. Inspecionar DOM via JavaScript
2. Identificar seletores CSS específicos
3. Mapear estrutura exata das tabelas/divs
4. Testar extração de dados



## Descobertas da Análise DOM

### Estrutura da Tabela Principal
- **Total de linhas:** 276 linhas
- **Primeiro resultado:** Linha 125
- **Estrutura por resultado:** 4 células por linha

### Padrão de Organização dos Dados

#### Estrutura de Células por Resultado:
- **Célula 0:** Número do resultado (1, 2, 3...)
- **Célula 1:** Rótulo do campo (Localidade, Autoridade, Título, etc.)
- **Célula 2:** Valor do campo
- **Célula 3:** Botão "Adicionar" (JavaScript)

#### Campos Identificados:
1. **Localidade** → Brasil
2. **Autoridade** → Congresso Nacional
3. **Título** → MPV 833/2018 (com link)
4. **Data** → 27/05/2018
5. **Ementa** → [Texto da ementa]
6. **URN** → urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833

### Padrões de Extração Identificados

#### Links "Adicionar":
- **Total encontrado:** 20 links (corresponde aos 20 resultados da página)
- **Formato:** `javascript:add_1()`, `javascript:add_2()`, etc.
- **Localização:** Célula 3 de cada resultado

#### URNs:
- **Total encontrado:** 2 URNs na página atual
- **Formato:** `urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833`
- **Localização:** Campo "URN" nos resultados de legislação

#### Datas:
- **Total encontrado:** 2 datas na página atual
- **Formato:** DD/MM/AAAA (27/05/2018)
- **Localização:** Campo "Data"

### Estratégia de Parsing Robusta

#### Algoritmo Proposto:
1. **Encontrar tabela principal** (maior número de linhas)
2. **Iterar pelas linhas** procurando células com números (1, 2, 3...)
3. **Para cada resultado encontrado:**
   - Extrair número da célula 0
   - Mapear pares rótulo-valor das células 1-2
   - Extrair link do botão "Adicionar" da célula 3
4. **Agrupar campos** por resultado
5. **Validar completude** dos dados extraídos

#### Seletores CSS Identificados:
- **Tabela principal:** `table` (a maior)
- **Linhas de resultado:** `tr` contendo célula com número
- **Células:** `td` (4 por resultado)
- **Links de título:** `a` dentro da célula de valor
- **Botões adicionar:** `a[href^="javascript:add_"]`

