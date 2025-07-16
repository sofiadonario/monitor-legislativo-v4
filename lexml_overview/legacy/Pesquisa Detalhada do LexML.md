# Pesquisa Detalhada do LexML

## Informações Básicas
- **URL Principal**: https://www.lexml.gov.br
- **Portal do Projeto**: https://projeto.lexml.gov.br/
- **Nome Completo**: LexML Brasil: Rede de Informação Legislativa e Jurídica

## Tipos de Documentos Indexados
O LexML indexa 5 tipos principais de documentos:
1. **Legislação** - Leis, decretos, portarias, etc.
2. **Jurisprudência** - Decisões judiciais, acórdãos, etc.
3. **Proposições Legislativas** - Projetos de lei em tramitação
4. **Doutrina** - Artigos, livros, textos acadêmicos
5. **Tudo** - Busca em todos os tipos

## Funcionalidades Identificadas
- Pesquisa simples e avançada
- Sistema de URN (Uniform Resource Name) para identificação única
- Metadados estruturados
- API de dados (mencionada nas notícias)
- Suporte a múltiplos idiomas (Português, Inglês, Francês, Espanhol)

## Documentação Técnica Disponível
- Parte 1: Modelo de Referência
- Parte 2: LEXML URN
- Parte 3: XML Schema
- Parte 4: Coleta de Metadados
- Parte 4-A: Kit Provedor de Dados
- Parte 5: Serviço de Resolução de URN
- Parte 6: Vocabulários Controlados

## Notícias Relevantes
- Portal disponibiliza metadados com marcação Schema.org/Legislation (2019)
- Metadados em formato JSON-LD
- Integração com padrões internacionais



## Descrição Detalhada do LexML

### O que é o LexML
O LexML é um portal especializado em informação jurídica e legislativa que pretende reunir:
- Leis, decretos, acórdãos, súmulas, projetos de leis
- Documentos das esferas federal, estadual e municipal
- Documentos dos Poderes Executivo, Legislativo e Judiciário
- Uma rede de informação legislativa e jurídica para organizar, integrar e dar acesso

### Objetivos Principais
- Identificar e estruturar informações legislativas e jurídicas
- Integração de processos de trabalho e compartilhamento de dados
- Utilização de padrões abertos nas três esferas administrativas
- Hiperlinks persistentes e sistemas online
- Tratamento padronizado da estrutura textual

### Sistema de URN (Uniform Resource Name)
O LexML utiliza um sistema de identificação única e persistente para cada documento:

**Exemplo de URN Legislativa:**
- Original: "LEI Nº 11.705, DE 19 DE JUNHO DE 2008"
- URN: `urn:lex:br:federal:lei:2008-06-19;11705`

**Processo de Criação da URN:**
1. Simplificação: "LEI Nº 11.705, DE 19 DE JUNHO DE 2008" → "lei 11705, de 19/06/2008"
2. Conversão de data: "19/06/2008" → "2008-06-19"
3. Ordem padrão: "lei;2008-06-19;11705"
4. Contexto: "br:federal:lei;2008-06-19;11705"

### Integração da Informação Jurídica
O sistema permite estabelecer relações entre documentos através de:
- **Citações**: Links entre normas que se referenciam
- **Dependências diretas**: Normas que revogam ou detalham outras
- **Dependências hierárquicas**: Relação entre normas gerais e específicas
- **Vinculação por assunto**: Agrupamento temático de normas

### Iniciativa e Governança
- Iniciativa conjunta de diversos órgãos do GT LexML
- Liderada pelo Senado Federal
- Parte da Comunidade TIControle
- Recomendado pela versão 4.0 do E-Ping (padrão de Interoperabilidade do Governo Eletrônico)


## Interface de Pesquisa do LexML

### URL de Pesquisa Identificada
- **Base URL**: `https://www.lexml.gov.br/busca/search`
- **Parâmetros**:
  - `keyword`: termo de busca
  - `f1-tipoDocumento`: filtro por tipo de documento

### Exemplo de Busca Realizada
- **Termo**: "transporte de carga"
- **URL**: `https://www.lexml.gov.br/busca/search?keyword=transporte+de+carga&f1-tipoDocumento=`
- **Resultados**: 6813 itens encontrados

### Categorias de Documentos Disponíveis
1. **Doutrina** (258 resultados)
2. **Jurisprudência** (5678 resultados)
3. **Legislação** (684 resultados)
4. **Outras Manifestações** (4 resultados)
5. **Proposições Legislativas** (189 resultados)

### Filtros Disponíveis
- **Localidade**: Brasil, Distrito Federal, Estados, Municípios
- **Autoridade**: Distrital, Estadual, Federal, Municipal
- **Período**: Por décadas (1850s até 2020s)
- **Idioma**: Português, Inglês, Francês, Espanhol
- **Classificação**: Sistema CDDir (Classificação Decimal de Direito)

### Estrutura dos Resultados
Cada resultado contém:
- **Localidade**: Jurisdição do documento
- **Autoridade**: Órgão emissor
- **Título**: Nome do documento
- **Data**: Data de publicação/promulgação
- **Ementa**: Resumo do conteúdo
- **URN**: Identificador único no formato LexML
- **Tipo**: Categoria do documento (para doutrina)
- **Autor**: Autor do documento (para doutrina)
- **Assuntos**: Palavras-chave temáticas
- **Classificação**: Código CDDir

### Exemplos de URNs Encontradas
1. **Legislação**: `urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;833`
2. **Legislação**: `urn:lex:br:congresso.nacional:medida.provisoria;mpv:2018-05-27;832`

### Funcionalidades Identificadas
- Pesquisa por relevância, título, data ascendente/descendente
- Paginação de resultados
- Filtros laterais por categoria
- Opção "Adicionar" para cesta de itens
- Visualização completa dos resultados


## Análise Técnica da Pesquisa Avançada

### Campos de Pesquisa Disponíveis
A interface de pesquisa avançada do LexML oferece os seguintes campos:

1. **Todos os Campos**: Busca geral em todos os metadados
2. **Sigla**: Sigla do documento (com opção "exceto")
3. **Categoria do Documento**: Dropdown com opções:
   - Todas
   - Legislação
   - Jurisprudência
   - Proposições Legislativas
   - Doutrina
   - Publicação Oficial
   - Outras Manifestações
4. **Tipo do Documento**: Campo específico do tipo (com opção "exceto")
5. **Localidade**: Local de origem (com opção "exceto")
6. **Esfera da Autoridade Emitente**: Dropdown com opções:
   - Todas
   - Federal
   - Estadual
   - Distrital
   - Municipal
7. **Autoridade Emitente**: Órgão específico (com opção "exceto")
8. **Número**: Número do documento (com opção "exceto")
9. **Título**: Título do documento (com opção "exceto")
10. **Apelido / Nome Popular**: Nome popular (com opção "exceto")
11. **Ementa**: Texto da ementa (com opção "exceto")
12. **Assunto / Indexação**: Palavras-chave (com opção "exceto")
13. **URN**: Identificador URN específico (com opção "exceto")
14. **Do ano**: Filtro de período (de/até)

### Campos Específicos para Doutrina
15. **Autor**: Nome do autor (com opção "exceto")
16. **Classificação CDDir**: Código de classificação (com opção "exceto")
17. **Idioma**: Idioma do documento (com opção "exceto")
18. **Biblioteca**: Biblioteca de origem (com opção "exceto")

### Funcionalidades Técnicas Identificadas
- **Operadores Booleanos**: Suporte a "exceto" (NOT)
- **Filtros de Data**: Período específico com "de" e "até"
- **Busca por URN**: Permite busca direta por identificador
- **Categorização**: Filtros específicos por tipo de documento
- **Metadados Estruturados**: Busca em campos específicos dos metadados


## Análise Técnica Detalhada da API de Pesquisa

### URL Completa da Pesquisa Avançada
```
https://www.lexml.gov.br/busca/search?keyword=transporte+de+carga&acronimo=&acronimo-exclude=&f1-tipoDocumento=Legisla%C3%A7%C3%A3o&tipoDocumento=&tipoDocumento-exclude=&localidade=&localidade-exclude=&f2-autoridade=&autoridade=&autoridade-exclude=&descritor=&descritor-exclude=&title=&title-exclude=&apelido=&apelido-exclude=&description=&description-exclude=&subject=&subject-exclude=&urn=&urn-exclude=&year=&year-max=&doutrinaAutor=&doutrinaAutor-exclude=&doutrinaClasse=&doutrinaClasse-exclude=&doutrinaLingua=&doutrinaLingua-exclude=&doutrinaBiblioteca=&doutrinaBiblioteca-exclude=&smode=advanced
```

### Mapeamento Completo dos Parâmetros da API

| Parâmetro | Descrição | Exemplo |
|-----------|-----------|---------|
| `keyword` | Busca geral em todos os campos | `transporte+de+carga` |
| `acronimo` | Sigla do documento | |
| `acronimo-exclude` | Excluir sigla específica | |
| `f1-tipoDocumento` | Categoria do documento | `Legislação` |
| `tipoDocumento` | Tipo específico do documento | |
| `tipoDocumento-exclude` | Excluir tipo específico | |
| `localidade` | Localidade específica | |
| `localidade-exclude` | Excluir localidade | |
| `f2-autoridade` | Esfera da autoridade | |
| `autoridade` | Autoridade emitente | |
| `autoridade-exclude` | Excluir autoridade | |
| `descritor` | Número do documento | |
| `descritor-exclude` | Excluir número | |
| `title` | Título do documento | |
| `title-exclude` | Excluir título | |
| `apelido` | Nome popular | |
| `apelido-exclude` | Excluir nome popular | |
| `description` | Ementa | |
| `description-exclude` | Excluir ementa | |
| `subject` | Assunto/Indexação | |
| `subject-exclude` | Excluir assunto | |
| `urn` | URN específica | |
| `urn-exclude` | Excluir URN | |
| `year` | Ano inicial | |
| `year-max` | Ano final | |
| `doutrinaAutor` | Autor (doutrina) | |
| `doutrinaAutor-exclude` | Excluir autor | |
| `doutrinaClasse` | Classificação CDDir | |
| `doutrinaClasse-exclude` | Excluir classificação | |
| `doutrinaLingua` | Idioma | |
| `doutrinaLingua-exclude` | Excluir idioma | |
| `doutrinaBiblioteca` | Biblioteca | |
| `doutrinaBiblioteca-exclude` | Excluir biblioteca | |
| `smode` | Modo de pesquisa | `advanced` |

### Resultados da Pesquisa de Teste
- **Termo**: "transporte de carga"
- **Filtro**: Apenas Legislação
- **Total**: 684 itens encontrados
- **Tipos mais comuns**: Decreto (405), Lei (166), Decreto-Lei (35), Medida Provisória (27)

### Estrutura dos Metadados Retornados
Cada resultado contém os seguintes campos estruturados:
- **Localidade**: Jurisdição (Brasil, Estado, Município)
- **Autoridade**: Esfera (Federal, Estadual, Distrital, Municipal)
- **Título**: Nome oficial do documento
- **Data**: Data de publicação/promulgação
- **Ementa**: Resumo oficial do conteúdo
- **URN**: Identificador único no padrão LexML
- **Assuntos**: Palavras-chave indexadas

### Funcionalidades de Filtro Identificadas
- **Filtros Booleanos**: Suporte a operadores "exceto" (NOT)
- **Filtros Temporais**: Período específico com ano inicial e final
- **Filtros Categóricos**: Por tipo de documento, autoridade, localidade
- **Filtros Textuais**: Busca em campos específicos (título, ementa, etc.)
- **Filtros Especializados**: Para doutrina (autor, classificação, idioma, biblioteca)

