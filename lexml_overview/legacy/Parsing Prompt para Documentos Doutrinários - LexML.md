# Parsing Prompt para Documentos Doutrinários - LexML

## Contexto e Objetivo

Este parsing prompt foi desenvolvido para processar documentos doutrinários (artigos, livros, teses, dissertações, etc.) indexados no LexML, complementando os parsing prompts existentes para legislação e jurisprudência.

## Estrutura das URNs de Doutrina

Os documentos doutrinários no LexML seguem uma estrutura de URN específica que difere dos documentos legislativos e jurisprudenciais. A análise dos dados extraídos revelou os seguintes padrões:

### Padrão Geral
```
urn:lex:br:[biblioteca/fonte]:[tipo_documento]:[ano];[identificador]
```

### Exemplos Identificados
1. `urn:lex:br:rede.virtual.bibliotecas:artigo.revista:1986;1000445040`
2. `urn:lex:br:rede.virtual.bibliotecas:artigo.revista:2004;1000695007`
3. `urn:lex:br:biblioteca.digital:livro:2009;1000123456` (exemplo hipotético)

## Parsing Prompt para Doutrina

### Instrução Principal
Você receberá uma URN de documento doutrinário do LexML. Sua tarefa é extrair e estruturar as informações contidas na URN seguindo o padrão estabelecido.

### Estrutura de Parsing
Para URNs de doutrina, extraia os seguintes componentes:

1. **País (country)**: Sempre "br" para documentos brasileiros
2. **Fonte/Biblioteca (source)**: Biblioteca ou fonte digital de origem
3. **Tipo de Documento (document_type)**: Categoria específica do documento doutrinário
4. **Ano de Publicação (publication_year)**: Ano de publicação do documento
5. **Identificador (identifier)**: Código único do documento na fonte

### Regras de Extração

#### 1. Identificação do Tipo
Se a URN contém "rede.virtual.bibliotecas", "biblioteca.digital", ou similar, classifique como documento doutrinário.

#### 2. Extração da Fonte
A fonte aparece após "br:" e antes do tipo de documento. Exemplos:
- `rede.virtual.bibliotecas` → "Rede Virtual de Bibliotecas"
- `biblioteca.digital` → "Biblioteca Digital"
- `repositorio.institucional` → "Repositório Institucional"

#### 3. Tipos de Documento Doutrinário
Mapeie os tipos encontrados:
- `artigo.revista` → "Artigo de Revista"
- `livro` → "Livro"
- `tese` → "Tese"
- `dissertacao` → "Dissertação"
- `capitulo.livro` → "Capítulo de Livro"
- `trabalho.congresso` → "Trabalho de Congresso"
- `monografia` → "Monografia"
- `relatorio.tecnico` → "Relatório Técnico"

#### 4. Extração do Ano
O ano aparece após o tipo de documento, separado por dois pontos (:).

#### 5. Identificador
O identificador único aparece após o ponto e vírgula (;).

### Exemplo de Aplicação

**URN de Entrada:**
```
urn:lex:br:rede.virtual.bibliotecas:artigo.revista:1986;1000445040
```

**Parsing Esperado:**
```
País: br (Brasil)
Fonte: Rede Virtual de Bibliotecas
Tipo de Documento: Artigo de Revista
Ano de Publicação: 1986
Identificador: 1000445040
Classificação: Doutrina
```

**Tradução Completa:**
"Artigo de revista número 1000445040, publicado em 1986, disponível na Rede Virtual de Bibliotecas, Brasil."

### Campos Adicionais para Doutrina

Além dos campos básicos da URN, os documentos doutrinários possuem metadados específicos que devem ser extraídos quando disponíveis:

#### Metadados Bibliográficos
- **Autor(es)**: Nome(s) do(s) autor(es) do documento
- **Título**: Título completo do documento
- **Subtítulo**: Subtítulo, se houver
- **Revista/Editora**: Nome da revista ou editora
- **Volume**: Volume da publicação
- **Número**: Número da edição
- **Páginas**: Intervalo de páginas
- **ISSN/ISBN**: Identificadores padronizados
- **DOI**: Digital Object Identifier, se disponível

#### Classificação Temática
- **Classificação CDDir**: Código da Classificação Decimal de Direito
- **Descritores**: Palavras-chave temáticas
- **Área do Direito**: Área específica (Direito Civil, Penal, etc.)
- **Assuntos**: Temas abordados no documento

#### Informações de Acesso
- **Biblioteca de Origem**: Instituição responsável
- **URL de Acesso**: Link para o documento completo
- **Tipo de Acesso**: Livre, restrito, mediante cadastro
- **Formato**: PDF, HTML, etc.

### Tratamento de Casos Especiais

#### 1. URNs Incompletas
Se a URN não seguir o padrão completo, extraia o máximo de informações possível e marque os campos faltantes como "não informado".

#### 2. Múltiplos Autores
Quando houver múltiplos autores, separe-os por ponto e vírgula (;) mantendo a ordem de autoria.

#### 3. Documentos Multilíngues
Para documentos em outros idiomas, mantenha o título original e indique o idioma no campo específico.

#### 4. Versões e Edições
Se o documento possuir múltiplas versões, indique a versão específica nos metadados.

### Validação e Qualidade

#### Critérios de Validação
1. **Completude**: Verificar se todos os campos obrigatórios foram preenchidos
2. **Consistência**: Validar se o ano está no formato correto (YYYY)
3. **Coerência**: Verificar se o tipo de documento condiz com os metadados
4. **Padronização**: Garantir que os nomes estão em formato consistente

#### Indicadores de Qualidade
- **Alta**: URN completa com todos os metadados
- **Média**: URN completa com metadados parciais
- **Baixa**: URN incompleta ou metadados insuficientes

### Integração com Sistema de Monitoramento

#### Campos de Saída Padronizados
Para integração com o sistema de monitoramento legislativo, utilize os seguintes campos:

```
search_term: [termo que levou ao documento]
date_searched: [data da pesquisa]
url: [URL do documento no LexML]
title: [título do documento]
urn: [URN completa]
urn_type: "doctrine"
country: "br"
state: [não aplicável para doutrina]
municipality: [não aplicável para doutrina]
justice: [não aplicável para doutrina]
region: [não aplicável para doutrina]
court_class: [não aplicável para doutrina]
document_type_full: [tipo completo do documento]
enacting_date: [ano de publicação]
document_description: [descritores e assuntos]
document_summary: [resumo ou ementa]
author: [autor(es) do documento]
source: [biblioteca/fonte de origem]
classification: [classificação CDDir]
language: [idioma do documento]
access_type: [tipo de acesso]
```

### Exemplo Completo de Parsing

**Documento de Entrada:**
```
URN: urn:lex:br:rede.virtual.bibliotecas:artigo.revista:2004;1000695007
Título: Dano ambiental no transporte e armazenagem de carga perigosa
Autor: Vicente, Silvia Helena
Ano: 2004
Tipo: Artigo de revista
Resumo: Apresenta aspectos do dano imposto ao meio ambiente devido às diversas modalidades de transporte de cargas...
Assuntos: Transporte marítimo internacional. Transporte marítimo, Brasil. Transporte terrestre, Brasil...
Classificação: DIREITO PRIVADO - 342::DIREITO COMERCIAL - 342.2::Instituições comerciais...
```

**Saída Estruturada:**
```json
{
  "search_term": "transporte de carga",
  "date_searched": "2025-07-12T15:22:36.755940",
  "url": "https://www.lexml.gov.br/urn/urn:lex:br:rede.virtual.bibliotecas:artigo.revista:2004;1000695007",
  "title": "Dano ambiental no transporte e armazenagem de carga perigosa",
  "urn": "urn:lex:br:rede.virtual.bibliotecas:artigo.revista:2004;1000695007",
  "urn_type": "doctrine",
  "country": "br",
  "state": "",
  "municipality": "",
  "justice": "",
  "region": "",
  "court_class": "",
  "document_type_full": "Artigo de Revista",
  "enacting_date": "2004",
  "document_description": "Transporte marítimo internacional. Transporte marítimo, Brasil. Transporte terrestre, Brasil. Transporte de carga perigosa, responsabilidade penal, legislação, Brasil.",
  "document_summary": "Apresenta aspectos do dano imposto ao meio ambiente devido às diversas modalidades de transporte de cargas, considerando as sanções civis, administrativas e penais impostas aos causadores destes danos, enfatizando a sanção penal aplicada à pessoa jurídica.",
  "author": "Vicente, Silvia Helena",
  "source": "Rede Virtual de Bibliotecas",
  "classification": "DIREITO PRIVADO - 342::DIREITO COMERCIAL - 342.2::Instituições comerciais. Mercado de capitais - 342.23::Falência - 342.236",
  "language": "português",
  "access_type": "digital"
}
```

### Considerações Técnicas

#### Implementação em Python
```python
def parse_doctrine_urn(urn: str) -> dict:
    """
    Faz parsing de URN de documento doutrinário.
    
    Args:
        urn: URN no formato LexML
        
    Returns:
        Dicionário com componentes extraídos
    """
    if not urn.startswith('urn:lex:br:'):
        return {}
    
    parts = urn[8:].split(':')  # Remove 'urn:lex:'
    
    result = {
        'urn_type': 'doctrine',
        'country': 'br',
        'source': '',
        'document_type_full': '',
        'publication_year': '',
        'identifier': ''
    }
    
    if len(parts) >= 2:
        # Extrai fonte
        source_part = parts[1]
        result['source'] = source_part.replace('.', ' ').title()
    
    if len(parts) >= 3:
        # Extrai tipo de documento
        doc_type = parts[2]
        type_mapping = {
            'artigo.revista': 'Artigo de Revista',
            'livro': 'Livro',
            'tese': 'Tese',
            'dissertacao': 'Dissertação',
            'capitulo.livro': 'Capítulo de Livro'
        }
        result['document_type_full'] = type_mapping.get(doc_type, doc_type.replace('.', ' ').title())
    
    if len(parts) >= 4:
        # Extrai ano e identificador
        year_id = parts[3].split(';')
        if len(year_id) >= 1:
            result['publication_year'] = year_id[0]
        if len(year_id) >= 2:
            result['identifier'] = year_id[1]
    
    return result
```

### Manutenção e Evolução

#### Atualização de Tipos
À medida que novos tipos de documentos doutrinários forem identificados no LexML, atualize o mapeamento de tipos no parsing prompt.

#### Validação Contínua
Implemente validação automática dos resultados do parsing para identificar padrões não reconhecidos e melhorar a cobertura.

#### Feedback e Refinamento
Colete feedback dos usuários sobre a qualidade do parsing e refine as regras conforme necessário.

---

**Autor:** Manus AI  
**Data:** 2025-07-12  
**Versão:** 1.0

