# Módulo de Metodologia - Funções de Conteúdo em Português
# Este arquivo contém todo o conteúdo de metodologia em português

overview_content_pt <- function() {
  div(
    h4(icon("compass"), " Visão Geral da Metodologia"),

    wellPanel(
      h5("Filosofia de Pesquisa"),
      tags$ul(
        tags$li(strong("Transparência:"), " Todos os algoritmos e métricas são documentados"),
        tags$li(strong("Reprodutibilidade:"), " Código e métodos são código aberto"),
        tags$li(strong("Rigor:"), " Validação estatística e padrões acadêmicos"),
        tags$li(strong("Utilidade Prática:"), " Ferramentas projetadas para pesquisa legislativa real")
      )
    ),

    fluidRow(
      column(4,
        div(class = "panel panel-primary",
          div(class = "panel-heading", h5("Conjunto de Dados")),
          div(class = "panel-body",
            tags$ul(
              tags$li("134.000+ documentos legislativos"),
              tags$li("Fontes Federal, Estadual, Municipal"),
              tags$li("Cobertura temporal 1988-presente"),
              tags$li("Foco em transporte com contexto legal mais amplo")
            )
          )
        )
      ),
      column(4,
        div(class = "panel panel-info",
          div(class = "panel-heading", h5("Métodos")),
          div(class = "panel-body",
            tags$ul(
              tags$li("Análise de Redes"),
              tags$li("Avaliação de Legibilidade"),
              tags$li("Modelagem de Tópicos"),
              tags$li("Busca Semântica"),
              tags$li("Detecção de Anomalias"),
              tags$li("Análise de Votação")
            )
          )
        )
      ),
      column(4,
        div(class = "panel panel-success",
          div(class = "panel-heading", h5("Tecnologias")),
          div(class = "panel-body",
            tags$ul(
              tags$li("R / Shiny"),
              tags$li("PostgreSQL"),
              tags$li("Word2Vec / BERT"),
              tags$li("STM (Modelos de Tópicos Estruturais)"),
              tags$li("Visualização de Redes")
            )
          )
        )
      )
    )
  )
}

data_content_pt <- function() {
  div(
    h4(icon("database"), " Coleta de Dados e Controle de Qualidade"),

    wellPanel(
      h5("Principais Fontes de Dados"),
      tags$ul(
        tags$li(strong("LexML:"), " Rede de Informação Legislativa e Jurídica"),
        tags$li(strong("Portais Governamentais:"), " Fontes oficiais federais, estaduais e municipais"),
        tags$li(strong("Assembleias Legislativas:"), " Scraping direto de sites quando disponível")
      )
    ),

    h5("Procedimentos de Controle de Qualidade"),
    fluidRow(
      column(6,
        div(class = "well",
          h6(icon("check-circle"), " Etapas de Validação"),
          tags$ol(
            tags$li(strong("Deduplicação:"), " Correspondência de hash MD5 para identificar duplicatas"),
            tags$li(strong("Validação de Esquema:"), " Garantir que todos os campos obrigatórios estejam presentes"),
            tags$li(strong("Verificação de Completude:"), " Verificar disponibilidade de texto completo"),
            tags$li(strong("Padronização de Codificação:"), " Converter todo o texto para UTF-8")
          )
        )
      ),
      column(6,
        div(class = "well",
          h6(icon("table"), " Estrutura de Dados"),
          tags$pre(
"documentos
├── Metadados (título, ementa, data_publicacao)
├── Classificação (tipo_documento, esfera, origem)
├── Texto Completo (texto_completo)
└── Status de Processamento (processamento_status)"
          )
        )
      )
    )
  )
}

voting_content_pt <- function() {
  div(
    h4(icon("chart-bar"), " Análise de Dados de Votação"),

    div(class = "alert alert-info",
      p(strong("Importante:"), " Esta análise inclui ", strong("apenas proposições com votações registradas"), ". Proposições sem dados de votação foram excluídas para garantir análise estatística válida.")
    ),

    wellPanel(
      h5("Visão Geral"),
      p("Análise de comportamento de votação legislativa examinando ~1000 proposições em 5 áreas temáticas (Transporte, Energia, Cidades, Meio Ambiente, Economia) ao longo de 3 legislaturas brasileiras (2015-2027).")
    ),

    tabsetPanel(
      tabPanel("Coleta de Dados",
        br(),
        h6("Fonte de Dados"),
        wellPanel(
          tags$ul(
            tags$li(strong("API:"), " API de Dados Abertos da Câmara dos Deputados"),
            tags$li(strong("Endpoint:"), " /api/v2/proposicoes"),
            tags$li(strong("Método:"), " REST API com paginação automática"),
            tags$li(strong("Autenticação:"), " Acesso público (sem chave de API)")
          )
        ),

        h6("Cobertura"),
        tags$ul(
          tags$li(strong("Temas:"), " 5 áreas políticas (500 proposições/tema com deduplicação)"),
          tags$li(strong("Linha do Tempo:"), " Legislatura 55 (2015-2019), 56 (2019-2023), 57 (2023-2027)"),
          tags$li(strong("Metadados:"), " ID, título, descrição, autores, data, status"),
          tags$li(strong("Registros de Votação:"), " Votos individuais de legisladores (sim/não/abstenção/ausente)")
        )
      ),

      tabPanel("Métodos Analíticos",
        br(),
        h6("1. Classificação Temática"),
        wellPanel(
          p(strong("Método:"), " Correspondência de padrões baseada em palavras-chave com operadores LIKE"),
          tags$pre(
'tema <- CASE
  WHEN LOWER(descricao) LIKE \'%transporte%\' THEN \'Transporte\'
  WHEN LOWER(descricao) LIKE \'%energia%\' THEN \'Energia\'
  WHEN LOWER(descricao) LIKE \'%cidade%\' THEN \'Cidades\'
  WHEN LOWER(descricao) LIKE \'%ambiente%\' THEN \'Meio Ambiente\'
  WHEN LOWER(descricao) LIKE \'%economia%\' THEN \'Economia\'
  ELSE \'Múltiplo/Outro\'
END'
          ),
          p(strong("Validação:"), " Revisão manual de amostra de 100 proposições (precisão de 95%)")
        ),

        h6("2. Análise de Padrões de Votação"),
        wellPanel(
          h6("Índice de Unidade Partidária:"),
          tags$pre("índice_unidade = (votos_com_partido / total_votos) × 100"),

          h6("Taxa de Votação Cruzada:"),
          tags$pre("taxa_cruzada = (votos_contra_partido / total_votos) × 100"),

          h6("Taxa de Participação:"),
          tags$pre("participação = ((sim + não + abstenção) / total_oportunidades) × 100")
        )
      ),

      tabPanel("Visualizações",
        br(),
        h6("1. Gráfico de Distribuição Temática"),
        tags$ul(
          tags$li(strong("Tipo:"), " Gráfico de barras horizontal"),
          tags$li(strong("Eixo X:"), " Contagem de proposições"),
          tags$li(strong("Eixo Y:"), " Tema (ordenado por contagem)"),
          tags$li(strong("Propósito:"), " Mostrar importância relativa de cada área política")
        ),

        h6("2. Linha do Tempo de Atividade de Proposições"),
        tags$ul(
          tags$li(strong("Tipo:"), " Série temporal multi-linha"),
          tags$li(strong("Eixo X:"), " Ano (2015-2027)"),
          tags$li(strong("Eixo Y:"), " Contagem de proposições"),
          tags$li(strong("Propósito:"), " Tendências temporais e mudanças de foco legislativo")
        ),

        h6("3. Mapa de Calor de Votação Partidária"),
        tags$ul(
          tags$li(strong("Tipo:"), " Mapa de calor com gradiente"),
          tags$li(strong("Eixos:"), " Tipo de voto vs. Partido"),
          tags$li(strong("Cor:"), " Gradiente percentual (vermelho→amarelo→verde)"),
          tags$li(strong("Propósito:"), " Padrões de votação e disciplina em nível partidário")
        )
      ),

      tabPanel("Interpretação",
        br(),
        h6("Distribuição Temática"),
        tags$ul(
          tags$li(strong("Alta contagem:"), " Prioridade política ou debate ativo"),
          tags$li(strong("Baixa contagem:"), " Área política emergente ou de nicho"),
          tags$li(strong("Equilíbrio:"), " Cobertura legislativa ampla")
        ),

        h6("Tendências Temporais"),
        tags$ul(
          tags$li(strong("Picos:"), " Resposta a eventos ou janelas políticas"),
          tags$li(strong("Lacunas:"), " Recesso legislativo ou impasse político"),
          tags$li(strong("Agrupamentos:"), " Desenvolvimento coordenado de políticas")
        ),

        h6("Padrões de Votação"),
        tags$ul(
          tags$li(strong("Alta unidade:"), " Forte disciplina partidária"),
          tags$li(strong("Baixa unidade:"), " Dissidência interna ou questões bipartidárias"),
          tags$li(strong("Votos cruzados:"), " Sinais de formação de coalizão")
        )
      ),

      tabPanel("Limitações",
        br(),
        tags$ul(
          tags$li(strong("Classificação Temática:"), " Baseada em palavras-chave (pode perder proposições nuançadas)"),
          tags$li(strong("Cobertura da API:"), " Limitada à Câmara dos Deputados (sem dados do Senado ainda)"),
          tags$li(strong("Dados Históricos:"), " Varia por legislatura (dados mais antigos podem estar incompletos)"),
          tags$li(strong("Mudanças de Legisladores:"), " Trocas de partido no meio do mandato não totalmente capturadas"),
          tags$li(strong("Contexto de Voto:"), " Faltam emendas de proposições e modificações de comissões"),
          tags$li(strong("Seleção de Dados:"), " Apenas proposições com votações registradas foram incluídas na análise. Proposições sem dados de votação foram excluídas para garantir validade estatística")
        )
      )
    )
  )
}

limitations_content_pt <- function() {
  div(
    h4(icon("exclamation-triangle"), " Limitações e Advertências"),

    div(class = "alert alert-warning",
      p(strong("Importante:"), " Todos os métodos automatizados têm limitações. Sempre valide os resultados com conhecimento especializado e revisão manual.")
    ),

    h5("Limitações dos Dados"),
    wellPanel(
      tags$ul(
        tags$li(strong("Lacunas de cobertura:"), " Nem todas as jurisdições têm digitalização completa"),
        tags$li(strong("Erros de OCR:"), " Documentos digitalizados podem ter problemas de extração de texto"),
        tags$li(strong("Qualidade de metadados:"), " Varia por fonte e jurisdição"),
        tags$li(strong("Viés temporal:"), " Documentos mais recentes são melhor representados")
      )
    ),

    h5("Limitações Metodológicas"),
    wellPanel(
      tags$ul(
        tags$li(strong("Métricas de legibilidade:"), " Desenvolvidas para texto geral, especificidade legal varia"),
        tags$li(strong("Extração de citações:"), " Baseada em regex, pode perder formatos não padronizados"),
        tags$li(strong("Modelos de tópicos:"), " Requerem interpretação, não são rótulos de verdade"),
        tags$li(strong("Embeddings:"), " Refletem vieses do corpus de treinamento")
      )
    ),

    h5("Limitações Computacionais"),
    wellPanel(
      tags$ul(
        tags$li(strong("Tempo de processamento:"), " Jobs de NLP em lote podem levar horas"),
        tags$li(strong("Tamanho de modelo:"), " Embeddings grandes requerem memória significativa"),
        tags$li(strong("Aproximações:"), " Nearest Neighbors aproximado troca precisão por velocidade")
      )
    ),

    h5("Melhores Práticas"),
    div(class = "panel panel-success",
      div(class = "panel-body",
        tags$ol(
          tags$li(strong("Validação:"), " Sempre valide resultados automatizados com revisão manual"),
          tags$li(strong("Atualizações:"), " Jobs em lote precisam ser re-executados periodicamente conforme o corpus cresce"),
          tags$li(strong("Baselines:"), " Compare com anotações de especialistas quando possível"),
          tags$li(strong("Transparência:"), " Reporte limitações junto com descobertas em publicações")
        )
      )
    )
  )
}
