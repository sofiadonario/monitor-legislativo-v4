# Brazilian Portuguese UI Localization
# Monitor Legislativo v4 - Portuguese Interface Text
# ==================================================

#' Brazilian Portuguese UI Text Dictionary
#' 
#' Comprehensive localization dictionary for academic and legal terminology
#' following Brazilian government standards and legal conventions
#' 
#' @export
ui_text_pt_br <- list(
  
  # Application Title and Branding
  app_title = "Monitor Legislativo",
  app_subtitle = "Plataforma Brasileira de Análise Legislativa",
  app_description = "Sistema acadêmico para pesquisa e análise de documentos legislativos brasileiros",
  
  # Navigation Menu
  nav = list(
    executive_summary = "Resumo Executivo",
    library = "Biblioteca de Documentos",
    advanced_analytics = "Análise Avançada",
    topic_modeling = "Modelagem de Tópicos",
    sentiment_analysis = "Análise de Sentimento",
    geographic_analysis = "Análise Geográfica",
    sao_paulo_analysis = "Análise São Paulo",
    text_analytics = "Análise Textual",
    system_monitoring = "Monitoramento do Sistema",
    research_tools = "Ferramentas de Pesquisa",
    citation_generator = "Gerador de Citações",
    data_export = "Exportação de Dados",
    api_documentation = "Documentação da API"
  ),
  
  # Executive Summary
  executive = list(
    title = "Visão Geral do Cenário Legislativo",
    focus_areas = "Áreas de Foco Atuais",
    activity_summary = "Atividade Legislativa",
    coverage_quality = "Qualidade da Cobertura",
    total_documents = "Total de Documentos",
    states_coverage = "Cobertura Estadual",
    recent_additions = "Adições Recentes",
    data_freshness = "Atualização dos Dados",
    federal_docs = "Documentos Federais",
    state_docs = "Documentos Estaduais",
    municipal_docs = "Documentos Municipais",
    jurisprudence_docs = "Jurisprudência",
    doctrine_docs = "Doutrina",
    active_themes = "Temas Ativos",
    publication_trends = "Tendências de Publicação",
    geographic_overview = "Distribuição Geográfica",
    recent_activity = "Atividade Recente",
    quality_metrics = "Métricas de Qualidade",
    last_update = "Última atualização"
  ),
  
  # Library/Search Interface
  library = list(
    title = "Busca Avançada de Documentos Legislativos",
    search_placeholder = "Digite termos de busca (ex: 'transporte público', 'meio ambiente', 'educação')",
    search_button = "Pesquisar",
    search_help = "Use aspas para busca exata, + para termos obrigatórios, - para excluir termos",
    advanced_filters = "Filtros Avançados",
    
    # Filters
    filter_state = "Estado/Jurisdição",
    filter_all_states = "Todos os Estados",
    filter_federal = "Federal",
    filter_document_type = "Tipo de Documento",
    filter_all_types = "Todos os Tipos",
    filter_year_from = "Ano Inicial",
    filter_year_to = "Ano Final",
    filter_theme = "Tema Principal",
    filter_all_themes = "Todos os Temas",
    filter_recent_only = "Apenas documentos recentes (últimos 2 anos)",
    clear_filters = "Limpar Filtros",
    
    # Document Types
    doc_types = list(
      lei = "Lei",
      decreto = "Decreto",
      portaria = "Portaria",
      resolucao = "Resolução",
      instrucao_normativa = "Instrução Normativa",
      medida_provisoria = "Medida Provisória",
      emenda_constitucional = "Emenda Constitucional",
      jurisprudencia = "Jurisprudência",
      doutrina = "Doutrina"
    ),
    
    # Legal Themes
    themes = list(
      meio_ambiente = "Meio Ambiente",
      saude = "Saúde",
      educacao = "Educação",
      transporte = "Transporte",
      seguranca = "Segurança Pública",
      economia = "Economia",
      trabalho = "Trabalho",
      previdencia = "Previdência",
      tributario = "Tributário",
      civil = "Civil",
      penal = "Penal",
      administrativo = "Administrativo"
    ),
    
    # Results Interface
    results_title = "Resultados da Pesquisa",
    sort_by = "Ordenar por:",
    sort_options = list(
      relevance = "Mais Relevantes",
      date_desc = "Mais Recentes",
      date_asc = "Mais Antigas",
      title_asc = "Alfabética A-Z",
      title_desc = "Alfabética Z-A"
    ),
    results_per_page = "Resultados por página:",
    export_csv = "Exportar CSV",
    export_bibtex = "Exportar Citações",
    create_collection = "Criar Coleção",
    
    # Search Help
    help_title = "Dicas de Pesquisa",
    help_exact = "Busca Exata:",
    help_exact_desc = 'Use aspas: "meio ambiente"',
    help_required = "Termo Obrigatório:",
    help_required_desc = "Use +: +lei +ambiental",
    help_exclude = "Excluir Termo:",
    help_exclude_desc = "Use -: transporte -rodoviário",
    help_number = "Busca por Número:",
    help_number_desc = "Digite: Lei 12345 ou 12345/2020",
    help_wildcard = "Coringas:",
    help_wildcard_desc = "Use *: ambient* (ambiental, ambiente)",
    keyboard_shortcuts = "Atalhos de Teclado:",
    keyboard_desc = "Ctrl+K para busca rápida | F6 para navegar entre seções | Esc para limpar"
  ),
  
  # Analytics Interface
  analytics = list(
    title = "Painel de Análise Avançada",
    description = "Análises e visualizações avançadas para dados de pesquisa legislativa",
    
    topic_modeling = "Modelagem de Tópicos",
    num_topics = "Número de Tópicos",
    run_analysis = "Executar Análise",
    
    temporal_trends = "Tendências Temporais",
    trend_metric = "Métrica",
    document_count = "Contagem de Documentos",
    activity_score = "Pontuação de Atividade",
    
    sentiment_analysis = "Análise de Sentimento",
    sentiment_positive = "Positivo",
    sentiment_neutral = "Neutro", 
    sentiment_negative = "Negativo",
    
    word_frequency = "Frequência de Palavras",
    network_analysis = "Análise de Redes",
    correlation_analysis = "Análise de Correlação"
  ),
  
  # Geographic Analysis
  geographic = list(
    title = "Análise Geográfica",
    description = "Análise geográfica interativa da atividade legislativa brasileira",
    interactive_map = "Mapa Interativo",
    map_controls = "Controles do Mapa",
    map_metric = "Métrica do Mapa:",
    map_metrics = list(
      count = "Contagem de Documentos",
      per_capita = "Por Capita",
      activity = "Pontuação de Atividade"
    ),
    map_year = "Ano:",
    show_capitals = "Mostrar Capitais",
    map_statistics = "Estatísticas do Mapa"
  ),
  
  # São Paulo Analysis
  sao_paulo = list(
    title = "Análise Legislativa de São Paulo",
    description = "Análise especializada para documentos legislativos estaduais e municipais de São Paulo",
    state_overview = "Visão Geral Estadual",
    municipal_breakdown = "Detalhamento Municipal",
    comparative_analysis = "Análise Comparativa"
  ),
  
  # Text Analytics/NLP
  nlp = list(
    title = "Análise Textual",
    description = "Processamento de linguagem natural e análise textual para documentos jurídicos em português",
    named_entities = "Entidades Nomeadas",
    key_phrases = "Frases-chave",
    document_similarity = "Similaridade de Documentos",
    legal_concepts = "Conceitos Jurídicos"
  ),
  
  # System Monitoring
  monitoring = list(
    title = "Monitoramento do Sistema",
    description = "Métricas de performance e monitoramento em tempo real",
    system_health = "Saúde do Sistema",
    performance_metrics = "Métricas de Performance",
    data_quality = "Qualidade dos Dados",
    api_status = "Status da API"
  ),
  
  # Research Tools
  research_tools = list(
    citation_generator = list(
      title = "Gerador de Citações",
      description = "Gere citações compatíveis com ABNT para documentos legislativos",
      citation_style = "Estilo de Citação:",
      abnt = "ABNT",
      chicago = "Chicago",
      apa = "APA",
      generate = "Gerar Citação"
    ),
    
    data_export = list(
      title = "Exportação de Dados",
      description = "Exporte dados de pesquisa em vários formatos acadêmicos",
      export_format = "Formato de Exportação:",
      csv = "CSV",
      excel = "Excel",
      json = "JSON",
      bibtex = "BibTeX",
      export_button = "Exportar Dados"
    ),
    
    api_docs = list(
      title = "Documentação da API",
      description = "Documentação para a API do Monitor Legislativo",
      endpoints = "Endpoints",
      authentication = "Autenticação",
      examples = "Exemplos",
      rate_limits = "Limites de Taxa"
    )
  ),
  
  # Brazilian States
  states = list(
    AC = "Acre",
    AL = "Alagoas",
    AP = "Amapá",
    AM = "Amazonas",
    BA = "Bahia",
    CE = "Ceará",
    DF = "Distrito Federal",
    ES = "Espírito Santo",
    GO = "Goiás",
    MA = "Maranhão",
    MT = "Mato Grosso",
    MS = "Mato Grosso do Sul",
    MG = "Minas Gerais",
    PA = "Pará",
    PB = "Paraíba",
    PR = "Paraná",
    PE = "Pernambuco",
    PI = "Piauí",
    RJ = "Rio de Janeiro",
    RN = "Rio Grande do Norte",
    RS = "Rio Grande do Sul",
    RO = "Rondônia",
    RR = "Roraima",
    SC = "Santa Catarina",
    SP = "São Paulo",
    SE = "Sergipe",
    TO = "Tocantins"
  ),
  
  # UI Elements
  ui = list(
    loading = "Carregando...",
    loading_data = "Carregando dados...",
    processing = "Processando...",
    searching = "Buscando...",
    exporting = "Exportando...",
    saving = "Salvando...",
    error = "Erro",
    success = "Sucesso",
    warning = "Aviso",
    info = "Informação",
    cancel = "Cancelar",
    confirm = "Confirmar",
    save = "Salvar",
    close = "Fechar",
    back = "Voltar",
    next = "Próximo",
    previous = "Anterior",
    first_page = "Primeira página",
    last_page = "Última página",
    page = "Página",
    of = "de",
    total = "Total",
    showing = "Mostrando",
    to = "até",
    entries = "entradas",
    no_data = "Nenhum dado disponível",
    no_results = "Nenhum resultado encontrado",
    try_different_search = "Tente uma busca diferente",
    clear_search = "Limpar busca"
  ),
  
  # Accessibility
  a11y = list(
    skip_to_main = "Pular para o conteúdo principal",
    skip_to_nav = "Pular para a navegação",
    skip_to_search = "Pular para a busca",
    main_navigation = "Navegação principal",
    main_content = "Conteúdo principal",
    sidebar = "Barra lateral",
    footer = "Rodapé",
    search_landmark = "Busca",
    results_landmark = "Resultados",
    filters_landmark = "Filtros",
    required_field = "Campo obrigatório",
    invalid_field = "Campo inválido",
    valid_field = "Campo válido",
    form_errors = "Erros no formulário",
    loading_content = "Carregando conteúdo",
    content_loaded = "Conteúdo carregado",
    modal_opened = "Modal aberto",
    modal_closed = "Modal fechado",
    menu_expanded = "Menu expandido",
    menu_collapsed = "Menu recolhido",
    sort_ascending = "Ordenação crescente",
    sort_descending = "Ordenação decrescente",
    page_navigation = "Navegação de páginas",
    results_per_page = "Resultados por página",
    current_page = "Página atual",
    high_contrast_enabled = "Alto contraste ativado",
    high_contrast_disabled = "Alto contraste desativado",
    keyboard_navigation = "Navegação por teclado ativada"
  ),
  
  # Legal/Academic Terms
  legal = list(
    constitution = "Constituição",
    federal_law = "Lei Federal",
    state_law = "Lei Estadual",
    municipal_law = "Lei Municipal",
    decree = "Decreto",
    ordinance = "Portaria",
    resolution = "Resolução",
    normative_instruction = "Instrução Normativa",
    provisional_measure = "Medida Provisória",
    constitutional_amendment = "Emenda Constitucional",
    jurisprudence = "Jurisprudência",
    doctrine = "Doutrina",
    case_law = "Jurisprudência",
    legal_precedent = "Precedente Legal",
    court_decision = "Decisão Judicial",
    supreme_court = "Supremo Tribunal Federal",
    superior_court = "Superior Tribunal de Justiça",
    federal_court = "Tribunal Federal",
    state_court = "Tribunal Estadual",
    legislative_branch = "Poder Legislativo",
    executive_branch = "Poder Executivo",
    judicial_branch = "Poder Judiciário",
    national_congress = "Congresso Nacional",
    senate = "Senado Federal",
    chamber_of_deputies = "Câmara dos Deputados",
    state_assembly = "Assembleia Legislativa",
    city_council = "Câmara Municipal"
  ),
  
  # Time and Date Formatting
  time = list(
    today = "Hoje",
    yesterday = "Ontem",
    this_week = "Esta semana",
    last_week = "Semana passada",
    this_month = "Este mês",
    last_month = "Mês passado",
    this_year = "Este ano",
    last_year = "Ano passado",
    days_ago = "dias atrás",
    weeks_ago = "semanas atrás",
    months_ago = "meses atrás",
    years_ago = "anos atrás",
    updated_at = "Atualizado em",
    published_at = "Publicado em",
    created_at = "Criado em",
    modified_at = "Modificado em"
  ),
  
  # Error Messages
  errors = list(
    connection_error = "Erro de conexão com o servidor",
    timeout_error = "Tempo limite excedido",
    server_error = "Erro interno do servidor",
    not_found = "Dados não encontrados",
    access_denied = "Acesso negado",
    invalid_search = "Termo de busca inválido",
    no_results = "Nenhum resultado encontrado para sua busca",
    export_failed = "Falha na exportação",
    save_failed = "Falha ao salvar",
    load_failed = "Falha ao carregar dados",
    network_error = "Erro de rede",
    unknown_error = "Erro desconhecido"
  ),
  
  # Success Messages
  success = list(
    data_loaded = "Dados carregados com sucesso",
    search_completed = "Busca concluída",
    export_completed = "Exportação concluída",
    save_completed = "Salvo com sucesso",
    analysis_completed = "Análise concluída",
    citation_generated = "Citação gerada",
    collection_created = "Coleção criada",
    filters_applied = "Filtros aplicados",
    data_updated = "Dados atualizados"
  )
)

#' Get Localized Text
#' 
#' Retrieves localized text based on key path
#' 
#' @param key Character string or vector representing the path to the text
#' @param default Default text if key not found
#' @return Character string with localized text
#' @export
get_text <- function(key, default = NULL) {
  
  # Handle vector keys (nested path)
  if (length(key) > 1) {
    result <- ui_text_pt_br
    for (k in key) {
      if (is.list(result) && k %in% names(result)) {
        result <- result[[k]]
      } else {
        return(default %||% paste(key, collapse = "."))
      }
    }
    return(result)
  }
  
  # Handle single key
  if (key %in% names(ui_text_pt_br)) {
    return(ui_text_pt_br[[key]])
  }
  
  return(default %||% key)
}

#' Generate Academic Citations in Portuguese
#' 
#' Generate ABNT-compliant citations for Brazilian legal documents
#' 
#' @param document_data List containing document metadata
#' @param style Citation style ("abnt", "chicago", "apa")
#' @return Character string with formatted citation
#' @export
generate_citation_pt <- function(document_data, style = "abnt") {
  
  switch(style,
    "abnt" = generate_abnt_citation(document_data),
    "chicago" = generate_chicago_citation(document_data),
    "apa" = generate_apa_citation(document_data),
    generate_abnt_citation(document_data)
  )
}

#' Generate ABNT Citation
#' 
#' Generate citation following ABNT NBR 6023:2018 standards
#' 
#' @param doc Document metadata list
#' @return Character string with ABNT citation
generate_abnt_citation <- function(doc) {
  
  # Extract document information
  title <- doc$titulo %||% "Título não disponível"
  number <- doc$numero
  year <- doc$ano
  jurisdiction <- doc$jurisdicao %||% "Brasil"
  type <- doc$tipo %||% "Documento"
  date <- doc$data_publicacao
  
  # Format according to ABNT standards
  if (!isTRUE(is.null(number)) && !is.null(year)) {
    citation <- sprintf("%s. %s nº %s, de %s. %s, %s.",
                       toupper(jurisdiction),
                       stringr::str_to_title(type),
                       number,
                       format_date_pt(date),
                       stringr::str_to_title(title),
                       year)
  } else {
    citation <- sprintf("%s. %s. %s, %s.",
                       toupper(jurisdiction),
                       stringr::str_to_title(title),
                       stringr::str_to_title(type),
                       year %||% "s.d.")
  }
  
  return(citation)
}

#' Format Date in Portuguese
#' 
#' Format date for Brazilian citations
#' 
#' @param date Date object or string
#' @return Character string with formatted date
format_date_pt <- function(date) {
  
  if (is.null(date)) return("data não disponível")
  
  # Convert to Date object if needed
  if (is.character(date)) {
    date <- tryCatch(as.Date(date), error = function(e) NULL)
  }
  
  if (is.null(date)) return("data não disponível")
  
  # Format in Portuguese
  day <- format(date, "%d")
  month <- switch(format(date, "%m"),
    "01" = "janeiro", "02" = "fevereiro", "03" = "março",
    "04" = "abril", "05" = "maio", "06" = "junho",
    "07" = "julho", "08" = "agosto", "09" = "setembro",
    "10" = "outubro", "11" = "novembro", "12" = "dezembro"
  )
  year <- format(date, "%Y")
  
  return(paste(day, "de", month, "de", year))
}

#' Legal Document Type Names in Portuguese
#' 
#' Map document type codes to proper Portuguese legal names
#' 
#' @export
legal_document_types_pt <- list(
  "lei" = "Lei",
  "decreto" = "Decreto",
  "portaria" = "Portaria",
  "resolucao" = "Resolução",
  "instrucao_normativa" = "Instrução Normativa",
  "medida_provisoria" = "Medida Provisória",
  "emenda_constitucional" = "Emenda Constitucional",
  "decreto_lei" = "Decreto-Lei",
  "lei_complementar" = "Lei Complementar",
  "lei_delegada" = "Lei Delegada",
  "orientacao_normativa" = "Orientação Normativa",
  "ato_declaratorio" = "Ato Declaratório",
  "circular" = "Circular",
  "ordem_servico" = "Ordem de Serviço",
  "parecer" = "Parecer",
  "decisao" = "Decisão",
  "acordao" = "Acórdão",
  "sentenca" = "Sentença",
  "despacho" = "Despacho"
)

#' Brazilian Legal Themes in Portuguese
#' 
#' Comprehensive list of legal themes used in Brazilian legislation
#' 
#' @export
legal_themes_pt <- list(
  "administrativo" = "Direito Administrativo",
  "ambiental" = "Direito Ambiental",
  "civil" = "Direito Civil",
  "comercial" = "Direito Comercial",
  "constitucional" = "Direito Constitucional",
  "consumidor" = "Direito do Consumidor",
  "empresarial" = "Direito Empresarial",
  "familia" = "Direito de Família",
  "financeiro" = "Direito Financeiro",
  "imobiliario" = "Direito Imobiliário",
  "internacional" = "Direito Internacional",
  "penal" = "Direito Penal",
  "previdenciario" = "Direito Previdenciário",
  "processual" = "Direito Processual",
  "trabalho" = "Direito do Trabalho",
  "tributario" = "Direito Tributário",
  "urbanistico" = "Direito Urbanístico",
  "saude" = "Saúde",
  "educacao" = "Educação",
  "transporte" = "Transporte",
  "seguranca" = "Segurança Pública",
  "economia" = "Economia",
  "agricultura" = "Agricultura",
  "industria" = "Indústria",
  "tecnologia" = "Tecnologia",
  "comunicacao" = "Comunicação",
  "energia" = "Energia",
  "mineracao" = "Mineração",
  "turismo" = "Turismo",
  "cultura" = "Cultura",
  "esporte" = "Esporte"
)

cat("✅ Brazilian Portuguese localization loaded\n")