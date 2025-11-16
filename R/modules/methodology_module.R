# Methodology Module
# Displays comprehensive research methodology and analytical methods

methodology_ui <- function(id) {
  ns <- NS(id)
  
  tagList(
    fluidRow(
      column(12,
        h3(icon("book-open"), " Research Methodology"),
        p(class = "lead", "Comprehensive guide to analytical methods, algorithms, and interpretation guidelines used in this platform."),
        hr(),
        
        # Navigation pills
        div(class = "btn-group", role = "group",
          actionButton(ns("show_overview"), "Overview", class = "btn btn-primary btn-sm"),
          actionButton(ns("show_data"), "Data Collection", class = "btn btn-outline-primary btn-sm"),
          actionButton(ns("show_sprint1"), "Sprint 1: Core Analysis", class = "btn btn-outline-primary btn-sm"),
          actionButton(ns("show_sprint2"), "Sprint 2: Readability", class = "btn btn-outline-primary btn-sm"),
          actionButton(ns("show_sprint3"), "Sprint 3: Advanced NLP", class = "btn btn-outline-primary btn-sm"),
          actionButton(ns("show_interpretation"), "Interpretation", class = "btn btn-outline-primary btn-sm"),
          actionButton(ns("show_limitations"), "Limitations", class = "btn btn-outline-primary btn-sm")
        ),
        
        hr(),
        
        # Content panel
        uiOutput(ns("content_panel"))
      )
    )
  )
}

methodology_server <- function(id) {
  moduleServer(id, function(input, output, session) {
    
    # Reactive value to store current section
    current_section <- reactiveVal("overview")
    
    observeEvent(input$show_overview, { current_section("overview") })
    observeEvent(input$show_data, { current_section("data") })
    observeEvent(input$show_sprint1, { current_section("sprint1") })
    observeEvent(input$show_sprint2, { current_section("sprint2") })
    observeEvent(input$show_sprint3, { current_section("sprint3") })
    observeEvent(input$show_interpretation, { current_section("interpretation") })
    observeEvent(input$show_limitations, { current_section("limitations") })
    
    output$content_panel <- renderUI({
      section <- current_section()
      
      switch(section,
        "overview" = overview_content(),
        "data" = data_content(),
        "sprint1" = sprint1_content(),
        "sprint2" = sprint2_content(),
        "sprint3" = sprint3_content(),
        "interpretation" = interpretation_content(),
        "limitations" = limitations_content(),
        overview_content()
      )
    })
  })
}

# Content functions
overview_content <- function() {
  div(
    h4(icon("compass"), " Methodology Overview"),
    
    wellPanel(
      h5("Research Philosophy"),
      tags$ul(
        tags$li(strong("Transparency:"), " All algorithms and metrics are documented"),
        tags$li(strong("Reproducibility:"), " Code and methods are open source"),
        tags$li(strong("Rigor:"), " Statistical validation and academic standards"),
        tags$li(strong("Practical Utility:"), " Tools designed for real-world legislative research")
      )
    ),
    
    fluidRow(
      column(4,
        div(class = "panel panel-primary",
          div(class = "panel-heading", h5("Dataset")),
          div(class = "panel-body",
            tags$ul(
              tags$li("134,000+ legislative documents"),
              tags$li("Federal, State, Municipal sources"),
              tags$li("1988-present temporal coverage"),
              tags$li("Transportation focus with broader legal context")
            )
          )
        )
      ),
      column(4,
        div(class = "panel panel-info",
          div(class = "panel-heading", h5("Methods")),
          div(class = "panel-body",
            tags$ul(
              tags$li("Network Analysis"),
              tags$li("Readability Assessment"),
              tags$li("Topic Modeling"),
              tags$li("Semantic Search"),
              tags$li("Anomaly Detection")
            )
          )
        )
      ),
      column(4,
        div(class = "panel panel-success",
          div(class = "panel-heading", h5("Technologies")),
          div(class = "panel-body",
            tags$ul(
              tags$li("R / Shiny"),
              tags$li("PostgreSQL"),
              tags$li("Word2Vec / BERT"),
              tags$li("STM (Structural Topic Models)"),
              tags$li("Network Visualization")
            )
          )
        )
      )
    )
  )
}

data_content <- function() {
  div(
    h4(icon("database"), " Data Collection & Quality Control"),
    
    wellPanel(
      h5("Primary Data Sources"),
      tags$ul(
        tags$li(strong("LexML:"), " Rede de Informação Legislativa e Jurídica"),
        tags$li(strong("Government Portals:"), " Federal, state, and municipal official sources"),
        tags$li(strong("Legislative Assemblies:"), " Direct website scraping where available")
      )
    ),
    
    h5("Quality Control Procedures"),
    fluidRow(
      column(6,
        div(class = "well",
          h6(icon("check-circle"), " Validation Steps"),
          tags$ol(
            tags$li(strong("Deduplication:"), " MD5 hash matching to identify duplicates"),
            tags$li(strong("Schema Validation:"), " Ensure all required fields are present"),
            tags$li(strong("Completeness Check:"), " Verify full text availability"),
            tags$li(strong("Encoding Standardization:"), " Convert all text to UTF-8")
          )
        )
      ),
      column(6,
        div(class = "well",
          h6(icon("table"), " Data Structure"),
          tags$pre(
"documentos
├── Metadata (título, ementa, data_publicacao)
├── Classification (tipo_documento, esfera, origem)
├── Full Text (texto_completo)
└── Processing Status (processamento_status)"
          )
        )
      )
    )
  )
}

sprint1_content <- function() {
  div(
    h4(icon("project-diagram"), " Sprint 1: Core Analysis Methods"),
    
    tabsetPanel(
      tabPanel("Network Analysis",
        br(),
        p(strong("Method:"), " Social Network Analysis (SNA) of legal citations"),
        wellPanel(
          h6("Algorithm"),
          tags$pre(
'# Citation extraction: regex-based pattern matching
lei_pattern <- "Lei\\\\s+(?:Federal\\\\s+)?n[º°]?\\\\s*[\\\\d.,/]+"

# Network construction: directed graph
G = (V, E) where:
  V = {legal documents}
  E = {(d1, d2) | d1 cites d2}

# Metrics calculated:
- Degree centrality
- Betweenness centrality  
- PageRank'
          )
        ),
        h6("Interpretation:"),
        tags$ul(
          tags$li(strong("High in-degree:"), " Foundational/frequently cited laws"),
          tags$li(strong("High out-degree:"), " Laws that build on existing framework"),
          tags$li(strong("High betweenness:"), " Bridge documents connecting legal clusters")
        )
      ),
      
      tabPanel("Anomaly Detection",
        br(),
        p(strong("Method:"), " Isolation Forest + Statistical Outliers"),
        wellPanel(
          h6("Features Used"),
          tags$ul(
            tags$li("Text length"),
            tags$li("Citation count"),
            tags$li("Amendment velocity"),
            tags$li("Jurisdiction rarity")
          ),
          h6("Detection Criteria"),
          tags$pre("anomaly_score > μ + 3σ")
        ),
        h6("Anomaly Types:"),
        tags$ul(
          tags$li(strong("Structural:"), " Unusual document format/length"),
          tags$li(strong("Content:"), " Atypical language or citations"),
          tags$li(strong("Temporal:"), " Unexpected timing of publication")
        )
      ),
      
      tabPanel("Text Reuse",
        br(),
        p(strong("Method:"), " N-gram shingling with Jaccard similarity"),
        wellPanel(
          h6("Algorithm"),
          tags$pre(
'# Shingling (k=5 words)
shingles(d) = {w_i, w_{i+1}, ..., w_{i+4}}

# Jaccard similarity
J(A,B) = |A ∩ B| / |A ∪ B|

# Thresholds
J > 0.3 → Significant reuse
J > 0.7 → High reuse/copy'
          )
        ),
        h6("Applications:"),
        tags$ul(
          tags$li(strong("Cross-jurisdiction reuse:"), " Policy diffusion analysis"),
          tags$li(strong("Temporal reuse:"), " Template-based lawmaking"),
          tags$li(strong("Exact matches:"), " Copy-paste legislation detection")
        )
      )
    )
  )
}

sprint2_content <- function() {
  div(
    h4(icon("graduation-cap"), " Sprint 2: Readability & Comparison"),
    
    h5("Readability Metrics for Portuguese"),
    
    tabsetPanel(
      tabPanel("Flesch Reading Ease",
        br(),
        wellPanel(
          tags$pre(
'FRE = 206.835 - (1.015 × ASL) - (84.6 × ASW)

where:
  ASL = Average Sentence Length
  ASW = Average Syllables per Word'
          )
        ),
        h6("Interpretation Scale:"),
        tags$table(class = "table table-striped",
          tags$thead(
            tags$tr(
              tags$th("Score"),
              tags$th("Difficulty"),
              tags$th("Grade Level")
            )
          ),
          tags$tbody(
            tags$tr(tags$td("90-100"), tags$td("Very Easy"), tags$td("5th grade")),
            tags$tr(tags$td("80-90"), tags$td("Easy"), tags$td("6th grade")),
            tags$tr(tags$td("70-80"), tags$td("Fairly Easy"), tags$td("7th grade")),
            tags$tr(tags$td("60-70"), tags$td("Standard"), tags$td("8th-9th grade")),
            tags$tr(tags$td("50-60"), tags$td("Fairly Difficult"), tags$td("10th-12th grade")),
            tags$tr(tags$td("30-50"), tags$td("Difficult"), tags$td("College level")),
            tags$tr(tags$td("0-30"), tags$td("Very Difficult"), tags$td("College graduate"))
          )
        )
      ),
      
      tabPanel("Other Metrics",
        br(),
        h6("Flesch-Kincaid Grade Level"),
        wellPanel(
          tags$pre("FKGL = (0.39 × ASL) + (11.8 × ASW) - 15.59"),
          p("Returns: Years of education needed to understand")
        ),
        
        h6("Gunning Fog Index"),
        wellPanel(
          tags$pre(
'FOG = 0.4 × [(ASL) + 100 × (complex_words / total_words)]

where complex_words = words with 3+ syllables'
          )
        ),
        
        h6("SMOG Index"),
        wellPanel(
          tags$pre("SMOG = 1.043 × √(polysyllables × (30 / sentences)) + 3.1291"),
          p("Optimized for technical/legal documents")
        )
      ),
      
      tabPanel("Jurisdictional Comparison",
        br(),
        h6("Comparative Metrics:"),
        tags$ul(
          tags$li(strong("Volume comparison:"), " Documents per capita analysis"),
          tags$li(strong("Content similarity:"), " Cross-jurisdiction TF-IDF cosine similarity"),
          tags$li(strong("Topic distribution:"), " KL divergence between regional topic models")
        ),
        
        h6("Statistical Tests:"),
        tags$ul(
          tags$li(strong("ANOVA:"), " Compare mean readability across jurisdictions"),
          tags$li(strong("Chi-square:"), " Test independence of document types and regions"),
          tags$li(strong("Mann-Whitney U:"), " Compare non-parametric distributions")
        )
      )
    )
  )
}

sprint3_content <- function() {
  div(
    h4(icon("brain"), " Sprint 3: Advanced NLP Methods"),
    
    tabsetPanel(
      tabPanel("Semantic Search (Word2Vec)",
        br(),
        p(strong("Model:"), " Continuous Bag of Words (CBOW) with 300-dimensional embeddings"),
        wellPanel(
          h6("Training Specifications"),
          tags$ul(
            tags$li("Corpus: 70,000+ legislative documents"),
            tags$li("Iterations: 10"),
            tags$li("Window size: 5 words"),
            tags$li("Min word count: 5 occurrences"),
            tags$li("Negative samples: 5")
          )
        ),
        h6("Document Embedding"),
        wellPanel(
          tags$pre("d_vector = (1/|d|) Σ word2vec(w_i)  # Average pooling")
        ),
        h6("Applications:"),
        tags$ul(
          tags$li("Find documents about same topic (different terminology)"),
          tags$li("Conceptual clustering of related legal concepts"),
          tags$li("Legal precedent discovery beyond keyword matching")
        )
      ),
      
      tabPanel("Topic Modeling (STM)",
        br(),
        p(strong("Method:"), " Structural Topic Model with metadata covariates"),
        wellPanel(
          h6("Model Specification"),
          tags$pre(
'topics ~ document_content + jurisdiction + year

# Multiple K values tested
K ∈ {10, 20, 30} topics'
          )
        ),
        h6("Output Interpretation:"),
        tags$ul(
          tags$li(strong("Top words:"), " Most probable words per topic"),
          tags$li(strong("Representative docs:"), " Documents with highest topic proportion"),
          tags$li(strong("Topic prevalence:"), " How common each topic is in corpus"),
          tags$li(strong("Covariate effects:"), " How metadata influences topic distribution")
        )
      ),
      
      tabPanel("Legal Precedents (BERT)",
        br(),
        p(strong("Model:"), " BERTimbau (neuralmind/bert-base-portuguese-cased)"),
        wellPanel(
          h6("Architecture"),
          tags$ul(
            tags$li("12 transformer layers"),
            tags$li("768 hidden units"),
            tags$li("12 attention heads"),
            tags$li("110M parameters")
          )
        ),
        h6("Advantages over traditional search:"),
        tags$ul(
          tags$li(strong("Contextual understanding:"), " Understands word meaning in context"),
          tags$li(strong("Semantic similarity:"), " Beyond exact keyword matching"),
          tags$li(strong("Legal reasoning:"), " Captures relationships between concepts"),
          tags$li(strong("Attention mechanism:"), " Highlights key phrases and clauses")
        )
      )
    )
  )
}

interpretation_content <- function() {
  div(
    h4(icon("lightbulb"), " Interpretation Guidelines"),
    
    fluidRow(
      column(4,
        wellPanel(
          h5(icon("user-graduate"), " For Researchers"),
          tags$ul(
            tags$li(strong("Context matters:"), " Consider historical/political background"),
            tags$li(strong("Triangulation:"), " Use multiple methods for validation"),
            tags$li(strong("Outliers:"), " Investigate anomalies for insights"),
            tags$li(strong("Temporal effects:"), " Account for time lags in policy diffusion")
          )
        )
      ),
      column(4,
        wellPanel(
          h5(icon("landmark"), " For Policymakers"),
          tags$ul(
            tags$li(strong("Accessibility:"), " Use readability scores for communication strategy"),
            tags$li(strong("Best practices:"), " Identify high-performing jurisdictions"),
            tags$li(strong("Gaps:"), " Geographic visualization reveals underserved regions"),
            tags$li(strong("Efficiency:"), " Text reuse shows policy adaptation patterns")
          )
        )
      ),
      column(4,
        wellPanel(
          h5(icon("balance-scale"), " For Legal Professionals"),
          tags$ul(
            tags$li(strong("Citations:"), " Network analysis reveals key foundational laws"),
            tags$li(strong("Precedents:"), " BERT search finds relevant cases"),
            tags$li(strong("Amendments:"), " Track evolution of specific regulations"),
            tags$li(strong("Comparisons:"), " Cross-jurisdiction analysis for model legislation")
          )
        )
      )
    )
  )
}

limitations_content <- function() {
  div(
    h4(icon("exclamation-triangle"), " Limitations & Caveats"),
    
    div(class = "alert alert-warning",
      p(strong("Important:"), " All automated methods have limitations. Always validate results with domain expertise and manual review.")
    ),
    
    tabsetPanel(
      tabPanel("Data Limitations",
        br(),
        tags$ul(
          tags$li(strong("Coverage gaps:"), " Not all jurisdictions have complete digitization"),
          tags$li(strong("OCR errors:"), " Scanned documents may have text extraction issues"),
          tags$li(strong("Metadata quality:"), " Varies by source and jurisdiction"),
          tags$li(strong("Temporal bias:"), " More recent documents are better represented")
        )
      ),
      
      tabPanel("Methodological Limitations",
        br(),
        tags$ul(
          tags$li(strong("Readability metrics:"), " Developed for general text, legal specificity varies"),
          tags$li(strong("Citation extraction:"), " Regex-based, may miss non-standard formats"),
          tags$li(strong("Topic models:"), " Require interpretation, not ground truth labels"),
          tags$li(strong("Embeddings:"), " Reflect training corpus biases")
        )
      ),
      
      tabPanel("Computational Limitations",
        br(),
        tags$ul(
          tags$li(strong("Processing time:"), " NLP batch jobs can take hours"),
          tags$li(strong("Model size:"), " Large embeddings require significant memory"),
          tags$li(strong("Approximations:"), " Approximate Nearest Neighbors trades accuracy for speed")
        )
      ),
      
      tabPanel("Recommendations",
        br(),
        div(class = "panel panel-success",
          div(class = "panel-heading", h5("Best Practices")),
          div(class = "panel-body",
            tags$ol(
              tags$li(strong("Validation:"), " Always validate automated results with manual review"),
              tags$li(strong("Updates:"), " Batch jobs need periodic re-running as corpus grows"),
              tags$li(strong("Baselines:"), " Compare against domain expert annotations where possible"),
              tags$li(strong("Transparency:"), " Report limitations alongside findings in publications")
            )
          )
        )
      )
    )
  )
}
