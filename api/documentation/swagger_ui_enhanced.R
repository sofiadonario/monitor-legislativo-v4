# ============================================================================
# ENHANCED SWAGGER UI IMPLEMENTATION - SPRINT 7A (API-006)
# ============================================================================
# 
# Enhanced Swagger UI with Brazilian government styling and interactive features
# Serves comprehensive OpenAPI documentation with live API testing
# 
# Features:
# - Brazilian government design system
# - Interactive API testing with authentication
# - Multi-language support (Portuguese/English)
# - Academic research workflow integration
# - Rate limiting visualization
# - Real-time example generation
# - LGPD compliance documentation
# ============================================================================

cat("📚 Loading Enhanced Swagger UI Implementation\n")

# Required packages for enhanced UI
required_packages <- c("htmlwidgets", "htmltools", "jsonlite", "stringr", "yaml")

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat(paste("📦 Installing", pkg, "\n"))
    install.packages(pkg, quiet = TRUE)
  }
  suppressPackageStartupMessages(library(pkg, character.only = TRUE))
}

# Brazilian Government Design System Colors
BRASIL_COLORS <- list(
  primary = "#1E4D8B",           # Azul Brasil
  secondary = "#2E7F32",         # Verde Brasil
  accent = "#FFB300",            # Amarelo Brasil
  success = "#4CAF50",           # Verde Sucesso
  warning = "#FF9800",           # Laranja Aviso
  error = "#F44336",             # Vermelho Erro
  background = "#FAFAFA",        # Cinza Claro
  surface = "#FFFFFF",           # Branco
  text_primary = "#212121",      # Cinza Escuro
  text_secondary = "#757575",    # Cinza Médio
  border = "#E0E0E0"            # Cinza Borda
)

# Enhanced Swagger UI CSS with Brazilian Government Theme
create_enhanced_swagger_css <- function() {
  css <- paste0('
    /* Brazilian Government Design System Theme */
    :root {
      --brasil-primary: ', BRASIL_COLORS$primary, ';
      --brasil-secondary: ', BRASIL_COLORS$secondary, ';
      --brasil-accent: ', BRASIL_COLORS$accent, ';
      --brasil-success: ', BRASIL_COLORS$success, ';
      --brasil-warning: ', BRASIL_COLORS$warning, ';
      --brasil-error: ', BRASIL_COLORS$error, ';
      --brasil-background: ', BRASIL_COLORS$background, ';
      --brasil-surface: ', BRASIL_COLORS$surface, ';
      --brasil-text-primary: ', BRASIL_COLORS$text_primary, ';
      --brasil-text-secondary: ', BRASIL_COLORS$text_secondary, ';
      --brasil-border: ', BRASIL_COLORS$border, ';
    }

    /* Main Layout */
    .swagger-ui {
      font-family: "Source Sans Pro", "Helvetica Neue", Arial, sans-serif;
      background-color: var(--brasil-background);
      color: var(--brasil-text-primary);
    }

    /* Header Styling */
    .swagger-ui .info {
      background: linear-gradient(135deg, var(--brasil-primary) 0%, var(--brasil-secondary) 100%);
      color: white;
      padding: 2rem;
      border-radius: 8px;
      margin-bottom: 2rem;
      box-shadow: 0 4px 12px rgba(30, 77, 139, 0.2);
    }

    .swagger-ui .info .title {
      color: white;
      font-size: 2.5rem;
      font-weight: 600;
      margin-bottom: 0.5rem;
    }

    .swagger-ui .info .description {
      color: rgba(255, 255, 255, 0.9);
      font-size: 1.1rem;
      line-height: 1.6;
    }

    /* Brazilian Government Badge */
    .brasil-badge {
      display: inline-flex;
      align-items: center;
      background: var(--brasil-accent);
      color: var(--brasil-text-primary);
      padding: 0.5rem 1rem;
      border-radius: 20px;
      font-weight: 600;
      font-size: 0.9rem;
      margin: 0.5rem 0.5rem 0.5rem 0;
      box-shadow: 0 2px 4px rgba(255, 179, 0, 0.3);
    }

    .brasil-badge::before {
      content: "🇧🇷";
      margin-right: 0.5rem;
    }

    /* Server Selection */
    .swagger-ui .servers > label {
      color: var(--brasil-text-primary);
      font-weight: 600;
    }

    .swagger-ui .servers select {
      border: 2px solid var(--brasil-border);
      border-radius: 6px;
      padding: 0.5rem;
      background: var(--brasil-surface);
      color: var(--brasil-text-primary);
    }

    .swagger-ui .servers select:focus {
      border-color: var(--brasil-primary);
      box-shadow: 0 0 0 3px rgba(30, 77, 139, 0.1);
    }

    /* Authentication Section */
    .swagger-ui .auth-wrapper {
      background: var(--brasil-surface);
      border: 2px solid var(--brasil-border);
      border-radius: 8px;
      padding: 1.5rem;
      margin: 1rem 0;
    }

    .swagger-ui .auth-wrapper .auth-container {
      background: transparent;
    }

    .swagger-ui .btn.authorize {
      background: var(--brasil-primary);
      border-color: var(--brasil-primary);
      color: white;
      font-weight: 600;
      border-radius: 6px;
      padding: 0.75rem 1.5rem;
      transition: all 0.3s ease;
    }

    .swagger-ui .btn.authorize:hover {
      background: #1a3f73;
      transform: translateY(-1px);
      box-shadow: 0 4px 8px rgba(30, 77, 139, 0.3);
    }

    /* Tag Groups */
    .swagger-ui .opblock-tag {
      background: var(--brasil-surface);
      border: 1px solid var(--brasil-border);
      border-radius: 8px;
      margin: 1rem 0;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
    }

    .swagger-ui .opblock-tag:hover {
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    }

    .swagger-ui .opblock-tag-section h3 {
      color: var(--brasil-primary);
      font-weight: 600;
      border-bottom: 2px solid var(--brasil-border);
      padding-bottom: 0.5rem;
      margin-bottom: 1rem;
    }

    /* HTTP Method Colors */
    .swagger-ui .opblock.opblock-get {
      border-color: var(--brasil-secondary);
      background: rgba(46, 127, 50, 0.05);
    }

    .swagger-ui .opblock.opblock-get .opblock-summary {
      border-color: var(--brasil-secondary);
    }

    .swagger-ui .opblock.opblock-post {
      border-color: var(--brasil-primary);
      background: rgba(30, 77, 139, 0.05);
    }

    .swagger-ui .opblock.opblock-post .opblock-summary {
      border-color: var(--brasil-primary);
    }

    .swagger-ui .opblock.opblock-put {
      border-color: var(--brasil-accent);
      background: rgba(255, 179, 0, 0.05);
    }

    .swagger-ui .opblock.opblock-delete {
      border-color: var(--brasil-error);
      background: rgba(244, 67, 54, 0.05);
    }

    /* Operation Blocks */
    .swagger-ui .opblock {
      border-radius: 8px;
      margin: 1rem 0;
      overflow: hidden;
      transition: all 0.3s ease;
    }

    .swagger-ui .opblock:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.1);
    }

    .swagger-ui .opblock-summary {
      padding: 1rem 1.5rem;
      font-weight: 600;
    }

    .swagger-ui .opblock-summary-description {
      color: var(--brasil-text-secondary);
      font-weight: normal;
      margin-left: 1rem;
    }

    /* Parameters */
    .swagger-ui .parameters-container {
      background: var(--brasil-background);
      border-radius: 6px;
      padding: 1rem;
      margin: 1rem 0;
    }

    .swagger-ui .parameter__name {
      color: var(--brasil-primary);
      font-weight: 600;
    }

    .swagger-ui .parameter__type {
      color: var(--brasil-secondary);
      font-weight: 500;
    }

    /* Try it out */
    .swagger-ui .btn.try-out__btn {
      background: var(--brasil-secondary);
      border-color: var(--brasil-secondary);
      color: white;
      border-radius: 6px;
      font-weight: 600;
    }

    .swagger-ui .btn.try-out__btn:hover {
      background: #245a29;
    }

    .swagger-ui .btn.execute {
      background: var(--brasil-primary);
      border-color: var(--brasil-primary);
      color: white;
      border-radius: 6px;
      font-weight: 600;
      padding: 0.75rem 2rem;
    }

    .swagger-ui .btn.execute:hover {
      background: #1a3f73;
    }

    /* Responses */
    .swagger-ui .responses-wrapper {
      background: var(--brasil-surface);
      border: 1px solid var(--brasil-border);
      border-radius: 8px;
      padding: 1rem;
      margin: 1rem 0;
    }

    .swagger-ui .response-col_status {
      color: var(--brasil-primary);
      font-weight: 600;
    }

    .swagger-ui .response-col_description {
      color: var(--brasil-text-primary);
    }

    /* Code Examples */
    .swagger-ui .highlight-code {
      background: #f8f9fa;
      border: 1px solid var(--brasil-border);
      border-radius: 6px;
      padding: 1rem;
      font-family: "Fira Code", Monaco, monospace;
    }

    /* Models */
    .swagger-ui .model-container {
      background: var(--brasil-surface);
      border: 1px solid var(--brasil-border);
      border-radius: 8px;
      padding: 1rem;
    }

    .swagger-ui .model-title {
      color: var(--brasil-primary);
      font-weight: 600;
    }

    /* Brazilian Academic Features */
    .academic-workflow {
      background: linear-gradient(45deg, var(--brasil-secondary), var(--brasil-primary));
      color: white;
      padding: 2rem;
      border-radius: 8px;
      margin: 2rem 0;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    }

    .academic-workflow h3 {
      color: white;
      margin-bottom: 1rem;
      font-weight: 600;
    }

    .workflow-steps {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }

    .workflow-step {
      background: rgba(255, 255, 255, 0.1);
      padding: 1rem;
      border-radius: 6px;
      border-left: 4px solid var(--brasil-accent);
    }

    .workflow-step h4 {
      color: white;
      margin-bottom: 0.5rem;
      font-weight: 600;
    }

    .workflow-step p {
      color: rgba(255, 255, 255, 0.9);
      font-size: 0.9rem;
      line-height: 1.4;
    }

    /* Rate Limiting Visualization */
    .rate-limit-info {
      background: var(--brasil-surface);
      border: 1px solid var(--brasil-border);
      border-radius: 8px;
      padding: 1.5rem;
      margin: 1rem 0;
    }

    .rate-limit-tiers {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-top: 1rem;
    }

    .rate-tier {
      text-align: center;
      padding: 1rem;
      border-radius: 6px;
      border: 2px solid var(--brasil-border);
      transition: all 0.3s ease;
    }

    .rate-tier:hover {
      border-color: var(--brasil-primary);
      transform: translateY(-2px);
    }

    .rate-tier.demo {
      background: linear-gradient(135deg, #ffd54f, #ffb300);
    }

    .rate-tier.academic {
      background: linear-gradient(135deg, #81c784, #4caf50);
    }

    .rate-tier.premium {
      background: linear-gradient(135deg, #64b5f6, #2196f3);
    }

    .rate-tier h4 {
      margin-bottom: 0.5rem;
      font-weight: 600;
      color: white;
    }

    .rate-tier p {
      color: rgba(255, 255, 255, 0.9);
      font-size: 0.9rem;
      margin: 0.25rem 0;
    }

    /* LGPD Compliance Section */
    .lgpd-section {
      background: var(--brasil-surface);
      border: 2px solid var(--brasil-secondary);
      border-radius: 8px;
      padding: 1.5rem;
      margin: 2rem 0;
    }

    .lgpd-section h3 {
      color: var(--brasil-secondary);
      font-weight: 600;
      margin-bottom: 1rem;
    }

    .lgpd-features {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 1rem;
    }

    .lgpd-feature {
      display: flex;
      align-items: center;
      padding: 0.75rem;
      background: rgba(76, 175, 80, 0.05);
      border-radius: 6px;
      border-left: 4px solid var(--brasil-secondary);
    }

    .lgpd-feature::before {
      content: "✓";
      color: var(--brasil-secondary);
      font-weight: bold;
      margin-right: 0.5rem;
    }

    /* Responsive Design */
    @media (max-width: 768px) {
      .swagger-ui .info {
        padding: 1rem;
      }
      
      .swagger-ui .info .title {
        font-size: 1.8rem;
      }
      
      .workflow-steps,
      .rate-limit-tiers,
      .lgpd-features {
        grid-template-columns: 1fr;
      }
    }

    /* Loading Animation */
    .loading-spinner {
      border: 3px solid var(--brasil-border);
      border-top: 3px solid var(--brasil-primary);
      border-radius: 50%;
      width: 30px;
      height: 30px;
      animation: spin 1s linear infinite;
      margin: 1rem auto;
    }

    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }

    /* Print Styles */
    @media print {
      .swagger-ui .info {
        background: white !important;
        color: black !important;
        box-shadow: none !important;
      }
      
      .swagger-ui .opblock {
        break-inside: avoid;
      }
    }
  ')
  
  return(css)
}

# Enhanced JavaScript for interactive features
create_enhanced_swagger_js <- function() {
  js <- '
    // Brazilian Government Swagger UI Enhancements
    class BrasilSwaggerUI {
      constructor() {
        this.initializeBrazilianFeatures();
        this.setupInteractiveExamples();
        this.initializeRateLimitVisualization();
        this.setupAcademicWorkflow();
      }

      initializeBrazilianFeatures() {
        // Add Brazilian government badges
        const infoSection = document.querySelector(".swagger-ui .info");
        if (infoSection) {
          const badges = this.createBrazilianBadges();
          infoSection.appendChild(badges);
        }

        // Add academic workflow section
        this.addAcademicWorkflowSection();
        
        // Add rate limiting information
        this.addRateLimitingSection();
        
        // Add LGPD compliance section
        this.addLGPDSection();
      }

      createBrazilianBadges() {
        const container = document.createElement("div");
        container.style.marginTop = "1rem";
        
        const badges = [
          { text: "Governo Federal", class: "brasil-badge" },
          { text: "LGPD Compliant", class: "brasil-badge" },
          { text: "Pesquisa Acadêmica", class: "brasil-badge" },
          { text: "Dados Abertos", class: "brasil-badge" }
        ];
        
        badges.forEach(badge => {
          const badgeEl = document.createElement("span");
          badgeEl.className = badge.class;
          badgeEl.textContent = badge.text;
          container.appendChild(badgeEl);
        });
        
        return container;
      }

      addAcademicWorkflowSection() {
        const container = document.createElement("div");
        container.className = "academic-workflow";
        container.innerHTML = `
          <h3>🎓 Fluxo de Trabalho para Pesquisa Acadêmica</h3>
          <p>Guia passo-a-passo para pesquisadores acadêmicos utilizarem a API Monitor Legislativo</p>
          <div class="workflow-steps">
            <div class="workflow-step">
              <h4>1. Descoberta</h4>
              <p>Use <code>/documents</code> para explorar o dataset e entender a estrutura dos dados</p>
            </div>
            <div class="workflow-step">
              <h4>2. Busca</h4>
              <p>Use <code>/search</code> para encontrar documentos específicos com filtros avançados</p>
            </div>
            <div class="workflow-step">
              <h4>3. Análise</h4>
              <p>Use <code>/analytics</code> para obter estatísticas e métricas agregadas</p>
            </div>
            <div class="workflow-step">
              <h4>4. Visualização</h4>
              <p>Use <code>/geographic</code> para análises espaciais e mapas coropléticos</p>
            </div>
            <div class="workflow-step">
              <h4>5. Exportação</h4>
              <p>Use <code>/export</code> para download de dados em formatos acadêmicos</p>
            </div>
            <div class="workflow-step">
              <h4>6. Citação</h4>
              <p>Use <code>/citations</code> para gerar referências no padrão ABNT</p>
            </div>
          </div>
        `;
        
        // Insert after info section
        const infoSection = document.querySelector(".swagger-ui .info");
        if (infoSection && infoSection.parentNode) {
          infoSection.parentNode.insertBefore(container, infoSection.nextSibling);
        }
      }

      addRateLimitingSection() {
        const container = document.createElement("div");
        container.className = "rate-limit-info";
        container.innerHTML = `
          <h3>🚦 Limites de Taxa por Nível de Acesso</h3>
          <div class="rate-limit-tiers">
            <div class="rate-tier demo">
              <h4>Demo</h4>
              <p>100 requisições/dia</p>
              <p>Dados limitados</p>
              <p>Sem autenticação acadêmica</p>
            </div>
            <div class="rate-tier academic">
              <h4>Acadêmico</h4>
              <p>10.000 requisições/dia</p>
              <p>Acesso completo</p>
              <p>Verificação institucional</p>
            </div>
            <div class="rate-tier premium">
              <h4>Premium</h4>
              <p>100.000 requisições/dia</p>
              <p>Recursos avançados</p>
              <p>Suporte prioritário</p>
            </div>
          </div>
        `;
        
        const workflowSection = document.querySelector(".academic-workflow");
        if (workflowSection && workflowSection.parentNode) {
          workflowSection.parentNode.insertBefore(container, workflowSection.nextSibling);
        }
      }

      addLGPDSection() {
        const container = document.createElement("div");
        container.className = "lgpd-section";
        container.innerHTML = `
          <h3>🛡️ Conformidade LGPD - Lei Geral de Proteção de Dados</h3>
          <div class="lgpd-features">
            <div class="lgpd-feature">Consentimento explícito para coleta de dados</div>
            <div class="lgpd-feature">Minimização de dados pessoais</div>
            <div class="lgpd-feature">Direito ao esquecimento implementado</div>
            <div class="lgpd-feature">Portabilidade de dados garantida</div>
            <div class="lgpd-feature">Auditoria completa de acessos</div>
            <div class="lgpd-feature">Criptografia end-to-end</div>
          </div>
        `;
        
        const rateLimitSection = document.querySelector(".rate-limit-info");
        if (rateLimitSection && rateLimitSection.parentNode) {
          rateLimitSection.parentNode.insertBefore(container, rateLimitSection.nextSibling);
        }
      }

      setupInteractiveExamples() {
        // Add realistic Brazilian legislative examples to parameters
        this.addBrazilianExamples();
        
        // Setup dynamic example generation
        this.setupDynamicExamples();
      }

      addBrazilianExamples() {
        const brazilianExamples = {
          "estado": ["SP", "RJ", "MG", "RS", "PR", "SC", "BA", "GO", "DF"],
          "ano": [2023, 2022, 2021, 2020, 2019],
          "species": ["Lei", "Decreto", "Medida Provisória", "Portaria", "Resolução"],
          "orgao": ["Presidência da República", "Ministério da Fazenda", "Ministério da Educação"],
          "query": [
            "licitação pública",
            "direitos humanos",
            "educação básica",
            "meio ambiente",
            "saúde pública",
            "segurança jurídica"
          ]
        };

        // Apply examples to parameter inputs
        setTimeout(() => {
          Object.keys(brazilianExamples).forEach(paramName => {
            const inputs = document.querySelectorAll(`input[placeholder*="${paramName}"], input[data-param="${paramName}"]`);
            inputs.forEach(input => {
              const examples = brazilianExamples[paramName];
              const randomExample = examples[Math.floor(Math.random() * examples.length)];
              input.placeholder = `Exemplo: ${randomExample}`;
            });
          });
        }, 1000);
      }

      setupDynamicExamples() {
        // Monitor parameter changes and provide contextual examples
        document.addEventListener("input", (event) => {
          if (event.target.matches("input[data-param], textarea[data-param]")) {
            this.updateContextualExamples(event.target);
          }
        });
      }

      updateContextualExamples(input) {
        const paramName = input.getAttribute("data-param") || input.name;
        
        // Provide contextual help based on parameter
        const contextualHelp = {
          "query": "Dica: Use termos jurídicos em português como 'licitação', 'contrato administrativo', 'direito constitucional'",
          "estado": "Dica: Use códigos de estado brasileiros (SP, RJ, MG, etc.)",
          "limit": "Dica: Máximo de 1000 resultados por requisição"
        };
        
        if (contextualHelp[paramName]) {
          this.showContextualHelp(input, contextualHelp[paramName]);
        }
      }

      showContextualHelp(element, message) {
        // Remove existing help
        const existingHelp = element.parentNode.querySelector(".contextual-help");
        if (existingHelp) {
          existingHelp.remove();
        }
        
        // Create help element
        const helpElement = document.createElement("div");
        helpElement.className = "contextual-help";
        helpElement.style.cssText = `
          color: var(--brasil-secondary);
          font-size: 0.8rem;
          margin-top: 0.25rem;
          font-style: italic;
        `;
        helpElement.textContent = message;
        
        // Insert help
        element.parentNode.appendChild(helpElement);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
          if (helpElement.parentNode) {
            helpElement.remove();
          }
        }, 5000);
      }

      initializeRateLimitVisualization() {
        // Add rate limit headers to response display
        const observer = new MutationObserver((mutations) => {
          mutations.forEach((mutation) => {
            if (mutation.type === "childList") {
              const responseHeaders = document.querySelectorAll(".response-col_header");
              responseHeaders.forEach(header => {
                if (header.textContent.toLowerCase().includes("rate-limit")) {
                  this.highlightRateLimitHeader(header);
                }
              });
            }
          });
        });
        
        observer.observe(document.body, { childList: true, subtree: true });
      }

      highlightRateLimitHeader(header) {
        header.style.cssText += `
          background: linear-gradient(45deg, var(--brasil-accent), var(--brasil-warning));
          color: white;
          padding: 0.25rem 0.5rem;
          border-radius: 4px;
          font-weight: 600;
        `;
      }

      setupAcademicWorkflow() {
        // Add quick action buttons for common academic workflows
        this.addQuickActionButtons();
      }

      addQuickActionButtons() {
        const container = document.createElement("div");
        container.style.cssText = `
          position: fixed;
          bottom: 2rem;
          right: 2rem;
          z-index: 1000;
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        `;
        
        const buttons = [
          {
            text: "📚 Guia Acadêmico",
            action: () => this.scrollToSection(".academic-workflow")
          },
          {
            text: "🔑 Autenticação",
            action: () => this.scrollToSection(".auth-wrapper")
          },
          {
            text: "📊 Endpoints",
            action: () => this.scrollToSection(".opblock-tag")
          }
        ];
        
        buttons.forEach(btn => {
          const button = document.createElement("button");
          button.textContent = btn.text;
          button.style.cssText = `
            background: var(--brasil-primary);
            color: white;
            border: none;
            border-radius: 50px;
            padding: 0.75rem 1rem;
            cursor: pointer;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(30, 77, 139, 0.3);
            transition: all 0.3s ease;
          `;
          
          button.addEventListener("click", btn.action);
          button.addEventListener("mouseenter", () => {
            button.style.transform = "translateY(-2px)";
            button.style.boxShadow = "0 6px 16px rgba(30, 77, 139, 0.4)";
          });
          button.addEventListener("mouseleave", () => {
            button.style.transform = "translateY(0)";
            button.style.boxShadow = "0 4px 12px rgba(30, 77, 139, 0.3)";
          });
          
          container.appendChild(button);
        });
        
        document.body.appendChild(container);
      }

      scrollToSection(selector) {
        const element = document.querySelector(selector);
        if (element) {
          element.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      }
    }

    // Initialize when DOM is ready
    document.addEventListener("DOMContentLoaded", () => {
      // Wait for Swagger UI to load
      setTimeout(() => {
        new BrasilSwaggerUI();
      }, 2000);
    });

    // Reinitialize on Swagger UI updates
    if (window.SwaggerUIBundle) {
      const originalRender = window.SwaggerUIBundle;
      window.SwaggerUIBundle = function(...args) {
        const result = originalRender.apply(this, args);
        setTimeout(() => {
          new BrasilSwaggerUI();
        }, 1000);
        return result;
      };
    }
  ';
  
  return(js)
}

# Generate Enhanced Swagger UI HTML
generate_enhanced_swagger_html <- function(openapi_spec_path = "openapi_complete.yaml", 
                                         title = "Monitor Legislativo API - Documentação Interativa",
                                         favicon_url = NULL,
                                         custom_css = NULL,
                                         custom_js = NULL) {
  
  # Read OpenAPI spec
  if (file.exists(openapi_spec_path)) {
    openapi_spec <- yaml::read_yaml(openapi_spec_path)
  } else {
    openapi_spec <- list(
      openapi = "3.0.3",
      info = list(
        title = "Monitor Legislativo API",
        version = "1.0.0"
      )
    )
  }
  
  # Convert spec to JSON for JavaScript
  openapi_json <- jsonlite::toJSON(openapi_spec, auto_unbox = TRUE, pretty = TRUE)
  
  # Brazilian Government favicon
  if (is.null(favicon_url)) {
    favicon_url <- "https://www.gov.br/favicon.ico"
  }
  
  # Combine CSS
  enhanced_css <- create_enhanced_swagger_css()
  if (!is.null(custom_css)) {
    enhanced_css <- paste(enhanced_css, custom_css, sep = "\n")
  }
  
  # Combine JavaScript
  enhanced_js <- create_enhanced_swagger_js()
  if (!is.null(custom_js)) {
    enhanced_js <- paste(enhanced_js, custom_js, sep = "\n")
  }
  
  # Generate HTML
  html_content <- paste0('
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>', title, '</title>
  <meta name="description" content="Documentação interativa da API Monitor Legislativo - Sistema de monitoramento da legislação brasileira">
  <meta name="keywords" content="API, legislação, Brasil, governo, dados abertos, pesquisa acadêmica">
  <meta name="author" content="Monitor Legislativo">
  
  <!-- Open Graph / Facebook -->
  <meta property="og:type" content="website">
  <meta property="og:url" content="https://monitorlegislativo.gov.br/api/docs">
  <meta property="og:title" content="', title, '">
  <meta property="og:description" content="API REST para acesso programático aos dados legislativos brasileiros">
  <meta property="og:image" content="https://monitorlegislativo.gov.br/assets/og-image.png">

  <!-- Twitter -->
  <meta property="twitter:card" content="summary_large_image">
  <meta property="twitter:url" content="https://monitorlegislativo.gov.br/api/docs">
  <meta property="twitter:title" content="', title, '">
  <meta property="twitter:description" content="API REST para acesso programático aos dados legislativos brasileiros">
  <meta property="twitter:image" content="https://monitorlegislativo.gov.br/assets/og-image.png">
  
  <!-- Favicon -->
  <link rel="icon" type="image/x-icon" href="', favicon_url, '">
  <link rel="apple-touch-icon" href="https://monitorlegislativo.gov.br/assets/apple-touch-icon.png">
  
  <!-- Swagger UI CSS -->
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
  
  <!-- Google Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@300;400;600;700&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
  
  <!-- Enhanced Brazilian Government Theme -->
  <style>
    ', enhanced_css, '
  </style>
</head>
<body>
  <!-- Loading Screen -->
  <div id="loading-screen" style="
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: var(--brasil-background, #fafafa);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 10000;
    transition: opacity 0.5s ease;
  ">
    <div class="loading-spinner"></div>
    <p style="margin-top: 1rem; color: var(--brasil-text-secondary, #757575); font-family: \"Source Sans Pro\", sans-serif;">
      Carregando documentação da API...
    </p>
  </div>

  <!-- Main Swagger UI Container -->
  <div id="swagger-ui"></div>

  <!-- Swagger UI JavaScript -->
  <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
  <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
  
  <script>
    // OpenAPI Specification
    const spec = ', openapi_json, ';
    
    // Initialize Swagger UI
    window.onload = function() {
      const ui = SwaggerUIBundle({
        spec: spec,
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIStandalonePreset
        ],
        plugins: [
          SwaggerUIBundle.plugins.DownloadUrl
        ],
        layout: "StandaloneLayout",
        supportedSubmitMethods: ["get", "post", "put", "delete", "patch"],
        showRequestHeaders: true,
        showCommonExtensions: true,
        requestInterceptor: function(request) {
          // Add Brazilian Portuguese language preference
          request.headers["Accept-Language"] = "pt-BR,pt;q=0.9,en;q=0.8";
          
          // Add user agent
          request.headers["User-Agent"] = "Monitor-Legislativo-API-Docs/1.0";
          
          return request;
        },
        responseInterceptor: function(response) {
          // Log rate limiting information
          if (response.headers["x-ratelimit-remaining"]) {
            console.log("Rate Limit Remaining:", response.headers["x-ratelimit-remaining"]);
          }
          
          return response;
        },
        onComplete: function() {
          // Hide loading screen
          const loadingScreen = document.getElementById("loading-screen");
          if (loadingScreen) {
            loadingScreen.style.opacity = "0";
            setTimeout(() => {
              loadingScreen.style.display = "none";
            }, 500);
          }
        },
        docExpansion: "list",
        filter: true,
        showExtensions: true,
        showCommonExtensions: true,
        defaultModelsExpandDepth: 1,
        defaultModelExpandDepth: 1,
        displayOperationId: false,
        displayRequestDuration: true,
        tryItOutEnabled: true,
        requestSnippetsEnabled: true,
        requestSnippets: {
          generators: {
            "curl_bash": {
              title: "cURL (bash)",
              syntax: "bash"
            },
            "javascript_fetch": {
              title: "JavaScript (fetch)",
              syntax: "javascript"
            },
            "python_requests": {
              title: "Python (requests)",
              syntax: "python"
            },
            "r_httr": {
              title: "R (httr)",
              syntax: "r"
            }
          },
          defaultExpanded: true,
          languages: ["curl_bash", "javascript_fetch", "python_requests", "r_httr"]
        }
      });
    };
    
    // Enhanced Brazilian Features JavaScript
    ', enhanced_js, '
  </script>

  <!-- Analytics (if needed) -->
  <script>
    // Brazilian Government Analytics
    if (typeof gtag !== "undefined") {
      gtag("config", "GA_MEASUREMENT_ID", {
        page_title: "API Documentation",
        page_location: window.location.href
      });
    }
  </script>
</body>
</html>
  ')
  
  return(html_content)
}

# Plumber endpoint to serve enhanced Swagger UI
serve_enhanced_swagger_ui <- function() {
  return(generate_enhanced_swagger_html())
}

# Function to create documentation files
create_swagger_documentation_files <- function(output_dir = "documentation") {
  
  # Ensure output directory exists
  if (!dir.exists(output_dir)) {
    dir.create(output_dir, recursive = TRUE)
    cat("📁 Created documentation directory:", output_dir, "\n")
  }
  
  # Generate and save HTML file
  html_content <- generate_enhanced_swagger_html()
  html_file <- file.path(output_dir, "swagger-ui.html")
  writeLines(html_content, html_file)
  cat("📄 Generated Swagger UI HTML:", html_file, "\n")
  
  # Generate standalone CSS file
  css_content <- create_enhanced_swagger_css()
  css_file <- file.path(output_dir, "brazilian-government-theme.css")
  writeLines(css_content, css_file)
  cat("🎨 Generated CSS theme file:", css_file, "\n")
  
  # Generate standalone JavaScript file
  js_content <- create_enhanced_swagger_js()
  js_file <- file.path(output_dir, "brazilian-enhancements.js")
  writeLines(js_content, js_file)
  cat("⚙️ Generated JavaScript enhancements:", js_file, "\n")
  
  return(list(
    html = html_file,
    css = css_file,
    js = js_file
  ))
}

# Export functions for use in plumber API
cat("✅ Enhanced Swagger UI Implementation loaded\n")
cat("📚 Functions available:\n")
cat("  - generate_enhanced_swagger_html(): Generate complete HTML\n")
cat("  - serve_enhanced_swagger_ui(): Plumber endpoint function\n")
cat("  - create_swagger_documentation_files(): Generate all files\n")
cat("  - create_enhanced_swagger_css(): Generate CSS theme\n")
cat("  - create_enhanced_swagger_js(): Generate JavaScript enhancements\n")