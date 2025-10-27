# ============================================================================
# BRAZILIAN INSTITUTION DOMAIN WHITELIST - SPRINT 6B (API-004)
# ============================================================================
# 
# Comprehensive domain whitelist management for Brazilian academic institutions,
# government agencies, and research organizations. Supports dynamic domain
# validation, institutional verification, and CORS integration.
# 
# Features:
# - Brazilian academic institution domain database
# - Government agency domain recognition
# - Research institute and think tank domains
# - International academic collaborators
# - Dynamic domain validation and verification
# - Institutional metadata and classification
# - LGPD-compliant domain management
# - Academic tier verification system
# ============================================================================

cat("🏛️ Loading Brazilian Institution Domain Whitelist\n")

# Brazilian Academic Domains Database
BRAZILIAN_ACADEMIC_DOMAINS <- list(
  # Major Public Universities
  universities = c(
    # São Paulo
    "usp.br", "unicamp.br", "unesp.br",
    "unifesp.br", "ufabc.br", "ufscar.br",
    
    # Rio de Janeiro
    "ufrj.br", "uff.br", "uerj.br", "unirio.br",
    
    # Minas Gerais
    "ufmg.br", "ufv.br", "ufu.br", "ufop.br", "ufjf.br",
    
    # Rio Grande do Sul
    "ufrgs.br", "ufsm.br", "furg.br", "unipampa.br",
    
    # Paraná
    "ufpr.br", "uel.br", "uem.br", "utfpr.br",
    
    # Santa Catarina
    "ufsc.br", "udesc.br", "unochapeco.br",
    
    # Bahia
    "ufba.br", "uefs.br", "uesc.br",
    
    # Pernambuco
    "ufpe.br", "ufrpe.br", "univasf.br",
    
    # Ceará
    "ufc.br", "uece.br",
    
    # Distrito Federal
    "unb.br",
    
    # Goiás
    "ufg.br", "puc-goias.edu.br",
    
    # Mato Grosso
    "ufmt.br",
    
    # Amazonas
    "ufam.br",
    
    # Pará
    "ufpa.br",
    
    # Major Private Universities
    "puc-rio.br", "puc-sp.br", "pucrs.br", "pucpr.br",
    "mackenzie.br", "fgv.br", "insper.edu.br",
    "fmu.br", "uninove.br", "anhembi.br",
    
    # Technology and Engineering Institutes
    "ita.br", "ime.eb.mil.br", "cefetmg.br",
    "ifsp.edu.br", "ifsul.edu.br", "ifrs.edu.br"
  ),
  
  # Research Institutes and Think Tanks
  research_institutes = c(
    # National Research Institutes
    "inpe.br", # Space Research
    "lnls.br", # Synchrotron Light
    "cbpf.br", # Brazilian Center for Physics Research
    "impa.br", # Pure and Applied Mathematics
    "cprm.gov.br", # Geological Service
    "inmetro.gov.br", # Metrology
    "inct.cnpq.br", # National Institutes of Science and Technology
    
    # EMBRAPA (Agricultural Research)
    "embrapa.br",
    
    # Fiocruz (Health Research)
    "fiocruz.br",
    
    # Think Tanks and Policy Research
    "ipea.gov.br", # Economic Research
    "ibge.gov.br", # Geography and Statistics
    "dnpm.gov.br", # Mining Research
    "anp.gov.br", # Oil and Gas Research
    
    # Technology Research Centers
    "cti.gov.br", # Information Technology
    "cetene.gov.br", # Nanotechnology
    "cetem.gov.br", # Technology Research
    
    # Regional Research Centers
    "fundaj.gov.br", # Joaquim Nabuco Foundation
    "museu-goeldi.br" # Pará Research
  ),
  
  # Government Education Agencies
  government_education = c(
    "mec.gov.br", # Ministry of Education
    "capes.gov.br", # Higher Education Personnel
    "cnpq.br", # Scientific Development
    "finep.gov.br", # Studies and Projects Financing
    "faperj.br", "fapesp.br", "fapemig.br", "fapergs.br", # State Research Foundations
    "inep.gov.br", # Educational Studies and Research
    "ifs.edu.br", "ifb.edu.br" # Federal Institutes
  )
)

# Brazilian Government Domains
BRAZILIAN_GOVERNMENT_DOMAINS <- c(
  # Federal Government
  "gov.br", "planalto.gov.br", "presidencia.gov.br",
  
  # Legislative Branch
  "senado.gov.br", "camara.gov.br", "congressonacional.gov.br",
  "senado.leg.br", "camara.leg.br",
  
  # Judicial Branch
  "stf.jus.br", "stj.jus.br", "tse.jus.br", "tcu.gov.br",
  "tjsp.jus.br", "tjrj.jus.br", "tjmg.jus.br", "tjrs.jus.br",
  
  # Ministries
  "fazenda.gov.br", "saude.gov.br", "educacao.gov.br",
  "justica.gov.br", "defesa.gov.br", "agricultura.gov.br",
  
  # Regulatory Agencies
  "anatel.gov.br", "anvisa.gov.br", "aneel.gov.br",
  "ans.gov.br", "antt.gov.br", "antaq.gov.br",
  
  # State Governments (examples)
  "sp.gov.br", "rj.gov.br", "mg.gov.br", "rs.gov.br",
  "pr.gov.br", "sc.gov.br", "ba.gov.br"
)

# International Academic Collaborators (pre-approved)
INTERNATIONAL_ACADEMIC_DOMAINS <- c(
  # Major US Universities
  "harvard.edu", "mit.edu", "stanford.edu", "berkeley.edu",
  "yale.edu", "princeton.edu", "columbia.edu", "uchicago.edu",
  
  # UK Universities
  "ox.ac.uk", "cam.ac.uk", "imperial.ac.uk", "ucl.ac.uk",
  "kcl.ac.uk", "lse.ac.uk",
  
  # European Universities
  "sorbonne-universite.fr", "univ-paris1.fr",
  "ethz.ch", "epfl.ch", # Switzerland
  "ku.dk", "dtu.dk", # Denmark
  "uva.nl", "vu.nl", # Netherlands
  
  # Latin American Partners
  "uchile.cl", "uc.cl", # Chile
  "unal.edu.co", "javeriana.edu.co", # Colombia
  "unam.mx", "itam.mx", # Mexico
  "uba.ar", "unlp.edu.ar", # Argentina
  
  # International Organizations
  "worldbank.org", "iadb.org", "oecd.org",
  "un.org", "unesco.org"
)

# Domain Classification and Metadata
DOMAIN_METADATA <- list(
  # Classification types
  classifications = list(
    "public_university" = "Brazilian Public University",
    "private_university" = "Brazilian Private University",
    "research_institute" = "Research Institute or Laboratory",
    "government_agency" = "Government Agency or Ministry",
    "regulatory_body" = "Regulatory Agency",
    "international_academic" = "International Academic Institution",
    "think_tank" = "Policy Research Organization"
  ),
  
  # Access levels
  access_levels = list(
    "full" = "Full API access with all endpoints",
    "academic" = "Academic research access only",
    "government" = "Government institutional access",
    "restricted" = "Restricted access with monitoring"
  ),
  
  # Special privileges
  privileges = list(
    "bulk_export" = "Bulk data export capabilities",
    "real_time_access" = "Real-time data streaming",
    "advanced_analytics" = "Advanced analytics endpoints",
    "priority_support" = "Priority technical support"
  )
)

# Domain Validator and Manager
DomainManager <- list(
  # Validate and classify domain
  validate_domain = function(domain) {
    if (isTRUE(is.null(domain)) || nchar(domain) == 0) {
      return(list(valid = FALSE, error = "Empty domain"))
    }
    
    # Normalize domain (remove www, convert to lowercase)
    normalized_domain <- tolower(gsub("^www\\.", "", domain))
    
    # Check Brazilian universities
    if (normalized_domain %in% BRAZILIAN_ACADEMIC_DOMAINS$universities) {
      return(list(
        valid = TRUE,
        type = "brazilian_university",
        classification = "public_university",
        access_level = "full",
        privileges = c("bulk_export", "advanced_analytics"),
        country = "Brazil",
        domain = normalized_domain
      ))
    }
    
    # Check research institutes
    if (normalized_domain %in% BRAZILIAN_ACADEMIC_DOMAINS$research_institutes) {
      return(list(
        valid = TRUE,
        type = "brazilian_research",
        classification = "research_institute",
        access_level = "full",
        privileges = c("real_time_access", "advanced_analytics"),
        country = "Brazil",
        domain = normalized_domain
      ))
    }
    
    # Check government education agencies
    if (normalized_domain %in% BRAZILIAN_ACADEMIC_DOMAINS$government_education) {
      return(list(
        valid = TRUE,
        type = "government_education",
        classification = "government_agency",
        access_level = "government",
        privileges = c("bulk_export", "real_time_access", "priority_support"),
        country = "Brazil",
        domain = normalized_domain
      ))
    }
    
    # Check government domains
    if (normalized_domain %in% BRAZILIAN_GOVERNMENT_DOMAINS) {
      return(list(
        valid = TRUE,
        type = "brazilian_government",
        classification = "government_agency",
        access_level = "government",
        privileges = c("bulk_export", "real_time_access", "priority_support"),
        country = "Brazil",
        domain = normalized_domain
      ))
    }
    
    # Check for government domain patterns
    if (grepl("\\.gov\\.br$", normalized_domain) || 
        grepl("\\.leg\\.br$", normalized_domain) ||
        grepl("\\.jus\\.br$", normalized_domain)) {
      return(list(
        valid = TRUE,
        type = "brazilian_government_pattern",
        classification = "government_agency",
        access_level = "government",
        privileges = c("bulk_export"),
        country = "Brazil",
        domain = normalized_domain
      ))
    }
    
    # Check international academic domains
    if (normalized_domain %in% INTERNATIONAL_ACADEMIC_DOMAINS) {
      return(list(
        valid = TRUE,
        type = "international_academic",
        classification = "international_academic",
        access_level = "academic",
        privileges = c("advanced_analytics"),
        country = "International",
        domain = normalized_domain
      ))
    }
    
    # Check for Brazilian academic patterns (subdomain matching)
    for (base_domain in BRAZILIAN_ACADEMIC_DOMAINS$universities) {
      if (grepl(paste0("\\.", gsub("\\.", "\\\\.", base_domain), "$"), normalized_domain)) {
        return(list(
          valid = TRUE,
          type = "brazilian_university_subdomain",
          classification = "public_university",
          access_level = "full",
          privileges = c("bulk_export", "advanced_analytics"),
          country = "Brazil",
          domain = normalized_domain,
          base_domain = base_domain
        ))
      }
    }
    
    return(list(
      valid = FALSE,
      error = "Domain not in whitelist",
      domain = normalized_domain
    ))
  },
  
  # Get domain information by type
  get_domains_by_type = function(type) {
    switch(type,
      "university" = BRAZILIAN_ACADEMIC_DOMAINS$universities,
      "research" = BRAZILIAN_ACADEMIC_DOMAINS$research_institutes,
      "government" = BRAZILIAN_GOVERNMENT_DOMAINS,
      "international" = INTERNATIONAL_ACADEMIC_DOMAINS,
      "all" = c(BRAZILIAN_ACADEMIC_DOMAINS$universities,
               BRAZILIAN_ACADEMIC_DOMAINS$research_institutes,
               BRAZILIAN_GOVERNMENT_DOMAINS,
               INTERNATIONAL_ACADEMIC_DOMAINS)
    )
  },
  
  # Add custom domain to user's whitelist
  add_custom_domain = function(api_key_id, domain, justification) {
    if (!exists("secure_db_pool") || isTRUE(is.null(secure_db_pool))) {
      return(list(success = FALSE, error = "Database not available"))
    }
    
    # Validate domain format
    domain_validation <- DomainManager$validate_domain(domain)
    normalized_domain <- tolower(gsub("^www\\.", "", domain))
    
    tryCatch({
      # Check if domain already exists for this API key
      existing_query <- "SELECT id FROM custom_domain_whitelist WHERE api_key_id = $1 AND domain = $2"
      existing <- DBI::dbGetQuery(secure_db_pool, existing_query, list(api_key_id, normalized_domain))
      
      if (nrow(existing) > 0) {
        return(list(success = FALSE, error = "Domain already exists in whitelist"))
      }
      
      # Add domain with pending approval
      DBI::dbExecute(secure_db_pool,
        "INSERT INTO custom_domain_whitelist (api_key_id, domain, justification, approval_status) 
         VALUES ($1, $2, $3, 'pending')",
        list(api_key_id, normalized_domain, justification))
      
      return(list(success = TRUE, message = "Domain added, pending approval"))
      
    }, error = function(e) {
      return(list(success = FALSE, error = paste("Failed to add domain:", e$message)))
    })
  },
  
  # Get custom domains for API key
  get_custom_domains = function(api_key_id) {
    if (!exists("secure_db_pool") || isTRUE(is.null(secure_db_pool))) {
      return(list())
    }
    
    tryCatch({
      query <- "SELECT domain, approval_status, created_at FROM custom_domain_whitelist WHERE api_key_id = $1"
      result <- DBI::dbGetQuery(secure_db_pool, query, list(api_key_id))
      return(result)
      
    }, error = function(e) {
      cat("Warning: Failed to get custom domains:", e$message, "\n")
      return(list())
    })
  },
  
  # Approve custom domain (admin function)
  approve_custom_domain = function(api_key_id, domain, admin_user_id) {
    if (!exists("secure_db_pool") || isTRUE(is.null(secure_db_pool))) {
      return(list(success = FALSE, error = "Database not available"))
    }
    
    tryCatch({
      # Update approval status
      result <- DBI::dbExecute(secure_db_pool,
        "UPDATE custom_domain_whitelist 
         SET approval_status = 'approved', approved_by = $3, approved_at = CURRENT_TIMESTAMP
         WHERE api_key_id = $1 AND domain = $2",
        list(api_key_id, domain, admin_user_id))
      
      if (result > 0) {
        return(list(success = TRUE, message = "Domain approved"))
      } else {
        return(list(success = FALSE, error = "Domain not found"))
      }
      
    }, error = function(e) {
      return(list(success = FALSE, error = paste("Failed to approve domain:", e$message)))
    })
  }
)

# Domain Statistics and Analytics
DomainAnalytics <- list(
  # Get domain usage statistics
  get_domain_usage_stats = function(period_days = 30) {
    if (!exists("secure_db_pool") || isTRUE(is.null(secure_db_pool))) {
      return(list(error = "Database not available"))
    }
    
    tryCatch({
      # Domain usage by type
      domain_usage_query <- "
        SELECT 
          domain_type,
          COUNT(DISTINCT origin) as unique_domains,
          COUNT(*) as total_requests,
          COUNT(DISTINCT api_key_id) as unique_api_keys
        FROM cors_log
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        AND cors_allowed = true
        GROUP BY domain_type
        ORDER BY total_requests DESC
      "
      domain_usage <- DBI::dbGetQuery(secure_db_pool, sprintf(domain_usage_query, period_days))
      
      # Top institutional domains
      top_domains_query <- "
        SELECT 
          origin,
          domain_classification,
          COUNT(*) as requests,
          COUNT(DISTINCT api_key_id) as unique_users
        FROM cors_log
        WHERE timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        AND cors_allowed = true
        AND domain_classification IS NOT NULL
        GROUP BY origin, domain_classification
        ORDER BY requests DESC
        LIMIT 20
      "
      top_domains <- DBI::dbGetQuery(secure_db_pool, sprintf(top_domains_query, period_days))
      
      return(list(
        period_days = period_days,
        domain_usage_by_type = domain_usage,
        top_institutional_domains = top_domains,
        total_whitelisted_domains = length(DomainManager$get_domains_by_type("all"))
      ))
      
    }, error = function(e) {
      return(list(error = paste("Failed to get domain usage statistics:", e$message)))
    })
  },
  
  # Get pending domain approvals (admin function)
  get_pending_approvals = function() {
    if (!exists("secure_db_pool") || isTRUE(is.null(secure_db_pool))) {
      return(list(error = "Database not available"))
    }
    
    tryCatch({
      query <- "
        SELECT 
          cdw.id,
          cdw.api_key_id,
          ak.user_email,
          ak.organization,
          cdw.domain,
          cdw.justification,
          cdw.created_at
        FROM custom_domain_whitelist cdw
        JOIN api_keys ak ON cdw.api_key_id = ak.id
        WHERE cdw.approval_status = 'pending'
        ORDER BY cdw.created_at ASC
      "
      result <- DBI::dbGetQuery(secure_db_pool, query)
      return(result)
      
    }, error = function(e) {
      return(list(error = paste("Failed to get pending approvals:", e$message)))
    })
  }
)

# Initialize domain management system
initialize_domain_management_system <- function() {
  # Ensure required tables exist
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    domain_management_schema <- "
      CREATE TABLE IF NOT EXISTS custom_domain_whitelist (
        id SERIAL PRIMARY KEY,
        api_key_id INTEGER REFERENCES api_keys(id),
        domain VARCHAR(255) NOT NULL,
        justification TEXT,
        approval_status VARCHAR(20) DEFAULT 'pending',
        approved_by INTEGER DEFAULT NULL,
        approved_at TIMESTAMP DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(api_key_id, domain)
      );
      
      CREATE INDEX IF NOT EXISTS idx_custom_domains_api_key ON custom_domain_whitelist(api_key_id);
      CREATE INDEX IF NOT EXISTS idx_custom_domains_status ON custom_domain_whitelist(approval_status);
    "
    
    tryCatch({
      DBI::dbExecute(secure_db_pool, domain_management_schema)
      cat("✅ Domain management tables initialized\n")
    }, error = function(e) {
      cat("⚠️ Failed to initialize domain management tables:", e$message, "\n")
    })
  }
  
  cat("✅ Brazilian Institution Domain Whitelist initialized\n")
  cat("  🏛️", length(BRAZILIAN_ACADEMIC_DOMAINS$universities), "Brazilian universities\n")
  cat("  🔬", length(BRAZILIAN_ACADEMIC_DOMAINS$research_institutes), "research institutes\n")
  cat("  🏛️", length(BRAZILIAN_GOVERNMENT_DOMAINS), "government domains\n")
  cat("  🌍", length(INTERNATIONAL_ACADEMIC_DOMAINS), "international academic partners\n")
  cat("  📊 Domain analytics and approval system active\n")
  
  return(TRUE)
}

# Auto-initialize
initialize_domain_management_system()

cat("✅ Brazilian Institution Domain Whitelist Loaded\n")