# ============================================================================
# USER REGISTRATION & ACADEMIC VERIFICATION - SPRINT 6B (API-002)
# ============================================================================
# 
# Complete user registration and academic verification workflow
# Handles user onboarding, email verification, academic institution validation,
# and API key provisioning for the Brazilian Legislative API
# 
# Features:
# - Secure user registration with email verification
# - Academic institution verification system
# - Automated API key provisioning based on verification
# - LGPD-compliant data collection and consent management
# - Integration with Brazilian academic databases
# - Document verification for academic researchers
# - Multi-step verification workflow
# - Email templates and notifications
# ============================================================================

cat("👤 Loading User Registration & Academic Verification System\n")

# Source required authentication modules
if (file.exists("api/auth/authentication_system.R")) {
  source("api/auth/authentication_system.R")
}
if (file.exists("api/auth/api_key_management.R")) {
  source("api/auth/api_key_management.R")
}

# User Registration Configuration
REGISTRATION_CONFIG <- list(
  # Email verification
  email_verification_required = TRUE,
  email_verification_expiry_hours = 24,
  max_verification_attempts = 3,
  
  # Academic verification
  academic_verification_methods = c("email_domain", "document_upload", "manual_review"),
  auto_approve_domains = TRUE,
  manual_review_required_domains = c("gmail.com", "yahoo.com", "hotmail.com", "outlook.com"),
  
  # Institution verification
  trusted_academic_domains = c(
    # Federal Universities
    "usp.br", "unicamp.br", "ufrj.br", "ufmg.br", "ufrs.br", "ufsc.br",
    "ufpe.br", "ufba.br", "ufpr.br", "ufrgs.br", "uff.br", "unb.br",
    "ufabc.br", "unifesp.br", "ufrn.br", "ufpb.br", "ufs.br", "ufal.br",
    
    # State Universities
    "unesp.br", "unicentro.br", "uem.br", "uel.br", "uepg.br",
    
    # Private Universities
    "puc-rio.br", "pucrs.br", "pucpr.br", "pucsp.br", "fgv.br",
    "mackenzie.br", "uninove.br", "anhembi.br",
    
    # Research Institutions
    "cnpq.br", "capes.gov.br", "fapesp.br", "inpe.br", "lnls.br",
    
    # International (common research partners)
    "edu", "ac.uk", "ox.ac.uk", "cam.ac.uk", "mit.edu", "harvard.edu",
    "stanford.edu", "berkeley.edu", "columbia.edu", "yale.edu"
  ),
  
  # Document verification
  accepted_document_types = c("academic_id", "student_id", "faculty_letter", "enrollment_certificate"),
  max_document_size_mb = 10,
  
  # LGPD compliance
  consent_required_fields = c("data_processing", "email_communication", "academic_verification"),
  data_retention_policy = "7 years as per Brazilian academic research requirements",
  
  # Notification settings
  email_templates_enabled = TRUE,
  admin_notification_email = Sys.getenv("ADMIN_EMAIL", "admin@monitorlegislativo.gov.br"),
  
  # Rate limiting for registration
  max_registrations_per_ip_per_hour = 5,
  max_registrations_per_email_per_day = 1
)

# Database schema for user registration
USER_REGISTRATION_SCHEMA <- "
-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    email_verification_expires_at TIMESTAMP,
    email_verification_attempts INTEGER DEFAULT 0,
    
    -- Personal information
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    title VARCHAR(50), -- Dr, Prof, Student, etc.
    
    -- Institution information
    institution_name VARCHAR(255),
    institution_country VARCHAR(100) DEFAULT 'Brazil',
    department VARCHAR(255),
    position VARCHAR(100), -- Professor, Student, Researcher, etc.
    
    -- Academic verification
    academic_status VARCHAR(20) DEFAULT 'pending', -- pending, verified, rejected, manual_review
    verification_method VARCHAR(50),
    verification_documents JSONB DEFAULT '[]',
    verified_at TIMESTAMP,
    verified_by VARCHAR(100),
    
    -- Research information
    research_field VARCHAR(255),
    research_description TEXT,
    intended_use TEXT,
    
    -- Account status
    status VARCHAR(20) DEFAULT 'active', -- active, suspended, deleted
    tier VARCHAR(20) DEFAULT 'demo', -- demo, academic, premium
    
    -- LGPD compliance
    consent_data_processing BOOLEAN DEFAULT FALSE,
    consent_email_communication BOOLEAN DEFAULT FALSE,
    consent_academic_verification BOOLEAN DEFAULT FALSE,
    consent_given_at TIMESTAMP,
    data_retention_until TIMESTAMP,
    
    -- Security
    password_hash VARCHAR(255),
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login_at TIMESTAMP,
    last_login_ip INET,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by_ip INET,
    notes TEXT,
    tags JSONB DEFAULT '[]'
);

-- Academic institutions reference table
CREATE TABLE IF NOT EXISTS academic_institutions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE,
    country VARCHAR(100) DEFAULT 'Brazil',
    type VARCHAR(50), -- university, research_institute, government, etc.
    auto_approve BOOLEAN DEFAULT FALSE,
    verification_required BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User verification documents
CREATE TABLE IF NOT EXISTS user_verification_documents (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    document_type VARCHAR(50) NOT NULL,
    original_filename VARCHAR(255),
    stored_filename VARCHAR(255),
    file_size_bytes INTEGER,
    mime_type VARCHAR(100),
    upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verification_status VARCHAR(20) DEFAULT 'pending', -- pending, approved, rejected
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP,
    review_notes TEXT
);

-- Registration attempts (for rate limiting and security)
CREATE TABLE IF NOT EXISTS registration_attempts (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    ip_address INET,
    attempt_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN DEFAULT FALSE,
    error_message TEXT,
    user_agent TEXT
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_academic_status ON users(academic_status);
CREATE INDEX IF NOT EXISTS idx_institutions_domain ON academic_institutions(domain);
CREATE INDEX IF NOT EXISTS idx_verification_docs_user_id ON user_verification_documents(user_id);
CREATE INDEX IF NOT EXISTS idx_registration_attempts_ip ON registration_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_registration_attempts_timestamp ON registration_attempts(attempt_timestamp);

-- Insert default academic institutions
INSERT INTO academic_institutions (name, domain, auto_approve, verification_required) VALUES
('Universidade de São Paulo', 'usp.br', TRUE, FALSE),
('Universidade Estadual de Campinas', 'unicamp.br', TRUE, FALSE),
('Universidade Federal do Rio de Janeiro', 'ufrj.br', TRUE, FALSE),
('Universidade Federal de Minas Gerais', 'ufmg.br', TRUE, FALSE),
('Universidade Federal do Rio Grande do Sul', 'ufrgs.br', TRUE, FALSE),
('Pontifícia Universidade Católica do Rio de Janeiro', 'puc-rio.br', TRUE, FALSE),
('Fundação Getúlio Vargas', 'fgv.br', TRUE, FALSE),
('Universidade Presbiteriana Mackenzie', 'mackenzie.br', TRUE, FALSE)
ON CONFLICT (domain) DO NOTHING;
"

# User Registration Function
register_user <- function(registration_data, client_ip = NULL) {
  # Validate required fields
  required_fields <- c("email", "first_name", "last_name", "institution_name", "intended_use")
  missing_fields <- setdiff(required_fields, names(registration_data))
  
  if (length(missing_fields) > 0) {
    return(list(
      success = FALSE,
      error = paste("Missing required fields:", paste(missing_fields, collapse = ", "))
    ))
  }
  
  # Validate email format
  if (!grepl("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", registration_data$email)) {
    return(list(success = FALSE, error = "Invalid email format"))
  }
  
  # Check rate limiting
  if (!check_registration_rate_limit(registration_data$email, client_ip)) {
    return(list(success = FALSE, error = "Registration rate limit exceeded"))
  }
  
  # Check LGPD consent
  if (!all(registration_data[REGISTRATION_CONFIG$consent_required_fields] == TRUE)) {
    return(list(success = FALSE, error = "All required consents must be given for LGPD compliance"))
  }
  
  email <- tolower(registration_data$email)
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      # Check if user already exists
      existing_user <- DBI::dbGetQuery(secure_db_pool,
        "SELECT id, email_verified, academic_status FROM users WHERE email = $1",
        params = list(email))
      
      if (nrow(existing_user) > 0) {
        return(list(success = FALSE, error = "User with this email already exists"))
      }
      
      # Determine academic verification method
      email_domain <- strsplit(email, "@")[[1]][2]
      verification_method <- determine_verification_method(email_domain)
      academic_status <- if (verification_method == "auto_approve") "verified" else "pending"
      
      # Generate email verification token
      verification_token <- generate_verification_token()
      verification_expires <- Sys.time() + (REGISTRATION_CONFIG$email_verification_expiry_hours * 3600)
      
      # Calculate data retention date
      data_retention_until <- Sys.time() + (AUTH_CONFIG$lgpd$data_retention_days * 24 * 3600)
      
      # Hash password if provided
      password_hash <- NULL
      if (!is.null(registration_data$password)) {
        password_hash <- hash_password(registration_data$password)
      }
      
      # Insert user
      insert_query <- "
        INSERT INTO users (
          email, first_name, last_name, title, institution_name, 
          institution_country, department, position, research_field, 
          research_description, intended_use, academic_status, 
          verification_method, email_verification_token, 
          email_verification_expires_at, consent_data_processing, 
          consent_email_communication, consent_academic_verification, 
          consent_given_at, data_retention_until, password_hash, 
          created_by_ip
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 
          $16, $17, $18, $19, $20, $21, $22
        ) RETURNING id, created_at
      "
      
      result <- DBI::dbGetQuery(secure_db_pool, insert_query, params = list(
        email,
        registration_data$first_name,
        registration_data$last_name,
        registration_data$title %||% "",
        registration_data$institution_name,
        registration_data$institution_country %||% "Brazil",
        registration_data$department %||% "",
        registration_data$position %||% "",
        registration_data$research_field %||% "",
        registration_data$research_description %||% "",
        registration_data$intended_use,
        academic_status,
        verification_method,
        verification_token,
        verification_expires,
        registration_data$consent_data_processing,
        registration_data$consent_email_communication,
        registration_data$consent_academic_verification,
        Sys.time(),
        data_retention_until,
        password_hash,
        client_ip
      ))
      
      if (nrow(result) > 0) {
        user_id <- result$id[1]
        
        # Log registration attempt
        log_registration_attempt(email, client_ip, TRUE, "User registered successfully")
        
        # Send verification email
        if (REGISTRATION_CONFIG$email_verification_required) {
          send_verification_email(email, verification_token, registration_data$first_name)
        }
        
        # Auto-create API key if academic verification is automatic
        api_key_result <- NULL
        if (academic_status == "verified") {
          api_key_result <- create_api_key(
            user_id = user_id,
            tier = "academic",
            purpose = "Academic research access"
          )
        }
        
        # Log for LGPD compliance
        log_data_access(user_id, "registration", "user_registration", "API access registration", "consent")
        
        return(list(
          success = TRUE,
          user_id = user_id,
          email = email,
          academic_status = academic_status,
          verification_method = verification_method,
          email_verification_required = REGISTRATION_CONFIG$email_verification_required,
          api_key = if (!is.null(api_key_result) && api_key_result$success) api_key_result$api_key else NULL,
          message = "User registered successfully"
        ))
        
      } else {
        return(list(success = FALSE, error = "Failed to create user account"))
      }
      
    } else {
      return(list(success = FALSE, error = "Database connection not available"))
    }
    
  }, error = function(e) {
    log_registration_attempt(email, client_ip, FALSE, e$message)
    return(list(success = FALSE, error = paste("Registration error:", e$message)))
  })
}

# Email Verification
verify_email <- function(email, verification_token) {
  email <- tolower(email)
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      # Check token validity
      user_query <- "
        SELECT id, email_verification_attempts, email_verification_expires_at 
        FROM users 
        WHERE email = $1 AND email_verification_token = $2 AND email_verified = FALSE
      "
      
      user_result <- DBI::dbGetQuery(secure_db_pool, user_query, params = list(email, verification_token))
      
      if (nrow(user_result) == 0) {
        return(list(success = FALSE, error = "Invalid verification token or email already verified"))
      }
      
      user_data <- user_result[1, ]
      
      # Check expiration
      if (user_data$email_verification_expires_at < Sys.time()) {
        return(list(success = FALSE, error = "Verification token has expired"))
      }
      
      # Check attempt limits
      if (user_data$email_verification_attempts >= REGISTRATION_CONFIG$max_verification_attempts) {
        return(list(success = FALSE, error = "Maximum verification attempts exceeded"))
      }
      
      # Update user as verified
      update_query <- "
        UPDATE users 
        SET email_verified = TRUE, 
            email_verification_token = NULL,
            email_verification_expires_at = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $1
      "
      
      DBI::dbExecute(secure_db_pool, update_query, params = list(user_data$id))
      
      # Create API key if academic status allows
      api_key_result <- NULL
      user_info <- get_user_by_id(user_data$id)
      if (user_info$academic_status == "verified") {
        api_key_result <- create_api_key(
          user_id = user_data$id,
          tier = "academic",
          purpose = "Email verification completed"
        )
      }
      
      return(list(
        success = TRUE,
        message = "Email verified successfully",
        api_key = if (!is.null(api_key_result) && api_key_result$success) api_key_result$api_key else NULL
      ))
      
    } else {
      return(list(success = FALSE, error = "Database connection not available"))
    }
    
  }, error = function(e) {
    return(list(success = FALSE, error = paste("Verification error:", e$message)))
  })
}

# Academic Verification Review
review_academic_verification <- function(user_id, status, reviewer_notes = "", reviewer_id = "admin") {
  if (!status %in% c("verified", "rejected")) {
    return(list(success = FALSE, error = "Invalid verification status"))
  }
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      # Update user academic status
      update_query <- "
        UPDATE users 
        SET academic_status = $1,
            verified_at = CASE WHEN $1 = 'verified' THEN CURRENT_TIMESTAMP ELSE NULL END,
            verified_by = $2,
            tier = CASE WHEN $1 = 'verified' THEN 'academic' ELSE 'demo' END,
            notes = CONCAT(COALESCE(notes, ''), ' | Academic review: ', $3, ' at ', CURRENT_TIMESTAMP),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = $4
      "
      
      rows_affected <- DBI::dbExecute(secure_db_pool, update_query, params = list(
        status, reviewer_id, reviewer_notes, user_id
      ))
      
      if (rows_affected > 0) {
        # Create API key if verified
        api_key_result <- NULL
        if (status == "verified") {
          api_key_result <- create_api_key(
            user_id = user_id,
            tier = "academic",
            purpose = "Academic verification approved"
          )
        }
        
        # Send notification email
        user_info <- get_user_by_id(user_id)
        send_verification_result_email(user_info$email, status, user_info$first_name, api_key_result)
        
        return(list(
          success = TRUE,
          status = status,
          api_key = if (!is.null(api_key_result) && api_key_result$success) api_key_result$api_key else NULL,
          message = paste("Academic verification", status)
        ))
        
      } else {
        return(list(success = FALSE, error = "User not found"))
      }
      
    } else {
      return(list(success = FALSE, error = "Database connection not available"))
    }
    
  }, error = function(e) {
    return(list(success = FALSE, error = paste("Review error:", e$message)))
  })
}

# Helper Functions
determine_verification_method <- function(email_domain) {
  if (email_domain %in% REGISTRATION_CONFIG$trusted_academic_domains) {
    return("auto_approve")
  } else if (email_domain %in% REGISTRATION_CONFIG$manual_review_required_domains) {
    return("manual_review")
  } else {
    # Check if it's an academic domain pattern
    academic_patterns <- c("\\.edu$", "\\.ac\\.", "\\.edu\\.")
    if (any(sapply(academic_patterns, function(pattern) grepl(pattern, email_domain)))) {
      return("document_verification")
    } else {
      return("manual_review")
    }
  }
}

generate_verification_token <- function() {
  return(paste0(
    sample(c(letters, LETTERS, 0:9), 32, replace = TRUE),
    collapse = ""
  ))
}

check_registration_rate_limit <- function(email, client_ip) {
  if (is.null(client_ip)) return(TRUE)
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      # Check IP rate limit
      ip_count <- DBI::dbGetQuery(secure_db_pool,
        "SELECT COUNT(*) as count FROM registration_attempts 
         WHERE ip_address = $1 AND attempt_timestamp > CURRENT_TIMESTAMP - INTERVAL '1 hour'",
        params = list(client_ip))
      
      if (ip_count$count[1] >= REGISTRATION_CONFIG$max_registrations_per_ip_per_hour) {
        return(FALSE)
      }
      
      # Check email rate limit
      email_count <- DBI::dbGetQuery(secure_db_pool,
        "SELECT COUNT(*) as count FROM registration_attempts 
         WHERE email = $1 AND attempt_timestamp > CURRENT_TIMESTAMP - INTERVAL '1 day'",
        params = list(email))
      
      if (email_count$count[1] >= REGISTRATION_CONFIG$max_registrations_per_email_per_day) {
        return(FALSE)
      }
    }
    
    return(TRUE)
    
  }, error = function(e) {
    return(TRUE) # Allow on error
  })
}

log_registration_attempt <- function(email, client_ip, success, message) {
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      DBI::dbExecute(secure_db_pool,
        "INSERT INTO registration_attempts (email, ip_address, success, error_message, user_agent) 
         VALUES ($1, $2, $3, $4, $5)",
        params = list(
          email, 
          client_ip, 
          success, 
          message,
          Sys.getenv("HTTP_USER_AGENT", "unknown")
        ))
    }
  }, error = function(e) {
    cat("Warning: Failed to log registration attempt:", e$message, "\n")
  })
}

get_user_by_id <- function(user_id) {
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    result <- DBI::dbGetQuery(secure_db_pool,
      "SELECT * FROM users WHERE id = $1",
      params = list(user_id))
    
    if (nrow(result) > 0) {
      return(result[1, ])
    }
  }
  return(NULL)
}

# Email Templates (placeholder - in production, use proper email service)
send_verification_email <- function(email, token, first_name) {
  cat("📧 Sending verification email to:", email, "\n")
  cat("   Token:", token, "\n")
  cat("   Verify at: /api/v1/auth/verify-email?email=", email, "&token=", token, "\n")
}

send_verification_result_email <- function(email, status, first_name, api_key_result) {
  cat("📧 Sending verification result email to:", email, "\n")
  cat("   Status:", status, "\n")
  if (!is.null(api_key_result) && api_key_result$success) {
    cat("   API Key provided:", substr(api_key_result$api_key, 1, 10), "...\n")
  }
}

# Initialize database schema
initialize_user_registration_db <- function() {
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    tryCatch({
      DBI::dbExecute(secure_db_pool, USER_REGISTRATION_SCHEMA)
      cat("✅ User registration database schema initialized\n")
      return(TRUE)
    }, error = function(e) {
      cat("⚠️ Failed to initialize user registration schema:", e$message, "\n")
      return(FALSE)
    })
  } else {
    cat("⚠️ Database connection not available for user registration\n")
    return(FALSE)
  }
}

# Auto-initialize
initialize_user_registration_db()

cat("✅ User Registration & Academic Verification System Loaded\n")