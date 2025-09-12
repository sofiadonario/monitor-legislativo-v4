# ============================================================================
# AUTHENTICATION SYSTEM INTEGRATION LOADER - SPRINT 6B (API-002)
# ============================================================================
# 
# Master integration script that loads and initializes the complete
# authentication framework for the Brazilian Legislative API
# 
# This script should be sourced by the main API to enable all authentication
# features including multi-tier API keys, user management, and LGPD compliance
# ============================================================================

cat("🚀 Loading Complete Authentication System Integration - Sprint 6B (API-002)\n")
cat("🔐 Brazilian Legislative API - Comprehensive Authentication Framework\n\n")

# Authentication System Components
AUTH_COMPONENTS <- list(
  core = "api/auth/authentication_system.R",
  key_management = "api/auth/api_key_management.R",
  user_registration = "api/auth/user_registration.R",
  middleware = "api/auth/middleware_integration.R",
  rate_limiting = "api/auth/rate_limiting_system.R",
  lgpd_compliance = "api/auth/lgpd_compliance_security.R",
  admin_panel = "api/admin/auth_admin_panel.R"
)

# Load Authentication Components
load_auth_components <- function() {
  loaded_components <- c()
  failed_components <- c()
  
  for (component_name in names(AUTH_COMPONENTS)) {
    component_path <- AUTH_COMPONENTS[[component_name]]
    
    cat("📦 Loading", component_name, "component...")
    
    if (file.exists(component_path)) {
      tryCatch({
        source(component_path)
        loaded_components <- c(loaded_components, component_name)
        cat(" ✅\n")
      }, error = function(e) {
        failed_components <- c(failed_components, component_name)
        cat(" ❌ Error:", e$message, "\n")
      })
    } else {
      failed_components <- c(failed_components, component_name)
      cat(" ❌ File not found\n")
    }
  }
  
  return(list(
    loaded = loaded_components,
    failed = failed_components,
    success = length(failed_components) == 0
  ))
}

# Initialize Database Schema
initialize_auth_database <- function() {
  cat("🗄️ Initializing authentication database schema...\n")
  
  if (!exists("secure_db_pool") || is.null(secure_db_pool)) {
    cat("⚠️ Database connection not available - schema initialization skipped\n")
    return(FALSE)
  }
  
  schema_file <- "db/auth_schema.sql"
  
  if (file.exists(schema_file)) {
    tryCatch({
      schema_content <- readLines(schema_file, warn = FALSE)
      schema_sql <- paste(schema_content, collapse = "\n")
      
      # Execute schema in chunks to handle large SQL files
      statements <- strsplit(schema_sql, ";")[[1]]
      
      for (statement in statements) {
        statement <- trimws(statement)
        if (nchar(statement) > 0 && !startsWith(statement, "--")) {
          DBI::dbExecute(secure_db_pool, statement)
        }
      }
      
      cat("✅ Authentication database schema initialized successfully\n")
      return(TRUE)
      
    }, error = function(e) {
      cat("❌ Failed to initialize database schema:", e$message, "\n")
      return(FALSE)
    })
  } else {
    cat("⚠️ Database schema file not found:", schema_file, "\n")
    return(FALSE)
  }
}

# Create Default Admin User
create_default_admin <- function() {
  cat("👨‍💼 Creating default admin user...\n")
  
  # Check if admin user already exists
  admin_email <- "admin@monitorlegislativo.gov.br"
  
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    tryCatch({
      existing_admin <- DBI::dbGetQuery(secure_db_pool,
        "SELECT id FROM users WHERE email = $1",
        list(admin_email))
      
      if (nrow(existing_admin) > 0) {
        cat("ℹ️ Admin user already exists\n")
        return(TRUE)
      }
      
      # Create admin user
      admin_data <- list(
        email = admin_email,
        first_name = "System",
        last_name = "Administrator",
        institution_name = "Monitor Legislativo",
        intended_use = "System administration and management",
        consent_data_processing = TRUE,
        consent_email_communication = TRUE,
        consent_academic_verification = TRUE
      )
      
      registration_result <- register_user(admin_data, "127.0.0.1")
      
      if (registration_result$success) {
        # Upgrade to admin tier
        DBI::dbExecute(secure_db_pool,
          "UPDATE users SET tier = 'premium', academic_status = 'verified', status = 'active' WHERE email = $1",
          list(admin_email))
        
        cat("✅ Default admin user created successfully\n")
        cat("📧 Admin email:", admin_email, "\n")
        return(TRUE)
      } else {
        cat("❌ Failed to create admin user:", registration_result$error, "\n")
        return(FALSE)
      }
      
    }, error = function(e) {
      cat("❌ Error creating admin user:", e$message, "\n")
      return(FALSE)
    })
  } else {
    cat("⚠️ Database not available for admin user creation\n")
    return(FALSE)
  }
}

# Validate System Configuration
validate_auth_system <- function() {
  cat("🔍 Validating authentication system configuration...\n")
  
  validation_results <- list()
  
  # Check core functions exist
  core_functions <- c(
    "generate_api_key", "validate_api_key_from_db", "register_user",
    "enhanced_auth_filter", "RateLimitEngine", "log_lgpd_event"
  )
  
  for (func_name in core_functions) {
    if (exists(func_name)) {
      validation_results[[func_name]] <- "✅ Available"
    } else {
      validation_results[[func_name]] <- "❌ Missing"
    }
  }
  
  # Check configuration objects
  config_objects <- c("AUTH_CONFIG", "MIDDLEWARE_CONFIG", "LGPD_CONFIG", "SECURITY_CONFIG")
  
  for (config_name in config_objects) {
    if (exists(config_name)) {
      validation_results[[config_name]] <- "✅ Configured"
    } else {
      validation_results[[config_name]] <- "❌ Missing"
    }
  }
  
  # Print validation results
  for (item in names(validation_results)) {
    cat("  ", item, ":", validation_results[[item]], "\n")
  }
  
  # Count failures
  failures <- sum(grepl("❌", validation_results))
  
  if (failures == 0) {
    cat("✅ All authentication system components validated successfully\n")
    return(TRUE)
  } else {
    cat("❌", failures, "validation failures detected\n")
    return(FALSE)
  }
}

# Main Integration Function
integrate_authentication_system <- function() {
  cat("=" %+% rep("=", 70) %+% "\n")
  cat("🔐 INTEGRATING AUTHENTICATION FRAMEWORK - SPRINT 6B (API-002)\n")
  cat("=" %+% rep("=", 70) %+% "\n\n")
  
  # Step 1: Load all authentication components
  component_result <- load_auth_components()
  
  if (!component_result$success) {
    cat("❌ Failed to load authentication components\n")
    cat("Failed components:", paste(component_result$failed, collapse = ", "), "\n")
    return(FALSE)
  }
  
  cat("✅ All authentication components loaded successfully\n")
  cat("Loaded:", paste(component_result$loaded, collapse = ", "), "\n\n")
  
  # Step 2: Initialize database schema
  db_result <- initialize_auth_database()
  
  if (!db_result) {
    cat("⚠️ Database schema initialization failed - continuing with limited functionality\n")
  }
  
  # Step 3: Create default admin user
  admin_result <- create_default_admin()
  
  if (!admin_result) {
    cat("⚠️ Admin user creation failed - manual setup may be required\n")
  }
  
  # Step 4: Validate system configuration
  validation_result <- validate_auth_system()
  
  if (!validation_result) {
    cat("⚠️ System validation detected issues - some features may not work correctly\n")
  }
  
  # Step 5: Display system status
  display_system_status()
  
  cat("\n" %+% "=" %+% rep("=", 70) %+% "\n")
  cat("🎉 AUTHENTICATION FRAMEWORK INTEGRATION COMPLETE\n")
  cat("=" %+% rep("=", 70) %+% "\n")
  
  return(TRUE)
}

# Display System Status
display_system_status <- function() {
  cat("\n📊 AUTHENTICATION SYSTEM STATUS\n")
  cat("-" %+% rep("-", 40) %+% "\n")
  
  # Tier configurations
  cat("🎯 Available API Tiers:\n")
  if (exists("AUTH_CONFIG")) {
    for (tier in names(AUTH_CONFIG$tiers)) {
      tier_config <- AUTH_CONFIG$tiers[[tier]]
      cat("  •", tier_config$name, "\n")
      cat("    - Requests/hour:", tier_config$requests_per_hour, "\n")
      cat("    - Requests/day:", tier_config$requests_per_day, "\n")
      cat("    - Endpoints:", paste(tier_config$allowed_endpoints, collapse = ", "), "\n")
    }
  }
  
  # Security features
  cat("\n🛡️ Security Features:\n")
  cat("  • Multi-tier API key authentication\n")
  cat("  • JWT token support\n")
  cat("  • Advanced rate limiting\n")
  cat("  • Academic institution verification\n")
  cat("  • LGPD compliance framework\n")
  cat("  • Security event monitoring\n")
  cat("  • Administrative interface\n")
  
  # Database status
  cat("\n🗄️ Database Status:\n")
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    tryCatch({
      test_query <- DBI::dbGetQuery(secure_db_pool, "SELECT 1 as test")
      cat("  • Database connection: ✅ Active\n")
      
      # Check if auth tables exist
      tables_query <- "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_name IN ('users', 'api_keys', 'academic_institutions')"
      auth_tables <- DBI::dbGetQuery(secure_db_pool, tables_query)
      cat("  • Authentication tables:", nrow(auth_tables), "of 3 present\n")
      
    }, error = function(e) {
      cat("  • Database connection: ❌ Error\n")
    })
  } else {
    cat("  • Database connection: ❌ Not available\n")
  }
  
  # API endpoints
  cat("\n🔗 Authentication Endpoints:\n")
  cat("  • POST /api/v1/auth/register - User registration\n")
  cat("  • POST /api/v1/auth/login - User authentication\n")
  cat("  • GET  /api/v1/auth/profile - User profile\n")
  cat("  • POST /api/v1/auth/api-key - Generate API key\n")
  cat("  • GET  /admin/users - User management (admin)\n")
  cat("  • GET  /admin/api-keys - API key management (admin)\n")
  cat("  • GET  /admin/analytics/dashboard - Usage analytics (admin)\n")
}

# String concatenation helper
`%+%` <- function(a, b) paste0(a, b)

# Export main integration function
if (!exists("AUTHENTICATION_INTEGRATED", envir = .GlobalEnv)) {
  result <- integrate_authentication_system()
  assign("AUTHENTICATION_INTEGRATED", result, envir = .GlobalEnv)
}

cat("✅ Authentication System Integration Loader Complete\n")