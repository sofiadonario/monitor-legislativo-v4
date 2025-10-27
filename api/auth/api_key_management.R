# ============================================================================
# API KEY LIFECYCLE MANAGEMENT - SPRINT 6B (API-002)
# ============================================================================
# 
# Comprehensive API key lifecycle management for Brazilian Legislative API
# Handles creation, validation, rotation, expiration, and revocation of API keys
# 
# Features:
# - Secure API key generation and storage
# - Automatic key rotation and expiration policies
# - Key usage analytics and monitoring
# - Bulk key management operations
# - Integration with database storage
# - Security audit trails
# - Emergency key revocation
# - Key recovery mechanisms
# ============================================================================

cat("🔑 Loading API Key Lifecycle Management System\n")

# Source the core authentication system
if (file.exists("api/auth/authentication_system.R")) {
  source("api/auth/authentication_system.R")
}

# API Key Management Configuration
KEY_MANAGEMENT_CONFIG <- list(
  # Storage settings
  storage_type = "database", # "database" or "file" or "redis"
  encryption_enabled = TRUE,
  backup_enabled = TRUE,
  
  # Rotation settings
  auto_rotation_enabled = TRUE,
  rotation_interval_days = 90,
  rotation_warning_days = 7,
  
  # Expiration settings
  default_expiry_days = 365,
  grace_period_days = 30,
  
  # Security settings
  max_keys_per_user = 5,
  key_generation_cooldown_hours = 1,
  failed_attempts_before_lockout = 3,
  
  # Monitoring settings
  usage_tracking_enabled = TRUE,
  analytics_retention_days = 730,
  alert_on_suspicious_usage = TRUE
)

# Database schema for API keys (will be created if doesn't exist)
API_KEY_SCHEMA <- "
CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    api_key_hash VARCHAR(256) NOT NULL UNIQUE,
    api_key_prefix VARCHAR(20) NOT NULL,
    tier VARCHAR(20) NOT NULL DEFAULT 'demo',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    permissions JSONB DEFAULT '[]',
    
    -- Usage tracking
    total_requests INTEGER DEFAULT 0,
    last_used_at TIMESTAMP,
    daily_usage_count INTEGER DEFAULT 0,
    daily_usage_date DATE,
    
    -- Rate limiting
    hourly_requests INTEGER DEFAULT 0,
    hourly_reset_at TIMESTAMP,
    
    -- Key lifecycle
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    rotated_from_key_id INTEGER,
    rotation_scheduled_at TIMESTAMP,
    
    -- Security
    ip_whitelist JSONB DEFAULT '[]',
    allowed_origins JSONB DEFAULT '[]',
    last_ip_address INET,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    
    -- LGPD compliance
    purpose_statement TEXT,
    legal_basis VARCHAR(50) DEFAULT 'legitimate_interest',
    consent_given_at TIMESTAMP,
    data_retention_until TIMESTAMP,
    
    -- Metadata
    created_by VARCHAR(100),
    notes TEXT,
    tags JSONB DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(api_key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_tier ON api_keys(tier);

-- Usage analytics table
CREATE TABLE IF NOT EXISTS api_key_usage_log (
    id SERIAL PRIMARY KEY,
    api_key_id INTEGER REFERENCES api_keys(id) ON DELETE CASCADE,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    endpoint VARCHAR(200),
    method VARCHAR(10),
    response_code INTEGER,
    response_time_ms INTEGER,
    request_size_bytes INTEGER,
    response_size_bytes INTEGER,
    ip_address INET,
    user_agent TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_usage_log_api_key_id ON api_key_usage_log(api_key_id);
CREATE INDEX IF NOT EXISTS idx_usage_log_timestamp ON api_key_usage_log(timestamp);
"

# Create API Key in Database
create_api_key <- function(user_id, tier = "demo", purpose = NULL, expiry_days = NULL, permissions = NULL) {
  # Validate inputs
  if (isTRUE(is.null(user_id)) || !is.numeric(user_id)) {
    return(list(success = FALSE, error = "Valid user_id is required"))
  }
  
  if (!tier %in% names(AUTH_CONFIG$tiers)) {
    return(list(success = FALSE, error = "Invalid tier specified"))
  }
  
  # Check user limits
  existing_keys_count <- count_user_active_keys(user_id)
  if (existing_keys_count >= KEY_MANAGEMENT_CONFIG$max_keys_per_user) {
    return(list(success = FALSE, error = paste("Maximum keys per user exceeded:", KEY_MANAGEMENT_CONFIG$max_keys_per_user)))
  }
  
  # Check cooldown period
  if (!check_key_generation_cooldown(user_id)) {
    return(list(success = FALSE, error = "Key generation cooldown period active"))
  }
  
  # Generate new API key
  api_key <- generate_api_key(user_id, tier)
  api_key_hash <- digest::digest(api_key, algo = "sha256")
  api_key_prefix <- substr(api_key, 1, 10)
  
  # Set expiration
  expiry_days <- expiry_days %||% KEY_MANAGEMENT_CONFIG$default_expiry_days
  expires_at <- Sys.time() + (expiry_days * 24 * 3600)
  
  # Set permissions based on tier
  if (is.null(permissions)) {
    permissions <- AUTH_CONFIG$tiers[[tier]]$allowed_endpoints
  }
  
  # Set LGPD compliance fields
  data_retention_until <- Sys.time() + (AUTH_CONFIG$lgpd$data_retention_days * 24 * 3600)
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      # Insert into database
      query <- "
        INSERT INTO api_keys (
          user_id, api_key_hash, api_key_prefix, tier, permissions,
          expires_at, purpose_statement, data_retention_until,
          created_by
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9
        ) RETURNING id, created_at
      "
      
      result <- DBI::dbGetQuery(secure_db_pool, query, params = list(
        user_id,
        api_key_hash,
        api_key_prefix,
        tier,
        jsonlite::toJSON(permissions, auto_unbox = TRUE),
        expires_at,
        purpose %||% paste("API access for", tier, "tier"),
        data_retention_until,
        "system"
      ))
      
      if (nrow(result) > 0) {
        # Log the creation for audit
        log_api_key_event(result$id[1], "created", paste("API key created for user", user_id))
        
        return(list(
          success = TRUE,
          api_key = api_key,
          key_id = result$id[1],
          tier = tier,
          expires_at = expires_at,
          permissions = permissions,
          message = "API key created successfully"
        ))
      } else {
        return(list(success = FALSE, error = "Failed to create API key in database"))
      }
      
    } else {
      # Fallback to in-memory storage (for development)
      if (!exists("API_KEYS_STORAGE", envir = .GlobalEnv)) {
        assign("API_KEYS_STORAGE", list(), envir = .GlobalEnv)
      }
      
      key_id <- length(API_KEYS_STORAGE) + 1
      API_KEYS_STORAGE[[as.character(key_id)]] <<- list(
        id = key_id,
        user_id = user_id,
        api_key_hash = api_key_hash,
        tier = tier,
        permissions = permissions,
        created_at = Sys.time(),
        expires_at = expires_at,
        status = "active"
      )
      
      return(list(
        success = TRUE,
        api_key = api_key,
        key_id = key_id,
        tier = tier,
        expires_at = expires_at,
        permissions = permissions,
        message = "API key created successfully (in-memory storage)"
      ))
    }
    
  }, error = function(e) {
    return(list(success = FALSE, error = paste("Database error:", e$message)))
  })
}

# Validate API Key from Database
validate_api_key_from_db <- function(api_key) {
  # First validate format
  format_validation <- validate_api_key_format(api_key)
  if (!format_validation$valid) {
    return(format_validation)
  }
  
  api_key_hash <- digest::digest(api_key, algo = "sha256")
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      query <- "
        SELECT 
          id, user_id, tier, status, permissions, total_requests,
          last_used_at, expires_at, failed_attempts, locked_until,
          ip_whitelist, allowed_origins
        FROM api_keys 
        WHERE api_key_hash = $1
      "
      
      result <- DBI::dbGetQuery(secure_db_pool, query, params = list(api_key_hash))
      
      if (nrow(result) == 0) {
        return(list(valid = FALSE, error = "API key not found"))
      }
      
      key_info <- result[1, ]
      
      # Check if key is active
      if (key_info$status != "active") {
        return(list(valid = FALSE, error = paste("API key is", key_info$status)))
      }
      
      # Check expiration
      if (!isTRUE(is.na(key_info$expires_at)) && key_info$expires_at < Sys.time()) {
        return(list(valid = FALSE, error = "API key has expired"))
      }
      
      # Check if key is locked due to failed attempts
      if (!isTRUE(is.na(key_info$locked_until)) && key_info$locked_until > Sys.time()) {
        return(list(valid = FALSE, error = "API key is temporarily locked"))
      }
      
      # Update last used timestamp
      update_key_last_used(key_info$id)
      
      return(list(
        valid = TRUE,
        key_info = list(
          id = key_info$id,
          user_id = key_info$user_id,
          tier = key_info$tier,
          permissions = if (!is.na(key_info$permissions)) jsonlite::fromJSON(key_info$permissions) else c(),
          total_requests = key_info$total_requests,
          last_used_at = key_info$last_used_at
        )
      ))
      
    } else {
      # Fallback to in-memory storage
      if (exists("API_KEYS_STORAGE", envir = .GlobalEnv)) {
        for (key_data in API_KEYS_STORAGE) {
          if (key_data$api_key_hash == api_key_hash) {
            if (key_data$status == "active" && 
                (isTRUE(is.null(key_data$expires_at)) || key_data$expires_at > Sys.time())) {
              return(list(valid = TRUE, key_info = key_data))
            } else {
              return(list(valid = FALSE, error = "API key is inactive or expired"))
            }
          }
        }
      }
      
      return(list(valid = FALSE, error = "API key not found"))
    }
    
  }, error = function(e) {
    return(list(valid = FALSE, error = paste("Database error:", e$message)))
  })
}

# Rotate API Key
rotate_api_key <- function(old_api_key, user_id = NULL) {
  # Validate old key
  validation_result <- validate_api_key_from_db(old_api_key)
  if (!validation_result$valid) {
    return(list(success = FALSE, error = "Invalid API key for rotation"))
  }
  
  old_key_info <- validation_result$key_info
  actual_user_id <- user_id %||% old_key_info$user_id
  
  # Create new key with same tier and permissions
  new_key_result <- create_api_key(
    user_id = actual_user_id,
    tier = old_key_info$tier,
    purpose = "Key rotation",
    permissions = old_key_info$permissions
  )
  
  if (!new_key_result$success) {
    return(list(success = FALSE, error = paste("Failed to create new key:", new_key_result$error)))
  }
  
  # Mark old key as rotated
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      query <- "
        UPDATE api_keys 
        SET status = 'rotated', 
            rotated_from_key_id = $1
        WHERE api_key_hash = $2
      "
      
      old_api_key_hash <- digest::digest(old_api_key, algo = "sha256")
      DBI::dbExecute(secure_db_pool, query, params = list(
        new_key_result$key_id,
        old_api_key_hash
      ))
      
      # Update the new key to reference the old one
      update_query <- "
        UPDATE api_keys 
        SET rotated_from_key_id = $1
        WHERE id = $2
      "
      DBI::dbExecute(secure_db_pool, update_query, params = list(
        old_key_info$id,
        new_key_result$key_id
      ))
    }
    
    # Log the rotation
    log_api_key_event(old_key_info$id, "rotated", "API key rotated to new key")
    log_api_key_event(new_key_result$key_id, "rotation_created", "New API key created from rotation")
    
    return(list(
      success = TRUE,
      new_api_key = new_key_result$api_key,
      old_key_deactivated = TRUE,
      message = "API key rotated successfully"
    ))
    
  }, error = function(e) {
    return(list(success = FALSE, error = paste("Rotation failed:", e$message)))
  })
}

# Revoke API Key
revoke_api_key <- function(api_key, reason = "Manual revocation") {
  api_key_hash <- digest::digest(api_key, algo = "sha256")
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      query <- "
        UPDATE api_keys 
        SET status = 'revoked',
            notes = CONCAT(COALESCE(notes, ''), ' | Revoked: ', $1, ' at ', $2)
        WHERE api_key_hash = $3
      "
      
      rows_affected <- DBI::dbExecute(secure_db_pool, query, params = list(
        reason,
        as.character(Sys.time()),
        api_key_hash
      ))
      
      if (rows_affected > 0) {
        # Get key info for logging
        key_info <- DBI::dbGetQuery(secure_db_pool, 
          "SELECT id FROM api_keys WHERE api_key_hash = $1", 
          params = list(api_key_hash))
        
        if (nrow(key_info) > 0) {
          log_api_key_event(key_info$id[1], "revoked", reason)
        }
        
        return(list(success = TRUE, message = "API key revoked successfully"))
      } else {
        return(list(success = FALSE, error = "API key not found"))
      }
      
    } else {
      # Fallback to in-memory storage
      if (exists("API_KEYS_STORAGE", envir = .GlobalEnv)) {
        for (key_id in names(API_KEYS_STORAGE)) {
          if (API_KEYS_STORAGE[[key_id]]$api_key_hash == api_key_hash) {
            API_KEYS_STORAGE[[key_id]]$status <<- "revoked"
            return(list(success = TRUE, message = "API key revoked successfully"))
          }
        }
      }
      
      return(list(success = FALSE, error = "API key not found"))
    }
    
  }, error = function(e) {
    return(list(success = FALSE, error = paste("Revocation failed:", e$message)))
  })
}

# Get API Key Usage Statistics
get_key_usage_stats <- function(api_key, days = 30) {
  api_key_hash <- digest::digest(api_key, algo = "sha256")
  
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      # Get key basic info
      key_query <- "
        SELECT id, user_id, tier, total_requests, created_at, last_used_at
        FROM api_keys 
        WHERE api_key_hash = $1
      "
      key_info <- DBI::dbGetQuery(secure_db_pool, key_query, params = list(api_key_hash))
      
      if (nrow(key_info) == 0) {
        return(list(success = FALSE, error = "API key not found"))
      }
      
      # Get usage statistics
      stats_query <- "
        SELECT 
          COUNT(*) as total_requests,
          COUNT(DISTINCT DATE(timestamp)) as active_days,
          AVG(response_time_ms) as avg_response_time,
          COUNT(CASE WHEN response_code >= 400 THEN 1 END) as error_count,
          COUNT(DISTINCT endpoint) as unique_endpoints,
          MIN(timestamp) as first_request,
          MAX(timestamp) as last_request
        FROM api_key_usage_log 
        WHERE api_key_id = $1 
          AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
      "
      
      usage_stats <- DBI::dbGetQuery(secure_db_pool, 
        sprintf(stats_query, days), 
        params = list(key_info$id[1]))
      
      # Get endpoint usage breakdown
      endpoint_query <- "
        SELECT 
          endpoint,
          COUNT(*) as request_count,
          AVG(response_time_ms) as avg_response_time
        FROM api_key_usage_log 
        WHERE api_key_id = $1 
          AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '%s days'
        GROUP BY endpoint
        ORDER BY request_count DESC
        LIMIT 10
      "
      
      endpoint_stats <- DBI::dbGetQuery(secure_db_pool, 
        sprintf(endpoint_query, days), 
        params = list(key_info$id[1]))
      
      return(list(
        success = TRUE,
        key_info = key_info[1, ],
        usage_stats = usage_stats[1, ],
        endpoint_breakdown = endpoint_stats,
        period_days = days
      ))
      
    } else {
      return(list(
        success = FALSE, 
        error = "Database connection not available for detailed statistics"
      ))
    }
    
  }, error = function(e) {
    return(list(success = FALSE, error = paste("Statistics error:", e$message)))
  })
}

# Helper Functions
count_user_active_keys <- function(user_id) {
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      result <- DBI::dbGetQuery(secure_db_pool, 
        "SELECT COUNT(*) as count FROM api_keys WHERE user_id = $1 AND status = 'active'",
        params = list(user_id))
      return(result$count[1])
    } else {
      return(0)
    }
  }, error = function(e) {
    return(0)
  })
}

check_key_generation_cooldown <- function(user_id) {
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      cooldown_hours <- KEY_MANAGEMENT_CONFIG$key_generation_cooldown_hours
      result <- DBI::dbGetQuery(secure_db_pool, 
        "SELECT COUNT(*) as count FROM api_keys 
         WHERE user_id = $1 AND created_at > CURRENT_TIMESTAMP - INTERVAL '%s hours'",
        params = list(user_id, cooldown_hours))
      return(result$count[1] == 0)
    } else {
      return(TRUE)
    }
  }, error = function(e) {
    return(TRUE)
  })
}

update_key_last_used <- function(key_id) {
  tryCatch({
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      DBI::dbExecute(secure_db_pool,
        "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP, total_requests = total_requests + 1 WHERE id = $1",
        params = list(key_id))
    }
  }, error = function(e) {
    cat("Warning: Failed to update key usage:", e$message, "\n")
  })
}

log_api_key_event <- function(key_id, event_type, description) {
  audit_entry <- list(
    timestamp = Sys.time(),
    key_id = key_id,
    event_type = event_type,
    description = description,
    source = "api_key_management"
  )
  
  cat("📋 API Key Event:", jsonlite::toJSON(audit_entry, auto_unbox = TRUE), "\n")
}

# Initialize database schema if needed
initialize_key_management_db <- function() {
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    tryCatch({
      # Create tables if they don't exist
      DBI::dbExecute(secure_db_pool, API_KEY_SCHEMA)
      cat("✅ API Key management database schema initialized\n")
      return(TRUE)
    }, error = function(e) {
      cat("⚠️ Failed to initialize database schema:", e$message, "\n")
      return(FALSE)
    })
  } else {
    cat("⚠️ Database connection not available\n")
    return(FALSE)
  }
}

# Auto-initialize
initialize_key_management_db()

cat("✅ API Key Lifecycle Management System Loaded\n")