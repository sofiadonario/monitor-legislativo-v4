# ==============================================================================
# GOOGLE CLOUD STORAGE INTEGRATION
# ==============================================================================
# Upload reports to Cloud Storage and generate signed URLs
# Integrates with gs://monitor-legislativo-reports bucket
#
# Author: Monitor Legislativo Team
# Date: 2025-11-26
# Version: 1.0
# ==============================================================================

# Check and load required packages
GCS_DEPENDENCIES_AVAILABLE <- requireNamespace("googleCloudStorageR", quietly = TRUE)

if (!GCS_DEPENDENCIES_AVAILABLE) {
  warning("Cloud Storage dependencies not available (googleCloudStorageR)")
}

# Global bucket name (configured in Week 1)
GCS_BUCKET_NAME <- "monitor-legislativo-reports"

#' Initialize Google Cloud Storage authentication
#'
#' @return TRUE if successful, FALSE otherwise
#' @export
init_gcs_auth <- function() {
  # Check dependencies first
  if (!GCS_DEPENDENCIES_AVAILABLE) {
    cat("❌ googleCloudStorageR package not available\n")
    return(FALSE)
  }

  tryCatch({
    # Check if running on Google Cloud (uses Application Default Credentials)
    if (nchar(Sys.getenv("GOOGLE_CLOUD_PROJECT")) > 0 ||
        nchar(Sys.getenv("GCE_METADATA_HOST")) > 0) {
      cat("🔑 Using Google Cloud Application Default Credentials\n")
      googleCloudStorageR::gcs_auth(token = NULL)
      return(TRUE)
    }

    # Check for service account key file
    key_file <- Sys.getenv("GCS_AUTH_FILE", "")
    if (nchar(key_file) > 0 && file.exists(key_file)) {
      cat("🔑 Authenticating with service account:", key_file, "\n")
      googleCloudStorageR::gcs_auth(json_file = key_file)
      return(TRUE)
    }

    # Try to use existing credentials
    cat("🔑 Attempting to use existing GCS credentials\n")
    googleCloudStorageR::gcs_auth()
    return(TRUE)

  }, error = function(e) {
    cat("❌ Error initializing GCS authentication:", e$message, "\n")
    cat("💡 Tip: Set GCS_AUTH_FILE environment variable or run on Google Cloud\n")
    return(FALSE)
  })
}

#' Upload file to Google Cloud Storage
#'
#' @param file_path Path to local file
#' @param bucket_name GCS bucket name (default: monitor-legislativo-reports)
#' @param object_name Object name in bucket (if NULL, uses basename of file_path)
#' @return GCS object name if successful, NULL otherwise
#' @export
upload_to_gcs <- function(file_path, bucket_name = GCS_BUCKET_NAME, object_name = NULL) {
  tryCatch({
    # Initialize authentication if not already done
    if (!init_gcs_auth()) {
      stop("GCS authentication failed")
    }

    # Validate file exists
    if (!file.exists(file_path)) {
      stop(sprintf("File not found: %s", file_path))
    }

    # Determine object name
    if (is.null(object_name)) {
      object_name <- basename(file_path)
    }

    cat(sprintf("☁️  Uploading %s to gs://%s/%s ...\n", file_path, bucket_name, object_name))

    # Set bucket
    googleCloudStorageR::gcs_global_bucket(bucket_name)

    # Upload file
    result <- googleCloudStorageR::gcs_upload(
      file = file_path,
      name = object_name,
      predefinedAcl = "private"  # Keep files private, use signed URLs
    )

    cat("✅ Upload successful\n")
    object_name

  }, error = function(e) {
    cat("❌ Error uploading to GCS:", e$message, "\n")
    NULL
  })
}

#' Generate signed URL for GCS object
#'
#' @param object_name Object name in bucket
#' @param bucket_name GCS bucket name (default: monitor-legislativo-reports)
#' @param expires_in_hours Hours until URL expires (default: 72)
#' @return Signed URL if successful, NULL otherwise
#' @export
generate_signed_url <- function(object_name, bucket_name = GCS_BUCKET_NAME, expires_in_hours = 72) {
  tryCatch({
    # Calculate expiration time
    expires_at <- Sys.time() + (expires_in_hours * 3600)

    cat(sprintf("🔗 Generating signed URL for gs://%s/%s ...\n", bucket_name, object_name))

    # Generate signed URL
    signed_url <- googleCloudStorageR::gcs_signed_url(
      object_name = object_name,
      bucket = bucket_name,
      expires = expires_at,
      version = "v4"
    )

    cat(sprintf("✅ Signed URL generated (expires in %d hours)\n", expires_in_hours))
    signed_url

  }, error = function(e) {
    cat("❌ Error generating signed URL:", e$message, "\n")
    NULL
  })
}

#' Upload report and get shareable link
#'
#' @param file_path Path to report file (PDF or HTML)
#' @param expires_in_hours Hours until URL expires (default: 72)
#' @return List with object_name and signed_url, or NULL if failed
#' @export
upload_report_and_share <- function(file_path, expires_in_hours = 72) {
  tryCatch({
    cat("📤 Uploading report to Cloud Storage...\n")

    # Upload file
    object_name <- upload_to_gcs(file_path)
    if (is.null(object_name)) {
      stop("Upload failed")
    }

    # Generate signed URL
    signed_url <- generate_signed_url(object_name, expires_in_hours = expires_in_hours)
    if (is.null(signed_url)) {
      stop("Failed to generate signed URL")
    }

    result <- list(
      object_name = object_name,
      signed_url = signed_url,
      bucket = GCS_BUCKET_NAME,
      expires_at = Sys.time() + (expires_in_hours * 3600),
      file_size = file.size(file_path)
    )

    cat("✅ Report uploaded and shareable link generated\n")
    result

  }, error = function(e) {
    cat("❌ Error in upload_report_and_share:", e$message, "\n")
    NULL
  })
}

#' List reports in Cloud Storage bucket
#'
#' @param bucket_name GCS bucket name (default: monitor-legislativo-reports)
#' @param max_results Maximum number of results (default: 100)
#' @return Data frame with object metadata, or NULL if failed
#' @export
list_reports <- function(bucket_name = GCS_BUCKET_NAME, max_results = 100) {
  tryCatch({
    # Initialize authentication
    if (!init_gcs_auth()) {
      stop("GCS authentication failed")
    }

    cat(sprintf("📋 Listing reports in gs://%s ...\n", bucket_name))

    # Set bucket
    googleCloudStorageR::gcs_global_bucket(bucket_name)

    # List objects
    objects <- googleCloudStorageR::gcs_list_objects(
      bucket = bucket_name,
      max_results = max_results
    )

    if (nrow(objects) == 0) {
      cat("ℹ️  No reports found in bucket\n")
      return(data.frame(
        name = character(0),
        size = numeric(0),
        updated = character(0)
      ))
    }

    cat(sprintf("✅ Found %d reports\n", nrow(objects)))
    objects[, c("name", "size", "updated")]

  }, error = function(e) {
    cat("❌ Error listing reports:", e$message, "\n")
    NULL
  })
}

#' Delete report from Cloud Storage
#'
#' @param object_name Object name to delete
#' @param bucket_name GCS bucket name (default: monitor-legislativo-reports)
#' @return TRUE if successful, FALSE otherwise
#' @export
delete_report <- function(object_name, bucket_name = GCS_BUCKET_NAME) {
  tryCatch({
    # Initialize authentication
    if (!init_gcs_auth()) {
      stop("GCS authentication failed")
    }

    cat(sprintf("🗑️  Deleting gs://%s/%s ...\n", bucket_name, object_name))

    # Set bucket
    googleCloudStorageR::gcs_global_bucket(bucket_name)

    # Delete object
    googleCloudStorageR::gcs_delete_object(object_name, bucket = bucket_name)

    cat("✅ Report deleted successfully\n")
    TRUE

  }, error = function(e) {
    cat("❌ Error deleting report:", e$message, "\n")
    FALSE
  })
}

cat("✅ Cloud Storage integration module loaded\n")
