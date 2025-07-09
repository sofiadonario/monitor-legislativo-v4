# Database Connection Debug Guide

## Issue: App showing "Database connection will be implemented in next version"

This means the database connection failed and the app fell back to sample data.

## Debugging Steps

### 1. Check Railway Environment Variables

In Railway Dashboard → monitor-legislativo-unified → Variables:

**Required:**
- `DATABASE_URL` should be set to your PostgreSQL connection string
- Format: `postgresql://postgres:password@host:port/railway`

**To set DATABASE_URL:**
1. Go to Railway Dashboard
2. Click on PostgreSQL service
3. Go to "Variables" tab
4. Copy the `DATABASE_URL` value
5. Go to monitor-legislativo-unified service
6. Go to "Variables" tab
7. Add new variable: `DATABASE_URL` = (paste the PostgreSQL URL)

### 2. Check Railway Deployment Logs

Look for these messages in the logs:
- "Attempting to initialize database connection..."
- "DATABASE_URL present: true/false"
- "Connecting to database:"
- "✅ Database connected successfully!" OR "❌ Database connection failed"

### 3. Manual DATABASE_URL Setup

If you don't have the DATABASE_URL, you can construct it:

```
postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway
```

### 4. Alternative: Force Database Connection

If DATABASE_URL is not working, you can temporarily hardcode it for testing:

In `r-shiny-app/R/database_connection.R`, replace:
```r
database_url <- Sys.getenv("DATABASE_URL")
```

With:
```r
database_url <- "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"
```

### 5. Check Package Installation

Make sure these packages are installed:
- RPostgres
- DBI
- pool
- dbplyr

### 6. Test Database Connection Manually

You can test the connection by adding this to the app startup:

```r
# Test manual connection
cat("Testing manual database connection...\n")
tryCatch({
  test_conn <- DBI::dbConnect(
    RPostgres::Postgres(),
    host = "nozomi.proxy.rlwy.net",
    port = 44844,
    dbname = "railway",
    user = "postgres",
    password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
  )
  
  result <- DBI::dbGetQuery(test_conn, "SELECT COUNT(*) FROM documents")
  cat("Manual connection successful! Document count:", result[[1]], "\n")
  DBI::dbDisconnect(test_conn)
}, error = function(e) {
  cat("Manual connection failed:", e$message, "\n")
})
```

## Expected Fix

Most likely issue: **DATABASE_URL environment variable not set in Railway**

**Solution:**
1. Set DATABASE_URL in Railway dashboard
2. Redeploy the application
3. Check logs for successful connection

## Next Steps

1. Check Railway environment variables
2. Set DATABASE_URL if missing
3. Redeploy and check logs
4. If still failing, try manual connection test