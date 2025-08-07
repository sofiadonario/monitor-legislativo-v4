library(DBI)
library(RPostgres)

# Connect to database
DATABASE_URL <- "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway"
con <- dbConnect(RPostgres::Postgres(), DATABASE_URL)

# Check tables
cat("Available tables:\n")
print(dbListTables(con))

# Check documents table structure
cat("\nDocuments table columns:\n")
print(dbListFields(con, "documents"))

# Check sample data
cat("\nSample documents (first 3 rows):\n")
sample_data <- dbGetQuery(con, "SELECT * FROM documents LIMIT 3")
print(sample_data)

# Check counts
cat("\nTotal documents count:\n")
total_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")
print(total_count)

# Check documents with titles
cat("\nDocuments with non-null titles:\n")
title_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents WHERE titulo IS NOT NULL AND titulo \!= ''")
print(title_count)

# Check state distribution
cat("\nState distribution:\n")
state_dist <- dbGetQuery(con, "SELECT estado, COUNT(*) as count FROM documents WHERE estado IS NOT NULL AND estado \!= '' GROUP BY estado ORDER BY count DESC LIMIT 10")
print(state_dist)

# Check document types
cat("\nDocument types:\n")
type_dist <- dbGetQuery(con, "SELECT tipo, COUNT(*) as count FROM documents WHERE tipo IS NOT NULL AND tipo \!= '' GROUP BY tipo ORDER BY count DESC")
print(type_dist)

# Check if data_publicacao is populated
cat("\nData publicacao distribution:\n")
date_check <- dbGetQuery(con, "SELECT COUNT(*) as with_date FROM documents WHERE data_publicacao IS NOT NULL")
print(date_check)

# Check metadata column
cat("\nMetadata column sample:\n")
metadata_sample <- dbGetQuery(con, "SELECT metadata FROM documents WHERE metadata IS NOT NULL LIMIT 3")
print(metadata_sample)

dbDisconnect(con)
EOF < /dev/null
