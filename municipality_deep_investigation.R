# Municipality Deep Investigation - Brazilian Legislative Database
# Deep text mining analysis to find hidden municipality data

# Load required libraries
library(RPostgreSQL)
library(DBI)
library(dplyr)
library(stringr)
library(ggplot2)
library(tidyr)
library(tm)
library(wordcloud)
library(RColorBrewer)
library(plotly)

# Database connection parameters
db_config <- list(
  host = "nozomi.proxy.rlwy.net",
  port = 44844,
  dbname = "railway", 
  user = "postgres",
  password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
)

# Connect to database
cat("Connecting to PostgreSQL database...\n")
drv <- dbDriver("PostgreSQL")
con <- dbConnect(drv, 
                 host = db_config$host,
                 port = db_config$port,
                 dbname = db_config$dbname,
                 user = db_config$user,
                 password = db_config$password)

# Test connection and examine table structure
cat("Testing connection and examining table structure...\n")
tables <- dbListTables(con)
print("Available tables:")
print(tables)

# Find the main documents table (likely 'documentos' or similar)
main_table <- tables[grep("documento|norma|lei", tables, ignore.case = TRUE)][1]
if(is.na(main_table)) main_table <- tables[1]

cat("\nExamining table:", main_table, "\n")
columns <- dbListFields(con, main_table)
print("Available columns:")
print(columns)

# Get sample data to understand structure
sample_query <- paste0("SELECT * FROM ", main_table, " LIMIT 5")
sample_data <- dbGetQuery(con, sample_query)
cat("\nSample data structure:\n")
str(sample_data)

# Get total record count
count_query <- paste0("SELECT COUNT(*) as total_records FROM ", main_table)
total_records <- dbGetQuery(con, count_query)
cat("\nTotal records:", total_records$total_records, "\n")

# Identify text fields that might contain municipality data
text_fields <- c("municipio", "localidade", "jurisdicao_original", "autoridade", 
                "titulo", "ementa", "resumo", "conteudo", "descricao", 
                "origem", "fonte", "orgao")

# Find which text fields actually exist in the table
existing_text_fields <- intersect(text_fields, columns)
cat("\nText fields available for municipality analysis:\n")
print(existing_text_fields)

# Additional fields that might contain geographic info
geo_fields <- columns[grep("geo|local|munic|cidade|estado|uf|regiao", columns, ignore.case = TRUE)]
cat("\nPotential geographic fields:\n")
print(geo_fields)

all_analysis_fields <- unique(c(existing_text_fields, geo_fields))
cat("\nAll fields to analyze:\n")
print(all_analysis_fields)