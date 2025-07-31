# Quick Fix for CSV Loading Issues
library(dplyr)
library(readr)

# Read the file with different approach
cat("🔍 Debugging CSV loading...\n")

# Try reading with different parameters
data1 <- read.csv("./data_current/processed/Geral.csv", stringsAsFactors = FALSE, fileEncoding = "UTF-8")
cat("📊 Method 1 (read.csv): ", nrow(data1), "rows\n")

# Try with readr
data2 <- read_csv("./data_current/processed/Geral.csv", locale = locale(encoding = "UTF-8"))
cat("📊 Method 2 (read_csv): ", nrow(data2), "rows\n")

# Check for issues
cat("🔍 Column names: ", paste(names(data1)[1:5], collapse = ", "), "\n")
cat("🔍 First few State values:\n")
print(head(data1$State, 10))

# Check unique states
states_found <- unique(data1$State[!is.na(data1$State) & data1$State != ""])
cat("🔍 States found: ", length(states_found), " unique states\n")
print(states_found)

# Check document types
types_found <- table(data1$Urn_type)
cat("🔍 Document types:\n")
print(types_found)

cat("✅ Debugging complete\n")