# Quick test to see what the data looks like
library(dplyr)

csv_path <- "data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv"

if (file.exists(csv_path)) {
  data <- read.csv(csv_path, stringsAsFactors = FALSE, nrows = 10)
  cat("Sample data columns:\n")
  print(names(data))
  cat("\nSample ano values:\n")
  print(data$ano[1:5])
  cat("\nSample data values:\n") 
  print(data$data[1:5])
  cat("\nSample estado values:\n")
  print(data$estado[1:5])
  cat("\nSample categoria values:\n")
  print(data$categoria[1:5])
} else {
  cat("CSV file not found\n")
}