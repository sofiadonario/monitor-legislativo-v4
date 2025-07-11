# Simple version test - should show in Railway logs
cat("=== VERSION TEST - DATABASE ENABLED ===\n")
cat("Current time:", as.character(Sys.time()), "\n")
cat("DATABASE_URL present:", nchar(Sys.getenv("DATABASE_URL")) > 0, "\n")
cat("DATABASE_URL value:", Sys.getenv("DATABASE_URL"), "\n")
cat("Current working directory:", getwd(), "\n")
cat("Files in current directory:\n")
print(list.files(".", recursive = FALSE))
cat("Files in R directory:\n")
if (dir.exists("R")) {
  print(list.files("R", recursive = FALSE))
} else {
  cat("R directory does not exist\n")
}
cat("=== END VERSION TEST ===\n")