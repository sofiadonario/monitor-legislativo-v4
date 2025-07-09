user_lib <- path.expand("~/R/library")
if (!dir.exists(user_lib)) dir.create(user_lib, recursive = TRUE)
.libPaths(c(user_lib, .libPaths()))
options(repos = c(CRAN = "https://cloud.r-project.org/"))

cat("Installing shiny...\n")
install.packages("shiny", lib = user_lib, dependencies = FALSE, quiet = TRUE)

cat("Testing shiny...\n")
library(shiny, lib.loc = user_lib)

cat("Shiny installation successful!\n")
cat("Library path:", user_lib, "\n")