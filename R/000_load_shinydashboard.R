# This file is alphabetically first in R/ so Shiny sources it before other modules.
# It ensures the shinydashboard package is attached, preventing 'object not found' errors
# when downstream files reference shinydashboard functions without explicit library() calls.

if (!requireNamespace("shinydashboard", quietly = TRUE)) {
  stop("Package 'shinydashboard' is required but not installed in the runtime image.")
}
library(shinydashboard)
