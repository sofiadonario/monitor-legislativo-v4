# Fast deployment using pre-built base image
FROM southamerica-east1-docker.pkg.dev/mackmonitor/monitor-legislativo-v4/base-image:latest

# Install missing packages for production app
RUN R -q -e "install.packages(c('pool','shinydashboard','redux','logger','httr2','future.apply','quanteda','spdep','R6','RPostgreSQL','arrow','cachem','cluster','fpc','htmlwidgets','knitr','microbenchmark','optparse','plumber','profvis','stringi','testthat','uuid','yaml','rmarkdown','dbplyr'), repos='https://cloud.r-project.org')"

# Sprint 3: Advanced NLP packages
RUN R -q -e "install.packages(c('word2vec','text2vec','RcppAnnoy','umap','stm','tidytext','igraph','visNetwork','reticulate','diffobj'), repos='https://cloud.r-project.org')"

# Copy application files
WORKDIR /app
COPY . /app/

# Environment + port
ENV PORT=3838
EXPOSE 3838

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3838/health || exit 1

# Start app
CMD ["R", "-e", "shiny::runApp('app_phoenix.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', '3838')))"]
